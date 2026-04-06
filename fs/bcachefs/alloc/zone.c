// SPDX-License-Identifier: GPL-2.0
/*
 * Zone-aware allocation for bcachefs on HDDs.
 *
 * Uses LBA as a proxy for radial position on spinning disks:
 * lower LBA = outer tracks = higher sequential throughput.
 *
 * Data is classified by temperature (hot/warm/cold) and steered to the
 * appropriate LBA zone at write time and during copygc relocation.
 */

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/buckets.h"
#include "alloc/foreground.h"
#include "alloc/zone.h"

#include "sb/members.h"

#include <linux/math64.h>
#include <linux/log2.h>
#include <linux/printbuf.h>

/* ── Zone boundary computation ────────────────────────────── */

void bch2_dev_zones_init(struct bch_dev *ca)
{
	struct bch_dev_zones *z = &ca->zones;
	u64 nb = ca->mi.nbuckets;
	u64 first = ca->mi.first_bucket;
	u64 usable = nb - first;

	/*
	 * Compute boundaries as bucket numbers.
	 *
	 * Layout:
	 *   [first_bucket, hot_read_end)    = HOT_READ   (0-10%)
	 *   [hot_read_end, hot_write_end)   = HOT_WRITE  (10-15%)
	 *   [hot_write_end, warm_end)       = WARM        (15-65%)
	 *   [warm_end, nbuckets)            = COLD         (65-100%)
	 */
	z->boundary[BCH_ZONE_hot_read]  = first;
	z->boundary[BCH_ZONE_hot_write] = first + div_u64(usable * BCH_ZONE_HOT_READ_END_PCT, 100);
	z->boundary[BCH_ZONE_warm]      = first + div_u64(usable * BCH_ZONE_HOT_WRITE_END_PCT, 100);
	z->boundary[BCH_ZONE_cold]      = first + div_u64(usable * BCH_ZONE_WARM_END_PCT, 100);

	/* Sector-based boundaries for fast LBA lookups */
	for (unsigned i = 0; i < BCH_ZONE_NR; i++)
		z->boundary_sector[i] = bucket_to_sector(ca, z->boundary[i]);

	/* Zero stats */
	for (unsigned i = 0; i < BCH_ZONE_NR; i++) {
		atomic64_set(&z->bytes[i], 0);
		atomic64_set(&z->extents[i], 0);
		atomic64_set(&z->shared_extents[i], 0);
		atomic64_set(&z->copygc_moved_in[i], 0);
		atomic64_set(&z->copygc_moved_out[i], 0);
		atomic64_set(&z->fragmented[i], 0);
	}
}

/* ── Extent heat calculation ──────────────────────────────── */

/*
 * Compute a heat score for a bucket's data.
 *
 * heat = read_weight * read_frequency
 *      + refcount_weight * log2(refcount)
 *      - rewrite_penalty * rewrite_rate
 *
 * Since we don't have per-extent read counters in the current format,
 * we approximate read_frequency from io_time[READ] recency relative to
 * io_time[WRITE]. The intuition: if io_time[READ] is much more recent
 * than io_time[WRITE], the data is being actively read.
 *
 * rewrite_rate is approximated by how much WRITE io_time has advanced
 * recently (frequent COW rewrites).
 *
 * Returns a value in fixed-point (8 fractional bits).
 */
unsigned bch2_extent_heat(const struct bch_alloc_v4 *a,
			  const struct bch_dev *ca)
{
	u64 read_time  = a->io_time[0];
	u64 write_time = a->io_time[1];
	u32 refcount   = a->stripe_refcount;

	/*
	 * Read frequency proxy: how recently was this bucket read vs written?
	 * If read_time > write_time, the data is being actively read since
	 * its last write. Clamp to 0..1024 range.
	 */
	s64 read_recency = (s64)(read_time - write_time);
	unsigned read_freq = clamp_t(s64, read_recency >> 4, 0, 1024);

	/*
	 * Refcount contribution: log2 of refcount (shared extents boost).
	 * log2(1) = 0, log2(2) = 1, log2(4) = 2, etc.
	 */
	unsigned ref_score = refcount > 1 ? ilog2(refcount) : 0;

	/*
	 * Rewrite rate: approximated by how recently the data was written.
	 * Lower write_time = older data = lower rewrite rate = good.
	 * We want to penalize recently-written data (high churn).
	 */
	unsigned rewrite_est = 0;
	if (write_time > read_time && write_time - read_time > 0)
		rewrite_est = clamp_t(u64, (write_time - read_time) >> 4, 0, 512);

	unsigned heat = (BCH_HEAT_READ_WEIGHT * read_freq +
			 BCH_HEAT_REFCOUNT_WEIGHT * ref_score * 256) >> 8;

	unsigned penalty = (BCH_HEAT_REWRITE_PENALTY * rewrite_est) >> 8;

	return heat > penalty ? heat - penalty : 0;
}

/* ── Classification ───────────────────────────────────────── */

enum bch_zone bch2_classify_extent(const struct bch_alloc_v4 *a,
				   const struct bch_dev *ca,
				   enum bch_data_type data_type)
{
	/* Metadata always goes to HOT_READ (outer tracks) */
	if (data_type == BCH_DATA_btree ||
	    data_type == BCH_DATA_sb ||
	    data_type == BCH_DATA_journal)
		return BCH_ZONE_hot_read;

	unsigned heat = bch2_extent_heat(a, ca);
	u32 refcount  = a->stripe_refcount;

	/* Shared extents: special handling */
	if (refcount >= BCH_SHARED_REFCOUNT_THRESHOLD) {
		if (heat >= BCH_HEAT_WARM_THRESHOLD)
			return BCH_ZONE_hot_read;  /* shared + read = outer tracks */
		return BCH_ZONE_warm;              /* shared but not hot = warm */
	}

	/* High heat + low rewrite → HOT_READ */
	if (heat >= BCH_HEAT_HOT_THRESHOLD)
		return BCH_ZONE_hot_read;

	/* Moderate heat → WARM */
	if (heat >= BCH_HEAT_WARM_THRESHOLD)
		return BCH_ZONE_warm;

	/* Low heat → COLD (push inward) */
	return BCH_ZONE_cold;
}

enum bch_zone bch2_select_write_zone(enum bch_data_type data_type,
				     bool is_copygc)
{
	/* Copygc relocations are classified dynamically, not here */
	if (is_copygc)
		return BCH_ZONE_warm;  /* default landing; overridden per-extent */

	switch (data_type) {
	case BCH_DATA_btree:
	case BCH_DATA_sb:
	case BCH_DATA_journal:
		return BCH_ZONE_hot_read;
	case BCH_DATA_user:
	case BCH_DATA_cached:
	default:
		return BCH_ZONE_hot_write;
	}
}

/* ── Zone-mismatch scoring ────────────────────────────────── */

unsigned bch2_zone_mismatch_score(const struct bch_alloc_v4 *a,
				  const struct bch_dev *ca)
{
	u64 bucket = a - (const struct bch_alloc_v4 *)NULL; /* bucket from key */

	/*
	 * We can't get the bucket number from alloc_v4 alone in this context.
	 * In the real integration, the caller passes the bucket position.
	 * For now, return 0 — the full scoring function below takes bucket.
	 */
	return 0;
}

/*
 * Full copygc victim score with zone awareness.
 *
 * score = W_frag * fragmentation + W_mismatch * zone_mismatch + W_age * age
 *
 * @a: bucket allocation metadata
 * @ca: device
 * @bucket: bucket number
 * @now: current io_clock time
 *
 * Returns score in fixed-point (higher = more desirable to evacuate).
 */
u64 bch2_zone_copygc_bucket_score(const struct bch_alloc_v4 *a,
				  const struct bch_dev *ca,
				  u64 bucket, u64 now)
{
	/* Fragmentation: ratio of dirty sectors to bucket size */
	u32 dirty = bch2_bucket_sectors_dirty(*a);
	u64 frag = 0;
	if (dirty < ca->mi.bucket_size && dirty > 0)
		frag = div_u64((u64)(ca->mi.bucket_size - dirty) << 8,
			       ca->mi.bucket_size);

	/* Zone mismatch: is the data in the wrong zone? */
	enum bch_zone current_zone = bch2_bucket_zone(ca, bucket);
	enum bch_zone ideal_zone = bch2_classify_extent(a, ca, a->data_type);
	u64 mismatch = (current_zone != ideal_zone) ? 256 : 0;

	/*
	 * Bonus: penalize data that's far from its ideal zone.
	 * e.g., cold data in HOT_READ is worse than cold data in WARM.
	 */
	if (mismatch) {
		int distance = abs((int)current_zone - (int)ideal_zone);
		mismatch = (u64)distance * 128;
	}

	/* Age: older data (lower write time) gets higher age score */
	u64 age = 0;
	if (now > a->io_time[1])
		age = min_t(u64, (now - a->io_time[1]) >> 8, 256);

	return (BCH_COPYGC_W_FRAG * frag +
		BCH_COPYGC_W_MISMATCH * mismatch +
		BCH_COPYGC_W_AGE * age) >> 8;
}

u64 bch2_zone_copygc_score(const struct bch_alloc_v4 *a,
			   const struct bch_dev *ca,
			   u64 now)
{
	/*
	 * Without bucket number context, return fragmentation-only score.
	 * The full path uses bch2_zone_copygc_bucket_score() instead.
	 */
	u32 dirty = bch2_bucket_sectors_dirty(*a);
	if (!dirty || dirty >= ca->mi.bucket_size)
		return 0;

	return div_u64((u64)(ca->mi.bucket_size - dirty) << 8,
		       ca->mi.bucket_size);
}

/* ── Zone-aware allocation cursor ─────────────────────────── */

bool bch2_set_alloc_cursor_zone(struct bch_dev *ca,
				enum bch_zone zone,
				unsigned btree_bitmap)
{
	u64 start, end;

	bch2_zone_bucket_range(ca, zone, &start, &end);

	if (start >= end)
		return false;

	ca->alloc_cursor[btree_bitmap] = start;
	return true;
}

/* ── Stats output ─────────────────────────────────────────── */

void bch2_dev_zone_stats_to_text(struct printbuf *out,
				 const struct bch_dev *ca)
{
	const struct bch_dev_zones *z = &ca->zones;

	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);

	prt_printf(out, "zone\tbuckets\tbytes\textents\tshared\tgc_in\tgc_out\n");

	for (unsigned i = 0; i < BCH_ZONE_NR; i++) {
		u64 start, end;
		bch2_zone_bucket_range(ca, i, &start, &end);

		prt_printf(out, "%s\t%llu\t", bch2_zone_name(i), end - start);
		prt_human_readable_u64(out, atomic64_read(&z->bytes[i]) << 9);
		prt_char(out, '\t');
		prt_printf(out, "%llu\t", atomic64_read(&z->extents[i]));
		prt_printf(out, "%llu\t", atomic64_read(&z->shared_extents[i]));
		prt_printf(out, "%llu\t", atomic64_read(&z->copygc_moved_in[i]));
		prt_printf(out, "%llu\n", atomic64_read(&z->copygc_moved_out[i]));
	}
}

void bch2_fs_zone_stats_to_text(struct printbuf *out,
				struct bch_fs *c)
{
	prt_printf(out, "Zone-aware allocation stats:\n");
	prt_newline(out);

	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL) {
		if (!ca->mi.rotational)
			continue;

		prt_printf(out, "Device %s (rotational):\n", ca->name);
		bch2_dev_zone_stats_to_text(out, ca);
		prt_newline(out);
	}
}
