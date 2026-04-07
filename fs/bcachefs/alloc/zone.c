// SPDX-License-Identifier: GPL-2.0
/*
 * Radial temperature zoning for bcachefs on HDDs.
 *
 * Uses LBA as a proxy for radial position on spinning disks:
 * lower LBA = outer tracks = higher sequential throughput.
 *
 * Each rotational device is divided into N radial zones:
 *   Zone 0   → outermost (fastest, hottest)
 *   Zone N-1 → innermost (slowest, coldest)
 *
 * Zone count scales with device size:
 *   zones = clamp(device_size_bytes >> 40, 2, 255)
 *
 * Data is classified by temperature and steered to the appropriate
 * radial zone. Movement occurs via promote (outward) and CopyGC (inward).
 */

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/buckets.h"
#include "alloc/foreground.h"
#include "alloc/zone.h"

#include "sb/members.h"

#include <linux/math64.h>
#include <linux/log2.h>

/* ── Radial zone geometry computation ─────────────────────── */

/*
 * Compute the number of radial zones for a device.
 * Scales ~1 zone per TB, clamped to [2, 255].
 */
static u8 bch2_compute_nr_radial_zones(const struct bch_dev *ca)
{
	u64 device_sectors = (u64)(ca->mi.nbuckets - ca->mi.first_bucket) *
			     ca->mi.bucket_size;
	/* Convert sectors to bytes (multiply by 512), then >> 40 for ~1 zone/TB */
	u64 device_bytes = device_sectors << 9;
	u64 zones = device_bytes >> 40;

	return clamp_t(u64, zones, BCH_RADIAL_ZONE_MIN, BCH_RADIAL_ZONE_MAX);
}

void bch2_dev_radial_zones_init(struct bch_dev *ca)
{
	struct bch_radial_map *m = &ca->radial_map;
	u64 first = ca->mi.first_bucket;
	u64 nb = ca->mi.nbuckets;
	u64 usable = nb - first;

	m->nr_zones = bch2_compute_nr_radial_zones(ca);
	m->zone_size_buckets = div_u64(usable, m->nr_zones);
	m->zone_size_sectors = m->zone_size_buckets * ca->mi.bucket_size;

	/* Ensure minimum of 1 bucket per zone */
	if (!m->zone_size_buckets) {
		m->nr_zones = BCH_RADIAL_ZONE_MIN;
		m->zone_size_buckets = div_u64(usable, m->nr_zones);
		m->zone_size_sectors = m->zone_size_buckets * ca->mi.bucket_size;
	}

	for (unsigned i = 0; i < m->nr_zones; i++) {
		struct bch_radial_zone *z = &m->zones[i];

		z->start_bucket = first + (u64)i * m->zone_size_buckets;
		z->end_bucket = (i + 1 < m->nr_zones)
			? first + (u64)(i + 1) * m->zone_size_buckets
			: nb;
		z->start_sector = bucket_to_sector(ca, z->start_bucket);
		z->end_sector = bucket_to_sector(ca, z->end_bucket);
		z->temperature = i; /* zone 0 = hottest (outermost) */

		/* Per-zone allocation cursor starts at zone beginning */
		atomic64_set(&z->alloc_cursor, z->start_bucket);
		atomic64_set(&z->nr_free, z->end_bucket - z->start_bucket);
		atomic64_set(&z->nr_used, 0);
	}

	/* Initialize zone pressure limits */
	for (unsigned i = 0; i < m->nr_zones; i++) {
		/*
		 * Outer zones get lower fill limits to keep headroom
		 * for hot data promotion. Inner zones can fill higher.
		 *
		 * Zone 0: 80%, then linearly increase to 95% at innermost.
		 */
		if (m->nr_zones > 1)
			m->max_fill_pct[i] = 80 + (15 * i) / (m->nr_zones - 1);
		else
			m->max_fill_pct[i] = 95;
	}

	/* Initialize tunables with defaults */
	m->migration_rate = BCH_RADIAL_MIGRATION_RATE_DEFAULT;
	m->heat_decay = BCH_RADIAL_HEAT_DECAY_DEFAULT;
	m->promote_bias = BCH_RADIAL_PROMOTE_BIAS_DEFAULT;
	m->seq_heat_boost = BCH_RADIAL_SEQ_HEAT_BOOST_DEFAULT;

	/* Zero per-zone statistics */
	for (unsigned i = 0; i < BCH_RADIAL_ZONE_MAX; i++) {
		atomic64_set(&m->zone_allocs[i], 0);
		atomic64_set(&m->zone_promotions[i], 0);
		atomic64_set(&m->zone_demotions[i], 0);
		atomic64_set(&m->zone_bytes[i], 0);
	}
}

/* ── Extent heat calculation ──────────────────────────────── */

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
	 */
	unsigned ref_score = refcount > 1 ? ilog2(refcount) : 0;

	/*
	 * Rewrite rate: penalize recently-written data (high churn).
	 */
	unsigned rewrite_est = 0;
	if (write_time > read_time && write_time - read_time > 0)
		rewrite_est = clamp_t(u64, (write_time - read_time) >> 4, 0, 512);

	unsigned heat = (BCH_HEAT_READ_WEIGHT * read_freq +
			 BCH_HEAT_REFCOUNT_WEIGHT * ref_score * 256) >> 8;

	unsigned penalty = (BCH_HEAT_REWRITE_PENALTY * rewrite_est) >> 8;

	heat = heat > penalty ? heat - penalty : 0;

	return min_t(unsigned, heat, BCH_HEAT_MAX);
}

/* ── Radial zone classification ───────────────────────────── */

u8 bch2_heat_to_radial_zone(const struct bch_dev *ca, unsigned heat,
			     enum bch_data_type data_type)
{
	const struct bch_radial_map *m = &ca->radial_map;

	/* Metadata always goes to zone 0 (outermost) */
	if (data_type == BCH_DATA_btree ||
	    data_type == BCH_DATA_sb ||
	    data_type == BCH_DATA_journal)
		return 0;

	if (!m->nr_zones)
		return 0;

	/*
	 * Map heat to zone: higher heat → lower zone number (outermost).
	 * heat = BCH_HEAT_MAX → zone 0
	 * heat = 0            → zone nr_zones - 1
	 */
	unsigned clamped_heat = min_t(unsigned, heat, BCH_HEAT_MAX);
	u8 zone = m->nr_zones - 1 -
		  (u8)div_u64((u64)clamped_heat * (m->nr_zones - 1), BCH_HEAT_MAX);

	return min_t(u8, zone, m->nr_zones - 1);
}

u8 bch2_classify_radial_zone(const struct bch_alloc_v4 *a,
			     const struct bch_dev *ca,
			     enum bch_data_type data_type)
{
	unsigned heat = bch2_extent_heat(a, ca);
	return bch2_heat_to_radial_zone(ca, heat, data_type);
}

u8 bch2_select_write_radial_zone(const struct bch_dev *ca,
				 enum bch_data_type data_type,
				 bool is_copygc)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (!m->nr_zones)
		return 0;

	/* Metadata always goes to outermost */
	if (data_type == BCH_DATA_btree ||
	    data_type == BCH_DATA_sb ||
	    data_type == BCH_DATA_journal)
		return 0;

	/* CopyGC relocation: default to middle, overridden per-extent */
	if (is_copygc)
		return m->nr_zones / 2;

	/*
	 * New user writes land in the outer-middle zone.
	 * They will migrate outward if hot, or inward if cold.
	 */
	return m->nr_zones / 4;
}

/* ── Sequential heat boost ─────────────────────────────────── */

u8 bch2_select_seq_write_radial_zone(const struct bch_dev *ca)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (!m->nr_zones)
		return 0;

	/*
	 * Sequential writes get a heat boost that pushes them
	 * toward outer (faster) zones. Apply the boost to a
	 * moderate base heat to determine the target zone.
	 */
	unsigned boosted_heat = bch2_radial_seq_heat_boost(ca, BCH_HEAT_MAX / 2);

	return bch2_heat_to_radial_zone(ca, boosted_heat, BCH_DATA_user);
}

/* ── Copygc scoring with radial awareness ─────────────────── */

u64 bch2_radial_copygc_bucket_score(const struct bch_alloc_v4 *a,
				    const struct bch_dev *ca,
				    u64 bucket, u64 now)
{
	/* Fragmentation: ratio of dirty sectors to bucket size */
	u32 dirty = bch2_bucket_sectors_dirty(*a);
	u64 frag = 0;
	if (dirty < ca->mi.bucket_size && dirty > 0)
		frag = div_u64((u64)(ca->mi.bucket_size - dirty) << 8,
			       ca->mi.bucket_size);

	/* Radial zone mismatch */
	u8 current_zone = bch2_bucket_radial_zone(ca, bucket);
	u8 ideal_zone = bch2_classify_radial_zone(a, ca, a->data_type);
	u64 mismatch = 0;

	if (current_zone != ideal_zone) {
		int distance = abs((int)current_zone - (int)ideal_zone);
		mismatch = (u64)distance * 128;
	}

	/* Age: older data gets higher age score */
	u64 age = 0;
	if (now > a->io_time[1])
		age = min_t(u64, (now - a->io_time[1]) >> 8, 256);

	return (BCH_COPYGC_W_FRAG * frag +
		BCH_COPYGC_W_MISMATCH * mismatch +
		BCH_COPYGC_W_AGE * age) >> 8;
}

/* ── Radial zone-aware allocation cursor ──────────────────── */

bool bch2_set_alloc_cursor_radial_zone(struct bch_dev *ca,
				       u8 zone,
				       unsigned btree_bitmap)
{
	struct bch_radial_map *m = &ca->radial_map;

	if (zone >= m->nr_zones)
		return false;

	struct bch_radial_zone *z = &m->zones[zone];

	if (z->start_bucket >= z->end_bucket)
		return false;

	/*
	 * Use the per-zone atomic cursor for sequential allocation.
	 * Advance the cursor and wrap within zone bounds.
	 */
	u64 cursor = (u64)atomic64_fetch_add(1, &z->alloc_cursor);
	if (cursor >= z->end_bucket) {
		atomic64_set(&z->alloc_cursor, z->start_bucket);
		cursor = z->start_bucket;
	}

	ca->alloc_cursor[btree_bitmap] = cursor;
	return true;
}

/* ── Zone pressure ────────────────────────────────────────── */

bool bch2_radial_zone_pressure(const struct bch_dev *ca, u8 zone)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (zone >= m->nr_zones)
		return false;

	const struct bch_radial_zone *z = &m->zones[zone];

	/*
	 * Check if this zone has exceeded its fill limit.
	 * Use per-zone nr_used/total ratio for fill level.
	 */
	u64 zone_total = z->end_bucket - z->start_bucket;
	u64 zone_used = (u64)atomic64_read(&z->nr_used);

	if (!zone_total)
		return false;

	u64 fill_pct = div_u64(zone_used * 100, zone_total);

	return fill_pct >= m->max_fill_pct[zone];
}

/* ── Stats output ─────────────────────────────────────────── */

void bch2_dev_radial_stats_to_text(struct printbuf *out,
				   const struct bch_dev *ca)
{
	const struct bch_radial_map *m = &ca->radial_map;

	prt_printf(out, "radial zones: %u\n", m->nr_zones);
	prt_printf(out, "zone size: %llu buckets (%llu sectors)\n",
		   m->zone_size_buckets, m->zone_size_sectors);
	prt_newline(out);

	printbuf_tabstop_push(out, 8);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 8);

	prt_printf(out, "zone\tstart\tend\tallocs\tpromote\tdemote\tfree\tused\tcursor\tfill%%\n");

	for (unsigned i = 0; i < m->nr_zones; i++) {
		const struct bch_radial_zone *z = &m->zones[i];

		prt_printf(out, "%u\t%llu\t%llu\t",
			   i, z->start_bucket, z->end_bucket);
		prt_printf(out, "%llu\t", atomic64_read(&m->zone_allocs[i]));
		prt_printf(out, "%llu\t", atomic64_read(&m->zone_promotions[i]));
		prt_printf(out, "%llu\t", atomic64_read(&m->zone_demotions[i]));
		prt_printf(out, "%lld\t", atomic64_read(&z->nr_free));
		prt_printf(out, "%lld\t", atomic64_read(&z->nr_used));
		prt_printf(out, "%lld\t", atomic64_read(&z->alloc_cursor));
		prt_printf(out, "%u%%\n", m->max_fill_pct[i]);
	}
}

void bch2_fs_radial_stats_to_text(struct printbuf *out,
				  struct bch_fs *c)
{
	prt_printf(out, "Radial temperature zone stats:\n");
	prt_newline(out);

	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL) {
		if (!ca->mi.rotational)
			continue;

		prt_printf(out, "Device %s (rotational, %u radial zones):\n",
			   ca->name, ca->radial_map.nr_zones);
		bch2_dev_radial_stats_to_text(out, ca);
		prt_newline(out);
	}
}
