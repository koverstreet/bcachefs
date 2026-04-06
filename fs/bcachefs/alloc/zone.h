/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_ZONE_H
#define _BCACHEFS_ALLOC_ZONE_H

#include "alloc/zone_types.h"
#include "alloc/buckets.h"
#include "sb/members.h"

struct bch_fs;
struct bch_dev;
struct bch_alloc_v4;

/* ── Zone boundary computation ────────────────────────────── */

/*
 * Compute zone boundaries for a device based on its bucket count.
 * Called at mount time and after runtime calibration.
 */
void bch2_dev_zones_init(struct bch_dev *ca);

/*
 * Return the zone a bucket belongs to, based on its bucket number.
 */
static inline enum bch_zone bch2_bucket_zone(const struct bch_dev *ca, u64 bucket)
{
	if (bucket < ca->zones.boundary[BCH_ZONE_hot_write])
		return BCH_ZONE_hot_read;
	if (bucket < ca->zones.boundary[BCH_ZONE_warm])
		return BCH_ZONE_hot_write;
	if (bucket < ca->zones.boundary[BCH_ZONE_cold])
		return BCH_ZONE_warm;
	return BCH_ZONE_cold;
}

/*
 * Return the zone a sector address belongs to.
 */
static inline enum bch_zone bch2_sector_zone(const struct bch_dev *ca, u64 sector)
{
	if (sector < ca->zones.boundary_sector[BCH_ZONE_hot_write])
		return BCH_ZONE_hot_read;
	if (sector < ca->zones.boundary_sector[BCH_ZONE_warm])
		return BCH_ZONE_hot_write;
	if (sector < ca->zones.boundary_sector[BCH_ZONE_cold])
		return BCH_ZONE_warm;
	return BCH_ZONE_cold;
}

/* ── Extent heat + classification ─────────────────────────── */

/*
 * Compute a heat score for data at a given bucket.
 * Uses io_time[] from alloc_v4 as a rough proxy for read frequency.
 */
unsigned bch2_extent_heat(const struct bch_alloc_v4 *a,
			  const struct bch_dev *ca);

/*
 * Classify an extent into the zone it *should* be in, based on
 * its heat, refcount, and data type.
 */
enum bch_zone bch2_classify_extent(const struct bch_alloc_v4 *a,
				   const struct bch_dev *ca,
				   enum bch_data_type data_type);

/*
 * Select the zone for a new write, based on data type (metadata vs user vs copygc).
 */
enum bch_zone bch2_select_write_zone(enum bch_data_type data_type,
				     bool is_copygc);

/* ── Zone-mismatch scoring for copygc ─────────────────────── */

/*
 * Returns nonzero if a bucket's data is in the wrong zone.
 * Used as a victim selection signal for copygc.
 */
unsigned bch2_zone_mismatch_score(const struct bch_alloc_v4 *a,
				  const struct bch_dev *ca);

/*
 * Full copygc victim score incorporating fragmentation, zone mismatch, and age.
 */
u64 bch2_zone_copygc_score(const struct bch_alloc_v4 *a,
			   const struct bch_dev *ca,
			   u64 now);

/*
 * Full score with explicit bucket number (preferred variant).
 */
u64 bch2_zone_copygc_bucket_score(const struct bch_alloc_v4 *a,
				  const struct bch_dev *ca,
				  u64 bucket, u64 now);

/*
 * Check if an extent was recently relocated (within cooldown period).
 */
static inline bool bch2_recently_moved(const struct bch_alloc_v4 *a, u64 now)
{
	/*
	 * Use io_time[WRITE] as the last-move timestamp proxy.
	 * If the write was less than BCH_ZONE_RELOCATION_COOLDOWN ago,
	 * suppress re-relocation.
	 */
	return (now - a->io_time[1]) < BCH_ZONE_RELOCATION_COOLDOWN;
}

/* ── Bucket range helpers ─────────────────────────────────── */

/*
 * Return the first and last+1 bucket of a zone on a given device.
 */
static inline void bch2_zone_bucket_range(const struct bch_dev *ca,
					  enum bch_zone zone,
					  u64 *start, u64 *end)
{
	*start = ca->zones.boundary[zone];
	*end = (zone + 1 < BCH_ZONE_NR)
		? ca->zones.boundary[zone + 1]
		: ca->mi.nbuckets;
}

/* ── Zone-aware allocation cursor ─────────────────────────── */

/*
 * Set the allocation cursor to prefer buckets within a specific zone.
 * Returns true if the cursor was adjusted.
 */
bool bch2_set_alloc_cursor_zone(struct bch_dev *ca,
				enum bch_zone zone,
				unsigned btree_bitmap);

/* ── Stats ─────────────────────────────────────────────────── */

void bch2_dev_zone_stats_to_text(struct printbuf *out,
				 const struct bch_dev *ca);
void bch2_fs_zone_stats_to_text(struct printbuf *out,
				struct bch_fs *c);

#endif /* _BCACHEFS_ALLOC_ZONE_H */
