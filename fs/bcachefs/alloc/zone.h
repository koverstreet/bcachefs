/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_ZONE_H
#define _BCACHEFS_ALLOC_ZONE_H

#include "alloc/zone_types.h"
#include "alloc/buckets.h"
#include "sb/members.h"

struct bch_fs;
struct bch_dev;
struct bch_alloc_v4;

/* ── Radial zone geometry ─────────────────────────────────── */

/*
 * Compute radial zone geometry for a device.
 * Called at mount time. Divides the LBA space into N radial zones
 * where zone 0 is outermost (hottest) and zone N-1 is innermost (coldest).
 */
void bch2_dev_radial_zones_init(struct bch_dev *ca);

/*
 * Return the radial zone a bucket belongs to.
 * Zone 0 = outermost (lowest LBA), zone N-1 = innermost.
 */
static inline u8 bch2_bucket_radial_zone(const struct bch_dev *ca, u64 bucket)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (!m->nr_zones || !m->zone_size_buckets)
		return 0;

	u64 offset = bucket - ca->mi.first_bucket;
	u8 zone = div_u64(offset, m->zone_size_buckets);

	return min_t(u8, zone, m->nr_zones - 1);
}

/*
 * Return the radial zone a sector address belongs to.
 */
static inline u8 bch2_sector_radial_zone(const struct bch_dev *ca, u64 sector)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (!m->nr_zones || !m->zone_size_sectors)
		return 0;

	u8 zone = div_u64(sector, m->zone_size_sectors);

	return min_t(u8, zone, m->nr_zones - 1);
}

/* ── Extent heat + radial classification ──────────────────── */

/*
 * Compute a heat score for data at a given bucket.
 * Uses io_time[] from alloc_v4 as a rough proxy for read frequency.
 * Returns a value in fixed-point (8 fractional bits), clamped to BCH_HEAT_MAX.
 */
unsigned bch2_extent_heat(const struct bch_alloc_v4 *a,
			  const struct bch_dev *ca);

/*
 * Map a heat score to a target radial zone.
 * Higher heat → lower zone number (outermost).
 * Metadata always maps to zone 0 (outermost).
 */
u8 bch2_heat_to_radial_zone(const struct bch_dev *ca, unsigned heat,
			     enum bch_data_type data_type);

/*
 * Classify a bucket's data into its ideal radial zone.
 */
u8 bch2_classify_radial_zone(const struct bch_alloc_v4 *a,
			     const struct bch_dev *ca,
			     enum bch_data_type data_type);

/*
 * Select the radial zone for a new write, based on data type.
 */
u8 bch2_select_write_radial_zone(const struct bch_dev *ca,
				 enum bch_data_type data_type,
				 bool is_copygc);

/* ── Zone-mismatch scoring for copygc ─────────────────────── */

/*
 * Full copygc victim score with radial zone awareness.
 */
u64 bch2_radial_copygc_bucket_score(const struct bch_alloc_v4 *a,
				    const struct bch_dev *ca,
				    u64 bucket, u64 now);

/*
 * Check if an extent was recently relocated (within cooldown period).
 */
static inline bool bch2_recently_moved(const struct bch_alloc_v4 *a, u64 now)
{
	return (now - a->io_time[1]) < BCH_ZONE_RELOCATION_COOLDOWN;
}

/* ── Bucket range helpers ─────────────────────────────────── */

/*
 * Return the first and last+1 bucket of a radial zone on a given device.
 */
static inline void bch2_radial_zone_bucket_range(const struct bch_dev *ca,
						 u8 zone,
						 u64 *start, u64 *end)
{
	const struct bch_radial_map *m = &ca->radial_map;

	if (zone >= m->nr_zones) {
		*start = *end = ca->mi.nbuckets;
		return;
	}

	*start = m->zones[zone].start_bucket;
	*end = m->zones[zone].end_bucket;
}

/* ── Zone-aware allocation cursor ─────────────────────────── */

/*
 * Set the allocation cursor to prefer buckets within a specific radial zone.
 * Returns true if the cursor was adjusted.
 */
bool bch2_set_alloc_cursor_radial_zone(struct bch_dev *ca,
				       u8 zone,
				       unsigned btree_bitmap);

/* ── Zone pressure ────────────────────────────────────────── */

/*
 * Check if a radial zone is over its fill pressure limit.
 * Returns true if the zone should spill to the next colder zone.
 */
bool bch2_radial_zone_pressure(const struct bch_dev *ca, u8 zone);

/* ── Sequential heat boost ────────────────────────────────── */

/*
 * Apply a temporary heat increase for sequential I/O patterns.
 * Called from readahead/sequential write paths. Returns the
 * boosted heat score.
 *
 * Sequential workloads naturally migrate outward when this
 * boost is applied. The heat decays over time.
 */
static inline unsigned bch2_radial_seq_heat_boost(const struct bch_dev *ca,
						  unsigned base_heat)
{
	return min_t(unsigned, base_heat + ca->radial_map.seq_heat_boost,
		     BCH_HEAT_MAX);
}

/*
 * Select radial zone for a sequential write pattern.
 * Applies heat boost to push sequential data toward outer zones.
 */
u8 bch2_select_seq_write_radial_zone(const struct bch_dev *ca);

/* ── Stats ─────────────────────────────────────────────────── */

void bch2_dev_radial_stats_to_text(struct printbuf *out,
				   const struct bch_dev *ca);
void bch2_fs_radial_stats_to_text(struct printbuf *out,
				  struct bch_fs *c);

#endif /* _BCACHEFS_ALLOC_ZONE_H */
