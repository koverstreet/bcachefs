/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_ZONE_TYPES_H
#define _BCACHEFS_ALLOC_ZONE_TYPES_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * Radial temperature zoning for HDD-optimized allocation.
 *
 * Lower LBAs correspond to outer tracks on spinning disks, which have higher
 * sequential throughput. We partition each rotational device into N radial
 * zones based on LBA position:
 *
 *   Zone 0   → outermost (fastest, hottest)
 *   Zone N-1 → innermost (slowest, coldest)
 *
 * Zone count scales with device size:
 *   zones = clamp(device_size_bytes >> 40, 2, 255)
 *
 * Data movement is temperature-driven:
 *   - Getting hotter → move outward (lower zone number)
 *   - Cooling        → move inward  (higher zone number)
 *
 * Movement occurs via promote, CopyGC relocation, and aging —
 * not via heavy per-write scoring logic.
 */

#define BCH_RADIAL_ZONE_MIN		2
#define BCH_RADIAL_ZONE_MAX		255

/*
 * Tuning weights for extent heat calculation.
 * Values are fixed-point with 8 fractional bits (i.e., 256 = 1.0).
 */
#define BCH_HEAT_READ_WEIGHT		256	/* 1.0 */
#define BCH_HEAT_REFCOUNT_WEIGHT	384	/* 1.5 */
#define BCH_HEAT_REWRITE_PENALTY	128	/* 0.5 */

/* Threshold for considering an extent "shared" (dedup) */
#define BCH_SHARED_REFCOUNT_THRESHOLD	2

/* Maximum heat value for normalization (fixed point, 8-bit frac) */
#define BCH_HEAT_MAX			1024

/* Minimum interval between relocations of the same extent (seconds) */
#define BCH_ZONE_RELOCATION_COOLDOWN	300

/*
 * copygc victim scoring weights (fixed point, 8-bit frac).
 */
#define BCH_COPYGC_W_FRAG		256	/* fragmentation weight */
#define BCH_COPYGC_W_MISMATCH		384	/* zone-mismatch weight */
#define BCH_COPYGC_W_AGE		64	/* age weight */

/*
 * Default tunable values for radial migration control.
 */
#define BCH_RADIAL_MIGRATION_RATE_DEFAULT	64	/* max migrations per copygc pass */
#define BCH_RADIAL_HEAT_DECAY_DEFAULT		4	/* heat decay shift per aging cycle */
#define BCH_RADIAL_PROMOTE_BIAS_DEFAULT		1	/* zones to jump on promote */
#define BCH_RADIAL_SEQ_HEAT_BOOST_DEFAULT	256	/* heat boost for sequential I/O */

/*
 * Per-radial-zone description.
 * Computed at mount time, never persisted.
 */
struct bch_radial_zone {
	u64			start_bucket;	/* first bucket in this zone */
	u64			end_bucket;	/* first bucket of next zone (exclusive) */
	u64			start_sector;	/* LBA start */
	u64			end_sector;	/* LBA end */
	u8			temperature;	/* 0 = hottest, nr_zones-1 = coldest */

	atomic64_t		alloc_cursor;	/* sequential allocation within zone */
	atomic64_t		nr_free;	/* free buckets in zone */
	atomic64_t		nr_used;	/* used buckets in zone */
};

/*
 * Per-device radial zone map, computed at mount time.
 *
 * Contains the geometry plus per-zone runtime statistics.
 * All runtime-generated — no persistence required.
 */
struct bch_radial_map {
	u8			nr_zones;
	u64			zone_size_buckets;	/* buckets per zone */
	u64			zone_size_sectors;	/* sectors per zone */

	struct bch_radial_zone	zones[BCH_RADIAL_ZONE_MAX];

	/* Per-zone runtime statistics (atomic for lock-free updates) */
	atomic64_t		zone_allocs[BCH_RADIAL_ZONE_MAX];
	atomic64_t		zone_promotions[BCH_RADIAL_ZONE_MAX];
	atomic64_t		zone_demotions[BCH_RADIAL_ZONE_MAX];
	atomic64_t		zone_bytes[BCH_RADIAL_ZONE_MAX];

	/* Zone pressure control: max fill percentage per zone */
	u8			max_fill_pct[BCH_RADIAL_ZONE_MAX];

	/* Tunables */
	unsigned		migration_rate;
	unsigned		heat_decay;
	unsigned		promote_bias;
	unsigned		seq_heat_boost;
};

#endif /* _BCACHEFS_ALLOC_ZONE_TYPES_H */
