/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_ZONE_TYPES_H
#define _BCACHEFS_ALLOC_ZONE_TYPES_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * LBA-based zone layout for HDD-optimized allocation.
 *
 * Lower LBAs correspond to outer tracks on spinning disks, which have higher
 * sequential throughput. We partition each device into four zones based on LBA
 * position, then steer data to the appropriate zone based on its access pattern
 * and temperature.
 *
 * Default boundaries (as percentage of device LBA range):
 *   0% – 10%   HOT_READ   - frequently read, stable data (outer tracks)
 *   10% – 15%  HOT_WRITE  - new writes, high churn (write buffer)
 *   15% – 65%  WARM       - actively used data, transition layer
 *   65% – 100% COLD       - cold/archival data (inner tracks)
 */

#define BCH_ZONES()			\
	x(hot_read,	0)		\
	x(hot_write,	1)		\
	x(warm,		2)		\
	x(cold,		3)

enum bch_zone {
#define x(name, val)	BCH_ZONE_##name = val,
	BCH_ZONES()
#undef x
	BCH_ZONE_NR,
};

static inline const char *bch2_zone_name(enum bch_zone z)
{
	static const char * const names[] = {
#define x(name, val) [val] = #name,
		BCH_ZONES()
#undef x
	};
	return z < BCH_ZONE_NR ? names[z] : "unknown";
}

/* Default zone boundary percentages (0-100 scale) */
#define BCH_ZONE_HOT_READ_END_PCT	10
#define BCH_ZONE_HOT_WRITE_END_PCT	15
#define BCH_ZONE_WARM_END_PCT		65
/* COLD runs from WARM_END to 100% */

/*
 * Tuning weights for extent heat calculation.
 * Values are fixed-point with 8 fractional bits (i.e., 256 = 1.0).
 */
#define BCH_HEAT_READ_WEIGHT		256	/* 1.0 */
#define BCH_HEAT_REFCOUNT_WEIGHT	384	/* 1.5 */
#define BCH_HEAT_REWRITE_PENALTY	128	/* 0.5 */

/* Threshold for considering an extent "shared" (dedup) */
#define BCH_SHARED_REFCOUNT_THRESHOLD	2

/* Heat thresholds for classification (fixed point, 8-bit frac) */
#define BCH_HEAT_HOT_THRESHOLD		512	/* above = hot */
#define BCH_HEAT_WARM_THRESHOLD		128	/* above = warm, below = cold */

/* Minimum interval between relocations of the same extent (seconds) */
#define BCH_ZONE_RELOCATION_COOLDOWN	300

/*
 * copygc victim scoring weights (fixed point, 8-bit frac).
 */
#define BCH_COPYGC_W_FRAG		256	/* fragmentation weight */
#define BCH_COPYGC_W_MISMATCH		384	/* zone-mismatch weight */
#define BCH_COPYGC_W_AGE		64	/* age weight */

/*
 * Per-device zone boundary cache, computed at mount or calibration time.
 * Stored as bucket numbers for fast lookup.
 */
struct bch_dev_zones {
	u64			boundary[BCH_ZONE_NR]; /* first bucket of each zone */
	u64			boundary_sector[BCH_ZONE_NR]; /* first sector */

	/* Runtime stats (atomic for lock-free updates) */
	atomic64_t		bytes[BCH_ZONE_NR];
	atomic64_t		extents[BCH_ZONE_NR];
	atomic64_t		shared_extents[BCH_ZONE_NR];
	atomic64_t		copygc_moved_in[BCH_ZONE_NR];
	atomic64_t		copygc_moved_out[BCH_ZONE_NR];
	atomic64_t		fragmented[BCH_ZONE_NR];
};

/*
 * Per-extent tracking fields added to the in-memory alloc_v4.
 * These are approximations — not fully persisted, but re-estimable.
 */
struct bch_extent_heat_state {
	u16			read_frequency;		/* decaying counter */
	u16			rewrite_rate;		/* copygc/overwrite counter */
	u32			last_move_time;		/* jiffies of last relocation */
};

#endif /* _BCACHEFS_ALLOC_ZONE_TYPES_H */
