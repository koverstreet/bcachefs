/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_COUNTERS_TYPES_H
#define _BCACHEFS_SB_COUNTERS_TYPES_H

struct bch_fs_counters {
	u64			mount[BCH_COUNTER_NR];
	u64 __percpu		*now;

#define NR_RECENT_COUNTERS	20

	u64			recent[NR_RECENT_COUNTERS][BCH_COUNTER_NR];
	struct delayed_work	work;
};

#endif /* _BCACHEFS_SB_COUNTERS_TYPES_H */
