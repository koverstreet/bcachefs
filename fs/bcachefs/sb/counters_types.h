/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_COUNTERS_TYPES_H
#define _BCACHEFS_SB_COUNTERS_TYPES_H

struct bch_fs_counters {
	u64			mount[BCH_COUNTER_NR];
	u64 __percpu		*now;
};

#endif /* _BCACHEFS_SB_COUNTERS_TYPES_H */
