/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_COPYGC_TYPES_H
#define _BCACHEFS_COPYGC_TYPES_H

#include "alloc/zone_types.h"

struct bch_fs_copygc {
	struct task_struct __rcu *thread;
	struct write_point	write_point;

	/*
	 * Radial zone write points for copygc relocation.
	 * Each radial zone gets its own write stream to prevent mixing
	 * data of different temperatures in the same buckets.
	 */
	struct write_point	radial_write_points[BCH_RADIAL_ZONE_MAX];

	s64			wait_at;
	s64			wait;
	bool			running;
	u32			run_count;
	wait_queue_head_t	running_wq;

	/* Dedicated workqueue for btree updates: */
	struct workqueue_struct	*wq;
};

#endif /* _BCACHEFS_COPYGC_TYPES_H */

