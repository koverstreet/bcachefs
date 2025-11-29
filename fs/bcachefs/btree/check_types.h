/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_GC_TYPES_H
#define _BCACHEFS_BTREE_GC_TYPES_H

#include "btree/bbpos_types.h"

#include <linux/generic-radix-tree.h>

#define GC_PHASES()		\
	x(not_running)		\
	x(start)		\
	x(sb)			\
	x(btree)

enum gc_phase {
#define x(n)	GC_PHASE_##n,
	GC_PHASES()
#undef x
};

struct gc_pos {
	enum gc_phase		phase:8;
	enum btree_id		btree:8;
	u16			level;
	struct bpos		pos;
};

struct reflink_gc {
	u64		offset;
	u32		size;
	u32		refcount;
};

typedef GENRADIX(struct reflink_gc) reflink_gc_table;

struct bch_fs_gc {
	seqcount_t		pos_lock;
	struct gc_pos		pos;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress.
	 */
	struct rw_semaphore	lock;
};

struct bch_fs_gc_gens {
	struct bbpos		pos;
	struct work_struct	work;
	struct mutex		lock;
};

#endif /* _BCACHEFS_BTREE_GC_TYPES_H */
