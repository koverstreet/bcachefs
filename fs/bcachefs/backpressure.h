/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BACKPRESSURE_H
#define _BCACHEFS_BACKPRESSURE_H

#include "closure.h"

struct bch_fs;
struct bch_dev;

/*
 * Backpressure sources are split into two scopes:
 *
 *   FS types: one packed state on bch_fs.backpressure (journal, btree,
 *     fs-wide allocator pools).
 *   DEV types: one packed state on bch_dev.backpressure, per device
 *     (per-device allocator counters).
 *
 * Each macro takes an adapter so call sites can plug into the same x-macro
 * — e.g. BCH_TIME_STATS folds the FS entries in via BCH_BACKPRESSURE_FS_TYPES.
 */
#define BCH_BACKPRESSURE_FS_TYPES(_x)					\
	_x(journal_pin,							\
	   "Insufficient available entries in the journal pin fifo")	\
	_x(journal_space,						\
	   "Insufficient available journal space on disk")		\
	_x(open_buckets,						\
	   "Insufficient open bucket handles")				\
	_x(btree_write_buffer,						\
	   "Flushing from the btree write buffer")			\
	_x(btree_key_cache,						\
	   "Btree key cache dirty percentage too high")			\
	_x(btree_node_cache,						\
	   "Btree node cache dirty percentage too high")		\
	_x(btree_node_writes,						\
	   "Too many btree node writes in flight")

#define BCH_BACKPRESSURE_DEV_TYPES(_x)					\
	_x(discards,							\
	   "Transitioning buckets from BCH_DATA_need_discard -> free")	\
	_x(invalidates,							\
	   "Invalidating buckets containing cached data")		\
	_x(copygc,							\
	   "Compacting fragmented buckets")

enum bch_backpressure_fs_type {
#define x(n, ...)	BCH_BACKPRESSURE_FS_##n,
	BCH_BACKPRESSURE_FS_TYPES(x)
#undef x
	BCH_BACKPRESSURE_FS_NR
};

enum bch_backpressure_dev_type {
#define x(n, ...)	BCH_BACKPRESSURE_DEV_##n,
	BCH_BACKPRESSURE_DEV_TYPES(x)
#undef x
	BCH_BACKPRESSURE_DEV_NR
};

enum bch_backpressure_level {
	BCH_BACKPRESSURE_LEVEL_none,
	BCH_BACKPRESSURE_LEVEL_lo,
	BCH_BACKPRESSURE_LEVEL_hi,
	BCH_BACKPRESSURE_LEVEL_NR,
};

/*
 * Processes (background tasks + foreground) that interact with backpressure
 * sources. Each declares an identity at trans_get(); bch2_backpressure_wait()
 * uses the (process, bp_type, level) profile to decide whether to park.
 */
#define BCH_PROCESSES()								\
	x(foreground,			"Foreground / user op")			\
	x(reconcile,			"Reconcile / data movement")		\
	x(discard,			"Discard worker")			\
	x(invalidate,			"Invalidate worker")			\
	x(copygc,			"copygc")				\
	x(journal_reclaim,		"Journal reclaim")			\
	x(btree_interior_updates,	"Interior btree updates")		\
	x(key_cache_flush,		"Btree key cache flush")		\
	x(write_buffer_flush,		"Btree write buffer flush")

enum bch_process {
#define x(name, ...)	BCH_PROCESS_##name,
	BCH_PROCESSES()
#undef x
	BCH_PROCESS_NR
};

/*
 * Used at fs scope (bch_fs.backpressure) and dev scope (bch_dev.backpressure).
 * @state is 2 bits per type, packed; @wait is only consumed at fs scope —
 * dev-side state changes wake the parent fs's queue, since waiters typically
 * care about both scopes together.
 */
struct bch_backpressure {
	unsigned long		state;
	struct closure_waitlist	wait;
};

enum bch_backpressure_level
__bch2_backpressure_fs_set(struct bch_fs *,
			   enum bch_backpressure_fs_type,
			   enum bch_backpressure_level);
enum bch_backpressure_level
__bch2_backpressure_dev_set(struct bch_dev *,
			    enum bch_backpressure_dev_type,
			    enum bch_backpressure_level);

static inline enum bch_backpressure_level
__bch2_backpressure_state_get(const struct bch_backpressure *bp, unsigned type)
{
	return (READ_ONCE(bp->state) >> (type * 2)) & 3;
}

/*
 * Fast path: clamp to LEVEL_hi and skip the slow cmpxchg path when the
 * stored level isn't changing. The READ_ONCE is racy vs concurrent setters,
 * but the slow path's cmpxchg loop has its own old==new early-return so a
 * lost race here just costs one extra call.
 */
#define bch2_backpressure_fs_set(_c, _type, _new_level)				\
({										\
	enum bch_backpressure_level _nl =					\
		min_t(enum bch_backpressure_level, (_new_level),		\
		      BCH_BACKPRESSURE_LEVEL_hi);				\
	enum bch_backpressure_level _ol =					\
		__bch2_backpressure_state_get(&(_c)->backpressure, (_type));	\
	_ol == _nl ? _ol : __bch2_backpressure_fs_set(_c, _type, _nl);		\
})

#define bch2_backpressure_dev_set(_ca, _type, _new_level)			\
({										\
	enum bch_backpressure_level _nl =					\
		min_t(enum bch_backpressure_level, (_new_level),		\
		      BCH_BACKPRESSURE_LEVEL_hi);				\
	enum bch_backpressure_level _ol =					\
		__bch2_backpressure_state_get(&(_ca)->backpressure, (_type));	\
	_ol == _nl ? _ol : __bch2_backpressure_dev_set(_ca, _type, _nl);	\
})

bool bch2_backpressure_check(struct bch_fs *, enum bch_process);
void bch2_backpressure_wait(struct bch_fs *, enum bch_process);

#endif /* _BCACHEFS_BACKPRESSURE_H */
