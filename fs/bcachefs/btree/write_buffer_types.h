/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_WRITE_BUFFER_TYPES_H
#define _BCACHEFS_BTREE_WRITE_BUFFER_TYPES_H

#include <linux/workqueue.h>

#include "util/darray.h"
#include "journal/types.h"

/*
 * Subset of BCH_BTREE_IDS() that are marked BTREE_IS_write_buffer, enumerated
 * densely so we can size per-btree write buffer state as a compact array. Must
 * be kept in sync with BCH_BTREE_IDS() — adding BTREE_IS_write_buffer to a new
 * btree requires a matching entry here.
 */
#define BCH_WRITE_BUFFER_BTREES()	\
	x(lru)				\
	x(need_discard)			\
	x(backpointers)			\
	x(deleted_inodes)		\
	x(reconcile_work)		\
	x(accounting)			\
	x(reconcile_hipri)		\
	x(reconcile_pending)		\
	x(reconcile_work_phys)		\
	x(reconcile_hipri_phys)		\
	x(stripe_backpointers)

enum bch_wb_btree {
#define x(name)	BCH_WB_BTREE_##name,
	BCH_WRITE_BUFFER_BTREES()
#undef x
	BCH_WB_BTREE_NR,
};

#define BTREE_WRITE_BUFERED_VAL_U64s_MAX	4

/*
 * Each bch_fs_btree_write_buffer is per-btree, so individual key entries don't
 * need to carry a btree id — it's implicit in the containing buffer.
 */
struct wb_key_ref {
union {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		u32				idx;
		u8				pos[sizeof(struct bpos)];
#else
		u8				pos[sizeof(struct bpos)];
		u32				idx;
#endif
	} __packed;
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		u64 lo;
		u64 mi;
		u64 hi;
#else
		u64 hi;
		u64 mi;
		u64 lo;
#endif
	};
};
};

struct btree_write_buffered_key {
	u64				journal_seq;

	/* BTREE_WRITE_BUFERED_VAL_U64s_MAX only applies to accounting keys */
	__BKEY_PADDED(k, BTREE_WRITE_BUFERED_VAL_U64s_MAX);
};

struct btree_write_buffer_keys {
	darray_u64			keys;
	struct journal_entry_pin	pin;
	struct mutex			lock;
	/*
	 * Back-references set at init so the journal-pin callback can recover
	 * which btree (and which of inc/flushing) a firing pin belongs to.
	 */
	enum bch_wb_btree		wb_btree;
	bool				is_flushing;
};

#define WB_FLUSH_CALLERS()		\
	x(thread)			\
	x(journal_pin)			\
	x(sync)				\
	x(maybe)			\
	x(tryflush)

enum wb_flush_caller {
#define x(n)	WB_FLUSH_##n,
	WB_FLUSH_CALLERS()
#undef x
	WB_FLUSH_NR,
};

struct bch_fs_btree_write_buffer {
	/* Back-refs set at init so the flush thread can find c and its idx. */
	struct bch_fs			*c;
	enum bch_wb_btree		idx;

	DARRAY(struct wb_key_ref)	sorted;
	struct btree_write_buffer_keys	inc;
	struct btree_write_buffer_keys	flushing;

	struct work_struct		flush_work;
	/*
	 * Set by the dispatcher (or auto-flush wakeup) before queue_work(),
	 * read by the worker on each flush_locked call. Racy under concurrent
	 * dispatchers — accepted; this only feeds the diagnostic
	 * nr_flushes_caller[] histogram.
	 */
	enum wb_flush_caller		flush_work_caller;

	u64				nr_flushes;
	u64				nr_flushes_caller[WB_FLUSH_NR];
	u64				nr_keys_flushed;
	u64				nr_keys_fast;
	u64				nr_keys_slowpath;

	DARRAY(struct btree_write_buffered_key) accounting;
};

#endif /* _BCACHEFS_BTREE_WRITE_BUFFER_TYPES_H */
