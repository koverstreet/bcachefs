/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_INTERIOR_TYPES_H
#define _BCACHEFS_BTREE_INTERIOR_TYPES_H

struct btree_alloc {
	struct open_buckets	ob;
	__BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX);
};

/* Maximum number of nodes we might need to allocate atomically: */
#define BTREE_RESERVE_MAX	(BTREE_MAX_DEPTH + (BTREE_MAX_DEPTH - 1))

/* Size of the freelist we allocate btree nodes from: */
#define BTREE_NODE_RESERVE	(BTREE_RESERVE_MAX * 4)

/*
 * Cache of allocated btree nodes - if we allocate a btree node and don't use
 * it, if we free it that space can't be reused until going _all_ the way
 * through the allocator (which exposes us to a livelock when allocating btree
 * reserves fail halfway through) - instead, we can stick them here:
 */
struct bch_fs_btree_reserve_cache {
	struct mutex		lock;
	unsigned		nr;
	struct btree_alloc	data[BTREE_NODE_RESERVE * 2];
};

struct bch_fs_btree_interior_updates {
	mempool_t		pool;
	struct list_head	list;
	struct list_head	unwritten;
	struct mutex		lock;
	struct mutex		commit_lock;
	struct closure_waitlist	wait;

	struct workqueue_struct	*worker;
	struct work_struct	work;
};

struct bch_fs_btree_node_rewrites {
	struct list_head	list;
	struct list_head	pending;
	spinlock_t		lock;
	struct closure_waitlist	wait;
	struct workqueue_struct	*worker;
};

#endif /* _BCACHEFS_BTREE_INTERIOR_TYPES_H */
