#ifndef _BCACHE_BTREE_INSERT_H
#define _BCACHE_BTREE_INSERT_H

#include "btree_cache.h"
#include "btree_iter.h"
#include "buckets.h"

struct cache_set;
struct bkey_format_state;
struct bkey_format;
struct btree;

struct btree_reserve {
	struct disk_reservation	disk_res;
	unsigned		nr;
	struct btree		*b[];
};

#define BTREE_RESERVE_SIZE						\
	(sizeof(struct btree_reserve) +					\
	 sizeof(struct btree *) * BTREE_RESERVE_MAX)

void __bch_btree_calc_format(struct bkey_format_state *, struct btree *);
bool bch_btree_node_format_fits(struct btree *, struct bkey_format *);

/* Btree node freeing/allocation: */

/*
 * Tracks a btree node that has been (or is about to be) freed in memory, but
 * has _not_ yet been freed on disk (because the write that makes the new
 * node(s) visible and frees the old hasn't completed yet)
 */
struct pending_btree_node_free {
	struct list_head	list;
	bool			index_update_done;

	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
};

/*
 * Tracks an in progress split/rewrite of a btree node and the update to the
 * parent node:
 *
 * When we split/rewrite a node, we do all the updates in memory without
 * waiting for any writes to complete - we allocate the new node(s) and update
 * the parent node, possibly recursively up to the root.
 *
 * The end result is that we have one or more new nodes being written -
 * possibly several, if there were multiple splits - and then a write (updating
 * an interior node) which will make all these new nodes visible.
 *
 * Additionally, as we split/rewrite nodes we free the old nodes - but the old
 * nodes can't be freed (their space on disk can't be reclaimed) until the
 * update to the interior node that makes the new node visible completes -
 * until then, the old nodes are still reachable on disk.
 *
 */
struct async_split {
	struct closure			cl;

	struct cache_set		*c;

	enum {
		ASYNC_SPLIT_NO_UPDATE,
		ASYNC_SPLIT_UPDATING_BTREE,
		ASYNC_SPLIT_UPDATING_ROOT,
		ASYNC_SPLIT_UPDATING_AS,
	} mode;

	/*
	 * ASYNC_SPLIT_UPDATING_BTREE:
	 * @b - node we're blocking from being written
	 * @list - corresponds to @b->write_blocked
	 */
	struct btree			*b;
	struct list_head		list;

	/*
	 * ASYNC_SPLIT_UPDATING_AS: btree node we updated was freed, so now
	 * we're now blocking another async_split
	 * @parent_as - async_split that's waiting on our nodes to finish
	 * writing, before it can make new nodes visible on disk
	 * @wait - list of child async_splits that are waiting on this
	 * async_split to make all the new nodes visible before they can free
	 * their old btree nodes
	 */
	struct async_split		*parent_as;
	struct closure_waitlist		wait;

	struct journal_entry_pin	journal;

	struct pending_btree_node_free	pending[BTREE_MAX_DEPTH + GC_MERGE_NODES];
	unsigned			nr_pending;

	/* Only here to reduce stack usage on recursive splits: */
	struct keylist			parent_keys;
	/*
	 * Enough room for btree_split's keys without realloc - btree node
	 * pointers never have crc/compression info, so we only need to acount
	 * for the pointers for three keys
	 */
	u64				inline_keys[BKEY_BTREE_PTR_U64s_MAX * 3];
};

void bch_btree_node_free_start(struct cache_set *, struct async_split *,
			       struct btree *);

void bch_btree_node_free_inmem(struct btree_iter *, struct btree *);
void bch_btree_node_free_never_inserted(struct cache_set *, struct btree *);

void btree_open_bucket_put(struct cache_set *c, struct btree *);

struct btree *__btree_node_alloc_replacement(struct cache_set *,
					     struct btree *,
					     struct bkey_format,
					     struct btree_reserve *);
struct btree *btree_node_alloc_replacement(struct cache_set *, struct btree *,
					   struct btree_reserve *);

struct async_split *__bch_async_split_alloc(struct btree *[], unsigned,
					    struct btree_iter *);
struct async_split *bch_async_split_alloc(struct btree *, struct btree_iter *);

void bch_btree_set_root_initial(struct cache_set *, struct btree *,
				struct btree_reserve *);

void bch_btree_reserve_put(struct cache_set *, struct btree_reserve *);
struct btree_reserve *bch_btree_reserve_get(struct cache_set *c,
					    struct btree *,
					    struct btree_iter *,
					    unsigned, bool);

int bch_btree_root_alloc(struct cache_set *, enum btree_id, struct closure *);

/* Inserting into a given leaf node (last stage of insert): */

void bch_btree_bset_insert(struct btree_iter *, struct btree *,
			   struct btree_node_iter *, struct bkey_i *);
void bch_btree_insert_and_journal(struct btree_iter *, struct bkey_i *,
				  struct journal_res *);

static inline struct btree_node_entry *write_block(struct cache_set *c,
						   struct btree *b)
{
	EBUG_ON(!b->written);

	return (void *) b->data + (b->written << (c->block_bits + 9));
}

static inline size_t bch_btree_keys_u64s_remaining(struct cache_set *c,
						   struct btree *b)
{
	struct bset *i = btree_bset_last(b);

	BUG_ON((PAGE_SIZE << b->keys.page_order) <
	       (bset_byte_offset(b, i) + __set_bytes(i, le16_to_cpu(i->u64s))));

	if (b->written == btree_blocks(c))
		return 0;

#if 1
	EBUG_ON(i != (b->written
		      ? &write_block(c, b)->keys
		      : &b->data->keys));

	return ((PAGE_SIZE << b->keys.page_order) -
		(bset_byte_offset(b, i) + __set_bytes(i, le16_to_cpu(i->u64s)))) /
		sizeof(u64);
#else
	/*
	 * first bset is embedded in a struct btree_node, not a
	 * btree_node_entry, so write_block() when b->written == 0 doesn't
	 * work... ugh
	 */

	if (!b->written ||
	    &write_block(c, b)->keys == i)
		return ((PAGE_SIZE << b->keys.page_order) -
			(bset_byte_offset(b, i) + set_bytes(i))) /
			sizeof(u64);

	/* haven't initialized the next bset: */

	BUG_ON(&write_block(c, b)->keys < i);

	BUG_ON(!b->written);

	return ((((btree_blocks(c) - b->written) <<
		  (c->block_bits + 9)) -
		 sizeof(struct btree_node_entry)) /
		sizeof(u64));

	return b->written < btree_blocks(c);
#endif
}

void bch_btree_insert_node(struct btree *, struct btree_iter *,
			   struct keylist *, struct btree_reserve *,
			   struct async_split *as);

/* Normal update interface: */

/*
 * Don't drop/retake locks: instead return -EINTR if need to upgrade to intent
 * locks, -EAGAIN if need to wait on btree reserve
 */
#define BTREE_INSERT_ATOMIC		(1 << 0)

/* Don't check for -ENOSPC: */
#define BTREE_INSERT_NOFAIL		(1 << 1)

/*
 * Don't account key being insert (bch_mark_key) - only for journal replay,
 * where we've already marked the new keys:
 */
#define BTREE_INSERT_NO_MARK_KEY	(1 << 2)

int bch_btree_insert_at(struct btree_iter *, struct keylist *,
			struct disk_reservation *,
			struct btree_insert_hook *, u64 *, unsigned);

struct btree_insert_multi {
	struct btree_iter	*iter;
	struct bkey_i		*k;
};

int bch_btree_insert_at_multi(struct btree_insert_multi[], unsigned,
			      u64 *, unsigned);

int bch_btree_insert_check_key(struct btree_iter *, struct bkey_i *);
int bch_btree_insert(struct cache_set *, enum btree_id, struct keylist *,
		     struct disk_reservation *,
		     struct btree_insert_hook *, u64 *, int flags);
int bch_btree_update(struct cache_set *, enum btree_id,
		     struct bkey_i *, u64 *);

int bch_btree_delete_range(struct cache_set *, enum btree_id,
			   struct bpos, struct bpos, u64,
			   struct btree_insert_hook *, u64 *);

int bch_btree_node_rewrite(struct btree *, struct btree_iter *, bool);

#endif /* _BCACHE_BTREE_INSERT_H */

