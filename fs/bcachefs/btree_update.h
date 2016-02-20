#ifndef _BCACHE_BTREE_INSERT_H
#define _BCACHE_BTREE_INSERT_H

#include "btree_cache.h"
#include "btree_iter.h"

struct cache_set;
struct bkey_format_state;
struct bkey_format;
struct btree;

struct btree_reserve {
	unsigned		sectors_reserved;
	unsigned		nr;
	struct btree		*b[];
};

#define BTREE_RESERVE_SIZE						\
	(sizeof(struct btree_reserve) +					\
	 sizeof(struct btree *) * BTREE_RESERVE_MAX)

void __bch_btree_calc_format(struct bkey_format_state *, struct btree *);
bool bch_btree_node_format_fits(struct btree *, struct bkey_format *);

/* Btree node freeing/allocation: */

struct pending_btree_node_free {
	struct list_head	list;
	bool			index_update_done;

	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
};

struct async_split {
	struct closure			cl;

	struct cache_set		*c;

	struct btree			*b;
	struct async_split		*as;
	struct list_head		list;

	/* for setting a new btree root: */
	struct journal_res		res;

	struct journal_entry_pin	journal;

	struct closure_waitlist		wait;

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

void bch_pending_btree_node_free_init(struct cache_set *, struct async_split *,
				      struct btree *);

void bch_btree_node_free_never_inserted(struct cache_set *, struct btree *);
void bch_btree_node_free(struct btree_iter *, struct btree *);

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

void bch_btree_set_root_initial(struct cache_set *, struct btree *);

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

int bch_btree_insert_node(struct btree *, struct btree_iter *,
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
 * Don't fail a btree insert if dirty stale pointers are being added
 *
 * Only for journal replay:
 */
#define BTREE_INSERT_NOFAIL_IF_STALE	(1 << 2)

int bch_btree_insert_at(struct btree_iter *, struct keylist *,
			struct btree_insert_hook *, u64 *, unsigned);

struct btree_insert_multi {
	struct btree_iter	*iter;
	struct bkey_i		*k;
};

int bch_btree_insert_at_multi(struct btree_insert_multi[], unsigned,
			      u64 *, unsigned);

int bch_btree_insert_check_key(struct btree_iter *, struct bkey_i *);
int bch_btree_insert(struct cache_set *, enum btree_id, struct keylist *,
		     struct btree_insert_hook *, u64 *, int flags);
int bch_btree_update(struct cache_set *, enum btree_id,
		     struct bkey_i *, u64 *);

int bch_btree_delete_range(struct cache_set *, enum btree_id,
			   struct bpos, struct bpos, u64,
			   struct btree_insert_hook *, u64 *);

int bch_btree_node_rewrite(struct btree *, struct btree_iter *, bool);

#endif /* _BCACHE_BTREE_INSERT_H */

