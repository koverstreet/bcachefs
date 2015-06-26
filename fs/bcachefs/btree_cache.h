#ifndef _BCACHE_BTREE_CACHE_H
#define _BCACHE_BTREE_CACHE_H

#include "bcache.h"
#include "btree_types.h"

struct btree_iter;

extern const char *bch_btree_id_names[BTREE_ID_NR];

void bch_recalc_btree_reserve(struct cache_set *);

void mca_hash_remove(struct cache_set *, struct btree *);
int mca_hash_insert(struct cache_set *, struct btree *,
		    unsigned, enum btree_id);

void mca_cannibalize_unlock(struct cache_set *);
int mca_cannibalize_lock(struct cache_set *, struct closure *);

struct btree *mca_alloc(struct cache_set *, struct closure *);

struct btree *bch_btree_node_get(struct btree_iter *,
				 const struct bkey_i *, int);

void bch_btree_cache_free(struct cache_set *);
int bch_btree_cache_alloc(struct cache_set *);

#define for_each_cached_btree(_b, _c, _tbl, _iter, _pos)		\
	for ((_tbl) = rht_dereference_rcu((_c)->btree_cache_table.tbl,	\
					  &(_c)->btree_cache_table),	\
	     _iter = 0;	_iter < (_tbl)->size; _iter++)			\
		rht_for_each_entry_rcu((_b), (_pos), _tbl, _iter, hash)

static inline size_t btree_bytes(struct cache_set *c)
{
	return CACHE_BTREE_NODE_SIZE(&c->sb) << 9;
}

static inline size_t btree_pages(struct cache_set *c)
{
	return CACHE_BTREE_NODE_SIZE(&c->sb) >> (PAGE_SHIFT - 9);
}

static inline unsigned btree_blocks(struct cache_set *c)
{
	return CACHE_BTREE_NODE_SIZE(&c->sb) >> c->block_bits;
}

#define btree_node_root(_b)	((_b)->c->btree_roots[(_b)->btree_id])

#endif /* _BCACHE_BTREE_CACHE_H */
