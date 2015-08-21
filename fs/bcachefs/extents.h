#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bset.h"

bool bch_generic_sort_cmp(struct btree_iter_set, struct btree_iter_set);
struct bkey *bch_generic_sort_fixup(struct btree_iter *, struct bkey *);
bool bch_generic_insert_fixup(struct btree_keys *, struct bkey *,
			      struct btree_iter *, struct bkey *);

extern const struct btree_keys_ops bch_btree_interior_node_ops;
extern const struct btree_keys_ops *bch_btree_ops[];

struct bkey;
struct cache_set;

void bch_extent_to_text(char *, size_t, const struct bkey *);
bool __bch_btree_ptr_invalid(struct cache_set *, const struct bkey *);
bool __bch_extent_invalid(struct cache_set *, const struct bkey *);
int bch_btree_pick_ptr(struct cache_set *, const struct bkey *);
int bch_extent_pick_ptr(struct cache_set *, const struct bkey *);
void bch_extent_normalize(struct cache_set *, struct bkey *);

static inline unsigned bch_extent_ptrs(const struct bkey *k)
{
	return bch_val_u64s(k);
}

static inline void bch_set_extent_ptrs(struct bkey *k, unsigned i)
{
	bch_set_val_u64s(k, i);
}

#endif /* _BCACHE_EXTENTS_H */
