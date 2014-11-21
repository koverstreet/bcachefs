#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bset.h"

struct bkey *bch_generic_sort_fixup(struct btree_iter *, struct bkey *);
bool bch_generic_insert_fixup(struct btree_keys *, struct bkey *,
			      struct btree_iter *, struct bkey *,
			      struct bkey *);

extern const struct btree_keys_ops bch_btree_interior_node_ops;
extern const struct btree_keys_ops *bch_btree_ops[];

struct bkey;
struct cache_set;

void bch_extent_to_text(const struct cache_set *, char *, size_t,
			const struct bkey *);
bool __bch_btree_ptr_invalid(const struct cache_set *, const struct bkey *);
bool __bch_extent_invalid(const struct cache_set *, const struct bkey *);

struct cache *bch_btree_pick_ptr(struct cache_set *, const struct bkey *,
				 unsigned *);
struct cache *bch_extent_pick_ptr(struct cache_set *, const struct bkey *,
				  unsigned *);

unsigned bch_extent_nr_ptrs_after_normalize(struct cache_set *,
					    const struct bkey *);
void bch_extent_drop_stale(struct cache_set *, struct bkey *);
bool bch_extent_normalize(struct cache_set *, struct bkey *);

int __bch_add_sectors(struct cache_set *, struct bkey *, u64, int, bool, bool);

static inline unsigned bch_extent_ptrs(const struct bkey *k)
{
	return bch_val_u64s(k);
}

static inline void bch_set_extent_ptrs(struct bkey *k, unsigned i)
{
	BUG_ON(i > BKEY_EXTENT_PTRS_MAX);
	bch_set_val_u64s(k, i);
}

static inline void bch_extent_drop_ptr(struct bkey *k, unsigned ptr)
{
	BUG_ON(bch_extent_ptrs(k) > BKEY_EXTENT_PTRS_MAX);
	BUG_ON(ptr >= bch_extent_ptrs(k));
	bch_set_extent_ptrs(k, bch_extent_ptrs(k) - 1);
	memmove(&k->val[ptr],
		&k->val[ptr + 1],
		(bch_extent_ptrs(k) - ptr) * sizeof(u64));
}

bool bch_cut_front(const struct bkey *, struct bkey *);
bool bch_cut_back(const struct bkey *, struct bkey *);
void bch_key_resize(struct bkey *, unsigned);

#endif /* _BCACHE_EXTENTS_H */
