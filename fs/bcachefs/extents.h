#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bset.h"
#include "journal_types.h"

struct bch_replace_info;

struct bkey *bch_generic_sort_fixup(struct btree_node_iter *, struct bkey *);
bool bch_insert_fixup_key(struct btree *,
			  struct bkey *,
			  struct btree_node_iter *,
			  struct bch_replace_info *,
			  struct bkey *,
			  struct journal_res *);

extern const struct btree_keys_ops bch_btree_interior_node_ops;
extern const struct btree_keys_ops *bch_btree_ops[];

struct bkey;
struct cache_set;

bool __bch_btree_ptr_invalid(const struct cache_set *, const struct bkey *);
bool __bch_extent_invalid(const struct cache_set *, const struct bkey *);

struct cache *bch_btree_pick_ptr(struct cache_set *, const struct bkey *,
				 unsigned *);
struct cache *bch_extent_pick_ptr_avoiding(struct cache_set *,
					   const struct bkey *,
					   unsigned *,
					   struct cache *);

static inline struct cache *bch_extent_pick_ptr(struct cache_set *c,
						const struct bkey *k,
						unsigned *ptr)
{
	return bch_extent_pick_ptr_avoiding(c, k, ptr, NULL);
}

bool bch_insert_fixup_extent(struct btree *, struct bkey *,
			     struct btree_node_iter *,
			     struct bch_replace_info *, struct bkey *,
			     struct journal_res *);

bool bch_insert_exact_extent(struct btree *, struct bkey *,
			     struct btree_node_iter *,
			     struct bch_replace_info *, struct bkey *,
			     struct journal_res *);

unsigned bch_extent_nr_ptrs_after_normalize(const struct cache_set *,
					    const struct bkey *);
void bch_extent_drop_stale(struct cache_set *, struct bkey *);
bool bch_extent_normalize(struct cache_set *, struct bkey *);

int __bch_add_sectors(struct cache_set *, struct btree *,
		      const struct bkey *, u64, int, bool);

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

void bch_bkey_copy_single_ptr(struct bkey *, const struct bkey *,
			      unsigned);

bool bch_cut_front(const struct bkey *, struct bkey *);
bool bch_cut_back(const struct bkey *, struct bkey *);
void bch_key_resize(struct bkey *, unsigned);
void bch_insert_check_key(struct btree_keys *, struct bkey *);

bool bch_extent_key_valid(struct cache_set *, struct bkey *);

static inline bool bch_same_extent(const struct bkey *l, const struct bkey *r)
{
	return bch_bkey_maybe_compatible(l, r)
		&& (KEY_INODE(l) == KEY_INODE(r))
		&& (KEY_SNAPSHOT(l) == KEY_SNAPSHOT(r))
		&& (KEY_OFFSET(l) == KEY_OFFSET(r))
		&& (KEY_SIZE(l) == KEY_SIZE(r));
}

#endif /* _BCACHE_EXTENTS_H */
