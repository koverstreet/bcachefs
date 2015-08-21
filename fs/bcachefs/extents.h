#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bkey.h"
#include "bset.h"
#include "journal_types.h"

struct bch_replace_info;

struct bkey *bch_generic_sort_fixup(struct btree_node_iter *, struct bkey *);
bool bch_insert_fixup_key(struct btree *,
			  struct bkey *,
			  struct btree_node_iter *,
			  struct bch_replace_info *,
			  struct bpos *,
			  struct journal_res *);

extern const struct btree_keys_ops bch_btree_interior_node_ops;
extern const struct btree_keys_ops *bch_btree_ops[];

struct bkey;
struct cache_set;

bool __bch_btree_ptr_invalid(const struct cache_set *, const struct bkey *);
bool __bch_extent_invalid(const struct cache_set *, const struct bkey *);

struct cache *bch_btree_pick_ptr(struct cache_set *, const struct bkey *,
				 const struct bch_extent_ptr **);
struct cache *bch_extent_pick_ptr_avoiding(struct cache_set *,
					   const struct bkey *,
					   const struct bch_extent_ptr **,
					   struct cache *);

static inline struct cache *bch_extent_pick_ptr(struct cache_set *c,
					const struct bkey *k,
					const struct bch_extent_ptr **ptr)
{
	return bch_extent_pick_ptr_avoiding(c, k, ptr, NULL);
}

bool bch_insert_fixup_extent(struct btree *, struct bkey *,
			     struct btree_node_iter *,
			     struct bch_replace_info *, struct bpos *,
			     struct journal_res *);

unsigned bch_extent_nr_ptrs_after_normalize(const struct cache_set *,
					    const struct bkey *);
void bch_extent_drop_stale(struct cache_set *, struct bkey *);
bool bch_extent_normalize(struct cache_set *, struct bkey *);

int __bch_add_sectors(struct cache_set *, struct btree *,
		      const struct bkey *, u64, int, bool);

static inline bool bkey_extent_cached(const struct bkey *k)
{
	return k->type == BCH_EXTENT &&
		EXTENT_CACHED(&bkey_i_to_extent_c(k)->v);
}

static inline unsigned bch_extent_ptrs(const struct bkey *k)
{
	BUG_ON(k->type != BCH_EXTENT);
	return bkey_val_u64s(k);
}

static inline void bch_set_extent_ptrs(struct bkey *k, unsigned i)
{
	BUG_ON(k->type != BCH_EXTENT);
	BUG_ON(i > BKEY_EXTENT_PTRS_MAX);
	set_bkey_val_u64s(k, i);
}

static inline void bch_extent_drop_ptr(struct bkey *k, unsigned ptr)
{
	struct bkey_i_extent *e = bkey_i_to_extent(k);

	BUG_ON(bch_extent_ptrs(&e->k) > BKEY_EXTENT_PTRS_MAX);
	BUG_ON(ptr >= bch_extent_ptrs(&e->k));

	e->k.u64s--;
	memmove(&e->v.ptr[ptr],
		&e->v.ptr[ptr + 1],
		(bch_extent_ptrs(&e->k) - ptr) * sizeof(u64));
}

static inline unsigned bch_extent_replicas_needed(const struct cache_set *c,
						  const struct bkey_i_extent *e)
{
	return EXTENT_CACHED(&e->v) ? 0 : CACHE_SET_DATA_REPLICAS_WANT(&c->sb);
}

static inline bool bch_extent_ptr_is_dirty(const struct cache_set *c,
					   const struct bkey_i_extent *e,
					   const struct bch_extent_ptr *ptr)
{
	/* Dirty pointers come last */

	return ptr + bch_extent_replicas_needed(c, e) >=
		e->v.ptr + bch_extent_ptrs(&e->k);
}

#define extent_for_each_ptr(_extent, _ptr)				\
	for ((_ptr) = (_extent)->v.ptr;					\
	     (_ptr) < (_extent)->v.ptr + bch_extent_ptrs(&(_extent)->k);\
	     (_ptr)++)

/*
 * Use this when you'll be dropping pointers as you iterate.
 * Any reason we shouldn't just always do this?
 */
#define extent_for_each_ptr_backwards(_extent, _ptr)			\
	for ((_ptr) = (_extent)->v.ptr + bch_extent_ptrs(&(_extent)->k) - 1;\
	     (_ptr) >= (_extent)->v.ptr;				\
	     --(_ptr))

#define __extent_next_online_device(_c, _extent, _ptr, _ca)		\
({									\
	(_ca) = NULL;							\
									\
	while ((_ptr) < (_extent)->v.ptr + bch_extent_ptrs(&(_extent)->k) &&\
	       !((_ca) = PTR_CACHE(_c, _ptr)))				\
		(_ptr)++;						\
	(_ca);								\
})

#define extent_for_each_online_device(_c, _extent, _ptr, _ca)		\
	for ((_ptr) = (_extent)->v.ptr;					\
	     ((_ca) = __extent_next_online_device(_c, _extent, _ptr, _ca));\
	     (_ptr)++)

bool bch_extent_has_device(const struct bkey_i_extent *, unsigned);
void bch_bkey_copy_single_ptr(struct bkey *, const struct bkey *,
			      unsigned);

bool bch_cut_front(struct bpos, struct bkey *);
bool bch_cut_back(struct bpos, struct bkey *);
void bch_key_resize(struct bkey *, unsigned);
void bch_insert_check_key(struct btree_keys *, struct bkey *);

#endif /* _BCACHE_EXTENTS_H */
