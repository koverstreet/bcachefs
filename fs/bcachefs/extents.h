#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bkey.h"

struct bch_replace_info;

struct btree_nr_keys bch_key_sort_fix_overlapping(struct btree_keys *,
						  struct bset *,
						  struct btree_node_iter *);
struct btree_nr_keys bch_extent_sort_fix_overlapping(struct btree_keys *,
						     struct bset *,
						     struct btree_node_iter *);

bool bch_insert_fixup_key(struct cache_set *, struct btree *,
			  struct bkey_i *, struct btree_node_iter *,
			  struct bch_replace_info *, struct bpos *,
			  struct journal_res *);
bool bch_insert_fixup_btree_ptr(struct cache_set *, struct btree *,
				struct bkey_i *, struct btree_node_iter *,
				struct bch_replace_info *, struct bpos *,
				struct journal_res *);

extern const struct bkey_ops bch_bkey_btree_ops;
extern const struct bkey_ops bch_bkey_extent_ops;

extern const struct btree_keys_ops bch_btree_interior_node_ops;
extern const struct btree_keys_ops *bch_btree_ops[];

struct cache_set;
struct journal_res;

struct cache *bch_btree_pick_ptr(struct cache_set *, const struct btree *,
				 const struct bch_extent_ptr **);
struct cache *bch_extent_pick_ptr_avoiding(struct cache_set *, struct bkey_s_c,
					   const struct bch_extent_ptr **,
					   struct cache *);

static inline struct cache *bch_extent_pick_ptr(struct cache_set *c,
					struct bkey_s_c k,
					const struct bch_extent_ptr **ptr)
{
	return bch_extent_pick_ptr_avoiding(c, k, ptr, NULL);
}

bool bch_insert_fixup_extent(struct cache_set *, struct btree *,
			     struct bkey_i *, struct btree_node_iter *,
			     struct bch_replace_info *, struct bpos *,
			     struct journal_res *, unsigned);

unsigned bch_extent_nr_ptrs_after_normalize(struct cache_set *,
					    const struct btree *,
					    const struct bkey_packed *);
void bch_extent_drop_stale(struct cache_set *c, struct bkey_s);
bool bch_extent_normalize(struct cache_set *, struct bkey_s);

int __bch_add_sectors(struct cache_set *, struct btree *,
		      struct bkey_s_c_extent, u64, int, bool);

static inline bool bkey_extent_cached(struct bkey_s_c k)
{
	return k.k->type == BCH_EXTENT &&
		EXTENT_CACHED(bkey_s_c_to_extent(k).v);
}

#define bch_extent_ptrs(_e)	bkey_val_u64s((_e).k)

static inline void bch_set_extent_ptrs(struct bkey_s_extent e, unsigned i)
{
	BUG_ON(i > BKEY_EXTENT_PTRS_MAX);
	set_bkey_val_u64s(e.k, i);
}

static inline void bch_extent_drop_ptr(struct bkey_s_extent e,
				       unsigned ptr)
{
	BUG_ON(bch_extent_ptrs(extent_s_to_s_c(e)) > BKEY_EXTENT_PTRS_MAX);
	BUG_ON(ptr >= bch_extent_ptrs(extent_s_to_s_c(e)));

	e.k->u64s--;
	memmove(&e.v->ptr[ptr],
		&e.v->ptr[ptr + 1],
		(bch_extent_ptrs(extent_s_to_s_c(e)) - ptr) * sizeof(u64));
}

static inline bool __bch_extent_ptr_is_dirty(const struct cache_set *c,
					     const struct bch_extent *e,
					     const struct bch_extent_ptr *ptr,
					     unsigned nr_ptrs)
{
	/* Dirty pointers come last */

	if (EXTENT_CACHED(e))
		return false;

	return ptr + CACHE_SET_DATA_REPLICAS_WANT(&c->sb) >=
		e->ptr + nr_ptrs;
}

static inline bool bch_extent_ptr_is_dirty(const struct cache_set *c,
					   struct bkey_s_c_extent e,
					   const struct bch_extent_ptr *ptr)
{
	return __bch_extent_ptr_is_dirty(c, e.v, ptr, bch_extent_ptrs(e));
}

#define extent_for_each_ptr(_extent, _ptr)				\
	for ((_ptr) = (_extent).v->ptr;					\
	     (_ptr) < (_extent).v->ptr + bch_extent_ptrs(_extent);	\
	     (_ptr)++)

/*
 * Use this when you'll be dropping pointers as you iterate.
 * Any reason we shouldn't just always do this?
 */
#define extent_for_each_ptr_backwards(_extent, _ptr)			\
	for ((_ptr) = (_extent).v->ptr + bch_extent_ptrs(_extent) - 1;	\
	     (_ptr) >= (_extent).v->ptr;				\
	     --(_ptr))

#define __extent_next_online_device(_c, _extent, _ptr, _ca)		\
({									\
	(_ca) = NULL;							\
									\
	while ((_ptr) < (_extent).v->ptr + bch_extent_ptrs(_extent) &&\
	       !((_ca) = PTR_CACHE(_c, _ptr)))				\
		(_ptr)++;						\
	(_ca);								\
})

#define extent_for_each_online_device(_c, _extent, _ptr, _ca)		\
	for ((_ptr) = (_extent).v->ptr;					\
	     ((_ca) = __extent_next_online_device(_c, _extent, _ptr, _ca));\
	     (_ptr)++)

bool bch_extent_has_device(struct bkey_s_c_extent, unsigned);
void bch_bkey_copy_single_ptr(struct bkey_i *, struct bkey_s_c, unsigned);

bool bch_cut_front(struct bpos, struct bkey_i *);
bool bch_cut_back(struct bpos, struct bkey *);
void bch_key_resize(struct bkey *, unsigned);

#endif /* _BCACHE_EXTENTS_H */
