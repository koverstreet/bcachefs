/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_SORT_H
#define _BCACHEFS_BKEY_SORT_H

#include "btree/interior.h"

struct sort_iter {
	struct btree		*b;
	unsigned		used;
	unsigned		size;

	struct sort_iter_set {
		struct bkey_packed *k, *end;
	} data[];
};

static inline void sort_iter_init(struct sort_iter *iter, struct btree *b, unsigned size)
{
	iter->b = b;
	iter->used = 0;
	iter->size = size;
}

struct sort_iter_stack {
	struct sort_iter	iter;
	struct sort_iter_set	sets[MAX_BSETS + 1];
};

static inline void sort_iter_stack_init(struct sort_iter_stack *iter, struct btree *b)
{
	sort_iter_init(&iter->iter, b, ARRAY_SIZE(iter->sets));
}

static inline void sort_iter_add(struct sort_iter *iter,
				 struct bkey_packed *k,
				 struct bkey_packed *end)
{
	BUG_ON(iter->used >= iter->size);

	if (k != end)
		iter->data[iter->used++] = (struct sort_iter_set) { k, end };
}

struct btree_nr_keys
bch2_key_sort_fix_overlapping(struct bch_fs *, struct bset *,
			      struct sort_iter *);

struct btree_nr_keys
bch2_sort_repack(struct bset *, struct btree *,
		 struct btree_node_iter *,
		 struct bkey_format *, bool);

unsigned bch2_sort_keys_keep_unwritten_whiteouts(struct bkey_packed *, struct sort_iter *);
unsigned bch2_sort_keys(struct bkey_packed *, struct sort_iter *);

void bch2_btree_bounce_free(struct bch_fs *, size_t, bool, void *);
void *bch2_btree_bounce_alloc(struct bch_fs *, size_t, bool *);

enum compact_mode {
	COMPACT_LAZY,
	COMPACT_ALL,
};

void bch2_set_bset_needs_whiteout(struct bset *, int);
void bch2_sort_whiteouts(struct bch_fs *, struct btree *);
bool bch2_drop_whiteouts(struct btree *, enum compact_mode mode);
bool bch2_compact_whiteouts(struct bch_fs *, struct btree *, enum compact_mode);

static inline bool should_compact_bset_lazy(struct btree *b,
					    struct bset_tree *t)
{
	unsigned total_u64s = bset_u64s(t);
	unsigned dead_u64s = bset_dead_u64s(b, t);

	return dead_u64s > 64 && dead_u64s * 3 > total_u64s;
}

static inline bool bch2_maybe_compact_whiteouts(struct bch_fs *c, struct btree *b)
{
	for_each_bset(b, t)
		if (should_compact_bset_lazy(b, t))
			return bch2_compact_whiteouts(c, b, COMPACT_LAZY);

	return false;
}

void bch2_btree_node_sort(struct bch_fs *, struct btree *, unsigned, unsigned);
void bch2_btree_sort_into(struct bch_fs *, struct btree *, struct btree *);
bool bch2_btree_node_compact(struct bch_fs *, struct btree *);

/*
 * If we have MAX_BSETS (3) bsets, should we sort them all down to just one?
 *
 * The first bset is going to be of similar order to the size of the node, the
 * last bset is bounded by btree_write_set_buffer(), which is set to keep the
 * memmove on insert from being too expensive: the middle bset should, ideally,
 * be the geometric mean of the first and the last.
 *
 * Returns true if the middle bset is greater than that geometric mean:
 */
static inline bool should_compact_all(struct bch_fs *c, struct btree *b)
{
	unsigned mid_u64s_bits =
		(ilog2(btree_max_u64s(c)) + BTREE_WRITE_SET_U64s_BITS) / 2;

	return bset_u64s(&b->set[1]) > 1U << mid_u64s_bits;
}

void bch2_btree_build_aux_trees(struct btree *);

#endif /* _BCACHEFS_BKEY_SORT_H */
