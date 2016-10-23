#ifndef _BCACHE_BSET_H
#define _BCACHE_BSET_H

#include <linux/kernel.h>
#include <linux/types.h>

#include "bcachefs_format.h"
#include "bkey.h"
#include "util.h" /* for time_stats */

/*
 * BKEYS:
 *
 * A bkey contains a key, a size field, a variable number of pointers, and some
 * ancillary flag bits.
 *
 * We use two different functions for validating bkeys, bkey_invalid and
 * bkey_deleted().
 *
 * The one exception to the rule that ptr_invalid() filters out invalid keys is
 * that it also filters out keys of size 0 - these are keys that have been
 * completely overwritten. It'd be safe to delete these in memory while leaving
 * them on disk, just unnecessary work - so we filter them out when resorting
 * instead.
 *
 * We can't filter out stale keys when we're resorting, because garbage
 * collection needs to find them to ensure bucket gens don't wrap around -
 * unless we're rewriting the btree node those stale keys still exist on disk.
 *
 * We also implement functions here for removing some number of sectors from the
 * front or the back of a bkey - this is mainly used for fixing overlapping
 * extents, by removing the overlapping sectors from the older key.
 *
 * BSETS:
 *
 * A bset is an array of bkeys laid out contiguously in memory in sorted order,
 * along with a header. A btree node is made up of a number of these, written at
 * different times.
 *
 * There could be many of them on disk, but we never allow there to be more than
 * 4 in memory - we lazily resort as needed.
 *
 * We implement code here for creating and maintaining auxiliary search trees
 * (described below) for searching an individial bset, and on top of that we
 * implement a btree iterator.
 *
 * BTREE ITERATOR:
 *
 * Most of the code in bcache doesn't care about an individual bset - it needs
 * to search entire btree nodes and iterate over them in sorted order.
 *
 * The btree iterator code serves both functions; it iterates through the keys
 * in a btree node in sorted order, starting from either keys after a specific
 * point (if you pass it a search key) or the start of the btree node.
 *
 * AUXILIARY SEARCH TREES:
 *
 * Since keys are variable length, we can't use a binary search on a bset - we
 * wouldn't be able to find the start of the next key. But binary searches are
 * slow anyways, due to terrible cache behaviour; bcache originally used binary
 * searches and that code topped out at under 50k lookups/second.
 *
 * So we need to construct some sort of lookup table. Since we only insert keys
 * into the last (unwritten) set, most of the keys within a given btree node are
 * usually in sets that are mostly constant. We use two different types of
 * lookup tables to take advantage of this.
 *
 * Both lookup tables share in common that they don't index every key in the
 * set; they index one key every BSET_CACHELINE bytes, and then a linear search
 * is used for the rest.
 *
 * For sets that have been written to disk and are no longer being inserted
 * into, we construct a binary search tree in an array - traversing a binary
 * search tree in an array gives excellent locality of reference and is very
 * fast, since both children of any node are adjacent to each other in memory
 * (and their grandchildren, and great grandchildren...) - this means
 * prefetching can be used to great effect.
 *
 * It's quite useful performance wise to keep these nodes small - not just
 * because they're more likely to be in L2, but also because we can prefetch
 * more nodes on a single cacheline and thus prefetch more iterations in advance
 * when traversing this tree.
 *
 * Nodes in the auxiliary search tree must contain both a key to compare against
 * (we don't want to fetch the key from the set, that would defeat the purpose),
 * and a pointer to the key. We use a few tricks to compress both of these.
 *
 * To compress the pointer, we take advantage of the fact that one node in the
 * search tree corresponds to precisely BSET_CACHELINE bytes in the set. We have
 * a function (to_inorder()) that takes the index of a node in a binary tree and
 * returns what its index would be in an inorder traversal, so we only have to
 * store the low bits of the offset.
 *
 * The key is 84 bits (KEY_DEV + key->key, the offset on the device). To
 * compress that,  we take advantage of the fact that when we're traversing the
 * search tree at every iteration we know that both our search key and the key
 * we're looking for lie within some range - bounded by our previous
 * comparisons. (We special case the start of a search so that this is true even
 * at the root of the tree).
 *
 * So we know the key we're looking for is between a and b, and a and b don't
 * differ higher than bit 50, we don't need to check anything higher than bit
 * 50.
 *
 * We don't usually need the rest of the bits, either; we only need enough bits
 * to partition the key range we're currently checking.  Consider key n - the
 * key our auxiliary search tree node corresponds to, and key p, the key
 * immediately preceding n.  The lowest bit we need to store in the auxiliary
 * search tree is the highest bit that differs between n and p.
 *
 * Note that this could be bit 0 - we might sometimes need all 80 bits to do the
 * comparison. But we'd really like our nodes in the auxiliary search tree to be
 * of fixed size.
 *
 * The solution is to make them fixed size, and when we're constructing a node
 * check if p and n differed in the bits we needed them to. If they don't we
 * flag that node, and when doing lookups we fallback to comparing against the
 * real key. As long as this doesn't happen to often (and it seems to reliably
 * happen a bit less than 1% of the time), we win - even on failures, that key
 * is then more likely to be in cache than if we were doing binary searches all
 * the way, since we're touching so much less memory.
 *
 * The keys in the auxiliary search tree are stored in (software) floating
 * point, with an exponent and a mantissa. The exponent needs to be big enough
 * to address all the bits in the original key, but the number of bits in the
 * mantissa is somewhat arbitrary; more bits just gets us fewer failures.
 *
 * We need 7 bits for the exponent and 3 bits for the key's offset (since keys
 * are 8 byte aligned); using 22 bits for the mantissa means a node is 4 bytes.
 * We need one node per 128 bytes in the btree node, which means the auxiliary
 * search trees take up 3% as much memory as the btree itself.
 *
 * Constructing these auxiliary search trees is moderately expensive, and we
 * don't want to be constantly rebuilding the search tree for the last set
 * whenever we insert another key into it. For the unwritten set, we use a much
 * simpler lookup table - it's just a flat array, so index i in the lookup table
 * corresponds to the i range of BSET_CACHELINE bytes in the set. Indexing
 * within each byte range works the same as with the auxiliary search trees.
 *
 * These are much easier to keep up to date when we insert a key - we do it
 * somewhat lazily; when we shift a key up we usually just increment the pointer
 * to it, only when it would overflow do we go to the trouble of finding the
 * first key in that range of bytes again.
 */

struct btree_keys;
struct btree_node_iter;
struct btree_node_iter_set;
struct bkey_float;

typedef bool (*ptr_filter_fn)(struct btree_keys *, struct bkey_s);

typedef bool (*iter_cmp_fn)(struct btree_node_iter_set,
			    struct btree_node_iter_set);

enum merge_result {
	BCH_MERGE_NOMERGE,

	/*
	 * The keys were mergeable, but would have overflowed size - so instead
	 * l was changed to the maximum size, and both keys were modified:
	 */
	BCH_MERGE_PARTIAL,
	BCH_MERGE_MERGE,
};

struct btree_keys_ops {
	ptr_filter_fn	key_normalize;
	enum merge_result (*key_merge)(struct btree_keys *,
				       struct bkey_i *, struct bkey_i *);

	/*
	 * Only used for deciding whether to use bkey_start_pos(k) or just the
	 * key itself in a couple places
	 */
	bool		is_extents;
};

#define MAX_BSETS		3U

struct bset_tree {
	/*
	 * We construct a binary tree in an array as if the array
	 * started at 1, so that things line up on the same cachelines
	 * better: see comments in bset.c at cacheline_to_bkey() for
	 * details
	 */

	/* size of the binary tree and prev array */
	unsigned		size;

	/* function of size - precalculated for to_inorder() */
	unsigned		extra;

	/* copy of the last key in the set */
	struct bkey_packed	end;
	struct bkey_float	*tree;

	/*
	 * The nodes in the bset tree point to specific keys - this
	 * array holds the sizes of the previous key.
	 *
	 * Conceptually it's a member of struct bkey_float, but we want
	 * to keep bkey_float to 4 bytes and prev isn't used in the fast
	 * path.
	 */
	u8			*prev;

	/* The actual btree node, with pointers to each sorted set */
	struct bset		*data;
};

enum bset_aux_tree_type {
	BSET_AUX_TREE_NONE,
	BSET_HAS_AUX_TREE,
	BSET_HAS_UNWRITTEN_TABLE,
};

#define BSET_TREE_NR_TYPES	3

#define BSET_AUX_TREE_NONE_VAL	(UINT_MAX)
#define BSET_UNWRITTEN_TABLE_VAL	(UINT_MAX - 1)

static inline enum bset_aux_tree_type bset_aux_tree_type(struct bset_tree *t)
{
	switch (t->extra) {
	case BSET_AUX_TREE_NONE_VAL:
		return BSET_AUX_TREE_NONE;
	case BSET_UNWRITTEN_TABLE_VAL:
		EBUG_ON(!t->size);
		return BSET_HAS_UNWRITTEN_TABLE;
	default:
		EBUG_ON(!t->size);
		return BSET_HAS_AUX_TREE;
	}
}

struct btree_nr_keys {

	/*
	 * Amount of live metadata (i.e. size of node after a compaction) in
	 * units of u64s
	 */
	u16			live_u64s;

	/* live keys only: */
	u16			packed_keys;
	u16			unpacked_keys;
};

struct btree_keys {
	const struct btree_keys_ops	*ops;
	u8			nsets;
	u8			page_order;

	struct btree_nr_keys	nr;

	struct bkey_format	format;

	/*
	 * Sets of sorted keys - the real btree node - plus a binary search tree
	 *
	 * set[0] is special; set[0]->tree, set[0]->prev and set[0]->data point
	 * to the memory we have allocated for this btree node. Additionally,
	 * set[0]->data points to the entire btree node as it exists on disk.
	 */
	struct bset_tree	set[MAX_BSETS];
#ifdef CONFIG_BCACHEFS_DEBUG
	bool			*expensive_debug_checks;
#endif
};

extern bool bch_expensive_debug_checks;

static inline bool btree_keys_expensive_checks(struct btree_keys *b)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	return bch_expensive_debug_checks || *b->expensive_debug_checks;
#else
	return false;
#endif
}

static inline struct bset_tree *bset_tree_last(struct btree_keys *b)
{
	return b->set + b->nsets;
}

static inline bool bset_has_aux_tree(struct bset_tree *t)
{
	return bset_aux_tree_type(t) == BSET_HAS_AUX_TREE;
}

#define __set_bytes(_i, _u64s)	(sizeof(*(_i)) + (_u64s) * sizeof(u64))
#define set_bytes(_i)		__set_bytes(_i, (_i)->u64s)

#define __set_blocks(_i, _u64s, _block_bytes)				\
	DIV_ROUND_UP((size_t) __set_bytes((_i), (_u64s)), (_block_bytes))

#define set_blocks(_i, _block_bytes)					\
	__set_blocks((_i), (_i)->u64s, (_block_bytes))

static inline struct bset *bset_next_set(struct btree_keys *b,
					 unsigned block_bytes)
{
	struct bset *i = bset_tree_last(b)->data;

	EBUG_ON(!is_power_of_2(block_bytes));

	return ((void *) i) + round_up(set_bytes(i), block_bytes);
}

void bch_btree_keys_free(struct btree_keys *);
int bch_btree_keys_alloc(struct btree_keys *, unsigned, gfp_t);
void bch_btree_keys_init(struct btree_keys *, const struct btree_keys_ops *,
			 bool *);

void bch_bset_init_first(struct btree_keys *, struct bset *);
void bch_bset_init_next(struct btree_keys *, struct bset *);
void bch_bset_build_written_tree(struct btree_keys *);
void bch_bset_fix_invalidated_key(struct btree_keys *, struct bkey_packed *);

struct bkey_packed *bch_bset_insert(struct btree_keys *,
				    struct btree_node_iter *,
				    struct bkey_i *);
bool bch_bset_try_overwrite(struct btree_keys *, struct btree_node_iter *iter,
			    struct bkey_packed *, struct bkey_i *);

static inline void btree_keys_account_key(struct btree_nr_keys *n,
					  struct bkey_packed *k,
					  int sign)
{
	n->live_u64s += k->u64s * sign;
	if (bkey_packed(k))
		n->packed_keys += sign;
	else
		n->unpacked_keys += sign;
}

#define btree_keys_account_key_add(_b, _k)			\
	btree_keys_account_key(_b, _k, 1)
#define btree_keys_account_key_drop(_b, _k)			\
	btree_keys_account_key(_b, _k, -1)

/* Bkey utility code */

/* Returns true if @k is after iterator position @pos */
static inline bool btree_iter_pos_cmp(struct bpos pos, const struct bkey *k,
				      bool strictly_greater)
{
	int cmp = bkey_cmp(k->p, pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

static inline bool btree_iter_pos_cmp_packed(const struct bkey_format *f,
					     struct bpos pos,
					     const struct bkey_packed *k,
					     bool strictly_greater)
{
	int cmp = bkey_cmp_left_packed(f, k, pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

static inline bool btree_iter_pos_cmp_p_or_unp(const struct bkey_format *f,
					struct bpos pos,
					const struct bkey_packed *pos_packed,
					const struct bkey_packed *k,
					bool strictly_greater)
{
	int cmp = bkey_cmp_p_or_unp(f, k, pos_packed, pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

#define BKEY_PADDED(key)	__BKEY_PADDED(key, BKEY_EXTENT_VAL_U64s_MAX)

#define __bkey_idx(_set, _offset)				\
	((_set)->_data + (_offset))

#define bkey_idx(_set, _offset)					\
	((typeof(&(_set)->start[0])) __bkey_idx((_set), (_offset)))

#define __bset_bkey_last(_set)					\
	 __bkey_idx((_set), (_set)->u64s)

#define bset_bkey_last(_set)					\
	 bkey_idx((_set), le16_to_cpu((_set)->u64s))

static inline struct bkey_packed *bset_bkey_idx(struct bset *i, unsigned idx)
{
	return bkey_idx(i, idx);
}

struct bset_tree *bch_bkey_to_bset(struct btree_keys *, struct bkey_packed *);
struct bkey_packed *bkey_prev(struct bset_tree *, struct bkey_packed *);

/*
 * Tries to merge l and r: l should be lower than r
 * Returns true if we were able to merge. If we did merge, l will be the merged
 * key, r will be untouched.
 */
static inline bool bch_bkey_try_merge(struct btree_keys *b,
				      struct bkey_i *l,
				      struct bkey_i *r)
{
	return b->ops->key_merge
		? b->ops->key_merge(b, l, r) == BCH_MERGE_MERGE
		: false;
}

enum bch_extent_overlap {
	BCH_EXTENT_OVERLAP_FRONT,
	BCH_EXTENT_OVERLAP_BACK,
	BCH_EXTENT_OVERLAP_ALL,
	BCH_EXTENT_OVERLAP_MIDDLE,
};

/* Returns how k overlaps with m */
static inline enum bch_extent_overlap bch_extent_overlap(const struct bkey *k,
							 const struct bkey *m)
{
	if (bkey_cmp(k->p, m->p) < 0) {
		if (bkey_cmp(bkey_start_pos(k),
			     bkey_start_pos(m)) > 0)
			return BCH_EXTENT_OVERLAP_MIDDLE;
		else
			return BCH_EXTENT_OVERLAP_FRONT;
	} else {
		if (bkey_cmp(bkey_start_pos(k),
			     bkey_start_pos(m)) <= 0)
			return BCH_EXTENT_OVERLAP_ALL;
		else
			return BCH_EXTENT_OVERLAP_BACK;
	}
}

/* Btree key iteration */

struct btree_node_iter {
	u8		is_extents;
	u16		used;

	struct btree_node_iter_set {
		u16	k, end;
	} data[MAX_BSETS];
};

static inline void __bch_btree_node_iter_init(struct btree_node_iter *iter,
					      struct btree_keys *b)
{
	iter->used = 0;
	iter->is_extents = b->ops->is_extents;
}

void bch_btree_node_iter_push(struct btree_node_iter *, struct btree_keys *,
			      const struct bkey_packed *,
			      const struct bkey_packed *);
void bch_btree_node_iter_init(struct btree_node_iter *, struct btree_keys *,
			      struct bpos, bool);
void bch_btree_node_iter_init_from_start(struct btree_node_iter *,
					 struct btree_keys *);
struct bkey_packed *bch_btree_node_iter_bset_pos(struct btree_node_iter *,
						 struct btree_keys *,
						 struct bset *);

void bch_btree_node_iter_sort(struct btree_node_iter *, struct btree_keys *);
void bch_btree_node_iter_advance(struct btree_node_iter *, struct btree_keys *);

#define btree_node_iter_for_each(_iter, _set)			\
	for (_set = (_iter)->data;				\
	     _set < (_iter)->data + (_iter)->used;		\
	     _set++)

static inline bool bch_btree_node_iter_end(struct btree_node_iter *iter)
{
	return !iter->used;
}

static inline u16
__btree_node_key_to_offset(struct btree_keys *b, const struct bkey_packed *k)
{
	size_t ret = (u64 *) k - (u64 *) b->set->data;

	EBUG_ON(ret > U16_MAX);
	return ret;
}

static inline struct bkey_packed *
__btree_node_offset_to_key(struct btree_keys *b, u16 k)
{
	return (void *) ((u64 *) b->set->data + k);
}

static inline struct bkey_packed *
__bch_btree_node_iter_peek_all(struct btree_node_iter *iter,
			       struct btree_keys *b)
{
	return __btree_node_offset_to_key(b, iter->data->k);
}

static inline struct bkey_packed *
bch_btree_node_iter_peek_all(struct btree_node_iter *iter,
			     struct btree_keys *b)
{
	return bch_btree_node_iter_end(iter)
		? NULL
		: __bch_btree_node_iter_peek_all(iter, b);
}

static inline struct bkey_packed *
bch_btree_node_iter_peek(struct btree_node_iter *iter, struct btree_keys *b)
{
	struct bkey_packed *ret;

	while ((ret = bch_btree_node_iter_peek_all(iter, b)) &&
	       bkey_deleted(ret))
		bch_btree_node_iter_advance(iter, b);

	return ret;
}

static inline struct bkey_packed *
bch_btree_node_iter_next_all(struct btree_node_iter *iter, struct btree_keys *b)
{
	struct bkey_packed *ret = bch_btree_node_iter_peek_all(iter, b);

	if (ret)
		bch_btree_node_iter_advance(iter, b);

	return ret;
}

struct bkey_packed *bch_btree_node_iter_prev_all(struct btree_node_iter *,
						 struct btree_keys *);

/*
 * Iterates over all _live_ keys - skipping deleted (and potentially
 * overlapping) keys
 */
#define for_each_btree_node_key(b, k, iter)				\
	for (bch_btree_node_iter_init_from_start((iter), (b));		\
	     ((k) = bch_btree_node_iter_peek(iter, b));			\
	     bch_btree_node_iter_advance(iter, b))

struct bkey_s_c bch_btree_node_iter_peek_unpack(struct btree_node_iter *,
						struct btree_keys *,
						struct bkey *);

#define for_each_btree_node_key_unpack(b, k, iter, unpacked)		\
	for (bch_btree_node_iter_init_from_start((iter), (b));		\
	     (k = bch_btree_node_iter_peek_unpack((iter), (b), (unpacked))).k;\
	     bch_btree_node_iter_advance(iter, b))

/* Sorting */

struct bset_sort_state {
	mempool_t		pool;

	unsigned		page_order;
	unsigned		crit_factor;

	struct time_stats	*time;
};

typedef struct btree_nr_keys (*btree_keys_sort_fn)(struct btree_keys *,
						   struct bset *,
						   struct btree_node_iter *);

void bch_bset_sort_state_free(struct bset_sort_state *);
int bch_bset_sort_state_init(struct bset_sort_state *, unsigned,
			     struct time_stats *times);

struct btree_nr_keys bch_sort_bsets(struct bset *, struct btree_keys *,
				    unsigned, struct btree_node_iter *,
				    btree_keys_sort_fn,
				    struct bset_sort_state *);

void bch_btree_sort_lazy(struct btree_keys *, struct bset_sort_state *);
void bch_btree_sort_into(struct btree_keys *, struct btree_keys *,
			 ptr_filter_fn, struct bset_sort_state *);

struct bset_stats {
	struct {
		size_t nr, bytes;
	} sets[BSET_TREE_NR_TYPES];

	size_t floats;
	size_t failed_unpacked;
	size_t failed_prev;
	size_t failed_overflow;
};

void bch_btree_keys_stats(struct btree_keys *, struct bset_stats *);
int bch_bkey_print_bfloat(struct btree_keys *, struct bkey_packed *,
			  char *, size_t);

/* Debug stuff */

#ifdef CONFIG_BCACHEFS_DEBUG

void bch_dump_bset(struct btree_keys *, struct bset *, unsigned);
void bch_dump_bucket(struct btree_keys *);
void __bch_verify_btree_nr_keys(struct btree_keys *);
void bch_btree_node_iter_verify(struct btree_node_iter *, struct btree_keys *);
void bch_verify_key_order(struct btree_keys *, struct btree_node_iter *,
			  struct bkey_packed *);

#else

static inline void bch_dump_bset(struct btree_keys *b, struct bset *i, unsigned set) {}
static inline void bch_dump_bucket(struct btree_keys *b) {}
static inline void __bch_verify_btree_nr_keys(struct btree_keys *b) {}
static inline void bch_btree_node_iter_verify(struct btree_node_iter *iter,
					      struct btree_keys *b) {}
static inline void bch_verify_key_order(struct btree_keys *b,
					struct btree_node_iter *iter,
					struct bkey_packed *where) {}
#endif


static inline void bch_verify_btree_nr_keys(struct btree_keys *b)
{
	if (btree_keys_expensive_checks(b))
		__bch_verify_btree_nr_keys(b);
}

#endif
