/*
 * Code for working with individual keys, and sorted sets of keys with in a
 * btree node
 *
 * Copyright 2012 Google, Inc.
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include "util.h"
#include "bset.h"
#include "bcache.h"

#include <asm/unaligned.h>
#include <linux/dynamic_fault.h>
#include <linux/console.h>
#include <linux/random.h>
#include <linux/prefetch.h>

/* hack.. */
#include "alloc_types.h"
#include <trace/events/bcachefs.h>

/*
 * There are never duplicate live keys in the btree - but including keys that
 * have been flagged as deleted (and will be cleaned up later) we _will_ see
 * duplicates.
 *
 * Sort order is important here:
 *  - For extents, the deleted keys have to come last. This is because we're
 *    using bkey_deleted() as a proxy for k->size == 0, and we still have to
 *    maintain the invariant that
 *    bkey_cmp(k->p, bkey_start_pos(bkey_next(k)) <= 0)
 *
 *    i.e. a key can't end after the start of the next key.
 *
 * - For non extents, deleted keys must come first.
 *   XXX: why is this?
 */

static bool keys_out_of_order(const struct bkey_format *f,
			      const struct bkey_packed *prev,
			      const struct bkey_packed *next,
			      bool is_extents)
{
	struct bkey nextu = bkey_unpack_key(f, next);

	return bkey_cmp_left_packed(f, prev, bkey_start_pos(&nextu)) > 0 ||
		((is_extents
		  ? !bkey_deleted(next)
		  : !bkey_deleted(prev)) &&
		 !bkey_cmp_packed(f, prev, next));
}

#ifdef CONFIG_BCACHEFS_DEBUG

void bch_dump_bset(struct btree_keys *b, struct bset *i, unsigned set)
{
	struct bkey_format *f = &b->format;
	struct bkey_packed *_k, *_n;
	struct bkey k, n;
	char buf[120];

	if (!i->u64s)
		return;

	for (_k = i->start, k = bkey_unpack_key(f, _k);
	     _k < bset_bkey_last(i);
	     _k = _n, k = n) {
		_n = bkey_next(_k);

		bch_bkey_to_text(buf, sizeof(buf), &k);
		printk(KERN_ERR "block %u key %zi/%u: %s\n", set,
		       _k->_data - i->_data, i->u64s, buf);

		if (_n == bset_bkey_last(i))
			continue;

		n = bkey_unpack_key(f, _n);

		if (bkey_cmp(bkey_start_pos(&n), k.p) < 0)
			printk(KERN_ERR "Key skipped backwards\n");
		else if (!b->ops->is_extents &&
			 !bkey_deleted(&k) &&
			 !bkey_cmp(n.p, k.p))
			printk(KERN_ERR "Duplicate keys\n");
	}
}

void bch_dump_bucket(struct btree_keys *b)
{
	unsigned i;

	console_lock();
	for (i = 0; i <= b->nsets; i++)
		bch_dump_bset(b, b->set[i].data, i);
	console_unlock();
}

s64 __bch_count_data(struct btree_keys *b)
{
	struct btree_node_iter iter;
	struct bkey_tup k;
	u64 ret = 0;

	if (b->ops->is_extents)
		for_each_btree_node_key_unpack(b, &k, &iter)
			ret += k.k.size;

	return ret;
}

void __bch_verify_btree_nr_keys(struct btree_keys *b)
{
	struct btree_node_iter iter;
	struct bkey_packed *k;
	unsigned u64s = 0, packed = 0, unpacked = 0;

	for_each_btree_node_key(b, k, &iter) {
		u64s += k->u64s;
		if (bkey_packed(k))
			packed++;
		else
			unpacked++;
	}

	BUG_ON(b->nr.live_u64s		!= u64s);
	BUG_ON(b->nr.packed_keys	!= packed);
	BUG_ON(b->nr.unpacked_keys	!= unpacked);
}

#endif

/* Auxiliary search trees */

/* 32 bits total: */
#define BKEY_MID_BITS		8U
#define BKEY_EXPONENT_BITS	8U
#define BKEY_MANTISSA_BITS	(32 - BKEY_MID_BITS - BKEY_EXPONENT_BITS)
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

#define BFLOAT_EXPONENT_MAX	((1 << BKEY_EXPONENT_BITS) - 1)

#define BFLOAT_FAILED_UNPACKED	(BFLOAT_EXPONENT_MAX - 0)
#define BFLOAT_FAILED_PREV	(BFLOAT_EXPONENT_MAX - 1)
#define BFLOAT_FAILED_OVERFLOW	(BFLOAT_EXPONENT_MAX - 2)
#define BFLOAT_FAILED		(BFLOAT_EXPONENT_MAX - 2)

#define KEY_WORDS		BITS_TO_LONGS(1 << BKEY_EXPONENT_BITS)

struct bkey_float {
	unsigned	exponent:BKEY_EXPONENT_BITS;
	unsigned	m:BKEY_MID_BITS;
	unsigned	mantissa:BKEY_MANTISSA_BITS;
} __packed;

/*
 * BSET_CACHELINE was originally intended to match the hardware cacheline size -
 * it used to be 64, but I realized the lookup code would touch slightly less
 * memory if it was 128.
 *
 * It definites the number of bytes (in struct bset) per struct bkey_float in
 * the auxiliar search tree - when we're done searching the bset_float tree we
 * have this many bytes left that we do a linear search over.
 *
 * Since (after level 5) every level of the bset_tree is on a new cacheline,
 * we're touching one fewer cacheline in the bset tree in exchange for one more
 * cacheline in the linear search - but the linear search might stop before it
 * gets to the second cacheline.
 */

#define BSET_CACHELINE		128

/* Space required for the btree node keys */
static inline size_t btree_keys_bytes(struct btree_keys *b)
{
	return PAGE_SIZE << b->page_order;
}

static inline size_t btree_keys_cachelines(struct btree_keys *b)
{
	return btree_keys_bytes(b) / BSET_CACHELINE;
}

/* Space required for the auxiliary search trees */
static inline size_t bset_tree_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(struct bkey_float);
}

/* Space required for the prev pointers */
static inline size_t bset_prev_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(u8);
}

/* Memory allocation */

void bch_btree_keys_free(struct btree_keys *b)
{
	struct bset_tree *t = b->set;

	if (bset_prev_bytes(b) < PAGE_SIZE)
		kfree(t->prev);
	else
		free_pages((unsigned long) t->prev,
			   get_order(bset_prev_bytes(b)));

	if (bset_tree_bytes(b) < PAGE_SIZE)
		kfree(t->tree);
	else
		free_pages((unsigned long) t->tree,
			   get_order(bset_tree_bytes(b)));

	t->prev = NULL;
	t->tree = NULL;
}
EXPORT_SYMBOL(bch_btree_keys_free);

int bch_btree_keys_alloc(struct btree_keys *b, unsigned page_order, gfp_t gfp)
{
	struct bset_tree *t = b->set;

	BUG_ON(t->tree || t->prev);

	b->page_order = page_order;

	t->tree = bset_tree_bytes(b) < PAGE_SIZE
		? kmalloc(bset_tree_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_tree_bytes(b)));
	if (!t->tree)
		goto err;

	t->prev = bset_prev_bytes(b) < PAGE_SIZE
		? kmalloc(bset_prev_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_prev_bytes(b)));
	if (!t->prev)
		goto err;

	return 0;
err:
	bch_btree_keys_free(b);
	return -ENOMEM;
}
EXPORT_SYMBOL(bch_btree_keys_alloc);

void bch_btree_keys_init(struct btree_keys *b, const struct btree_keys_ops *ops,
			 bool *expensive_debug_checks)
{
	struct bkey_format_state s;
	unsigned i;

	bch_bkey_format_init(&s);
	b->format = bch_bkey_format_done(&s);

	b->ops			= ops;
	b->nsets		= 0;
	memset(&b->nr, 0, sizeof(b->nr));
#ifdef CONFIG_BCACHEFS_DEBUG
	b->expensive_debug_checks = expensive_debug_checks;
#endif
	for (i = 0; i < MAX_BSETS; i++) {
		b->set[i].data = NULL;
		b->set[i].size = 0;
		b->set[i].extra = BSET_TREE_NONE_VAL;
	}
}
EXPORT_SYMBOL(bch_btree_keys_init);

/* Binary tree stuff for auxiliary search trees */

static unsigned inorder_next(unsigned j, unsigned size)
{
	if (j * 2 + 1 < size) {
		j = j * 2 + 1;

		while (j * 2 < size)
			j *= 2;
	} else
		j >>= ffz(j) + 1;

	return j;
}

static unsigned inorder_prev(unsigned j, unsigned size)
{
	if (j * 2 < size) {
		j = j * 2;

		while (j * 2 + 1 < size)
			j = j * 2 + 1;
	} else
		j >>= ffs(j);

	return j;
}

/* I have no idea why this code works... and I'm the one who wrote it
 *
 * However, I do know what it does:
 * Given a binary tree constructed in an array (i.e. how you normally implement
 * a heap), it converts a node in the tree - referenced by array index - to the
 * index it would have if you did an inorder traversal.
 *
 * Also tested for every j, size up to size somewhere around 6 million.
 *
 * The binary tree starts at array index 1, not 0
 * extra is a function of size:
 *   extra = (size - rounddown_pow_of_two(size - 1)) << 1;
 */
static inline unsigned __to_inorder(unsigned j, unsigned size, unsigned extra)
{
	unsigned b = fls(j);
	unsigned shift = fls(size - 1) - b;

	j  ^= 1U << (b - 1);
	j <<= 1;
	j  |= 1;
	j <<= shift;

	if (j > extra)
		j -= (j - extra) >> 1;

	return j;
}

static inline unsigned to_inorder(unsigned j, struct bset_tree *t)
{
	return __to_inorder(j, t->size, t->extra);
}

static unsigned __inorder_to_tree(unsigned j, unsigned size, unsigned extra)
{
	unsigned shift;

	if (j > extra)
		j += j - extra;

	shift = ffs(j);

	j >>= shift;
	j  |= roundup_pow_of_two(size) >> shift;

	return j;
}

static unsigned inorder_to_tree(unsigned j, struct bset_tree *t)
{
	return __inorder_to_tree(j, t->size, t->extra);
}

#if 0
void inorder_test(void)
{
	unsigned long done = 0;
	ktime_t start = ktime_get();

	for (unsigned size = 2;
	     size < 65536000;
	     size++) {
		unsigned extra = (size - rounddown_pow_of_two(size - 1)) << 1;
		unsigned i = 1, j = rounddown_pow_of_two(size - 1);

		if (!(size % 4096))
			printk(KERN_NOTICE "loop %u, %llu per us\n", size,
			       done / ktime_us_delta(ktime_get(), start));

		while (1) {
			if (__inorder_to_tree(i, size, extra) != j)
				panic("size %10u j %10u i %10u", size, j, i);

			if (__to_inorder(j, size, extra) != i)
				panic("size %10u j %10u i %10u", size, j, i);

			if (j == rounddown_pow_of_two(size) - 1)
				break;

			BUG_ON(inorder_prev(inorder_next(j, size), size) != j);

			j = inorder_next(j, size);
			i++;
		}

		done += size - 1;
	}
}
#endif

/*
 * Cacheline/offset <-> bkey pointer arithmetic:
 *
 * t->tree is a binary search tree in an array; each node corresponds to a key
 * in one cacheline in t->set (BSET_CACHELINE bytes).
 *
 * This means we don't have to store the full index of the key that a node in
 * the binary tree points to; to_inorder() gives us the cacheline, and then
 * bkey_float->m gives us the offset within that cacheline, in units of 8 bytes.
 *
 * cacheline_to_bkey() and friends abstract out all the pointer arithmetic to
 * make this work.
 *
 * To construct the bfloat for an arbitrary key we need to know what the key
 * immediately preceding it is: we have to check if the two keys differ in the
 * bits we're going to store in bkey_float->mantissa. t->prev[j] stores the size
 * of the previous key so we can walk backwards to it from t->tree[j]'s key.
 */

static struct bkey_packed *cacheline_to_bkey(struct bset_tree *t,
					     unsigned cacheline,
					     unsigned offset)
{
	return ((void *) t->data) + cacheline * BSET_CACHELINE + offset * 8;
}

static unsigned bkey_to_cacheline(struct bset_tree *t, struct bkey_packed *k)
{
	return ((void *) k - (void *) t->data) / BSET_CACHELINE;
}

static unsigned bkey_to_cacheline_offset(struct bset_tree *t,
					 unsigned cacheline,
					 struct bkey_packed *k)
{
	size_t m = (u64 *) k - (u64 *) cacheline_to_bkey(t, cacheline, 0);

	BUG_ON(m > (1U << BKEY_MID_BITS) - 1);
	return m;
}

static struct bkey_packed *tree_to_bkey(struct bset_tree *t, unsigned j)
{
	return cacheline_to_bkey(t, to_inorder(j, t), t->tree[j].m);
}

static struct bkey_packed *tree_to_prev_bkey(struct bset_tree *t, unsigned j)
{
	return (void *) (((u64 *) tree_to_bkey(t, j)) - t->prev[j]);
}

/*
 * For the write set - the one we're currently inserting keys into - we don't
 * maintain a full search tree, we just keep a simple lookup table in t->prev.
 */
static struct bkey_packed *table_to_bkey(struct bset_tree *t,
					 unsigned cacheline)
{
	return cacheline_to_bkey(t, cacheline, t->prev[cacheline]);
}

static inline unsigned bfloat_mantissa(const struct bkey_packed *k,
				       const struct bkey_float *f)
{
	u64 *ptr;

	EBUG_ON(!bkey_packed(k));

	ptr = (u64 *) (((u32 *) k->_data) + (f->exponent >> 5));

	return (get_unaligned(ptr) >> (f->exponent & 31)) &
		BKEY_MANTISSA_MASK;
}

static void make_bfloat(struct bkey_format *format,
			struct bset_tree *t, unsigned j)
{
	struct bkey_float *f = &t->tree[j];
	struct bkey_packed *m = tree_to_bkey(t, j);
	struct bkey_packed *p = tree_to_prev_bkey(t, j);

	struct bkey_packed *l = is_power_of_2(j)
		? t->data->start
		: tree_to_prev_bkey(t, j >> ffs(j));

	struct bkey_packed *r = is_power_of_2(j + 1)
		? bset_bkey_idx(t->data, t->data->u64s - t->end.u64s)
		: tree_to_bkey(t, j >> (ffz(j) + 1));
	unsigned exponent, shift, extra = 0, key_bits_start =
		format->key_u64s * 64 - bkey_format_key_bits(format);

	EBUG_ON(m < l || m > r);
	EBUG_ON(bkey_next(p) != m);

	/*
	 * for failed bfloats, the lookup code falls back to comparing against
	 * the original key.
	 */

	if (!bkey_packed(l) || !bkey_packed(r) ||
	    !bkey_packed(p) || !bkey_packed(m)) {
		f->exponent = BFLOAT_FAILED_UNPACKED;
		return;
	}

	exponent = max_t(int, bkey_greatest_differing_bit(format, l, r) -
			 BKEY_MANTISSA_BITS + 1, 0);

#ifdef __LITTLE_ENDIAN
	shift = key_bits_start + exponent;
#endif
	EBUG_ON(shift >= BFLOAT_FAILED);

	/*
	 * There might be fewer key bits than BKEY_MANTISSA_BITS:
	 * bfloat_mantissa() is in the fast path so it doesn't check for this -
	 * it's going to return some garbage bits we don't want.
	 *
	 * So firstly, ensure that the garbage bits are the least significant
	 * bits:
	 */
	if (shift > format->key_u64s * 64 - BKEY_MANTISSA_BITS) {
		shift = format->key_u64s * 64 - BKEY_MANTISSA_BITS;
		extra = key_bits_start - shift;
	}

	/*
	 * If we've got garbage bits, set them to all 1s - it's legal for the
	 * bfloat to compare larger than the original key, but not smaller:
	 */
	f->exponent = shift;
	f->mantissa = bfloat_mantissa(m, f) | ~(~0U << extra);

	/*
	 * The bfloat must be able to tell its key apart from the previous key -
	 * if its key and the previous key don't differ in the required bits,
	 * flag as failed - unless the keys are actually equal, in which case
	 * we aren't required to return a specific one:
	 */
	if (shift > key_bits_start &&
	    f->mantissa == bfloat_mantissa(p, f) &&
	    bkey_cmp_packed(format, p, m)) {
		f->exponent = BFLOAT_FAILED_PREV;
		return;
	}

	/*
	 * f->mantissa must compare >= the original key - for transitivity with
	 * the comparison in bset_search_tree. If we're dropping set bits,
	 * increment it:
	 */
	if (shift > key_bits_start &&
	    shift > key_bits_start + bkey_ffs(format, m)) {
		if (f->mantissa == BKEY_MANTISSA_MASK)
			f->exponent = BFLOAT_FAILED_OVERFLOW;

		f->mantissa++;
	}
}

static void bset_alloc_tree(struct btree_keys *b, struct bset_tree *t)
{
	if (t != b->set) {
		unsigned j = round_up(t[-1].size,
				      64 / sizeof(struct bkey_float));

		t->tree = t[-1].tree + j;
		t->prev = t[-1].prev + j;

		BUG_ON(t->tree > b->set->tree + btree_keys_cachelines(b));
	}

	t->size = 0;

	while (++t < b->set + MAX_BSETS) {
		t->size = 0;
		t->tree = NULL;
		t->prev = NULL;
	}
}

/* Only valid for the last bset: */
static unsigned bset_tree_capacity(struct btree_keys *b, struct bset_tree *t)
{
	EBUG_ON(t != bset_tree_last(b));

	return b->set->tree + btree_keys_cachelines(b) - t->tree;
}

static void bch_bset_build_unwritten_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);

	bset_alloc_tree(b, t);

	if (bset_tree_capacity(b, t)) {
		t->prev[0] = bkey_to_cacheline_offset(t, 0, t->data->start);
		t->size = 1;
		t->extra = BSET_TREE_UNWRITTEN_VAL;
	} else {
		t->extra = BSET_TREE_NONE_VAL;
	}
}

void bch_bset_init_first(struct btree_keys *b, struct bset *i)
{
	b->set[0].data = i;
	memset(i, 0, sizeof(*i));
	get_random_bytes(&i->seq, sizeof(i->seq));

	bch_bset_build_unwritten_tree(b);
}
EXPORT_SYMBOL(bch_bset_init_first);

void bch_bset_init_next(struct btree_keys *b, struct bset *i)
{
	b->set[++b->nsets].data = i;
	memset(i, 0, sizeof(*i));
	i->seq = b->set->data->seq;

	bch_bset_build_unwritten_tree(b);
}
EXPORT_SYMBOL(bch_bset_init_next);

void bch_bset_build_written_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);
	struct bkey_packed *prev = NULL, *k = t->data->start;
	unsigned j, cacheline = 1;

	bset_alloc_tree(b, t);

	t->size = min(bkey_to_cacheline(t, bset_bkey_last(t->data)),
		      bset_tree_capacity(b, t));
retry:
	if (t->size < 2) {
		t->size = 0;
		t->extra = BSET_TREE_NONE_VAL;
		return;
	}

	t->extra = (t->size - rounddown_pow_of_two(t->size - 1)) << 1;
	BUG_ON(!bset_written(t));

	/* First we figure out where the first key in each cacheline is */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size)) {
		while (bkey_to_cacheline(t, k) < cacheline)
			prev = k, k = bkey_next(k);

		if (k >= bset_bkey_last(t->data)) {
			t->size--;
			goto retry;
		}

		t->prev[j] = prev->u64s;
		t->tree[j].m = bkey_to_cacheline_offset(t, cacheline++, k);

		BUG_ON(tree_to_prev_bkey(t, j) != prev);
		BUG_ON(tree_to_bkey(t, j) != k);
	}

	while (bkey_next(k) != bset_bkey_last(t->data))
		k = bkey_next(k);

	t->end = *k;

	/* Then we build the tree */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size))
		make_bfloat(&b->format, t, j);
}
EXPORT_SYMBOL(bch_bset_build_written_tree);

struct bkey_packed *bkey_prev(struct bset_tree *t, struct bkey_packed *k)
{
	struct bkey_packed *p;
	int j;

	if (k == t->data->start)
		return NULL;

	j = min(bkey_to_cacheline(t, k), t->size);

	do {
		if (--j <= 0) {
			p = t->data->start;
			break;

		}

		p = bset_written(t)
			? tree_to_bkey(t, inorder_to_tree(j, t))
			: table_to_bkey(t, j);
	} while (p == k);

	while (bkey_next(p) != k)
		p = bkey_next(p);

	return p;
}

/* Insert */

static void verify_insert_pos(struct btree_keys *b,
			      const struct bkey_packed *prev,
			      const struct bkey_packed *where,
			      const struct bkey_i *insert)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	const struct bkey_format *f = &b->format;
	struct bset_tree *t = bset_tree_last(b);

	BUG_ON(prev &&
	       keys_out_of_order(f, prev, bkey_to_packed_c(insert),
				 b->ops->is_extents));

	BUG_ON(where != bset_bkey_last(t->data) &&
	       keys_out_of_order(f, bkey_to_packed_c(insert), where,
				 b->ops->is_extents));
#endif
}

/**
 * bch_bset_fix_invalidated_key() - given an existing  key @k that has been
 * modified, fix any auxiliary search tree by remaking all the nodes in the
 * auxiliary search tree that @k corresponds to
 */
void bch_bset_fix_invalidated_key(struct btree_keys *b, struct bkey_packed *k)
{
	struct bset_tree *t;
	unsigned inorder, j = 1;

	for (t = b->set; t <= bset_tree_last(b); t++)
		if (k < bset_bkey_last(t->data))
			goto found_set;

	BUG();
found_set:
	if (!bset_written(t))
		return;

	inorder = bkey_to_cacheline(t, k);

	if (k == t->data->start)
		for (j = 1; j < t->size; j = j * 2)
			make_bfloat(&b->format, t, j);

	if (bkey_next(k) == bset_bkey_last(t->data)) {
		t->end = *k;

		for (j = 1; j < t->size; j = j * 2 + 1)
			make_bfloat(&b->format, t, j);
	}

	j = inorder_to_tree(inorder, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_bkey(t, j)) {
		/* Fix the auxiliary search tree node this key corresponds to */
		make_bfloat(&b->format, t, j);

		/* Children for which this key is the right side boundary */
		for (j = j * 2; j < t->size; j = j * 2 + 1)
			make_bfloat(&b->format, t, j);
	}

	j = inorder_to_tree(inorder + 1, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_prev_bkey(t, j)) {
		make_bfloat(&b->format, t, j);

		/* Children for which this key is the left side boundary */
		for (j = j * 2 + 1; j < t->size; j = j * 2)
			make_bfloat(&b->format, t, j);
	}
}
EXPORT_SYMBOL(bch_bset_fix_invalidated_key);

static void bch_bset_fix_lookup_table(struct btree_keys *b,
				      struct bset_tree *t,
				      struct bkey_packed *k)
{
	unsigned shift = k->u64s;
	unsigned j = bkey_to_cacheline(t, k);

	BUG_ON(bset_written(t));

	if (bset_tree_type(t) == BSET_TREE_NONE)
		return;

	/* k is the key we just inserted; we need to find the entry in the
	 * lookup table for the first key that is strictly greater than k:
	 * it's either k's cacheline or the next one
	 */
	while (j < t->size &&
	       table_to_bkey(t, j) <= k)
		j++;

	/* Adjust all the lookup table entries, and find a new key for any that
	 * have gotten too big
	 */
	for (; j < t->size; j++) {
		/* Avoid overflow - might temporarily be larger than a u8 */
		unsigned p = (unsigned) t->prev[j] + shift;

		if (p > 7) {
			k = table_to_bkey(t, j - 1);

			while (k < cacheline_to_bkey(t, j, 0))
				k = bkey_next(k);

			p = bkey_to_cacheline_offset(t, j, k);
		}

		t->prev[j] = p;
	}

	BUG_ON(t->size > bset_tree_capacity(b, t));

	if (t->size == bset_tree_capacity(b, t))
		return;

	/* Possibly add a new entry to the end of the lookup table */

	for (k = table_to_bkey(t, t->size - 1);
	     k != bset_bkey_last(t->data);
	     k = bkey_next(k))
		if (t->size == bkey_to_cacheline(t, k)) {
			t->prev[t->size] = bkey_to_cacheline_offset(t, t->size, k);
			t->size++;
			return;
		}
}

/**
 * bch_bset_insert - insert the key @insert into @b
 *
 * Attempts front and back merges (if @b has a method for key merging).
 *
 * @iter is used as a hint for where to insert at, but it's not
 * fixed/revalidated for the insertion, that's the caller's responsibility
 * (because there may be other iterators to fix, it's easier to just do all of
 * them the same way).
 *
 * If an insert was done (and not a merge), returns the position of the insert:
 * it is the caller's responsibility to update all iterators that point to @b
 * with bch_btree_node_iter_fix().
 *
 * If NULL is returned, the caller must sort all iterators that point to @b
 * with bch_btree_node_iter_sort(), because we may have done a merge that
 * modified one of the keys the iterator currently points to.
 */
struct bkey_packed *bch_bset_insert(struct btree_keys *b,
				    struct btree_node_iter *iter,
				    struct bkey_i *insert)
{
	struct bkey_format *f = &b->format;
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = t->data;
	struct bkey_packed *prev = NULL;
	struct bkey_packed *where = bch_btree_node_iter_bset_pos(iter, b, i) ?:
		bset_bkey_last(i);
	struct bkey_packed packed, *src;
	BKEY_PADDED(k) tmp;

	BUG_ON(bset_written(t));
	BUG_ON(insert->k.u64s < BKEY_U64s);
	BUG_ON(insert->k.format != KEY_FORMAT_CURRENT);
	BUG_ON(b->ops->is_extents &&
	       (!insert->k.size || bkey_deleted(&insert->k)));

	BUG_ON(where < i->start);
	BUG_ON(where > bset_bkey_last(i));
	bch_verify_btree_nr_keys(b);

	while (where != bset_bkey_last(i) &&
	       keys_out_of_order(f, bkey_to_packed(insert),
				 where, b->ops->is_extents))
		prev = where, where = bkey_next(where);

	if (!prev)
		prev = bkey_prev(t, where);

	verify_insert_pos(b, prev, where, insert);

	/* prev is in the tree, if we merge we're done */
	if (prev &&
	    bch_bkey_try_merge_inline(b, iter, prev,
				      bkey_to_packed(insert), true))
		return NULL;

	if (where != bset_bkey_last(i) &&
	    bkey_bytes(&insert->k) <= sizeof(tmp)) {
		bkey_copy(&tmp.k, insert);
		insert = &tmp.k;

		/*
		 * bch_bkey_try_merge() modifies the left argument, but we can't
		 * modify insert since the caller needs to be able to journal
		 * the key that was actually inserted (and it can't just pass us
		 * a copy of insert, since ->insert_fixup() might trim insert if
		 * this is a replace operation)
		 */
		if (bch_bkey_try_merge_inline(b, iter,
					      bkey_to_packed(insert),
					      where, false))
			return NULL;
	}

	/*
	 * Can we overwrite the current key, instead of doing a memmove()?
	 *
	 * This is only legal for extents that are marked as deleted - because
	 * extents are marked as deleted iff they are 0 size, deleted extents
	 * don't overlap with any other existing keys. Non extents marked as
	 * deleted may be needed as whiteouts, until the node is rewritten.
	 */
	if (b->ops->is_extents &&
	    where != bset_bkey_last(i) &&
	    where->u64s == insert->k.u64s &&
	    bkey_deleted(where)) {
		if (!bkey_deleted(&insert->k))
			btree_keys_account_key_add(&b->nr,
					bkey_to_packed(insert));

		bkey_copy((void *) where, insert);
		return NULL;
	}

	src = bkey_pack_key(&packed, &insert->k, f)
		? &packed
		: bkey_to_packed(insert);

	memmove((u64 *) where + src->u64s,
		where,
		(void *) bset_bkey_last(i) - (void *) where);

	memcpy(where, src,
	       bkeyp_key_bytes(f, src));
	memcpy(bkeyp_val(f, where), &insert->v,
	       bkeyp_val_bytes(f, src));
	i->u64s += src->u64s;

	if (!bkey_deleted(src))
		btree_keys_account_key_add(&b->nr, src);

	bch_bset_fix_lookup_table(b, t, where);
	bch_verify_btree_nr_keys(b);

	return where;
}
EXPORT_SYMBOL(bch_bset_insert);

/* Lookup */

__attribute__((flatten))
static struct bkey_packed *bset_search_write_set(const struct bkey_format *f,
				struct bset_tree *t,
				struct bpos search,
				const struct bkey_packed *packed_search)
{
	unsigned li = 0, ri = t->size;

	while (li + 1 != ri) {
		unsigned m = (li + ri) >> 1;

		if (bkey_cmp_p_or_unp(f, table_to_bkey(t, m),
				      packed_search, search) >= 0)
			ri = m;
		else
			li = m;
	}

	return table_to_bkey(t, li);
}

__attribute__((flatten))
static struct bkey_packed *bset_search_tree(const struct bkey_format *format,
				struct bset_tree *t,
				struct bpos search,
				const struct bkey_packed *packed_search)
{
	struct bkey_float *f = &t->tree[1];
	unsigned inorder, n = 1;

	/*
	 * If there are bits in search that don't fit in the packed format,
	 * packed_search will always compare less than search - it'll
	 * effectively have 0s where search did not - so we can still use
	 * packed_search and we'll just do more linear searching than we would
	 * have.
	 *
	 * If we can't pack a pos that compares <= search, we're screwed:
	 */
	if (!packed_search)
		return t->data->start;

	while (1) {
		if (likely(n << 4 < t->size)) {
			prefetch(&t->tree[n << 4]);
		} else if (n << 3 < t->size) {
			inorder = to_inorder(n, t);
			prefetch(cacheline_to_bkey(t, inorder, 0));
			prefetch(cacheline_to_bkey(t, inorder + 1, 0));
			prefetch(cacheline_to_bkey(t, inorder + 2, 0));
			prefetch(cacheline_to_bkey(t, inorder + 3, 0));
		} else if (n >= t->size)
			break;

		f = &t->tree[n];

		/*
		 * n *= 2;
		 * if (bfloat_mantissa(search) >= f->mantissa)
		 *	n++;
		 *
		 * n = (f->mantissa >= bfloat_mantissa(search))
		 *	? n * 2
		 *	: n * 2 + 1;
		 *
		 * n = (f->mantissa - bfloat_mantissa(search) >= 0)
		 *	? n * 2
		 *	: n * 2 + 1;
		 */
		if (likely(f->exponent < BFLOAT_FAILED))
			n = n * 2 + (((unsigned)
				      (f->mantissa -
				       bfloat_mantissa(packed_search,
						       f))) >> 31);
		else
			n = bkey_cmp_p_or_unp(format, tree_to_bkey(t, n),
					      packed_search, search) >= 0
				? n * 2
				: n * 2 + 1;
	} while (n < t->size);

	inorder = to_inorder(n >> 1, t);

	/*
	 * n would have been the node we recursed to - the low bit tells us if
	 * we recursed left or recursed right.
	 */
	if (n & 1) {
		return cacheline_to_bkey(t, inorder, f->m);
	} else {
		if (--inorder) {
			f = &t->tree[inorder_prev(n >> 1, t->size)];
			return cacheline_to_bkey(t, inorder, f->m);
		} else
			return t->data->start;
	}
}

/*
 * Returns the first key greater than or equal to @search
 */
__always_inline
static struct bkey_packed *bch_bset_search(struct btree_keys *b,
				struct bset_tree *t,
				struct bpos search,
				struct bkey_packed *packed_search,
				const struct bkey_packed *lossy_packed_search)
{
	const struct bkey_format *f = &b->format;
	struct bkey_packed *m;

	/*
	 * First, we search for a cacheline, then lastly we do a linear search
	 * within that cacheline.
	 *
	 * To search for the cacheline, there's three different possibilities:
	 *  * The set is too small to have a search tree, so we just do a linear
	 *    search over the whole set.
	 *  * The set is the one we're currently inserting into; keeping a full
	 *    auxiliary search tree up to date would be too expensive, so we
	 *    use a much simpler lookup table to do a binary search -
	 *    bset_search_write_set().
	 *  * Or we use the auxiliary search tree we constructed earlier -
	 *    bset_search_tree()
	 */

	switch (bset_tree_type(t)) {
	case BSET_TREE_NONE:
		m = t->data->start;
		break;
	case BSET_TREE_UNWRITTEN:
		m = bset_search_write_set(f, t, search, lossy_packed_search);
		break;
	case BSET_TREE_WRITTEN:
		/*
		 * Each node in the auxiliary search tree covers a certain range
		 * of bits, and keys above and below the set it covers might
		 * differ outside those bits - so we have to special case the
		 * start and end - handle that here:
		 */

		if (unlikely(bkey_cmp_p_or_unp(f, &t->end,
					       packed_search, search) < 0))
			return bset_bkey_last(t->data);

		if (unlikely(bkey_cmp_p_or_unp(f, t->data->start,
					       packed_search, search) >= 0))
			return t->data->start;

		m = bset_search_tree(f, t, search, lossy_packed_search);
		break;
	}

	if (lossy_packed_search)
		while (m != bset_bkey_last(t->data) &&
		       bkey_cmp_p_or_unp(f, m,
					 lossy_packed_search, search) < 0)
			m = bkey_next(m);

	if (!packed_search)
		while (m != bset_bkey_last(t->data) &&
		       bkey_cmp_left_packed(f, m, search) < 0)
			m = bkey_next(m);

	if (btree_keys_expensive_checks(b)) {
		struct bkey_packed *p = bkey_prev(t, m);

		BUG_ON(p &&
		       bkey_cmp_p_or_unp(f, p, packed_search, search) >= 0);
	}

	return m;
}

/* Btree node iterator */

static inline bool __btree_node_iter_cmp(struct btree_node_iter *iter,
					 struct btree_keys *b,
					 struct bkey_packed *l,
					 struct bkey_packed *r)
{
	s64 c = bkey_cmp_packed(&b->format, l, r);

	/*
	 * For non extents, when keys compare equal the deleted keys have to
	 * come first - so that bch_btree_node_iter_next_check() can detect
	 * duplicate nondeleted keys (and possibly other reasons?)
	 *
	 * For extents, bkey_deleted() is used as a proxy for k->size == 0, so
	 * deleted keys have to sort last.
	 */
	return c ? c > 0
		: iter->is_extents
		? bkey_deleted(l) > bkey_deleted(r)
		: bkey_deleted(l) < bkey_deleted(r);
}

/*
 * Returns true if l > r:
 */
static inline bool btree_node_iter_cmp(struct btree_node_iter *iter,
				       struct btree_keys *b,
				       struct btree_node_iter_set l,
				       struct btree_node_iter_set r)
{
	return __btree_node_iter_cmp(iter, b,
			__btree_node_offset_to_key(b, l.k),
			__btree_node_offset_to_key(b, r.k));
}

void bch_btree_node_iter_push(struct btree_node_iter *iter,
			      struct btree_keys *b,
			      const struct bkey_packed *k,
			      const struct bkey_packed *end)
{
	if (k != end) {
		struct btree_node_iter_set n =
			((struct btree_node_iter_set) {
				 __btree_node_key_to_offset(b, k),
				 __btree_node_key_to_offset(b, end)
			 });
		unsigned i;

		for (i = 0;
		     i < iter->used &&
		     btree_node_iter_cmp(iter, b, n, iter->data[i]);
		     i++)
			;

		memmove(&iter->data[i + 1],
			&iter->data[i],
			(iter->used - i) * sizeof(struct btree_node_iter_set));
		iter->used++;
		iter->data[i] = n;
	}
}

/**
 * bch_btree_node_iter_init - initialize a btree node iterator, starting from a
 * given position
 *
 * Main entry point to the lookup code for individual btree nodes:
 *
 * NOTE:
 *
 * When you don't filter out deleted keys, btree nodes _do_ contain duplicate
 * keys. This doesn't matter for most code, but it does matter for lookups.
 *
 * Some adjacent keys with a string of equal keys:
 *	i j k k k k l m
 *
 * If you search for k, the lookup code isn't guaranteed to return you any
 * specific k. The lookup code is conceptually doing a binary search and
 * iterating backwards is very expensive so if the pivot happens to land at the
 * last k that's what you'll get.
 *
 * This works out ok, but it's something to be aware of:
 *
 *  - For non extents, we guarantee that the live key comes last - see
 *    btree_node_iter_cmp(), keys_out_of_order(). So the duplicates you don't
 *    see will only be deleted keys you don't care about.
 *
 *  - For extents, deleted keys sort last (see the comment at the top of this
 *    file). But when you're searching for extents, you actually want the first
 *    key strictly greater than your search key - an extent that compares equal
 *    to the search key is going to have 0 sectors after the search key.
 *
 *    But this does mean that we can't just search for
 *    bkey_successor(start_of_range) to get the first extent that overlaps with
 *    the range we want - if we're unlucky and there's an extent that ends
 *    exactly where we searched, then there could be a deleted key at the same
 *    position and we'd get that when we search instead of the preceding extent
 *    we needed.
 *
 *    So we've got to search for start_of_range, then after the lookup iterate
 *    past any extents that compare equal to the position we searched for.
 */
void bch_btree_node_iter_init(struct btree_node_iter *iter,
			      struct btree_keys *b, struct bpos search,
			      bool strictly_greater)
{
	struct bset_tree *t;
	struct bkey_packed p, *packed_search, *lossy_packed_search;

	switch (bkey_pack_pos_lossy(&p, search, &b->format)) {
	case BKEY_PACK_POS_EXACT:
		packed_search = &p;
		lossy_packed_search = &p;
		break;
	case BKEY_PACK_POS_SMALLER:
		packed_search = NULL;
		lossy_packed_search = &p;
		trace_bkey_pack_pos_fail(search);
		break;
	case BKEY_PACK_POS_FAIL:
		packed_search = NULL;
		lossy_packed_search = NULL;
		trace_bkey_pack_pos_lossy_fail(search);
		break;
	default:
		BUG();
	}

	__bch_btree_node_iter_init(iter, b);

	for (t = b->set; t <= b->set + b->nsets; t++)
		bch_btree_node_iter_push(iter, b,
					 bch_bset_search(b, t, search,
							 packed_search,
							 lossy_packed_search),
					 bset_bkey_last(t->data));

	if (strictly_greater) {
		struct bkey_packed *m;

		while ((m = bch_btree_node_iter_peek_all(iter, b)) &&
		       (bkey_cmp_p_or_unp(&b->format, m,
					  packed_search, search) == 0))
			bch_btree_node_iter_advance(iter, b);
	}
}
EXPORT_SYMBOL(bch_btree_node_iter_init);

void bch_btree_node_iter_init_from_start(struct btree_node_iter *iter,
					 struct btree_keys *b)
{
	struct bset_tree *t;

	__bch_btree_node_iter_init(iter, b);

	for (t = b->set; t <= b->set + b->nsets; t++)
		bch_btree_node_iter_push(iter, b,
					 t->data->start,
					 bset_bkey_last(t->data));
}
EXPORT_SYMBOL(bch_btree_node_iter_init_from_start);

struct bkey_packed *bch_btree_node_iter_bset_pos(struct btree_node_iter *iter,
						 struct btree_keys *b,
						 struct bset *i)
{
	unsigned end = __btree_node_key_to_offset(b, bset_bkey_last(i));
	struct btree_node_iter_set *set;

	BUG_ON(iter->used > MAX_BSETS);

	for (set = iter->data;
	     set < iter->data + iter->used;
	     set++)
		if (end == set->end)
			return __btree_node_offset_to_key(b, set->k);

	return NULL;
}

static inline void btree_node_iter_sift(struct btree_node_iter *iter,
					struct btree_keys *b,
					unsigned start)
{
	unsigned i;

	BUG_ON(iter->used > MAX_BSETS);

	for (i = start;
	     i + 1 < iter->used &&
	     btree_node_iter_cmp(iter, b, iter->data[i], iter->data[i + 1]);
	     i++)
		swap(iter->data[i], iter->data[i + 1]);
}

void bch_btree_node_iter_sort(struct btree_node_iter *iter,
			      struct btree_keys *b)
{
	int i;

	BUG_ON(iter->used > MAX_BSETS);

	for (i = iter->used - 1; i >= 0; --i)
		btree_node_iter_sift(iter, b, i);
}
EXPORT_SYMBOL(bch_btree_node_iter_sort);

/**
 * bch_btree_node_iter_advance - advance @iter by one key
 *
 * Doesn't do debugchecks - for cases where (insert_fixup_extent()) a bset might
 * momentarily have out of order extents.
 */
void bch_btree_node_iter_advance(struct btree_node_iter *iter,
				 struct btree_keys *b)
{
	iter->data->k += __bch_btree_node_iter_peek_all(iter, b)->u64s;

	BUG_ON(iter->data->k > iter->data->end);

	if (iter->data->k == iter->data->end) {
		BUG_ON(iter->used == 0);
		iter->data[0] = iter->data[--iter->used];
	}

	btree_node_iter_sift(iter, b, 0);
}
EXPORT_SYMBOL(bch_btree_node_iter_advance);

#ifdef CONFIG_BCACHEFS_DEBUG
void bch_btree_node_iter_verify(struct btree_node_iter *iter,
				struct btree_keys *b)
{
	struct btree_node_iter_set *set;
	struct bset_tree *t;

	BUG_ON(iter->used > MAX_BSETS);

	for (set = iter->data;
	     set < iter->data + iter->used;
	     set++) {
		BUG_ON(set + 1 < iter->data + iter->used &&
		       btree_node_iter_cmp(iter, b, set[0], set[1]));

		for (t =  b->set;
		     t <= b->set + b->nsets;
		     t++)
			if (__btree_node_offset_to_key(b, set->end) ==
			    bset_bkey_last(t->data))
				goto next;
		BUG();
next:
		;
	}
}

static void bch_btree_node_iter_next_check(struct btree_node_iter *iter,
					   struct btree_keys *b,
					   struct bkey_packed *k)
{
	const struct bkey_format *f = &b->format;
	const struct bkey_packed *n = bch_btree_node_iter_peek_all(iter, b);

	bkey_unpack_key(f, k);

	if (n &&
	    keys_out_of_order(f, k, n, iter->is_extents)) {
		struct bkey ku = bkey_unpack_key(f, k);
		struct bkey nu = bkey_unpack_key(f, n);
		char buf1[80], buf2[80];

		bch_dump_bucket(b);
		bch_bkey_to_text(buf1, sizeof(buf1), &ku);
		bch_bkey_to_text(buf2, sizeof(buf2), &nu);
		panic("out of order/overlapping:\n%s\n%s\n", buf1, buf2);
	}
}

struct bkey_packed *bch_btree_node_iter_next_all(struct btree_node_iter *iter,
						 struct btree_keys *b)
{
	struct bkey_packed *ret = bch_btree_node_iter_peek_all(iter, b);

	if (ret) {
		bch_btree_node_iter_advance(iter, b);
		bch_btree_node_iter_next_check(iter, b, ret);
	}

	return ret;
}
EXPORT_SYMBOL(bch_btree_node_iter_next_all);
#endif

/*
 * Expensive:
 */
struct bkey_packed *bch_btree_node_iter_prev_all(struct btree_node_iter *iter,
						 struct btree_keys *b)
{
	struct bkey_packed *prev = NULL;
	struct btree_node_iter_set *i, *prev_set = NULL;
	struct bset_tree *t, *prev_t = NULL;
	struct bkey_packed *k;

	for (t = b->set; t <= b->set + b->nsets; t++) {
		for (i = iter->data; i < iter->data + iter->used; i++) {
			k = __btree_node_offset_to_key(b, i->k);

			if (k >= t->data->start && k < bset_bkey_last(t->data))
				goto found;
		}

		k = bset_bkey_last(t->data);
		i = NULL;
found:
		k = bkey_prev(t, k);

		if (k &&
		    (!prev ||
		     __btree_node_iter_cmp(iter, b, k, prev))) {
			prev = k;
			prev_set = i;
			prev_t = t;
		}
	}

	if (!prev)
		return NULL;

	if (prev_set) {
		prev_set->k -= prev->u64s;
		bch_btree_node_iter_sort(iter, b);
	} else {
		bch_btree_node_iter_push(iter, b, prev,
					 bset_bkey_last(prev_t->data));
	}

	return bch_btree_node_iter_peek_all(iter, b);
}

bool bch_btree_node_iter_next_unpack(struct btree_node_iter *iter,
				     struct btree_keys *b,
				     struct bkey_tup *tup)
{
	struct bkey_format *f = &b->format;
	struct bkey_packed *k = bch_btree_node_iter_next(iter, b);

	if (!k)
		return false;

	bkey_disassemble(tup, f, k);
	return true;
}
EXPORT_SYMBOL(bch_btree_node_iter_next_unpack);

/* Mergesort */

void bch_bset_sort_state_free(struct bset_sort_state *state)
{
	mempool_exit(&state->pool);
}

int bch_bset_sort_state_init(struct bset_sort_state *state, unsigned page_order,
			     struct time_stats *time)
{
	state->page_order = page_order;
	state->crit_factor = int_sqrt(1 << page_order);
	state->time = time;

	if (mempool_init_page_pool(&state->pool, 1, page_order))
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL(bch_bset_sort_state_init);

/* No repacking: */
static struct btree_nr_keys btree_mergesort_simple(struct btree_keys *b,
						   struct bset *bset,
						   struct btree_node_iter *iter)
{
	struct bkey_packed *in, *out = bset->start;

	while (!bch_btree_node_iter_end(iter)) {
		in = bch_btree_node_iter_next_all(iter, b);

		if (!bkey_deleted(in)) {
			/* XXX: need better bkey_copy */
			memcpy(out, in, bkey_bytes(in));
			out = bkey_next(out);
		}
	}

	bset->u64s = (u64 *) out - bset->_data;
	return b->nr;
}

/* Sort + repack in a new format: */
static struct btree_nr_keys btree_mergesort(struct btree_keys *dst,
					    struct bset *dst_set,
					    struct btree_keys *src,
					    struct btree_node_iter *iter,
					    ptr_filter_fn filter)
{
	struct bkey_format *in_f = &src->format;
	struct bkey_format *out_f = &dst->format;
	struct bkey_packed *in, *out = dst_set->start;
	struct btree_nr_keys nr;

	BUG_ON(filter);
	EBUG_ON(filter && !dst->ops->is_extents);

	memset(&nr, 0, sizeof(nr));

	while (!bch_btree_node_iter_end(iter)) {
		in = bch_btree_node_iter_next_all(iter, src);

		if (bkey_deleted(in))
			continue;

		if (bch_bkey_transform(out_f, out, bkey_packed(in)
				       ? in_f : &bch_bkey_format_current, in))
			out->format = KEY_FORMAT_LOCAL_BTREE;
		else
			bkey_unpack((void *) out, in_f, in);

		btree_keys_account_key_add(&nr, out);
		out = bkey_next(out);

		BUG_ON((void *) out >
		       (void *) dst_set + (PAGE_SIZE << dst->page_order));
	}

	dst_set->u64s = (u64 *) out - dst_set->_data;
	return nr;
}

/* Sort, repack, and merge extents */
static struct btree_nr_keys btree_mergesort_extents(struct btree_keys *dst,
						    struct bset *dst_set,
						    struct btree_keys *src,
						    struct btree_node_iter *iter,
						    ptr_filter_fn filter)
{
	struct bkey_format *in_f = &src->format;
	struct bkey_format *out_f = &dst->format;
	struct bkey_packed *k, *prev = NULL, *out = dst_set->start;
	struct btree_nr_keys nr;
	struct bkey_tup tup;
	BKEY_PADDED(k) tmp;

	EBUG_ON(!dst->ops->is_extents);

	memset(&nr, 0, sizeof(nr));

	while (!bch_btree_node_iter_end(iter)) {
		k = bch_btree_node_iter_next_all(iter, src);

		if (bkey_deleted(k))
			continue;

		/*
		 * The filter might modify pointers, so we have to unpack the
		 * key and values to &tmp.k:
		 */
		bkey_unpack(&tmp.k, in_f, k);

		if (filter && filter(src, bkey_i_to_s(&tmp.k)))
			continue;

		if (prev &&
		    src->ops->key_merge &&
		    bch_bkey_try_merge(src, (void *) prev, &tmp.k))
			continue;

		bkey_disassemble(&tup, in_f, bkey_to_packed(&tmp.k));

		if (prev) {
			bkey_pack(prev, (void *) prev, out_f);

			btree_keys_account_key_add(&nr, prev);
			out = bkey_next(prev);
		} else {
			out = dst_set->start;
		}

		bkey_reassemble((void *) out, bkey_tup_to_s_c(&tup));

		prev = out;
		out = bkey_next(out);

		BUG_ON((void *) out >
		       (void *) dst_set + (PAGE_SIZE << dst->page_order));
	}

	if (prev) {
		bkey_pack(prev, (void *) prev, out_f);
		btree_keys_account_key_add(&nr, prev);
		out = bkey_next(prev);
	} else {
		out = dst_set->start;
	}

	dst_set->u64s = (u64 *) out - dst_set->_data;
	return nr;
}

struct btree_nr_keys bch_sort_bsets(struct bset *dst, struct btree_keys *b,
				    unsigned from, struct btree_node_iter *iter,
				    btree_keys_sort_fn sort,
				    struct bset_sort_state *state)
{
	u64 start_time = local_clock();
	struct btree_node_iter _iter;
	struct btree_nr_keys nr;

	if (!iter) {
		struct bset_tree *t;

		iter = &_iter;
		__bch_btree_node_iter_init(iter, b);

		for (t = b->set + from; t <= b->set + b->nsets; t++)
			bch_btree_node_iter_push(iter, b,
						 t->data->start,
						 bset_bkey_last(t->data));
	}

	/*
	 * If we're only doing a partial sort (start != 0), then we can't merge
	 * extents because that might produce extents that overlap with 0 size
	 * extents in bsets we aren't sorting:
	 */
	if (sort)
		nr = sort(b, dst, iter);
	else if (b->ops->is_extents && !from)
		nr = btree_mergesort_extents(b, dst, b, iter, NULL);
	else
		nr = btree_mergesort_simple(b, dst, iter);

	if (!from)
		bch_time_stats_update(state->time, start_time);

	return nr;
}

/**
 * bch_btree_sort_into - sort with a specified output, instead of allocating
 * temporary space
 *
 * does not create the auxiliary search tree
 */
void bch_btree_sort_into(struct btree_keys *dst,
			 struct btree_keys *src,
			 ptr_filter_fn filter,
			 struct bset_sort_state *state)
{
	u64 start_time = local_clock();
	struct btree_node_iter iter;
	struct btree_nr_keys nr;

	bch_btree_node_iter_init_from_start(&iter, src);

	if (!dst->ops->is_extents)
		nr = btree_mergesort(dst, dst->set->data,
				     src, &iter, filter);
	else
		nr = btree_mergesort_extents(dst, dst->set->data,
					     src, &iter, filter);

	BUG_ON(set_bytes(dst->set->data) > (PAGE_SIZE << dst->page_order));

	bch_time_stats_update(state->time, start_time);

	dst->nr = nr;
	dst->nsets = 0;
	/* No auxiliary search tree yet */
	dst->set->size	= 0;
	dst->set->extra = BSET_TREE_NONE_VAL;

	bch_verify_btree_nr_keys(dst);
}

void bch_btree_keys_stats(struct btree_keys *b, struct bset_stats *stats)
{
	unsigned i;

	for (i = 0; i <= b->nsets; i++) {
		struct bset_tree *t = &b->set[i];
		enum bset_tree_type type = bset_tree_type(t);
		size_t j;

		stats->sets[type].nr++;
		stats->sets[type].bytes += t->data->u64s * sizeof(u64);

		if (bset_written(t)) {
			stats->floats += t->size - 1;

			for (j = 1; j < t->size; j++)
				switch (t->tree[j].exponent) {
				case BFLOAT_FAILED_UNPACKED:
					stats->failed_unpacked++;
					break;
				case BFLOAT_FAILED_PREV:
					stats->failed_prev++;
					break;
				case BFLOAT_FAILED_OVERFLOW:
					stats->failed_overflow++;
					break;
				}
		}
	}
}
