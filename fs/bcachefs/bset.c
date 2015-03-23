/*
 * Code for working with individual keys, and sorted sets of keys with in a
 * btree node
 *
 * Copyright 2012 Google, Inc.
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include "util.h"
#include "bset.h"

#include <asm/unaligned.h>
#include <linux/dynamic_fault.h>
#include <linux/console.h>
#include <linux/random.h>
#include <linux/prefetch.h>

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
	char buf[80];

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

	if (!btree_keys_expensive_checks(b))
		return -1;

	if (b->ops->is_extents)
		for_each_btree_node_key_unpack(b, &k, &iter)
			ret += k.k.size;

	return ret;
}

void __bch_count_data_verify(struct btree_keys *b, int oldsize)
{
	if (oldsize != -1) {
		int newsize = __bch_count_data(b);

		BUG_ON(newsize != -1 && newsize < oldsize);
	}
}

void bch_verify_btree_keys_accounting(struct btree_keys *b)
{
	struct btree_node_iter iter;
	struct bkey_packed *k;
	unsigned u64s = 0, packed = 0, unpacked = 0;

	if (!btree_keys_expensive_checks(b))
		return;

	for_each_btree_node_key(b, k, &iter) {
		u64s += k->u64s;
		if (bkey_packed(k))
			packed++;
		else
			unpacked++;
	}

	BUG_ON(b->nr_live_u64s		!= u64s);
	BUG_ON(b->nr_packed_keys	!= packed);
	BUG_ON(b->nr_unpacked_keys	!= unpacked);
}

#endif

/* Auxiliary search trees */

/* 32 bits total: */
#define BKEY_MID_BITS		5U
#define BKEY_EXPONENT_BITS	8U
#define BKEY_MANTISSA_BITS	(32 - BKEY_MID_BITS - BKEY_EXPONENT_BITS)
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

#define BFLOAT_FAILED		((1 << BKEY_EXPONENT_BITS) - 1)

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
	return btree_keys_cachelines(b) * sizeof(uint8_t);
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
	b->last_set_unwritten	= 0;
	b->nr_live_u64s		= 0;
	b->nr_packed_keys	= 0;
	b->nr_unpacked_keys	= 0;
#ifdef CONFIG_BCACHEFS_DEBUG
	b->expensive_debug_checks = expensive_debug_checks;
#endif
	for (i = 0; i < MAX_BSETS; i++) {
		b->set[i].data = NULL;
		b->set[i].size = 0;
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
	return (void *) (((uint64_t *) tree_to_bkey(t, j)) - t->prev[j]);
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
	unsigned exponent, shift, key_bits_start =
		format->key_u64s * 64 - bkey_format_key_bits(format);

	BUG_ON(m < l || m > r);
	BUG_ON(bkey_next(p) != m);

	/*
	 * for failed bfloats, the lookup code falls back to comparing against
	 * the original key.
	 */
	f->exponent = BFLOAT_FAILED;

	if (!bkey_packed(l) || !bkey_packed(r) ||
	    !bkey_packed(p) || !bkey_packed(m))
		return;

	exponent = max_t(int, bkey_greatest_differing_bit(format, l, r) -
			 BKEY_MANTISSA_BITS + 1, 0);

#ifdef __LITTLE_ENDIAN
	shift = min(key_bits_start + exponent,
		    format->key_u64s * 64 - BKEY_MANTISSA_BITS);
#endif
	BUG_ON(shift >= BFLOAT_FAILED);

	f->exponent = shift;
	f->mantissa = bfloat_mantissa(m, f) - 1;

	if (bfloat_mantissa(m, f) == bfloat_mantissa(p, f) &&
	    shift > format->key_u64s * 64 - bkey_format_key_bits(format))
		f->exponent = BFLOAT_FAILED;
}

static void bset_alloc_tree(struct btree_keys *b, struct bset_tree *t)
{
	if (t != b->set) {
		unsigned j = roundup(t[-1].size,
				     64 / sizeof(struct bkey_float));

		t->tree = t[-1].tree + j;
		t->prev = t[-1].prev + j;
	}

	while (t < b->set + MAX_BSETS)
		t++->size = 0;
}

static void bch_bset_build_unwritten_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);

	BUG_ON(b->last_set_unwritten);
	b->last_set_unwritten = 1;

	bset_alloc_tree(b, t);

	if (t->tree != b->set->tree + btree_keys_cachelines(b)) {
		t->prev[0] = bkey_to_cacheline_offset(t, 0, t->data->start);
		t->size = 1;
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

	b->last_set_unwritten = 0;

	bset_alloc_tree(b, t);

	t->size = min_t(unsigned,
			bkey_to_cacheline(t, bset_bkey_last(t->data)),
			b->set->tree + btree_keys_cachelines(b) - t->tree);
retry:
	if (t->size < 2) {
		t->size = 0;
		return;
	}

	t->extra = (t->size - rounddown_pow_of_two(t->size - 1)) << 1;

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

struct bkey_packed *bkey_prev(struct btree_keys *b,
			      struct bset_tree *t,
			      struct bkey_packed *k)
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

		p = bset_written(b, t)
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
 * Used by extent fixup functions which insert entries into the bset.
 * We have to update the iterator's cached ->end pointer.
 *
 * @top must be in the last bset.
 */
static void bch_btree_node_iter_fix(struct btree_node_iter *iter,
				    struct btree_keys *b,
				    const struct bkey_packed *where)
{
	struct btree_node_iter_set *set;
	unsigned offset = __btree_node_key_to_offset(b, where);
	unsigned shift = where->u64s;

	BUG_ON(iter->used > MAX_BSETS);

	for (set = iter->data;
	     set < iter->data + iter->used;
	     set++)
		if (set->end >= offset) {
			set->end += shift;

			if (set->k >= offset)
				set->k += shift;
			break;
		}
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
	if (!t->size || !bset_written(b, t))
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

	/* We're getting called from btree_split() or btree_gc, just bail out */
	if (!t->size)
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
		t->prev[j] += shift;

		if (t->prev[j] > 7) {
			k = table_to_bkey(t, j - 1);

			while (k < cacheline_to_bkey(t, j, 0))
				k = bkey_next(k);

			t->prev[j] = bkey_to_cacheline_offset(t, j, k);
		}
	}

	if (t->size == b->set->tree + btree_keys_cachelines(b) - t->tree)
		return;

	/* Possibly add a new entry to the end of the lookup table */

	for (k = table_to_bkey(t, t->size - 1);
	     k != bset_bkey_last(t->data);
	     k = bkey_next(k))
		if (t->size == bkey_to_cacheline(t, k)) {
			t->prev[t->size] = bkey_to_cacheline_offset(t, t->size, k);
			t->size++;
		}
}

void bch_bset_insert(struct btree_keys *b,
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

	BUG_ON(b->ops->is_extents &&
	       (!insert->k.size || bkey_deleted(&insert->k)));
	BUG_ON(!b->last_set_unwritten);
	BUG_ON(where < i->start);
	BUG_ON(where > bset_bkey_last(i));
	bch_verify_btree_keys_accounting(b);

	while (where != bset_bkey_last(i) &&
	       keys_out_of_order(f, bkey_to_packed(insert),
				 where, b->ops->is_extents))
		prev = where, where = bkey_next(where);

	if (!prev)
		prev = bkey_prev(b, t, where);

	verify_insert_pos(b, prev, where, insert);

	/* prev is in the tree, if we merge we're done */
	if (prev &&
	    bch_bkey_try_merge_inline(b, iter, prev, bkey_to_packed(insert)))
		return;

	if (b->ops->is_extents &&
	    where != bset_bkey_last(i) &&
	    where->u64s == insert->k.u64s &&
	    bkey_deleted(where)) {
		if (!bkey_deleted(&insert->k))
			btree_keys_account_key_add(b, bkey_to_packed(insert));

		bkey_copy((void *) where, insert);

		/*
		 * We're modifying a key that might be the btree node iter's
		 * current position for that bset, so we have to resort it -
		 * this isn't an issue for back merges because then the insert
		 * key comes after the key being modified, so the iter will have
		 * advanced past it.
		 */
		bch_btree_node_iter_sort(iter, b);
		return;
	}

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
					      where))
			return;
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
		btree_keys_account_key_add(b, src);

	bch_bset_fix_lookup_table(b, t, where);
	bch_btree_node_iter_fix(iter, b, where);

	bch_btree_node_iter_verify(iter, b);
	bch_verify_btree_keys_accounting(b);
}
EXPORT_SYMBOL(bch_bset_insert);

/* Lookup */

__attribute__((flatten))
static struct bkey_packed *bset_search_write_set(const struct bkey_format *f,
				struct bset_tree *t,
				const struct bkey_packed *packed_search,
				struct bpos search)
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
					    struct bpos search)
{
	struct bkey_float *f = &t->tree[1];
	unsigned inorder, n = 1;
	struct bkey_packed packed_search;

	/* don't ask. */
	if (!search.snapshot-- &&
	    !search.offset-- &&
	    !search.inode--)
		BUG();

	/*
	 * If there are bits in search that don't fit in the packed format,
	 * packed_search will always compare less than search - it'll
	 * effectively have 0s where search did not - so we can still use
	 * packed_search and we'll just do more linear searching than we would
	 * have.
	 */
	if (bkey_pack_pos_lossy(&packed_search, search, format) ==
	    BKEY_PACK_POS_FAIL)
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
		 * n = (f->mantissa > bfloat_mantissa())
		 *	? n * 2
		 *	: n * 2 + 1;
		 *
		 * We need to subtract 1 from f->mantissa for the sign bit trick
		 * to work  - that's done in make_bfloat()
		 */
		if (likely(f->exponent != BFLOAT_FAILED))
			n = n * 2 + (((unsigned)
				      (f->mantissa -
				       bfloat_mantissa(&packed_search,
						       f))) >> 31);
		else
			n = bkey_cmp_p_or_unp(format, tree_to_bkey(t, n),
					      &packed_search, search) > 0
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
					   struct bkey_packed *packed_search)
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

	if (unlikely(!t->size)) {
		m = t->data->start;
	} else if (bset_written(b, t)) {
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

		m = bset_search_tree(f, t, search);
	} else {
		m = bset_search_write_set(f, t, packed_search, search);
	}

	while (m != bset_bkey_last(t->data) &&
	       bkey_cmp_p_or_unp(f, m,
				 packed_search, search) < 0)
		m = bkey_next(m);

	if (btree_keys_expensive_checks(b)) {
		struct bkey_packed *p = bkey_prev(b, t, m);

		BUG_ON(p &&
		       bkey_cmp_p_or_unp(f, p, packed_search, search) >= 0);
	}

	return m;
}

/* Btree node iterator */

static inline bool btree_node_iter_cmp(struct btree_node_iter *iter,
				       struct btree_keys *b,
				       struct btree_node_iter_set ls,
				       struct btree_node_iter_set rs)
{
	struct bkey_packed *l = __btree_node_offset_to_key(b, ls.k);
	struct bkey_packed *r = __btree_node_offset_to_key(b, rs.k);
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

void bch_btree_node_iter_push(struct btree_node_iter *iter,
			      struct btree_keys *b,
			      struct bkey_packed *k,
			      struct bkey_packed *end)
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

static void __bch_btree_node_iter_init(struct btree_node_iter *iter,
				       struct btree_keys *b,
				       struct bset_tree *start)
{
	iter->used = 0;
	iter->is_extents = b->ops->is_extents;
}

void bch_btree_node_iter_init(struct btree_node_iter *iter,
			      struct btree_keys *b, struct bpos search)
{
	struct bset_tree *t;
	struct bkey_packed p, *packed_search =
		bkey_pack_pos(&p, search, &b->format) ? &p : NULL;

	__bch_btree_node_iter_init(iter, b, b->set);

	for (t = b->set; t <= b->set + b->nsets; t++)
		bch_btree_node_iter_push(iter, b,
					 bch_bset_search(b, t, search,
							 packed_search),
					 bset_bkey_last(t->data));
}
EXPORT_SYMBOL(bch_btree_node_iter_init);

void bch_btree_node_iter_init_from_start(struct btree_node_iter *iter,
					 struct btree_keys *b)
{
	struct bset_tree *t;

	__bch_btree_node_iter_init(iter, b, b->set);

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
	mempool_destroy(state->pool);
}

int bch_bset_sort_state_init(struct bset_sort_state *state, unsigned page_order)
{
	spin_lock_init(&state->time.lock);

	state->page_order = page_order;
	state->crit_factor = int_sqrt(1 << page_order);

	state->pool = mempool_create_page_pool(1, page_order);
	if (!state->pool)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL(bch_bset_sort_state_init);

static void btree_mergesort_simple(struct btree_keys *b, struct bset *bset,
				   struct btree_node_iter *iter)
{
	struct bkey_packed *k, *out = bset->start;

	while (!bch_btree_node_iter_end(iter)) {
		k = bch_btree_node_iter_next_all(iter, b);

		if (!bkey_deleted(k)) {
			/* XXX: need better bkey_copy */
			memcpy(out, k, bkey_bytes(k));
			out = bkey_next(out);
		}
	}

	bset->u64s = (u64 *) out - bset->_data;

	pr_debug("sorted %i keys", bset->u64s);
}

static void btree_mergesort(struct btree_keys *dst,
			    struct bset *dst_set,
			    struct btree_keys *src,
			    struct btree_node_iter *iter,
			    ptr_filter_fn filter)
{
	struct bkey_format *in_f = &src->format;
	struct bkey_format *out_f = &dst->format;
	struct bkey_packed *k, *prev = NULL, *out = dst_set->start;
	struct bkey_tup tup;
	BKEY_PADDED(k) tmp;

	EBUG_ON(filter && !dst->ops->is_extents);

	dst->nr_packed_keys	= 0;
	dst->nr_unpacked_keys	= 0;

	while (!bch_btree_node_iter_end(iter)) {
		k = bch_btree_node_iter_next_all(iter, src);

		if (bkey_deleted(k))
			continue;

		if (dst->ops->is_extents) {
			/*
			 * For extents, the filter might modify pointers, so we
			 * have to unpack the key and values to &tmp.k.
			 */
			bkey_unpack(&tmp.k, in_f, k);

			if (filter && filter(src, bkey_i_to_s(&tmp.k)))
				continue;

			if (prev &&
			    src->ops->key_merge &&
			    bch_bkey_try_merge(src, (void *) prev, &tmp.k))
				continue;

			bkey_disassemble(&tup, in_f, bkey_to_packed(&tmp.k));
		} else {
			/* We're not touching values -- only copy the key */
			bkey_disassemble(&tup, in_f, k);
		}

		if (prev) {
			if (bkey_pack(prev, (void *) prev, out_f))
				dst->nr_packed_keys++;
			else
				dst->nr_unpacked_keys++;

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
		if (bkey_pack(prev, (void *) prev, out_f))
			dst->nr_packed_keys++;
		else
			dst->nr_unpacked_keys++;
		out = bkey_next(prev);
	} else {
		out = dst_set->start;
	}

	dst_set->u64s = (u64 *) out - dst_set->_data;
	dst->nr_live_u64s = dst_set->u64s;

	pr_debug("sorted %i keys", dst_set->u64s);
}

static void __btree_sort(struct btree_keys *b, struct btree_node_iter *iter,
			 unsigned start, unsigned order,
			 btree_keys_sort_fn sort,
			 struct bset_sort_state *state)
{
	uint64_t start_time;
	bool used_mempool = false;
	struct bset *out = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOWAIT,
						     order);
	if (!out) {
		struct page *outp;

		BUG_ON(order > state->page_order);

		outp = mempool_alloc(state->pool, GFP_NOIO);
		out = page_address(outp);
		used_mempool = true;
		order = state->page_order;
	}

	start_time = local_clock();

	/*
	 * If we're only doing a partial sort (start != 0), then we can't merge
	 * extents because that might produce extents that overlap with 0 size
	 * extents in bsets we aren't sorting:
	 */
	if (sort)
		sort(b, out, iter);
	else if (start)
		btree_mergesort_simple(b, out, iter);
	else
		btree_mergesort(b, out, b, iter, NULL);

	BUG_ON(set_bytes(out) > (PAGE_SIZE << b->page_order));

	b->nsets = start;

	if (0 && !start && order == b->page_order) {
		unsigned u64s = out->u64s;
		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */

		*out = *b->set->data;
		out->u64s = u64s;
		swap(out, b->set->data);
	} else {
		b->set[start].data->u64s = out->u64s;
		memcpy(b->set[start].data->start, out->start,
		       (void *) bset_bkey_last(out) - (void *) out->start);
	}

	if (used_mempool)
		mempool_free(virt_to_page(out), state->pool);
	else
		free_pages((unsigned long) out, order);

	bch_bset_build_written_tree(b);

	bch_verify_btree_keys_accounting(b);

	if (!start)
		bch_time_stats_update(&state->time, start_time);
}

void bch_btree_sort_partial(struct btree_keys *b, unsigned start,
			    struct bset_sort_state *state)
{
	size_t order = b->page_order, u64s = 0;
	struct btree_node_iter iter;
	struct bset_tree *t;

	__bch_btree_node_iter_init(&iter, b, &b->set[start]);

	for (t = b->set + start; t <= b->set + b->nsets; t++)
		bch_btree_node_iter_push(&iter, b,
					 t->data->start,
					 bset_bkey_last(t->data));

	if (start) {
		for (t = b->set + start; t <= b->set + b->nsets; t++)
			u64s += t->data->u64s;

		order = get_order(__set_bytes(b->set->data, u64s));
	}

	__btree_sort(b, &iter, start, order, false, state);
}
EXPORT_SYMBOL(bch_btree_sort_partial);

void bch_btree_sort_and_fix_extents(struct btree_keys *b,
				    struct btree_node_iter *iter,
				    btree_keys_sort_fn sort,
				    struct bset_sort_state *state)
{
	BUG_ON(!sort);
	__btree_sort(b, iter, 0, b->page_order, sort, state);
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
	uint64_t start_time = local_clock();
	struct btree_node_iter iter;

	bch_btree_node_iter_init_from_start(&iter, src);

	btree_mergesort(dst, dst->set->data,
			src, &iter, filter);

	BUG_ON(set_bytes(dst->set->data) > (PAGE_SIZE << dst->page_order));

	bch_time_stats_update(&state->time, start_time);

	dst->nsets = 0;
	/* No auxiliary search tree yet */
	dst->set->size = 0;

	bch_verify_btree_keys_accounting(dst);
}

#define SORT_CRIT	(4096 / sizeof(uint64_t))

void bch_btree_sort_lazy(struct btree_keys *b,
			 struct bset_sort_state *state)
{
	unsigned crit = SORT_CRIT;
	int i;

	/* Don't sort if nothing to do */
	if (!b->nsets)
		goto out;

	for (i = b->nsets - 1; i >= 0; --i) {
		crit *= state->crit_factor;

		if (b->set[i].data->u64s < crit) {
			bch_btree_sort_partial(b, i, state);
			return;
		}
	}

	/* Sort if we'd overflow */
	if (b->nsets + 1 == MAX_BSETS) {
		bch_btree_sort(b, state);
		return;
	}

out:
	bch_bset_build_written_tree(b);
}
EXPORT_SYMBOL(bch_btree_sort_lazy);

void bch_btree_keys_stats(struct btree_keys *b, struct bset_stats *stats)
{
	unsigned i;

	for (i = 0; i <= b->nsets; i++) {
		struct bset_tree *t = &b->set[i];
		size_t bytes = t->data->u64s * sizeof(u64);
		size_t j;

		if (bset_written(b, t)) {
			stats->sets_written++;
			stats->bytes_written += bytes;

			if (t->size)
				stats->floats += t->size - 1;

			for (j = 1; j < t->size; j++)
				if (t->tree[j].exponent == BFLOAT_FAILED)
					stats->failed++;
		} else {
			stats->sets_unwritten++;
			stats->bytes_unwritten += bytes;
		}
	}
}
