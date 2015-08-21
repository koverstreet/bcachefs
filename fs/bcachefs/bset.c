/*
 * Code for working with individual keys, and sorted sets of keys with in a
 * btree node
 *
 * Copyright 2012 Google, Inc.
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include "util.h"
#include "bset.h"

#include <linux/dynamic_fault.h>
#include <linux/console.h>
#include <linux/random.h>
#include <linux/prefetch.h>

#ifdef CONFIG_BCACHEFS_DEBUG

void bch_dump_bset(struct btree_keys *b, struct bset *i, unsigned set)
{
	struct bkey *k, *next;

	for (k = i->start; k < bset_bkey_last(i); k = next) {
		next = bkey_next(k);

		printk(KERN_ERR "block %u key %u/%u: ", set,
		       (unsigned) ((u64 *) k - i->d), i->keys);

		if (b->ops->key_dump)
			b->ops->key_dump(b, k);
		else
			printk("%llu:%llu\n", KEY_INODE(k), KEY_OFFSET(k));

		if (next < bset_bkey_last(i)) {
			if (b->ops->is_extents) {
				if (bkey_cmp(k, &START_KEY(next)) > 0)
					printk(KERN_ERR "Key skipped backwards\n");
			} else {
				if (!bkey_cmp(k, next))
					printk(KERN_ERR "Duplicate keys\n");
			}
		}
	}
}

void bch_dump_bucket(struct btree_keys *b)
{
	unsigned i;

	console_lock();
	for (i = 0; i <= b->nsets; i++)
		bch_dump_bset(b, b->set[i].data,
			      bset_sector_offset(b, b->set[i].data));
	console_unlock();
}

int __bch_count_data(struct btree_keys *b)
{
	unsigned ret = 0;
	struct btree_iter iter;
	struct bkey *k;

	if (b->ops->is_extents)
		for_each_key_all(b, k, &iter)
			ret += KEY_SIZE(k);
	return ret;
}

void __bch_count_data_verify(struct btree_keys *b, int oldsize)
{
	if (oldsize != -1) {
		int newsize = __bch_count_data(b);

		BUG_ON(newsize != -1 && newsize < oldsize);
	}
}

void __bch_check_keys(struct btree_keys *b, const char *fmt, ...)
{
	va_list args;
	struct bkey *k, *p = NULL;
	struct btree_iter iter;
	char buf1[80], buf2[80];
	const char *err;

	for_each_key_all(b, k, &iter) {
		if (b->ops->is_extents) {
			err = "keys out of order";
			if (p && bkey_cmp(&START_KEY(p), &START_KEY(k)) > 0)
				goto bug;

			if (!KEY_SIZE(k))
				continue;

			err =  "overlapping keys";
			if (p && bkey_cmp(p, &START_KEY(k)) > 0)
				goto bug;
		} else {
			if (bkey_deleted(b, k))
				continue;

			err = "duplicate keys";
			if (p && !bkey_cmp(p, k))
				goto bug;
		}
		p = k;
	}
#if 0
	err = "Key larger than btree node key";
	if (p && bkey_cmp(p, &b->key) > 0)
		goto bug;
#endif
	return;
bug:
	bch_dump_bucket(b);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	bch_bkey_to_text(b, buf1, sizeof(buf1), p);
	bch_bkey_to_text(b, buf2, sizeof(buf2), k);
	panic("bch_check_keys error:  %s %s, %s\n", err, buf1, buf2);
}

static void bch_btree_iter_next_check(struct btree_iter *iter)
{
	struct bkey *k = iter->data->k, *next = bkey_next(k);

	if (next < iter->data->end &&
	    bkey_cmp(k, iter->b->ops->is_extents ?
		     &START_KEY(next) : next) > 0) {
		char buf1[80], buf2[80];

		bch_dump_bucket(iter->b);

		bch_bkey_to_text(iter->b, buf1, sizeof(buf1), k);
		bch_bkey_to_text(iter->b, buf2, sizeof(buf2), next);
		panic("Key skipped backwards - %s > %s\n", buf1, buf2);
	}
}

void bch_btree_iter_verify(struct btree_keys *b, struct btree_iter *iter)
{
	struct btree_iter_set *set;
	struct bset_tree *t;

	for (set = iter->data;
	     set < iter->data + iter->used;
	     set++) {
		for (t =  b->set;
		     t <= b->set + b->nsets;
		     t++)
			if (set->end == bset_bkey_last(t->data))
				goto next;
		BUG();
next:
		;
	}
}

#else

static inline void bch_btree_iter_next_check(struct btree_iter *iter) {}

#endif

/* Keylists */

int bch_keylist_realloc(struct keylist *l, unsigned u64s)
{
	size_t oldsize = bch_keylist_size(l);
	size_t offset = bch_keylist_offset(l);
	size_t newsize = oldsize + u64s;
	u64 *old_keys = l->start_keys_p;
	u64 *new_keys;

	if (old_keys == l->inline_keys)
		old_keys = NULL;

	/*
	 * The idea here is that the allocated size is always a power of two:
	 * thus, we know we need to reallocate if current_space_used and
	 * current_space_used + new_space spans a power of two
	 */
	newsize = roundup_pow_of_two(newsize);

	if (newsize <= KEYLIST_INLINE ||
	    roundup_pow_of_two(oldsize) == newsize)
		return 0;

	/* We simulate being out of memory -- the code using the key list
	   has to handle that case. */
	if (newsize > KEYLIST_MAX)
		return -ENOMEM;

	new_keys = krealloc(old_keys, sizeof(u64) * newsize, GFP_NOIO);

	if (!new_keys)
		return -ENOMEM;

	if (!old_keys)
		memcpy(new_keys, l->inline_keys, sizeof(u64) * oldsize);

	l->start_keys_p = new_keys;
	l->top_p = new_keys + oldsize;
	l->bot_p = new_keys + offset;
	l->end_keys_p = new_keys + newsize;

	return 0;
}

void bch_keylist_add_in_order(struct keylist *l, struct bkey *insert)
{
	struct bkey *where = l->bot;

	while (where != l->top &&
	       bkey_cmp(insert, where) >= 0)
		where = bkey_next(where);

	memmove((u64 *) where + KEY_U64s(insert),
		where,
		((void *) l->top) - ((void *) where));

	l->top_p += KEY_U64s(insert);
	BUG_ON(l->top_p > l->end_keys_p);
	bkey_copy(where, insert);
}

/* Auxiliary search trees */

/* 32 bits total: */
#define BKEY_MID_BITS		5
#define BKEY_EXPONENT_BITS	7
#define BKEY_MANTISSA_BITS	(32 - BKEY_MID_BITS - BKEY_EXPONENT_BITS)
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

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

	free_pages((unsigned long) t->data, b->page_order);

	t->prev = NULL;
	t->tree = NULL;
	t->data = NULL;
}
EXPORT_SYMBOL(bch_btree_keys_free);

int bch_btree_keys_alloc(struct btree_keys *b, unsigned page_order, gfp_t gfp)
{
	struct bset_tree *t = b->set;

	BUG_ON(t->data);

	b->page_order = page_order;

	t->data = (void *) __get_free_pages(gfp, b->page_order);
	if (!t->data)
		goto err;

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
	unsigned i;

	b->ops = ops;
	b->expensive_debug_checks = expensive_debug_checks;
	b->nsets = 0;
	b->last_set_unwritten = 0;

	/* XXX: shouldn't be needed */
	for (i = 0; i < MAX_BSETS; i++)
		b->set[i].size = 0;
	/*
	 * Second loop starts at 1 because b->keys[0]->data is the memory we
	 * allocated
	 */
	for (i = 1; i < MAX_BSETS; i++)
		b->set[i].data = NULL;
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

static struct bkey *cacheline_to_bkey(struct bset_tree *t, unsigned cacheline,
				      unsigned offset)
{
	return ((void *) t->data) + cacheline * BSET_CACHELINE + offset * 8;
}

static unsigned bkey_to_cacheline(struct bset_tree *t, struct bkey *k)
{
	return ((void *) k - (void *) t->data) / BSET_CACHELINE;
}

static unsigned bkey_to_cacheline_offset(struct bset_tree *t,
					 unsigned cacheline,
					 struct bkey *k)
{
	size_t m = (u64 *) k - (u64 *) cacheline_to_bkey(t, cacheline, 0);

	BUG_ON(m > (1U << BKEY_MID_BITS) - 1);
	return m;
}

static struct bkey *tree_to_bkey(struct bset_tree *t, unsigned j)
{
	return cacheline_to_bkey(t, to_inorder(j, t), t->tree[j].m);
}

static struct bkey *tree_to_prev_bkey(struct bset_tree *t, unsigned j)
{
	return (void *) (((uint64_t *) tree_to_bkey(t, j)) - t->prev[j]);
}

/*
 * For the write set - the one we're currently inserting keys into - we don't
 * maintain a full search tree, we just keep a simple lookup table in t->prev.
 */
static struct bkey *table_to_bkey(struct bset_tree *t, unsigned cacheline)
{
	return cacheline_to_bkey(t, cacheline, t->prev[cacheline]);
}

static inline unsigned bfloat_mantissa(const struct bkey *k,
				       struct bkey_float *f)
{
	unsigned w = f->exponent >> 5;
	u64 low, high;

#if defined(__LITTLE_ENDIAN)
	low  = k->kw[w];
	high = k->kw[w + 1];
#elif defined(__BIG_ENDIAN)
	low  = k->kw[-w - 1];
	high = k->kw[-w - 2];
#else
#error edit for your odd byteorder.
#endif
	return ((low | (high << 32)) >> (f->exponent & 31)) &
		BKEY_MANTISSA_MASK;
}

static void make_bfloat(struct bset_tree *t, unsigned j)
{
	struct bkey_float *f = &t->tree[j];
	struct bkey *m = tree_to_bkey(t, j);
	struct bkey *p = tree_to_prev_bkey(t, j);

	struct bkey *l = is_power_of_2(j)
		? t->data->start
		: tree_to_prev_bkey(t, j >> ffs(j));

	struct bkey *r = is_power_of_2(j + 1)
		? bset_bkey_idx(t->data, t->data->keys - KEY_U64s(&t->end))
		: tree_to_bkey(t, j >> (ffz(j) + 1));

	BUG_ON(m < l || m > r);
	BUG_ON(bkey_next(p) != m);

	if ((l->k1 ^ r->k1) & KEY_HIGH_MASK)
		f->exponent = fls64((l->k1 ^ r->k1) & KEY_HIGH_MASK) + 64;
	else
		f->exponent = fls64(r->k2 ^ l->k2);

	f->exponent = max_t(int, f->exponent - BKEY_MANTISSA_BITS, 0);

	/*
	 * Setting f->exponent = 127 flags this node as failed, and causes the
	 * lookup code to fall back to comparing against the original key.
	 */

	if (bfloat_mantissa(m, f) != bfloat_mantissa(p, f))
		f->mantissa = bfloat_mantissa(m, f) - 1;
	else
		f->exponent = 127;
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

void bch_bset_init_next(struct btree_keys *b, struct bset *i)
{
	memset(i, 0, sizeof(*i));

	if (i != b->set->data) {
		b->set[++b->nsets].data = i;
		i->seq = b->set->data->seq;
	} else
		get_random_bytes(&i->seq, sizeof(uint64_t));

	bch_bset_build_unwritten_tree(b);
}
EXPORT_SYMBOL(bch_bset_init_next);

void bch_bset_build_written_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);
	struct bkey *prev = NULL, *k = t->data->start;
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

		t->prev[j] = KEY_U64s(prev);
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
		make_bfloat(t, j);
}
EXPORT_SYMBOL(bch_bset_build_written_tree);

/* Insert */

/**
 * Used by extent fixup functions which insert entries into the bset.
 * We have to update the iterator's cached ->end pointer.
 *
 * @top must be in the last bset.
 */
static void bch_btree_iter_fix(struct btree_iter *iter, struct bkey *where,
			       struct bkey *new)
{
	struct btree_iter_set *set;
	u64 n = KEY_U64s(new);

	for (set = iter->data;
	     set < iter->data + iter->used;
	     set++) {
		if (set->k >= where)
			set->k = (struct bkey *) ((u64 *) set->k + n);
		if (set->end >= where)
			set->end = (struct bkey *) ((u64 *) set->end + n);
	}
}

void bch_bset_fix_invalidated_key(struct btree_keys *b, struct bkey *k)
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
		goto fix_left;

	if (bkey_next(k) == bset_bkey_last(t->data)) {
		t->end = *k;
		goto fix_right;
	}

	j = inorder_to_tree(inorder, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_bkey(t, j))
fix_left:	do {
			make_bfloat(t, j);
			j = j * 2;
		} while (j < t->size);

	j = inorder_to_tree(inorder + 1, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_prev_bkey(t, j))
fix_right:	do {
			make_bfloat(t, j);
			j = j * 2 + 1;
		} while (j < t->size);
}
EXPORT_SYMBOL(bch_bset_fix_invalidated_key);

static void bch_bset_fix_lookup_table(struct btree_keys *b,
				      struct bset_tree *t,
				      struct bkey *k)
{
	unsigned shift = KEY_U64s(k);
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

static void __bch_bset_insert(struct btree_keys *b, struct bkey *where,
			      struct bkey *insert)
{
	struct bset_tree *t = bset_tree_last(b);

	BUG_ON(where < t->data->start);
	BUG_ON(where > bset_bkey_last(t->data));
	BUG_ON(KEY_U64s(insert) > bch_btree_keys_u64s_remaining(b));

	memmove((u64 *) where + KEY_U64s(insert),
		where,
		(void *) bset_bkey_last(t->data) - (void *) where);

	t->data->keys += KEY_U64s(insert);
	bkey_copy(where, insert);
	bch_bset_fix_lookup_table(b, t, where);
}

static unsigned bch_bset_insert(struct btree_keys *b, struct btree_iter *iter,
				struct bkey *where, struct bkey *insert)
{
	struct bset *i = bset_tree_last(b)->data;
	struct bkey *prev = NULL;
	BKEY_PADDED(k) tmp;

	BUG_ON(b->ops->is_extents && !KEY_SIZE(insert));
	BUG_ON(!b->last_set_unwritten);

	while (where != bset_bkey_last(i) &&
	       bkey_cmp(insert, b->ops->is_extents
			? &START_KEY(where) : where) > 0)
		prev = where, where = bkey_next(where);

	/* prev is in the tree, if we merge we're done */
	if (prev &&
	    bch_bkey_try_merge(b, prev, insert))
		return BTREE_INSERT_STATUS_BACK_MERGE;

	if (where != bset_bkey_last(i) &&
	    b->ops->is_extents &&
	    bch_val_u64s(where) == bch_val_u64s(insert) && !KEY_SIZE(where)) {
		bkey_copy(where, insert);
		return BTREE_INSERT_STATUS_OVERWROTE;
	}

	if (where != bset_bkey_last(i) &&
	    bkey_bytes(insert) <= sizeof(tmp)) {
		bkey_copy(&tmp.k, insert);
		insert = &tmp.k;

		/*
		 * bch_bkey_try_merge() modifies the left argument, but we can't
		 * modify insert since the caller needs to be able to journal
		 * the key that was actually inserted (and it can't just pass us
		 * a copy of insert, since ->insert_fixup() might trim insert if
		 * this is a replace operation)
		 */
		if (bch_bkey_try_merge(b, insert, where)) {
			bkey_copy(where, insert);
			return BTREE_INSERT_STATUS_FRONT_MERGE;
		}
	}

	__bch_bset_insert(b, where, insert);
	bch_btree_iter_fix(iter, where, insert);
	return BTREE_INSERT_STATUS_INSERT;
}

unsigned bch_bset_insert_with_hint(struct btree_keys *b,
				   struct btree_iter *iter,
				   struct bkey *where,
				   struct bkey *insert)
{
	if (!where || bkey_written(b, where))
		where = bch_bset_search(b, bset_tree_last(b),
					&START_KEY(insert));

	return bch_bset_insert(b, iter, where, insert);
}
EXPORT_SYMBOL(bch_bset_insert_with_hint);

unsigned __bch_btree_insert_key(struct btree_keys *b, struct bkey *insert,
				struct bkey *replace, struct btree_iter *iter,
				struct bkey *where)
{
	int oldsize = bch_count_data(b);
	unsigned status = BTREE_INSERT_STATUS_NO_INSERT;

	BUG_ON(b->ops->is_extents && !KEY_SIZE(insert));

	if (b->ops->insert_fixup(b, insert, iter, replace))
		goto done;

	status = bch_bset_insert(b, iter, where, insert);
done:
	BUG_ON(bch_count_data(b) < oldsize);
	return status;
}

/**
 * bch_btree_insert_key - insert a single key @k into @b
 *
 * This does the real work of looking up where to insert, doing the insert, and
 * merging extents if possible. It also handles replace (cmpxchg) insertions
 * when @replace_key != NULL; the insert might fail (and return
 * BTREE_INSERT_STATUS_NO_INSERT) if @replace_key wasn't present, or if
 * @replace_key was only partially present @k will be modified to represent what
 * was actually inserted.
 */
unsigned bch_btree_insert_key(struct btree_keys *b, struct bkey *insert,
			      struct bkey *replace)
{
	struct bkey *where;
	struct btree_iter iter;

	where = bch_btree_iter_init(b, &iter, b->ops->is_extents
				    ? &START_KEY(insert) : insert);

	return __bch_btree_insert_key(b, insert, replace, &iter, where);
}
EXPORT_SYMBOL(bch_btree_insert_key);

/* Lookup */

#define PRECEDING_KEY(_k)					\
({								\
	struct bkey *_ret = NULL;				\
								\
	if ((_k)->k2) {						\
		_ret = &KEY(KEY_INODE(_k), KEY_OFFSET(_k), 0);	\
		_ret->k2--;					\
	} else if ((_k)->k1 & KEY_HIGH_MASK) {			\
		_ret = &KEY(KEY_INODE(_k), KEY_OFFSET(_k), 0);	\
		_ret->k1--;					\
		_ret->k2--;					\
	}							\
								\
	_ret;							\
})

static struct bkey *bset_search_write_set(struct bset_tree *t,
					  const struct bkey *search)
{
	unsigned li = 0, ri = t->size;

	while (li + 1 != ri) {
		unsigned m = (li + ri) >> 1;

		if (bkey_cmp(table_to_bkey(t, m), search) >= 0)
			ri = m;
		else
			li = m;
	}

	return table_to_bkey(t, li);
}

static struct bkey *bset_search_tree(struct bset_tree *t,
				     const struct bkey *search)
{
	struct bkey_float *f;
	unsigned inorder, j, n = 1;

	do {
		unsigned p = n << 4;
		p &= ((int) (p - t->size)) >> 31;

		/* Prefetch the cacheline we'll be working on four
		 * iterations from now. If out of bounds, just prefetch
		 * root to avoid a branch. */
		prefetch(&t->tree[p]);

		j = n;
		f = &t->tree[j];

		/*
		 * n = (f->mantissa > bfloat_mantissa())
		 *	? j * 2
		 *	: j * 2 + 1;
		 *
		 * We need to subtract 1 from f->mantissa for the sign bit trick
		 * to work  - that's done in make_bfloat()
		 */
		if (likely(f->exponent != 127))
			n = j * 2 + (((unsigned)
				      (f->mantissa -
				       bfloat_mantissa(search, f))) >> 31);
		else
			n = (bkey_cmp(tree_to_bkey(t, j), search) > 0)
				? j * 2
				: j * 2 + 1;
	} while (n < t->size);

	inorder = to_inorder(j, t);

	/*
	 * n would have been the node we recursed to - the low bit tells us if
	 * we recursed left or recursed right.
	 */
	if (n & 1) {
		return cacheline_to_bkey(t, inorder, f->m);
	} else {
		if (--inorder) {
			f = &t->tree[inorder_prev(j, t->size)];
			return cacheline_to_bkey(t, inorder, f->m);
		} else
			return t->data->start;
	}
}

__attribute__((flatten))
struct bkey *__bch_bset_search(struct btree_keys *b, struct bset_tree *t,
			       const struct bkey *search)
{
	struct bkey *m;

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

		if (unlikely(bkey_cmp(search, &t->end) > 0))
			return bset_bkey_last(t->data);

		if (unlikely(bkey_cmp(search, t->data->start) <= 0))
			return t->data->start;

		m = bset_search_tree(t, PRECEDING_KEY(search));
	} else {
		m = bset_search_write_set(t, search);
	}

	while (m != bset_bkey_last(t->data) &&
	       bkey_cmp(m, search) < 0)
		m = bkey_next(m);

	if (btree_keys_expensive_checks(b)) {
		struct bkey *p = t->data->start;

		while (p < m &&
		       bkey_next(p) < m)
			p = bkey_next(p);

		BUG_ON(p < m && bkey_cmp(p, search) >= 0);
	}

	return m;
}
EXPORT_SYMBOL(__bch_bset_search);

/* Btree iterator */

void bch_btree_iter_push(struct btree_iter *iter, struct bkey *k,
			 struct bkey *end)
{
	if (k != end)
		BUG_ON(!heap_add(iter,
				 ((struct btree_iter_set) { k, end }),
				 iter_cmp(iter)));
}

static struct bkey *__bch_btree_iter_init(struct btree_keys *b,
					  struct btree_iter *iter,
					  struct bkey *search,
					  struct bset_tree *start)
{
	struct bkey *ret = NULL;

	iter->size = ARRAY_SIZE(iter->data);
	iter->used = 0;
	iter->is_extents = b->ops->is_extents;

#ifdef CONFIG_BCACHEFS_DEBUG
	iter->b = b;
#endif

	for (; start <= bset_tree_last(b); start++) {
		ret = bch_bset_search(b, start, search);
		bch_btree_iter_push(iter, ret, bset_bkey_last(start->data));
	}

	return ret;
}

struct bkey *bch_btree_iter_init(struct btree_keys *b,
				 struct btree_iter *iter,
				 struct bkey *search)
{
	return __bch_btree_iter_init(b, iter, search, b->set);
}
EXPORT_SYMBOL(bch_btree_iter_init);

struct bkey *bch_btree_iter_next_all(struct btree_iter *iter)
{
	struct btree_iter_set unused;
	struct bkey *ret = NULL;

	if (!bch_btree_iter_end(iter)) {
		bch_btree_iter_next_check(iter);

		ret = iter->data->k;
		iter->data->k = bkey_next(iter->data->k);

		if (iter->data->k > iter->data->end) {
			WARN_ONCE(1, "bset was corrupt!\n");
			iter->data->k = iter->data->end;
		}

		if (iter->data->k == iter->data->end)
			BUG_ON(!heap_pop(iter, unused, iter_cmp(iter)));
		else
			btree_iter_sift(iter, 0);
	}

	return ret;
}
EXPORT_SYMBOL(bch_btree_iter_next_all);

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

static void btree_mergesort(struct btree_keys *b, struct bset *bset,
			    struct btree_iter *iter,
			    ptr_filter_fn filter, bool fixup)
{
	struct bkey *k, *prev = NULL, *out = bset->start;
	BKEY_PADDED(k) tmp;

	while (!bch_btree_iter_end(iter)) {
		if (fixup && b->ops->sort_fixup)
			k = b->ops->sort_fixup(iter, &tmp.k);
		else
			k = NULL;

		if (!k)
			k = bch_btree_iter_next_all(iter);

		bkey_copy(out, k);

		if (filter && filter(b, out))
			continue;

		if (KEY_DELETED(out))
			continue;

		if (prev && bch_bkey_try_merge(b, prev, out))
			continue;

		prev = out;
		out = bkey_next(out);
	}

	bset->keys = (u64 *) out - bset->d;

	pr_debug("sorted %i keys", bset->keys);
}

static void __btree_sort(struct btree_keys *b, struct btree_iter *iter,
			 unsigned start, unsigned order,
			 ptr_filter_fn filter, bool fixup,
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

	btree_mergesort(b, out, iter, filter, fixup);
	b->nsets = start;

	if (!start && order == b->page_order) {
		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */

		out->magic	= b->set->data->magic;
		out->seq	= b->set->data->seq;
		out->version	= b->set->data->version;
		swap(out, b->set->data);
	} else {
		b->set[start].data->keys = out->keys;
		memcpy(b->set[start].data->start, out->start,
		       (void *) bset_bkey_last(out) - (void *) out->start);
	}

	if (used_mempool)
		mempool_free(virt_to_page(out), state->pool);
	else
		free_pages((unsigned long) out, order);

	bch_bset_build_written_tree(b);

	if (!start)
		bch_time_stats_update(&state->time, start_time);
}

void bch_btree_sort_partial(struct btree_keys *b, unsigned start,
			    ptr_filter_fn filter,
			    struct bset_sort_state *state)
{
	size_t order = b->page_order, keys = 0;
	struct btree_iter iter;

	__bch_btree_iter_init(b, &iter, NULL, &b->set[start]);

	if (start) {
		unsigned i;

		for (i = start; i <= b->nsets; i++)
			keys += b->set[i].data->keys;

		order = get_order(__set_bytes(b->set->data, keys));
	}

	__btree_sort(b, &iter, start, order, filter, false, state);
}
EXPORT_SYMBOL(bch_btree_sort_partial);

void bch_btree_sort_and_fix_extents(struct btree_keys *b,
				    struct btree_iter *iter,
				    ptr_filter_fn filter,
				    struct bset_sort_state *state)
{
	__btree_sort(b, iter, 0, b->page_order, filter, true, state);
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

	struct btree_iter iter;
	bch_btree_iter_init(src, &iter, NULL);

	btree_mergesort(src, dst->set->data, &iter, filter, false);

	bch_time_stats_update(&state->time, start_time);

	dst->nsets = 0;
	/* No auxiliary search tree yet */
	dst->set->size = 0;
}

#define SORT_CRIT	(4096 / sizeof(uint64_t))

void bch_btree_sort_lazy(struct btree_keys *b,
			 ptr_filter_fn filter,
			 struct bset_sort_state *state)
{
	unsigned crit = SORT_CRIT;
	int i;

	/* Don't sort if nothing to do */
	if (!b->nsets)
		goto out;

	for (i = b->nsets - 1; i >= 0; --i) {
		crit *= state->crit_factor;

		if (b->set[i].data->keys < crit) {
			bch_btree_sort_partial(b, i, filter, state);
			return;
		}
	}

	/* Sort if we'd overflow */
	if (b->nsets + 1 == MAX_BSETS) {
		bch_btree_sort(b, filter, state);
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
		size_t bytes = t->data->keys * sizeof(uint64_t);
		size_t j;

		if (bset_written(b, t)) {
			stats->sets_written++;
			stats->bytes_written += bytes;

			stats->floats += t->size - 1;

			for (j = 1; j < t->size; j++)
				if (t->tree[j].exponent == 127)
					stats->failed++;
		} else {
			stats->sets_unwritten++;
			stats->bytes_unwritten += bytes;
		}
	}
}
