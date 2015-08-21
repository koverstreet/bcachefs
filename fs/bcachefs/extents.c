/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Uses a block device as cache for other block devices; optimized for SSDs.
 * All allocation is done in buckets, which should match the erase block size
 * of the device.
 *
 * Buckets containing cached data are kept on a heap sorted by priority;
 * bucket priority is increased on cache hit, and periodically all the buckets
 * on the heap have their priority scaled down. This currently is just used as
 * an LRU but in the future should allow for more intelligent heuristics.
 *
 * Buckets have an 8 bit counter; freeing is accomplished by incrementing the
 * counter. Garbage collection is used to remove stale pointers.
 *
 * Indexing is done via a btree; nodes are not necessarily fully sorted, rather
 * as keys are inserted we only sort the pages that have not yet been written.
 * When garbage collection is run, we resort the entire node.
 *
 * All configuration is done via sysfs; see Documentation/bcache.txt.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "writeback.h"

static void sort_key_next(struct btree_iter *iter,
			  struct btree_iter_set *i)
{
	i->k = bkey_next(i->k);

	if (i->k == i->end)
		*i = iter->data[--iter->used];
}

static bool bch_key_sort_cmp(struct btree_iter_set l,
			     struct btree_iter_set r)
{
	int64_t c = bkey_cmp(l.k, r.k);

	return c ? c > 0 : l.k < r.k;
}

static struct bkey *bch_key_sort_fixup(struct btree_iter *iter,
				       struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_iter_set *top = iter->data, *i = top + 1;

		if (iter->used > 2 &&
		    bch_key_sort_cmp(i[0], i[1]))
			i++;

		/*
		 * If this key and the next key don't compare equal, we're done.
		 */

		if (bkey_cmp(top->k, i->k))
			break;

		/*
		 * If they do compare equal, the newer key overwrote the older
		 * key and we need to drop the older key.
		 *
		 * bch_key_sort_cmp() ensures that when keys compare equal the
		 * newer key comes first; so i->k is older than top->k and we
		 * drop i->k.
		 */

		i->k = bkey_next(i->k);

		if (i->k == i->end)
			*i = iter->data[--iter->used];

		heap_sift(iter, i - top, bch_key_sort_cmp);
	}

	return NULL;
}

static bool bch_key_insert_fixup(struct btree_keys *b,
				 struct bkey *insert,
				 struct btree_iter *iter,
				 struct bkey *replace_key)
{
	BUG_ON(replace_key);

	while (1) {
		struct bkey *k = bch_btree_iter_next(iter);

		if (!k || bkey_cmp(k, insert) > 0)
			break;

		if (bkey_cmp(k, insert) < 0)
			continue;

		SET_KEY_DELETED(k, 1);
	}

	return false;
}

const struct btree_keys_ops bch_generic_keys_ops = {
	.sort_cmp	= bch_key_sort_cmp,
	.sort_fixup	= bch_key_sort_fixup,
	.insert_fixup	= bch_key_insert_fixup,
};

/* Common among btree and extent ptrs */

void bch_extent_normalize(struct cache_set *c, struct bkey *k)
{
	unsigned i;
	bool swapped;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (!ptr_available(c, k, i) ||
		    ptr_stale(c, k, i)) {
			bch_set_extent_ptrs(k, bch_extent_ptrs(k) - 1);
			memmove(&k->val[i],
				&k->val[i + 1],
				(bch_extent_ptrs(k) - i) * sizeof(u64));
			continue;
		}

	/* Bubble sort pointers by tier, lowest (fastest) tier first */
	do {
		swapped = false;
		for (i = 0; i + 1 < bch_extent_ptrs(k); i++) {
			if (PTR_TIER(c, k, i) > PTR_TIER(c, k, i + 1)) {
				swap(k->val[i], k->val[i + 1]);
				swapped = true;
			}
		}
	} while (swapped);

	if (!bch_extent_ptrs(k))
		SET_KEY_DELETED(k, true);
}

static void bch_ptr_normalize(struct btree_keys *bk,
			      struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	bch_extent_normalize(b->c, k);
}

static bool __ptr_invalid(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	if (KEY_U64s(k) < BKEY_U64s)
		return true;

	if (!bch_extent_ptrs(k) && !KEY_DELETED(k))
		return true;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i)) {
			struct cache *ca = PTR_CACHE(c, k, i);
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size ||
			    bucket <  ca->sb.first_bucket ||
			    bucket >= ca->sb.nbuckets)
				return true;
		}

	return false;
}

static const char *bch_ptr_status(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i)) {
			struct cache *ca = PTR_CACHE(c, k, i);
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size)
				return "bad, length too big";
			if (bucket <  ca->sb.first_bucket)
				return "bad, short offset";
			if (bucket >= ca->sb.nbuckets)
				return "bad, offset past end of device";
			if (ptr_stale(c, k, i))
				return "stale";
		}

	if (!bkey_cmp(k, &ZERO_KEY))
		return "bad, null key";
	if (!bch_extent_ptrs(k))
		return "bad, no pointers";
	if (!KEY_SIZE(k))
		return "zeroed key";
	return "";
}

void bch_extent_to_text(char *buf, size_t size, const struct bkey *k)
{
	unsigned i = 0;
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("%llu:%llu len %llu -> [", KEY_INODE(k), KEY_START(k), KEY_SIZE(k));

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		if (i)
			p(", ");

		if (PTR_DEV(k, i) == PTR_CHECK_DEV)
			p("check dev");
		else
			p("%llu:%llu gen %llu", PTR_DEV(k, i),
			  PTR_OFFSET(k, i), PTR_GEN(k, i));
	}

	p("]");

	if (KEY_DELETED(k))
		p(" deleted");
	if (KEY_CACHED(k))
		p(" cached");
	if (KEY_CSUM(k))
		p(" cs%llu %llx", KEY_CSUM(k), k->val[1]);
#undef p
}

static void bch_bkey_dump(struct btree_keys *keys, const struct bkey *k)
{
	struct btree *b = container_of(keys, struct btree, keys);
	unsigned j;
	char buf[80];

	bch_extent_to_text(buf, sizeof(buf), k);
	printk(" %s", buf);

	for (j = 0; j < bch_extent_ptrs(k); j++) {
		size_t n = PTR_BUCKET_NR(b->c, k, j);
		printk(" bucket %zu", n);

		if (n >= b->c->sb.first_bucket && n < b->c->sb.nbuckets)
			printk(" prio %i",
			       PTR_BUCKET(b->c, k, j)->read_prio);
	}

	printk(" %s\n", bch_ptr_status(b->c, k));
}

/* Btree ptrs */

bool __bch_btree_ptr_invalid(struct cache_set *c, const struct bkey *k)
{
	char buf[80];

	if (KEY_CACHED(k))
		goto bad;

	if (!KEY_DELETED(k) && !bch_extent_ptrs(k))
		goto bad;

	if (__ptr_invalid(c, k))
		goto bad;

	return false;
bad:
	bch_extent_to_text(buf, sizeof(buf), k);
	cache_bug(c, "spotted btree ptr %s: %s", buf, bch_ptr_status(c, k));
	return true;
}

static bool bch_btree_ptr_invalid(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	return __bch_btree_ptr_invalid(b->c, k);
}

static bool btree_ptr_bad_expensive(struct btree *b, const struct bkey *k)
{
	unsigned i;
	char buf[80];
	struct bucket *g;

	if (mutex_trylock(&b->c->bucket_lock)) {
		for (i = 0; i < bch_extent_ptrs(k); i++)
			if (ptr_available(b->c, k, i)) {
				g = PTR_BUCKET(b->c, k, i);

				if (KEY_CACHED(k) ||
				    (b->c->gc_mark_valid &&
				     GC_MARK(g) != GC_MARK_METADATA))
					goto err;
			}

		mutex_unlock(&b->c->bucket_lock);
	}

	return false;
err:
	mutex_unlock(&b->c->bucket_lock);
	bch_extent_to_text(buf, sizeof(buf), k);
	btree_bug(b,
"inconsistent btree pointer %s: bucket %zi prio %i gen %i last_gc %i mark %llu",
		  buf, PTR_BUCKET_NR(b->c, k, i),
		  g->read_prio, g->gen, g->last_gc, GC_MARK(g));
	return true;
}

static bool bch_btree_ptr_bad(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	if (KEY_DELETED(k) ||
	    __bch_btree_ptr_invalid(b->c, k))
		return true;

	if (expensive_debug_checks(b->c) &&
	    btree_ptr_bad_expensive(b, k))
		return true;

	return false;
}

int bch_btree_pick_ptr(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	if (!KEY_SIZE(k))
		return -1;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i))
			return i;

	return -1;
}

const struct btree_keys_ops bch_btree_keys_ops = {
	.sort_cmp	= bch_key_sort_cmp,
	.sort_fixup	= bch_key_sort_fixup,
	.insert_fixup	= bch_key_insert_fixup,
	.key_invalid	= bch_btree_ptr_invalid,
	.key_bad	= bch_btree_ptr_bad,
	.key_to_text	= bch_extent_to_text,
	.key_dump	= bch_bkey_dump,
};

/* Extents */

void bch_bkey_copy_single_ptr(struct bkey *dest, const struct bkey *src,
			      unsigned i)
{
	BUG_ON(i > bch_extent_ptrs(src));

	/* Only copy the header, key, and one pointer. */
	*dest = *src;
	dest->val[0] = src->val[i];

	bch_set_extent_ptrs(dest, 1);
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dest, 0);
}

bool __bch_cut_front(const struct bkey *where, struct bkey *k)
{
	unsigned i, len = 0;

	if (bkey_cmp(where, &START_KEY(k)) <= 0)
		return false;

	if (bkey_cmp(where, k) < 0)
		len = KEY_OFFSET(k) - KEY_OFFSET(where);
	else
		bkey_copy_key(k, where);

	for (i = 0; i < bch_extent_ptrs(k); i++)
		SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + KEY_SIZE(k) - len);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

bool __bch_cut_back(const struct bkey *where, struct bkey *k)
{
	unsigned len = 0;

	if (bkey_cmp(where, k) >= 0)
		return false;

	BUG_ON(KEY_INODE(where) != KEY_INODE(k));

	if (bkey_cmp(where, &START_KEY(k)) > 0)
		len = KEY_OFFSET(where) - KEY_START(k);

	bkey_copy_key(k, where);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

/*
 * Returns true if l > r - unless l == r, in which case returns true if l is
 * older than r.
 *
 * Necessary for btree_sort_fixup() - if there are multiple keys that compare
 * equal in different sets, we have to process them newest to oldest.
 */
static bool bch_extent_sort_cmp(struct btree_iter_set l,
				struct btree_iter_set r)
{
	int64_t c = bkey_cmp(&START_KEY(l.k), &START_KEY(r.k));

	return c ? c > 0 : l.k < r.k;
}

static struct bkey *bch_extent_sort_fixup(struct btree_iter *iter,
					  struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_iter_set *top = iter->data, *i = top + 1;

		if (iter->used > 2 &&
		    bch_extent_sort_cmp(i[0], i[1]))
			i++;

		if (bkey_cmp(top->k, &START_KEY(i->k)) <= 0)
			break;

		if (!KEY_SIZE(i->k)) {
			sort_key_next(iter, i);
			heap_sift(iter, i - top, bch_extent_sort_cmp);
			continue;
		}

		if (top->k > i->k) {
			if (bkey_cmp(top->k, i->k) >= 0)
				sort_key_next(iter, i);
			else
				bch_cut_front(top->k, i->k);

			heap_sift(iter, i - top, bch_extent_sort_cmp);
		} else {
			/* can't happen because of comparison func */
			BUG_ON(!bkey_cmp(&START_KEY(top->k), &START_KEY(i->k)));

			if (bkey_cmp(i->k, top->k) < 0) {
				bkey_copy(tmp, top->k);

				bch_cut_back(&START_KEY(i->k), tmp);
				bch_cut_front(i->k, top->k);
				heap_sift(iter, 0, bch_extent_sort_cmp);

				return tmp;
			} else {
				bch_cut_back(&START_KEY(i->k), top->k);
			}
		}
	}

	return NULL;
}

static void bch_subtract_dirty(struct bkey *k,
			   struct cache_set *c,
			   uint64_t offset,
			   int sectors)
{
	if (!KEY_CACHED(k) && bch_extent_ptrs(k))
		bcache_dev_sectors_dirty_add(c, KEY_INODE(k),
					     offset, -sectors);
}

static bool bch_extent_insert_fixup(struct btree_keys *b,
				    struct bkey *insert,
				    struct btree_iter *iter,
				    struct bkey *replace_key)
{
	struct cache_set *c = container_of(b, struct btree, keys)->c;

	uint64_t old_offset;
	unsigned old_size, sectors_found = 0;

	BUG_ON(!KEY_OFFSET(insert));
	BUG_ON(!KEY_SIZE(insert));

	while (1) {
		struct bkey *k = bch_btree_iter_next(iter);
		if (!k)
			break;

		if (bkey_cmp(&START_KEY(k), insert) >= 0) {
			if (KEY_SIZE(k))
				break;
			else
				continue;
		}

		if (bkey_cmp(k, &START_KEY(insert)) <= 0)
			continue;

		old_offset = KEY_START(k);
		old_size = KEY_SIZE(k);

		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for replace
		 * operations.
		 */

		if (replace_key && KEY_SIZE(k)) {
			/*
			 * k might have been split since we inserted/found the
			 * key we're replacing
			 */
			unsigned i;
			uint64_t offset = KEY_START(k) -
				KEY_START(replace_key);

			/* But it must be a subset of the replace key */
			if (KEY_START(k) < KEY_START(replace_key) ||
			    KEY_OFFSET(k) > KEY_OFFSET(replace_key))
				goto check_failed;

			/* We didn't find a key that we were supposed to */
			if (KEY_START(k) > KEY_START(insert) + sectors_found)
				goto check_failed;

			if (!bch_bkey_equal_header(k, replace_key))
				goto check_failed;

			/* skip past gen */
			offset <<= 8;

			BUG_ON(!bch_extent_ptrs(replace_key));

			for (i = 0; i < bch_extent_ptrs(replace_key); i++)
				if (k->val[i] != replace_key->val[i] + offset)
					goto check_failed;

			sectors_found = KEY_OFFSET(k) - KEY_START(insert);
		}

		if (bkey_cmp(insert, k) < 0 &&
		    bkey_cmp(&START_KEY(insert), &START_KEY(k)) > 0) {
			/*
			 * We overlapped in the middle of an existing key: that
			 * means we have to split the old key. But we have to do
			 * slightly different things depending on whether the
			 * old key has been written out yet.
			 */

			struct bkey *top;

			bch_subtract_dirty(k, c, KEY_START(insert),
				       KEY_SIZE(insert));

			if (bkey_written(b, k)) {
				/*
				 * We insert a new key to cover the top of the
				 * old key, and the old key is modified in place
				 * to represent the bottom split.
				 *
				 * It's completely arbitrary whether the new key
				 * is the top or the bottom, but it has to match
				 * up with what btree_sort_fixup() does - it
				 * doesn't check for this kind of overlap, it
				 * depends on us inserting a new key for the top
				 * here.
				 */
				top = bch_bset_search(b, bset_tree_last(b),
						      insert);
				bch_bset_insert(b, top, k);
			} else {
				BKEY_PADDED(key) temp;
				bkey_copy(&temp.key, k);
				bch_bset_insert(b, k, &temp.key);
				top = bkey_next(k);
			}

			bch_cut_front(insert, top);
			bch_cut_back(&START_KEY(insert), k);
			bch_bset_fix_invalidated_key(b, k);
			goto out;
		}

		if (bkey_cmp(insert, k) < 0) {
			bch_cut_front(insert, k);
		} else {
			if (bkey_cmp(&START_KEY(insert), &START_KEY(k)) > 0)
				old_offset = KEY_START(insert);

			if (bkey_written(b, k) &&
			    bkey_cmp(&START_KEY(insert), &START_KEY(k)) <= 0) {
				/*
				 * Completely overwrote, so we don't have to
				 * invalidate the binary search tree
				 */
				bch_cut_front(k, k);
			} else {
				__bch_cut_back(&START_KEY(insert), k);
				bch_bset_fix_invalidated_key(b, k);
			}
		}

		bch_subtract_dirty(k, c, old_offset, old_size - KEY_SIZE(k));
	}

check_failed:
	if (replace_key) {
		if (!sectors_found) {
			return true;
		} else if (sectors_found < KEY_SIZE(insert)) {
			SET_KEY_OFFSET(insert, KEY_OFFSET(insert) -
				       (KEY_SIZE(insert) - sectors_found));
			SET_KEY_SIZE(insert, sectors_found);
		}
	}
out:
	if (!KEY_CACHED(insert) && bch_extent_ptrs(insert))
		bcache_dev_sectors_dirty_add(c, KEY_INODE(insert),
					     KEY_START(insert),
					     KEY_SIZE(insert));

	return false;
}

bool __bch_extent_invalid(struct cache_set *c, const struct bkey *k)
{
	char buf[80];

	if (KEY_U64s(k) < BKEY_U64s)
		goto bad;

	if (!KEY_SIZE(k))
		return true;

	if (KEY_SIZE(k) > KEY_OFFSET(k))
		goto bad;

	if (__ptr_invalid(c, k))
		goto bad;

	return false;
bad:
	bch_extent_to_text(buf, sizeof(buf), k);
	cache_bug(c, "spotted extent %s: %s", buf, bch_ptr_status(c, k));
	return true;
}

static bool bch_extent_invalid(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	return __bch_extent_invalid(b->c, k);
}

static bool bch_extent_bad_expensive(struct btree *b, const struct bkey *k)
{
	unsigned stale, replicas_needed, locked = false;
	struct bucket *g;
	char buf[80];
	int i;

	replicas_needed = KEY_CACHED(k) ? 0 : b->c->data_replicas;

	if (mutex_trylock(&b->c->bucket_lock)) {
		if (b->c->gc_mark_valid)
			locked = true;
		else
			mutex_unlock(&b->c->bucket_lock);
	}

	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i) {
		if (!ptr_available(b->c, k, i))
			continue;

		g = PTR_BUCKET(b->c, k, i);
		stale = ptr_stale(b->c, k, i);

		btree_bug_on(stale > 96, b,
			     "key too stale: %i, need_gc %u",
			     stale, b->c->need_gc);

		btree_bug_on(stale && replicas_needed && KEY_SIZE(k),
			     b, "stale dirty pointer");

		if (stale)
			continue;

		if (locked &&
		    (!GC_MARK(g) ||
		     GC_MARK(g) == GC_MARK_METADATA ||
		     (GC_MARK(g) != GC_MARK_DIRTY &&
		      replicas_needed)))
			goto err;

		if (replicas_needed)
			replicas_needed--;
	}

	if (locked)
		mutex_unlock(&b->c->bucket_lock);

	return false;
err:
	mutex_unlock(&b->c->bucket_lock);
	bch_extent_to_text(buf, sizeof(buf), k);
	btree_bug(b,
"inconsistent extent pointer %s:\nbucket %zu prio %i gen %i last_gc %i mark %llu",
		  buf, PTR_BUCKET_NR(b->c, k, i),
		  g->read_prio, g->gen, g->last_gc, GC_MARK(g));
	return true;
}

static bool bch_extent_bad(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	if (KEY_DELETED(k) ||
	    bch_extent_invalid(bk, k))
		return true;

	if (expensive_debug_checks(b->c))
		bch_extent_bad_expensive(b, k);

	return false;
}

int bch_extent_pick_ptr(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	if (!KEY_SIZE(k))
		return -1;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i) && !ptr_stale(c, k, i))
			return i;

	return -1;
}

static uint64_t merge_chksums(struct bkey *l, struct bkey *r)
{
	return (l->val[bch_extent_ptrs(l)] + r->val[bch_extent_ptrs(r)]) &
		~((uint64_t)1 << 63);
}

static bool bch_extent_merge(struct btree_keys *bk, struct bkey *l, struct bkey *r)
{
	struct btree *b = container_of(bk, struct btree, keys);
	unsigned i;

	if (key_merging_disabled(b->c))
		return false;

	for (i = 0; i < bch_extent_ptrs(l); i++)
		if (l->val[i] + PTR(0, KEY_SIZE(l), 0) != r->val[i] ||
		    PTR_BUCKET_NR(b->c, l, i) != PTR_BUCKET_NR(b->c, r, i))
			return false;

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if (KEY_SIZE(l) + KEY_SIZE(r) > USHRT_MAX) {
		SET_KEY_OFFSET(l, KEY_OFFSET(l) + USHRT_MAX - KEY_SIZE(l));
		SET_KEY_SIZE(l, USHRT_MAX);

		bch_cut_front(l, r);
		return false;
	}

	if (KEY_CSUM(l)) {
		if (KEY_CSUM(r))
			l->val[bch_extent_ptrs(l)] = merge_chksums(l, r);
		else
			SET_KEY_CSUM(l, 0);
	}

	SET_KEY_OFFSET(l, KEY_OFFSET(l) + KEY_SIZE(r));
	SET_KEY_SIZE(l, KEY_SIZE(l) + KEY_SIZE(r));

	return true;
}

const struct btree_keys_ops bch_extent_keys_ops = {
	.sort_cmp	= bch_extent_sort_cmp,
	.sort_fixup	= bch_extent_sort_fixup,
	.insert_fixup	= bch_extent_insert_fixup,
	.key_invalid	= bch_extent_invalid,
	.key_bad	= bch_extent_bad,
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.key_to_text	= bch_extent_to_text,
	.key_dump	= bch_bkey_dump,
	.is_extents	= true,
};
