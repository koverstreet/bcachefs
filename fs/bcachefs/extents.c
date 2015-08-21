/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Code for managing the extent btree and dynamically updating the writeback
 * dirty sector count.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "inode.h"
#include "writeback.h"

static void sort_key_next(struct btree_iter *iter,
			  struct btree_iter_set *i)
{
	i->k = bkey_next(i->k);

	if (i->k == i->end)
		*i = iter->data[--iter->used];
}

bool bch_generic_sort_cmp(struct btree_iter_set l,
			  struct btree_iter_set r)
{
	int64_t c = bkey_cmp(l.k, r.k);

	return c ? c > 0 : l.k < r.k;
}

struct bkey *bch_generic_sort_fixup(struct btree_iter *iter,
				    struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_iter_set *top = iter->data, *i = top + 1;

		if (iter->used > 2 &&
		    bch_generic_sort_cmp(i[0], i[1]))
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
		 * bch_generic_sort_cmp() ensures that when keys compare equal
		 * the newer key comes first; so i->k is older than top->k and
		 * we drop i->k.
		 */

		i->k = bkey_next(i->k);

		if (i->k == i->end)
			*i = iter->data[--iter->used];

		heap_sift(iter, i - top, bch_generic_sort_cmp);
	}

	return NULL;
}

bool bch_generic_insert_fixup(struct btree_keys *b, struct bkey *insert,
			      struct btree_iter *iter, struct bkey *replace_key)
{
	BUG_ON(replace_key);

	while (1) {
		struct bkey *k = bch_btree_iter_next_all(iter);

		if (!k || bkey_cmp(k, insert) > 0)
			break;

		if (bkey_cmp(k, insert) < 0)
			continue;

		SET_KEY_DELETED(k, 1);
	}

	return false;
}

/* Common among btree and extent ptrs */

static bool should_drop_ptr(struct cache_set *c, const struct bkey *k,
			    unsigned ptr)
{
	struct cache *ca;

	if (PTR_DEV(k, ptr) > c->sb.nr_in_set)
		return true;

	return (ca = PTR_CACHE(c, k, ptr)) &&
		ptr_stale(c, ca, k, ptr);
}

static unsigned PTR_TIER(struct cache_set *c, const struct bkey *k,
			 unsigned ptr)
{
	struct cache *ca = PTR_CACHE(c, k, ptr);

	return ca ? CACHE_TIER(&ca->sb) : UINT_MAX;
}

unsigned bch_extent_nr_ptrs_after_normalize(struct cache_set *c,
					    const struct bkey *k)
{
	unsigned ret = 0, ptr;

	rcu_read_lock();
	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++)
		if (!should_drop_ptr(c, k, ptr))
			ret++;
	rcu_read_unlock();

	if (ret)
		ret += BKEY_U64s;

	return ret;
}

bool bch_extent_normalize(struct cache_set *c, struct bkey *k)
{
	unsigned i = 0;
	bool swapped;

	if (!KEY_SIZE(k)) {
		bch_set_extent_ptrs(k, 0);
		SET_KEY_DELETED(k, true);
		return true;
	}

	rcu_read_lock();

	while (i < bch_extent_ptrs(k))
		if (should_drop_ptr(c, k, i)) {
			bch_set_extent_ptrs(k, bch_extent_ptrs(k) - 1);
			memmove(&k->val[i],
				&k->val[i + 1],
				(bch_extent_ptrs(k) - i) * sizeof(u64));
		} else
			i++;

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

	rcu_read_unlock();

	if (!bch_extent_ptrs(k))
		SET_KEY_DELETED(k, true);

	return KEY_DELETED(k);
}

static bool bch_ptr_normalize(struct btree_keys *bk,
			      struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return bch_extent_normalize(b->c, k);
}

static bool __ptr_invalid(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	if (KEY_U64s(k) < BKEY_U64s)
		return true;

	if (!bch_extent_ptrs(k) && !KEY_DELETED(k))
		return true;

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		struct cache *ca = PTR_CACHE(c, k, i);

		if (ca) {
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size ||
			    bucket <  ca->sb.first_bucket ||
			    bucket >= ca->sb.nbuckets)
				return true;
		}
	}

	rcu_read_unlock();

	return false;
}

static const char *__bch_ptr_status(struct cache_set *c, const struct bkey *k)
{
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		struct cache *ca = PTR_CACHE(c, k, i);

		if (ca) {
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size)
				return "bad, length too big";
			if (bucket <  ca->sb.first_bucket)
				return "bad, short offset";
			if (bucket >= ca->sb.nbuckets)
				return "bad, offset past end of device";
			if (ptr_stale(c, ca, k, i))
				return "stale";
		}
	}

	if (!bkey_cmp(k, &ZERO_KEY))
		return "bad, null key";
	if (!bch_extent_ptrs(k))
		return "bad, no pointers";
	if (!KEY_SIZE(k))
		return "zeroed key";
	return "";
}

static const char *bch_ptr_status(struct cache_set *c, const struct bkey *k)
{
	const char *ret;

	rcu_read_lock();
	ret = __bch_ptr_status(c, k);
	rcu_read_unlock();

	return ret;
}

void bch_extent_to_text(char *buf, size_t size, const struct bkey *k)
{
	unsigned i = 0;
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("%llu:%llu-%llu len %llu ver %llu -> [",
	  KEY_INODE(k), KEY_START(k), KEY_OFFSET(k),
	  KEY_SIZE(k), KEY_VERSION(k));

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
	}

	printk(" %s\n", bch_ptr_status(b->c, k));
}

/* Btree ptrs */

bool __bch_btree_ptr_invalid(struct cache_set *c, const struct bkey *k)
{
	return (KEY_CACHED(k) ||
		(!KEY_DELETED(k) && !bch_extent_ptrs(k)) ||
		__ptr_invalid(c, k));
}

static bool bch_btree_ptr_invalid(struct btree_keys *bk, struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	return __bch_btree_ptr_invalid(b->c, k);
}

static bool btree_ptr_debug_invalid(struct btree_keys *bk, struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	unsigned i, seq;
	char buf[80];
	struct bucket *g;
	struct cache *ca;
	struct cache_set *c = b->c;
	bool bad;

	if (bch_btree_ptr_invalid(bk, k)) {
		bch_extent_to_text(buf, sizeof(buf), k);
		btree_bug(b, "invalid bkey %s", buf);
		return true;
	}

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i))) {
			g = PTR_BUCKET(c, ca, k, i);

			if (KEY_CACHED(k))
				goto err;

			do {
				seq = read_seqbegin(&c->gc_cur_lock);
				bad = (!__gc_will_visit_key(c, k) &&
				       !g->mark.is_metadata);
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto err;
		}

	rcu_read_unlock();

	return false;
err:
	bch_extent_to_text(buf, sizeof(buf), k);
	btree_bug(b, "inconsistent btree pointer %s: bucket %zi prio %i "
		  "gen %i last_gc %i mark %08x",
		  buf, PTR_BUCKET_NR(b->c, k, i),
		  g->read_prio, PTR_BUCKET_GEN(b->c, ca, k, i),
		  g->last_gc, g->mark.counter);
	rcu_read_unlock();
	return true;
}

struct cache *bch_btree_pick_ptr(struct cache_set *c, const struct bkey *k,
				 unsigned *ptr)
{
	rcu_read_lock();

	for (*ptr = 0; *ptr < bch_extent_ptrs(k); (*ptr)++) {
		struct cache *ca = PTR_CACHE(c, k, *ptr);

		if (ca) {
			percpu_ref_get(&ca->ref);
			rcu_read_unlock();
			return ca;
		}
	}

	rcu_read_unlock();

	return NULL;
}

const struct btree_keys_ops bch_btree_interior_node_ops = {
	.sort_cmp	= bch_generic_sort_cmp,
	.sort_fixup	= bch_generic_sort_fixup,
	.insert_fixup	= bch_generic_insert_fixup,

	.key_invalid	= bch_btree_ptr_invalid,
	.key_debug_invalid = btree_ptr_debug_invalid,
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

bool bch_cut_front(const struct bkey *where, struct bkey *k)
{
	unsigned i, len = 0;

	BUG_ON(bkey_cmp(where, k) > 0);

	if (bkey_cmp(where, &START_KEY(k)) <= 0)
		return false;

	if (bkey_cmp(where, k) < 0)
		len = KEY_OFFSET(k) - KEY_OFFSET(where);
	else
		bkey_copy_key(k, where);

	/*
	 * Don't readjust offset if the key size is now 0, because that could
	 * cause offset to point to the next bucket:
	 */
	if (len)
		for (i = 0; i < bch_extent_ptrs(k); i++)
			SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) +
				       KEY_SIZE(k) - len);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);

	if (!len)
		SET_KEY_DELETED(k, true);

	return true;
}

bool bch_cut_back(const struct bkey *where, struct bkey *k)
{
	unsigned len = 0;

	BUG_ON(bkey_cmp(where, &START_KEY(k)) < 0);

	if (bkey_cmp(where, k) >= 0)
		return false;

	BUG_ON(KEY_INODE(where) != KEY_INODE(k));

	if (bkey_cmp(where, &START_KEY(k)) > 0)
		len = KEY_OFFSET(where) - KEY_START(k);

	bkey_copy_key(k, where);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);

	if (!len)
		SET_KEY_DELETED(k, true);

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

enum bch_extent_overlap {
	BCH_EXTENT_OVERLAP_FRONT,
	BCH_EXTENT_OVERLAP_BACK,
	BCH_EXTENT_OVERLAP_ALL,
	BCH_EXTENT_OVERLAP_MIDDLE,
};

/* Returns how k overlaps with m */
static enum bch_extent_overlap bch_extent_overlap(const struct bkey *k,
						  const struct bkey *m)
{
	if (bkey_cmp(k, m) < 0) {
		if (bkey_cmp(&START_KEY(k), &START_KEY(m)) > 0)
			return BCH_EXTENT_OVERLAP_MIDDLE;
		else
			return BCH_EXTENT_OVERLAP_FRONT;
	} else {
		if (bkey_cmp(&START_KEY(k), &START_KEY(m)) <= 0)
			return BCH_EXTENT_OVERLAP_ALL;
		else
			return BCH_EXTENT_OVERLAP_BACK;
	}
}

static void bch_add_sectors(struct bkey *k,
			    struct cache_set *c,
			    u64 offset,
			    int sectors)
{
	unsigned replicas_found = 0, replicas_needed = c->data_replicas;
	struct cache *ca;
	int i;

	if (!bch_extent_ptrs(k))
		return;

	if (!sectors)
		return;

	BUG_ON(KEY_DELETED(k));

	if (!KEY_CACHED(k))
		bcache_dev_sectors_dirty_add(c, KEY_INODE(k),
					     offset, sectors);

	if (KEY_CACHED(k))
		replicas_needed = 0;

	rcu_read_lock();
	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i)
		if ((ca = PTR_CACHE(c, k, i))) {
			bch_mark_data_bucket(c, ca, k, i, sectors,
					     replicas_found < replicas_needed,
					     false);
			replicas_found++;
		}
	rcu_read_unlock();
}

static void bch_subtract_sectors(struct bkey *k,
				 struct cache_set *c,
				 u64 offset,
				 int sectors)
{
	bch_add_sectors(k, c, offset, -sectors);
}

static struct bkey *bch_btree_iter_next_overlapping(struct btree_iter *iter,
						    struct bkey *end)
{
	struct bkey *k;

	while ((k = bch_btree_iter_next_all(iter))) {
		if (bkey_cmp(&START_KEY(k), end) >= 0) {
			if (!KEY_SIZE(k))
				continue;
			return NULL;
		}

		if (bkey_cmp(k, &START_KEY(end)) > 0)
			break;
	}

	return k;
}

static bool bkey_cmpxchg_cmp(struct bkey *k, struct bkey *old)
{
	/* skip past gen */
	s64 offset = (KEY_START(k) - KEY_START(old)) << 8;
	unsigned i;

	if (!bch_bkey_equal_header(k, old))
		return false;

	for (i = 0; i < bch_extent_ptrs(old); i++)
		if (k->val[i] != old->val[i] + offset)
			return false;

	return true;
}

static bool bkey_cmpxchg(struct cache_set *c,
			 struct bkey *k,
			 struct bkey *old,
			 struct bkey *new,
			 unsigned *sectors_found)
{
	/* must have something to compare against */
	BUG_ON(!bch_extent_ptrs(old));

	/* new must be a subset of old */
	BUG_ON(bkey_cmp(new, old) > 0 ||
	       bkey_cmp(&START_KEY(new), &START_KEY(old)) < 0);

	/*
	 * first, check if there was a hole - part of the new key that we
	 * haven't checked against any existing key
	 */
	if (KEY_START(new) + *sectors_found < KEY_START(k)) {
		if (*sectors_found)
			return false;

		bch_subtract_sectors(new, c, KEY_START(new),
				     KEY_START(k) - KEY_START(new));
		bch_cut_front(&START_KEY(k), new);
	}

	if (!bkey_cmpxchg_cmp(k, old)) {
		if (*sectors_found || bkey_cmp(k, new) >= 0)
			return false;

		bch_subtract_sectors(new, c, KEY_START(new),
				     KEY_OFFSET(k) - KEY_START(new));
		bch_cut_front(k, new);
	} else {
		*sectors_found = KEY_OFFSET(k) - KEY_START(new);
	}

	return true;
}

static bool bch_extent_insert_fixup(struct btree_keys *b,
				    struct bkey *insert,
				    struct btree_iter *iter,
				    struct bkey *replace_key)
{
	struct cache_set *c = container_of(b, struct btree, keys)->c;
	unsigned sectors_found = 0;  /* for cmpxchg */
	struct bkey *k, *top;

	BUG_ON(!KEY_SIZE(insert));

	bch_add_sectors(insert, c, KEY_START(insert), KEY_SIZE(insert));

	while ((k = bch_btree_iter_next_overlapping(iter, insert))) {
		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for replace
		 * operations.
		 */

		if (replace_key && KEY_SIZE(k)) {
			/* This might make @insert shorter */
			if (!bkey_cmpxchg(c, k, replace_key, insert,
					  &sectors_found))
				goto check_failed;

			if (bkey_cmp(k, &START_KEY(insert)) <= 0)
				continue;
		}

		switch (bch_extent_overlap(insert, k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			bch_subtract_sectors(k, c, KEY_START(k),
					     KEY_OFFSET(insert) - KEY_START(k));
			bch_cut_front(insert, k);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			bch_subtract_sectors(k, c, KEY_START(insert),
					     KEY_OFFSET(k) - KEY_START(insert));
			bch_cut_back(&START_KEY(insert), k);
			bch_bset_fix_invalidated_key(b, k);
			break;

		case BCH_EXTENT_OVERLAP_ALL:
			if (KEY_SIZE(k))
				bch_subtract_sectors(k, c, KEY_OFFSET(k),
						     KEY_SIZE(k));

			/*
			 * Completely overwrote, so we don't have to invalidate
			 * the binary search tree
			 */
			SET_KEY_SIZE(k, 0);
			SET_KEY_DELETED(k, true);
			if (!bkey_written(b, k))
				SET_KEY_OFFSET(k, KEY_START(insert));

			break;

		case BCH_EXTENT_OVERLAP_MIDDLE:
			bch_subtract_sectors(k, c, KEY_START(insert),
					     KEY_SIZE(insert));

			/*
			 * We overlapped in the middle of an existing key: that
			 * means we have to split the old key. But we have to do
			 * slightly different things depending on whether the
			 * old key has been written out yet.
			 */
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
			return false;
		}
	}

check_failed:
	if (replace_key && sectors_found < KEY_SIZE(insert)) {
		bch_subtract_sectors(insert, c,
				     KEY_START(insert) + sectors_found,
				     KEY_SIZE(insert) - sectors_found);

		SET_KEY_OFFSET(insert, KEY_OFFSET(insert) -
			       (KEY_SIZE(insert) - sectors_found));
		SET_KEY_SIZE(insert, sectors_found);

		if (!sectors_found)
			return true;
	}

	return false;
}

bool __bch_extent_invalid(struct cache_set *c, const struct bkey *k)
{
	return (KEY_U64s(k) < BKEY_U64s ||
		KEY_SIZE(k) > KEY_OFFSET(k) ||
		(!KEY_SIZE(k) && !KEY_DELETED(k)) ||
		__ptr_invalid(c, k));
}

static bool bch_extent_invalid(struct btree_keys *bk, struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	return __bch_extent_invalid(b->c, k);
}

static bool bch_extent_debug_invalid(struct btree_keys *bk, struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct cache_set *c = b->c;
	struct cache *ca;
	struct bucket *g;
	unsigned seq, stale, replicas_needed;
	char buf[80];
	bool bad;
	int i;

	if (bch_extent_invalid(bk, k)) {
		bch_extent_to_text(buf, sizeof(buf), k);
		btree_bug(b, "invalid bkey %s", buf);
		return true;
	}

	replicas_needed = KEY_CACHED(k) ? 0 : c->data_replicas;

	rcu_read_lock();

	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i) {
		if ((ca = PTR_CACHE(c, k, i))) {
			g = PTR_BUCKET(c, ca, k, i);

			do {
				struct bucket_mark mark;

				seq = read_seqbegin(&c->gc_cur_lock);
				mark = READ_ONCE(g->mark);

				/* between mark and bucket gen */
				smp_rmb();

				stale = ptr_stale(c, ca, k, i);

				btree_bug_on(stale > 96, b,
					     "key too stale: %i",
					     stale);

				btree_bug_on(
					stale && replicas_needed &&
					KEY_SIZE(k), b,
					"stale dirty pointer:\n"
					"bucket %zu gen %i != %llu",
					PTR_BUCKET_NR(c, k, i),
					PTR_BUCKET_GEN(c, ca, k, i),
					PTR_GEN(k, i));

				bad = (!stale &&
				       !__gc_will_visit_key(c, k) &&
				       (mark.is_metadata ||
					(!mark.dirty_sectors &&
					 !mark.owned_by_allocator &&
					 replicas_needed)));
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto err;
		}

		if (replicas_needed)
			replicas_needed--;
	}

	rcu_read_unlock();

	return false;
err:
	bch_extent_to_text(buf, sizeof(buf), k);
	btree_bug(b, "extent pointer %i bad: %s:\nbucket %zu prio %i "
		  "gen %i last_gc %i mark 0x%08x", i,
		  buf, PTR_BUCKET_NR(c, k, i),
		  g->read_prio, PTR_BUCKET_GEN(c, ca, k, i),
		  g->last_gc, g->mark.counter);
	rcu_read_unlock();
	return true;
}

struct cache *bch_extent_pick_ptr(struct cache_set *c, const struct bkey *k,
				  unsigned *ptr)
{
	if (!KEY_SIZE(k))
		return NULL;

	rcu_read_lock();

	for (*ptr = 0; *ptr < bch_extent_ptrs(k); (*ptr)++) {
		struct cache *ca = PTR_CACHE(c, k, *ptr);

		if (ca && !ptr_stale(c, ca, k, *ptr)) {
			percpu_ref_get(&ca->ref);
			rcu_read_unlock();
			return ca;
		}
	}

	rcu_read_unlock();

	return NULL;
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

static const struct btree_keys_ops bch_extent_ops = {
	.sort_cmp	= bch_extent_sort_cmp,
	.sort_fixup	= bch_extent_sort_fixup,
	.insert_fixup	= bch_extent_insert_fixup,
	.key_invalid	= bch_extent_invalid,
	.key_debug_invalid = bch_extent_debug_invalid,
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.key_to_text	= bch_extent_to_text,
	.key_dump	= bch_bkey_dump,
	.is_extents	= true,
};

const struct btree_keys_ops *bch_btree_ops[] = {
	[BTREE_ID_EXTENTS]	= &bch_extent_ops,
	[BTREE_ID_INODES]	= &bch_inode_ops,
};
