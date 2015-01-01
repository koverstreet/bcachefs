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
#include "gc.h"
#include "inode.h"
#include "journal.h"
#include "super.h"
#include "writeback.h"

#include <trace/events/bcachefs.h>

static void sort_key_next(struct btree_node_iter *iter,
			  struct btree_node_iter_set *i)
{
	i->k = bkey_next(i->k);

	if (i->k == i->end)
		*i = iter->data[--iter->used];
}

struct bkey *bch_generic_sort_fixup(struct btree_node_iter *iter,
				    struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_node_iter_set *top = iter->data, *i = top + 1;

		if (iter->used > 2 &&
		    iter_cmp(iter)(i[0], i[1]))
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
		 * iter_cmp() ensures that when keys compare equal the newer key
		 * comes first; so i->k is older than top->k and we drop i->k.
		 */

		i->k = bkey_next(i->k);

		if (i->k == i->end)
			*i = iter->data[--iter->used];

		btree_node_iter_sift(iter, i - top);
	}

	return NULL;
}

/* This returns true if insert should be inserted, false otherwise */

bool bch_insert_fixup_key(struct btree *b, struct bkey *insert,
			  struct btree_node_iter *iter,
			  struct bch_replace_info *replace,
			  struct bkey *done,
			  struct journal_res *res)
{
	BUG_ON(replace);

	while (1) {
		struct bkey *k = bch_btree_node_iter_peek_all(iter);

		if (!k || bkey_cmp(k, insert) > 0)
			break;

		if (!bkey_cmp(k, insert) && !KEY_DELETED(k)) {
			SET_KEY_DELETED(k, 1);
			b->keys.nr_live_keys -= KEY_U64s(k);
		}

		bch_btree_node_iter_next_all(iter);
	}

	bch_btree_insert_and_journal(b, iter, insert, res);
	return true;
}

/* Common among btree and extent ptrs */

static bool should_drop_ptr(const struct cache_set *c, const struct bkey *k,
			    unsigned ptr)
{
	unsigned dev;
	struct cache *ca;
	struct cache_member *mi;

	dev = PTR_DEV(k, ptr);
	if (dev == PTR_LOST_DEV)
		return false;

	if (dev >= c->sb.nr_in_set)
		return true;

	mi = rcu_dereference(c->members)->m;

	if (bch_is_zero(mi[PTR_DEV(k, ptr)].uuid.b, sizeof(uuid_le)))
		return true;

	return (ca = PTR_CACHE(c, k, ptr)) &&
		ptr_stale(ca, k, ptr);
}

unsigned bch_extent_nr_ptrs_after_normalize(const struct cache_set *c,
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

void bch_extent_drop_stale(struct cache_set *c, struct bkey *k)
{
	unsigned i = 0;

	rcu_read_lock();

	while (i < bch_extent_ptrs(k))
		if (should_drop_ptr(c, k, i))
			bch_extent_drop_ptr(k, i);
		else
			i++;

	rcu_read_unlock();
}

static bool bch_ptr_normalize(struct btree_keys *bk,
			      struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return bch_extent_normalize(b->c, k);
}

static bool __ptr_invalid(const struct cache_set *c, const struct bkey *k)
{
	struct cache *ca;
	unsigned i;

	if (KEY_U64s(k) < BKEY_U64s ||
	    bch_extent_ptrs(k) > BKEY_EXTENT_PTRS_MAX)
		return true;

	if (!bch_extent_ptrs(k)
	    && !KEY_DELETED(k) && !KEY_WIPED(k) && !KEY_BAD(k))
		return true;

	if (KEY_WIPED(k) || KEY_BAD(k))
		return false;

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i))) {
			size_t bucket = PTR_BUCKET_NR(ca, k, i);
			size_t r = bucket_remainder(ca, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > ca->sb.bucket_size ||
			    bucket <  ca->sb.first_bucket ||
			    bucket >= ca->sb.nbuckets) {
				rcu_read_unlock();
				return true;
			}
		}

	rcu_read_unlock();

	return false;
}

static const char *bch_ptr_status(const struct cache_set *c,
				  const struct bkey *k)
{
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		struct cache *ca = PTR_CACHE(c, k, i);

		if (ca) {
			size_t bucket = PTR_BUCKET_NR(ca, k, i);
			size_t r = bucket_remainder(ca, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > ca->sb.bucket_size)
				return "bad, length too big";
			if (bucket <  ca->sb.first_bucket)
				return "bad, short offset";
			if (bucket >= ca->sb.nbuckets)
				return "bad, offset past end of device";
			if (ptr_stale(ca, k, i))
				return "stale";
		}
	}

	if (!bkey_cmp(k, &ZERO_KEY))
		return "bad, null key";
	if (!bch_extent_ptrs(k)) {
		if (KEY_WIPED(k))
			return "wiped key";
		else if (KEY_BAD(k))
			return "bad key, data lost";
		else
			return "bad, no pointers";
	}
	if (!KEY_SIZE(k))
		/* This should really say 'deleted key' or some such */
		return "zeroed key";
	return "";
}

static void bch_extent_to_text(const struct btree_keys *bk, char *buf,
			       size_t size, const struct bkey *k)
{
	const struct cache_set *c = container_of(bk, struct btree, keys)->c;
	unsigned i = 0;
	char *out = buf, *end = buf + size;
	const char *status;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		if (i)
			p(", ");

		if (PTR_DEV(k, i) == PTR_CHECK_DEV)
			p("check dev");
		else
			p("%llu:%llu gen %llu", PTR_DEV(k, i),
			  PTR_OFFSET(k, i), PTR_GEN(k, i));
	}

	if (KEY_CACHED(k))
		p(" cached");
	if (KEY_CSUM(k))
		p(" cs%llu %llx", KEY_CSUM(k), k->val[1]);

	rcu_read_lock();
	status = bch_ptr_status(c, k);
	rcu_read_unlock();
	if (status)
		p(" %s", status);
#undef p
}

/* Btree ptrs */

bool __bch_btree_ptr_invalid(const struct cache_set *c, const struct bkey *k)
{
	return (KEY_CACHED(k) ||
		KEY_SIZE(k) ||
		(!KEY_DELETED(k) && !KEY_WIPED(k) && !KEY_BAD(k)
		 && !bch_extent_ptrs(k)) ||
		__ptr_invalid(c, k));
}

static bool bch_btree_ptr_invalid(const struct btree_keys *bk,
				  const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return __bch_btree_ptr_invalid(b->c, k);
}

static void btree_ptr_debugcheck(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct cache_set *c = b->c;
	unsigned i, seq;
	char buf[80];
	struct bucket *g;
	struct cache *ca;
	bool bad;

	if (bch_btree_ptr_invalid(bk, k)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		btree_bug(b, "invalid bkey %s", buf);
		return;
	}

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i))) {
			g = PTR_BUCKET(ca, k, i);

			if (KEY_CACHED(k))
				goto err;

			do {
				seq = read_seqbegin(&c->gc_cur_lock);
				bad = (!__gc_will_visit_node(c, b) &&
				       !g->mark.is_metadata);
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto err;
		}

	rcu_read_unlock();

	return;
err:
	bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
	btree_bug(b, "inconsistent btree pointer %s: bucket %zi prio %i "
		  "gen %i oldest_gen %i mark 0x%08x",
		  buf, PTR_BUCKET_NR(ca, k, i),
		  g->read_prio, PTR_BUCKET_GEN(ca, k, i),
		  g->oldest_gen, g->mark.counter);
	rcu_read_unlock();
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
	.sort_fixup	= bch_generic_sort_fixup,

	.key_invalid	= bch_btree_ptr_invalid,
	.key_debugcheck	= btree_ptr_debugcheck,
	.val_to_text	= bch_extent_to_text,
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
		SET_KEY_DELETED(k, 1);

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
		SET_KEY_DELETED(k, 1);

	return true;
}

/*
 * Returns a key corresponding to the end of @k split at @where, @k will be the
 * first half of the split
 */
#define bch_key_split(where, k)					\
({								\
	BKEY_PADDED(k) __tmp;					\
								\
	bkey_copy(&__tmp.k, k);					\
	bch_cut_back(where, &__tmp.k);				\
	bch_cut_front(where, k);				\
	&__tmp.k;						\
})

/**
 * bch_key_resize - adjust size of @k
 *
 * KEY_START(k) will be preserved, modifies where the extent ends
 */
void bch_key_resize(struct bkey *k, unsigned new_size)
{
	SET_KEY_OFFSET(k, KEY_START(k) + new_size);
	SET_KEY_SIZE(k, new_size);
}

static struct bkey *bch_extent_sort_fixup(struct btree_node_iter *iter,
					  struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_node_iter_set *top = iter->data, *i = top + 1;

		if (iter->used > 2 &&
		    iter_cmp(iter)(i[0], i[1]))
			i++;

		if (bkey_cmp(top->k, &START_KEY(i->k)) <= 0)
			break;

		if (!KEY_SIZE(i->k)) {
			sort_key_next(iter, i);
			btree_node_iter_sift(iter, i - top);
			continue;
		}

		if (top->k > i->k) {
			if (bkey_cmp(top->k, i->k) >= 0)
				sort_key_next(iter, i);
			else
				bch_cut_front(top->k, i->k);

			btree_node_iter_sift(iter, i - top);
		} else {
			/* can't happen because of comparison func */
			BUG_ON(!bkey_cmp(&START_KEY(top->k), &START_KEY(i->k)));

			if (bkey_cmp(i->k, top->k) < 0) {
				bkey_copy(tmp, top->k);

				bch_cut_back(&START_KEY(i->k), tmp);
				bch_cut_front(i->k, top->k);
				btree_node_iter_sift(iter, 0);

				return tmp;
			} else {
				bch_cut_back(&START_KEY(i->k), top->k);
			}
		}
	}

	return NULL;
}

int __bch_add_sectors(struct cache_set *c, struct btree *b,
		      const struct bkey *k, u64 offset,
		      int sectors, bool fail_if_stale)
{
	unsigned replicas_found = 0, replicas_needed =
		CACHE_SET_DATA_REPLICAS_WANT(&c->sb);
	struct cache *ca;
	int i;

	if (KEY_CACHED(k))
		replicas_needed = 0;

	rcu_read_lock();
	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i)
		if ((ca = PTR_CACHE(c, k, i))) {
			bool dirty = replicas_found < replicas_needed;

			trace_bcache_add_sectors(ca, k, i, offset,
						 sectors, dirty);

			/*
			 * Two ways a dirty pointer could be stale here:
			 *
			 * - A bkey_cmpxchg() operation could be trying to
			 *   replace a key that no longer exists. The new key,
			 *   which can have some of the same pointers as the old
			 *   key, gets added here before checking if the cmpxchg
			 *   operation succeeds or not to avoid another race.
			 *
			 *   If that's the case, we just bail out of the
			 *   cmpxchg operation early - a dirty pointer can only
			 *   be stale if the actual dirty pointer in the btree
			 *   was overwritten.
			 *
			 *   And in that case we _have_ to bail out here instead
			 *   of letting bkey_cmpxchg() fail and undoing the
			 *   accounting we did here with subtract_sectors()
			 *   (like we do otherwise), because buckets going stale
			 *   out from under us changes which pointers we count
			 *   as dirty.
			 *
			 * - Journal replay
			 *
			 *   A dirty pointer could be stale in journal replay
			 *   if we haven't finished journal replay - if it's
			 *   going to get overwritten again later in replay.
			 *
			 *   In that case, we don't want to fail the insert
			 *   (just for mental health) - but, since
			 *   extent_normalize() drops stale pointers, we need to
			 *   count replicas in a way that's invariant under
			 *   normalize.
			 *
			 *   Fuck me, I hate my life.
			 */

			if (!bch_mark_data_bucket(c, ca, b, k, i, sectors,
						  dirty))
				replicas_found++;
			else if (dirty && fail_if_stale)
				goto stale;
		}
	rcu_read_unlock();

	return 0;
stale:
	while (++i < bch_extent_ptrs(k))
		if ((ca = PTR_CACHE(c, k, i)))
			bch_mark_data_bucket(c, ca, b, k, i, -sectors,
					     true);
	rcu_read_unlock();

	return -1;
}

static int bch_add_sectors(struct btree *b, const struct bkey *k, u64 offset,
			   int sectors, bool fail_if_stale)
{
	int ret;

	if (!bch_extent_ptrs(k))
		return 0;

	if (!sectors)
		return 0;

	BUG_ON(KEY_DELETED(k));

	ret = __bch_add_sectors(b->c, b, k, offset, sectors, fail_if_stale);
	if (ret)
		return ret;

	if (!KEY_CACHED(k))
		bcache_dev_sectors_dirty_add(b->c, KEY_INODE(k),
					     offset, sectors);

	return 0;
}

static void bch_subtract_sectors(struct btree *b, struct bkey *k,
				 u64 offset, int sectors)
{
	bch_add_sectors(b, k, offset, -sectors, false);
}

/* These wrappers subtract exactly the sectors that we're removing from @k */
static void bch_cut_subtract_back(struct btree *b, const struct bkey *where,
				  struct bkey *k)
{
	bch_subtract_sectors(b, k, KEY_OFFSET(where),
			     KEY_OFFSET(k) - KEY_OFFSET(where));
	bch_cut_back(where, k);
}

static void bch_cut_subtract_front(struct btree *b, const struct bkey *where,
				   struct bkey *k)
{
	bch_subtract_sectors(b, k, KEY_START(k),
			     KEY_OFFSET(where) - KEY_START(k));
	bch_cut_front(where, k);
}

static void bch_drop_subtract(struct btree *b, struct bkey *k)
{
	if (KEY_SIZE(k))
		bch_subtract_sectors(b, k, KEY_START(k), KEY_SIZE(k));
	SET_KEY_SIZE(k, 0);
	SET_KEY_DELETED(k, true);
}

/*
 * Note: If this returns true because only some pointers matched,
 * we can lose some caching that had happened in the interim.
 * Because cache promotion only promotes the part of the extent
 * actually read, and not the whole extent, and due to the key
 * splitting done in bch_extent_insert_fixup, preserving such
 * caching is difficult.
 */

static bool bkey_cmpxchg_cmp(struct bkey *k, struct bkey *old, bool exact)
{
	/* skip past gen */
	s64 offset = (KEY_START(k) - KEY_START(old)) << 8;
	unsigned i;

	if (!KEY_SIZE(old))
		return false;

	/* This does not compare KEY_OFFSET or KEY_SIZE */

	if (bch_bkey_equal_header(k, old)) {
		for (i = 0; i < bch_extent_ptrs(old); i++)
			if (k->val[i] != old->val[i] + offset)
				goto try_partial_match;

		return true;
	}

try_partial_match:
	if (exact)
		/* Non-exact matches not allowed */
		return false;
#if (0)
	/* This does not compare KEY_U64s or KEY_CSUM either */

	if (bch_bkey_maybe_compatible(k, old)) {
		for (i = 0; i < bch_extent_ptrs(old); i++) {
			unsigned j;

			for (j = 0; j < bch_extent_ptrs(k); j++)
				if (k->val[j] == old->val[i] + offset)
					return true;
		}
	}
#endif

	return false;
}

/*
 * Returns true on success, false on failure (and false means @new no longer
 * overlaps with @k)
 *
 * If returned true, we may have inserted up to one key in @b.
 * If returned false, we may have inserted up to two keys in @b.
 *
 * On return, there is room in @res for at least one more key of the same size
 * as @new.
 */
static bool bkey_cmpxchg(struct btree *b,
			 struct btree_node_iter *iter,
			 struct bkey *k,
			 struct bch_replace_info *replace,
			 struct bkey *new,
			 struct bkey *done,
			 bool *inserted,
			 struct journal_res *res)
{
	bool ret;
	struct bkey *old = &replace->key;

	/* must have something to compare against */
	BUG_ON(!bch_extent_ptrs(old));
	BUG_ON(b->level);

	/* new must be a subset of old */
	BUG_ON(bkey_cmp(new, old) > 0 ||
	       bkey_cmp(&START_KEY(new), &START_KEY(old)) < 0);

	/*
	 * first, check if there was a hole - part of the new key that we
	 * haven't checked against any existing key
	 */
	if (bkey_cmp(&START_KEY(k), done) > 0) {
		/* insert previous partial match: */
		if (bkey_cmp(done, &START_KEY(new)) > 0) {
			replace->successes += 1;
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(done, new),
						     res);
			*inserted = true;

			/*
			 * If we don't have room for one more insert, we have
			 * to get a new journal reservation all the way up in
			 * bch_btree_insert_keys().
			 */
			if (journal_res_full(res, new)) {
				bch_cut_subtract_front(b, &START_KEY(k), new);
				*done = START_KEY(k);

				return false;
			}
		}

		bch_cut_subtract_front(b, &START_KEY(k), new);
		*done = START_KEY(k);
	}

	ret = bkey_cmpxchg_cmp(k, old, false);
	if (!ret) {
		/* failed: */
		replace->failures += 1;
		if (bkey_cmp(done, &START_KEY(new)) > 0) {
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(done, new),
						     res);
			*inserted = true;
		}

		if (bkey_cmp(k, new) > 0)
			bch_drop_subtract(b, new);
		else
			bch_cut_subtract_front(b, k, new);
	} else
		replace->successes += 1;

	*done = bkey_cmp(k, new) < 0 ? *k : *new;
	return ret;
}

/* We are trying to insert a key with an older version than the existing one */
static void handle_existing_key_newer(struct btree *b,
				      struct btree_node_iter *iter,
				      struct bkey *insert,
				      struct bkey *k,
				      bool *inserted,
				      struct journal_res *res)
{
	/* k is the key currently in the tree, 'insert' the new key */

	switch (bch_extent_overlap(k, insert)) {
	case BCH_EXTENT_OVERLAP_FRONT:
		/* k and insert share the start, remove it from insert */
		bch_cut_subtract_front(b, k, insert);
		break;

	case BCH_EXTENT_OVERLAP_BACK:
		/* k and insert share the end, remove it from insert */
		bch_cut_subtract_back(b, &START_KEY(k), insert);
		break;

	case BCH_EXTENT_OVERLAP_MIDDLE:
		/*
		 * We have an overlap where @k (newer version splits
		 * @insert (older version) in three:
		 * - start only in insert
		 * - middle common section -- keep k
		 * - end only in insert
		 *
		 * Insert the start of @insert ourselves, then update
		 * @insert to to represent the end.
		 *
		 * Since we're splitting the insert key, we have to use
		 * bch_btree_insert_and_journal(), which adds a journal
		 * entry to @res.
		 */
		bch_btree_insert_and_journal(b, iter,
				bch_key_split(&START_KEY(k), insert),
				res);
		bch_cut_subtract_front(b, k, insert);
		*inserted = true;
		break;

	case BCH_EXTENT_OVERLAP_ALL:
		/* k completely covers insert -- drop insert */
		bch_drop_subtract(b, insert);
		break;
	}
}

static void overwrite_full_key(struct btree *b, struct bkey *insert,
			     struct btree_node_iter *iter,
			     struct bkey *k)
{
	if (!KEY_DELETED(k))
		b->keys.nr_live_keys -= KEY_U64s(k);

	bch_drop_subtract(b, k);
	/*
	 * Completely overwrote, so if this key isn't in the
	 * same bset as the one we're going to insert into we
	 * can just set its size to 0, and not modify the
	 * offset, and not have to invalidate/fix the auxiliary
	 * search tree.
	 *
	 * Note: peek_overlapping() will think we still overlap,
	 * so we need the explicit iter_next() call.
	 */
	if (!bkey_written(&b->keys, k))
		SET_KEY_OFFSET(k, KEY_START(insert));

	bch_btree_node_iter_next_all(iter);
}

/*
 * bch_insert_exact_extent is similar to bch_insert_fixup_extent but it
 * is always used to replace and does not fragment the key.
 * It is pre-checked by the caller to make sure that it would be a
 * complete replacement.
 *
 * This returns true if it inserted, false otherwise.  It can return
 * false because the comparison fails or because there is no room --
 * the caller needs to split the btree node.
 */
bool bch_insert_exact_extent(struct btree *b,
			     struct bkey *insert,
			     struct btree_node_iter *iter,
			     struct bch_replace_info *replace,
			     struct bkey *done,
			     struct journal_res *res)
{
	bool ret;
	struct bkey *k;

	BUG_ON(!KEY_SIZE(insert));
	BUG_ON(replace == NULL || !replace->replace_exact);
	BUG_ON(!bch_same_extent(insert, &replace->key));

	/* Make sure there is enough room for the insertion */

	if (bch_btree_keys_u64s_remaining(&b->keys) < BKEY_EXTENT_MAX_U64s) {
		/*
		 * XXX: would be better to explicitly signal that we
		 * need to split
		 */
		*done = START_KEY(insert);
		return false;
	}

	/* Whether we succeed or fail, it is all or nothing */
	*done = *insert;

	k = bch_btree_node_iter_peek_overlapping(iter, insert);

	ret = (k != NULL
	       && !KEY_DELETED(k)
	       && bch_same_extent(k, &replace->key)
	       && bkey_cmpxchg_cmp(k, &replace->key, true));

	if (ret) {
		/*
		 * Do not insert if the pointers being inserted are stale.
		 */
		if (bch_add_sectors(b, insert, KEY_START(insert),
				    KEY_SIZE(insert), true)) {
			/* We raced - a dirty pointer was stale */
			ret = false;
		} else {
			overwrite_full_key(b, insert, iter, k);
			bch_btree_insert_and_journal(b, iter, insert, res);
			replace->successes += 1;
		}
	}

	if (!ret)
		replace->failures += 1;

	return ret;
}

/**
 * bch_extent_insert_fixup - insert a new extent and deal with overlaps
 *
 * this may result in not actually doing the insert, or inserting some subset
 * of the insert key. For cmpxchg operations this is where that logic lives.
 *
 * All subsets of @insert that need to be inserted are inserted using
 * bch_btree_insert_and_journal(). If @b or @res fills up, this function
 * returns false, setting @done for the prefix of @insert that actually got
 * inserted.
 *
 * BSET INVARIANTS: this function is responsible for maintaining all the
 * invariants for bsets of extents in memory. things get really hairy with 0
 * size extents
 *
 * within one bset:
 *
 * START_KEY(bkey_next(k)) >= k
 * or KEY_START(bkey_next(k)) >= KEY_OFFSET(k)
 *
 * i.e. strict ordering, no overlapping extents.
 *
 * multiple bsets (i.e. full btree node):
 *
 * ∀ k, j
 *   KEY_SIZE(k) != 0 ∧ KEY_SIZE(j) != 0 →
 *     ¬ (k > START_KEY(j) ∧ k < j)
 *
 * i.e. no two overlapping keys _of nonzero size_
 *
 * We can't realistically maintain this invariant for zero size keys because of
 * the key merging done in bch_btree_insert_key() - for two mergeable keys k, j
 * there may be another 0 size key between them in another bset, and it will
 * thus overlap with the merged key.
 *
 * This returns true if it inserted, false otherwise.
 * Note that it can return false due to failure or because there is no
 * room for the insertion -- the caller needs to split the btree node.
 *
 * In addition, the end of done indicates how much has been processed.
 * If the end of done is not the same as the end of insert, then
 * key insertion needs to continue/be retried.
 */
bool bch_insert_fixup_extent(struct btree *b, struct bkey *insert,
			     struct btree_node_iter *iter,
			     struct bch_replace_info *replace,
			     struct bkey *done,
			     struct journal_res *res)
{
	struct bkey *k, *split, orig_insert = *insert;
	bool inserted = false;

	BUG_ON(!KEY_SIZE(insert));

	*done = START_KEY(insert);

	/*
	 * If this is a cmpxchg operation, @insert doesn't necessarily exist in
	 * the btree, and may have pointers not pinned by open buckets; thus
	 * some of the pointers might be stale because we raced with foreground
	 * writes.
	 *
	 * If that happens bkey_cmpxchg() is going to fail; bail out here
	 * instead of calling subtract_sectors() in the fail path to avoid
	 * various races (we definitely don't want to increment/decrement
	 * sectors_dirty on a bucket that's been reused, or worse have a bucket
	 * go stale between here and subtract_sectors()).
	 *
	 * But only bail out here for cmpxchg operations - in journal replay we
	 * can also insert keys with stale pointers, but for those we still need
	 * to proceed with the insertion.
	 */
	if (bch_add_sectors(b, insert, KEY_START(insert),
			    KEY_SIZE(insert), (replace != NULL))) {
		/* We raced - a dirty pointer was stale */
		*done = *insert;
		SET_KEY_SIZE(insert, 0);
		if (replace != NULL)
			replace->failures += 1;
		return false;
	}

	while (KEY_SIZE(insert) &&
	       (k = bch_btree_node_iter_peek_overlapping(iter, insert))) {
		/*
		 * Incrementing @done indicates to the caller that we've
		 * finished with @insert up to that point.
		 *
		 * Before setting @done, we first check if we have space for
		 * the insert plus one potential split in the btree node and
		 * journal reservation.
		 */
		bool needs_split = (bch_btree_keys_u64s_remaining(&b->keys) <
				    BKEY_EXTENT_MAX_U64s * 2);
		bool res_full = journal_res_full(res, insert);

		if (needs_split || res_full) {
			/*
			 * XXX: would be better to explicitly signal that we
			 * need to split
			 */
			bch_cut_subtract_back(b, done, insert);
			BUG_ON(KEY_SIZE(insert));
			return false;
		}

		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for replace
		 * operations.
		 */
		if (replace == NULL)
			*done = bkey_cmp(k, insert) < 0 ? *k : *insert;
		else if (KEY_SIZE(k) &&
			 !bkey_cmpxchg(b, iter, k, replace, insert, done,
				       &inserted, res))
			continue;

		if (KEY_SIZE(k) && !KEY_DELETED(insert) &&
		    KEY_VERSION(insert) < KEY_VERSION(k)) {
			handle_existing_key_newer(b, iter, insert, k,
						  &inserted, res);
			continue;
		}

		/* k is the key currently in the tree, 'insert' the new key */

		switch (bch_extent_overlap(insert, k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			/* insert and k share the start, invalidate in k */
			bch_cut_subtract_front(b, insert, k);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			/* insert and k share the end, invalidate in k */
			bch_cut_subtract_back(b, &START_KEY(insert), k);
			/*
			 * As the auxiliary tree is indexed by the end of the
			 * key and we've just changed the end, update the
			 * auxiliary tree.
			 */
			bch_bset_fix_invalidated_key(&b->keys, k);
			break;

		case BCH_EXTENT_OVERLAP_ALL:
			/* The insert key completely covers k, invalidate k */
			overwrite_full_key(b, insert, iter, k);
			break;

		case BCH_EXTENT_OVERLAP_MIDDLE:
			/*
			 * The insert key falls 'in the middle' of k
			 * The insert key splits k in 3:
			 * - start only in k, preserve
			 * - middle common section, invalidate in k
			 * - end only in k, preserve
			 *
			 * We update the old key to preserve the start,
			 * insert will be the new common section,
			 * we manually insert the end that we are preserving.
			 *
			 * modify k _before_ doing the insert (which will move
			 * what k points to)
			 */
			split = bch_key_split(&START_KEY(insert), k);
			bch_cut_subtract_front(b, insert, k);
			bch_bset_insert(&b->keys, iter, split);
			break;
		}
	}

	/* Was there a hole? */
	if (bkey_cmp(done, insert) < 0) {
		/*
		 * Holes not allowed for cmpxchg operations, so chop off
		 * whatever we're not inserting (but done needs to reflect what
		 * we've processed, i.e. what insert was)
		 */
		if (replace != NULL)
			bch_cut_subtract_back(b, done, insert);

		*done = orig_insert;
	}

	if (KEY_SIZE(insert)) {
		bch_btree_insert_and_journal(b, iter, insert, res);
		inserted = true;
	}

	return inserted;
}

bool __bch_extent_invalid(const struct cache_set *c, const const struct bkey *k)
{
	return (KEY_SIZE(k) > KEY_OFFSET(k) ||
		(!KEY_SIZE(k) && !KEY_WIPED(k)
		 && !KEY_BAD(k) && !KEY_DELETED(k)) ||
		__ptr_invalid(c, k));
}

static bool bch_extent_invalid(const struct btree_keys *bk,
			       const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return __bch_extent_invalid(b->c, k);
}

/*
 * This is a subset of bch_extent_debugcheck but doesn't complain,
 * just returns a boolean.
 */

bool bch_extent_key_valid(struct cache_set *c, struct bkey *k)
{
	int i;
	bool ret = true;
	struct cache *ca;
	struct cache_member_rcu *mi;
	unsigned dev, stale, replicas_needed;

	if (__bch_extent_invalid(c, k))
		return false;

	if (bkey_deleted(k) || KEY_WIPED(k) || KEY_BAD(k))
		return true;

	replicas_needed = KEY_CACHED(k) ? 0
		: CACHE_SET_DATA_REPLICAS_WANT(&c->sb);

	mi = cache_member_info_get(c);

	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i) {
		dev = PTR_DEV(k, i);

		/* Could be a special pointer such as PTR_CHECK_DEV */
		if (dev >= mi->nr_in_set) {
			/*
			 * PTR_LOST_DEV counts as a valid replica...
			 * Since it is a valid state (data loss due to device
			 * removal with unsuccessful data motion).
			 */
			if ((dev == PTR_LOST_DEV) && replicas_needed)
				replicas_needed--;
			continue;
		}

		if (replicas_needed &&
		    bch_is_zero(mi->m[dev].uuid.b, sizeof(uuid_le)))
			break;

		ca = PTR_CACHE(c, k, i);
		if (ca == NULL)
			continue;

		stale = ptr_stale(ca, k, i);
		if (replicas_needed && !stale)
			replicas_needed--;
	}

	if (replicas_needed && KEY_SIZE(k))
		ret = false;

	cache_member_info_put();
	return ret;
}

static void bch_extent_debugcheck(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct cache_member_rcu *mi;
	struct cache_set *c = b->c;
	struct cache *ca;
	struct bucket *g;
	unsigned seq, stale, replicas_needed;
	char buf[80];
	bool bad;
	int i;
	unsigned ptrs_per_tier[CACHE_TIERS];
	unsigned dev, tier, replicas;

	if (__bch_extent_invalid(c, k)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		cache_set_bug(c, "invalid bkey %s", buf);
		return;
	}

	if (bkey_deleted(k) || KEY_WIPED(k) || KEY_BAD(k))
		return;

	memset(ptrs_per_tier, 0, sizeof(ptrs_per_tier));

	replicas_needed = KEY_CACHED(k) ? 0
		: CACHE_SET_DATA_REPLICAS_WANT(&c->sb);

	mi = cache_member_info_get(c);

	for (i = bch_extent_ptrs(k) - 1; i >= 0; --i) {
		dev = PTR_DEV(k, i);

		/* Could be a special pointer such as PTR_CHECK_DEV */
		if (dev >= mi->nr_in_set) {
			/*
			 * PTR_LOST_DEV counts as a valid replica...
			 * Since it is a valid state (data loss due to device
			 * removal with unsuccessful data motion).
			 */
			if ((dev == PTR_LOST_DEV) && replicas_needed)
				replicas_needed--;
			continue;
		}

		if (replicas_needed &&
		    bch_is_zero(mi->m[dev].uuid.b, sizeof(uuid_le)))
			goto bad_device;

		tier = CACHE_TIER(&mi->m[dev]);
		ptrs_per_tier[tier]++;

		stale = 0;

		if ((ca = PTR_CACHE(c, k, i))) {
			g = PTR_BUCKET(ca, k, i);

			do {
				struct bucket_mark mark;

				seq = read_seqbegin(&c->gc_cur_lock);
				mark = READ_ONCE(g->mark);

				/* between mark and bucket gen */
				smp_rmb();

				stale = ptr_stale(ca, k, i);

				cache_set_bug_on(stale > 96, c,
						 "key too stale: %i",
						 stale);

				bad = (!stale &&
				       !__gc_will_visit_node(c, b) &&
				       (mark.is_metadata ||
					(!mark.dirty_sectors &&
					 !mark.owned_by_allocator &&
					 replicas_needed)));
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto bad_ptr;
		}

		if (replicas_needed && !stale)
			replicas_needed--;
	}

	if (replicas_needed && KEY_SIZE(k)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		cache_set_bug(c, "extent key bad (too few replicas): %s", buf);
		goto done;
	}

	replicas = CACHE_SET_DATA_REPLICAS_WANT(&c->sb);
	for (i = 0; i < CACHE_TIERS; i++)
		if (ptrs_per_tier[i] > replicas) {
			bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
			cache_set_bug(c,
				      "extent key bad (too many tier %u replicas): %s",
				      i, buf);
			break;
		}

done:
	cache_member_info_put();
	return;

bad_device:
	bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %i device missing: %s", i, buf);
	cache_member_info_put();
	return;

bad_ptr:
	bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %i bad gc mark: %s:\nbucket %zu prio %i "
		      "gen %i oldest_gen %i mark 0x%08x", i,
		      buf, PTR_BUCKET_NR(ca, k, i),
		      g->read_prio, PTR_BUCKET_GEN(ca, k, i),
		      g->oldest_gen, g->mark.counter);
	cache_member_info_put();
	return;
}

static unsigned PTR_TIER(struct cache_member_rcu *mi, const struct bkey *k,
			 unsigned ptr)
{
	unsigned dev = PTR_DEV(k, ptr);

	return dev < mi->nr_in_set ? CACHE_TIER(&mi->m[dev]) : UINT_MAX;
}

bool bch_extent_normalize(struct cache_set *c, struct bkey *k)
{
	struct cache_member_rcu *mi;
	unsigned i;
	bool swapped;

	if (!KEY_SIZE(k)) {
		bch_set_extent_ptrs(k, 0);
		SET_KEY_DELETED(k, 1);
		return true;
	}

	bch_extent_drop_stale(c, k);

	mi = cache_member_info_get(c);

	/* Bubble sort pointers by tier, lowest (fastest) tier first. */
	do {
		swapped = false;
		for (i = 0; i + 1 < bch_extent_ptrs(k); i++) {
			if (PTR_TIER(mi, k, i) > PTR_TIER(mi, k, i + 1)) {
				swap(k->val[i], k->val[i + 1]);
				swapped = true;
			}
		}
	} while (swapped);

	cache_member_info_put();

	if (!bch_extent_ptrs(k) && !KEY_WIPED(k) && !KEY_BAD(k))
		SET_KEY_DELETED(k, 1);

	return KEY_DELETED(k);
}

/*
 * This picks a non-stale pointer, preferabbly from a device other than
 * avoid.  Avoid can be NULL, meaning pick any.  If there are no non-stale
 * pointers to other devices, it will still pick a pointer from avoid.
 * Note that it prefers lowered-numbered pointers to higher-numbered pointers
 * as the pointers are sorted by tier, hence preferring pointers to tier 0
 * rather than pointers to tier 1.
 */

struct cache *bch_extent_pick_ptr_avoiding(struct cache_set *c,
					   const struct bkey *k,
					   unsigned *ptr,
					   struct cache *avoid)
{
	unsigned i;
	struct cache *picked = NULL;

	if (((KEY_SIZE(k)) == 0) || (KEY_WIPED(k)) || (KEY_BAD(k)))
		return NULL;

	rcu_read_lock();

	/*
	 * Note: If DEV is PTR_LOST_DEV, PTR_CACHE returns NULL
	 * so if there are no other pointers, we'll return ERR_PTR(-EIO).
	 */

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		struct cache *ca = PTR_CACHE(c, k, i);

		if (ca && !ptr_stale(ca, k, i)) {
			picked = ca;
			*ptr = i;
			if (ca != avoid)
				break;
		}
	}

	if (picked != NULL) {
		percpu_ref_get(&picked->ref);
		rcu_read_unlock();
		return picked;
	}

	rcu_read_unlock();

	/* data missing that's not supposed to be? */
	if (!KEY_CACHED(k) && bch_extent_ptrs(k))
		return ERR_PTR(-EIO);

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
	struct cache *ca;
	unsigned i;

	if (key_merging_disabled(b->c))
		return false;

	/*
	 * Generic header checks
	 * Assumes left and right are in order
	 * Left and right must be exactly aligned
	 */
	if (!bch_bkey_equal_header(l, r) ||
	     bkey_cmp(l, &START_KEY(r)))
		return false;

	for (i = 0; i < bch_extent_ptrs(l); i++) {
		/*
		 * compare all the pointer fields at once, adding the size to
		 * the left pointer's offset:
		 */
		if (l->val[i] + PTR(0, KEY_SIZE(l), 0) != r->val[i])
			return false;

		/*
		 * we don't allow extent pointers to straddle buckets - if the
		 * device is offline, we don't know the bucket size so we can't
		 * check
		 */
		rcu_read_lock();
		if (!(ca = PTR_CACHE(b->c, l, i)) ||
		    PTR_BUCKET_NR(ca, l, i) !=
		    PTR_BUCKET_NR(ca, r, i)) {
			rcu_read_unlock();
			return false;
		}
		rcu_read_unlock();
	}

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if (KEY_SIZE(l) + KEY_SIZE(r) > KEY_SIZE_MAX) {
		bch_key_resize(l, KEY_SIZE_MAX);
		bch_cut_front(l, r);
		return false;
	}

	if (KEY_CSUM(l)) {
		if (KEY_CSUM(r))
			l->val[bch_extent_ptrs(l)] = merge_chksums(l, r);
		else
			SET_KEY_CSUM(l, 0);
	}

	bch_key_resize(l, KEY_SIZE(l) + KEY_SIZE(r));

	return true;
}

static const struct btree_keys_ops bch_extent_ops = {
	.sort_fixup	= bch_extent_sort_fixup,
	.key_invalid	= bch_extent_invalid,
	.key_debugcheck	= bch_extent_debugcheck,
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.val_to_text	= bch_extent_to_text,
	.is_extents	= true,
};

const struct btree_keys_ops *bch_btree_ops[] = {
	[BTREE_ID_EXTENTS]	= &bch_extent_ops,
	[BTREE_ID_INODES]	= &bch_inode_ops,
};

void bch_insert_check_key(struct btree_keys *bk, struct bkey *k)
{
	BUG_ON(bk->ops == NULL);
	if (bk->ops->is_extents)
		BUG_ON(bk->ops->val_to_text == NULL
		       || bk->ops->key_debugcheck == NULL);

	if ((bk->ops->key_debugcheck != NULL)
	    && (bk->ops->val_to_text != NULL))
		bk->ops->key_debugcheck(bk, k);
}
