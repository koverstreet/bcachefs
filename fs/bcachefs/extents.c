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

		if (bkey_cmp(top->k->p, i->k->p))
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
			  struct bpos *done,
			  struct journal_res *res)
{
	BUG_ON(replace);

	while (1) {
		struct bkey *k = bch_btree_node_iter_peek_all(iter);

		if (!k || bkey_cmp(k->p, insert->p) > 0)
			break;

		if (!bkey_cmp(k->p, insert->p) && !bkey_deleted(k)) {
			__set_bkey_deleted(k);
			b->keys.nr_live_keys -= k->u64s;
		}

		bch_btree_node_iter_next_all(iter);
	}

	bch_btree_insert_and_journal(b, iter, insert, res);
	return true;
}

/* Common among btree and extent ptrs */

bool bch_extent_has_device(const struct bkey_i_extent *e, unsigned dev)
{
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr)
		if (PTR_DEV(ptr) == dev)
			return true;

	return false;
}

static bool should_drop_ptr(const struct cache_set *c,
			    const struct bkey_i_extent *e,
			    const struct bch_extent_ptr *ptr)
{
	unsigned dev;
	struct cache *ca;
	struct cache_member *mi;

	dev = PTR_DEV(ptr);
	if (dev == PTR_LOST_DEV)
		return false;

	if (dev >= c->sb.nr_in_set)
		return true;

	mi = rcu_dereference(c->members)->m;

	if (bch_is_zero(mi[dev].uuid.b, sizeof(uuid_le)))
		return true;

	if (bch_extent_ptr_is_dirty(c, e, ptr))
		return false;

	return (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr);
}

unsigned bch_extent_nr_ptrs_after_normalize(const struct cache_set *c,
					    const struct bkey *k)
{
	const struct bkey_i_extent *e;
	const struct bch_extent_ptr *ptr;
	unsigned ret = 0;

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_COOKIE:
		return 0;

	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		return BKEY_U64s;

	case BCH_EXTENT:
		e = bkey_i_to_extent_c(k);

		rcu_read_lock();
		extent_for_each_ptr(e, ptr)
			if (!should_drop_ptr(c, e, ptr))
				ret++;
		rcu_read_unlock();

		if (ret)
			ret += BKEY_U64s;

		return ret;
	default:
		BUG();
	}
}

void bch_extent_drop_stale(struct cache_set *c, struct bkey *k)
{
	struct bkey_i_extent *e = bkey_i_to_extent(k);
	struct bch_extent_ptr *ptr;

	rcu_read_lock();

	extent_for_each_ptr_backwards(e, ptr)
		if (should_drop_ptr(c, e, ptr))
			bch_extent_drop_ptr(&e->k, ptr - e->v.ptr);

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
	const struct bkey_i_extent *e;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	if (k->u64s < BKEY_U64s)
		return true;

	switch (k->type) {
	case KEY_TYPE_DELETED:
		return false;

	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		return bkey_val_bytes(k) != 0;

	case KEY_TYPE_COOKIE:
		if (bkey_val_bytes(k) != sizeof(struct bch_cookie))
			return true;
		return false;

	case BCH_EXTENT:
		e = bkey_i_to_extent_c(k);

		if (bch_extent_ptrs(e) > BKEY_EXTENT_PTRS_MAX)
			return true;

		rcu_read_lock();

		extent_for_each_online_device(c, e, ptr, ca) {
			size_t bucket = PTR_BUCKET_NR(ca, ptr);
			size_t r = bucket_remainder(ca, PTR_OFFSET(ptr));

			if (k->size + r > c->sb.bucket_size ||
			    bucket <  ca->sb.first_bucket ||
			    bucket >= ca->sb.nbuckets) {
				rcu_read_unlock();
				return true;
			}
		}

		rcu_read_unlock();

		return false;
	default:
		return true;
	}
}

static const char *bch_ptr_status(const struct cache_set *c,
				  const struct bkey *k)
{
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	extent_for_each_online_device(c, e, ptr, ca) {
		size_t bucket = PTR_BUCKET_NR(ca, ptr);
		size_t r = bucket_remainder(ca, PTR_OFFSET(ptr));

		if (k->size + r > ca->sb.bucket_size)
			return "bad, length too big";
		if (bucket <  ca->sb.first_bucket)
			return "bad, short offset";
		if (bucket >= ca->sb.nbuckets)
			return "bad, offset past end of device";
		if (ptr_stale(ca, ptr))
			return "stale";
	}

	if (!bkey_cmp(e->k.p, POS_MIN))
		return "bad, null key";
	if (!bch_extent_ptrs(e))
		return "bad, no pointers";
	if (!k->size)
		return "zeroed key";
	return "";
}

static void bch_extent_to_text(const struct btree_keys *bk, char *buf,
			       size_t size, const struct bkey *k)
{
	const struct cache_set *c = container_of(bk, struct btree, keys)->c;
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	char *out = buf, *end = buf + size;
	const struct bch_extent_ptr *ptr;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	extent_for_each_ptr(e, ptr) {
		if (ptr != e->v.ptr)
			p(", ");

		p("%llu:%llu gen %llu", PTR_DEV(ptr),
		  PTR_OFFSET(ptr), PTR_GEN(ptr));
	}

	if (EXTENT_CACHED(&e->v))
		p(" cached");
#if 0
	if (KEY_CSUM(k))
		p(" cs%llu %llx", KEY_CSUM(k), k->val[1]);
#endif

	rcu_read_lock();
	p(" %s", bch_ptr_status(c, k));
	rcu_read_unlock();
#undef p
}

/* Btree ptrs */

bool __bch_btree_ptr_invalid(const struct cache_set *c, const struct bkey *k)
{
	const struct bkey_i_extent *e;

	if (k->size ||
	    __ptr_invalid(c, k))
		return true;

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_ERROR:
		return false;
	case BCH_EXTENT:
		e = bkey_i_to_extent_c(k);

		return EXTENT_CACHED(&e->v) || !bch_extent_ptrs(e);
	default:
		return true;
	}
}

static bool bch_btree_ptr_invalid(const struct btree_keys *bk,
				  const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return __bch_btree_ptr_invalid(b->c, k);
}

static void btree_ptr_debugcheck(struct btree_keys *bk, const struct bkey *k)
{
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	const struct bch_extent_ptr *ptr;
	struct btree *b = container_of(bk, struct btree, keys);
	struct cache_set *c = b->c;
	unsigned seq;
	char buf[160];
	struct bucket *g;
	struct cache *ca;
	bool bad;

	if (bch_btree_ptr_invalid(bk, k)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		btree_bug(b, "invalid bkey %s", buf);
		return;
	}

	if (EXTENT_CACHED(&e->v)) {
		btree_bug(b, "btree ptr marked as cached");
		return;
	}

	rcu_read_lock();

	extent_for_each_online_device(c, e, ptr, ca) {
		g = PTR_BUCKET(ca, ptr);

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
		  "gen %i last_gc %i mark %08x",
		  buf, PTR_BUCKET_NR(ca, ptr),
		  g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		  g->oldest_gen, g->mark.counter);
	rcu_read_unlock();
}

struct cache *bch_btree_pick_ptr(struct cache_set *c, const struct bkey *k,
				 const struct bch_extent_ptr **ptr)
{
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	struct cache *ca;

	rcu_read_lock();

	extent_for_each_online_device(c, e, *ptr, ca) {
		percpu_ref_get(&ca->ref);
		rcu_read_unlock();
		return ca;
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

void bch_bkey_copy_single_ptr(struct bkey *dst, const struct bkey *src,
			      unsigned i)
{
	const struct bkey_i_extent *srce = bkey_i_to_extent_c(src);
	struct bkey_i_extent *dste;

	BUG_ON(i > bch_extent_ptrs(srce));

	/* Only copy the header, key, and one pointer. */
	*dst = srce->k;
	dste = bkey_i_to_extent(dst);

	dste->v.ptr[0] = srce->v.ptr[i];

	bch_set_extent_ptrs(dste, 1);
#if 0
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dst, 0);
#endif
}

bool bch_cut_front(struct bpos where, struct bkey *k)
{
	struct bkey_i_extent *e;
	struct bch_extent_ptr *ptr;
	unsigned len = 0;

	BUG_ON(bkey_cmp(where, k->p) > 0);

	if (bkey_cmp(where, bkey_start_pos(k)) <= 0)
		return false;

	if (bkey_cmp(where, k->p) < 0)
		len = k->p.offset - where.offset;
	else
		k->p = where;

	/*
	 * Don't readjust offset if the key size is now 0, because that could
	 * cause offset to point to the next bucket:
	 */
	if (len)
		switch (k->type) {
		case BCH_EXTENT:
			e = bkey_i_to_extent(k);

			extent_for_each_ptr(e, ptr)
				SET_PTR_OFFSET(ptr, PTR_OFFSET(ptr) +
					       e->k.size - len);
			break;
		default:
			break;
		}

	BUG_ON(len > k->size);
	k->size = len;

	if (!len)
		__set_bkey_deleted(k);

	return true;
}

bool bch_cut_back(struct bpos where, struct bkey *k)
{
	unsigned len = 0;

	BUG_ON(bkey_cmp(where, bkey_start_pos(k)) < 0);

	if (bkey_cmp(where, k->p) >= 0)
		return false;

	BUG_ON(where.inode != k->p.inode);

	if (bkey_cmp(where, bkey_start_pos(k)) > 0)
		len = where.offset - bkey_start_offset(k);

	k->p = where;

	BUG_ON(len > k->size);
	k->size = len;

	if (!len)
		__set_bkey_deleted(k);

	return true;
}

/*
 * Returns a key corresponding to the start of @k split at @where, @k will be
 * the second half of the split
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
 * bkey_start_offset(k) will be preserved, modifies where the extent ends
 */
void bch_key_resize(struct bkey *k, unsigned new_size)
{
	k->p.offset -= k->size;
	k->p.offset += new_size;
	k->size = new_size;
}

static struct bkey *bch_extent_sort_fixup(struct btree_node_iter *iter,
					  struct bkey *tmp)
{
	while (iter->used > 1) {
		struct btree_node_iter_set *l = iter->data, *r = l + 1;

		if (iter->used > 2 &&
		    iter_cmp(iter)(r[0], r[1]))
			r++;

		/* If they don't overlap, we're done */
		if (bkey_cmp(l->k->p, bkey_start_pos(r->k)) <= 0)
			break;

		/* Skip 0 size keys */
		if (!r->k->size) {
			sort_key_next(iter, r);
			btree_node_iter_sift(iter, r - iter->data);
			continue;
		}

		/*
		 * overlap: keep the newer key and trim the older key so they
		 * don't overlap. comparing pointers tells us which one is
		 * newer, since the bsets are appended one after the other.
		 */

		/* can't happen because of comparison func */
		BUG_ON(l->k < r->k &&
		       !bkey_cmp(bkey_start_pos(l->k), bkey_start_pos(r->k)));

		if (l->k > r->k) {
			/* l wins, trim r */
			if (bkey_cmp(l->k->p, r->k->p) >= 0)
				sort_key_next(iter, r);
			else
				bch_cut_front(l->k->p, r->k);

			btree_node_iter_sift(iter, r - iter->data);
		} else if (bkey_cmp(l->k->p, r->k->p) > 0) {
			/*
			 * r wins, but it overlaps in the middle of l - split l:
			 */
			bkey_copy(tmp, l->k);

			bch_cut_back(bkey_start_pos(r->k), tmp);
			bch_cut_front(r->k->p, l->k);
			btree_node_iter_sift(iter, 0);

			return tmp;
		} else {
			/* r wins, no split: */
			bch_cut_back(bkey_start_pos(r->k), l->k);
		}
	}

	return NULL;
}

int __bch_add_sectors(struct cache_set *c, struct btree *b,
		      const struct bkey_i_extent *e, u64 offset,
		      int sectors, bool fail_if_stale)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca) {
		bool stale, dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		trace_bcache_add_sectors(ca, e, ptr, offset,
					 sectors, dirty);

		/*
		 * Two ways a dirty pointer could be stale here:
		 *
		 * - A bkey_cmpxchg() operation could be trying to replace a key
		 *   that no longer exists. The new key, which can have some of
		 *   the same pointers as the old key, gets added here before
		 *   checking if the cmpxchg operation succeeds or not to avoid
		 *   another race.
		 *
		 *   If that's the case, we just bail out of the cmpxchg
		 *   operation early - a dirty pointer can only be stale if the
		 *   actual dirty pointer in the btree was overwritten.
		 *
		 *   And in that case we _have_ to bail out here instead of
		 *   letting bkey_cmpxchg() fail and undoing the accounting we
		 *   did here with subtract_sectors() (like we do otherwise),
		 *   because buckets going stale out from under us changes which
		 *   pointers we count as dirty.
		 *
		 * - Journal replay
		 *
		 *   A dirty pointer could be stale in journal replay if we
		 *   haven't finished journal replay - if it's going to get
		 *   overwritten again later in replay.
		 *
		 *   In that case, we don't want to fail the insert (just for
		 *   mental health) - but, since extent_normalize() drops stale
		 *   pointers, we need to count replicas in a way that's
		 *   invariant under normalize.
		 *
		 *   Fuck me, I hate my life.
		 */
		stale = bch_mark_data_bucket(c, ca, b, ptr, sectors, dirty);
		if (stale && dirty && fail_if_stale)
			goto stale;
	}
	rcu_read_unlock();

	return 0;
stale:
	while (--ptr >= e->v.ptr)
		if ((ca = PTR_CACHE(c, ptr)))
			bch_mark_data_bucket(c, ca, b, ptr, -sectors,
				bch_extent_ptr_is_dirty(c, e, ptr));
	rcu_read_unlock();

	return -1;
}

static int bch_add_sectors(struct btree *b, const struct bkey *k, u64 offset,
			   int sectors, bool fail_if_stale)
{
	if (sectors && k->type == BCH_EXTENT) {
		const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
		int ret;

		ret = __bch_add_sectors(b->c, b, e, offset,
					sectors, fail_if_stale);
		if (ret)
			return ret;

		if (!EXTENT_CACHED(&e->v))
			bcache_dev_sectors_dirty_add(b->c, e->k.p.inode,
						     offset, sectors);
	}

	return 0;
}

static void bch_subtract_sectors(struct btree *b, struct bkey *k,
				 u64 offset, int sectors)
{
	bch_add_sectors(b, k, offset, -sectors, false);
}

/* These wrappers subtract exactly the sectors that we're removing from @k */
static void bch_cut_subtract_back(struct btree *b, struct bpos where,
				  struct bkey *k)
{
	bch_subtract_sectors(b, k, where.offset,
			     k->p.offset - where.offset);
	bch_cut_back(where, k);
}

static void bch_cut_subtract_front(struct btree *b, struct bpos where,
				   struct bkey *k)
{
	bch_subtract_sectors(b, k, bkey_start_offset(k),
			     where.offset - bkey_start_offset(k));
	bch_cut_front(where, k);
}

static void bch_drop_subtract(struct btree *b, struct bkey *k)
{
	if (k->size)
		bch_subtract_sectors(b, k, bkey_start_offset(k), k->size);
	k->size = 0;
	__set_bkey_deleted(k);
}

/*
 * Note: If this returns true because only some pointers matched,
 * we can lose some caching that had happened in the interim.
 * Because cache promotion only promotes the part of the extent
 * actually read, and not the whole extent, and due to the key
 * splitting done in bch_extent_insert_fixup, preserving such
 * caching is difficult.
 */
static bool bkey_cmpxchg_cmp(const struct bkey *l, const struct bkey *r)
{
	const struct bkey_i_extent *le, *re;
	s64 offset;
	unsigned i;

	BUG_ON(!l->size || !r->size);

	if (l->type != r->type ||
	    l->version != r->version)
		return false;

	switch (l->type) {
	case KEY_TYPE_COOKIE:
		return !memcmp(&bkey_i_to_cookie_c(l)->v,
			       &bkey_i_to_cookie_c(r)->v,
			       sizeof(struct bch_cookie));

	case BCH_EXTENT:
		le = bkey_i_to_extent_c(l);
		re = bkey_i_to_extent_c(r);

		/*
		 * bkey_cmpxchg() handles partial matches - when either l or r
		 * has been trimmed - so we need just to handle l or r not
		 * starting at the same place when checking for a match here.
		 *
		 * If the starts of the keys are different, we just apply that
		 * offset to the device pointer offsets when checking those -
		 * matching how bch_cut_front() adjusts device pointer offsets
		 * when adjusting the start of a key:
		 */
		offset = bkey_start_offset(l) - bkey_start_offset(r);

		if (bch_extent_ptrs(le) == bch_extent_ptrs(re)) {
			for (i = 0; i < bch_extent_ptrs(le); i++)
				if (le->v.ptr[i]._val !=
				    re->v.ptr[i]._val +
				    (offset << PTR_OFFSET_OFFSET))
					goto try_partial;

			return true;
		}

try_partial:
#if (0)
		unsigned j;

		/*
		 * Maybe we just raced with copygc or tiering replacing one of
		 * the pointers: it should suffice to find _any_ matching
		 * pointer:
		 */
		for (i = 0; i < bch_extent_ptrs(l); i++)
			for (j = 0; j < bch_extent_ptrs(r); j++)
				if (le->v.ptr[i]._val !=
				    re->v.ptr[i]._val +
				    (offset << PTR_OFFSET_OFFSET))
					return true;
#endif
		return false;
	default:
		return false;
	}

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
			 struct bpos *done,
			 bool *inserted,
			 struct journal_res *res)
{
	bool ret;
	struct bkey *old = &replace->key;

	/* must have something to compare against */
	BUG_ON(!bkey_val_u64s(old));
	BUG_ON(b->level);

	/* new must be a subset of old */
	BUG_ON(bkey_cmp(new->p, old->p) > 0 ||
	       bkey_cmp(bkey_start_pos(new), bkey_start_pos(old)) < 0);

	/* if an exact match was requested, those are simple: */
	if (replace->replace_exact) {
		ret = (k->u64s == old->u64s &&
		       !memcmp(k, old, bkey_bytes(old)));

		if (ret)
			replace->successes += 1;
		else
			replace->failures += 1;

		*done = new->p;
		return ret;
	}

	/*
	 * first, check if there was a hole - part of the new key that we
	 * haven't checked against any existing key
	 */
	if (bkey_cmp(bkey_start_pos(k), *done) > 0) {
		/* insert previous partial match: */
		if (bkey_cmp(*done, bkey_start_pos(new)) > 0) {
			replace->successes += 1;

			/*
			 * [ prev key ]
			 *                 [ k        ]
			 *         [**|   new      ]
			 *            ^
			 *            |
			 *            +-- done
			 *
			 * The [**] are already known to match, so insert them.
			 */
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(*done, new),
						     res);
			*inserted = true;
		}

		bch_cut_subtract_front(b, bkey_start_pos(k), new);
		/* advance @done from the end of prev key to the start of @k */
		*done = bkey_start_pos(k);
	}

	ret = bkey_cmpxchg_cmp(k, old);
	if (!ret) {
		/* failed: */
		replace->failures += 1;

		if (bkey_cmp(*done, bkey_start_pos(new)) > 0) {
			/*
			 * [ prev key ]
			 *             [ k        ]
			 *    [*******| new              ]
			 *            ^
			 *            |
			 *            +-- done
			 *
			 * The [**] are already known to match, so insert them.
			 */
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(*done, new),
						     res);
			*inserted = true;
		}

		/* update @new to be the part we haven't checked yet */
		if (bkey_cmp(k->p, new->p) > 0)
			bch_drop_subtract(b, new);
		else
			bch_cut_subtract_front(b, k->p, new);
	} else
		replace->successes += 1;

	/* advance @done past the part of @k overlapping @new */
	*done = bkey_cmp(k->p, new->p) < 0 ? k->p : new->p;
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
	struct bkey *split;

	/* k is the key currently in the tree, 'insert' the new key */

	switch (bch_extent_overlap(k, insert)) {
	case BCH_EXTENT_OVERLAP_FRONT:
		/* k and insert share the start, remove it from insert */
		bch_cut_subtract_front(b, k->p, insert);
		break;

	case BCH_EXTENT_OVERLAP_BACK:
		/* k and insert share the end, remove it from insert */
		bch_cut_subtract_back(b, bkey_start_pos(k), insert);
		break;

	case BCH_EXTENT_OVERLAP_MIDDLE:
		/*
		 * We have an overlap where @k (newer version) splits
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
		split = bch_key_split(bkey_start_pos(k), insert),
		bch_cut_subtract_front(b, k->p, insert);
		bch_btree_insert_and_journal(b, iter, split, res);
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
	if (!bkey_deleted(k))
		b->keys.nr_live_keys -= k->u64s;

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
		k->p.offset = bkey_start_offset(insert);

	bch_btree_node_iter_next_all(iter);
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
 * bkey_start_pos(bkey_next(k)) >= k
 * or bkey_start_offset(bkey_next(k)) >= k->offset
 *
 * i.e. strict ordering, no overlapping extents.
 *
 * multiple bsets (i.e. full btree node):
 *
 * ∀ k, j
 *   KEY_SIZE(k) != 0 ∧ KEY_SIZE(j) != 0 →
 *     ¬ (k > bkey_start_pos(j) ∧ k < j)
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
			     struct bpos *done,
			     struct journal_res *res)
{
	struct bkey *k, *split;
	struct bpos orig_insert = insert->p;
	bool inserted = false;

	BUG_ON(!insert->size);

	/*
	 * The end of this key is the range processed so far.
	 *
	 * At the start, we add bucket sector counts for the entirely of the
	 * new insert, then we subtract sector counts for existing keys or
	 * parts of the new key as necessary.
	 *
	 * All sector counts up to @done are finalized.
	 */
	*done = bkey_start_pos(insert);

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
	if (bch_add_sectors(b, insert, bkey_start_offset(insert),
			    insert->size, replace != NULL)) {
		/* We raced - a dirty pointer was stale */
		*done = insert->p;
		insert->size = 0;
		if (replace != NULL)
			replace->failures += 1;
		return false;
	}

	while (insert->size &&
	       (k = bch_btree_node_iter_peek_overlapping(iter, insert))) {
		/*
		 * Before setting @done, we first check if we have space for
		 * the insert in the btree node and journal reservation.
		 *
		 * Each insert checks for room in the journal entry, but we
		 * check for room in the btree node up-front. In the worst
		 * case, bkey_cmpxchg() will insert two keys, and one
		 * iteration of this room will insert one key, so we need
		 * room for three keys.
		 */
		bool needs_split = (bch_btree_keys_u64s_remaining(&b->keys) <
				    BKEY_EXTENT_MAX_U64s * 3);
		bool res_full = journal_res_full(res, insert);

		if (needs_split || res_full) {
			/*
			 * XXX: would be better to explicitly signal that we
			 * need to split
			 */
			bch_cut_subtract_back(b, *done, insert);
			goto out;
		}

		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for replace
		 * operations.
		 */
		if (replace == NULL)
			*done = bkey_cmp(k->p, insert->p) < 0
				? k->p : insert->p;
		else if (k->size &&
			 !bkey_cmpxchg(b, iter, k, replace, insert, done,
				       &inserted, res))
			continue;

		if (k->size && !bkey_deleted(insert) &&
		    insert->version < k->version) {
			handle_existing_key_newer(b, iter, insert, k,
						  &inserted, res);
			continue;
		}

		/* k is the key currently in the tree, 'insert' the new key */

		switch (bch_extent_overlap(insert, k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			/* insert and k share the start, invalidate in k */
			bch_cut_subtract_front(b, insert->p, k);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			/* insert and k share the end, invalidate in k */
			bch_cut_subtract_back(b, bkey_start_pos(insert), k);
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
			split = bch_key_split(bkey_start_pos(insert), k);
			bch_cut_subtract_front(b, insert->p, k);
			bch_bset_insert(&b->keys, iter, split);
			break;
		}
	}

	/* Was there a hole? */
	if (bkey_cmp(*done, insert->p) < 0) {
		/*
		 * Holes not allowed for cmpxchg operations, so chop off
		 * whatever we're not inserting (but done needs to reflect what
		 * we've processed, i.e. what insert was)
		 */
		if (replace != NULL)
			bch_cut_subtract_back(b, *done, insert);

		*done = orig_insert;
	}

out:
	if (insert->size) {
		bch_btree_insert_and_journal(b, iter, insert, res);
		inserted = true;
	}

	return inserted;
}

bool __bch_extent_invalid(const struct cache_set *c, const const struct bkey *k)
{
	return (k->size > k->p.offset ||
		__ptr_invalid(c, k));
}

static bool bch_extent_invalid(const struct btree_keys *bk,
			       const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return __bch_extent_invalid(b->c, k);
}

static void bch_extent_debugcheck(struct btree_keys *bk, const struct bkey *k)
{
	struct btree *b = container_of(bk, struct btree, keys);
	const struct bkey_i_extent *e;
	const struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	struct cache_set *c = b->c;
	struct cache *ca;
	struct bucket *g;
	unsigned seq, stale;
	char buf[80];
	bool bad;
	unsigned ptrs_per_tier[CACHE_TIERS];
	unsigned i, dev, tier, replicas;

	memset(ptrs_per_tier, 0, sizeof(ptrs_per_tier));

	if (__bch_extent_invalid(c, k)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		cache_set_bug(c, "invalid bkey %s", buf);
		return;
	}

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
	case KEY_TYPE_COOKIE:
		return;
	case BCH_EXTENT:
		e = bkey_i_to_extent_c(k);
		break;
	default:
		cache_set_bug(c, "invalid extent type %u", k->type);
		return;
	}

	if (bch_extent_ptrs(e) < bch_extent_replicas_needed(c, e)) {
		bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
		cache_set_bug(c, "extent key bad (too few replicas): %s", buf);
		return;
	}

	mi = cache_member_info_get(c);

	extent_for_each_ptr(e, ptr) {
		bool dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		dev = PTR_DEV(ptr);

		/* Could be a special pointer such as PTR_CHECK_DEV */
		if (dev >= mi->nr_in_set) {
			if (dev != PTR_LOST_DEV)
				goto bad_device;

			continue;
		}

		tier = CACHE_TIER(&mi->m[dev]);
		ptrs_per_tier[tier]++;

		stale = 0;

		if ((ca = PTR_CACHE(c, ptr))) {
			g = PTR_BUCKET(ca, ptr);

			do {
				struct bucket_mark mark;

				seq = read_seqbegin(&c->gc_cur_lock);
				mark = READ_ONCE(g->mark);

				/* between mark and bucket gen */
				smp_rmb();

				stale = ptr_stale(ca, ptr);

				cache_set_bug_on(stale && dirty, c,
						 "stale dirty pointer");

				cache_set_bug_on(stale > 96, c,
						 "key too stale: %i",
						 stale);

				bad = (!stale &&
				       !__gc_will_visit_node(c, b) &&
				       (mark.is_metadata ||
					(!mark.dirty_sectors &&
					 !mark.owned_by_allocator &&
					 dirty)));
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto bad_ptr;
		}
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

	cache_member_info_put();
	return;

bad_device:
	bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %u device missing: %s",
		      (unsigned) (ptr - e->v.ptr), buf);
	cache_member_info_put();
	return;

bad_ptr:
	bch_bkey_val_to_text(bk, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %u bad gc mark: %s:\nbucket %zu prio %i "
		      "gen %i last_gc %i mark 0x%08x",
		      (unsigned) (ptr - e->v.ptr), buf, PTR_BUCKET_NR(ca, ptr),
		      g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		      g->oldest_gen, g->mark.counter);
	cache_member_info_put();
	return;
}

static unsigned PTR_TIER(struct cache_member_rcu *mi,
			 const struct bch_extent *e,
			 unsigned ptr)
{
	unsigned dev = PTR_DEV(&e->ptr[ptr]);

	return dev < mi->nr_in_set ? CACHE_TIER(&mi->m[dev]) : UINT_MAX;
}

bool bch_extent_normalize(struct cache_set *c, struct bkey *k)
{
	struct bkey_i_extent *e;
	struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	unsigned i;
	bool swapped, have_data = false;

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		break;

	case KEY_TYPE_COOKIE:
		set_bkey_deleted(k);
		break;

	case BCH_EXTENT:
		e = bkey_i_to_extent(k);

		if (!e->k.size) {
			set_bkey_deleted(&e->k);
			return true;
		}

		bch_extent_drop_stale(c, &e->k);

		mi = cache_member_info_get(c);

		/* Bubble sort pointers by tier, lowest (fastest) tier first */
		do {
			swapped = false;
			for (i = 0; i + 1 < bch_extent_ptrs(e); i++) {
				if (PTR_TIER(mi, &e->v, i) >
				    PTR_TIER(mi, &e->v, i + 1)) {
					swap(e->v.ptr[i], e->v.ptr[i + 1]);
					swapped = true;
				}
			}
		} while (swapped);

		cache_member_info_put();

		extent_for_each_ptr(e, ptr)
			if (PTR_DEV(ptr) != PTR_LOST_DEV)
				have_data = true;

		if (!have_data)
			bch_set_extent_ptrs(e, 0);

		if (!bch_extent_ptrs(e))
			k->type = EXTENT_CACHED(&e->v)
				? KEY_TYPE_DELETED
				: KEY_TYPE_ERROR;

		break;
	default:
		BUG();
	}

	return bkey_deleted(k);
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
					   const struct bch_extent_ptr **ptr,
					   struct cache *avoid)
{
	const struct bkey_i_extent *e;
	const struct bch_extent_ptr *i;
	struct cache *ca, *picked = NULL;

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_COOKIE:
		return NULL;

	case KEY_TYPE_ERROR:
		return ERR_PTR(-EIO);

	case BCH_EXTENT:
		/*
		 * Note: If DEV is PTR_LOST_DEV, PTR_CACHE returns NULL so if
		 * there are no other pointers, we'll return ERR_PTR(-EIO).
		 */
		e = bkey_i_to_extent_c(k);
		rcu_read_lock();

		extent_for_each_online_device(c, e, i, ca)
			if (!ptr_stale(ca, i)) {
				picked = ca;
				*ptr = i;
				if (ca != avoid)
					break;
			}

		if (picked != NULL) {
			percpu_ref_get(&picked->ref);
			rcu_read_unlock();
			return picked;
		}

		rcu_read_unlock();

		/* data missing that's not supposed to be? */
		return EXTENT_CACHED(&e->v)
			? NULL
			: ERR_PTR(-EIO);

	default:
		BUG();
	}
}

#if 0
static uint64_t merge_chksums(struct bkey *l, struct bkey *r)
{
	return (l->val[bch_extent_ptrs(l)] + r->val[bch_extent_ptrs(r)]) &
		~((uint64_t)1 << 63);
}
#endif

static bool bch_extent_merge(struct btree_keys *bk, struct bkey *l, struct bkey *r)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct bkey_i_extent *el;
	struct bkey_i_extent *er;
	struct cache *ca;
	unsigned i;

	if (key_merging_disabled(b->c))
		return false;

	/*
	 * Generic header checks
	 * Assumes left and right are in order
	 * Left and right must be exactly aligned
	 */

	if (l->u64s	!= r->u64s ||
	    l->type	!= r->type ||
	    l->version	!= r->version ||
	    bkey_cmp(l->p, bkey_start_pos(r)))
		return false;

	switch (l->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		/* These types are mergeable, and no val to check */
		break;

	case BCH_EXTENT:
		el = bkey_i_to_extent(l);
		er = bkey_i_to_extent(r);

		for (i = 0; i < bch_extent_ptrs(el); i++) {
			/*
			 * compare all the pointer fields at once, adding the
			 * size to the left pointer's offset:
			 */
			if (el->v.ptr[i]._val + PTR(0, el->k.size, 0)._val !=
			    er->v.ptr[i]._val)
				return false;

			/*
			 * we don't allow extent pointers to straddle buckets -
			 * if the device is offline, we don't know the bucket
			 * size so we can't check
			 */
			rcu_read_lock();
			if (!(ca = PTR_CACHE(b->c, &el->v.ptr[i])) ||
			    PTR_BUCKET_NR(ca, &el->v.ptr[i]) !=
			    PTR_BUCKET_NR(ca, &er->v.ptr[i])) {
				rcu_read_unlock();
				return false;
			}
			rcu_read_unlock();
		}

		break;
	default:
		return false;
	}

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if ((u64) l->size + r->size > KEY_SIZE_MAX) {
		bch_key_resize(l, KEY_SIZE_MAX);
		bch_cut_front(l->p, r);
		return false;
	}
#if 0
	if (KEY_CSUM(l)) {
		if (KEY_CSUM(r))
			l->val[bch_extent_ptrs(l)] = merge_chksums(l, r);
		else
			SET_KEY_CSUM(l, 0);
	}
#endif
	bch_key_resize(l, l->size + r->size);

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

	bkey_debugcheck(bk, k);
}
