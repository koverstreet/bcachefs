
#include "bcache.h"
#include "btree.h"
#include "gc.h"
#include "keybuf.h"

#include <trace/events/bcachefs.h>

/*
 * For buffered iteration over the btree, with predicates and ratelimiting and
 * whatnot
 */

static inline int keybuf_cmp(struct keybuf_key *l, struct keybuf_key *r)
{
	/* Overlapping keys compare equal */
	if (bkey_cmp(&l->key, &START_KEY(&r->key)) <= 0)
		return -1;
	if (bkey_cmp(&START_KEY(&l->key), &r->key) >= 0)
		return 1;
	return 0;
}

static inline int keybuf_nonoverlapping_cmp(struct keybuf_key *l,
					    struct keybuf_key *r)
{
	return clamp_t(s64, bkey_cmp(&l->key, &r->key), -1, 1);
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bkey *end, keybuf_pred_fn *pred)
{
	struct bkey start = buf->last_scanned;
	struct btree_iter iter;
	const struct bkey *k;
	unsigned nr_found = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, &buf->last_scanned, k) {
		if (bkey_cmp(k, end) >= 0) {
			buf->last_scanned = *k;
			goto done;
		}

		if (pred(buf, k)) {
			struct keybuf_key *w;

			spin_lock(&buf->lock);

			w = array_alloc(&buf->freelist);
			if (!w) {
				spin_unlock(&buf->lock);
				goto done;
			}

			bkey_copy(&w->key, k);
			atomic_set(&w->ref, -1); /* -1 means hasn't started */

			if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
				array_free(&buf->freelist, w);
			else
				nr_found++;

			spin_unlock(&buf->lock);
		}

		buf->last_scanned = *k;
		bch_btree_iter_cond_resched(&iter);
	}

	/* If we end up here, it means:
	 * - the map_fn didn't fill up the keybuf
	 * - the map_fn didn't see the end key
	 * - there were no more keys to map over
	 * Therefore, we are at the end of the key space */
	buf->last_scanned = MAX_KEY;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_keyscan(nr_found,
			     KEY_INODE(&start), KEY_OFFSET(&start),
			     KEY_INODE(&buf->last_scanned),
			     KEY_OFFSET(&buf->last_scanned));

	spin_lock(&buf->lock);

	if (!RB_EMPTY_ROOT(&buf->keys)) {
		struct keybuf_key *w;

		w = RB_FIRST(&buf->keys, struct keybuf_key, node);
		buf->start	= START_KEY(&w->key);

		w = RB_LAST(&buf->keys, struct keybuf_key, node);
		buf->end	= w->key;
	} else {
		buf->start	= MAX_KEY;
		buf->end	= MAX_KEY;
	}

	spin_unlock(&buf->lock);
}

static void bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	rb_erase(&w->node, &buf->keys);
	array_free(&buf->freelist, w);
}

void bch_keybuf_put(struct keybuf *buf, struct keybuf_key *w)
{
	BUG_ON(atomic_read(&w->ref) <= 0);

	if (atomic_dec_and_test(&w->ref)) {
		up(&buf->in_flight);

		spin_lock(&buf->lock);
		bch_keybuf_del(buf, w);
		spin_unlock(&buf->lock);
	}
}

/**
 * bch_mark_keybuf_keys - update oldest generation pointer into a bucket
 *
 * This prevents us from wrapping around gens for a bucket only referenced from
 * the writeback keybufs. We don't actually care that the data in those buckets
 * is marked live, only that we don't wrap the gens.
 */
void bch_mark_keybuf_keys(struct cache_set *c, struct keybuf *buf)
{
	struct keybuf_key *w, *n;

	spin_lock(&buf->lock);
	rcu_read_lock();
	rbtree_postorder_for_each_entry_safe(w, n,
				&buf->keys, node)
		bch_btree_mark_last_gc(c, &w->key);
	rcu_read_unlock();
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bkey *start,
				  struct bkey *end)
{
	bool ret = false;
	struct keybuf_key *w, *next, s = { .key = *start };

	if (bkey_cmp(end, &buf->start) <= 0 ||
	    bkey_cmp(start, &buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);

	for (w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);
	     w && bkey_cmp(&START_KEY(&w->key), end) < 0;
	     w = next) {
		next = RB_NEXT(w, node);

		if (atomic_read(&w->ref) == -1)
			bch_keybuf_del(buf, w);
		else
			ret = true;
	}

	spin_unlock(&buf->lock);
	return ret;
}

struct keybuf_key *bch_keybuf_next(struct keybuf *buf)
{
	struct keybuf_key *w;

	spin_lock(&buf->lock);

	w = RB_FIRST(&buf->keys, struct keybuf_key, node);

	while (w && atomic_read(&w->ref) != -1)
		w = RB_NEXT(w, node);

	if (!w) {
		spin_unlock(&buf->lock);
		return NULL;
	}

	atomic_set(&w->ref, 1);
	spin_unlock(&buf->lock);

	down(&buf->in_flight);

	return w;
}

struct keybuf_key *bch_keybuf_next_rescan(struct cache_set *c,
					  struct keybuf *buf,
					  struct bkey *end,
					  keybuf_pred_fn *pred)
{
	struct keybuf_key *ret;

	while (1) {
		ret = bch_keybuf_next(buf);
		if (ret)
			break;

		if (bkey_cmp(&buf->last_scanned, end) >= 0) {
			pr_debug("scan finished");
			break;
		}

		bch_refill_keybuf(c, buf, end, pred);
	}

	return ret;
}

void bch_keybuf_init(struct keybuf *buf)
{
	sema_init(&buf->in_flight, BTREE_SCAN_BATCH / 2);

	buf->last_scanned	= MAX_KEY;
	buf->keys		= RB_ROOT;

	spin_lock_init(&buf->lock);
	array_allocator_init(&buf->freelist);
}
