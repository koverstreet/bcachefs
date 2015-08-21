
#include "bcache.h"
#include "btree.h"
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

struct refill {
	struct btree_op	op;
	unsigned	nr_found;
	struct keybuf	*buf;
	struct bkey	*end;
	keybuf_pred_fn	*pred;
};

static int refill_keybuf_fn(struct btree_op *op, struct btree *b,
			    struct bkey *k)
{
	struct refill *refill = container_of(op, struct refill, op);
	struct keybuf *buf = refill->buf;
	int ret = MAP_CONTINUE;

	if (bkey_cmp(k, refill->end) >= 0) {
		ret = MAP_DONE;
		goto out;
	}

	if (refill->pred(buf, k)) {
		struct keybuf_key *w;

		spin_lock(&buf->lock);

		w = array_alloc(&buf->freelist);
		if (!w) {
			spin_unlock(&buf->lock);
			return MAP_DONE;
		}

		bkey_copy(&w->key, k);
		atomic_set(&w->ref, -1); /* -1 means hasn't started */

		if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
			array_free(&buf->freelist, w);
		else
			refill->nr_found++;

		if (array_freelist_empty(&buf->freelist))
			ret = MAP_DONE;

		spin_unlock(&buf->lock);
	}
out:
	buf->last_scanned = *k;
	return ret;
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bkey *end, keybuf_pred_fn *pred)
{
	struct bkey start = buf->last_scanned;
	struct refill refill;
	int ret;

	cond_resched();

	bch_btree_op_init(&refill.op, BTREE_ID_EXTENTS, -1);
	refill.nr_found	= 0;
	refill.buf	= buf;
	refill.end	= end;
	refill.pred	= pred;

	ret = bch_btree_map_keys(&refill.op, c,
				 &buf->last_scanned,
				 refill_keybuf_fn, 0);
	if (ret == MAP_CONTINUE) {
		/* If we end up here, it means:
		 * - the map_fn didn't fill up the keybuf
		 * - the map_fn didn't see the end key
		 * - there were no more keys to map over
		 * Therefore, we are at the end of the key space */
		buf->last_scanned = MAX_KEY;
	}

	trace_bcache_keyscan(refill.nr_found,
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
	sema_init(&buf->in_flight, KEYBUF_NR / 2);

	buf->last_scanned	= MAX_KEY;
	buf->keys		= RB_ROOT;

	spin_lock_init(&buf->lock);
	array_allocator_init(&buf->freelist);
}
