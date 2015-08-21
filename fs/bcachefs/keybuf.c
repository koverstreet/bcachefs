
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

	if (!k)
		k = &KEY(KEY_INODE(&b->key), KEY_OFFSET(&b->key), 0);

	if (bkey_cmp(k, refill->end) >= 0) {
		ret = MAP_DONE;
		goto out;
	}

	if (!KEY_SIZE(k)) /* end key */
		goto out;

	if (refill->pred(buf, k)) {
		struct keybuf_key *w;

		spin_lock(&buf->lock);

		w = array_alloc(&buf->freelist);
		if (!w) {
			spin_unlock(&buf->lock);
			return MAP_DONE;
		}

		w->private = NULL;
		bkey_copy(&w->key, k);

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

	cond_resched();

	bch_btree_op_init(&refill.op, -1);
	refill.nr_found	= 0;
	refill.buf	= buf;
	refill.end	= end;
	refill.pred	= pred;

	bch_btree_map_keys(&refill.op, c, BTREE_ID_EXTENTS,
			   &buf->last_scanned, refill_keybuf_fn, MAP_END_KEY);

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

static void __bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	if (w->private)
		up(&buf->in_flight);

	rb_erase(&w->node, &buf->keys);
	array_free(&buf->freelist, w);
}

void bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	spin_lock(&buf->lock);
	__bch_keybuf_del(buf, w);
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bkey *start,
				  struct bkey *end)
{
	bool ret = false;
	struct keybuf_key *p, *w, s = { .key = *start };

	if (bkey_cmp(end, &buf->start) <= 0 ||
	    bkey_cmp(start, &buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);
	w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);

	while (w && bkey_cmp(&START_KEY(&w->key), end) < 0) {
		p = w;
		w = RB_NEXT(w, node);

		if (p->private)
			ret = true;
		else
			__bch_keybuf_del(buf, p);
	}

	spin_unlock(&buf->lock);
	return ret;
}

struct keybuf_key *bch_keybuf_next(struct keybuf *buf)
{
	struct keybuf_key *w;

	spin_lock(&buf->lock);

	w = RB_FIRST(&buf->keys, struct keybuf_key, node);

	while (w && w->private)
		w = RB_NEXT(w, node);

	if (!w) {
		spin_unlock(&buf->lock);
		return NULL;
	}

	w->private = ERR_PTR(-EINTR);
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
