
#include "bcache.h"
#include "btree_gc.h"
#include "btree_iter.h"
#include "keybuf.h"

#include <trace/events/bcachefs.h>

/*
 * For buffered iteration over the btree, with predicates and ratelimiting and
 * whatnot
 */

static inline int keybuf_cmp(struct keybuf_key *l, struct keybuf_key *r)
{
	/* Overlapping keys compare equal */
	if (bkey_cmp(l->key.k.p, bkey_start_pos(&r->key.k)) <= 0)
		return -1;
	if (bkey_cmp(bkey_start_pos(&l->key.k), r->key.k.p) >= 0)
		return 1;
	return 0;
}

static inline int keybuf_nonoverlapping_cmp(struct keybuf_key *l,
					    struct keybuf_key *r)
{
	return clamp_t(s64, bkey_cmp(l->key.k.p, r->key.k.p), -1, 1);
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bpos end, keybuf_pred_fn *pred)
{
	struct bpos start = buf->last_scanned;
	struct btree_iter iter;
	struct bkey_s_c k;
	unsigned nr_found = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, buf->last_scanned, k) {
		if (bkey_cmp(k.k->p, end) >= 0) {
			buf->last_scanned = k.k->p;
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

			bkey_reassemble(&w->key, k);
			atomic_set(&w->ref, -1); /* -1 means hasn't started */

			if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
				array_free(&buf->freelist, w);
			else
				nr_found++;

			spin_unlock(&buf->lock);
		}

		buf->last_scanned = k.k->p;
		bch_btree_iter_cond_resched(&iter);
	}

	/* If we end up here, it means:
	 * - the map_fn didn't fill up the keybuf
	 * - the map_fn didn't see the end key
	 * - there were no more keys to map over
	 * Therefore, we are at the end of the key space */
	buf->last_scanned = POS_MAX;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_keyscan(nr_found,
			     start.inode, start.offset,
			     buf->last_scanned.inode,
			     buf->last_scanned.offset);

	spin_lock(&buf->lock);

	if (!RB_EMPTY_ROOT(&buf->keys)) {
		struct keybuf_key *w;

		w = RB_FIRST(&buf->keys, struct keybuf_key, node);
		buf->start	= bkey_start_pos(&w->key.k);

		w = RB_LAST(&buf->keys, struct keybuf_key, node);
		buf->end	= w->key.k.p;
	} else {
		buf->start	= POS_MAX;
		buf->end	= POS_MAX;
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

void bch_keybuf_recalc_oldest_gens(struct cache_set *c, struct keybuf *buf)
{
	struct keybuf_key *w, *n;

	spin_lock(&buf->lock);
	rbtree_postorder_for_each_entry_safe(w, n,
				&buf->keys, node)
		bch_btree_key_recalc_oldest_gen(c, bkey_i_to_s_c(&w->key));
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bpos start,
				  struct bpos end)
{
	bool ret = false;
	struct keybuf_key *w, *next, s = { .key.k.p = start };

	if (bkey_cmp(end, buf->start) <= 0 ||
	    bkey_cmp(start, buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);

	for (w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);
	     w && bkey_cmp(bkey_start_pos(&w->key.k), end) < 0;
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

void bch_keybuf_init(struct keybuf *buf)
{
	sema_init(&buf->in_flight, KEYBUF_REFILL_BATCH / 2);

	buf->last_scanned	= POS_MAX;
	buf->start		= POS_MIN;
	buf->end		= POS_MIN;

	buf->keys		= RB_ROOT;

	spin_lock_init(&buf->lock);
	array_allocator_init(&buf->freelist);
}
