// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "replicas.h"
#include "trace.h"

#include <linux/sort.h>

/* Inserting into a given leaf node (last stage of insert): */

/* Handle overwrites and do insert, for non extents: */
bool bch2_btree_bset_insert_key(struct btree_iter *iter,
				struct btree *b,
				struct btree_node_iter *node_iter,
				struct bkey_i *insert)
{
	const struct bkey_format *f = &b->format;
	struct bkey_packed *k;
	unsigned clobber_u64s;

	EBUG_ON(btree_node_just_written(b));
	EBUG_ON(bset_written(b, btree_bset_last(b)));
	EBUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	EBUG_ON(bkey_cmp(bkey_start_pos(&insert->k), b->data->min_key) < 0 ||
		bkey_cmp(insert->k.p, b->data->max_key) > 0);

	k = bch2_btree_node_iter_peek_all(node_iter, b);
	if (k && !bkey_cmp_packed(b, k, &insert->k)) {
		BUG_ON(bkey_whiteout(k));

		if (!bkey_written(b, k) &&
		    bkey_val_u64s(&insert->k) == bkeyp_val_u64s(f, k) &&
		    !bkey_whiteout(&insert->k)) {
			k->type = insert->k.type;
			memcpy_u64s(bkeyp_val(f, k), &insert->v,
				    bkey_val_u64s(&insert->k));
			return true;
		}

		insert->k.needs_whiteout = k->needs_whiteout;

		btree_account_key_drop(b, k);

		if (k >= btree_bset_last(b)->start) {
			clobber_u64s = k->u64s;

			/*
			 * If we're deleting, and the key we're deleting doesn't
			 * need a whiteout (it wasn't overwriting a key that had
			 * been written to disk) - just delete it:
			 */
			if (bkey_whiteout(&insert->k) && !k->needs_whiteout) {
				bch2_bset_delete(b, k, clobber_u64s);
				bch2_btree_node_iter_fix(iter, b, node_iter,
							 k, clobber_u64s, 0);
				bch2_btree_iter_verify(iter, b);
				return true;
			}

			goto overwrite;
		}

		k->type = KEY_TYPE_deleted;
		bch2_btree_node_iter_fix(iter, b, node_iter, k,
					 k->u64s, k->u64s);
		bch2_btree_iter_verify(iter, b);

		if (bkey_whiteout(&insert->k)) {
			reserve_whiteout(b, k);
			return true;
		} else {
			k->needs_whiteout = false;
		}
	} else {
		/*
		 * Deleting, but the key to delete wasn't found - nothing to do:
		 */
		if (bkey_whiteout(&insert->k))
			return false;

		insert->k.needs_whiteout = false;
	}

	k = bch2_btree_node_iter_bset_pos(node_iter, b, bset_tree_last(b));
	clobber_u64s = 0;
overwrite:
	bch2_bset_insert(b, node_iter, k, insert, clobber_u64s);
	if (k->u64s != clobber_u64s || bkey_whiteout(&insert->k))
		bch2_btree_node_iter_fix(iter, b, node_iter, k,
					 clobber_u64s, k->u64s);
	bch2_btree_iter_verify(iter, b);
	return true;
}

static void __btree_node_flush(struct journal *j, struct journal_entry_pin *pin,
			       unsigned i, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[i]);

	btree_node_lock_type(c, b, SIX_LOCK_read);
	bch2_btree_node_write_cond(c, b,
		(btree_current_write(b) == w && w->journal.seq == seq));
	six_unlock_read(&b->lock);
}

static void btree_node_flush0(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 0, seq);
}

static void btree_node_flush1(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 1, seq);
}

static inline void __btree_journal_key(struct btree_insert *trans,
				       enum btree_id btree_id,
				       struct bkey_i *insert)
{
	struct journal *j = &trans->c->journal;
	u64 seq = trans->journal_res.seq;
	bool needs_whiteout = insert->k.needs_whiteout;

	/* ick */
	insert->k.needs_whiteout = false;
	bch2_journal_add_keys(j, &trans->journal_res,
			      btree_id, insert);
	insert->k.needs_whiteout = needs_whiteout;

	bch2_journal_set_has_inode(j, &trans->journal_res,
				   insert->k.p.inode);

	if (trans->journal_seq)
		*trans->journal_seq = seq;
}

void bch2_btree_journal_key(struct btree_insert *trans,
			   struct btree_iter *iter,
			   struct bkey_i *insert)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct btree *b = iter->l[0].b;
	struct btree_write *w = btree_current_write(b);

	EBUG_ON(iter->level || b->level);
	EBUG_ON(trans->journal_res.ref !=
		!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY));

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		__btree_journal_key(trans, iter->btree_id, insert);
		btree_bset_last(b)->journal_seq =
			cpu_to_le64(trans->journal_res.seq);
	}

	if (unlikely(!journal_pin_active(&w->journal))) {
		u64 seq = likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))
			? trans->journal_res.seq
			: j->replay_journal_seq;

		bch2_journal_pin_add(j, seq, &w->journal,
				     btree_node_write_idx(b) == 0
				     ? btree_node_flush0
				     : btree_node_flush1);
	}

	if (unlikely(!btree_node_dirty(b)))
		set_btree_node_dirty(b);
}

static enum btree_insert_ret
bch2_insert_fixup_key(struct btree_insert *trans,
		     struct btree_insert_entry *insert)
{
	struct btree_iter *iter = insert->iter;
	struct btree_iter_level *l = &iter->l[0];

	EBUG_ON(iter->level);
	EBUG_ON(insert->k->k.u64s >
		bch_btree_keys_u64s_remaining(trans->c, l->b));

	if (bch2_btree_bset_insert_key(iter, l->b, &l->iter,
				       insert->k))
		bch2_btree_journal_key(trans, iter, insert->k);

	return BTREE_INSERT_OK;
}

/**
 * btree_insert_key - insert a key one key into a leaf node
 */
static enum btree_insert_ret
btree_insert_key_leaf(struct btree_insert *trans,
		      struct btree_insert_entry *insert)
{
	struct bch_fs *c = trans->c;
	struct btree_iter *iter = insert->iter;
	struct btree *b = iter->l[0].b;
	enum btree_insert_ret ret;
	int old_u64s = le16_to_cpu(btree_bset_last(b)->u64s);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

	bch2_mark_update(trans, insert);

	ret = !btree_node_is_extents(b)
		? bch2_insert_fixup_key(trans, insert)
		: bch2_insert_fixup_extent(trans, insert);

	live_u64s_added = (int) b->nr.live_u64s - old_live_u64s;
	u64s_added = (int) le16_to_cpu(btree_bset_last(b)->u64s) - old_u64s;

	if (b->sib_u64s[0] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[0] = max(0, (int) b->sib_u64s[0] + live_u64s_added);
	if (b->sib_u64s[1] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[1] = max(0, (int) b->sib_u64s[1] + live_u64s_added);

	if (u64s_added > live_u64s_added &&
	    bch2_maybe_compact_whiteouts(c, b))
		bch2_btree_iter_reinit_node(iter, b);

	trace_btree_insert_key(c, b, insert->k);
	return ret;
}

/* Deferred btree updates: */

static void deferred_update_flush(struct journal *j,
					struct journal_entry_pin *pin,
					u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct deferred_update *d =
		container_of(pin, struct deferred_update, journal);
	u64 tmp[32];
	struct bkey_i *k = (void *) tmp;
	unsigned gen;
	int ret;

	if (d->allocated_u64s > ARRAY_SIZE(tmp)) {
		k = kmalloc(d->allocated_u64s * sizeof(u64), GFP_NOFS);

		BUG_ON(!k); /* XXX */
	}

	spin_lock(&d->lock);
	gen = d->gen;

	if (journal_pin_active(&d->journal)) {
		BUG_ON(d->k.k.u64s > d->allocated_u64s);
		bkey_copy(k, &d->k);

		spin_unlock(&d->lock);

		ret = bch2_btree_insert(c, d->btree_id, k, NULL, NULL,
					BTREE_INSERT_NOFAIL);
		bch2_fs_fatal_err_on(ret && !bch2_journal_error(j),
			c, "error flushing deferred btree update: %i", ret);

		spin_lock(&d->lock);
	}

	if (gen == d->gen)
		bch2_journal_pin_drop(j, &d->journal);
	spin_unlock(&d->lock);

	if (k != (void *) tmp)
		kfree(k);
}

static enum btree_insert_ret
btree_insert_key_deferred(struct btree_insert *trans,
			  struct btree_insert_entry *insert)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct deferred_update *d = insert->d;

	BUG_ON(trans->flags & BTREE_INSERT_JOURNAL_REPLAY);
	BUG_ON(insert->k->u64s > d->allocated_u64s);

	__btree_journal_key(trans, d->btree_id, insert->k);

	spin_lock(&d->lock);
	d->gen++;
	bkey_copy(&d->k, insert->k);
	spin_unlock(&d->lock);

	bch2_journal_pin_update(j, trans->journal_res.seq, &d->journal,
				deferred_update_flush);

	return BTREE_INSERT_OK;
}

void bch2_deferred_update_free(struct bch_fs *c,
			       struct deferred_update *d)
{
	deferred_update_flush(&c->journal, &d->journal, 0);

	BUG_ON(journal_pin_active(&d->journal));

	bch2_journal_pin_flush(&c->journal, &d->journal);
	kfree(d);
}

struct deferred_update *
bch2_deferred_update_alloc(struct bch_fs *c,
			   enum btree_id btree_id,
			   unsigned u64s)
{
	struct deferred_update *d;

	BUG_ON(u64s > U8_MAX);

	d = kmalloc(offsetof(struct deferred_update, k) +
		    u64s * sizeof(u64), GFP_NOFS);
	BUG_ON(!d);

	memset(d, 0, offsetof(struct deferred_update, k));

	spin_lock_init(&d->lock);
	d->allocated_u64s	= u64s;
	d->btree_id		= btree_id;

	return d;
}

/* struct btree_insert operations: */

/*
 * We sort transaction entries so that if multiple iterators point to the same
 * leaf node they'll be adjacent:
 */
static bool same_leaf_as_prev(struct btree_insert *trans,
			      struct btree_insert_entry *i)
{
	return i != trans->entries &&
		!i->deferred &&
		i[0].iter->l[0].b == i[-1].iter->l[0].b;
}

#define __trans_next_entry(_trans, _i, _filter)				\
({									\
	while ((_i) < (_trans)->entries + (_trans->nr) && !(_filter))	\
		(_i)++;							\
									\
	(_i) < (_trans)->entries + (_trans->nr);			\
})

#define __trans_for_each_entry(_trans, _i, _filter)			\
	for ((_i) = (_trans)->entries;					\
	     __trans_next_entry(_trans, _i, _filter);			\
	     (_i)++)

#define trans_for_each_entry(trans, i)					\
	__trans_for_each_entry(trans, i, true)

#define trans_for_each_iter(trans, i)					\
	__trans_for_each_entry(trans, i, !(i)->deferred)

#define trans_for_each_leaf(trans, i)					\
	__trans_for_each_entry(trans, i, !(i)->deferred &&		\
			       !same_leaf_as_prev(trans, i))

inline void bch2_btree_node_lock_for_insert(struct bch_fs *c, struct btree *b,
					    struct btree_iter *iter)
{
	bch2_btree_node_lock_write(b, iter);

	if (btree_node_just_written(b) &&
	    bch2_btree_post_write_cleanup(c, b))
		bch2_btree_iter_reinit_node(iter, b);

	/*
	 * If the last bset has been written, or if it's gotten too big - start
	 * a new bset to insert into:
	 */
	if (want_new_bset(c, b))
		bch2_btree_init_next(c, b, iter);
}

static void multi_lock_write(struct bch_fs *c, struct btree_insert *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_leaf(trans, i)
		bch2_btree_node_lock_for_insert(c, i->iter->l[0].b, i->iter);
}

static void multi_unlock_write(struct btree_insert *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_leaf(trans, i)
		bch2_btree_node_unlock_write(i->iter->l[0].b, i->iter);
}

static inline int btree_trans_cmp(struct btree_insert_entry l,
				  struct btree_insert_entry r)
{
	return (l.deferred > r.deferred) - (l.deferred < r.deferred) ?:
		btree_iter_cmp(l.iter, r.iter);
}

/* Normal update interface: */

static enum btree_insert_ret
btree_key_can_insert(struct btree_insert *trans,
		     struct btree_insert_entry *insert,
		     unsigned *u64s)
{
	struct bch_fs *c = trans->c;
	struct btree *b = insert->iter->l[0].b;
	static enum btree_insert_ret ret;

	if (unlikely(btree_node_fake(b)))
		return BTREE_INSERT_BTREE_NODE_FULL;

	if (!bch2_bkey_replicas_marked(c,
			bkey_i_to_s_c(insert->k),
			true))
		return BTREE_INSERT_NEED_MARK_REPLICAS;

	ret = !btree_node_is_extents(b)
		? BTREE_INSERT_OK
		: bch2_extent_can_insert(trans, insert, u64s);
	if (ret)
		return ret;

	if (*u64s > bch_btree_keys_u64s_remaining(c, b))
		return BTREE_INSERT_BTREE_NODE_FULL;

	return BTREE_INSERT_OK;
}

static inline enum btree_insert_ret
do_btree_insert_one(struct btree_insert *trans,
		    struct btree_insert_entry *insert)
{
	return likely(!insert->deferred)
		? btree_insert_key_leaf(trans, insert)
		: btree_insert_key_deferred(trans, insert);
}

/*
 * Get journal reservation, take write locks, and attempt to do btree update(s):
 */
static inline int do_btree_insert_at(struct btree_insert *trans,
				     struct btree_insert_entry **stopped_at)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;
	struct btree_iter *linked;
	unsigned u64s;
	int ret;

	trans_for_each_iter(trans, i)
		BUG_ON(i->iter->uptodate >= BTREE_ITER_NEED_RELOCK);

	/* reserve space for deferred updates */
	__trans_for_each_entry(trans, i, i->deferred) {

	}

	memset(&trans->journal_res, 0, sizeof(trans->journal_res));

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		u64s = 0;
		trans_for_each_entry(trans, i)
			u64s += jset_u64s(i->k->k.u64s);

		while ((ret = bch2_journal_res_get(&c->journal,
					&trans->journal_res, u64s,
					JOURNAL_RES_GET_NONBLOCK)) == -EAGAIN) {
			struct btree_iter *iter = NULL;

			trans_for_each_iter(trans, i)
				iter = i->iter;

			if (iter)
				bch2_btree_iter_unlock(iter);

			ret = bch2_journal_res_get(&c->journal,
					&trans->journal_res, u64s,
					JOURNAL_RES_GET_CHECK);
			if (ret)
				return ret;

			if (iter && !bch2_btree_iter_relock(iter)) {
				trans_restart(" (iter relock after journal res get blocked)");
				return -EINTR;
			}
		}

		if (ret)
			return ret;
	}

	multi_lock_write(c, trans);

	if (race_fault()) {
		ret = -EINTR;
		trans_restart(" (race)");
		goto out;
	}

	/*
	 * Check if the insert will fit in the leaf node with the write lock
	 * held, otherwise another thread could write the node changing the
	 * amount of space available:
	 */
	u64s = 0;
	trans_for_each_iter(trans, i) {
		/* Multiple inserts might go to same leaf: */
		if (!same_leaf_as_prev(trans, i))
			u64s = 0;

		u64s += i->k->k.u64s;
		ret = btree_key_can_insert(trans, i, &u64s);
		if (ret) {
			*stopped_at = i;
			goto out;
		}
	}

	if (!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)) {
		if (journal_seq_verify(c))
			trans_for_each_entry(trans, i)
				i->k->k.version.lo = trans->journal_res.seq;
		else if (inject_invalid_keys(c))
			trans_for_each_entry(trans, i)
				i->k->k.version = MAX_VERSION;
	}

	if (trans->flags & BTREE_INSERT_NOUNLOCK) {
		/*
		 * linked iterators that weren't being updated may or may not
		 * have been traversed/locked, depending on what the caller was
		 * doing:
		 */
		trans_for_each_iter(trans, i) {
			for_each_btree_iter(i->iter, linked)
				if (linked->uptodate < BTREE_ITER_NEED_RELOCK)
					linked->flags |= BTREE_ITER_NOUNLOCK;
			break;
		}
	}
	trans->did_work = true;

	trans_for_each_entry(trans, i) {
		switch (do_btree_insert_one(trans, i)) {
		case BTREE_INSERT_OK:
			break;
		case BTREE_INSERT_NEED_TRAVERSE:
			BUG_ON((trans->flags &
				(BTREE_INSERT_ATOMIC|BTREE_INSERT_NOUNLOCK)));
			ret = -EINTR;
			goto out;
		default:
			BUG();
		}
	}
out:
	multi_unlock_write(trans);
	bch2_journal_res_put(&c->journal, &trans->journal_res);

	return ret;
}

static inline void btree_insert_entry_checks(struct bch_fs *c,
					     struct btree_insert_entry *i)
{
	enum btree_id btree_id = !i->deferred
		? i->iter->btree_id
		: i->d->btree_id;

	if (!i->deferred) {
		BUG_ON(i->iter->level);
		BUG_ON(bkey_cmp(bkey_start_pos(&i->k->k), i->iter->pos));

		bch2_btree_iter_verify_locks(i->iter);
	}

	BUG_ON(debug_check_bkeys(c) &&
	       !bkey_deleted(&i->k->k) &&
	       bch2_bkey_invalid(c, bkey_i_to_s_c(i->k), btree_id));
}

/**
 * __bch_btree_insert_at - insert keys at given iterator positions
 *
 * This is main entry point for btree updates.
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again. Only returned
 *  if passed BTREE_INSERT_ATOMIC.
 * -EROFS: filesystem read only
 * -EIO: journal or btree node IO error
 */
int __bch2_btree_insert_at(struct btree_insert *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;
	struct btree_iter *linked;
	unsigned flags;
	int ret;

	BUG_ON(!trans->nr);

	/* for the sake of sanity: */
	BUG_ON(trans->nr > 1 && !(trans->flags & BTREE_INSERT_ATOMIC));

	bubble_sort(trans->entries, trans->nr, btree_trans_cmp);

	trans_for_each_entry(trans, i)
		btree_insert_entry_checks(c, i);

	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return -EROFS;
retry:
	trans_for_each_iter(trans, i) {
		unsigned old_locks_want = i->iter->locks_want;
		unsigned old_uptodate = i->iter->uptodate;

		if (!bch2_btree_iter_upgrade(i->iter, 1, true)) {
			trans_restart(" (failed upgrade, locks_want %u uptodate %u)",
				      old_locks_want, old_uptodate);
			ret = -EINTR;
			goto err;
		}

		if (i->iter->flags & BTREE_ITER_ERROR) {
			ret = -EIO;
			goto err;
		}
	}

	ret = do_btree_insert_at(trans, &i);
	if (unlikely(ret))
		goto err;

	trans_for_each_leaf(trans, i)
		bch2_foreground_maybe_merge(c, i->iter, 0, trans->flags);

	trans_for_each_iter(trans, i)
		bch2_btree_iter_downgrade(i->iter);
out:
	percpu_ref_put(&c->writes);

	/* make sure we didn't drop or screw up locks: */
	trans_for_each_iter(trans, i) {
		bch2_btree_iter_verify_locks(i->iter);
		break;
	}

	trans_for_each_iter(trans, i) {
		for_each_btree_iter(i->iter, linked)
			linked->flags &= ~BTREE_ITER_NOUNLOCK;
		break;
	}

	BUG_ON(!(trans->flags & BTREE_INSERT_ATOMIC) && ret == -EINTR);

	return ret;
err:
	flags = trans->flags;

	/*
	 * BTREE_INSERT_NOUNLOCK means don't unlock _after_ successful btree
	 * update; if we haven't done anything yet it doesn't apply
	 */
	if (!trans->did_work)
		flags &= ~BTREE_INSERT_NOUNLOCK;

	switch (ret) {
	case BTREE_INSERT_BTREE_NODE_FULL:
		ret = bch2_btree_split_leaf(c, i->iter, flags);

		/*
		 * if the split succeeded without dropping locks the insert will
		 * still be atomic (in the BTREE_INSERT_ATOMIC sense, what the
		 * caller peeked() and is overwriting won't have changed)
		 */
#if 0
		/*
		 * XXX:
		 * split -> btree node merging (of parent node) might still drop
		 * locks when we're not passing it BTREE_INSERT_NOUNLOCK
		 */
		if (!ret && !trans->did_work)
			goto retry;
#endif

		/*
		 * don't care if we got ENOSPC because we told split it
		 * couldn't block:
		 */
		if (!ret || (flags & BTREE_INSERT_NOUNLOCK)) {
			trans_restart(" (split)");
			ret = -EINTR;
		}
		break;
	case BTREE_INSERT_NEED_GC_LOCK:
		ret = -EINTR;

		if (!down_read_trylock(&c->gc_lock)) {
			if (flags & BTREE_INSERT_NOUNLOCK)
				goto out;

			bch2_btree_iter_unlock(trans->entries[0].iter);
			down_read(&c->gc_lock);
		}
		up_read(&c->gc_lock);
		break;
	case BTREE_INSERT_ENOSPC:
		ret = -ENOSPC;
		break;
	case BTREE_INSERT_NEED_MARK_REPLICAS:
		if (flags & BTREE_INSERT_NOUNLOCK) {
			ret = -EINTR;
			goto out;
		}

		bch2_btree_iter_unlock(trans->entries[0].iter);
		ret = bch2_mark_bkey_replicas(c, bkey_i_to_s_c(i->k))
			?: -EINTR;
		break;
	default:
		BUG_ON(ret >= 0);
		break;
	}

	if (ret == -EINTR) {
		if (flags & BTREE_INSERT_NOUNLOCK) {
			trans_restart(" (can't unlock)");
			goto out;
		}

		trans_for_each_iter(trans, i) {
			int ret2 = bch2_btree_iter_traverse(i->iter);
			if (ret2) {
				ret = ret2;
				trans_restart(" (traverse)");
				goto out;
			}

			BUG_ON(i->iter->uptodate > BTREE_ITER_NEED_PEEK);
		}

		/*
		 * BTREE_ITER_ATOMIC means we have to return -EINTR if we
		 * dropped locks:
		 */
		if (!(flags & BTREE_INSERT_ATOMIC))
			goto retry;

		trans_restart(" (atomic)");
	}

	goto out;
}

int bch2_trans_commit(struct btree_trans *trans,
		      struct disk_reservation *disk_res,
		      u64 *journal_seq,
		      unsigned flags)
{
	struct btree_insert insert = {
		.c		= trans->c,
		.disk_res	= disk_res,
		.journal_seq	= journal_seq,
		.flags		= flags,
		.nr		= trans->nr_updates,
		.entries	= trans->updates,
	};

	if (!trans->nr_updates)
		return 0;

	trans->nr_updates = 0;

	return __bch2_btree_insert_at(&insert);
}

int bch2_btree_delete_at(struct btree_iter *iter, unsigned flags)
{
	struct bkey_i k;

	bkey_init(&k.k);
	k.k.p = iter->pos;

	return bch2_btree_insert_at(iter->c, NULL, NULL,
				    BTREE_INSERT_NOFAIL|
				    BTREE_INSERT_USE_RESERVE|flags,
				    BTREE_INSERT_ENTRY(iter, &k));
}

int bch2_btree_insert_list_at(struct btree_iter *iter,
			     struct keylist *keys,
			     struct disk_reservation *disk_res,
			     u64 *journal_seq, unsigned flags)
{
	BUG_ON(flags & BTREE_INSERT_ATOMIC);
	BUG_ON(bch2_keylist_empty(keys));
	bch2_verify_keylist_sorted(keys);

	while (!bch2_keylist_empty(keys)) {
		int ret = bch2_btree_insert_at(iter->c, disk_res,
				journal_seq, flags,
				BTREE_INSERT_ENTRY(iter, bch2_keylist_front(keys)));
		if (ret)
			return ret;

		bch2_keylist_pop_front(keys);
	}

	return 0;
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct bch_fs
 * @id:			btree to insert into
 * @insert_keys:	list of keys to insert
 * @hook:		insert callback
 */
int bch2_btree_insert(struct bch_fs *c, enum btree_id id,
		     struct bkey_i *k,
		     struct disk_reservation *disk_res,
		     u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	int ret;

	bch2_btree_iter_init(&iter, c, id, bkey_start_pos(&k->k),
			     BTREE_ITER_INTENT);
	ret = bch2_btree_insert_at(c, disk_res, journal_seq, flags,
				   BTREE_INSERT_ENTRY(&iter, k));
	bch2_btree_iter_unlock(&iter);

	return ret;
}

/*
 * bch_btree_delete_range - delete everything within a given range
 *
 * Range is a half open interval - [start, end)
 */
int bch2_btree_delete_range(struct bch_fs *c, enum btree_id id,
			    struct bpos start, struct bpos end,
			    u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch2_btree_iter_init(&iter, c, id, start,
			     BTREE_ITER_INTENT);

	while ((k = bch2_btree_iter_peek(&iter)).k &&
	       !(ret = btree_iter_err(k)) &&
	       bkey_cmp(iter.pos, end) < 0) {
		unsigned max_sectors = KEY_SIZE_MAX & (~0 << c->block_bits);
		/* really shouldn't be using a bare, unpadded bkey_i */
		struct bkey_i delete;

		bkey_init(&delete.k);

		/*
		 * For extents, iter.pos won't necessarily be the same as
		 * bkey_start_pos(k.k) (for non extents they always will be the
		 * same). It's important that we delete starting from iter.pos
		 * because the range we want to delete could start in the middle
		 * of k.
		 *
		 * (bch2_btree_iter_peek() does guarantee that iter.pos >=
		 * bkey_start_pos(k.k)).
		 */
		delete.k.p = iter.pos;

		if (iter.flags & BTREE_ITER_IS_EXTENTS) {
			/* create the biggest key we can */
			bch2_key_resize(&delete.k, max_sectors);
			bch2_cut_back(end, &delete.k);
		}

		ret = bch2_btree_insert_at(c, NULL, journal_seq,
					   BTREE_INSERT_NOFAIL,
					   BTREE_INSERT_ENTRY(&iter, &delete));
		if (ret)
			break;

		bch2_btree_iter_cond_resched(&iter);
	}

	bch2_btree_iter_unlock(&iter);
	return ret;
}
