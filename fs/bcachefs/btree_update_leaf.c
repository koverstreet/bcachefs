// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_gc.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_key_cache.h"
#include "btree_locking.h"
#include "buckets.h"
#include "debug.h"
#include "error.h"
#include "extent_update.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "subvolume.h"
#include "replicas.h"
#include "trace.h"

#include <linux/prefetch.h>
#include <linux/sort.h>

static inline int btree_insert_entry_cmp(const struct btree_insert_entry *l,
					 const struct btree_insert_entry *r)
{
	return   cmp_int(l->btree_id,	r->btree_id) ?:
		 -cmp_int(l->level,	r->level) ?:
		 bpos_cmp(l->k->k.p,	r->k->k.p);
}

static inline struct btree_path_level *insert_l(struct btree_insert_entry *i)
{
	return i->path->l + i->level;
}

static inline bool same_leaf_as_prev(struct btree_trans *trans,
				     struct btree_insert_entry *i)
{
	return i != trans->updates &&
		insert_l(&i[0])->b == insert_l(&i[-1])->b;
}

static inline bool same_leaf_as_next(struct btree_trans *trans,
				     struct btree_insert_entry *i)
{
	return i + 1 < trans->updates + trans->nr_updates &&
		insert_l(&i[0])->b == insert_l(&i[1])->b;
}

static inline void bch2_btree_node_prep_for_write(struct btree_trans *trans,
						  struct btree_path *path,
						  struct btree *b)
{
	struct bch_fs *c = trans->c;

	if (path->cached)
		return;

	if (unlikely(btree_node_just_written(b)) &&
	    bch2_btree_post_write_cleanup(c, b))
		bch2_trans_node_reinit_iter(trans, b);

	/*
	 * If the last bset has been written, or if it's gotten too big - start
	 * a new bset to insert into:
	 */
	if (want_new_bset(c, b))
		bch2_btree_init_next(trans, b);
}

void bch2_btree_node_lock_for_insert(struct btree_trans *trans,
				     struct btree_path *path,
				     struct btree *b)
{
	bch2_btree_node_lock_write(trans, path, b);
	bch2_btree_node_prep_for_write(trans, path, b);
}

/* Inserting into a given leaf node (last stage of insert): */

/* Handle overwrites and do insert, for non extents: */
bool bch2_btree_bset_insert_key(struct btree_trans *trans,
				struct btree_path *path,
				struct btree *b,
				struct btree_node_iter *node_iter,
				struct bkey_i *insert)
{
	struct bkey_packed *k;
	unsigned clobber_u64s = 0, new_u64s = 0;

	EBUG_ON(btree_node_just_written(b));
	EBUG_ON(bset_written(b, btree_bset_last(b)));
	EBUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	EBUG_ON(bpos_cmp(insert->k.p, b->data->min_key) < 0);
	EBUG_ON(bpos_cmp(insert->k.p, b->data->max_key) > 0);
	EBUG_ON(insert->k.u64s >
		bch_btree_keys_u64s_remaining(trans->c, b));

	k = bch2_btree_node_iter_peek_all(node_iter, b);
	if (k && bkey_cmp_left_packed(b, k, &insert->k.p))
		k = NULL;

	/* @k is the key being overwritten/deleted, if any: */
	EBUG_ON(k && bkey_deleted(k));

	/* Deleting, but not found? nothing to do: */
	if (bkey_deleted(&insert->k) && !k)
		return false;

	if (bkey_deleted(&insert->k)) {
		/* Deleting: */
		btree_account_key_drop(b, k);
		k->type = KEY_TYPE_deleted;

		if (k->needs_whiteout)
			push_whiteout(trans->c, b, insert->k.p);
		k->needs_whiteout = false;

		if (k >= btree_bset_last(b)->start) {
			clobber_u64s = k->u64s;
			bch2_bset_delete(b, k, clobber_u64s);
			goto fix_iter;
		} else {
			bch2_btree_path_fix_key_modified(trans, b, k);
		}

		return true;
	}

	if (k) {
		/* Overwriting: */
		btree_account_key_drop(b, k);
		k->type = KEY_TYPE_deleted;

		insert->k.needs_whiteout = k->needs_whiteout;
		k->needs_whiteout = false;

		if (k >= btree_bset_last(b)->start) {
			clobber_u64s = k->u64s;
			goto overwrite;
		} else {
			bch2_btree_path_fix_key_modified(trans, b, k);
		}
	}

	k = bch2_btree_node_iter_bset_pos(node_iter, b, bset_tree_last(b));
overwrite:
	bch2_bset_insert(b, node_iter, k, insert, clobber_u64s);
	new_u64s = k->u64s;
fix_iter:
	if (clobber_u64s != new_u64s)
		bch2_btree_node_iter_fix(trans, path, b, node_iter, k,
					 clobber_u64s, new_u64s);
	return true;
}

static int __btree_node_flush(struct journal *j, struct journal_entry_pin *pin,
			       unsigned i, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[i]);

	btree_node_lock_type(c, b, SIX_LOCK_read);
	bch2_btree_node_write_cond(c, b,
		(btree_current_write(b) == w && w->journal.seq == seq));
	six_unlock_read(&b->c.lock);
	return 0;
}

static int btree_node_flush0(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 0, seq);
}

static int btree_node_flush1(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 1, seq);
}

inline void bch2_btree_add_journal_pin(struct bch_fs *c,
				       struct btree *b, u64 seq)
{
	struct btree_write *w = btree_current_write(b);

	bch2_journal_pin_add(&c->journal, seq, &w->journal,
			     btree_node_write_idx(b) == 0
			     ? btree_node_flush0
			     : btree_node_flush1);
}

/**
 * btree_insert_key - insert a key one key into a leaf node
 */
static bool btree_insert_key_leaf(struct btree_trans *trans,
				  struct btree_insert_entry *insert)
{
	struct bch_fs *c = trans->c;
	struct btree *b = insert_l(insert)->b;
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = bset(b, t);
	int old_u64s = bset_u64s(t);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

	EBUG_ON(!insert->level &&
		!test_bit(BCH_FS_BTREE_INTERIOR_REPLAY_DONE, &c->flags));

	if (unlikely(!bch2_btree_bset_insert_key(trans, insert->path, b,
					&insert_l(insert)->iter, insert->k)))
		return false;

	i->journal_seq = cpu_to_le64(max(trans->journal_res.seq,
					 le64_to_cpu(i->journal_seq)));

	bch2_btree_add_journal_pin(c, b, trans->journal_res.seq);

	if (unlikely(!btree_node_dirty(b)))
		set_btree_node_dirty(c, b);

	live_u64s_added = (int) b->nr.live_u64s - old_live_u64s;
	u64s_added = (int) bset_u64s(t) - old_u64s;

	if (b->sib_u64s[0] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[0] = max(0, (int) b->sib_u64s[0] + live_u64s_added);
	if (b->sib_u64s[1] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[1] = max(0, (int) b->sib_u64s[1] + live_u64s_added);

	if (u64s_added > live_u64s_added &&
	    bch2_maybe_compact_whiteouts(c, b))
		bch2_trans_node_reinit_iter(trans, b);

	return true;
}

/* Cached btree updates: */

/* Normal update interface: */

static inline void btree_insert_entry_checks(struct btree_trans *trans,
					     struct btree_insert_entry *i)
{
	BUG_ON(bpos_cmp(i->k->k.p, i->path->pos));
	BUG_ON(i->cached	!= i->path->cached);
	BUG_ON(i->level		!= i->path->level);
	BUG_ON(i->btree_id	!= i->path->btree_id);
	EBUG_ON(!i->level &&
		!(i->flags & BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE) &&
		test_bit(JOURNAL_REPLAY_DONE, &trans->c->journal.flags) &&
		i->k->k.p.snapshot &&
		bch2_snapshot_internal_node(trans->c, i->k->k.p.snapshot));
}

static noinline int
bch2_trans_journal_preres_get_cold(struct btree_trans *trans, unsigned u64s,
				   unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	int ret;

	bch2_trans_unlock(trans);

	ret = bch2_journal_preres_get(&c->journal,
			&trans->journal_preres, u64s, 0);
	if (ret)
		return ret;

	if (!bch2_trans_relock(trans)) {
		trace_trans_restart_journal_preres_get(trans->ip, trace_ip);
		return -EINTR;
	}

	return 0;
}

static inline int bch2_trans_journal_res_get(struct btree_trans *trans,
					     unsigned flags)
{
	struct bch_fs *c = trans->c;
	int ret;

	if (trans->flags & BTREE_INSERT_JOURNAL_RESERVED)
		flags |= JOURNAL_RES_GET_RESERVED;

	ret = bch2_journal_res_get(&c->journal, &trans->journal_res,
				   trans->journal_u64s, flags);

	return ret == -EAGAIN ? BTREE_INSERT_NEED_JOURNAL_RES : ret;
}

static inline enum btree_insert_ret
btree_key_can_insert(struct btree_trans *trans,
		     struct btree *b,
		     unsigned u64s)
{
	struct bch_fs *c = trans->c;

	if (!bch2_btree_node_insert_fits(c, b, u64s))
		return BTREE_INSERT_BTREE_NODE_FULL;

	return BTREE_INSERT_OK;
}

static enum btree_insert_ret
btree_key_can_insert_cached(struct btree_trans *trans,
			    struct btree_path *path,
			    unsigned u64s)
{
	struct bkey_cached *ck = (void *) path->l[0].b;
	unsigned new_u64s;
	struct bkey_i *new_k;

	EBUG_ON(path->level);

	if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags) &&
	    bch2_btree_key_cache_must_wait(trans->c) &&
	    !(trans->flags & BTREE_INSERT_JOURNAL_RECLAIM))
		return BTREE_INSERT_NEED_JOURNAL_RECLAIM;

	/*
	 * bch2_varint_decode can read past the end of the buffer by at most 7
	 * bytes (it won't be used):
	 */
	u64s += 1;

	if (u64s <= ck->u64s)
		return BTREE_INSERT_OK;

	new_u64s	= roundup_pow_of_two(u64s);
	new_k		= krealloc(ck->k, new_u64s * sizeof(u64), GFP_NOFS);
	if (!new_k)
		return -ENOMEM;

	ck->u64s	= new_u64s;
	ck->k		= new_k;
	return BTREE_INSERT_OK;
}

static inline void do_btree_insert_one(struct btree_trans *trans,
				       struct btree_insert_entry *i)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	bool did_work;

	EBUG_ON(trans->journal_res.ref !=
		!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY));

	i->k->k.needs_whiteout = false;

	did_work = !i->cached
		? btree_insert_key_leaf(trans, i)
		: bch2_btree_insert_key_cached(trans, i->path, i->k);
	if (!did_work)
		return;

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		bch2_journal_add_keys(j, &trans->journal_res,
				      i->btree_id,
				      i->level,
				      i->k);

		bch2_journal_set_has_inode(j, &trans->journal_res,
					   i->k->k.p.inode);

		if (trans->journal_seq)
			*trans->journal_seq = trans->journal_res.seq;
	}
}

static noinline void bch2_trans_mark_gc(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;

	trans_for_each_update(trans, i) {
		/*
		 * XXX: synchronization of cached update triggers with gc
		 * XXX: synchronization of interior node updates with gc
		 */
		BUG_ON(i->cached || i->level);

		if (gc_visited(c, gc_pos_btree_node(insert_l(i)->b)))
			bch2_mark_update(trans, i->path, i->k,
					 i->flags|BTREE_TRIGGER_GC);
	}
}

static inline int
bch2_trans_commit_write_locked(struct btree_trans *trans,
			       struct btree_insert_entry **stopped_at,
			       unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;
	struct btree_trans_commit_hook *h;
	unsigned u64s = 0;
	bool marking = false;
	int ret;

	if (race_fault()) {
		trace_trans_restart_fault_inject(trans->ip, trace_ip);
		trans->restarted = true;
		return -EINTR;
	}

	/*
	 * Check if the insert will fit in the leaf node with the write lock
	 * held, otherwise another thread could write the node changing the
	 * amount of space available:
	 */

	prefetch(&trans->c->journal.flags);

	h = trans->hooks;
	while (h) {
		ret = h->fn(trans, h);
		if (ret)
			return ret;
		h = h->next;
	}

	trans_for_each_update(trans, i) {
		/* Multiple inserts might go to same leaf: */
		if (!same_leaf_as_prev(trans, i))
			u64s = 0;

		u64s += i->k->k.u64s;
		ret = !i->cached
			? btree_key_can_insert(trans, insert_l(i)->b, u64s)
			: btree_key_can_insert_cached(trans, i->path, u64s);
		if (ret) {
			*stopped_at = i;
			return ret;
		}

		if (btree_node_type_needs_gc(i->bkey_type))
			marking = true;
	}

	if (marking) {
		percpu_down_read(&c->mark_lock);
	}

	/* Must be called under mark_lock: */
	if (marking && trans->fs_usage_deltas &&
	    !bch2_replicas_delta_list_marked(c, trans->fs_usage_deltas)) {
		ret = BTREE_INSERT_NEED_MARK_REPLICAS;
		goto err;
	}

	/*
	 * Don't get journal reservation until after we know insert will
	 * succeed:
	 */
	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		ret = bch2_trans_journal_res_get(trans,
				JOURNAL_RES_GET_NONBLOCK);
		if (ret)
			goto err;
	} else {
		trans->journal_res.seq = c->journal.replay_journal_seq;
	}

	if (unlikely(trans->extra_journal_entry_u64s)) {
		memcpy_u64s_small(journal_res_entry(&c->journal, &trans->journal_res),
				  trans->extra_journal_entries,
				  trans->extra_journal_entry_u64s);

		trans->journal_res.offset	+= trans->extra_journal_entry_u64s;
		trans->journal_res.u64s		-= trans->extra_journal_entry_u64s;
	}

	/*
	 * Not allowed to fail after we've gotten our journal reservation - we
	 * have to use it:
	 */

	if (!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)) {
		if (bch2_journal_seq_verify)
			trans_for_each_update(trans, i)
				i->k->k.version.lo = trans->journal_res.seq;
		else if (bch2_inject_invalid_keys)
			trans_for_each_update(trans, i)
				i->k->k.version = MAX_VERSION;
	}

	trans_for_each_update(trans, i)
		if (BTREE_NODE_TYPE_HAS_MEM_TRIGGERS & (1U << i->bkey_type))
			bch2_mark_update(trans, i->path, i->k, i->flags);

	if (marking && trans->fs_usage_deltas)
		bch2_trans_fs_usage_apply(trans, trans->fs_usage_deltas);

	if (unlikely(c->gc_pos.phase))
		bch2_trans_mark_gc(trans);

	trans_for_each_update(trans, i)
		do_btree_insert_one(trans, i);
err:
	if (marking) {
		percpu_up_read(&c->mark_lock);
	}

	return ret;
}

static inline void upgrade_readers(struct btree_trans *trans, struct btree_path *path)
{
	struct btree *b = path_l(path)->b;

	do {
		if (path->nodes_locked &&
		    path->nodes_locked != path->nodes_intent_locked)
			BUG_ON(!bch2_btree_path_upgrade(trans, path, path->level + 1));
	} while ((path = prev_btree_path(trans, path)) &&
		 path_l(path)->b == b);
}

/*
 * Check for nodes that we have both read and intent locks on, and upgrade the
 * readers to intent:
 */
static inline void normalize_read_intent_locks(struct btree_trans *trans)
{
	struct btree_path *path;
	unsigned i, nr_read = 0, nr_intent = 0;

	trans_for_each_path_inorder(trans, path, i) {
		struct btree_path *next = i + 1 < trans->nr_sorted
			? trans->paths + trans->sorted[i + 1]
			: NULL;

		if (path->nodes_locked) {
			if (path->nodes_intent_locked)
				nr_intent++;
			else
				nr_read++;
		}

		if (!next || path_l(path)->b != path_l(next)->b) {
			if (nr_read && nr_intent)
				upgrade_readers(trans, path);

			nr_read = nr_intent = 0;
		}
	}

	bch2_trans_verify_locks(trans);
}

static inline bool have_conflicting_read_lock(struct btree_trans *trans, struct btree_path *pos)
{
	struct btree_path *path;
	unsigned i;

	trans_for_each_path_inorder(trans, path, i) {
		//if (path == pos)
		//	break;

		if (path->nodes_locked != path->nodes_intent_locked)
			return true;
	}

	return false;
}

static inline int trans_lock_write(struct btree_trans *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_update(trans, i) {
		if (same_leaf_as_prev(trans, i))
			continue;

		if (!six_trylock_write(&insert_l(i)->b->c.lock)) {
			if (have_conflicting_read_lock(trans, i->path))
				goto fail;

			__btree_node_lock_type(trans->c, insert_l(i)->b,
					       SIX_LOCK_write);
		}

		bch2_btree_node_prep_for_write(trans, i->path, insert_l(i)->b);
	}

	return 0;
fail:
	while (--i >= trans->updates) {
		if (same_leaf_as_prev(trans, i))
			continue;

		bch2_btree_node_unlock_write_inlined(trans, i->path, insert_l(i)->b);
	}

	trace_trans_restart_would_deadlock_write(trans->ip);
	return btree_trans_restart(trans);
}

/*
 * Get journal reservation, take write locks, and attempt to do btree update(s):
 */
static inline int do_bch2_trans_commit(struct btree_trans *trans,
				       struct btree_insert_entry **stopped_at,
				       unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;
	struct bkey_s_c old;
	int ret, u64s_delta = 0;

	trans_for_each_update(trans, i) {
		const char *invalid = bch2_bkey_invalid(c,
				bkey_i_to_s_c(i->k), i->bkey_type);
		if (invalid) {
			char buf[200];

			bch2_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(i->k));
			bch_err(c, "invalid bkey %s on insert from %ps -> %ps: %s\n",
				buf, (void *) trans->ip,
				(void *) i->ip_allocated, invalid);
			bch2_fatal_error(c);
			return -EINVAL;
		}
		btree_insert_entry_checks(trans, i);
	}

	trans_for_each_update(trans, i) {
		struct bkey u;

		/*
		 * peek_slot() doesn't yet work on iterators that point to
		 * interior nodes:
		 */
		if (i->cached || i->level)
			continue;

		old = bch2_btree_path_peek_slot(i->path, &u);
		ret = bkey_err(old);
		if (unlikely(ret))
			return ret;

		u64s_delta += !bkey_deleted(&i->k->k) ? i->k->k.u64s : 0;
		u64s_delta -= !bkey_deleted(old.k) ? old.k->u64s : 0;

		if (!same_leaf_as_next(trans, i)) {
			if (u64s_delta <= 0) {
				ret = bch2_foreground_maybe_merge(trans, i->path,
							i->level, trans->flags);
				if (unlikely(ret))
					return ret;
			}

			u64s_delta = 0;
		}
	}

	ret = bch2_journal_preres_get(&c->journal,
			&trans->journal_preres, trans->journal_preres_u64s,
			JOURNAL_RES_GET_NONBLOCK|
			((trans->flags & BTREE_INSERT_JOURNAL_RESERVED)
			 ? JOURNAL_RES_GET_RESERVED : 0));
	if (unlikely(ret == -EAGAIN))
		ret = bch2_trans_journal_preres_get_cold(trans,
						trans->journal_preres_u64s, trace_ip);
	if (unlikely(ret))
		return ret;

	normalize_read_intent_locks(trans);

	ret = trans_lock_write(trans);
	if (unlikely(ret))
		return ret;

	ret = bch2_trans_commit_write_locked(trans, stopped_at, trace_ip);

	trans_for_each_update(trans, i)
		if (!same_leaf_as_prev(trans, i))
			bch2_btree_node_unlock_write_inlined(trans, i->path,
							insert_l(i)->b);

	if (!ret && trans->journal_pin)
		bch2_journal_pin_add(&c->journal, trans->journal_res.seq,
				     trans->journal_pin, NULL);

	/*
	 * Drop journal reservation after dropping write locks, since dropping
	 * the journal reservation may kick off a journal write:
	 */
	bch2_journal_res_put(&c->journal, &trans->journal_res);

	if (unlikely(ret))
		return ret;

	bch2_trans_downgrade(trans);

	return 0;
}

static int journal_reclaim_wait_done(struct bch_fs *c)
{
	int ret = bch2_journal_error(&c->journal) ?:
		!bch2_btree_key_cache_must_wait(c);

	if (!ret)
		journal_reclaim_kick(&c->journal);
	return ret;
}

static noinline
int bch2_trans_commit_error(struct btree_trans *trans,
			    struct btree_insert_entry *i,
			    int ret, unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;

	switch (ret) {
	case BTREE_INSERT_BTREE_NODE_FULL:
		ret = bch2_btree_split_leaf(trans, i->path, trans->flags);
		if (!ret)
			return 0;

		if (ret == -EINTR)
			trace_trans_restart_btree_node_split(trans->ip, trace_ip,
						i->btree_id, &i->path->pos);
		break;
	case BTREE_INSERT_NEED_MARK_REPLICAS:
		bch2_trans_unlock(trans);

		ret = bch2_replicas_delta_list_mark(c, trans->fs_usage_deltas);
		if (ret)
			break;

		if (bch2_trans_relock(trans))
			return 0;

		trace_trans_restart_mark_replicas(trans->ip, trace_ip);
		ret = -EINTR;
		break;
	case BTREE_INSERT_NEED_JOURNAL_RES:
		bch2_trans_unlock(trans);

		if ((trans->flags & BTREE_INSERT_JOURNAL_RECLAIM) &&
		    !(trans->flags & BTREE_INSERT_JOURNAL_RESERVED)) {
			trans->restarted = true;
			ret = -EAGAIN;
			break;
		}

		ret = bch2_trans_journal_res_get(trans, JOURNAL_RES_GET_CHECK);
		if (ret)
			break;

		if (bch2_trans_relock(trans))
			return 0;

		trace_trans_restart_journal_res_get(trans->ip, trace_ip);
		ret = -EINTR;
		break;
	case BTREE_INSERT_NEED_JOURNAL_RECLAIM:
		bch2_trans_unlock(trans);

		trace_trans_blocked_journal_reclaim(trans->ip, trace_ip);

		wait_event_freezable(c->journal.reclaim_wait,
				     (ret = journal_reclaim_wait_done(c)));
		if (ret < 0)
			break;

		if (bch2_trans_relock(trans))
			return 0;

		trace_trans_restart_journal_reclaim(trans->ip, trace_ip);
		ret = -EINTR;
		break;
	default:
		BUG_ON(ret >= 0);
		break;
	}

	BUG_ON((ret == EINTR || ret == -EAGAIN) && !trans->restarted);
	BUG_ON(ret == -ENOSPC && (trans->flags & BTREE_INSERT_NOFAIL));

	return ret;
}

static noinline int
bch2_trans_commit_get_rw_cold(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	int ret;

	if (likely(!(trans->flags & BTREE_INSERT_LAZY_RW)))
		return -EROFS;

	bch2_trans_unlock(trans);

	ret = bch2_fs_read_write_early(c);
	if (ret)
		return ret;

	if (!bch2_trans_relock(trans))
		return -EINTR;

	percpu_ref_get(&c->writes);
	return 0;
}

int __bch2_trans_commit(struct btree_trans *trans)
{
	struct btree_insert_entry *i = NULL;
	bool trans_trigger_run;
	unsigned u64s;
	int ret = 0;

	if (!trans->nr_updates &&
	    !trans->extra_journal_entry_u64s)
		goto out_reset;

	if (trans->flags & BTREE_INSERT_GC_LOCK_HELD)
		lockdep_assert_held(&trans->c->gc_lock);

	memset(&trans->journal_preres, 0, sizeof(trans->journal_preres));

	trans->journal_u64s		= trans->extra_journal_entry_u64s;
	trans->journal_preres_u64s	= 0;

	if (!(trans->flags & BTREE_INSERT_NOCHECK_RW) &&
	    unlikely(!percpu_ref_tryget(&trans->c->writes))) {
		ret = bch2_trans_commit_get_rw_cold(trans);
		if (ret)
			goto out_reset;
	}

#ifdef CONFIG_BCACHEFS_DEBUG
	/*
	 * if BTREE_TRIGGER_NORUN is set, it means we're probably being called
	 * from the key cache flush code:
	 */
	trans_for_each_update(trans, i)
		if (!i->cached &&
		    !(i->flags & BTREE_TRIGGER_NORUN))
			bch2_btree_key_cache_verify_clean(trans,
					i->btree_id, i->k->k.p);
#endif

	/*
	 * Running triggers will append more updates to the list of updates as
	 * we're walking it:
	 */
	do {
		trans_trigger_run = false;

		trans_for_each_update(trans, i) {
			if ((BTREE_NODE_TYPE_HAS_TRANS_TRIGGERS & (1U << i->bkey_type)) &&
			    !i->trans_triggers_run) {
				i->trans_triggers_run = true;
				trans_trigger_run = true;

				ret = bch2_trans_mark_update(trans, i->path,
							     i->k, i->flags);
				if (unlikely(ret)) {
					if (ret == -EINTR)
						trace_trans_restart_mark(trans->ip, _RET_IP_,
								i->btree_id, &i->path->pos);
					goto out;
				}
			}
		}
	} while (trans_trigger_run);

	trans_for_each_update(trans, i) {
		BUG_ON(!i->path->should_be_locked);

		if (unlikely(!bch2_btree_path_upgrade(trans, i->path, i->level + 1))) {
			trace_trans_restart_upgrade(trans->ip, _RET_IP_,
						    i->btree_id, &i->path->pos);
			ret = btree_trans_restart(trans);
			goto out;
		}

		BUG_ON(!btree_node_intent_locked(i->path, i->level));

		u64s = jset_u64s(i->k->k.u64s);
		if (i->cached &&
		    likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)))
			trans->journal_preres_u64s += u64s;
		trans->journal_u64s += u64s;
	}

	if (trans->extra_journal_res) {
		ret = bch2_disk_reservation_add(trans->c, trans->disk_res,
				trans->extra_journal_res,
				(trans->flags & BTREE_INSERT_NOFAIL)
				? BCH_DISK_RESERVATION_NOFAIL : 0);
		if (ret)
			goto err;
	}
retry:
	BUG_ON(trans->restarted);
	memset(&trans->journal_res, 0, sizeof(trans->journal_res));

	ret = do_bch2_trans_commit(trans, &i, _RET_IP_);

	/* make sure we didn't drop or screw up locks: */
	bch2_trans_verify_locks(trans);

	if (ret)
		goto err;
out:
	bch2_journal_preres_put(&trans->c->journal, &trans->journal_preres);

	if (likely(!(trans->flags & BTREE_INSERT_NOCHECK_RW)))
		percpu_ref_put(&trans->c->writes);
out_reset:
	trans_for_each_update(trans, i)
		bch2_path_put(trans, i->path, true);

	trans->extra_journal_res	= 0;
	trans->nr_updates		= 0;
	trans->hooks			= NULL;
	trans->extra_journal_entries	= NULL;
	trans->extra_journal_entry_u64s	= 0;

	if (trans->fs_usage_deltas) {
		trans->fs_usage_deltas->used = 0;
		memset((void *) trans->fs_usage_deltas +
		       offsetof(struct replicas_delta_list, memset_start), 0,
		       (void *) &trans->fs_usage_deltas->memset_end -
		       (void *) &trans->fs_usage_deltas->memset_start);
	}

	return ret;
err:
	ret = bch2_trans_commit_error(trans, i, ret, _RET_IP_);
	if (ret)
		goto out;

	goto retry;
}

static noinline int extent_front_merge(struct btree_trans *trans,
				       struct btree_iter *iter,
				       struct bkey_s_c k,
				       struct bkey_i **insert,
				       enum btree_update_flags flags)
{
	struct bch_fs *c = trans->c;
	struct bkey_i *update;
	int ret;

	update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
	ret = PTR_ERR_OR_ZERO(update);
	if (ret)
		return ret;

	bkey_reassemble(update, k);

	if (bch2_bkey_merge(c, bkey_i_to_s(update), bkey_i_to_s_c(*insert))) {
		ret = bch2_btree_delete_at(trans, iter, flags);
		if (ret)
			return ret;

		*insert = update;
	}

	return 0;
}

static int bch2_trans_update_extent(struct btree_trans *trans,
				    struct btree_iter *orig_iter,
				    struct bkey_i *insert,
				    enum btree_update_flags flags)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter, update_iter;
	struct bpos start = bkey_start_pos(&insert->k);
	struct bkey_i *update;
	struct bkey_s_c k;
	enum btree_id btree_id = orig_iter->btree_id;
	int ret = 0, compressed_sectors;

	bch2_trans_iter_init(trans, &iter, btree_id, start,
			     BTREE_ITER_INTENT|
			     BTREE_ITER_WITH_UPDATES|
			     BTREE_ITER_NOT_EXTENTS);
	k = bch2_btree_iter_peek(&iter);
	if ((ret = bkey_err(k)))
		goto err;
	if (!k.k)
		goto out;

	if (!bkey_cmp(k.k->p, bkey_start_pos(&insert->k))) {
		if (bch2_bkey_maybe_mergable(k.k, &insert->k)) {
			ret = extent_front_merge(trans, &iter, k, &insert, flags);
			if (ret)
				goto out;
		}

		goto next;
	}

	if (!bkey_cmp(k.k->p, bkey_start_pos(&insert->k)))
		goto next;

	while (bkey_cmp(insert->k.p, bkey_start_pos(k.k)) > 0) {
		/*
		 * If we're going to be splitting a compressed extent, note it
		 * so that __bch2_trans_commit() can increase our disk
		 * reservation:
		 */
		if (bkey_cmp(bkey_start_pos(k.k), start) < 0 &&
		    bkey_cmp(k.k->p, insert->k.p) > 0 &&
		    (compressed_sectors = bch2_bkey_sectors_compressed(k)))
			trans->extra_journal_res += compressed_sectors;

		if (bkey_cmp(bkey_start_pos(k.k), start) < 0) {
			update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_reassemble(update, k);

			bch2_cut_back(start, update);

			bch2_trans_iter_init(trans, &update_iter, btree_id, update->k.p,
					     BTREE_ITER_NOT_EXTENTS|
					     BTREE_ITER_INTENT);
			ret   = bch2_btree_iter_traverse(&update_iter) ?:
				bch2_trans_update(trans, &update_iter, update,
						  BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE|
						  flags);
			bch2_trans_iter_exit(trans, &update_iter);
			if (ret)
				goto err;
		}

		if (bkey_cmp(k.k->p, insert->k.p) <= 0) {
			ret = bch2_btree_delete_at(trans, &iter, flags);
			if (ret)
				goto err;
		}

		if (bkey_cmp(k.k->p, insert->k.p) > 0) {
			update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_reassemble(update, k);
			bch2_cut_front(insert->k.p, update);

			ret = bch2_trans_update(trans, &iter, update, flags);
			if (ret)
				goto err;

			goto out;
		}
next:
		k = bch2_btree_iter_next(&iter);
		if ((ret = bkey_err(k)))
			goto err;
		if (!k.k)
			goto out;
	}

	if (bch2_bkey_maybe_mergable(&insert->k, k.k))
		bch2_bkey_merge(c, bkey_i_to_s(insert), k);
out:
	if (!bkey_deleted(&insert->k)) {
		/*
		 * Rewinding iterators is expensive: get a new one and the one
		 * that points to the start of insert will be cloned from:
		 */
		bch2_trans_iter_exit(trans, &iter);
		bch2_trans_iter_init(trans, &iter, btree_id, insert->k.p,
				     BTREE_ITER_NOT_EXTENTS|
				     BTREE_ITER_INTENT);
		ret   = bch2_btree_iter_traverse(&iter) ?:
			bch2_trans_update(trans, &iter, insert, flags);
	}
err:
	bch2_trans_iter_exit(trans, &iter);

	return ret;
}

int bch2_trans_update(struct btree_trans *trans, struct btree_iter *iter,
		      struct bkey_i *k, enum btree_update_flags flags)
{
	struct btree_insert_entry *i, n;

	BUG_ON(!iter->path->should_be_locked);

	if (iter->flags & BTREE_ITER_IS_EXTENTS)
		return bch2_trans_update_extent(trans, iter, k, flags);

	BUG_ON(trans->nr_updates >= BTREE_ITER_MAX);
	BUG_ON(bpos_cmp(k->k.p, iter->path->pos));

	n = (struct btree_insert_entry) {
		.flags		= flags,
		.bkey_type	= __btree_node_type(iter->path->level, iter->btree_id),
		.btree_id	= iter->btree_id,
		.level		= iter->path->level,
		.cached		= iter->flags & BTREE_ITER_CACHED,
		.path		= iter->path,
		.k		= k,
		.ip_allocated	= _RET_IP_,
	};

	__btree_path_get(n.path, true);

#ifdef CONFIG_BCACHEFS_DEBUG
	trans_for_each_update(trans, i)
		BUG_ON(i != trans->updates &&
		       btree_insert_entry_cmp(i - 1, i) >= 0);
#endif

	/*
	 * Pending updates are kept sorted: first, find position of new update,
	 * then delete/trim any updates the new update overwrites:
	 */
	trans_for_each_update(trans, i)
		if (btree_insert_entry_cmp(&n, i) <= 0)
			break;

	if (i < trans->updates + trans->nr_updates &&
	    !btree_insert_entry_cmp(&n, i)) {
		BUG_ON(i->trans_triggers_run);

		/*
		 * This is a hack to ensure that inode creates update the btree,
		 * not the key cache, which helps with cache coherency issues in
		 * other areas:
		 */
		if (n.cached && !i->cached) {
			i->k = n.k;
			i->flags = n.flags;

			__btree_path_get(n.path, false);
		} else {
			bch2_path_put(trans, i->path, true);
			*i = n;
		}
	} else
		array_insert_item(trans->updates, trans->nr_updates,
				  i - trans->updates, n);

	return 0;
}

void bch2_trans_commit_hook(struct btree_trans *trans,
			    struct btree_trans_commit_hook *h)
{
	h->next = trans->hooks;
	trans->hooks = h;
}

int __bch2_btree_insert(struct btree_trans *trans,
			enum btree_id id, struct bkey_i *k)
{
	struct btree_iter iter;
	int ret;

	bch2_trans_iter_init(trans, &iter, id, bkey_start_pos(&k->k),
			     BTREE_ITER_INTENT);
	ret   = bch2_btree_iter_traverse(&iter) ?:
		bch2_trans_update(trans, &iter, k, 0);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/**
 * bch2_btree_insert - insert keys into the extent btree
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
	return bch2_trans_do(c, disk_res, journal_seq, flags,
			     __bch2_btree_insert(&trans, id, k));
}

int bch2_btree_delete_at(struct btree_trans *trans,
			 struct btree_iter *iter, unsigned update_flags)
{
	struct bkey_i *k;

	k = bch2_trans_kmalloc(trans, sizeof(*k));
	if (IS_ERR(k))
		return PTR_ERR(k);

	bkey_init(&k->k);
	k->k.p = iter->pos;
	return bch2_trans_update(trans, iter, k, update_flags);
}

int bch2_btree_delete_range_trans(struct btree_trans *trans, enum btree_id id,
				  struct bpos start, struct bpos end,
				  unsigned iter_flags,
				  u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, id, start, BTREE_ITER_INTENT|iter_flags);
retry:
	while ((bch2_trans_begin(trans),
	       (k = bch2_btree_iter_peek(&iter)).k) &&
	       !(ret = bkey_err(k)) &&
	       bkey_cmp(iter.pos, end) < 0) {
		struct bkey_i delete;

		bkey_init(&delete.k);

		/*
		 * This could probably be more efficient for extents:
		 */

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

		if (btree_node_type_is_extents(id)) {
			unsigned max_sectors =
				KEY_SIZE_MAX & (~0 << trans->c->block_bits);

			/* create the biggest key we can */
			bch2_key_resize(&delete.k, max_sectors);
			bch2_cut_back(end, &delete);

			ret = bch2_extent_trim_atomic(trans, &iter, &delete);
			if (ret)
				break;
		}

		ret   = bch2_trans_update(trans, &iter, &delete, 0) ?:
			bch2_trans_commit(trans, NULL, journal_seq,
					BTREE_INSERT_NOFAIL);
		if (ret)
			break;

		bch2_trans_cond_resched(trans);
	}

	if (ret == -EINTR) {
		ret = 0;
		goto retry;
	}

	bch2_trans_iter_exit(trans, &iter);
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
	return bch2_trans_do(c, NULL, journal_seq, 0,
			     bch2_btree_delete_range_trans(&trans, id, start, end, 0, journal_seq));
}
