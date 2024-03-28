// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_gc.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_journal_iter.h"
#include "btree_key_cache.h"
#include "btree_update_interior.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "errcode.h"
#include "error.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "replicas.h"
#include "snapshot.h"

#include <linux/prefetch.h>

static void verify_update_old_key(struct btree_trans *trans, struct btree_insert_entry *i)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bch_fs *c = trans->c;
	struct bkey u;
	struct bkey_s_c k = bch2_btree_path_peek_slot_exact(trans->paths + i->path, &u);

	if (unlikely(trans->journal_replay_not_finished)) {
		struct bkey_i *j_k =
			bch2_journal_keys_peek_slot(c, i->btree_id, i->level, i->k->k.p);

		if (j_k)
			k = bkey_i_to_s_c(j_k);
	}

	u = *k.k;
	u.needs_whiteout = i->old_k.needs_whiteout;

	BUG_ON(memcmp(&i->old_k, &u, sizeof(struct bkey)));
	BUG_ON(i->old_v != k.v);
#endif
}

static inline struct btree_path_level *insert_l(struct btree_trans *trans, struct btree_insert_entry *i)
{
	return (trans->paths + i->path)->l + i->level;
}

static inline bool same_leaf_as_prev(struct btree_trans *trans,
				     struct btree_insert_entry *i)
{
	return i != trans->updates &&
		insert_l(trans, &i[0])->b == insert_l(trans, &i[-1])->b;
}

static inline bool same_leaf_as_next(struct btree_trans *trans,
				     struct btree_insert_entry *i)
{
	return i + 1 < trans->updates + trans->nr_updates &&
		insert_l(trans, &i[0])->b == insert_l(trans, &i[1])->b;
}

inline void bch2_btree_node_prep_for_write(struct btree_trans *trans,
					   struct btree_path *path,
					   struct btree *b)
{
	struct bch_fs *c = trans->c;

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

static noinline int trans_lock_write_fail(struct btree_trans *trans, struct btree_insert_entry *i)
{
	while (--i >= trans->updates) {
		if (same_leaf_as_prev(trans, i))
			continue;

		bch2_btree_node_unlock_write(trans, trans->paths + i->path, insert_l(trans, i)->b);
	}

	trace_and_count(trans->c, trans_restart_would_deadlock_write, trans);
	return btree_trans_restart(trans, BCH_ERR_transaction_restart_would_deadlock_write);
}

static inline int bch2_trans_lock_write(struct btree_trans *trans)
{
	EBUG_ON(trans->write_locked);

	trans_for_each_update(trans, i) {
		if (same_leaf_as_prev(trans, i))
			continue;

		if (bch2_btree_node_lock_write(trans, trans->paths + i->path, &insert_l(trans, i)->b->c))
			return trans_lock_write_fail(trans, i);

		if (!i->cached)
			bch2_btree_node_prep_for_write(trans, trans->paths + i->path, insert_l(trans, i)->b);
	}

	trans->write_locked = true;
	return 0;
}

static inline void bch2_trans_unlock_write(struct btree_trans *trans)
{
	if (likely(trans->write_locked)) {
		trans_for_each_update(trans, i)
			if (!same_leaf_as_prev(trans, i))
				bch2_btree_node_unlock_write_inlined(trans,
						trans->paths + i->path, insert_l(trans, i)->b);
		trans->write_locked = false;
	}
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
	EBUG_ON(bpos_lt(insert->k.p, b->data->min_key));
	EBUG_ON(bpos_gt(insert->k.p, b->data->max_key));
	EBUG_ON(insert->k.u64s > bch2_btree_keys_u64s_remaining(b));
	EBUG_ON(!b->c.level && !bpos_eq(insert->k.p, path->pos));

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
			push_whiteout(b, insert->k.p);
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
	struct btree_trans *trans = bch2_trans_get(c);
	unsigned long old, new, v;
	unsigned idx = w - b->writes;

	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);
	v = READ_ONCE(b->flags);

	do {
		old = new = v;

		if (!(old & (1 << BTREE_NODE_dirty)) ||
		    !!(old & (1 << BTREE_NODE_write_idx)) != idx ||
		    w->journal.seq != seq)
			break;

		new &= ~BTREE_WRITE_TYPE_MASK;
		new |= BTREE_WRITE_journal_reclaim;
		new |= 1 << BTREE_NODE_need_write;
	} while ((v = cmpxchg(&b->flags, old, new)) != old);

	btree_node_write_if_need(c, b, SIX_LOCK_read);
	six_unlock_read(&b->c.lock);

	bch2_trans_put(trans);
	return 0;
}

int bch2_btree_node_flush0(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 0, seq);
}

int bch2_btree_node_flush1(struct journal *j, struct journal_entry_pin *pin, u64 seq)
{
	return __btree_node_flush(j, pin, 1, seq);
}

inline void bch2_btree_add_journal_pin(struct bch_fs *c,
				       struct btree *b, u64 seq)
{
	struct btree_write *w = btree_current_write(b);

	bch2_journal_pin_add(&c->journal, seq, &w->journal,
			     btree_node_write_idx(b) == 0
			     ? bch2_btree_node_flush0
			     : bch2_btree_node_flush1);
}

/**
 * bch2_btree_insert_key_leaf() - insert a key one key into a leaf node
 * @trans:		btree transaction object
 * @path:		path pointing to @insert's pos
 * @insert:		key to insert
 * @journal_seq:	sequence number of journal reservation
 */
inline void bch2_btree_insert_key_leaf(struct btree_trans *trans,
				       struct btree_path *path,
				       struct bkey_i *insert,
				       u64 journal_seq)
{
	struct bch_fs *c = trans->c;
	struct btree *b = path_l(path)->b;
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = bset(b, t);
	int old_u64s = bset_u64s(t);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

	if (unlikely(!bch2_btree_bset_insert_key(trans, path, b,
					&path_l(path)->iter, insert)))
		return;

	i->journal_seq = cpu_to_le64(max(journal_seq, le64_to_cpu(i->journal_seq)));

	bch2_btree_add_journal_pin(c, b, journal_seq);

	if (unlikely(!btree_node_dirty(b))) {
		EBUG_ON(test_bit(BCH_FS_clean_shutdown, &c->flags));
		set_btree_node_dirty_acct(c, b);
	}

	live_u64s_added = (int) b->nr.live_u64s - old_live_u64s;
	u64s_added = (int) bset_u64s(t) - old_u64s;

	if (b->sib_u64s[0] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[0] = max(0, (int) b->sib_u64s[0] + live_u64s_added);
	if (b->sib_u64s[1] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[1] = max(0, (int) b->sib_u64s[1] + live_u64s_added);

	if (u64s_added > live_u64s_added &&
	    bch2_maybe_compact_whiteouts(c, b))
		bch2_trans_node_reinit_iter(trans, b);
}

/* Cached btree updates: */

/* Normal update interface: */

static inline void btree_insert_entry_checks(struct btree_trans *trans,
					     struct btree_insert_entry *i)
{
	struct btree_path *path = trans->paths + i->path;

	BUG_ON(!bpos_eq(i->k->k.p, path->pos));
	BUG_ON(i->cached	!= path->cached);
	BUG_ON(i->level		!= path->level);
	BUG_ON(i->btree_id	!= path->btree_id);
	EBUG_ON(!i->level &&
		btree_type_has_snapshots(i->btree_id) &&
		!(i->flags & BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE) &&
		test_bit(JOURNAL_REPLAY_DONE, &trans->c->journal.flags) &&
		i->k->k.p.snapshot &&
		bch2_snapshot_is_internal_node(trans->c, i->k->k.p.snapshot) > 0);
}

static __always_inline int bch2_trans_journal_res_get(struct btree_trans *trans,
						      unsigned flags)
{
	return bch2_journal_res_get(&trans->c->journal, &trans->journal_res,
				    trans->journal_u64s, flags);
}

#define JSET_ENTRY_LOG_U64s		4

static noinline void journal_transaction_name(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct jset_entry *entry =
		bch2_journal_add_entry(j, &trans->journal_res,
				       BCH_JSET_ENTRY_log, 0, 0,
				       JSET_ENTRY_LOG_U64s);
	struct jset_entry_log *l =
		container_of(entry, struct jset_entry_log, entry);

	strncpy(l->d, trans->fn, JSET_ENTRY_LOG_U64s * sizeof(u64));
}

static inline int btree_key_can_insert(struct btree_trans *trans,
				       struct btree *b, unsigned u64s)
{
	if (!bch2_btree_node_insert_fits(b, u64s))
		return -BCH_ERR_btree_insert_btree_node_full;

	return 0;
}

noinline static int
btree_key_can_insert_cached_slowpath(struct btree_trans *trans, unsigned flags,
				     struct btree_path *path, unsigned new_u64s)
{
	struct bkey_cached *ck = (void *) path->l[0].b;
	struct bkey_i *new_k;
	int ret;

	bch2_trans_unlock_write(trans);
	bch2_trans_unlock(trans);

	new_k = kmalloc(new_u64s * sizeof(u64), GFP_KERNEL);
	if (!new_k) {
		bch_err(trans->c, "error allocating memory for key cache key, btree %s u64s %u",
			bch2_btree_id_str(path->btree_id), new_u64s);
		return -BCH_ERR_ENOMEM_btree_key_cache_insert;
	}

	ret =   bch2_trans_relock(trans) ?:
		bch2_trans_lock_write(trans);
	if (unlikely(ret)) {
		kfree(new_k);
		return ret;
	}

	memcpy(new_k, ck->k, ck->u64s * sizeof(u64));

	trans_for_each_update(trans, i)
		if (i->old_v == &ck->k->v)
			i->old_v = &new_k->v;

	kfree(ck->k);
	ck->u64s	= new_u64s;
	ck->k		= new_k;
	return 0;
}

static int btree_key_can_insert_cached(struct btree_trans *trans, unsigned flags,
				       struct btree_path *path, unsigned u64s)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck = (void *) path->l[0].b;
	unsigned new_u64s;
	struct bkey_i *new_k;

	EBUG_ON(path->level);

	if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags) &&
	    bch2_btree_key_cache_must_wait(c) &&
	    !(flags & BCH_TRANS_COMMIT_journal_reclaim))
		return -BCH_ERR_btree_insert_need_journal_reclaim;

	/*
	 * bch2_varint_decode can read past the end of the buffer by at most 7
	 * bytes (it won't be used):
	 */
	u64s += 1;

	if (u64s <= ck->u64s)
		return 0;

	new_u64s	= roundup_pow_of_two(u64s);
	new_k		= krealloc(ck->k, new_u64s * sizeof(u64), GFP_NOWAIT|__GFP_NOWARN);
	if (unlikely(!new_k))
		return btree_key_can_insert_cached_slowpath(trans, flags, path, new_u64s);

	trans_for_each_update(trans, i)
		if (i->old_v == &ck->k->v)
			i->old_v = &new_k->v;

	ck->u64s	= new_u64s;
	ck->k		= new_k;
	return 0;
}

/* Triggers: */

static int run_one_mem_trigger(struct btree_trans *trans,
			       struct btree_insert_entry *i,
			       unsigned flags)
{
	struct bkey_s_c old = { &i->old_k, i->old_v };
	struct bkey_i *new = i->k;
	const struct bkey_ops *old_ops = bch2_bkey_type_ops(old.k->type);
	const struct bkey_ops *new_ops = bch2_bkey_type_ops(i->k->k.type);
	int ret;

	verify_update_old_key(trans, i);

	if (unlikely(flags & BTREE_TRIGGER_NORUN))
		return 0;

	if (old_ops->trigger == new_ops->trigger) {
		ret   = bch2_key_trigger(trans, i->btree_id, i->level,
				old, bkey_i_to_s(new),
				BTREE_TRIGGER_INSERT|BTREE_TRIGGER_OVERWRITE|flags);
	} else {
		ret   = bch2_key_trigger_new(trans, i->btree_id, i->level,
				bkey_i_to_s(new), flags) ?:
			bch2_key_trigger_old(trans, i->btree_id, i->level,
				old, flags);
	}

	return ret;
}

static int run_one_trans_trigger(struct btree_trans *trans, struct btree_insert_entry *i,
				 bool overwrite)
{
	/*
	 * Transactional triggers create new btree_insert_entries, so we can't
	 * pass them a pointer to a btree_insert_entry, that memory is going to
	 * move:
	 */
	struct bkey old_k = i->old_k;
	struct bkey_s_c old = { &old_k, i->old_v };
	const struct bkey_ops *old_ops = bch2_bkey_type_ops(old.k->type);
	const struct bkey_ops *new_ops = bch2_bkey_type_ops(i->k->k.type);
	unsigned flags = i->flags|BTREE_TRIGGER_TRANSACTIONAL;

	verify_update_old_key(trans, i);

	if ((i->flags & BTREE_TRIGGER_NORUN) ||
	    !(BTREE_NODE_TYPE_HAS_TRANS_TRIGGERS & (1U << i->bkey_type)))
		return 0;

	if (!i->insert_trigger_run &&
	    !i->overwrite_trigger_run &&
	    old_ops->trigger == new_ops->trigger) {
		i->overwrite_trigger_run = true;
		i->insert_trigger_run = true;
		return bch2_key_trigger(trans, i->btree_id, i->level, old, bkey_i_to_s(i->k),
					BTREE_TRIGGER_INSERT|
					BTREE_TRIGGER_OVERWRITE|flags) ?: 1;
	} else if (overwrite && !i->overwrite_trigger_run) {
		i->overwrite_trigger_run = true;
		return bch2_key_trigger_old(trans, i->btree_id, i->level, old, flags) ?: 1;
	} else if (!overwrite && !i->insert_trigger_run) {
		i->insert_trigger_run = true;
		return bch2_key_trigger_new(trans, i->btree_id, i->level, bkey_i_to_s(i->k), flags) ?: 1;
	} else {
		return 0;
	}
}

static int run_btree_triggers(struct btree_trans *trans, enum btree_id btree_id,
			      struct btree_insert_entry *btree_id_start)
{
	struct btree_insert_entry *i;
	bool trans_trigger_run;
	int ret, overwrite;

	for (overwrite = 1; overwrite >= 0; --overwrite) {

		/*
		 * Running triggers will append more updates to the list of updates as
		 * we're walking it:
		 */
		do {
			trans_trigger_run = false;

			for (i = btree_id_start;
			     i < trans->updates + trans->nr_updates && i->btree_id <= btree_id;
			     i++) {
				if (i->btree_id != btree_id)
					continue;

				ret = run_one_trans_trigger(trans, i, overwrite);
				if (ret < 0)
					return ret;
				if (ret)
					trans_trigger_run = true;
			}
		} while (trans_trigger_run);
	}

	return 0;
}

static int bch2_trans_commit_run_triggers(struct btree_trans *trans)
{
	struct btree_insert_entry *btree_id_start = trans->updates;
	unsigned btree_id = 0;
	int ret = 0;

	/*
	 *
	 * For a given btree, this algorithm runs insert triggers before
	 * overwrite triggers: this is so that when extents are being moved
	 * (e.g. by FALLOCATE_FL_INSERT_RANGE), we don't drop references before
	 * they are re-added.
	 */
	for (btree_id = 0; btree_id < BTREE_ID_NR; btree_id++) {
		if (btree_id == BTREE_ID_alloc)
			continue;

		while (btree_id_start < trans->updates + trans->nr_updates &&
		       btree_id_start->btree_id < btree_id)
			btree_id_start++;

		ret = run_btree_triggers(trans, btree_id, btree_id_start);
		if (ret)
			return ret;
	}

	trans_for_each_update(trans, i) {
		if (i->btree_id > BTREE_ID_alloc)
			break;
		if (i->btree_id == BTREE_ID_alloc) {
			ret = run_btree_triggers(trans, BTREE_ID_alloc, i);
			if (ret)
				return ret;
			break;
		}
	}

#ifdef CONFIG_BCACHEFS_DEBUG
	trans_for_each_update(trans, i)
		BUG_ON(!(i->flags & BTREE_TRIGGER_NORUN) &&
		       (BTREE_NODE_TYPE_HAS_TRANS_TRIGGERS & (1U << i->bkey_type)) &&
		       (!i->insert_trigger_run || !i->overwrite_trigger_run));
#endif
	return 0;
}

static noinline int bch2_trans_commit_run_gc_triggers(struct btree_trans *trans)
{
	trans_for_each_update(trans, i) {
		/*
		 * XXX: synchronization of cached update triggers with gc
		 * XXX: synchronization of interior node updates with gc
		 */
		BUG_ON(i->cached || i->level);

		if (btree_node_type_needs_gc(__btree_node_type(i->level, i->btree_id)) &&
		    gc_visited(trans->c, gc_pos_btree_node(insert_l(trans, i)->b))) {
			int ret = run_one_mem_trigger(trans, i, i->flags|BTREE_TRIGGER_GC);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static inline int
bch2_trans_commit_write_locked(struct btree_trans *trans, unsigned flags,
			       struct btree_insert_entry **stopped_at,
			       unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree_trans_commit_hook *h;
	unsigned u64s = 0;
	int ret;

	if (race_fault()) {
		trace_and_count(c, trans_restart_fault_inject, trans, trace_ip);
		return btree_trans_restart_nounlock(trans, BCH_ERR_transaction_restart_fault_inject);
	}

	/*
	 * Check if the insert will fit in the leaf node with the write lock
	 * held, otherwise another thread could write the node changing the
	 * amount of space available:
	 */

	prefetch(&trans->c->journal.flags);

	trans_for_each_update(trans, i) {
		/* Multiple inserts might go to same leaf: */
		if (!same_leaf_as_prev(trans, i))
			u64s = 0;

		u64s += i->k->k.u64s;
		ret = !i->cached
			? btree_key_can_insert(trans, insert_l(trans, i)->b, u64s)
			: btree_key_can_insert_cached(trans, flags, trans->paths + i->path, u64s);
		if (ret) {
			*stopped_at = i;
			return ret;
		}

		i->k->k.needs_whiteout = false;
	}

	/*
	 * Don't get journal reservation until after we know insert will
	 * succeed:
	 */
	if (likely(!(flags & BCH_TRANS_COMMIT_no_journal_res))) {
		ret = bch2_trans_journal_res_get(trans,
				(flags & BCH_WATERMARK_MASK)|
				JOURNAL_RES_GET_NONBLOCK);
		if (ret)
			return ret;

		if (unlikely(trans->journal_transaction_names))
			journal_transaction_name(trans);
	}

	/*
	 * Not allowed to fail after we've gotten our journal reservation - we
	 * have to use it:
	 */

	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG) &&
	    !(flags & BCH_TRANS_COMMIT_no_journal_res)) {
		if (bch2_journal_seq_verify)
			trans_for_each_update(trans, i)
				i->k->k.version.lo = trans->journal_res.seq;
		else if (bch2_inject_invalid_keys)
			trans_for_each_update(trans, i)
				i->k->k.version = MAX_VERSION;
	}

	if (trans->fs_usage_deltas &&
	    bch2_trans_fs_usage_apply(trans, trans->fs_usage_deltas))
		return -BCH_ERR_btree_insert_need_mark_replicas;

	/* XXX: we only want to run this if deltas are nonzero */
	bch2_trans_account_disk_usage_change(trans);

	h = trans->hooks;
	while (h) {
		ret = h->fn(trans, h);
		if (ret)
			goto revert_fs_usage;
		h = h->next;
	}

	trans_for_each_update(trans, i)
		if (BTREE_NODE_TYPE_HAS_ATOMIC_TRIGGERS & (1U << i->bkey_type)) {
			ret = run_one_mem_trigger(trans, i, BTREE_TRIGGER_ATOMIC|i->flags);
			if (ret)
				goto fatal_err;
		}

	if (unlikely(c->gc_pos.phase)) {
		ret = bch2_trans_commit_run_gc_triggers(trans);
		if  (ret)
			goto fatal_err;
	}

	if (likely(!(flags & BCH_TRANS_COMMIT_no_journal_res))) {
		struct journal *j = &c->journal;
		struct jset_entry *entry;

		trans_for_each_update(trans, i) {
			if (i->key_cache_already_flushed)
				continue;

			if (i->flags & BTREE_UPDATE_NOJOURNAL)
				continue;

			verify_update_old_key(trans, i);

			if (trans->journal_transaction_names) {
				entry = bch2_journal_add_entry(j, &trans->journal_res,
						       BCH_JSET_ENTRY_overwrite,
						       i->btree_id, i->level,
						       i->old_k.u64s);
				bkey_reassemble((struct bkey_i *) entry->start,
						(struct bkey_s_c) { &i->old_k, i->old_v });
			}

			entry = bch2_journal_add_entry(j, &trans->journal_res,
					       BCH_JSET_ENTRY_btree_keys,
					       i->btree_id, i->level,
					       i->k->k.u64s);
			bkey_copy((struct bkey_i *) entry->start, i->k);
		}

		memcpy_u64s_small(journal_res_entry(&c->journal, &trans->journal_res),
				  trans->journal_entries,
				  trans->journal_entries_u64s);

		trans->journal_res.offset	+= trans->journal_entries_u64s;
		trans->journal_res.u64s		-= trans->journal_entries_u64s;

		if (trans->journal_seq)
			*trans->journal_seq = trans->journal_res.seq;
	}

	trans_for_each_update(trans, i) {
		struct btree_path *path = trans->paths + i->path;

		if (!i->cached) {
			bch2_btree_insert_key_leaf(trans, path, i->k, trans->journal_res.seq);
		} else if (!i->key_cache_already_flushed)
			bch2_btree_insert_key_cached(trans, flags, i);
		else {
			bch2_btree_key_cache_drop(trans, path);
			btree_path_set_dirty(path, BTREE_ITER_NEED_TRAVERSE);
		}
	}

	return 0;
fatal_err:
	bch2_fatal_error(c);
revert_fs_usage:
	if (trans->fs_usage_deltas)
		bch2_trans_fs_usage_revert(trans, trans->fs_usage_deltas);
	return ret;
}

static noinline void bch2_drop_overwrites_from_journal(struct btree_trans *trans)
{
	trans_for_each_update(trans, i)
		bch2_journal_key_overwritten(trans->c, i->btree_id, i->level, i->k->k.p);
}

static noinline int bch2_trans_commit_bkey_invalid(struct btree_trans *trans,
						   enum bkey_invalid_flags flags,
						   struct btree_insert_entry *i,
						   struct printbuf *err)
{
	struct bch_fs *c = trans->c;

	printbuf_reset(err);
	prt_printf(err, "invalid bkey on insert from %s -> %ps",
		   trans->fn, (void *) i->ip_allocated);
	prt_newline(err);
	printbuf_indent_add(err, 2);

	bch2_bkey_val_to_text(err, c, bkey_i_to_s_c(i->k));
	prt_newline(err);

	bch2_bkey_invalid(c, bkey_i_to_s_c(i->k), i->bkey_type, flags, err);
	bch2_print_string_as_lines(KERN_ERR, err->buf);

	bch2_inconsistent_error(c);
	bch2_dump_trans_updates(trans);

	return -EINVAL;
}

static noinline int bch2_trans_commit_journal_entry_invalid(struct btree_trans *trans,
						   struct jset_entry *i)
{
	struct bch_fs *c = trans->c;
	struct printbuf buf = PRINTBUF;

	prt_printf(&buf, "invalid bkey on insert from %s", trans->fn);
	prt_newline(&buf);
	printbuf_indent_add(&buf, 2);

	bch2_journal_entry_to_text(&buf, c, i);
	prt_newline(&buf);

	bch2_print_string_as_lines(KERN_ERR, buf.buf);

	bch2_inconsistent_error(c);
	bch2_dump_trans_updates(trans);

	return -EINVAL;
}

static int bch2_trans_commit_journal_pin_flush(struct journal *j,
				struct journal_entry_pin *_pin, u64 seq)
{
	return 0;
}

/*
 * Get journal reservation, take write locks, and attempt to do btree update(s):
 */
static inline int do_bch2_trans_commit(struct btree_trans *trans, unsigned flags,
				       struct btree_insert_entry **stopped_at,
				       unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	int ret = 0, u64s_delta = 0;

	trans_for_each_update(trans, i) {
		if (i->cached)
			continue;

		u64s_delta += !bkey_deleted(&i->k->k) ? i->k->k.u64s : 0;
		u64s_delta -= i->old_btree_u64s;

		if (!same_leaf_as_next(trans, i)) {
			if (u64s_delta <= 0) {
				ret = bch2_foreground_maybe_merge(trans, i->path,
							i->level, flags);
				if (unlikely(ret))
					return ret;
			}

			u64s_delta = 0;
		}
	}

	ret = bch2_trans_lock_write(trans);
	if (unlikely(ret))
		return ret;

	ret = bch2_trans_commit_write_locked(trans, flags, stopped_at, trace_ip);

	if (!ret && unlikely(trans->journal_replay_not_finished))
		bch2_drop_overwrites_from_journal(trans);

	bch2_trans_unlock_write(trans);

	if (!ret && trans->journal_pin)
		bch2_journal_pin_add(&c->journal, trans->journal_res.seq,
				     trans->journal_pin,
				     bch2_trans_commit_journal_pin_flush);

	/*
	 * Drop journal reservation after dropping write locks, since dropping
	 * the journal reservation may kick off a journal write:
	 */
	if (likely(!(flags & BCH_TRANS_COMMIT_no_journal_res)))
		bch2_journal_res_put(&c->journal, &trans->journal_res);

	return ret;
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
int bch2_trans_commit_error(struct btree_trans *trans, unsigned flags,
			    struct btree_insert_entry *i,
			    int ret, unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;

	switch (ret) {
	case -BCH_ERR_btree_insert_btree_node_full:
		ret = bch2_btree_split_leaf(trans, i->path, flags);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			trace_and_count(c, trans_restart_btree_node_split, trans,
					trace_ip, trans->paths + i->path);
		break;
	case -BCH_ERR_btree_insert_need_mark_replicas:
		ret = drop_locks_do(trans,
			bch2_replicas_delta_list_mark(c, trans->fs_usage_deltas));
		break;
	case -BCH_ERR_journal_res_get_blocked:
		/*
		 * XXX: this should probably be a separate BTREE_INSERT_NONBLOCK
		 * flag
		 */
		if ((flags & BCH_TRANS_COMMIT_journal_reclaim) &&
		    (flags & BCH_WATERMARK_MASK) != BCH_WATERMARK_reclaim) {
			ret = -BCH_ERR_journal_reclaim_would_deadlock;
			break;
		}

		ret = drop_locks_do(trans,
			bch2_trans_journal_res_get(trans,
					(flags & BCH_WATERMARK_MASK)|
					JOURNAL_RES_GET_CHECK));
		break;
	case -BCH_ERR_btree_insert_need_journal_reclaim:
		bch2_trans_unlock(trans);

		trace_and_count(c, trans_blocked_journal_reclaim, trans, trace_ip);

		wait_event_freezable(c->journal.reclaim_wait,
				     (ret = journal_reclaim_wait_done(c)));
		if (ret < 0)
			break;

		ret = bch2_trans_relock(trans);
		break;
	default:
		BUG_ON(ret >= 0);
		break;
	}

	BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart) != !!trans->restarted);

	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOSPC) &&
				(flags & BCH_TRANS_COMMIT_no_enospc), c,
		"%s: incorrectly got %s\n", __func__, bch2_err_str(ret));

	return ret;
}

static noinline int
bch2_trans_commit_get_rw_cold(struct btree_trans *trans, unsigned flags)
{
	struct bch_fs *c = trans->c;
	int ret;

	if (likely(!(flags & BCH_TRANS_COMMIT_lazy_rw)) ||
	    test_bit(BCH_FS_started, &c->flags))
		return -BCH_ERR_erofs_trans_commit;

	ret = drop_locks_do(trans, bch2_fs_read_write_early(c));
	if (ret)
		return ret;

	bch2_write_ref_get(c, BCH_WRITE_REF_trans);
	return 0;
}

/*
 * This is for updates done in the early part of fsck - btree_gc - before we've
 * gone RW. we only add the new key to the list of keys for journal replay to
 * do.
 */
static noinline int
do_bch2_trans_commit_to_journal_replay(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	trans_for_each_update(trans, i) {
		ret = bch2_journal_key_insert(c, i->btree_id, i->level, i->k);
		if (ret)
			break;
	}

	return ret;
}

int __bch2_trans_commit(struct btree_trans *trans, unsigned flags)
{
	struct btree_insert_entry *errored_at = NULL;
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (!trans->nr_updates &&
	    !trans->journal_entries_u64s)
		goto out_reset;

	memset(&trans->fs_usage_delta, 0, sizeof(trans->fs_usage_delta));

	ret = bch2_trans_commit_run_triggers(trans);
	if (ret)
		goto out_reset;

	trans_for_each_update(trans, i) {
		struct printbuf buf = PRINTBUF;
		enum bkey_invalid_flags invalid_flags = 0;

		if (!(flags & BCH_TRANS_COMMIT_no_journal_res))
			invalid_flags |= BKEY_INVALID_WRITE|BKEY_INVALID_COMMIT;

		if (unlikely(bch2_bkey_invalid(c, bkey_i_to_s_c(i->k),
					       i->bkey_type, invalid_flags, &buf)))
			ret = bch2_trans_commit_bkey_invalid(trans, invalid_flags, i, &buf);
		btree_insert_entry_checks(trans, i);
		printbuf_exit(&buf);

		if (ret)
			return ret;
	}

	for (struct jset_entry *i = trans->journal_entries;
	     i != (void *) ((u64 *) trans->journal_entries + trans->journal_entries_u64s);
	     i = vstruct_next(i)) {
		enum bkey_invalid_flags invalid_flags = 0;

		if (!(flags & BCH_TRANS_COMMIT_no_journal_res))
			invalid_flags |= BKEY_INVALID_WRITE|BKEY_INVALID_COMMIT;

		if (unlikely(bch2_journal_entry_validate(c, NULL, i,
					bcachefs_metadata_version_current,
					CPU_BIG_ENDIAN, invalid_flags)))
			ret = bch2_trans_commit_journal_entry_invalid(trans, i);

		if (ret)
			return ret;
	}

	if (unlikely(!test_bit(BCH_FS_may_go_rw, &c->flags))) {
		ret = do_bch2_trans_commit_to_journal_replay(trans);
		goto out_reset;
	}

	if (!(flags & BCH_TRANS_COMMIT_no_check_rw) &&
	    unlikely(!bch2_write_ref_tryget(c, BCH_WRITE_REF_trans))) {
		ret = bch2_trans_commit_get_rw_cold(trans, flags);
		if (ret)
			goto out_reset;
	}

	EBUG_ON(test_bit(BCH_FS_clean_shutdown, &c->flags));

	trans->journal_u64s		= trans->journal_entries_u64s;
	trans->journal_transaction_names = READ_ONCE(c->opts.journal_transaction_names);
	if (trans->journal_transaction_names)
		trans->journal_u64s += jset_u64s(JSET_ENTRY_LOG_U64s);

	trans_for_each_update(trans, i) {
		struct btree_path *path = trans->paths + i->path;

		EBUG_ON(!path->should_be_locked);

		ret = bch2_btree_path_upgrade(trans, path, i->level + 1);
		if (unlikely(ret))
			goto out;

		EBUG_ON(!btree_node_intent_locked(path, i->level));

		if (i->key_cache_already_flushed)
			continue;

		if (i->flags & BTREE_UPDATE_NOJOURNAL)
			continue;

		/* we're going to journal the key being updated: */
		trans->journal_u64s += jset_u64s(i->k->k.u64s);

		/* and we're also going to log the overwrite: */
		if (trans->journal_transaction_names)
			trans->journal_u64s += jset_u64s(i->old_k.u64s);
	}

	if (trans->extra_disk_res) {
		ret = bch2_disk_reservation_add(c, trans->disk_res,
				trans->extra_disk_res,
				(flags & BCH_TRANS_COMMIT_no_enospc)
				? BCH_DISK_RESERVATION_NOFAIL : 0);
		if (ret)
			goto err;
	}
retry:
	errored_at = NULL;
	bch2_trans_verify_not_in_restart(trans);
	if (likely(!(flags & BCH_TRANS_COMMIT_no_journal_res)))
		memset(&trans->journal_res, 0, sizeof(trans->journal_res));

	ret = do_bch2_trans_commit(trans, flags, &errored_at, _RET_IP_);

	/* make sure we didn't drop or screw up locks: */
	bch2_trans_verify_locks(trans);

	if (ret)
		goto err;

	trace_and_count(c, transaction_commit, trans, _RET_IP_);
out:
	if (likely(!(flags & BCH_TRANS_COMMIT_no_check_rw)))
		bch2_write_ref_put(c, BCH_WRITE_REF_trans);
out_reset:
	if (!ret)
		bch2_trans_downgrade(trans);
	bch2_trans_reset_updates(trans);

	return ret;
err:
	ret = bch2_trans_commit_error(trans, flags, errored_at, ret, _RET_IP_);
	if (ret)
		goto out;

	/*
	 * We might have done another transaction commit in the error path -
	 * i.e. btree write buffer flush - which will have made use of
	 * trans->journal_res, but with BCH_TRANS_COMMIT_no_journal_res that is
	 * how the journal sequence number to pin is passed in - so we must
	 * restart:
	 */
	if (flags & BCH_TRANS_COMMIT_no_journal_res) {
		ret = -BCH_ERR_transaction_restart_nested;
		goto out;
	}

	goto retry;
}
