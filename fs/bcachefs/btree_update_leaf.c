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
#include "errcode.h"
#include "error.h"
#include "extent_update.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "recovery.h"
#include "subvolume.h"
#include "replicas.h"
#include "trace.h"

#include <linux/prefetch.h>
#include <linux/sort.h>

static int __must_check
bch2_trans_update_by_path(struct btree_trans *, struct btree_path *,
			  struct bkey_i *, enum btree_update_flags);

static inline int btree_insert_entry_cmp(const struct btree_insert_entry *l,
					 const struct btree_insert_entry *r)
{
	return   cmp_int(l->btree_id,	r->btree_id) ?:
		 cmp_int(l->cached,	r->cached) ?:
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
	bch2_btree_node_lock_write_nofail(trans, path, &b->c);
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
	struct btree_trans trans;
	unsigned long old, new, v;
	unsigned idx = w - b->writes;

	bch2_trans_init(&trans, c, 0, 0);

	btree_node_lock_nopath_nofail(&trans, &b->c, SIX_LOCK_read);
	v = READ_ONCE(b->flags);

	do {
		old = new = v;

		if (!(old & (1 << BTREE_NODE_dirty)) ||
		    !!(old & (1 << BTREE_NODE_write_idx)) != idx ||
		    w->journal.seq != seq)
			break;

		new |= 1 << BTREE_NODE_need_write;
	} while ((v = cmpxchg(&b->flags, old, new)) != old);

	btree_node_write_if_need(c, b, SIX_LOCK_read);
	six_unlock_read(&b->c.lock);

	bch2_trans_exit(&trans);
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
static void btree_insert_key_leaf(struct btree_trans *trans,
				  struct btree_insert_entry *insert)
{
	struct bch_fs *c = trans->c;
	struct btree *b = insert_l(insert)->b;
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = bset(b, t);
	int old_u64s = bset_u64s(t);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

	if (unlikely(!bch2_btree_bset_insert_key(trans, insert->path, b,
					&insert_l(insert)->iter, insert->k)))
		return;

	i->journal_seq = cpu_to_le64(max(trans->journal_res.seq,
					 le64_to_cpu(i->journal_seq)));

	bch2_btree_add_journal_pin(c, b, trans->journal_res.seq);

	if (unlikely(!btree_node_dirty(b)))
		set_btree_node_dirty_acct(c, b);

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

	ret = bch2_trans_relock(trans);
	if (ret) {
		trace_and_count(c, trans_restart_journal_preres_get, trans, trace_ip, 0);
		return ret;
	}

	return 0;
}

static inline int bch2_trans_journal_res_get(struct btree_trans *trans,
					     unsigned flags)
{
	struct bch_fs *c = trans->c;
	int ret;

	ret = bch2_journal_res_get(&c->journal, &trans->journal_res,
				   trans->journal_u64s,
				   flags|
				   (trans->flags & JOURNAL_WATERMARK_MASK));

	return ret == -EAGAIN ? BTREE_INSERT_NEED_JOURNAL_RES : ret;
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
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck = (void *) path->l[0].b;
	unsigned old_u64s = ck->u64s, new_u64s;
	struct bkey_i *new_k;

	EBUG_ON(path->level);

	if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags) &&
	    bch2_btree_key_cache_must_wait(c) &&
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
	if (!new_k) {
		bch_err(c, "error allocating memory for key cache key, btree %s u64s %u",
			bch2_btree_ids[path->btree_id], new_u64s);
		return -ENOMEM;
	}

	ck->u64s	= new_u64s;
	ck->k		= new_k;
	/*
	 * Keys returned by peek() are no longer valid pointers, so we need a
	 * transaction restart:
	 */
	trace_and_count(c, trans_restart_key_cache_key_realloced, trans, _RET_IP_, path, old_u64s, new_u64s);
	return btree_trans_restart_nounlock(trans, BCH_ERR_transaction_restart_key_cache_realloced);
}

/* Triggers: */

static int run_one_mem_trigger(struct btree_trans *trans,
			       struct btree_insert_entry *i,
			       unsigned flags)
{
	struct bkey_s_c old = { &i->old_k, i->old_v };
	struct bkey_i *new = i->k;
	int ret;

	if (unlikely(flags & BTREE_TRIGGER_NORUN))
		return 0;

	if (!btree_node_type_needs_gc(i->btree_id))
		return 0;

	if (bch2_bkey_ops[old.k->type].atomic_trigger ==
	    bch2_bkey_ops[i->k->k.type].atomic_trigger &&
	    ((1U << old.k->type) & BTREE_TRIGGER_WANTS_OLD_AND_NEW)) {
		ret   = bch2_mark_key(trans, old, bkey_i_to_s_c(new),
				BTREE_TRIGGER_INSERT|BTREE_TRIGGER_OVERWRITE|flags);
	} else {
		struct bkey		_deleted = KEY(0, 0, 0);
		struct bkey_s_c		deleted = (struct bkey_s_c) { &_deleted, NULL };

		_deleted.p = i->path->pos;

		ret   = bch2_mark_key(trans, deleted, bkey_i_to_s_c(new),
				BTREE_TRIGGER_INSERT|flags) ?:
			bch2_mark_key(trans, old, deleted,
				BTREE_TRIGGER_OVERWRITE|flags);
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

	if ((i->flags & BTREE_TRIGGER_NORUN) ||
	    !(BTREE_NODE_TYPE_HAS_TRANS_TRIGGERS & (1U << i->bkey_type)))
		return 0;

	if (!i->insert_trigger_run &&
	    !i->overwrite_trigger_run &&
	    bch2_bkey_ops[old.k->type].trans_trigger ==
	    bch2_bkey_ops[i->k->k.type].trans_trigger &&
	    ((1U << old.k->type) & BTREE_TRIGGER_WANTS_OLD_AND_NEW)) {
		i->overwrite_trigger_run = true;
		i->insert_trigger_run = true;
		return bch2_trans_mark_key(trans, i->btree_id, i->level, old, i->k,
					   BTREE_TRIGGER_INSERT|
					   BTREE_TRIGGER_OVERWRITE|
					   i->flags) ?: 1;
	} else if (overwrite && !i->overwrite_trigger_run) {
		i->overwrite_trigger_run = true;
		return bch2_trans_mark_old(trans, i->btree_id, i->level, old, i->flags) ?: 1;
	} else if (!overwrite && !i->insert_trigger_run) {
		i->insert_trigger_run = true;
		return bch2_trans_mark_new(trans, i->btree_id, i->level, i->k, i->flags) ?: 1;
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
	struct btree_insert_entry *i = NULL, *btree_id_start = trans->updates;
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

	trans_for_each_update(trans, i)
		BUG_ON(!(i->flags & BTREE_TRIGGER_NORUN) &&
		       (BTREE_NODE_TYPE_HAS_TRANS_TRIGGERS & (1U << i->bkey_type)) &&
		       (!i->insert_trigger_run || !i->overwrite_trigger_run));

	return 0;
}

static noinline int bch2_trans_commit_run_gc_triggers(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i;
	int ret = 0;

	trans_for_each_update(trans, i) {
		/*
		 * XXX: synchronization of cached update triggers with gc
		 * XXX: synchronization of interior node updates with gc
		 */
		BUG_ON(i->cached || i->level);

		if (gc_visited(c, gc_pos_btree_node(insert_l(i)->b))) {
			ret = run_one_mem_trigger(trans, i, i->flags|BTREE_TRIGGER_GC);
			if (ret)
				break;
		}
	}

	return ret;
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
		trace_and_count(c, trans_restart_fault_inject, trans, trace_ip);
		return btree_trans_restart_nounlock(trans, BCH_ERR_transaction_restart_fault_inject);
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

		/*
		 * Revalidate before calling mem triggers - XXX, ugly:
		 *
		 * - successful btree node splits don't cause transaction
		 *   restarts and will have invalidated the pointer to the bkey
		 *   value
		 * - btree_node_lock_for_insert() -> btree_node_prep_for_write()
		 *   when it has to resort
		 * - btree_key_can_insert_cached() when it has to reallocate
		 *
		 *   Ugly because we currently have no way to tell if the
		 *   pointer's been invalidated, which means it's debatabale
		 *   whether we should be stashing the old key at all.
		 */
		i->old_v = bch2_btree_path_peek_slot(i->path, &i->old_k).v;

		if (unlikely(!test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags))) {
			struct bkey_i *j_k =
				bch2_journal_keys_peek_slot(c, i->btree_id, i->level,
							    i->k->k.p);

			if (j_k) {
				i->old_k = j_k->k;
				i->old_v = &j_k->v;
			}
		}
	}

	/*
	 * Don't get journal reservation until after we know insert will
	 * succeed:
	 */
	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		ret = bch2_trans_journal_res_get(trans,
				JOURNAL_RES_GET_NONBLOCK);
		if (ret)
			return ret;

		if (unlikely(trans->journal_transaction_names))
			journal_transaction_name(trans);
	} else {
		trans->journal_res.seq = c->journal.replay_journal_seq;
	}

	if (unlikely(trans->extra_journal_entries.nr)) {
		memcpy_u64s_small(journal_res_entry(&c->journal, &trans->journal_res),
				  trans->extra_journal_entries.data,
				  trans->extra_journal_entries.nr);

		trans->journal_res.offset	+= trans->extra_journal_entries.nr;
		trans->journal_res.u64s		-= trans->extra_journal_entries.nr;
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

	if (trans->fs_usage_deltas &&
	    bch2_trans_fs_usage_apply(trans, trans->fs_usage_deltas))
		return BTREE_INSERT_NEED_MARK_REPLICAS;

	trans_for_each_update(trans, i)
		if (BTREE_NODE_TYPE_HAS_MEM_TRIGGERS & (1U << i->bkey_type)) {
			ret = run_one_mem_trigger(trans, i, i->flags);
			if (ret)
				return ret;
		}

	if (unlikely(c->gc_pos.phase)) {
		ret = bch2_trans_commit_run_gc_triggers(trans);
		if  (ret)
			return ret;
	}

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		trans_for_each_update(trans, i) {
			struct journal *j = &c->journal;
			struct jset_entry *entry;

			if (i->key_cache_already_flushed)
				continue;

			if (i->flags & BTREE_UPDATE_NOJOURNAL)
				continue;

			if (trans->journal_transaction_names) {
				entry = bch2_journal_add_entry(j, &trans->journal_res,
						       BCH_JSET_ENTRY_overwrite,
						       i->btree_id, i->level,
						       i->old_k.u64s);
				bkey_reassemble(&entry->start[0],
						(struct bkey_s_c) { &i->old_k, i->old_v });
			}

			entry = bch2_journal_add_entry(j, &trans->journal_res,
					       BCH_JSET_ENTRY_btree_keys,
					       i->btree_id, i->level,
					       i->k->k.u64s);
			bkey_copy(&entry->start[0], i->k);
		}

		if (trans->journal_seq)
			*trans->journal_seq = trans->journal_res.seq;
	}

	trans_for_each_update(trans, i) {
		i->k->k.needs_whiteout = false;

		if (!i->cached)
			btree_insert_key_leaf(trans, i);
		else if (!i->key_cache_already_flushed)
			bch2_btree_insert_key_cached(trans, i->path, i->k);
		else {
			bch2_btree_key_cache_drop(trans, i->path);
			btree_path_set_dirty(i->path, BTREE_ITER_NEED_TRAVERSE);
		}
	}

	return ret;
}

static inline int trans_lock_write(struct btree_trans *trans)
{
	struct btree_insert_entry *i;
	int ret;

	trans_for_each_update(trans, i) {
		if (same_leaf_as_prev(trans, i))
			continue;

		ret = bch2_btree_node_lock_write(trans, i->path, &insert_l(i)->b->c);
		if (ret)
			goto fail;

		bch2_btree_node_prep_for_write(trans, i->path, insert_l(i)->b);
	}

	return 0;
fail:
	while (--i >= trans->updates) {
		if (same_leaf_as_prev(trans, i))
			continue;

		bch2_btree_node_unlock_write_inlined(trans, i->path, insert_l(i)->b);
	}

	trace_and_count(trans->c, trans_restart_would_deadlock_write, trans);
	return btree_trans_restart(trans, BCH_ERR_transaction_restart_would_deadlock_write);
}

static noinline void bch2_drop_overwrites_from_journal(struct btree_trans *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_update(trans, i)
		bch2_journal_key_overwritten(trans->c, i->btree_id, i->level, i->k->k.p);
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
	struct printbuf buf = PRINTBUF;
	int ret, u64s_delta = 0;
	int rw = (trans->flags & BTREE_INSERT_JOURNAL_REPLAY) ? READ : WRITE;

	trans_for_each_update(trans, i) {
		if (bch2_bkey_invalid(c, bkey_i_to_s_c(i->k),
				      i->bkey_type, rw, &buf)) {
			printbuf_reset(&buf);
			prt_printf(&buf, "invalid bkey on insert from %s -> %ps",
			       trans->fn, (void *) i->ip_allocated);
			prt_newline(&buf);
			printbuf_indent_add(&buf, 2);

			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(i->k));
			prt_newline(&buf);

			bch2_bkey_invalid(c, bkey_i_to_s_c(i->k),
					  i->bkey_type, rw, &buf);

			bch2_trans_inconsistent(trans, "%s", buf.buf);
			printbuf_exit(&buf);
			return -EINVAL;
		}
		btree_insert_entry_checks(trans, i);
	}

	printbuf_exit(&buf);

	trans_for_each_update(trans, i) {
		if (i->cached)
			continue;

		u64s_delta += !bkey_deleted(&i->k->k) ? i->k->k.u64s : 0;
		u64s_delta -= i->old_btree_u64s;

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
			(trans->flags & JOURNAL_WATERMARK_MASK));
	if (unlikely(ret == -EAGAIN))
		ret = bch2_trans_journal_preres_get_cold(trans,
						trans->journal_preres_u64s, trace_ip);
	if (unlikely(ret))
		return ret;

	ret = trans_lock_write(trans);
	if (unlikely(ret))
		return ret;

	ret = bch2_trans_commit_write_locked(trans, stopped_at, trace_ip);

	if (!ret && unlikely(trans->journal_replay_not_finished))
		bch2_drop_overwrites_from_journal(trans);

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
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			trace_and_count(c, trans_restart_btree_node_split, trans, trace_ip, i->path);
		break;
	case BTREE_INSERT_NEED_MARK_REPLICAS:
		bch2_trans_unlock(trans);

		ret = bch2_replicas_delta_list_mark(c, trans->fs_usage_deltas);
		if (ret)
			break;

		ret = bch2_trans_relock(trans);
		if (ret)
			trace_and_count(c, trans_restart_mark_replicas, trans, trace_ip);
		break;
	case BTREE_INSERT_NEED_JOURNAL_RES:
		bch2_trans_unlock(trans);

		if ((trans->flags & BTREE_INSERT_JOURNAL_RECLAIM) &&
		    !(trans->flags & JOURNAL_WATERMARK_reserved)) {
			ret = -BCH_ERR_journal_reclaim_would_deadlock;
			break;
		}

		ret = bch2_trans_journal_res_get(trans, JOURNAL_RES_GET_CHECK);
		if (ret)
			break;

		ret = bch2_trans_relock(trans);
		if (ret)
			trace_and_count(c, trans_restart_journal_res_get, trans, trace_ip);
		break;
	case BTREE_INSERT_NEED_JOURNAL_RECLAIM:
		bch2_trans_unlock(trans);

		trace_and_count(c, trans_blocked_journal_reclaim, trans, trace_ip);

		wait_event_freezable(c->journal.reclaim_wait,
				     (ret = journal_reclaim_wait_done(c)));
		if (ret < 0)
			break;

		ret = bch2_trans_relock(trans);
		if (ret)
			trace_and_count(c, trans_restart_journal_reclaim, trans, trace_ip);
		break;
	default:
		BUG_ON(ret >= 0);
		break;
	}

	BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart) != !!trans->restarted);

	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOSPC) &&
				!(trans->flags & BTREE_INSERT_NOWAIT) &&
				(trans->flags & BTREE_INSERT_NOFAIL), c,
		"%s: incorrectly got %s\n", __func__, bch2_err_str(ret));

	return ret;
}

static noinline int
bch2_trans_commit_get_rw_cold(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	int ret;

	if (likely(!(trans->flags & BTREE_INSERT_LAZY_RW)) ||
	    test_bit(BCH_FS_STARTED, &c->flags))
		return -EROFS;

	bch2_trans_unlock(trans);

	ret =   bch2_fs_read_write_early(c) ?:
		bch2_trans_relock(trans);
	if (ret)
		return ret;

	percpu_ref_get(&c->writes);
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
	struct btree_insert_entry *i;
	int ret = 0;

	trans_for_each_update(trans, i) {
		ret = bch2_journal_key_insert(c, i->btree_id, i->level, i->k);
		if (ret)
			break;
	}

	return ret;
}

int __bch2_trans_commit(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i = NULL;
	unsigned u64s;
	int ret = 0;

	if (!trans->nr_updates &&
	    !trans->extra_journal_entries.nr)
		goto out_reset;

	if (trans->flags & BTREE_INSERT_GC_LOCK_HELD)
		lockdep_assert_held(&c->gc_lock);

	ret = bch2_trans_commit_run_triggers(trans);
	if (ret)
		goto out_reset;

	if (unlikely(!test_bit(BCH_FS_MAY_GO_RW, &c->flags))) {
		ret = do_bch2_trans_commit_to_journal_replay(trans);
		goto out_reset;
	}

	if (!(trans->flags & BTREE_INSERT_NOCHECK_RW) &&
	    unlikely(!percpu_ref_tryget_live(&c->writes))) {
		ret = bch2_trans_commit_get_rw_cold(trans);
		if (ret)
			goto out_reset;
	}

	EBUG_ON(test_bit(BCH_FS_CLEAN_SHUTDOWN, &c->flags));

	memset(&trans->journal_preres, 0, sizeof(trans->journal_preres));

	trans->journal_u64s		= trans->extra_journal_entries.nr;
	trans->journal_preres_u64s	= 0;

	trans->journal_transaction_names = READ_ONCE(c->opts.journal_transaction_names);

	if (trans->journal_transaction_names)
		trans->journal_u64s += jset_u64s(JSET_ENTRY_LOG_U64s);

	trans_for_each_update(trans, i) {
		BUG_ON(!i->path->should_be_locked);

		ret = bch2_btree_path_upgrade(trans, i->path, i->level + 1);
		if (unlikely(ret))
			goto out;

		BUG_ON(!btree_node_intent_locked(i->path, i->level));

		if (i->key_cache_already_flushed)
			continue;

		/* we're going to journal the key being updated: */
		u64s = jset_u64s(i->k->k.u64s);
		if (i->cached &&
		    likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)))
			trans->journal_preres_u64s += u64s;

		if (i->flags & BTREE_UPDATE_NOJOURNAL)
			continue;

		trans->journal_u64s += u64s;

		/* and we're also going to log the overwrite: */
		if (trans->journal_transaction_names)
			trans->journal_u64s += jset_u64s(i->old_k.u64s);
	}

	if (trans->extra_journal_res) {
		ret = bch2_disk_reservation_add(c, trans->disk_res,
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

	trace_and_count(c, transaction_commit, trans, _RET_IP_);
out:
	bch2_journal_preres_put(&c->journal, &trans->journal_preres);

	if (likely(!(trans->flags & BTREE_INSERT_NOCHECK_RW)))
		percpu_ref_put(&c->writes);
out_reset:
	bch2_trans_reset_updates(trans);

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

static noinline int __check_pos_snapshot_overwritten(struct btree_trans *trans,
					  enum btree_id id,
					  struct bpos pos)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	bch2_trans_iter_init(trans, &iter, id, pos,
			     BTREE_ITER_NOT_EXTENTS|
			     BTREE_ITER_ALL_SNAPSHOTS);
	while (1) {
		k = bch2_btree_iter_prev(&iter);
		ret = bkey_err(k);
		if (ret)
			break;

		if (!k.k)
			break;

		if (bkey_cmp(pos, k.k->p))
			break;

		if (bch2_snapshot_is_ancestor(c, k.k->p.snapshot, pos.snapshot)) {
			ret = 1;
			break;
		}
	}
	bch2_trans_iter_exit(trans, &iter);

	return ret;
}

static inline int check_pos_snapshot_overwritten(struct btree_trans *trans,
					  enum btree_id id,
					  struct bpos pos)
{
	if (!btree_type_has_snapshots(id) ||
	    pos.snapshot == U32_MAX ||
	    !snapshot_t(trans->c, pos.snapshot)->children[0])
		return 0;

	return __check_pos_snapshot_overwritten(trans, id, pos);
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

	if (!bch2_bkey_merge(c, bkey_i_to_s(update), bkey_i_to_s_c(*insert)))
		return 0;

	ret =   check_pos_snapshot_overwritten(trans, iter->btree_id, k.k->p) ?:
		check_pos_snapshot_overwritten(trans, iter->btree_id, (*insert)->k.p);
	if (ret < 0)
		return ret;
	if (ret)
		return 0;

	ret = bch2_btree_delete_at(trans, iter, flags);
	if (ret)
		return ret;

	*insert = update;
	return 0;
}

static noinline int extent_back_merge(struct btree_trans *trans,
				      struct btree_iter *iter,
				      struct bkey_i *insert,
				      struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	int ret;

	ret =   check_pos_snapshot_overwritten(trans, iter->btree_id, insert->k.p) ?:
		check_pos_snapshot_overwritten(trans, iter->btree_id, k.k->p);
	if (ret < 0)
		return ret;
	if (ret)
		return 0;

	bch2_bkey_merge(c, bkey_i_to_s(insert), k);
	return 0;
}

int bch2_trans_update_extent(struct btree_trans *trans,
			     struct btree_iter *orig_iter,
			     struct bkey_i *insert,
			     enum btree_update_flags flags)
{
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
	k = bch2_btree_iter_peek_upto(&iter, POS(insert->k.p.inode, U64_MAX));
	if ((ret = bkey_err(k)))
		goto err;
	if (!k.k)
		goto out;

	if (!bkey_cmp(k.k->p, bkey_start_pos(&insert->k))) {
		if (bch2_bkey_maybe_mergable(k.k, &insert->k)) {
			ret = extent_front_merge(trans, &iter, k, &insert, flags);
			if (ret)
				goto err;
		}

		goto next;
	}

	while (bkey_cmp(insert->k.p, bkey_start_pos(k.k)) > 0) {
		bool front_split = bkey_cmp(bkey_start_pos(k.k), start) < 0;
		bool back_split  = bkey_cmp(k.k->p, insert->k.p) > 0;

		/*
		 * If we're going to be splitting a compressed extent, note it
		 * so that __bch2_trans_commit() can increase our disk
		 * reservation:
		 */
		if (((front_split && back_split) ||
		     ((front_split || back_split) && k.k->p.snapshot != insert->k.p.snapshot)) &&
		    (compressed_sectors = bch2_bkey_sectors_compressed(k)))
			trans->extra_journal_res += compressed_sectors;

		if (front_split) {
			update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_reassemble(update, k);

			bch2_cut_back(start, update);

			bch2_trans_iter_init(trans, &update_iter, btree_id, update->k.p,
					     BTREE_ITER_NOT_EXTENTS|
					     BTREE_ITER_ALL_SNAPSHOTS|
					     BTREE_ITER_INTENT);
			ret   = bch2_btree_iter_traverse(&update_iter) ?:
				bch2_trans_update(trans, &update_iter, update,
						  BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE|
						  flags);
			bch2_trans_iter_exit(trans, &update_iter);

			if (ret)
				goto err;
		}

		if (k.k->p.snapshot != insert->k.p.snapshot &&
		    (front_split || back_split)) {
			update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_reassemble(update, k);

			bch2_cut_front(start, update);
			bch2_cut_back(insert->k.p, update);

			bch2_trans_iter_init(trans, &update_iter, btree_id, update->k.p,
					     BTREE_ITER_NOT_EXTENTS|
					     BTREE_ITER_ALL_SNAPSHOTS|
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
			update = bch2_trans_kmalloc(trans, sizeof(*update));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_init(&update->k);
			update->k.p = k.k->p;

			if (insert->k.p.snapshot != k.k->p.snapshot) {
				update->k.p.snapshot = insert->k.p.snapshot;
				update->k.type = KEY_TYPE_whiteout;
			}

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

		if (back_split) {
			update = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
			if ((ret = PTR_ERR_OR_ZERO(update)))
				goto err;

			bkey_reassemble(update, k);
			bch2_cut_front(insert->k.p, update);

			ret = bch2_trans_update_by_path(trans, iter.path, update,
						  BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE|
						  flags);
			if (ret)
				goto err;
			goto out;
		}
next:
		bch2_btree_iter_advance(&iter);
		k = bch2_btree_iter_peek_upto(&iter, POS(insert->k.p.inode, U64_MAX));
		if ((ret = bkey_err(k)))
			goto err;
		if (!k.k)
			goto out;
	}

	if (bch2_bkey_maybe_mergable(&insert->k, k.k)) {
		ret = extent_back_merge(trans, &iter, insert, k);
		if (ret)
			goto err;
	}
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

/*
 * When deleting, check if we need to emit a whiteout (because we're overwriting
 * something in an ancestor snapshot)
 */
static int need_whiteout_for_snapshot(struct btree_trans *trans,
				      enum btree_id btree_id, struct bpos pos)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u32 snapshot = pos.snapshot;
	int ret;

	if (!bch2_snapshot_parent(trans->c, pos.snapshot))
		return 0;

	pos.snapshot++;

	for_each_btree_key_norestart(trans, iter, btree_id, pos,
			   BTREE_ITER_ALL_SNAPSHOTS|
			   BTREE_ITER_NOPRESERVE, k, ret) {
		if (bkey_cmp(k.k->p, pos))
			break;

		if (bch2_snapshot_is_ancestor(trans->c, snapshot,
					      k.k->p.snapshot)) {
			ret = !bkey_whiteout(k.k);
			break;
		}
	}
	bch2_trans_iter_exit(trans, &iter);

	return ret;
}

static int __must_check
bch2_trans_update_by_path_trace(struct btree_trans *trans, struct btree_path *path,
				struct bkey_i *k, enum btree_update_flags flags,
				unsigned long ip)
{
	struct bch_fs *c = trans->c;
	struct btree_insert_entry *i, n;
	int ret = 0;

	BUG_ON(!path->should_be_locked);

	BUG_ON(trans->nr_updates >= BTREE_ITER_MAX);
	BUG_ON(bpos_cmp(k->k.p, path->pos));

	n = (struct btree_insert_entry) {
		.flags		= flags,
		.bkey_type	= __btree_node_type(path->level, path->btree_id),
		.btree_id	= path->btree_id,
		.level		= path->level,
		.cached		= path->cached,
		.path		= path,
		.k		= k,
		.ip_allocated	= ip,
	};

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
		BUG_ON(i->insert_trigger_run || i->overwrite_trigger_run);

		bch2_path_put(trans, i->path, true);
		i->flags	= n.flags;
		i->cached	= n.cached;
		i->k		= n.k;
		i->path		= n.path;
		i->ip_allocated	= n.ip_allocated;
	} else {
		array_insert_item(trans->updates, trans->nr_updates,
				  i - trans->updates, n);

		i->old_v = bch2_btree_path_peek_slot(path, &i->old_k).v;
		i->old_btree_u64s = !bkey_deleted(&i->old_k) ? i->old_k.u64s : 0;

		if (unlikely(trans->journal_replay_not_finished)) {
			struct bkey_i *j_k =
				bch2_journal_keys_peek_slot(c, n.btree_id, n.level, k->k.p);

			if (j_k) {
				i->old_k = j_k->k;
				i->old_v = &j_k->v;
			}
		}
	}

	__btree_path_get(i->path, true);

	/*
	 * If a key is present in the key cache, it must also exist in the
	 * btree - this is necessary for cache coherency. When iterating over
	 * a btree that's cached in the key cache, the btree iter code checks
	 * the key cache - but the key has to exist in the btree for that to
	 * work:
	 */
	if (path->cached &&
	    bkey_deleted(&i->old_k) &&
	    !(flags & BTREE_UPDATE_NO_KEY_CACHE_COHERENCY)) {
		struct btree_path *btree_path;

		i->key_cache_already_flushed = true;
		i->flags |= BTREE_TRIGGER_NORUN;

		btree_path = bch2_path_get(trans, path->btree_id, path->pos,
					   1, 0, BTREE_ITER_INTENT);

		ret = bch2_btree_path_traverse(trans, btree_path, 0);
		if (ret)
			goto err;

		btree_path_set_should_be_locked(btree_path);
		ret = bch2_trans_update_by_path_trace(trans, btree_path, k, flags, ip);
err:
		bch2_path_put(trans, btree_path, true);
	}

	return ret;
}

static int __must_check
bch2_trans_update_by_path(struct btree_trans *trans, struct btree_path *path,
			  struct bkey_i *k, enum btree_update_flags flags)
{
	return bch2_trans_update_by_path_trace(trans, path, k, flags, _RET_IP_);
}

int __must_check bch2_trans_update(struct btree_trans *trans, struct btree_iter *iter,
				   struct bkey_i *k, enum btree_update_flags flags)
{
	struct btree_path *path = iter->update_path ?: iter->path;
	struct bkey_cached *ck;
	int ret;

	if (iter->flags & BTREE_ITER_IS_EXTENTS)
		return bch2_trans_update_extent(trans, iter, k, flags);

	if (bkey_deleted(&k->k) &&
	    !(flags & BTREE_UPDATE_KEY_CACHE_RECLAIM) &&
	    (iter->flags & BTREE_ITER_FILTER_SNAPSHOTS)) {
		ret = need_whiteout_for_snapshot(trans, iter->btree_id, k->k.p);
		if (unlikely(ret < 0))
			return ret;

		if (ret)
			k->k.type = KEY_TYPE_whiteout;
	}

	/*
	 * Ensure that updates to cached btrees go to the key cache:
	 */
	if (!(flags & BTREE_UPDATE_KEY_CACHE_RECLAIM) &&
	    !path->cached &&
	    !path->level &&
	    btree_id_cached(trans->c, path->btree_id)) {
		if (!iter->key_cache_path ||
		    !iter->key_cache_path->should_be_locked ||
		    bpos_cmp(iter->key_cache_path->pos, k->k.p)) {
			if (!iter->key_cache_path)
				iter->key_cache_path =
					bch2_path_get(trans, path->btree_id, path->pos, 1, 0,
						      BTREE_ITER_INTENT|BTREE_ITER_CACHED);

			iter->key_cache_path =
				bch2_btree_path_set_pos(trans, iter->key_cache_path, path->pos,
							iter->flags & BTREE_ITER_INTENT);

			ret = bch2_btree_path_traverse(trans, iter->key_cache_path,
						       BTREE_ITER_CACHED);
			if (unlikely(ret))
				return ret;

			ck = (void *) iter->key_cache_path->l[0].b;

			if (test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
				trace_and_count(trans->c, trans_restart_key_cache_raced, trans, _RET_IP_);
				return btree_trans_restart(trans, BCH_ERR_transaction_restart_key_cache_raced);
			}

			btree_path_set_should_be_locked(iter->key_cache_path);
		}

		path = iter->key_cache_path;
	}

	return bch2_trans_update_by_path(trans, path, k, flags);
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

int bch2_btree_delete_extent_at(struct btree_trans *trans, struct btree_iter *iter,
				unsigned len, unsigned update_flags)
{
	struct bkey_i *k;

	k = bch2_trans_kmalloc(trans, sizeof(*k));
	if (IS_ERR(k))
		return PTR_ERR(k);

	bkey_init(&k->k);
	k->k.p = iter->pos;
	bch2_key_resize(&k->k, len);
	return bch2_trans_update(trans, iter, k, update_flags);
}

int bch2_btree_delete_at(struct btree_trans *trans,
			 struct btree_iter *iter, unsigned update_flags)
{
	return bch2_btree_delete_extent_at(trans, iter, 0, update_flags);
}

int bch2_btree_delete_range_trans(struct btree_trans *trans, enum btree_id id,
				  struct bpos start, struct bpos end,
				  unsigned update_flags,
				  u64 *journal_seq)
{
	u32 restart_count = trans->restart_count;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, id, start, BTREE_ITER_INTENT);
retry:
	while ((k = bch2_btree_iter_peek(&iter)).k &&
	       !(ret = bkey_err(k) ?:
		 btree_trans_too_many_iters(trans)) &&
	       bkey_cmp(iter.pos, end) < 0) {
		struct disk_reservation disk_res =
			bch2_disk_reservation_init(trans->c, 0);
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

		if (iter.flags & BTREE_ITER_IS_EXTENTS) {
			unsigned max_sectors =
				KEY_SIZE_MAX & (~0 << trans->c->block_bits);

			/* create the biggest key we can */
			bch2_key_resize(&delete.k, max_sectors);
			bch2_cut_back(end, &delete);

			ret = bch2_extent_trim_atomic(trans, &iter, &delete);
			if (ret)
				break;
		}

		ret   = bch2_trans_update(trans, &iter, &delete, update_flags) ?:
			bch2_trans_commit(trans, &disk_res, journal_seq,
					  BTREE_INSERT_NOFAIL);
		bch2_disk_reservation_put(trans->c, &disk_res);
		if (ret)
			break;
	}

	if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
		bch2_trans_begin(trans);
		ret = 0;
		goto retry;
	}

	bch2_trans_iter_exit(trans, &iter);

	if (!ret && trans_was_restarted(trans, restart_count))
		ret = -BCH_ERR_transaction_restart_nested;
	return ret;
}

/*
 * bch_btree_delete_range - delete everything within a given range
 *
 * Range is a half open interval - [start, end)
 */
int bch2_btree_delete_range(struct bch_fs *c, enum btree_id id,
			    struct bpos start, struct bpos end,
			    unsigned update_flags,
			    u64 *journal_seq)
{
	int ret = bch2_trans_run(c,
			bch2_btree_delete_range_trans(&trans, id, start, end,
						      update_flags, journal_seq));
	if (ret == -BCH_ERR_transaction_restart_nested)
		ret = 0;
	return ret;
}

int bch2_trans_log_msg(struct btree_trans *trans, const char *msg)
{
	unsigned len = strlen(msg);
	unsigned u64s = DIV_ROUND_UP(len, sizeof(u64));
	struct jset_entry_log *l;
	int ret;

	ret = darray_make_room(&trans->extra_journal_entries, jset_u64s(u64s));
	if (ret)
		return ret;

	l = (void *) &darray_top(trans->extra_journal_entries);
	l->entry.u64s		= cpu_to_le16(u64s);
	l->entry.btree_id	= 0;
	l->entry.level		= 1;
	l->entry.type		= BCH_JSET_ENTRY_log;
	l->entry.pad[0]		= 0;
	l->entry.pad[1]		= 0;
	l->entry.pad[2]		= 0;
	memcpy(l->d, msg, len);
	while (len & 7)
		l->d[len++] = '\0';

	trans->extra_journal_entries.nr += jset_u64s(u64s);
	return 0;
}
