// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/foreground.h"
#include "alloc/replicas.h"

#include "btree/bkey_methods.h"
#include "btree/bkey_buf.h"
#include "btree/check.h"
#include "btree/key_cache.h"
#include "btree/locking.h"
#include "btree/node_scan.h"
#include "btree/interior.h"
#include "btree/journal_overlay.h"
#include "btree/read.h"

#include "data/ec.h"
#include "data/extents.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/reflink.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/passes.h"
#include "init/recovery.h"

#include "journal/journal.h"

#include "sb/io.h"

#include "util/enumerated_ref.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>

static const char * const bch2_gc_phase_strs[] = {
#define x(n)	#n,
	GC_PHASES()
#undef x
	NULL
};

void bch2_gc_pos_to_text(struct printbuf *out, struct gc_pos *p)
{
	prt_str(out, bch2_gc_phase_strs[p->phase]);
	prt_char(out, ' ');
	bch2_btree_id_level_to_text(out, p->btree, p->level);
	prt_char(out, ' ');
	bch2_bpos_to_text(out, p->pos);
}

static struct bkey_s unsafe_bkey_s_c_to_s(struct bkey_s_c k)
{
	return (struct bkey_s) {{{
		(struct bkey *) k.k,
		(struct bch_val *) k.v
	}}};
}

static inline void __gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	guard(preempt)();
	write_seqcount_begin(&c->gc_pos_lock);
	c->gc_pos = new_pos;
	write_seqcount_end(&c->gc_pos_lock);
}

static inline void gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	BUG_ON(gc_pos_cmp(new_pos, c->gc_pos) < 0);
	__gc_pos_set(c, new_pos);
}

static void btree_ptr_to_v2(struct btree *b, struct bkey_i_btree_ptr_v2 *dst)
{
	switch (b->key.k.type) {
	case KEY_TYPE_btree_ptr: {
		struct bkey_i_btree_ptr *src = bkey_i_to_btree_ptr(&b->key);

		dst->k.p		= src->k.p;
		dst->v.mem_ptr		= 0;
		dst->v.seq		= b->data->keys.seq;
		dst->v.sectors_written	= 0;
		dst->v.flags		= 0;
		dst->v.min_key		= b->data->min_key;
		set_bkey_val_bytes(&dst->k, sizeof(dst->v) + bkey_val_bytes(&src->k));
		memcpy(dst->v.start, src->v.start, bkey_val_bytes(&src->k));
		break;
	}
	case KEY_TYPE_btree_ptr_v2:
		bkey_copy(&dst->k_i, &b->key);
		break;
	default:
		BUG();
	}
}

static int set_node_min(struct bch_fs *c, struct btree *b, struct bpos new_min)
{
	struct bkey_i_btree_ptr_v2 *new;
	int ret;

	if (c->opts.verbose) {
		CLASS(printbuf, buf)();

		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
		prt_str(&buf, " -> ");
		bch2_bpos_to_text(&buf, new_min);

		bch_info(c, "%s(): %s", __func__, buf.buf);
	}

	new = kmalloc_array(BKEY_BTREE_PTR_U64s_MAX, sizeof(u64), GFP_KERNEL);
	if (!new)
		return bch_err_throw(c, ENOMEM_gc_repair_key);

	btree_ptr_to_v2(b, new);
	b->data->min_key	= new_min;
	new->v.min_key		= new_min;
	SET_BTREE_PTR_RANGE_UPDATED(&new->v, true);

	ret = bch2_journal_key_insert_take(c, b->c.btree_id, b->c.level + 1, &new->k_i);
	if (ret) {
		kfree(new);
		return ret;
	}

	bch2_btree_node_drop_keys_outside_node(b);
	bkey_copy(&b->key, &new->k_i);
	return 0;
}

static int set_node_max(struct bch_fs *c, struct btree *b, struct bpos new_max)
{
	struct bkey_i_btree_ptr_v2 *new;

	if (c->opts.verbose) {
		CLASS(printbuf, buf)();

		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
		prt_str(&buf, " -> ");
		bch2_bpos_to_text(&buf, new_max);

		bch_info(c, "%s(): %s", __func__, buf.buf);
	}

	try(bch2_journal_key_delete(c, b->c.btree_id, b->c.level + 1, b->key.k.p));

	new = kmalloc_array(BKEY_BTREE_PTR_U64s_MAX, sizeof(u64), GFP_KERNEL);
	if (!new)
		return bch_err_throw(c, ENOMEM_gc_repair_key);

	btree_ptr_to_v2(b, new);
	b->data->max_key	= new_max;
	new->k.p		= new_max;
	SET_BTREE_PTR_RANGE_UPDATED(&new->v, true);

	int ret = bch2_journal_key_insert_take(c, b->c.btree_id, b->c.level + 1, &new->k_i);
	if (ret) {
		kfree(new);
		return ret;
	}

	bch2_btree_node_drop_keys_outside_node(b);

	guard(mutex)(&c->btree_cache.lock);
	__bch2_btree_node_hash_remove(&c->btree_cache, b);

	bkey_copy(&b->key, &new->k_i);
	ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
	BUG_ON(ret);
	return 0;
}

static int btree_check_node_boundaries(struct btree_trans *trans, struct btree *b,
				       struct btree *prev, struct btree *cur,
				       struct bpos *pulled_from_scan)
{
	struct bch_fs *c = trans->c;
	struct bpos expected_start = !prev
		? b->data->min_key
		: bpos_successor(prev->key.k.p);
	CLASS(printbuf, buf)();
	int ret = 0;

	BUG_ON(b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	       !bpos_eq(bkey_i_to_btree_ptr_v2(&b->key)->v.min_key,
			b->data->min_key));

	if (bpos_eq(expected_start, cur->data->min_key))
		return 0;

	prt_printf(&buf, " at ");
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_printf(&buf, ":\nparent: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	if (prev) {
		prt_printf(&buf, "\nprev: ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&prev->key));
	}

	prt_str(&buf, "\nnext: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&cur->key));

	if (bpos_lt(expected_start, cur->data->min_key)) {				/* gap */
		if (b->c.level == 1 &&
		    bpos_lt(*pulled_from_scan, cur->data->min_key)) {
			try(bch2_get_scanned_nodes(c, b->c.btree_id, 0,
						   expected_start,
						   bpos_predecessor(cur->data->min_key)));

			*pulled_from_scan = cur->data->min_key;
			ret = bch_err_throw(c, topology_repair_did_fill_from_scan);
		} else {
			if (mustfix_fsck_err(trans, btree_node_topology_gap_between_nodes,
					     "gap between btree nodes%s", buf.buf))
				ret = set_node_min(c, cur, expected_start);
		}
	} else {									/* overlap */
		if (prev && BTREE_NODE_SEQ(cur->data) > BTREE_NODE_SEQ(prev->data)) {	/* cur overwrites prev */
			if (bpos_ge(prev->data->min_key, cur->data->min_key)) {		/* fully? */
				if (mustfix_fsck_err(trans, btree_node_topology_overwritten_by_next_node,
						     "btree node overwritten by next node%s", buf.buf))
					ret = bch_err_throw(c, topology_repair_drop_prev_node);
			} else {
				if (mustfix_fsck_err(trans, btree_node_topology_bad_max_key,
						     "btree node with incorrect max_key%s", buf.buf))
					ret = set_node_max(c, prev,
							   bpos_predecessor(cur->data->min_key));
			}
		} else {
			if (bpos_ge(expected_start, cur->data->max_key)) {		/* fully? */
				if (mustfix_fsck_err(trans, btree_node_topology_overwritten_by_prev_node,
						     "btree node overwritten by prev node%s", buf.buf))
					ret = bch_err_throw(c, topology_repair_drop_this_node);
			} else {
				if (mustfix_fsck_err(trans, btree_node_topology_bad_min_key,
						     "btree node with incorrect min_key%s", buf.buf))
					ret = set_node_min(c, cur, expected_start);
			}
		}
	}
fsck_err:
	return ret;
}

static int btree_check_root_boundaries(struct btree_trans *trans, struct btree *b)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	BUG_ON(b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	       !bpos_eq(bkey_i_to_btree_ptr_v2(&b->key)->v.min_key,
			b->data->min_key));

	CLASS(printbuf, buf)();
	prt_str(&buf, "  at ");
	bch2_btree_pos_to_text(&buf, c, b);

	if (mustfix_fsck_err_on(!bpos_eq(b->data->min_key, POS_MIN),
				trans, btree_node_topology_bad_root_min_key,
			     "btree root with incorrect min_key%s", buf.buf))
		try(set_node_min(c, b, POS_MIN));

	if (mustfix_fsck_err_on(!bpos_eq(b->data->max_key, SPOS_MAX),
				trans, btree_node_topology_bad_root_max_key,
			     "btree root with incorrect min_key%s", buf.buf))
		try(set_node_max(c, b, SPOS_MAX));
fsck_err:
	return ret;
}

static int btree_repair_node_end(struct btree_trans *trans, struct btree *b,
				 struct btree *child, struct bpos *pulled_from_scan)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (bpos_eq(child->key.k.p, b->key.k.p))
		return 0;

	CLASS(printbuf, buf)();
	prt_printf(&buf, "\nat: ");
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_printf(&buf, "\nparent: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	prt_str(&buf, "\nchild: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&child->key));

	if (mustfix_fsck_err(trans, btree_node_topology_bad_max_key,
			     "btree node with incorrect max_key%s", buf.buf)) {
		if (b->c.level == 1 &&
		    bpos_lt(*pulled_from_scan, b->key.k.p)) {
			try(bch2_get_scanned_nodes(c, b->c.btree_id, 0,
						   bpos_successor(child->key.k.p), b->key.k.p));

			*pulled_from_scan = b->key.k.p;
			return bch_err_throw(c, topology_repair_did_fill_from_scan);
		} else {
			try(set_node_max(c, child, b->key.k.p));
		}
	}
fsck_err:
	return ret;
}

static int bch2_btree_repair_topology_recurse(struct btree_trans *trans, struct btree *b,
					      struct bpos *pulled_from_scan)
{
	struct bch_fs *c = trans->c;
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	struct btree *prev = NULL, *cur = NULL;
	bool have_child, new_pass = false;
	CLASS(printbuf, buf)();
	int ret = 0;

	if (!b->c.level)
		return 0;

	struct bkey_buf prev_k __cleanup(bch2_bkey_buf_exit);
	struct bkey_buf cur_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&prev_k);
	bch2_bkey_buf_init(&cur_k);
again:
	cur = prev = NULL;
	have_child = new_pass = false;
	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);
	iter.prefetch = true;

	while ((k = bch2_btree_and_journal_iter_peek(c, &iter)).k) {
		BUG_ON(bpos_lt(k.k->p, b->data->min_key));
		BUG_ON(bpos_gt(k.k->p, b->data->max_key));

		bch2_btree_and_journal_iter_advance(&iter);
		bch2_bkey_buf_reassemble(&cur_k, k);

		cur = bch2_btree_node_get_noiter(trans, cur_k.k,
					b->c.btree_id, b->c.level - 1,
					false);
		ret = PTR_ERR_OR_ZERO(cur);

		printbuf_reset(&buf);
		bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level - 1);
		prt_char(&buf, ' ');
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(cur_k.k));

		if (bch2_err_matches(ret, EIO)) {
			bch2_btree_node_evict(trans, cur_k.k);
			cur = NULL;
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			if (ret)
				break;
			continue;
		}

		bch_err_msg(c, ret, "getting btree node");
		if (ret)
			break;

		if (bch2_btree_node_is_stale(c, cur)) {
			bch_info(c, "btree node older than nodes found by scanning\n  %s", buf.buf);
			six_unlock_read(&cur->c.lock);
			bch2_btree_node_evict(trans, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			cur = NULL;
			if (ret)
				break;
			continue;
		}

		ret = lockrestart_do(trans,
			btree_check_node_boundaries(trans, b, prev, cur, pulled_from_scan));
		if (ret && !bch2_err_matches(ret, BCH_ERR_topology_repair))
			goto err;

		if (bch2_err_matches(ret, BCH_ERR_topology_repair_did_fill_from_scan)) {
			new_pass = true;
			ret = 0;
		}

		if (bch2_err_matches(ret, BCH_ERR_topology_repair_drop_this_node)) {
			six_unlock_read(&cur->c.lock);
			bch2_btree_node_evict(trans, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			cur = NULL;
			if (ret)
				break;
			continue;
		}

		if (prev)
			six_unlock_read(&prev->c.lock);
		prev = NULL;

		if (bch2_err_matches(ret, BCH_ERR_topology_repair_drop_prev_node)) {
			bch_info(c, "dropped prev node");
			bch2_btree_node_evict(trans, prev_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, prev_k.k->k.p);
			if (ret)
				break;

			bch2_btree_and_journal_iter_exit(&iter);
			goto again;
		} else if (ret)
			break;

		prev = cur;
		cur = NULL;
		bch2_bkey_buf_copy(&prev_k, cur_k.k);
	}

	if (!ret && !IS_ERR_OR_NULL(prev)) {
		BUG_ON(cur);
		ret = lockrestart_do(trans,
			btree_repair_node_end(trans, b, prev, pulled_from_scan));
		if (bch2_err_matches(ret, BCH_ERR_topology_repair_did_fill_from_scan)) {
			new_pass = true;
			ret = 0;
		}
	}

	if (!IS_ERR_OR_NULL(prev))
		six_unlock_read(&prev->c.lock);
	prev = NULL;
	if (!IS_ERR_OR_NULL(cur))
		six_unlock_read(&cur->c.lock);
	cur = NULL;

	if (ret)
		goto err;

	bch2_btree_and_journal_iter_exit(&iter);

	if (new_pass)
		goto again;

	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);
	iter.prefetch = true;

	while ((k = bch2_btree_and_journal_iter_peek(c, &iter)).k) {
		bch2_bkey_buf_reassemble(&cur_k, k);
		bch2_btree_and_journal_iter_advance(&iter);

		cur = bch2_btree_node_get_noiter(trans, cur_k.k,
					b->c.btree_id, b->c.level - 1,
					false);
		ret = PTR_ERR_OR_ZERO(cur);

		bch_err_msg(c, ret, "getting btree node");
		if (ret)
			goto err;

		ret = bch2_btree_repair_topology_recurse(trans, cur, pulled_from_scan);
		six_unlock_read(&cur->c.lock);
		cur = NULL;

		if (bch2_err_matches(ret, BCH_ERR_topology_repair_drop_this_node)) {
			bch2_btree_node_evict(trans, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			new_pass = true;
		}

		if (ret)
			goto err;

		have_child = true;
	}

	printbuf_reset(&buf);
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_newline(&buf);
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	/*
	 * XXX: we're not passing the trans object here because we're not set up
	 * to handle a transaction restart - this code needs to be rewritten
	 * when we start doing online topology repair
	 */
	bch2_trans_unlock_long(trans);
	if (mustfix_fsck_err_on(!have_child,
			c, btree_node_topology_interior_node_empty,
			"empty interior btree node at %s", buf.buf))
		ret = bch_err_throw(c, topology_repair_drop_this_node);
err:
fsck_err:
	if (!IS_ERR_OR_NULL(prev))
		six_unlock_read(&prev->c.lock);
	if (!IS_ERR_OR_NULL(cur))
		six_unlock_read(&cur->c.lock);

	bch2_btree_and_journal_iter_exit(&iter);

	if (!ret && new_pass)
		goto again;

	BUG_ON(!ret && bch2_btree_node_check_topology(trans, b));

	if (!bch2_err_matches(ret, BCH_ERR_topology_repair))
		bch_err_fn(c, ret);
	return ret;
}

static int bch2_topology_check_root(struct btree_trans *trans, enum btree_id btree,
				    bool *reconstructed_root)
{
	struct bch_fs *c = trans->c;
	struct btree_root *r = bch2_btree_id_root(c, btree);

	if (!r->error)
		return 0;

	CLASS(printbuf, buf)();
	int ret = 0;

	if (!btree_id_recovers_from_scan(btree)) {
		r->alive = false;
		r->error = 0;
		bch2_btree_root_alloc_fake_trans(trans, btree, 0);
		ret = bch2_btree_lost_data(c, &buf, btree);
		bch2_print_str(c, KERN_NOTICE, buf.buf);
		goto out;
	}

	bch2_btree_id_to_text(&buf, btree);
	bch_info(c, "btree root %s unreadable, must recover from scan", buf.buf);

	ret = bch2_btree_has_scanned_nodes(c, btree);
	if (ret < 0)
		goto err;

	if (!ret) {
		__fsck_err(trans,
			   FSCK_CAN_FIX|(btree_id_can_reconstruct(btree) ? FSCK_AUTOFIX : 0),
			   btree_root_unreadable_and_scan_found_nothing,
			   "no nodes found for btree %s, continue?", buf.buf);

		r->alive = false;
		r->error = 0;
		bch2_btree_root_alloc_fake_trans(trans, btree, 0);
	} else {
		r->alive = false;
		r->error = 0;
		bch2_btree_root_alloc_fake_trans(trans, btree, 1);

		bch2_shoot_down_journal_keys(c, btree, 1, BTREE_MAX_DEPTH, POS_MIN, SPOS_MAX);
		try(bch2_get_scanned_nodes(c, btree, 0, POS_MIN, SPOS_MAX));
	}
out:
	*reconstructed_root = true;
	return 0;
err:
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

int bch2_check_topology(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	struct bpos pulled_from_scan = POS_MIN;
	int ret = 0;

	bch2_trans_srcu_unlock(trans);

	for (unsigned i = 0; i < btree_id_nr_alive(c) && !ret; i++) {
		bool reconstructed_root = false;
recover:
		ret = lockrestart_do(trans, bch2_topology_check_root(trans, i, &reconstructed_root));
		if (ret)
			break;

		struct btree_root *r = bch2_btree_id_root(c, i);
		struct btree *b = r->b;

		btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);
		ret =   btree_check_root_boundaries(trans, b) ?:
			bch2_btree_repair_topology_recurse(trans, b, &pulled_from_scan);
		six_unlock_read(&b->c.lock);

		if (bch2_err_matches(ret, BCH_ERR_topology_repair_drop_this_node)) {
			scoped_guard(mutex, &c->btree_cache.lock)
				bch2_btree_node_hash_remove(&c->btree_cache, b);

			r->b = NULL;

			if (!reconstructed_root) {
				r->error = -EIO;
				goto recover;
			}

			CLASS(printbuf, buf)();
			bch2_btree_id_to_text(&buf, i);
			bch_err(c, "empty btree root %s", buf.buf);
			bch2_btree_root_alloc_fake_trans(trans, i, 0);
			r->alive = false;
			ret = 0;
		}
	}

	return ret;
}

/* marking of btree keys/nodes: */

static int bch2_gc_mark_key(struct btree_trans *trans, enum btree_id btree_id,
			    unsigned level, struct btree **prev,
			    struct btree_iter *iter, struct bkey_s_c k,
			    bool initial)
{
	struct bch_fs *c = trans->c;

	if (iter) {
		struct btree_path *path = btree_iter_path(trans, iter);
		struct btree *b = path_l(path)->b;

		if (*prev != b)
			try(bch2_btree_node_check_topology(trans, b));
		*prev = b;
	}

	struct bkey deleted = KEY(0, 0, 0);
	struct bkey_s_c old = (struct bkey_s_c) { &deleted, NULL };
	CLASS(printbuf, buf)();
	int ret = 0;

	deleted.p = k.k->p;

	if (initial) {
		BUG_ON(static_branch_unlikely(&bch2_journal_seq_verify) &&
		       k.k->bversion.lo > atomic64_read(&c->journal.seq));

		if (fsck_err_on(btree_id != BTREE_ID_accounting &&
				k.k->bversion.lo > atomic64_read(&c->key_version),
				trans, bkey_version_in_future,
				"key version number higher than recorded %llu\n%s",
				atomic64_read(&c->key_version),
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			atomic64_set(&c->key_version, k.k->bversion.lo);
	}

	if (mustfix_fsck_err_on(level && !bch2_dev_btree_bitmap_marked(c, k),
				trans, btree_bitmap_not_marked,
				"btree ptr not marked in member info btree allocated bitmap\n%s",
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, k),
				 buf.buf))) {
		guard(mutex)(&c->sb_lock);
		bch2_dev_btree_bitmap_mark(c, k);
		bch2_write_super(c);
	}

	/*
	 * We require a commit before key_trigger() because
	 * key_trigger(BTREE_TRIGGER_GC) is not idempotant; we'll calculate the
	 * wrong result if we run it multiple times.
	 */
	unsigned flags = !iter ? BTREE_TRIGGER_is_root : 0;

	try(bch2_key_trigger(trans, btree_id, level, old, unsafe_bkey_s_c_to_s(k),
			     BTREE_TRIGGER_check_repair|flags));

	if (bch2_trans_has_updates(trans)) {
		CLASS(disk_reservation, res)(c);
		return bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc) ?:
			-BCH_ERR_transaction_restart_nested;
	}

	try(bch2_key_trigger(trans, btree_id, level, old, unsafe_bkey_s_c_to_s(k),
			     BTREE_TRIGGER_gc|BTREE_TRIGGER_insert|flags));
fsck_err:
	return ret;
}

static int bch2_gc_btree_root(struct btree_trans *trans, enum btree_id btree, bool initial)
{
	struct bch_fs *c = trans->c;
	CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0,
				     bch2_btree_id_root(c, btree)->b->c.level, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	if (b != btree_node_root(c, b))
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_root_race);

	gc_pos_set(c, gc_pos_btree(btree, b->c.level + 1, SPOS_MAX));
	struct bkey_s_c k = bkey_i_to_s_c(&b->key);
	return bch2_gc_mark_key(trans, btree, b->c.level + 1, NULL, NULL, k, initial);
}

static int bch2_gc_btree(struct btree_trans *trans,
			 struct progress_indicator_state *progress,
			 enum btree_id btree, unsigned target_depth,
			 bool initial)
{
	for (unsigned level = target_depth; level < BTREE_MAX_DEPTH; level++) {
		struct btree *prev = NULL;
		CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0, level, BTREE_ITER_prefetch);

		try(for_each_btree_key_continue(trans, iter, 0, k, ({
			gc_pos_set(trans->c, gc_pos_btree(btree, level, k.k->p));
			bch2_progress_update_iter(trans, progress, &iter, "check_allocations") ?:
			bch2_gc_mark_key(trans, btree, level, &prev, &iter, k, initial);
		})));
	}

	return lockrestart_do(trans, bch2_gc_btree_root(trans, btree, initial));
}

static inline int btree_id_gc_phase_cmp(enum btree_id l, enum btree_id r)
{
	return cmp_int(gc_btree_order(l), gc_btree_order(r));
}

static int bch2_gc_btrees(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(printbuf, buf)();
	int ret = 0;

	struct progress_indicator_state progress;
	bch2_progress_init_inner(&progress, c, ~0ULL, ~0ULL);

	enum btree_id ids[BTREE_ID_NR];
	for (unsigned i = 0; i < BTREE_ID_NR; i++)
		ids[i] = i;
	bubble_sort(ids, BTREE_ID_NR, btree_id_gc_phase_cmp);

	for (unsigned i = 0; i < btree_id_nr_alive(c) && !ret; i++) {
		unsigned btree = i < BTREE_ID_NR ? ids[i] : i;

		if (IS_ERR_OR_NULL(bch2_btree_id_root(c, btree)->b))
			continue;


		unsigned target_depth = BIT_ULL(btree) & btree_leaf_has_triggers_mask ? 0 : 1;

		/*
		 * In fsck, we need to make sure every leaf node is readable
		 * before going RW, otherwise we can no longer rewind inside
		 * btree_lost_data to repair during the current fsck run.
		 *
		 * Otherwise, we can delay the repair to the next
		 * mount or offline fsck.
		 */
		if (test_bit(BCH_FS_in_fsck, &c->flags))
			target_depth = 0;

		ret = bch2_gc_btree(trans, &progress, btree, target_depth, true);
	}

	bch_err_fn(c, ret);
	return ret;
}

static int bch2_mark_superblocks(struct bch_fs *c)
{
	gc_pos_set(c, gc_phase(GC_PHASE_sb));

	return bch2_trans_mark_dev_sbs_flags(c, BTREE_TRIGGER_gc);
}

static void bch2_gc_free(struct bch_fs *c)
{
	bch2_accounting_gc_free(c);

	genradix_free(&c->reflink_gc_table);
	genradix_free(&c->gc_stripes);

	for_each_member_device(c, ca)
		genradix_free(&ca->buckets_gc);
}

static int bch2_gc_start(struct bch_fs *c)
{
	for_each_member_device(c, ca) {
		int ret = bch2_dev_usage_init(ca, true);
		if (ret) {
			bch2_dev_put(ca);
			return ret;
		}
	}

	return 0;
}

/* returns true if not equal */
static inline bool bch2_alloc_v4_cmp(struct bch_alloc_v4 l,
				     struct bch_alloc_v4 r)
{
	return  l.gen != r.gen				||
		l.oldest_gen != r.oldest_gen		||
		l.data_type != r.data_type		||
		l.dirty_sectors	!= r.dirty_sectors	||
		l.stripe_sectors != r.stripe_sectors	||
		l.cached_sectors != r.cached_sectors	 ||
		l.stripe_redundancy != r.stripe_redundancy ||
		l.stripe != r.stripe;
}

static int bch2_alloc_write_key(struct btree_trans *trans,
				struct btree_iter *iter,
				struct bch_dev *ca,
				struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_alloc_v4 *a;
	struct bch_alloc_v4 old_gc, gc, old_convert, new;
	const struct bch_alloc_v4 *old;
	int ret;

	if (!bucket_valid(ca, k.k->p.offset))
		return 0;

	old = bch2_alloc_to_v4(k, &old_convert);
	gc = new = *old;

	__bucket_m_to_alloc(&gc, *gc_bucket(ca, iter->pos.offset));

	old_gc = gc;

	if ((old->data_type == BCH_DATA_sb ||
	     old->data_type == BCH_DATA_journal) &&
	    !bch2_dev_is_online(ca)) {
		gc.data_type = old->data_type;
		gc.dirty_sectors = old->dirty_sectors;
	}

	/*
	 * gc.data_type doesn't yet include need_discard & need_gc_gen states -
	 * fix that here:
	 */
	alloc_data_type_set(&gc, gc.data_type);
	if (gc.data_type != old_gc.data_type ||
	    gc.dirty_sectors != old_gc.dirty_sectors) {
		try(bch2_alloc_key_to_dev_counters(trans, ca, &old_gc, &gc, BTREE_TRIGGER_gc));

		/*
		 * Ugly: alloc_key_to_dev_counters(..., BTREE_TRIGGER_gc) is not
		 * safe w.r.t. transaction restarts, so fixup the gc_bucket so
		 * we don't run it twice:
		 */
		struct bucket *gc_m = gc_bucket(ca, iter->pos.offset);
		gc_m->data_type = gc.data_type;
		gc_m->dirty_sectors = gc.dirty_sectors;
	}

	if (fsck_err_on(new.data_type != gc.data_type,
			trans, alloc_key_data_type_wrong,
			"bucket %llu:%llu gen %u has wrong data_type"
			": got %s, should be %s",
			iter->pos.inode, iter->pos.offset,
			gc.gen,
			bch2_data_type_str(new.data_type),
			bch2_data_type_str(gc.data_type)))
		new.data_type = gc.data_type;

#define copy_bucket_field(_errtype, _f)					\
	if (fsck_err_on(new._f != gc._f,				\
			trans, _errtype,				\
			"bucket %llu:%llu gen %u data type %s has wrong " #_f	\
			": got %llu, should be %llu",			\
			iter->pos.inode, iter->pos.offset,		\
			gc.gen,						\
			bch2_data_type_str(gc.data_type),		\
			(u64) new._f, (u64) gc._f))				\
		new._f = gc._f;						\

	copy_bucket_field(alloc_key_gen_wrong,			gen);
	copy_bucket_field(alloc_key_dirty_sectors_wrong,	dirty_sectors);
	copy_bucket_field(alloc_key_stripe_sectors_wrong,	stripe_sectors);
	copy_bucket_field(alloc_key_cached_sectors_wrong,	cached_sectors);
	copy_bucket_field(alloc_key_stripe_wrong,		stripe);
	copy_bucket_field(alloc_key_stripe_redundancy_wrong,	stripe_redundancy);
#undef copy_bucket_field

	if (!bch2_alloc_v4_cmp(*old, new))
		return 0;

	a = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	a->v = new;

	/*
	 * The trigger normally makes sure these are set, but we're not running
	 * triggers:
	 */
	if (a->v.data_type == BCH_DATA_cached && !a->v.io_time[READ])
		a->v.io_time[READ] = max_t(u64, 1, atomic64_read(&c->io_clock[READ].now));

	ret = bch2_trans_update(trans, iter, &a->k_i, BTREE_TRIGGER_norun);
fsck_err:
	return ret;
}

static int bch2_gc_alloc_done(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	int ret = 0;

	for_each_member_device(c, ca) {
		ret = for_each_btree_key_max_commit(trans, iter, BTREE_ID_alloc,
					POS(ca->dev_idx, ca->mi.first_bucket),
					POS(ca->dev_idx, ca->mi.nbuckets - 1),
					BTREE_ITER_slots|BTREE_ITER_prefetch, k,
					NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
				bch2_alloc_write_key(trans, &iter, ca, k));
		if (ret) {
			bch2_dev_put(ca);
			break;
		}
	}

	bch_err_fn(c, ret);
	return ret;
}

static int bch2_gc_alloc_start(struct bch_fs *c)
{
	int ret = 0;

	for_each_member_device(c, ca) {
		ret = genradix_prealloc(&ca->buckets_gc, ca->mi.nbuckets, GFP_KERNEL);
		if (ret) {
			bch2_dev_put(ca);
			ret = bch_err_throw(c, ENOMEM_gc_alloc_start);
			break;
		}
	}

	bch_err_fn(c, ret);
	return ret;
}

static int bch2_gc_write_stripes_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	const struct bch_stripe *s;
	struct gc_stripe *m;
	bool bad = false;
	unsigned i;
	int ret = 0;

	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	s = bkey_s_c_to_stripe(k).v;
	m = genradix_ptr(&c->gc_stripes, k.k->p.offset);

	for (i = 0; i < s->nr_blocks; i++) {
		u32 old = stripe_blockcount_get(s, i);
		u32 new = (m ? m->block_sectors[i] : 0);

		if (old != new) {
			prt_printf(&buf, "stripe block %u has wrong sector count: got %u, should be %u\n",
				   i, old, new);
			bad = true;
		}
	}

	if (bad)
		bch2_bkey_val_to_text(&buf, c, k);

	if (fsck_err_on(bad,
			trans, stripe_sector_count_wrong,
			"%s", buf.buf)) {
		struct bkey_i_stripe *new =
			errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k)));

		bkey_reassemble(&new->k_i, k);

		for (i = 0; i < new->v.nr_blocks; i++)
			stripe_blockcount_set(&new->v, i, m ? m->block_sectors[i] : 0);

		ret = bch2_trans_update(trans, iter, &new->k_i, 0);
	}
fsck_err:
	return ret;
}

static int bch2_gc_stripes_done(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter,
				BTREE_ID_stripes, POS_MIN,
				BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_gc_write_stripes_key(trans, &iter, k));
}

/**
 * bch2_check_allocations - walk all references to buckets, and recompute them:
 *
 * @c:			filesystem object
 *
 * Returns: 0 on success, or standard errcode on failure
 *
 * Order matters here:
 *  - Concurrent GC relies on the fact that we have a total ordering for
 *    everything that GC walks - see  gc_will_visit_node(),
 *    gc_will_visit_root()
 *
 *  - also, references move around in the course of index updates and
 *    various other crap: everything needs to agree on the ordering
 *    references are allowed to move around in - e.g., we're allowed to
 *    start with a reference owned by an open_bucket (the allocator) and
 *    move it to the btree, but not the reverse.
 *
 *    This is necessary to ensure that gc doesn't miss references that
 *    move around - if references move backwards in the ordering GC
 *    uses, GC could skip past them
 */
int bch2_check_allocations(struct bch_fs *c)
{
	int ret;

	guard(rwsem_read)(&c->state_lock);
	guard(rwsem_write)(&c->gc_lock);

	bch2_btree_interior_updates_flush(c);

	ret   = bch2_gc_accounting_start(c) ?:
		bch2_gc_start(c) ?:
		bch2_gc_alloc_start(c) ?:
		bch2_gc_reflink_start(c);
	if (ret)
		goto out;

	gc_pos_set(c, gc_phase(GC_PHASE_start));

	ret = bch2_mark_superblocks(c);
	bch_err_msg(c, ret, "marking superblocks");
	if (ret)
		goto out;

	ret = bch2_gc_btrees(c);
	if (ret)
		goto out;

	c->gc_count++;

	ret   = bch2_gc_alloc_done(c) ?:
		bch2_gc_accounting_done(c) ?:
		bch2_gc_stripes_done(c) ?:
		bch2_gc_reflink_done(c);
out:
	scoped_guard(percpu_write, &c->mark_lock) {
		/* Indicates that gc is no longer in progress: */
		__gc_pos_set(c, gc_phase(GC_PHASE_not_running));
		bch2_gc_free(c);
	}

	/*
	 * At startup, allocations can happen directly instead of via the
	 * allocator thread - issue wakeup in case they blocked on gc_lock:
	 */
	closure_wake_up(&c->freelist_wait);

	if (!ret && !test_bit(BCH_FS_errors_not_fixed, &c->flags))
		bch2_sb_members_clean_deleted(c);

	return ret;
}

static int gc_btree_gens_key(struct btree_trans *trans,
			     struct btree_iter *iter,
			     struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	if (unlikely(test_bit(BCH_FS_going_ro, &c->flags)))
		return -EROFS;

	return bch2_bkey_drop_stale_ptrs(trans, iter, k);
}

static int bch2_alloc_write_oldest_gen(struct btree_trans *trans, struct bch_dev *ca,
				       struct btree_iter *iter, struct bkey_s_c k)
{
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);

	if (a->oldest_gen == ca->oldest_gen[iter->pos.offset])
		return 0;

	struct bkey_i_alloc_v4 *a_mut = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	a_mut->v.oldest_gen = ca->oldest_gen[iter->pos.offset];

	return bch2_trans_update(trans, iter, &a_mut->k_i, 0);
}

int bch2_gc_gens(struct bch_fs *c)
{
	u64 b, start_time = local_clock();
	int ret;

	if (!mutex_trylock(&c->gc_gens_lock))
		return 0;

	trace_and_count(c, gc_gens_start, c);

	/*
	 * We have to use trylock here. Otherwise, we would
	 * introduce a deadlock in the RO path - we take the
	 * state lock at the start of going RO.
	 */
	if (!down_read_trylock(&c->state_lock)) {
		mutex_unlock(&c->gc_gens_lock);
		return 0;
	}

	for_each_member_device(c, ca) {
		struct bucket_gens *gens = bucket_gens(ca);

		BUG_ON(ca->oldest_gen);

		ca->oldest_gen = kvmalloc(gens->nbuckets, GFP_KERNEL);
		if (!ca->oldest_gen) {
			bch2_dev_put(ca);
			ret = bch_err_throw(c, ENOMEM_gc_gens);
			goto err;
		}

		for (b = gens->first_bucket;
		     b < gens->nbuckets; b++)
			ca->oldest_gen[b] = gens->b[b];
	}

	for (unsigned i = 0; i < BTREE_ID_NR; i++)
		if (btree_type_has_data_ptrs(i)) {
			c->gc_gens_btree = i;
			c->gc_gens_pos = POS_MIN;

			ret = bch2_trans_run(c,
				for_each_btree_key_commit(trans, iter, i,
						POS_MIN,
						BTREE_ITER_prefetch|BTREE_ITER_all_snapshots,
						k,
						NULL, NULL,
						BCH_TRANS_COMMIT_no_enospc,
					gc_btree_gens_key(trans, &iter, k)));
			if (ret)
				goto err;
		}

	struct bch_dev *ca = NULL;
	ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter, BTREE_ID_alloc,
				POS_MIN,
				BTREE_ITER_prefetch,
				k,
				NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc, ({
			ca = bch2_dev_iterate(c, ca, k.k->p.inode);
			if (!ca) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}
			bch2_alloc_write_oldest_gen(trans, ca, &iter, k);
		})));
	bch2_dev_put(ca);

	if (ret)
		goto err;

	c->gc_gens_btree	= 0;
	c->gc_gens_pos		= POS_MIN;

	c->gc_count++;

	bch2_time_stats_update(&c->times[BCH_TIME_btree_gc], start_time);
	trace_and_count(c, gc_gens_end, c);

	if (!(c->sb.compat & BIT_ULL(BCH_COMPAT_no_stale_ptrs))) {
		guard(mutex)(&c->sb_lock);
		c->disk_sb.sb->compat[0] |= cpu_to_le64(BIT_ULL(BCH_COMPAT_no_stale_ptrs));
		bch2_write_super(c);
	}
err:
	for_each_member_device(c, ca) {
		kvfree(ca->oldest_gen);
		ca->oldest_gen = NULL;
	}

	up_read(&c->state_lock);
	mutex_unlock(&c->gc_gens_lock);
	if (!bch2_err_matches(ret, EROFS))
		bch_err_fn(c, ret);
	return ret;
}

static void bch2_gc_gens_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, gc_gens_work);
	bch2_gc_gens(c);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_gc_gens);
}

void bch2_gc_gens_async(struct bch_fs *c)
{
	if (enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_gc_gens) &&
	    !queue_work(c->write_ref_wq, &c->gc_gens_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_gc_gens);
}

void bch2_fs_btree_gc_init_early(struct bch_fs *c)
{
	seqcount_init(&c->gc_pos_lock);
	INIT_WORK(&c->gc_gens_work, bch2_gc_gens_work);

	init_rwsem(&c->gc_lock);
	mutex_init(&c->gc_gens_lock);
}
