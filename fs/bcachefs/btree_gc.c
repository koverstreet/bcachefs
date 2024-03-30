// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "backpointers.h"
#include "bkey_methods.h"
#include "bkey_buf.h"
#include "btree_journal_iter.h"
#include "btree_key_cache.h"
#include "btree_locking.h"
#include "btree_node_scan.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "debug.h"
#include "ec.h"
#include "error.h"
#include "extents.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "recovery_passes.h"
#include "reflink.h"
#include "replicas.h"
#include "super-io.h"
#include "trace.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>

#define DROP_THIS_NODE		10
#define DROP_PREV_NODE		11
#define DID_FILL_FROM_SCAN	12

static struct bkey_s unsafe_bkey_s_c_to_s(struct bkey_s_c k)
{
	return (struct bkey_s) {{{
		(struct bkey *) k.k,
		(struct bch_val *) k.v
	}}};
}

static bool should_restart_for_topology_repair(struct bch_fs *c)
{
	return c->opts.fix_errors != FSCK_FIX_no &&
		!(c->recovery_passes_complete & BIT_ULL(BCH_RECOVERY_PASS_check_topology));
}

static inline void __gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	preempt_disable();
	write_seqcount_begin(&c->gc_pos_lock);
	c->gc_pos = new_pos;
	write_seqcount_end(&c->gc_pos_lock);
	preempt_enable();
}

static inline void gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	BUG_ON(gc_pos_cmp(new_pos, c->gc_pos) <= 0);
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

static void bch2_btree_node_update_key_early(struct btree_trans *trans,
					     enum btree_id btree, unsigned level,
					     struct bkey_s_c old, struct bkey_i *new)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	struct bkey_buf tmp;
	int ret;

	bch2_bkey_buf_init(&tmp);
	bch2_bkey_buf_reassemble(&tmp, c, old);

	b = bch2_btree_node_get_noiter(trans, tmp.k, btree, level, true);
	if (!IS_ERR_OR_NULL(b)) {
		mutex_lock(&c->btree_cache.lock);

		bch2_btree_node_hash_remove(&c->btree_cache, b);

		bkey_copy(&b->key, new);
		ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
		BUG_ON(ret);

		mutex_unlock(&c->btree_cache.lock);
		six_unlock_read(&b->c.lock);
	}

	bch2_bkey_buf_exit(&tmp, c);
}

static int set_node_min(struct bch_fs *c, struct btree *b, struct bpos new_min)
{
	struct bkey_i_btree_ptr_v2 *new;
	int ret;

	if (c->opts.verbose) {
		struct printbuf buf = PRINTBUF;

		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
		prt_str(&buf, " -> ");
		bch2_bpos_to_text(&buf, new_min);

		bch_info(c, "%s(): %s", __func__, buf.buf);
		printbuf_exit(&buf);
	}

	new = kmalloc_array(BKEY_BTREE_PTR_U64s_MAX, sizeof(u64), GFP_KERNEL);
	if (!new)
		return -BCH_ERR_ENOMEM_gc_repair_key;

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
	int ret;

	if (c->opts.verbose) {
		struct printbuf buf = PRINTBUF;

		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
		prt_str(&buf, " -> ");
		bch2_bpos_to_text(&buf, new_max);

		bch_info(c, "%s(): %s", __func__, buf.buf);
		printbuf_exit(&buf);
	}

	ret = bch2_journal_key_delete(c, b->c.btree_id, b->c.level + 1, b->key.k.p);
	if (ret)
		return ret;

	new = kmalloc_array(BKEY_BTREE_PTR_U64s_MAX, sizeof(u64), GFP_KERNEL);
	if (!new)
		return -BCH_ERR_ENOMEM_gc_repair_key;

	btree_ptr_to_v2(b, new);
	b->data->max_key	= new_max;
	new->k.p		= new_max;
	SET_BTREE_PTR_RANGE_UPDATED(&new->v, true);

	ret = bch2_journal_key_insert_take(c, b->c.btree_id, b->c.level + 1, &new->k_i);
	if (ret) {
		kfree(new);
		return ret;
	}

	bch2_btree_node_drop_keys_outside_node(b);

	mutex_lock(&c->btree_cache.lock);
	bch2_btree_node_hash_remove(&c->btree_cache, b);

	bkey_copy(&b->key, &new->k_i);
	ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
	BUG_ON(ret);
	mutex_unlock(&c->btree_cache.lock);
	return 0;
}

static int btree_check_node_boundaries(struct bch_fs *c, struct btree *b,
				       struct btree *prev, struct btree *cur,
				       struct bpos *pulled_from_scan)
{
	struct bpos expected_start = !prev
		? b->data->min_key
		: bpos_successor(prev->key.k.p);
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	BUG_ON(b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	       !bpos_eq(bkey_i_to_btree_ptr_v2(&b->key)->v.min_key,
			b->data->min_key));

	if (bpos_eq(expected_start, cur->data->min_key))
		return 0;

	prt_printf(&buf, "  at btree %s level %u:\n  parent: ",
		   bch2_btree_id_str(b->c.btree_id), b->c.level);
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	if (prev) {
		prt_printf(&buf, "\n  prev: ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&prev->key));
	}

	prt_str(&buf, "\n  next: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&cur->key));

	if (bpos_lt(expected_start, cur->data->min_key)) {				/* gap */
		if (b->c.level == 1 &&
		    bpos_lt(*pulled_from_scan, cur->data->min_key)) {
			ret = bch2_get_scanned_nodes(c, b->c.btree_id, 0,
						     expected_start,
						     bpos_predecessor(cur->data->min_key));
			if (ret)
				goto err;

			*pulled_from_scan = cur->data->min_key;
			ret = DID_FILL_FROM_SCAN;
		} else {
			if (mustfix_fsck_err(c, btree_node_topology_bad_min_key,
					     "btree node with incorrect min_key%s", buf.buf))
				ret = set_node_min(c, cur, expected_start);
		}
	} else {									/* overlap */
		if (prev && BTREE_NODE_SEQ(cur->data) > BTREE_NODE_SEQ(prev->data)) {	/* cur overwrites prev */
			if (bpos_ge(prev->data->min_key, cur->data->min_key)) {		/* fully? */
				if (mustfix_fsck_err(c, btree_node_topology_overwritten_by_next_node,
						     "btree node overwritten by next node%s", buf.buf))
					ret = DROP_PREV_NODE;
			} else {
				if (mustfix_fsck_err(c, btree_node_topology_bad_max_key,
						     "btree node with incorrect max_key%s", buf.buf))
					ret = set_node_max(c, prev,
							   bpos_predecessor(cur->data->min_key));
			}
		} else {
			if (bpos_ge(expected_start, cur->data->max_key)) {		/* fully? */
				if (mustfix_fsck_err(c, btree_node_topology_overwritten_by_prev_node,
						     "btree node overwritten by prev node%s", buf.buf))
					ret = DROP_THIS_NODE;
			} else {
				if (mustfix_fsck_err(c, btree_node_topology_bad_min_key,
						     "btree node with incorrect min_key%s", buf.buf))
					ret = set_node_min(c, cur, expected_start);
			}
		}
	}
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static int btree_repair_node_end(struct bch_fs *c, struct btree *b,
				 struct btree *child, struct bpos *pulled_from_scan)
{
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	if (bpos_eq(child->key.k.p, b->key.k.p))
		return 0;

	prt_printf(&buf, "at btree %s level %u:\n  parent: ",
		   bch2_btree_id_str(b->c.btree_id), b->c.level);
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	prt_str(&buf, "\n  child: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&child->key));

	if (mustfix_fsck_err(c, btree_node_topology_bad_max_key,
			     "btree node with incorrect max_key%s", buf.buf)) {
		if (b->c.level == 1 &&
		    bpos_lt(*pulled_from_scan, b->key.k.p)) {
			ret = bch2_get_scanned_nodes(c, b->c.btree_id, 0,
						bpos_successor(child->key.k.p), b->key.k.p);
			if (ret)
				goto err;

			*pulled_from_scan = b->key.k.p;
			ret = DID_FILL_FROM_SCAN;
		} else {
			ret = set_node_max(c, child, b->key.k.p);
		}
	}
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static int bch2_btree_repair_topology_recurse(struct btree_trans *trans, struct btree *b,
					      struct bpos *pulled_from_scan)
{
	struct bch_fs *c = trans->c;
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	struct bkey_buf prev_k, cur_k;
	struct btree *prev = NULL, *cur = NULL;
	bool have_child, new_pass = false;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	if (!b->c.level)
		return 0;

	bch2_bkey_buf_init(&prev_k);
	bch2_bkey_buf_init(&cur_k);
again:
	cur = prev = NULL;
	have_child = new_pass = false;
	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);
	iter.prefetch = true;

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		BUG_ON(bpos_lt(k.k->p, b->data->min_key));
		BUG_ON(bpos_gt(k.k->p, b->data->max_key));

		bch2_btree_and_journal_iter_advance(&iter);
		bch2_bkey_buf_reassemble(&cur_k, c, k);

		cur = bch2_btree_node_get_noiter(trans, cur_k.k,
					b->c.btree_id, b->c.level - 1,
					false);
		ret = PTR_ERR_OR_ZERO(cur);

		printbuf_reset(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(cur_k.k));

		if (mustfix_fsck_err_on(bch2_err_matches(ret, EIO), c,
				btree_node_unreadable,
				"Topology repair: unreadable btree node at btree %s level %u:\n"
				"  %s",
				bch2_btree_id_str(b->c.btree_id),
				b->c.level - 1,
				buf.buf)) {
			bch2_btree_node_evict(trans, cur_k.k);
			cur = NULL;
			ret =   bch2_run_explicit_recovery_pass(c, BCH_RECOVERY_PASS_scan_for_btree_nodes) ?:
				bch2_journal_key_delete(c, b->c.btree_id,
							b->c.level, cur_k.k->k.p);
			if (ret)
				break;
			continue;
		}

		bch_err_msg(c, ret, "getting btree node");
		if (ret)
			break;

		if (bch2_btree_node_is_stale(c, cur)) {
			bch_info(c, "btree node %s older than nodes found by scanning", buf.buf);
			six_unlock_read(&cur->c.lock);
			bch2_btree_node_evict(trans, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			cur = NULL;
			if (ret)
				break;
			continue;
		}

		ret = btree_check_node_boundaries(c, b, prev, cur, pulled_from_scan);
		if (ret == DID_FILL_FROM_SCAN) {
			new_pass = true;
			ret = 0;
		}

		if (ret == DROP_THIS_NODE) {
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

		if (ret == DROP_PREV_NODE) {
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
		bch2_bkey_buf_copy(&prev_k, c, cur_k.k);
	}

	if (!ret && !IS_ERR_OR_NULL(prev)) {
		BUG_ON(cur);
		ret = btree_repair_node_end(c, b, prev, pulled_from_scan);
		if (ret == DID_FILL_FROM_SCAN) {
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

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		bch2_bkey_buf_reassemble(&cur_k, c, k);
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

		if (ret == DROP_THIS_NODE) {
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
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	if (mustfix_fsck_err_on(!have_child, c,
			btree_node_topology_interior_node_empty,
			"empty interior btree node at btree %s level %u\n"
			"  %s",
			bch2_btree_id_str(b->c.btree_id),
			b->c.level, buf.buf))
		ret = DROP_THIS_NODE;
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

	bch2_bkey_buf_exit(&prev_k, c);
	bch2_bkey_buf_exit(&cur_k, c);
	printbuf_exit(&buf);
	return ret;
}

int bch2_check_topology(struct bch_fs *c)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct bpos pulled_from_scan = POS_MIN;
	int ret = 0;

	for (unsigned i = 0; i < btree_id_nr_alive(c) && !ret; i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);
		bool reconstructed_root = false;

		if (r->error) {
			ret = bch2_run_explicit_recovery_pass(c, BCH_RECOVERY_PASS_scan_for_btree_nodes);
			if (ret)
				break;
reconstruct_root:
			bch_info(c, "btree root %s unreadable, must recover from scan", bch2_btree_id_str(i));

			r->alive = false;
			r->error = 0;

			if (!bch2_btree_has_scanned_nodes(c, i)) {
				mustfix_fsck_err(c, btree_root_unreadable_and_scan_found_nothing,
						 "no nodes found for btree %s, continue?", bch2_btree_id_str(i));
				bch2_btree_root_alloc_fake(c, i, 0);
			} else {
				bch2_btree_root_alloc_fake(c, i, 1);
				ret = bch2_get_scanned_nodes(c, i, 0, POS_MIN, SPOS_MAX);
				if (ret)
					break;
			}

			bch2_shoot_down_journal_keys(c, i, 1, BTREE_MAX_DEPTH, POS_MIN, SPOS_MAX);
			reconstructed_root = true;
		}

		struct btree *b = r->b;

		btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);
		ret = bch2_btree_repair_topology_recurse(trans, b, &pulled_from_scan);
		six_unlock_read(&b->c.lock);

		if (ret == DROP_THIS_NODE) {
			bch2_btree_node_hash_remove(&c->btree_cache, b);
			mutex_lock(&c->btree_cache.lock);
			list_move(&b->list, &c->btree_cache.freeable);
			mutex_unlock(&c->btree_cache.lock);

			r->b = NULL;

			if (!reconstructed_root)
				goto reconstruct_root;

			bch_err(c, "empty btree root %s", bch2_btree_id_str(i));
			bch2_btree_root_alloc_fake(c, i, 0);
			r->alive = false;
			ret = 0;
		}
	}
fsck_err:
	bch2_trans_put(trans);
	return ret;
}

static int bch2_check_fix_ptrs(struct btree_trans *trans, enum btree_id btree_id,
			       unsigned level, bool is_root,
			       struct bkey_s_c *k)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs_c = bch2_bkey_ptrs_c(*k);
	const union bch_extent_entry *entry_c;
	struct extent_ptr_decoded p = { 0 };
	bool do_update = false;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	/*
	 * XXX
	 * use check_bucket_ref here
	 */
	bkey_for_each_ptr_decode(k->k, ptrs_c, p, entry_c) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, p.ptr.dev);
		struct bucket *g = PTR_GC_BUCKET(ca, &p.ptr);
		enum bch_data_type data_type = bch2_bkey_ptr_data_type(*k, p, entry_c);

		if (fsck_err_on(!g->gen_valid,
				c, ptr_to_missing_alloc_key,
				"bucket %u:%zu data type %s ptr gen %u missing in alloc btree\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_type_str(ptr_data_type(k->k, &p.ptr)),
				p.ptr.gen,
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, *k), buf.buf))) {
			if (!p.ptr.cached) {
				g->gen_valid		= true;
				g->gen			= p.ptr.gen;
			} else {
				do_update = true;
			}
		}

		if (fsck_err_on(gen_cmp(p.ptr.gen, g->gen) > 0,
				c, ptr_gen_newer_than_bucket_gen,
				"bucket %u:%zu data type %s ptr gen in the future: %u > %u\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_type_str(ptr_data_type(k->k, &p.ptr)),
				p.ptr.gen, g->gen,
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, *k), buf.buf))) {
			if (!p.ptr.cached) {
				g->gen_valid		= true;
				g->gen			= p.ptr.gen;
				g->data_type		= 0;
				g->dirty_sectors	= 0;
				g->cached_sectors	= 0;
				set_bit(BCH_FS_need_another_gc, &c->flags);
			} else {
				do_update = true;
			}
		}

		if (fsck_err_on(gen_cmp(g->gen, p.ptr.gen) > BUCKET_GC_GEN_MAX,
				c, ptr_gen_newer_than_bucket_gen,
				"bucket %u:%zu gen %u data type %s: ptr gen %u too stale\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr), g->gen,
				bch2_data_type_str(ptr_data_type(k->k, &p.ptr)),
				p.ptr.gen,
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, *k), buf.buf)))
			do_update = true;

		if (fsck_err_on(!p.ptr.cached && gen_cmp(p.ptr.gen, g->gen) < 0,
				c, stale_dirty_ptr,
				"bucket %u:%zu data type %s stale dirty ptr: %u < %u\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_type_str(ptr_data_type(k->k, &p.ptr)),
				p.ptr.gen, g->gen,
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, *k), buf.buf)))
			do_update = true;

		if (data_type != BCH_DATA_btree && p.ptr.gen != g->gen)
			continue;

		if (fsck_err_on(bucket_data_type(g->data_type) &&
				bucket_data_type(g->data_type) !=
				bucket_data_type(data_type), c,
				ptr_bucket_data_type_mismatch,
				"bucket %u:%zu different types of data in same bucket: %s, %s\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_type_str(g->data_type),
				bch2_data_type_str(data_type),
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, *k), buf.buf))) {
			if (data_type == BCH_DATA_btree) {
				g->data_type	= data_type;
				set_bit(BCH_FS_need_another_gc, &c->flags);
			} else {
				do_update = true;
			}
		}

		if (p.has_ec) {
			struct gc_stripe *m = genradix_ptr(&c->gc_stripes, p.ec.idx);

			if (fsck_err_on(!m || !m->alive, c,
					ptr_to_missing_stripe,
					"pointer to nonexistent stripe %llu\n"
					"while marking %s",
					(u64) p.ec.idx,
					(printbuf_reset(&buf),
					 bch2_bkey_val_to_text(&buf, c, *k), buf.buf)))
				do_update = true;

			if (fsck_err_on(m && m->alive && !bch2_ptr_matches_stripe_m(m, p), c,
					ptr_to_incorrect_stripe,
					"pointer does not match stripe %llu\n"
					"while marking %s",
					(u64) p.ec.idx,
					(printbuf_reset(&buf),
					 bch2_bkey_val_to_text(&buf, c, *k), buf.buf)))
				do_update = true;
		}
	}

	if (do_update) {
		if (is_root) {
			bch_err(c, "cannot update btree roots yet");
			ret = -EINVAL;
			goto err;
		}

		struct bkey_i *new = kmalloc(bkey_bytes(k->k), GFP_KERNEL);
		if (!new) {
			ret = -BCH_ERR_ENOMEM_gc_repair_key;
			bch_err_msg(c, ret, "allocating new key");
			goto err;
		}

		bkey_reassemble(new, *k);

		if (level) {
			/*
			 * We don't want to drop btree node pointers - if the
			 * btree node isn't there anymore, the read path will
			 * sort it out:
			 */
			struct bkey_ptrs ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
			bkey_for_each_ptr(ptrs, ptr) {
				struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
				struct bucket *g = PTR_GC_BUCKET(ca, ptr);

				ptr->gen = g->gen;
			}
		} else {
			struct bkey_ptrs ptrs;
			union bch_extent_entry *entry;
restart_drop_ptrs:
			ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
			bkey_for_each_ptr_decode(bkey_i_to_s(new).k, ptrs, p, entry) {
				struct bch_dev *ca = bch_dev_bkey_exists(c, p.ptr.dev);
				struct bucket *g = PTR_GC_BUCKET(ca, &p.ptr);
				enum bch_data_type data_type = bch2_bkey_ptr_data_type(bkey_i_to_s_c(new), p, entry);

				if ((p.ptr.cached &&
				     (!g->gen_valid || gen_cmp(p.ptr.gen, g->gen) > 0)) ||
				    (!p.ptr.cached &&
				     gen_cmp(p.ptr.gen, g->gen) < 0) ||
				    gen_cmp(g->gen, p.ptr.gen) > BUCKET_GC_GEN_MAX ||
				    (g->data_type &&
				     g->data_type != data_type)) {
					bch2_bkey_drop_ptr(bkey_i_to_s(new), &entry->ptr);
					goto restart_drop_ptrs;
				}
			}
again:
			ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
			bkey_extent_entry_for_each(ptrs, entry) {
				if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_stripe_ptr) {
					struct gc_stripe *m = genradix_ptr(&c->gc_stripes,
									entry->stripe_ptr.idx);
					union bch_extent_entry *next_ptr;

					bkey_extent_entry_for_each_from(ptrs, next_ptr, entry)
						if (extent_entry_type(next_ptr) == BCH_EXTENT_ENTRY_ptr)
							goto found;
					next_ptr = NULL;
found:
					if (!next_ptr) {
						bch_err(c, "aieee, found stripe ptr with no data ptr");
						continue;
					}

					if (!m || !m->alive ||
					    !__bch2_ptr_matches_stripe(&m->ptrs[entry->stripe_ptr.block],
								       &next_ptr->ptr,
								       m->sectors)) {
						bch2_bkey_extent_entry_drop(new, entry);
						goto again;
					}
				}
			}
		}

		if (level)
			bch2_btree_node_update_key_early(trans, btree_id, level - 1, *k, new);

		if (0) {
			printbuf_reset(&buf);
			bch2_bkey_val_to_text(&buf, c, *k);
			bch_info(c, "updated %s", buf.buf);

			printbuf_reset(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(new));
			bch_info(c, "new key %s", buf.buf);
		}

		ret = bch2_journal_key_insert_take(c, btree_id, level, new);
		if (ret) {
			kfree(new);
			goto err;
		}

		*k = bkey_i_to_s_c(new);
	}
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

/* marking of btree keys/nodes: */

static int bch2_gc_mark_key(struct btree_trans *trans, enum btree_id btree_id,
			    unsigned level, bool is_root,
			    struct bkey_s_c *k,
			    bool initial)
{
	struct bch_fs *c = trans->c;
	struct bkey deleted = KEY(0, 0, 0);
	struct bkey_s_c old = (struct bkey_s_c) { &deleted, NULL };
	int ret = 0;

	deleted.p = k->k->p;

	if (initial) {
		BUG_ON(bch2_journal_seq_verify &&
		       k->k->version.lo > atomic64_read(&c->journal.seq));

		if (fsck_err_on(k->k->version.lo > atomic64_read(&c->key_version), c,
				bkey_version_in_future,
				"key version number higher than recorded: %llu > %llu",
				k->k->version.lo,
				atomic64_read(&c->key_version)))
			atomic64_set(&c->key_version, k->k->version.lo);
	}

	ret = bch2_check_fix_ptrs(trans, btree_id, level, is_root, k);
	if (ret)
		goto err;

	ret = commit_do(trans, NULL, NULL, 0,
			bch2_key_trigger(trans, btree_id, level, old,
					 unsafe_bkey_s_c_to_s(*k), BTREE_TRIGGER_GC));
fsck_err:
err:
	bch_err_fn(c, ret);
	return ret;
}

static int btree_gc_mark_node(struct btree_trans *trans, struct btree *b, bool initial)
{
	struct btree_node_iter iter;
	struct bkey unpacked;
	struct bkey_s_c k;
	int ret = 0;

	ret = bch2_btree_node_check_topology(trans, b);
	if (ret)
		return ret;

	if (!btree_node_type_needs_gc(btree_node_type(b)))
		return 0;

	bch2_btree_node_iter_init_from_start(&iter, b);

	while ((k = bch2_btree_node_iter_peek_unpack(&iter, b, &unpacked)).k) {
		ret = bch2_gc_mark_key(trans, b->c.btree_id, b->c.level, false,
				       &k, initial);
		if (ret)
			return ret;

		bch2_btree_node_iter_advance(&iter, b);
	}

	return 0;
}

static int bch2_gc_btree(struct btree_trans *trans, enum btree_id btree_id,
			 bool initial, bool metadata_only)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct btree *b;
	unsigned depth = metadata_only ? 1 : 0;
	int ret = 0;

	gc_pos_set(c, gc_pos_btree(btree_id, POS_MIN, 0));

	__for_each_btree_node(trans, iter, btree_id, POS_MIN,
			      0, depth, BTREE_ITER_PREFETCH, b, ret) {
		bch2_verify_btree_nr_keys(b);

		gc_pos_set(c, gc_pos_btree_node(b));

		ret = btree_gc_mark_node(trans, b, initial);
		if (ret)
			break;
	}
	bch2_trans_iter_exit(trans, &iter);

	if (ret)
		return ret;

	mutex_lock(&c->btree_root_lock);
	b = bch2_btree_id_root(c, btree_id)->b;
	if (!btree_node_fake(b)) {
		struct bkey_s_c k = bkey_i_to_s_c(&b->key);

		ret = bch2_gc_mark_key(trans, b->c.btree_id, b->c.level + 1,
				       true, &k, initial);
	}
	gc_pos_set(c, gc_pos_btree_root(b->c.btree_id));
	mutex_unlock(&c->btree_root_lock);

	return ret;
}

static int bch2_gc_btree_init_recurse(struct btree_trans *trans, struct btree *b,
				      unsigned target_depth)
{
	struct bch_fs *c = trans->c;
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	struct bkey_buf cur;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	ret = bch2_btree_node_check_topology(trans, b);
	if (ret)
		return ret;

	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);
	bch2_bkey_buf_init(&cur);

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		BUG_ON(bpos_lt(k.k->p, b->data->min_key));
		BUG_ON(bpos_gt(k.k->p, b->data->max_key));

		ret = bch2_gc_mark_key(trans, b->c.btree_id, b->c.level,
				       false, &k, true);
		if (ret)
			goto fsck_err;

		bch2_btree_and_journal_iter_advance(&iter);
	}

	if (b->c.level > target_depth) {
		bch2_btree_and_journal_iter_exit(&iter);
		bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);
		iter.prefetch = true;

		while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
			struct btree *child;

			bch2_bkey_buf_reassemble(&cur, c, k);
			bch2_btree_and_journal_iter_advance(&iter);

			child = bch2_btree_node_get_noiter(trans, cur.k,
						b->c.btree_id, b->c.level - 1,
						false);
			ret = PTR_ERR_OR_ZERO(child);

			if (bch2_err_matches(ret, EIO)) {
				bch2_topology_error(c);

				if (__fsck_err(c,
					  FSCK_CAN_FIX|
					  FSCK_CAN_IGNORE|
					  FSCK_NO_RATELIMIT,
					  btree_node_read_error,
					  "Unreadable btree node at btree %s level %u:\n"
					  "  %s",
					  bch2_btree_id_str(b->c.btree_id),
					  b->c.level - 1,
					  (printbuf_reset(&buf),
					   bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(cur.k)), buf.buf)) &&
				    should_restart_for_topology_repair(c)) {
					bch_info(c, "Halting mark and sweep to start topology repair pass");
					ret = bch2_run_explicit_recovery_pass(c, BCH_RECOVERY_PASS_check_topology);
					goto fsck_err;
				} else {
					/* Continue marking when opted to not
					 * fix the error: */
					ret = 0;
					set_bit(BCH_FS_initial_gc_unfixed, &c->flags);
					continue;
				}
			} else if (ret) {
				bch_err_msg(c, ret, "getting btree node");
				break;
			}

			ret = bch2_gc_btree_init_recurse(trans, child,
							 target_depth);
			six_unlock_read(&child->c.lock);

			if (ret)
				break;
		}
	}
fsck_err:
	bch2_bkey_buf_exit(&cur, c);
	bch2_btree_and_journal_iter_exit(&iter);
	printbuf_exit(&buf);
	return ret;
}

static int bch2_gc_btree_init(struct btree_trans *trans,
			      enum btree_id btree_id,
			      bool metadata_only)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	unsigned target_depth = metadata_only ? 1 : 0;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	b = bch2_btree_id_root(c, btree_id)->b;

	six_lock_read(&b->c.lock, NULL, NULL);
	printbuf_reset(&buf);
	bch2_bpos_to_text(&buf, b->data->min_key);
	if (mustfix_fsck_err_on(!bpos_eq(b->data->min_key, POS_MIN), c,
				btree_root_bad_min_key,
			"btree root with incorrect min_key: %s", buf.buf)) {
		bch_err(c, "repair unimplemented");
		ret = -BCH_ERR_fsck_repair_unimplemented;
		goto fsck_err;
	}

	printbuf_reset(&buf);
	bch2_bpos_to_text(&buf, b->data->max_key);
	if (mustfix_fsck_err_on(!bpos_eq(b->data->max_key, SPOS_MAX), c,
				btree_root_bad_max_key,
			"btree root with incorrect max_key: %s", buf.buf)) {
		bch_err(c, "repair unimplemented");
		ret = -BCH_ERR_fsck_repair_unimplemented;
		goto fsck_err;
	}

	if (b->c.level >= target_depth)
		ret = bch2_gc_btree_init_recurse(trans, b, target_depth);

	if (!ret) {
		struct bkey_s_c k = bkey_i_to_s_c(&b->key);

		ret = bch2_gc_mark_key(trans, b->c.btree_id, b->c.level + 1, true,
				       &k, true);
	}
fsck_err:
	six_unlock_read(&b->c.lock);

	bch_err_fn(c, ret);
	printbuf_exit(&buf);
	return ret;
}

static inline int btree_id_gc_phase_cmp(enum btree_id l, enum btree_id r)
{
	return  (int) btree_id_to_gc_phase(l) -
		(int) btree_id_to_gc_phase(r);
}

static int bch2_gc_btrees(struct bch_fs *c, bool initial, bool metadata_only)
{
	struct btree_trans *trans = bch2_trans_get(c);
	enum btree_id ids[BTREE_ID_NR];
	unsigned i;
	int ret = 0;

	for (i = 0; i < BTREE_ID_NR; i++)
		ids[i] = i;
	bubble_sort(ids, BTREE_ID_NR, btree_id_gc_phase_cmp);

	for (i = 0; i < BTREE_ID_NR && !ret; i++)
		ret = initial
			? bch2_gc_btree_init(trans, ids[i], metadata_only)
			: bch2_gc_btree(trans, ids[i], initial, metadata_only);

	for (i = BTREE_ID_NR; i < btree_id_nr_alive(c) && !ret; i++) {
		if (!bch2_btree_id_root(c, i)->alive)
			continue;

		ret = initial
			? bch2_gc_btree_init(trans, i, metadata_only)
			: bch2_gc_btree(trans, i, initial, metadata_only);
	}

	bch2_trans_put(trans);
	bch_err_fn(c, ret);
	return ret;
}

static void mark_metadata_sectors(struct bch_fs *c, struct bch_dev *ca,
				  u64 start, u64 end,
				  enum bch_data_type type,
				  unsigned flags)
{
	u64 b = sector_to_bucket(ca, start);

	do {
		unsigned sectors =
			min_t(u64, bucket_to_sector(ca, b + 1), end) - start;

		bch2_mark_metadata_bucket(c, ca, b, type, sectors,
					  gc_phase(GC_PHASE_SB), flags);
		b++;
		start += sectors;
	} while (start < end);
}

static void bch2_mark_dev_superblock(struct bch_fs *c, struct bch_dev *ca,
				     unsigned flags)
{
	struct bch_sb_layout *layout = &ca->disk_sb.sb->layout;
	unsigned i;
	u64 b;

	for (i = 0; i < layout->nr_superblocks; i++) {
		u64 offset = le64_to_cpu(layout->sb_offset[i]);

		if (offset == BCH_SB_SECTOR)
			mark_metadata_sectors(c, ca, 0, BCH_SB_SECTOR,
					      BCH_DATA_sb, flags);

		mark_metadata_sectors(c, ca, offset,
				      offset + (1 << layout->sb_max_size_bits),
				      BCH_DATA_sb, flags);
	}

	for (i = 0; i < ca->journal.nr; i++) {
		b = ca->journal.buckets[i];
		bch2_mark_metadata_bucket(c, ca, b, BCH_DATA_journal,
					  ca->mi.bucket_size,
					  gc_phase(GC_PHASE_SB), flags);
	}
}

static void bch2_mark_superblocks(struct bch_fs *c)
{
	mutex_lock(&c->sb_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_SB));

	for_each_online_member(c, ca)
		bch2_mark_dev_superblock(c, ca, BTREE_TRIGGER_GC);
	mutex_unlock(&c->sb_lock);
}

#if 0
/* Also see bch2_pending_btree_node_free_insert_done() */
static void bch2_mark_pending_btree_node_frees(struct bch_fs *c)
{
	struct btree_update *as;
	struct pending_btree_node_free *d;

	mutex_lock(&c->btree_interior_update_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_PENDING_DELETE));

	for_each_pending_btree_node_free(c, as, d)
		if (d->index_update_done)
			bch2_mark_key(c, bkey_i_to_s_c(&d->key), BTREE_TRIGGER_GC);

	mutex_unlock(&c->btree_interior_update_lock);
}
#endif

static void bch2_gc_free(struct bch_fs *c)
{
	genradix_free(&c->reflink_gc_table);
	genradix_free(&c->gc_stripes);

	for_each_member_device(c, ca) {
		kvfree(rcu_dereference_protected(ca->buckets_gc, 1));
		ca->buckets_gc = NULL;

		free_percpu(ca->usage_gc);
		ca->usage_gc = NULL;
	}

	free_percpu(c->usage_gc);
	c->usage_gc = NULL;
}

static int bch2_gc_done(struct bch_fs *c,
			bool initial, bool metadata_only)
{
	struct bch_dev *ca = NULL;
	struct printbuf buf = PRINTBUF;
	bool verify = !metadata_only &&
		!c->opts.reconstruct_alloc &&
		(!initial || (c->sb.compat & (1ULL << BCH_COMPAT_alloc_info)));
	unsigned i;
	int ret = 0;

	percpu_down_write(&c->mark_lock);

#define copy_field(_err, _f, _msg, ...)					\
	if (dst->_f != src->_f &&					\
	    (!verify ||							\
	     fsck_err(c, _err, _msg ": got %llu, should be %llu"	\
		      , ##__VA_ARGS__, dst->_f, src->_f)))		\
		dst->_f = src->_f
#define copy_dev_field(_err, _f, _msg, ...)				\
	copy_field(_err, _f, "dev %u has wrong " _msg, ca->dev_idx, ##__VA_ARGS__)
#define copy_fs_field(_err, _f, _msg, ...)				\
	copy_field(_err, _f, "fs has wrong " _msg, ##__VA_ARGS__)

	for (i = 0; i < ARRAY_SIZE(c->usage); i++)
		bch2_fs_usage_acc_to_base(c, i);

	__for_each_member_device(c, ca) {
		struct bch_dev_usage *dst = ca->usage_base;
		struct bch_dev_usage *src = (void *)
			bch2_acc_percpu_u64s((u64 __percpu *) ca->usage_gc,
					     dev_usage_u64s());

		for (i = 0; i < BCH_DATA_NR; i++) {
			copy_dev_field(dev_usage_buckets_wrong,
				       d[i].buckets,	"%s buckets", bch2_data_type_str(i));
			copy_dev_field(dev_usage_sectors_wrong,
				       d[i].sectors,	"%s sectors", bch2_data_type_str(i));
			copy_dev_field(dev_usage_fragmented_wrong,
				       d[i].fragmented,	"%s fragmented", bch2_data_type_str(i));
		}
	}

	{
		unsigned nr = fs_usage_u64s(c);
		struct bch_fs_usage *dst = c->usage_base;
		struct bch_fs_usage *src = (void *)
			bch2_acc_percpu_u64s((u64 __percpu *) c->usage_gc, nr);

		copy_fs_field(fs_usage_hidden_wrong,
			      b.hidden,		"hidden");
		copy_fs_field(fs_usage_btree_wrong,
			      b.btree,		"btree");

		if (!metadata_only) {
			copy_fs_field(fs_usage_data_wrong,
				      b.data,	"data");
			copy_fs_field(fs_usage_cached_wrong,
				      b.cached,	"cached");
			copy_fs_field(fs_usage_reserved_wrong,
				      b.reserved,	"reserved");
			copy_fs_field(fs_usage_nr_inodes_wrong,
				      b.nr_inodes,"nr_inodes");

			for (i = 0; i < BCH_REPLICAS_MAX; i++)
				copy_fs_field(fs_usage_persistent_reserved_wrong,
					      persistent_reserved[i],
					      "persistent_reserved[%i]", i);
		}

		for (i = 0; i < c->replicas.nr; i++) {
			struct bch_replicas_entry_v1 *e =
				cpu_replicas_entry(&c->replicas, i);

			if (metadata_only &&
			    (e->data_type == BCH_DATA_user ||
			     e->data_type == BCH_DATA_cached))
				continue;

			printbuf_reset(&buf);
			bch2_replicas_entry_to_text(&buf, e);

			copy_fs_field(fs_usage_replicas_wrong,
				      replicas[i], "%s", buf.buf);
		}
	}

#undef copy_fs_field
#undef copy_dev_field
#undef copy_stripe_field
#undef copy_field
fsck_err:
	if (ca)
		percpu_ref_put(&ca->ref);
	bch_err_fn(c, ret);

	percpu_up_write(&c->mark_lock);
	printbuf_exit(&buf);
	return ret;
}

static int bch2_gc_start(struct bch_fs *c)
{
	BUG_ON(c->usage_gc);

	c->usage_gc = __alloc_percpu_gfp(fs_usage_u64s(c) * sizeof(u64),
					 sizeof(u64), GFP_KERNEL);
	if (!c->usage_gc) {
		bch_err(c, "error allocating c->usage_gc");
		return -BCH_ERR_ENOMEM_gc_start;
	}

	for_each_member_device(c, ca) {
		BUG_ON(ca->usage_gc);

		ca->usage_gc = alloc_percpu(struct bch_dev_usage);
		if (!ca->usage_gc) {
			bch_err(c, "error allocating ca->usage_gc");
			percpu_ref_put(&ca->ref);
			return -BCH_ERR_ENOMEM_gc_start;
		}

		this_cpu_write(ca->usage_gc->d[BCH_DATA_free].buckets,
			       ca->mi.nbuckets - ca->mi.first_bucket);
	}

	return 0;
}

static int bch2_gc_reset(struct bch_fs *c)
{
	for_each_member_device(c, ca) {
		free_percpu(ca->usage_gc);
		ca->usage_gc = NULL;
	}

	free_percpu(c->usage_gc);
	c->usage_gc = NULL;

	return bch2_gc_start(c);
}

/* returns true if not equal */
static inline bool bch2_alloc_v4_cmp(struct bch_alloc_v4 l,
				     struct bch_alloc_v4 r)
{
	return  l.gen != r.gen				||
		l.oldest_gen != r.oldest_gen		||
		l.data_type != r.data_type		||
		l.dirty_sectors	!= r.dirty_sectors	||
		l.cached_sectors != r.cached_sectors	 ||
		l.stripe_redundancy != r.stripe_redundancy ||
		l.stripe != r.stripe;
}

static int bch2_alloc_write_key(struct btree_trans *trans,
				struct btree_iter *iter,
				struct bkey_s_c k,
				bool metadata_only)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = bch_dev_bkey_exists(c, iter->pos.inode);
	struct bucket old_gc, gc, *b;
	struct bkey_i_alloc_v4 *a;
	struct bch_alloc_v4 old_convert, new;
	const struct bch_alloc_v4 *old;
	int ret;

	old = bch2_alloc_to_v4(k, &old_convert);
	new = *old;

	percpu_down_read(&c->mark_lock);
	b = gc_bucket(ca, iter->pos.offset);
	old_gc = *b;

	if ((old->data_type == BCH_DATA_sb ||
	     old->data_type == BCH_DATA_journal) &&
	    !bch2_dev_is_online(ca)) {
		b->data_type = old->data_type;
		b->dirty_sectors = old->dirty_sectors;
	}

	/*
	 * b->data_type doesn't yet include need_discard & need_gc_gen states -
	 * fix that here:
	 */
	b->data_type = __alloc_data_type(b->dirty_sectors,
					 b->cached_sectors,
					 b->stripe,
					 *old,
					 b->data_type);
	gc = *b;

	if (gc.data_type != old_gc.data_type ||
	    gc.dirty_sectors != old_gc.dirty_sectors)
		bch2_dev_usage_update_m(c, ca, &old_gc, &gc);
	percpu_up_read(&c->mark_lock);

	if (metadata_only &&
	    gc.data_type != BCH_DATA_sb &&
	    gc.data_type != BCH_DATA_journal &&
	    gc.data_type != BCH_DATA_btree)
		return 0;

	if (gen_after(old->gen, gc.gen))
		return 0;

	if (fsck_err_on(new.data_type != gc.data_type, c,
			alloc_key_data_type_wrong,
			"bucket %llu:%llu gen %u has wrong data_type"
			": got %s, should be %s",
			iter->pos.inode, iter->pos.offset,
			gc.gen,
			bch2_data_type_str(new.data_type),
			bch2_data_type_str(gc.data_type)))
		new.data_type = gc.data_type;

#define copy_bucket_field(_errtype, _f)					\
	if (fsck_err_on(new._f != gc._f, c, _errtype,			\
			"bucket %llu:%llu gen %u data type %s has wrong " #_f	\
			": got %u, should be %u",			\
			iter->pos.inode, iter->pos.offset,		\
			gc.gen,						\
			bch2_data_type_str(gc.data_type),		\
			new._f, gc._f))					\
		new._f = gc._f;						\

	copy_bucket_field(alloc_key_gen_wrong,
			  gen);
	copy_bucket_field(alloc_key_dirty_sectors_wrong,
			  dirty_sectors);
	copy_bucket_field(alloc_key_cached_sectors_wrong,
			  cached_sectors);
	copy_bucket_field(alloc_key_stripe_wrong,
			  stripe);
	copy_bucket_field(alloc_key_stripe_redundancy_wrong,
			  stripe_redundancy);
#undef copy_bucket_field

	if (!bch2_alloc_v4_cmp(*old, new))
		return 0;

	a = bch2_alloc_to_v4_mut(trans, k);
	ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		return ret;

	a->v = new;

	/*
	 * The trigger normally makes sure this is set, but we're not running
	 * triggers:
	 */
	if (a->v.data_type == BCH_DATA_cached && !a->v.io_time[READ])
		a->v.io_time[READ] = max_t(u64, 1, atomic64_read(&c->io_clock[READ].now));

	ret = bch2_trans_update(trans, iter, &a->k_i, BTREE_TRIGGER_NORUN);
fsck_err:
	return ret;
}

static int bch2_gc_alloc_done(struct bch_fs *c, bool metadata_only)
{
	int ret = 0;

	for_each_member_device(c, ca) {
		ret = bch2_trans_run(c,
			for_each_btree_key_upto_commit(trans, iter, BTREE_ID_alloc,
					POS(ca->dev_idx, ca->mi.first_bucket),
					POS(ca->dev_idx, ca->mi.nbuckets - 1),
					BTREE_ITER_SLOTS|BTREE_ITER_PREFETCH, k,
					NULL, NULL, BCH_TRANS_COMMIT_lazy_rw,
				bch2_alloc_write_key(trans, &iter, k, metadata_only)));
		if (ret) {
			percpu_ref_put(&ca->ref);
			break;
		}
	}

	bch_err_fn(c, ret);
	return ret;
}

static int bch2_gc_alloc_start(struct bch_fs *c, bool metadata_only)
{
	for_each_member_device(c, ca) {
		struct bucket_array *buckets = kvmalloc(sizeof(struct bucket_array) +
				ca->mi.nbuckets * sizeof(struct bucket),
				GFP_KERNEL|__GFP_ZERO);
		if (!buckets) {
			percpu_ref_put(&ca->ref);
			bch_err(c, "error allocating ca->buckets[gc]");
			return -BCH_ERR_ENOMEM_gc_alloc_start;
		}

		buckets->first_bucket	= ca->mi.first_bucket;
		buckets->nbuckets	= ca->mi.nbuckets;
		rcu_assign_pointer(ca->buckets_gc, buckets);
	}

	int ret = bch2_trans_run(c,
		for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
					 BTREE_ITER_PREFETCH, k, ({
			struct bch_dev *ca = bch_dev_bkey_exists(c, k.k->p.inode);
			struct bucket *g = gc_bucket(ca, k.k->p.offset);

			struct bch_alloc_v4 a_convert;
			const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);

			g->gen_valid	= 1;
			g->gen		= a->gen;

			if (metadata_only &&
			    (a->data_type == BCH_DATA_user ||
			     a->data_type == BCH_DATA_cached ||
			     a->data_type == BCH_DATA_parity)) {
				g->data_type		= a->data_type;
				g->dirty_sectors	= a->dirty_sectors;
				g->cached_sectors	= a->cached_sectors;
				g->stripe		= a->stripe;
				g->stripe_redundancy	= a->stripe_redundancy;
			}

			0;
		})));
	bch_err_fn(c, ret);
	return ret;
}

static void bch2_gc_alloc_reset(struct bch_fs *c, bool metadata_only)
{
	for_each_member_device(c, ca) {
		struct bucket_array *buckets = gc_bucket_array(ca);
		struct bucket *g;

		for_each_bucket(g, buckets) {
			if (metadata_only &&
			    (g->data_type == BCH_DATA_user ||
			     g->data_type == BCH_DATA_cached ||
			     g->data_type == BCH_DATA_parity))
				continue;
			g->data_type = 0;
			g->dirty_sectors = 0;
			g->cached_sectors = 0;
		}
	}
}

static int bch2_gc_write_reflink_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k,
				     size_t *idx)
{
	struct bch_fs *c = trans->c;
	const __le64 *refcount = bkey_refcount_c(k);
	struct printbuf buf = PRINTBUF;
	struct reflink_gc *r;
	int ret = 0;

	if (!refcount)
		return 0;

	while ((r = genradix_ptr(&c->reflink_gc_table, *idx)) &&
	       r->offset < k.k->p.offset)
		++*idx;

	if (!r ||
	    r->offset != k.k->p.offset ||
	    r->size != k.k->size) {
		bch_err(c, "unexpected inconsistency walking reflink table at gc finish");
		return -EINVAL;
	}

	if (fsck_err_on(r->refcount != le64_to_cpu(*refcount), c,
			reflink_v_refcount_wrong,
			"reflink key has wrong refcount:\n"
			"  %s\n"
			"  should be %u",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf),
			r->refcount)) {
		struct bkey_i *new = bch2_bkey_make_mut_noupdate(trans, k);
		ret = PTR_ERR_OR_ZERO(new);
		if (ret)
			return ret;

		if (!r->refcount)
			new->k.type = KEY_TYPE_deleted;
		else
			*bkey_refcount(bkey_i_to_s(new)) = cpu_to_le64(r->refcount);
		ret = bch2_trans_update(trans, iter, new, 0);
	}
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static int bch2_gc_reflink_done(struct bch_fs *c, bool metadata_only)
{
	size_t idx = 0;

	if (metadata_only)
		return 0;

	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_reflink, POS_MIN,
				BTREE_ITER_PREFETCH, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_gc_write_reflink_key(trans, &iter, k, &idx)));
	c->reflink_gc_nr = 0;
	return ret;
}

static int bch2_gc_reflink_start(struct bch_fs *c,
				 bool metadata_only)
{

	if (metadata_only)
		return 0;

	c->reflink_gc_nr = 0;

	int ret = bch2_trans_run(c,
		for_each_btree_key(trans, iter, BTREE_ID_reflink, POS_MIN,
				   BTREE_ITER_PREFETCH, k, ({
			const __le64 *refcount = bkey_refcount_c(k);

			if (!refcount)
				continue;

			struct reflink_gc *r = genradix_ptr_alloc(&c->reflink_gc_table,
							c->reflink_gc_nr++, GFP_KERNEL);
			if (!r) {
				ret = -BCH_ERR_ENOMEM_gc_reflink_start;
				break;
			}

			r->offset	= k.k->p.offset;
			r->size		= k.k->size;
			r->refcount	= 0;
			0;
		})));

	bch_err_fn(c, ret);
	return ret;
}

static void bch2_gc_reflink_reset(struct bch_fs *c, bool metadata_only)
{
	struct genradix_iter iter;
	struct reflink_gc *r;

	genradix_for_each(&c->reflink_gc_table, iter, r)
		r->refcount = 0;
}

static int bch2_gc_write_stripes_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct printbuf buf = PRINTBUF;
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

	if (fsck_err_on(bad, c, stripe_sector_count_wrong,
			"%s", buf.buf)) {
		struct bkey_i_stripe *new;

		new = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
		ret = PTR_ERR_OR_ZERO(new);
		if (ret)
			return ret;

		bkey_reassemble(&new->k_i, k);

		for (i = 0; i < new->v.nr_blocks; i++)
			stripe_blockcount_set(&new->v, i, m ? m->block_sectors[i] : 0);

		ret = bch2_trans_update(trans, iter, &new->k_i, 0);
	}
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static int bch2_gc_stripes_done(struct bch_fs *c, bool metadata_only)
{
	if (metadata_only)
		return 0;

	return bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_stripes, POS_MIN,
				BTREE_ITER_PREFETCH, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_gc_write_stripes_key(trans, &iter, k)));
}

static void bch2_gc_stripes_reset(struct bch_fs *c, bool metadata_only)
{
	genradix_free(&c->gc_stripes);
}

/**
 * bch2_gc - walk _all_ references to buckets, and recompute them:
 *
 * @c:			filesystem object
 * @initial:		are we in recovery?
 * @metadata_only:	are we just checking metadata references, or everything?
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
int bch2_gc(struct bch_fs *c, bool initial, bool metadata_only)
{
	unsigned iter = 0;
	int ret;

	lockdep_assert_held(&c->state_lock);

	down_write(&c->gc_lock);

	bch2_btree_interior_updates_flush(c);

	ret   = bch2_gc_start(c) ?:
		bch2_gc_alloc_start(c, metadata_only) ?:
		bch2_gc_reflink_start(c, metadata_only);
	if (ret)
		goto out;
again:
	gc_pos_set(c, gc_phase(GC_PHASE_START));

	bch2_mark_superblocks(c);

	ret = bch2_gc_btrees(c, initial, metadata_only);

	if (ret)
		goto out;

#if 0
	bch2_mark_pending_btree_node_frees(c);
#endif
	c->gc_count++;

	if (test_bit(BCH_FS_need_another_gc, &c->flags) ||
	    (!iter && bch2_test_restart_gc)) {
		if (iter++ > 2) {
			bch_info(c, "Unable to fix bucket gens, looping");
			ret = -EINVAL;
			goto out;
		}

		/*
		 * XXX: make sure gens we fixed got saved
		 */
		bch_info(c, "Second GC pass needed, restarting:");
		clear_bit(BCH_FS_need_another_gc, &c->flags);
		__gc_pos_set(c, gc_phase(GC_PHASE_NOT_RUNNING));

		bch2_gc_stripes_reset(c, metadata_only);
		bch2_gc_alloc_reset(c, metadata_only);
		bch2_gc_reflink_reset(c, metadata_only);
		ret = bch2_gc_reset(c);
		if (ret)
			goto out;

		/* flush fsck errors, reset counters */
		bch2_flush_fsck_errs(c);
		goto again;
	}
out:
	if (!ret) {
		bch2_journal_block(&c->journal);

		ret   = bch2_gc_alloc_done(c, metadata_only) ?:
			bch2_gc_done(c, initial, metadata_only) ?:
			bch2_gc_stripes_done(c, metadata_only) ?:
			bch2_gc_reflink_done(c, metadata_only);

		bch2_journal_unblock(&c->journal);
	}

	percpu_down_write(&c->mark_lock);
	/* Indicates that gc is no longer in progress: */
	__gc_pos_set(c, gc_phase(GC_PHASE_NOT_RUNNING));

	bch2_gc_free(c);
	percpu_up_write(&c->mark_lock);

	up_write(&c->gc_lock);

	/*
	 * At startup, allocations can happen directly instead of via the
	 * allocator thread - issue wakeup in case they blocked on gc_lock:
	 */
	closure_wake_up(&c->freelist_wait);
	bch_err_fn(c, ret);
	return ret;
}

static int gc_btree_gens_key(struct btree_trans *trans,
			     struct btree_iter *iter,
			     struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct bkey_i *u;
	int ret;

	percpu_down_read(&c->mark_lock);
	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);

		if (ptr_stale(ca, ptr) > 16) {
			percpu_up_read(&c->mark_lock);
			goto update;
		}
	}

	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
		u8 *gen = &ca->oldest_gen[PTR_BUCKET_NR(ca, ptr)];

		if (gen_after(*gen, ptr->gen))
			*gen = ptr->gen;
	}
	percpu_up_read(&c->mark_lock);
	return 0;
update:
	u = bch2_bkey_make_mut(trans, iter, &k, 0);
	ret = PTR_ERR_OR_ZERO(u);
	if (ret)
		return ret;

	bch2_extent_normalize(c, bkey_i_to_s(u));
	return 0;
}

static int bch2_alloc_write_oldest_gen(struct btree_trans *trans, struct btree_iter *iter,
				       struct bkey_s_c k)
{
	struct bch_dev *ca = bch_dev_bkey_exists(trans->c, iter->pos.inode);
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);
	struct bkey_i_alloc_v4 *a_mut;
	int ret;

	if (a->oldest_gen == ca->oldest_gen[iter->pos.offset])
		return 0;

	a_mut = bch2_alloc_to_v4_mut(trans, k);
	ret = PTR_ERR_OR_ZERO(a_mut);
	if (ret)
		return ret;

	a_mut->v.oldest_gen = ca->oldest_gen[iter->pos.offset];
	a_mut->v.data_type = alloc_data_type(a_mut->v, a_mut->v.data_type);

	return bch2_trans_update(trans, iter, &a_mut->k_i, 0);
}

int bch2_gc_gens(struct bch_fs *c)
{
	u64 b, start_time = local_clock();
	int ret;

	/*
	 * Ideally we would be using state_lock and not gc_lock here, but that
	 * introduces a deadlock in the RO path - we currently take the state
	 * lock at the start of going RO, thus the gc thread may get stuck:
	 */
	if (!mutex_trylock(&c->gc_gens_lock))
		return 0;

	trace_and_count(c, gc_gens_start, c);
	down_read(&c->gc_lock);

	for_each_member_device(c, ca) {
		struct bucket_gens *gens = bucket_gens(ca);

		BUG_ON(ca->oldest_gen);

		ca->oldest_gen = kvmalloc(gens->nbuckets, GFP_KERNEL);
		if (!ca->oldest_gen) {
			percpu_ref_put(&ca->ref);
			ret = -BCH_ERR_ENOMEM_gc_gens;
			goto err;
		}

		for (b = gens->first_bucket;
		     b < gens->nbuckets; b++)
			ca->oldest_gen[b] = gens->b[b];
	}

	for (unsigned i = 0; i < BTREE_ID_NR; i++)
		if (btree_type_has_ptrs(i)) {
			c->gc_gens_btree = i;
			c->gc_gens_pos = POS_MIN;

			ret = bch2_trans_run(c,
				for_each_btree_key_commit(trans, iter, i,
						POS_MIN,
						BTREE_ITER_PREFETCH|BTREE_ITER_ALL_SNAPSHOTS,
						k,
						NULL, NULL,
						BCH_TRANS_COMMIT_no_enospc,
					gc_btree_gens_key(trans, &iter, k)));
			if (ret)
				goto err;
		}

	ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter, BTREE_ID_alloc,
				POS_MIN,
				BTREE_ITER_PREFETCH,
				k,
				NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc,
			bch2_alloc_write_oldest_gen(trans, &iter, k)));
	if (ret)
		goto err;

	c->gc_gens_btree	= 0;
	c->gc_gens_pos		= POS_MIN;

	c->gc_count++;

	bch2_time_stats_update(&c->times[BCH_TIME_btree_gc], start_time);
	trace_and_count(c, gc_gens_end, c);
err:
	for_each_member_device(c, ca) {
		kvfree(ca->oldest_gen);
		ca->oldest_gen = NULL;
	}

	up_read(&c->gc_lock);
	mutex_unlock(&c->gc_gens_lock);
	if (!bch2_err_matches(ret, EROFS))
		bch_err_fn(c, ret);
	return ret;
}

static int bch2_gc_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last = atomic64_read(&clock->now);
	unsigned last_kick = atomic_read(&c->kick_gc);

	set_freezable();

	while (1) {
		while (1) {
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop()) {
				__set_current_state(TASK_RUNNING);
				return 0;
			}

			if (atomic_read(&c->kick_gc) != last_kick)
				break;

			if (c->btree_gc_periodic) {
				unsigned long next = last + c->capacity / 16;

				if (atomic64_read(&clock->now) >= next)
					break;

				bch2_io_clock_schedule_timeout(clock, next);
			} else {
				schedule();
			}

			try_to_freeze();
		}
		__set_current_state(TASK_RUNNING);

		last = atomic64_read(&clock->now);
		last_kick = atomic_read(&c->kick_gc);

		/*
		 * Full gc is currently incompatible with btree key cache:
		 */
#if 0
		ret = bch2_gc(c, false, false);
#else
		bch2_gc_gens(c);
#endif
		debug_check_no_locks_held();
	}

	return 0;
}

void bch2_gc_thread_stop(struct bch_fs *c)
{
	struct task_struct *p;

	p = c->gc_thread;
	c->gc_thread = NULL;

	if (p) {
		kthread_stop(p);
		put_task_struct(p);
	}
}

int bch2_gc_thread_start(struct bch_fs *c)
{
	struct task_struct *p;

	if (c->gc_thread)
		return 0;

	p = kthread_create(bch2_gc_thread, c, "bch-gc/%s", c->name);
	if (IS_ERR(p)) {
		bch_err_fn(c, PTR_ERR(p));
		return PTR_ERR(p);
	}

	get_task_struct(p);
	c->gc_thread = p;
	wake_up_process(p);
	return 0;
}
