// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "bkey_methods.h"
#include "bkey_buf.h"
#include "btree_locking.h"
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
#include "recovery.h"
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

/*
 * Missing: if an interior btree node is empty, we need to do something -
 * perhaps just kill it
 */
static int bch2_gc_check_topology(struct bch_fs *c,
				  struct btree *b,
				  struct bkey_buf *prev,
				  struct bkey_buf cur,
				  bool is_last)
{
	struct bpos node_start	= b->data->min_key;
	struct bpos node_end	= b->data->max_key;
	struct bpos expected_start = bkey_deleted(&prev->k->k)
		? node_start
		: bpos_successor(prev->k->k.p);
	char buf1[200], buf2[200];
	int ret = 0;

	if (cur.k->k.type == KEY_TYPE_btree_ptr_v2) {
		struct bkey_i_btree_ptr_v2 *bp = bkey_i_to_btree_ptr_v2(cur.k);

		if (bkey_deleted(&prev->k->k)) {
			struct printbuf out = PBUF(buf1);
			pr_buf(&out, "start of node: ");
			bch2_bpos_to_text(&out, node_start);
		} else {
			bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(prev->k));
		}

		if (bpos_cmp(expected_start, bp->v.min_key)) {
			bch2_topology_error(c);

			if (__fsck_err(c,
				  FSCK_CAN_FIX|
				  FSCK_CAN_IGNORE|
				  FSCK_NO_RATELIMIT,
				  "btree node with incorrect min_key at btree %s level %u:\n"
				  "  prev %s\n"
				  "  cur %s",
				  bch2_btree_ids[b->c.btree_id], b->c.level,
				  buf1,
				  (bch2_bkey_val_to_text(&PBUF(buf2), c, bkey_i_to_s_c(cur.k)), buf2)) &&
			    !test_bit(BCH_FS_TOPOLOGY_REPAIR_DONE, &c->flags)) {
				bch_info(c, "Halting mark and sweep to start topology repair pass");
				return FSCK_ERR_START_TOPOLOGY_REPAIR;
			} else {
				set_bit(BCH_FS_INITIAL_GC_UNFIXED, &c->flags);
			}
		}
	}

	if (is_last && bpos_cmp(cur.k->k.p, node_end)) {
		bch2_topology_error(c);

		if (__fsck_err(c,
			  FSCK_CAN_FIX|
			  FSCK_CAN_IGNORE|
			  FSCK_NO_RATELIMIT,
			  "btree node with incorrect max_key at btree %s level %u:\n"
			  "  %s\n"
			  "  expected %s",
			  bch2_btree_ids[b->c.btree_id], b->c.level,
			  (bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(cur.k)), buf1),
			  (bch2_bpos_to_text(&PBUF(buf2), node_end), buf2)) &&
		    !test_bit(BCH_FS_TOPOLOGY_REPAIR_DONE, &c->flags)) {
			bch_info(c, "Halting mark and sweep to start topology repair pass");
			return FSCK_ERR_START_TOPOLOGY_REPAIR;
		} else {
			set_bit(BCH_FS_INITIAL_GC_UNFIXED, &c->flags);
		}
	}

	bch2_bkey_buf_copy(prev, c, cur.k);
fsck_err:
	return ret;
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

	new = kmalloc(BKEY_BTREE_PTR_U64s_MAX * sizeof(u64), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	btree_ptr_to_v2(b, new);
	b->data->min_key	= new_min;
	new->v.min_key		= new_min;
	SET_BTREE_PTR_RANGE_UPDATED(&new->v, true);

	ret = bch2_journal_key_insert(c, b->c.btree_id, b->c.level + 1, &new->k_i);
	if (ret) {
		kfree(new);
		return ret;
	}

	bch2_btree_node_drop_keys_outside_node(b);

	return 0;
}

static int set_node_max(struct bch_fs *c, struct btree *b, struct bpos new_max)
{
	struct bkey_i_btree_ptr_v2 *new;
	int ret;

	ret = bch2_journal_key_delete(c, b->c.btree_id, b->c.level + 1, b->key.k.p);
	if (ret)
		return ret;

	new = kmalloc(BKEY_BTREE_PTR_U64s_MAX * sizeof(u64), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	btree_ptr_to_v2(b, new);
	b->data->max_key	= new_max;
	new->k.p		= new_max;
	SET_BTREE_PTR_RANGE_UPDATED(&new->v, true);

	ret = bch2_journal_key_insert(c, b->c.btree_id, b->c.level + 1, &new->k_i);
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

static int btree_repair_node_boundaries(struct bch_fs *c, struct btree *b,
					struct btree *prev, struct btree *cur)
{
	struct bpos expected_start = !prev
		? b->data->min_key
		: bpos_successor(prev->key.k.p);
	char buf1[200], buf2[200];
	int ret = 0;

	if (!prev) {
		struct printbuf out = PBUF(buf1);
		pr_buf(&out, "start of node: ");
		bch2_bpos_to_text(&out, b->data->min_key);
	} else {
		bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(&prev->key));
	}

	bch2_bkey_val_to_text(&PBUF(buf2), c, bkey_i_to_s_c(&cur->key));

	if (prev &&
	    bpos_cmp(expected_start, cur->data->min_key) > 0 &&
	    BTREE_NODE_SEQ(cur->data) > BTREE_NODE_SEQ(prev->data)) {
		/* cur overwrites prev: */

		if (mustfix_fsck_err_on(bpos_cmp(prev->data->min_key,
						 cur->data->min_key) >= 0, c,
				"btree node overwritten by next node at btree %s level %u:\n"
				"  node %s\n"
				"  next %s",
				bch2_btree_ids[b->c.btree_id], b->c.level,
				buf1, buf2))
			return DROP_PREV_NODE;

		if (mustfix_fsck_err_on(bpos_cmp(prev->key.k.p,
						 bpos_predecessor(cur->data->min_key)), c,
				"btree node with incorrect max_key at btree %s level %u:\n"
				"  node %s\n"
				"  next %s",
				bch2_btree_ids[b->c.btree_id], b->c.level,
				buf1, buf2))
			ret = set_node_max(c, prev,
					   bpos_predecessor(cur->data->min_key));
	} else {
		/* prev overwrites cur: */

		if (mustfix_fsck_err_on(bpos_cmp(expected_start,
						 cur->data->max_key) >= 0, c,
				"btree node overwritten by prev node at btree %s level %u:\n"
				"  prev %s\n"
				"  node %s",
				bch2_btree_ids[b->c.btree_id], b->c.level,
				buf1, buf2))
			return DROP_THIS_NODE;

		if (mustfix_fsck_err_on(bpos_cmp(expected_start, cur->data->min_key), c,
				"btree node with incorrect min_key at btree %s level %u:\n"
				"  prev %s\n"
				"  node %s",
				bch2_btree_ids[b->c.btree_id], b->c.level,
				buf1, buf2))
		    ret = set_node_min(c, cur, expected_start);
	}
fsck_err:
	return ret;
}

static int btree_repair_node_end(struct bch_fs *c, struct btree *b,
				 struct btree *child)
{
	char buf1[200], buf2[200];
	int ret = 0;

	if (mustfix_fsck_err_on(bpos_cmp(child->key.k.p, b->key.k.p), c,
			"btree node with incorrect max_key at btree %s level %u:\n"
			"  %s\n"
			"  expected %s",
			bch2_btree_ids[b->c.btree_id], b->c.level,
			(bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(&child->key)), buf1),
			(bch2_bpos_to_text(&PBUF(buf2), b->key.k.p), buf2))) {
		ret = set_node_max(c, child, b->key.k.p);
		if (ret)
			return ret;
	}
fsck_err:
	return ret;
}

static int bch2_btree_repair_topology_recurse(struct bch_fs *c, struct btree *b)
{
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	struct bkey_buf prev_k, cur_k;
	struct btree *prev = NULL, *cur = NULL;
	bool have_child, dropped_children = false;
	char buf[200];
	int ret = 0;

	if (!b->c.level)
		return 0;
again:
	prev = NULL;
	have_child = dropped_children = false;
	bch2_bkey_buf_init(&prev_k);
	bch2_bkey_buf_init(&cur_k);
	bch2_btree_and_journal_iter_init_node_iter(&iter, c, b);

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		BUG_ON(bpos_cmp(k.k->p, b->data->min_key) < 0);
		BUG_ON(bpos_cmp(k.k->p, b->data->max_key) > 0);

		bch2_btree_and_journal_iter_advance(&iter);
		bch2_bkey_buf_reassemble(&cur_k, c, k);

		cur = bch2_btree_node_get_noiter(c, cur_k.k,
					b->c.btree_id, b->c.level - 1,
					false);
		ret = PTR_ERR_OR_ZERO(cur);

		if (mustfix_fsck_err_on(ret == -EIO, c,
				"Unreadable btree node at btree %s level %u:\n"
				"  %s",
				bch2_btree_ids[b->c.btree_id],
				b->c.level - 1,
				(bch2_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(cur_k.k)), buf))) {
			bch2_btree_node_evict(c, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			if (ret)
				break;
			continue;
		}

		if (ret) {
			bch_err(c, "%s: error %i getting btree node",
				__func__, ret);
			break;
		}

		ret = btree_repair_node_boundaries(c, b, prev, cur);

		if (ret == DROP_THIS_NODE) {
			six_unlock_read(&cur->c.lock);
			bch2_btree_node_evict(c, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			if (ret)
				break;
			continue;
		}

		if (prev)
			six_unlock_read(&prev->c.lock);
		prev = NULL;

		if (ret == DROP_PREV_NODE) {
			bch2_btree_node_evict(c, prev_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, prev_k.k->k.p);
			if (ret)
				break;

			bch2_btree_and_journal_iter_exit(&iter);
			bch2_bkey_buf_exit(&prev_k, c);
			bch2_bkey_buf_exit(&cur_k, c);
			goto again;
		} else if (ret)
			break;

		prev = cur;
		cur = NULL;
		bch2_bkey_buf_copy(&prev_k, c, cur_k.k);
	}

	if (!ret && !IS_ERR_OR_NULL(prev)) {
		BUG_ON(cur);
		ret = btree_repair_node_end(c, b, prev);
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
	bch2_btree_and_journal_iter_init_node_iter(&iter, c, b);

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		bch2_bkey_buf_reassemble(&cur_k, c, k);
		bch2_btree_and_journal_iter_advance(&iter);

		cur = bch2_btree_node_get_noiter(c, cur_k.k,
					b->c.btree_id, b->c.level - 1,
					false);
		ret = PTR_ERR_OR_ZERO(cur);

		if (ret) {
			bch_err(c, "%s: error %i getting btree node",
				__func__, ret);
			goto err;
		}

		ret = bch2_btree_repair_topology_recurse(c, cur);
		six_unlock_read(&cur->c.lock);
		cur = NULL;

		if (ret == DROP_THIS_NODE) {
			bch2_btree_node_evict(c, cur_k.k);
			ret = bch2_journal_key_delete(c, b->c.btree_id,
						      b->c.level, cur_k.k->k.p);
			dropped_children = true;
		}

		if (ret)
			goto err;

		have_child = true;
	}

	if (mustfix_fsck_err_on(!have_child, c,
			"empty interior btree node at btree %s level %u\n"
			"  %s",
			bch2_btree_ids[b->c.btree_id],
			b->c.level,
			(bch2_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(&b->key)), buf)))
		ret = DROP_THIS_NODE;
err:
fsck_err:
	if (!IS_ERR_OR_NULL(prev))
		six_unlock_read(&prev->c.lock);
	if (!IS_ERR_OR_NULL(cur))
		six_unlock_read(&cur->c.lock);

	bch2_btree_and_journal_iter_exit(&iter);
	bch2_bkey_buf_exit(&prev_k, c);
	bch2_bkey_buf_exit(&cur_k, c);

	if (!ret && dropped_children)
		goto again;

	return ret;
}

static int bch2_repair_topology(struct bch_fs *c)
{
	struct btree *b;
	unsigned i;
	int ret = 0;

	for (i = 0; i < BTREE_ID_NR && !ret; i++) {
		b = c->btree_roots[i].b;
		if (btree_node_fake(b))
			continue;

		six_lock_read(&b->c.lock, NULL, NULL);
		ret = bch2_btree_repair_topology_recurse(c, b);
		six_unlock_read(&b->c.lock);

		if (ret == DROP_THIS_NODE) {
			bch_err(c, "empty btree root - repair unimplemented");
			ret = FSCK_ERR_EXIT;
		}
	}

	return ret;
}

static int bch2_check_fix_ptrs(struct bch_fs *c, enum btree_id btree_id,
			       unsigned level, bool is_root,
			       struct bkey_s_c *k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(*k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p = { 0 };
	bool do_update = false;
	char buf[200];
	int ret = 0;

	bkey_for_each_ptr_decode(k->k, ptrs, p, entry) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, p.ptr.dev);
		struct bucket *g = PTR_BUCKET(ca, &p.ptr, true);
		struct bucket *g2 = PTR_BUCKET(ca, &p.ptr, false);
		enum bch_data_type data_type = bch2_bkey_ptr_data_type(*k, &entry->ptr);

		if (fsck_err_on(g->mark.data_type &&
				g->mark.data_type != data_type, c,
				"bucket %u:%zu different types of data in same bucket: %s, %s\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_types[g->mark.data_type],
				bch2_data_types[data_type],
				(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf))) {
			if (data_type == BCH_DATA_btree) {
				g2->_mark.data_type = g->_mark.data_type = data_type;
				set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);
			} else {
				do_update = true;
			}
		}

		if (fsck_err_on(!g->gen_valid, c,
				"bucket %u:%zu data type %s ptr gen %u missing in alloc btree\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_types[ptr_data_type(k->k, &p.ptr)],
				p.ptr.gen,
				(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf))) {
			if (!p.ptr.cached) {
				g2->_mark.gen	= g->_mark.gen		= p.ptr.gen;
				g2->gen_valid	= g->gen_valid		= true;
				set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);
			} else {
				do_update = true;
			}
		}

		if (fsck_err_on(gen_cmp(p.ptr.gen, g->mark.gen) > 0, c,
				"bucket %u:%zu data type %s ptr gen in the future: %u > %u\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_types[ptr_data_type(k->k, &p.ptr)],
				p.ptr.gen, g->mark.gen,
				(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf))) {
			if (!p.ptr.cached) {
				g2->_mark.gen	= g->_mark.gen	= p.ptr.gen;
				g2->gen_valid	= g->gen_valid	= true;
				g2->_mark.data_type		= 0;
				g2->_mark.dirty_sectors		= 0;
				g2->_mark.cached_sectors	= 0;
				set_bit(BCH_FS_NEED_ANOTHER_GC, &c->flags);
				set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);
			} else {
				do_update = true;
			}
		}

		if (fsck_err_on(!p.ptr.cached &&
				gen_cmp(p.ptr.gen, g->mark.gen) < 0, c,
				"bucket %u:%zu data type %s stale dirty ptr: %u < %u\n"
				"while marking %s",
				p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr),
				bch2_data_types[ptr_data_type(k->k, &p.ptr)],
				p.ptr.gen, g->mark.gen,
				(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf)))
			do_update = true;

		if (p.has_ec) {
			struct stripe *m = genradix_ptr(&c->stripes[true], p.ec.idx);

			if (fsck_err_on(!m || !m->alive, c,
					"pointer to nonexistent stripe %llu\n"
					"while marking %s",
					(u64) p.ec.idx,
					(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf)))
				do_update = true;

			if (fsck_err_on(!bch2_ptr_matches_stripe_m(m, p), c,
					"pointer does not match stripe %llu\n"
					"while marking %s",
					(u64) p.ec.idx,
					(bch2_bkey_val_to_text(&PBUF(buf), c, *k), buf)))
				do_update = true;
		}
	}

	if (do_update) {
		struct bkey_ptrs ptrs;
		union bch_extent_entry *entry;
		struct bch_extent_ptr *ptr;
		struct bkey_i *new;

		if (is_root) {
			bch_err(c, "cannot update btree roots yet");
			return -EINVAL;
		}

		new = kmalloc(bkey_bytes(k->k), GFP_KERNEL);
		if (!new) {
			bch_err(c, "%s: error allocating new key", __func__);
			return -ENOMEM;
		}

		bkey_reassemble(new, *k);

		if (level) {
			/*
			 * We don't want to drop btree node pointers - if the
			 * btree node isn't there anymore, the read path will
			 * sort it out:
			 */
			ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
			bkey_for_each_ptr(ptrs, ptr) {
				struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
				struct bucket *g = PTR_BUCKET(ca, ptr, true);

				ptr->gen = g->mark.gen;
			}
		} else {
			bch2_bkey_drop_ptrs(bkey_i_to_s(new), ptr, ({
				struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
				struct bucket *g = PTR_BUCKET(ca, ptr, true);
				enum bch_data_type data_type = bch2_bkey_ptr_data_type(*k, ptr);

				(ptr->cached &&
				 (!g->gen_valid || gen_cmp(ptr->gen, g->mark.gen) > 0)) ||
				(!ptr->cached &&
				 gen_cmp(ptr->gen, g->mark.gen) < 0) ||
				(g->mark.data_type &&
				 g->mark.data_type != data_type);
			}));
again:
			ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
			bkey_extent_entry_for_each(ptrs, entry) {
				if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_stripe_ptr) {
					struct stripe *m = genradix_ptr(&c->stripes[true],
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

		ret = bch2_journal_key_insert(c, btree_id, level, new);
		if (ret)
			kfree(new);
		else
			*k = bkey_i_to_s_c(new);
	}
fsck_err:
	return ret;
}

/* marking of btree keys/nodes: */

static int bch2_gc_mark_key(struct bch_fs *c, enum btree_id btree_id,
			    unsigned level, bool is_root,
			    struct bkey_s_c *k,
			    u8 *max_stale, bool initial)
{
	struct bkey_ptrs_c ptrs;
	const struct bch_extent_ptr *ptr;
	unsigned flags =
		BTREE_TRIGGER_INSERT|
		BTREE_TRIGGER_GC|
		(initial ? BTREE_TRIGGER_NOATOMIC : 0);
	int ret = 0;

	if (initial) {
		BUG_ON(bch2_journal_seq_verify &&
		       k->k->version.lo > journal_cur_seq(&c->journal));

		ret = bch2_check_fix_ptrs(c, btree_id, level, is_root, k);
		if (ret)
			goto err;

		if (fsck_err_on(k->k->version.lo > atomic64_read(&c->key_version), c,
				"key version number higher than recorded: %llu > %llu",
				k->k->version.lo,
				atomic64_read(&c->key_version)))
			atomic64_set(&c->key_version, k->k->version.lo);

		if (test_bit(BCH_FS_REBUILD_REPLICAS, &c->flags) ||
		    fsck_err_on(!bch2_bkey_replicas_marked(c, *k), c,
				"superblock not marked as containing replicas (type %u)",
				k->k->type)) {
			ret = bch2_mark_bkey_replicas(c, *k);
			if (ret) {
				bch_err(c, "error marking bkey replicas: %i", ret);
				goto err;
			}
		}
	}

	ptrs = bch2_bkey_ptrs_c(*k);
	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
		struct bucket *g = PTR_BUCKET(ca, ptr, true);

		if (gen_after(g->oldest_gen, ptr->gen))
			g->oldest_gen = ptr->gen;

		*max_stale = max(*max_stale, ptr_stale(ca, ptr));
	}

	bch2_mark_key(c, *k, flags);
fsck_err:
err:
	if (ret)
		bch_err(c, "%s: ret %i", __func__, ret);
	return ret;
}

static int btree_gc_mark_node(struct bch_fs *c, struct btree *b, u8 *max_stale,
			      bool initial)
{
	struct btree_node_iter iter;
	struct bkey unpacked;
	struct bkey_s_c k;
	struct bkey_buf prev, cur;
	int ret = 0;

	*max_stale = 0;

	if (!btree_node_type_needs_gc(btree_node_type(b)))
		return 0;

	bch2_btree_node_iter_init_from_start(&iter, b);
	bch2_bkey_buf_init(&prev);
	bch2_bkey_buf_init(&cur);
	bkey_init(&prev.k->k);

	while ((k = bch2_btree_node_iter_peek_unpack(&iter, b, &unpacked)).k) {
		ret = bch2_gc_mark_key(c, b->c.btree_id, b->c.level, false,
				       &k, max_stale, initial);
		if (ret)
			break;

		bch2_btree_node_iter_advance(&iter, b);

		if (b->c.level) {
			bch2_bkey_buf_reassemble(&cur, c, k);

			ret = bch2_gc_check_topology(c, b, &prev, cur,
					bch2_btree_node_iter_end(&iter));
			if (ret)
				break;
		}
	}

	bch2_bkey_buf_exit(&cur, c);
	bch2_bkey_buf_exit(&prev, c);
	return ret;
}

static int bch2_gc_btree(struct bch_fs *c, enum btree_id btree_id,
			 bool initial, bool metadata_only)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct btree *b;
	unsigned depth = metadata_only			? 1
		: bch2_expensive_debug_checks		? 0
		: !btree_node_type_needs_gc(btree_id)	? 1
		: 0;
	u8 max_stale = 0;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);

	gc_pos_set(c, gc_pos_btree(btree_id, POS_MIN, 0));

	__for_each_btree_node(&trans, iter, btree_id, POS_MIN,
			      0, depth, BTREE_ITER_PREFETCH, b) {
		bch2_verify_btree_nr_keys(b);

		gc_pos_set(c, gc_pos_btree_node(b));

		ret = btree_gc_mark_node(c, b, &max_stale, initial);
		if (ret)
			break;

		if (!initial) {
			if (max_stale > 64)
				bch2_btree_node_rewrite(&trans, iter,
						b->data->keys.seq,
						BTREE_INSERT_NOWAIT|
						BTREE_INSERT_GC_LOCK_HELD);
			else if (!bch2_btree_gc_rewrite_disabled &&
				 (bch2_btree_gc_always_rewrite || max_stale > 16))
				bch2_btree_node_rewrite(&trans, iter,
						b->data->keys.seq,
						BTREE_INSERT_NOWAIT|
						BTREE_INSERT_GC_LOCK_HELD);
		}

		bch2_trans_cond_resched(&trans);
	}
	bch2_trans_iter_put(&trans, iter);

	ret = bch2_trans_exit(&trans) ?: ret;
	if (ret)
		return ret;

	mutex_lock(&c->btree_root_lock);
	b = c->btree_roots[btree_id].b;
	if (!btree_node_fake(b)) {
		struct bkey_s_c k = bkey_i_to_s_c(&b->key);

		ret = bch2_gc_mark_key(c, b->c.btree_id, b->c.level, true,
				       &k, &max_stale, initial);
	}
	gc_pos_set(c, gc_pos_btree_root(b->c.btree_id));
	mutex_unlock(&c->btree_root_lock);

	return ret;
}

static int bch2_gc_btree_init_recurse(struct bch_fs *c, struct btree *b,
				      unsigned target_depth)
{
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	struct bkey_buf cur, prev;
	u8 max_stale = 0;
	char buf[200];
	int ret = 0;

	bch2_btree_and_journal_iter_init_node_iter(&iter, c, b);
	bch2_bkey_buf_init(&prev);
	bch2_bkey_buf_init(&cur);
	bkey_init(&prev.k->k);

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		BUG_ON(bpos_cmp(k.k->p, b->data->min_key) < 0);
		BUG_ON(bpos_cmp(k.k->p, b->data->max_key) > 0);

		ret = bch2_gc_mark_key(c, b->c.btree_id, b->c.level, false,
				       &k, &max_stale, true);
		if (ret) {
			bch_err(c, "%s: error %i from bch2_gc_mark_key", __func__, ret);
			goto fsck_err;
		}

		if (b->c.level) {
			bch2_bkey_buf_reassemble(&cur, c, k);
			k = bkey_i_to_s_c(cur.k);

			bch2_btree_and_journal_iter_advance(&iter);

			ret = bch2_gc_check_topology(c, b,
					&prev, cur,
					!bch2_btree_and_journal_iter_peek(&iter).k);
			if (ret)
				goto fsck_err;
		} else {
			bch2_btree_and_journal_iter_advance(&iter);
		}
	}

	if (b->c.level > target_depth) {
		bch2_btree_and_journal_iter_exit(&iter);
		bch2_btree_and_journal_iter_init_node_iter(&iter, c, b);

		while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
			struct btree *child;

			bch2_bkey_buf_reassemble(&cur, c, k);
			bch2_btree_and_journal_iter_advance(&iter);

			child = bch2_btree_node_get_noiter(c, cur.k,
						b->c.btree_id, b->c.level - 1,
						false);
			ret = PTR_ERR_OR_ZERO(child);

			if (ret == -EIO) {
				bch2_topology_error(c);

				if (__fsck_err(c,
					  FSCK_CAN_FIX|
					  FSCK_CAN_IGNORE|
					  FSCK_NO_RATELIMIT,
					  "Unreadable btree node at btree %s level %u:\n"
					  "  %s",
					  bch2_btree_ids[b->c.btree_id],
					  b->c.level - 1,
					  (bch2_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(cur.k)), buf)) &&
				    !test_bit(BCH_FS_TOPOLOGY_REPAIR_DONE, &c->flags)) {
					ret = FSCK_ERR_START_TOPOLOGY_REPAIR;
					bch_info(c, "Halting mark and sweep to start topology repair pass");
					goto fsck_err;
				} else {
					/* Continue marking when opted to not
					 * fix the error: */
					ret = 0;
					set_bit(BCH_FS_INITIAL_GC_UNFIXED, &c->flags);
					continue;
				}
			} else if (ret) {
				bch_err(c, "%s: error %i getting btree node",
					__func__, ret);
				break;
			}

			ret = bch2_gc_btree_init_recurse(c, child,
							 target_depth);
			six_unlock_read(&child->c.lock);

			if (ret)
				break;
		}
	}
fsck_err:
	bch2_bkey_buf_exit(&cur, c);
	bch2_bkey_buf_exit(&prev, c);
	bch2_btree_and_journal_iter_exit(&iter);
	return ret;
}

static int bch2_gc_btree_init(struct bch_fs *c,
			      enum btree_id btree_id,
			      bool metadata_only)
{
	struct btree *b;
	unsigned target_depth = metadata_only		? 1
		: bch2_expensive_debug_checks		? 0
		: !btree_node_type_needs_gc(btree_id)	? 1
		: 0;
	u8 max_stale = 0;
	char buf[100];
	int ret = 0;

	b = c->btree_roots[btree_id].b;

	if (btree_node_fake(b))
		return 0;

	six_lock_read(&b->c.lock, NULL, NULL);
	if (mustfix_fsck_err_on(bpos_cmp(b->data->min_key, POS_MIN), c,
			"btree root with incorrect min_key: %s",
			(bch2_bpos_to_text(&PBUF(buf), b->data->min_key), buf))) {
		bch_err(c, "repair unimplemented");
		ret = FSCK_ERR_EXIT;
		goto fsck_err;
	}

	if (mustfix_fsck_err_on(bpos_cmp(b->data->max_key, SPOS_MAX), c,
			"btree root with incorrect max_key: %s",
			(bch2_bpos_to_text(&PBUF(buf), b->data->max_key), buf))) {
		bch_err(c, "repair unimplemented");
		ret = FSCK_ERR_EXIT;
		goto fsck_err;
	}

	if (b->c.level >= target_depth)
		ret = bch2_gc_btree_init_recurse(c, b, target_depth);

	if (!ret) {
		struct bkey_s_c k = bkey_i_to_s_c(&b->key);

		ret = bch2_gc_mark_key(c, b->c.btree_id, b->c.level, true,
				       &k, &max_stale, true);
	}
fsck_err:
	six_unlock_read(&b->c.lock);

	if (ret < 0)
		bch_err(c, "%s: ret %i", __func__, ret);
	return ret;
}

static inline int btree_id_gc_phase_cmp(enum btree_id l, enum btree_id r)
{
	return  (int) btree_id_to_gc_phase(l) -
		(int) btree_id_to_gc_phase(r);
}

static int bch2_gc_btrees(struct bch_fs *c, bool initial, bool metadata_only)
{
	enum btree_id ids[BTREE_ID_NR];
	unsigned i;
	int ret = 0;

	for (i = 0; i < BTREE_ID_NR; i++)
		ids[i] = i;
	bubble_sort(ids, BTREE_ID_NR, btree_id_gc_phase_cmp);

	for (i = 0; i < BTREE_ID_NR && !ret; i++)
		ret = initial
			? bch2_gc_btree_init(c, ids[i], metadata_only)
			: bch2_gc_btree(c, ids[i], initial, metadata_only);

	if (ret < 0)
		bch_err(c, "%s: ret %i", __func__, ret);
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

void bch2_mark_dev_superblock(struct bch_fs *c, struct bch_dev *ca,
			      unsigned flags)
{
	struct bch_sb_layout *layout = &ca->disk_sb.sb->layout;
	unsigned i;
	u64 b;

	/*
	 * This conditional is kind of gross, but we may be called from the
	 * device add path, before the new device has actually been added to the
	 * running filesystem:
	 */
	if (c) {
		lockdep_assert_held(&c->sb_lock);
		percpu_down_read(&c->mark_lock);
	}

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

	if (c)
		percpu_up_read(&c->mark_lock);
}

static void bch2_mark_superblocks(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	mutex_lock(&c->sb_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_SB));

	for_each_online_member(ca, c, i)
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
			bch2_mark_key(c, bkey_i_to_s_c(&d->key),
				      BTREE_TRIGGER_INSERT|BTREE_TRIGGER_GC);

	mutex_unlock(&c->btree_interior_update_lock);
}
#endif

static void bch2_gc_free(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	genradix_free(&c->stripes[1]);

	for_each_member_device(ca, c, i) {
		kvpfree(rcu_dereference_protected(ca->buckets[1], 1),
			sizeof(struct bucket_array) +
			ca->mi.nbuckets * sizeof(struct bucket));
		ca->buckets[1] = NULL;

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
	bool verify = !metadata_only && (!initial ||
		       (c->sb.compat & (1ULL << BCH_COMPAT_alloc_info)));
	unsigned i, dev;
	int ret = 0;

#define copy_field(_f, _msg, ...)					\
	if (dst->_f != src->_f) {					\
		if (verify)						\
			fsck_err(c, _msg ": got %llu, should be %llu"	\
				, ##__VA_ARGS__, dst->_f, src->_f);	\
		dst->_f = src->_f;					\
		set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);		\
	}
#define copy_stripe_field(_f, _msg, ...)				\
	if (dst->_f != src->_f) {					\
		if (verify)						\
			fsck_err(c, "stripe %zu has wrong "_msg		\
				": got %u, should be %u",		\
				iter.pos, ##__VA_ARGS__,		\
				dst->_f, src->_f);			\
		dst->_f = src->_f;					\
		set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);		\
	}
#define copy_bucket_field(_f)						\
	if (dst->b[b].mark._f != src->b[b].mark._f) {			\
		if (verify)						\
			fsck_err(c, "bucket %u:%zu gen %u data type %s has wrong " #_f	\
				": got %u, should be %u", dev, b,	\
				dst->b[b].mark.gen,			\
				bch2_data_types[dst->b[b].mark.data_type],\
				dst->b[b].mark._f, src->b[b].mark._f);	\
		dst->b[b]._mark._f = src->b[b].mark._f;			\
		set_bit(BCH_FS_NEED_ALLOC_WRITE, &c->flags);		\
	}
#define copy_dev_field(_f, _msg, ...)					\
	copy_field(_f, "dev %u has wrong " _msg, dev, ##__VA_ARGS__)
#define copy_fs_field(_f, _msg, ...)					\
	copy_field(_f, "fs has wrong " _msg, ##__VA_ARGS__)

	if (!metadata_only) {
		struct genradix_iter iter = genradix_iter_init(&c->stripes[1], 0);
		struct stripe *dst, *src;

		while ((src = genradix_iter_peek(&iter, &c->stripes[1]))) {
			dst = genradix_ptr_alloc(&c->stripes[0], iter.pos, GFP_KERNEL);

			if (dst->alive		!= src->alive ||
			    dst->sectors	!= src->sectors ||
			    dst->algorithm	!= src->algorithm ||
			    dst->nr_blocks	!= src->nr_blocks ||
			    dst->nr_redundant	!= src->nr_redundant) {
				bch_err(c, "unexpected stripe inconsistency at bch2_gc_done, confused");
				ret = -EINVAL;
				goto fsck_err;
			}

			for (i = 0; i < ARRAY_SIZE(dst->block_sectors); i++)
				copy_stripe_field(block_sectors[i],
						  "block_sectors[%u]", i);

			dst->blocks_nonempty = 0;
			for (i = 0; i < dst->nr_blocks; i++)
				dst->blocks_nonempty += dst->block_sectors[i] != 0;

			genradix_iter_advance(&iter, &c->stripes[1]);
		}
	}

	for (i = 0; i < ARRAY_SIZE(c->usage); i++)
		bch2_fs_usage_acc_to_base(c, i);

	for_each_member_device(ca, c, dev) {
		struct bucket_array *dst = __bucket_array(ca, 0);
		struct bucket_array *src = __bucket_array(ca, 1);
		size_t b;

		for (b = 0; b < src->nbuckets; b++) {
			copy_bucket_field(gen);
			copy_bucket_field(data_type);
			copy_bucket_field(stripe);
			copy_bucket_field(dirty_sectors);
			copy_bucket_field(cached_sectors);

			dst->b[b].oldest_gen = src->b[b].oldest_gen;
		}

		{
			struct bch_dev_usage *dst = ca->usage_base;
			struct bch_dev_usage *src = (void *)
				bch2_acc_percpu_u64s((void *) ca->usage_gc,
						     dev_usage_u64s());

			copy_dev_field(buckets_ec,		"buckets_ec");
			copy_dev_field(buckets_unavailable,	"buckets_unavailable");

			for (i = 0; i < BCH_DATA_NR; i++) {
				copy_dev_field(d[i].buckets,	"%s buckets", bch2_data_types[i]);
				copy_dev_field(d[i].sectors,	"%s sectors", bch2_data_types[i]);
				copy_dev_field(d[i].fragmented,	"%s fragmented", bch2_data_types[i]);
			}
		}
	};

	{
		unsigned nr = fs_usage_u64s(c);
		struct bch_fs_usage *dst = c->usage_base;
		struct bch_fs_usage *src = (void *)
			bch2_acc_percpu_u64s((void *) c->usage_gc, nr);

		copy_fs_field(hidden,		"hidden");
		copy_fs_field(btree,		"btree");

		if (!metadata_only) {
			copy_fs_field(data,	"data");
			copy_fs_field(cached,	"cached");
			copy_fs_field(reserved,	"reserved");
			copy_fs_field(nr_inodes,"nr_inodes");

			for (i = 0; i < BCH_REPLICAS_MAX; i++)
				copy_fs_field(persistent_reserved[i],
					      "persistent_reserved[%i]", i);
		}

		for (i = 0; i < c->replicas.nr; i++) {
			struct bch_replicas_entry *e =
				cpu_replicas_entry(&c->replicas, i);
			char buf[80];

			if (metadata_only &&
			    (e->data_type == BCH_DATA_user ||
			     e->data_type == BCH_DATA_cached))
				continue;

			bch2_replicas_entry_to_text(&PBUF(buf), e);

			copy_fs_field(replicas[i], "%s", buf);
		}
	}

#undef copy_fs_field
#undef copy_dev_field
#undef copy_bucket_field
#undef copy_stripe_field
#undef copy_field
fsck_err:
	if (ca)
		percpu_ref_put(&ca->ref);
	if (ret)
		bch_err(c, "%s: ret %i", __func__, ret);
	return ret;
}

static int bch2_gc_start(struct bch_fs *c,
			 bool metadata_only)
{
	struct bch_dev *ca = NULL;
	unsigned i;
	int ret;

	BUG_ON(c->usage_gc);

	c->usage_gc = __alloc_percpu_gfp(fs_usage_u64s(c) * sizeof(u64),
					 sizeof(u64), GFP_KERNEL);
	if (!c->usage_gc) {
		bch_err(c, "error allocating c->usage_gc");
		return -ENOMEM;
	}

	for_each_member_device(ca, c, i) {
		BUG_ON(ca->buckets[1]);
		BUG_ON(ca->usage_gc);

		ca->buckets[1] = kvpmalloc(sizeof(struct bucket_array) +
				ca->mi.nbuckets * sizeof(struct bucket),
				GFP_KERNEL|__GFP_ZERO);
		if (!ca->buckets[1]) {
			percpu_ref_put(&ca->ref);
			bch_err(c, "error allocating ca->buckets[gc]");
			return -ENOMEM;
		}

		ca->usage_gc = alloc_percpu(struct bch_dev_usage);
		if (!ca->usage_gc) {
			bch_err(c, "error allocating ca->usage_gc");
			percpu_ref_put(&ca->ref);
			return -ENOMEM;
		}
	}

	ret = bch2_ec_mem_alloc(c, true);
	if (ret) {
		bch_err(c, "error allocating ec gc mem");
		return ret;
	}

	percpu_down_write(&c->mark_lock);

	/*
	 * indicate to stripe code that we need to allocate for the gc stripes
	 * radix tree, too
	 */
	gc_pos_set(c, gc_phase(GC_PHASE_START));

	for_each_member_device(ca, c, i) {
		struct bucket_array *dst = __bucket_array(ca, 1);
		struct bucket_array *src = __bucket_array(ca, 0);
		size_t b;

		dst->first_bucket	= src->first_bucket;
		dst->nbuckets		= src->nbuckets;

		for (b = 0; b < src->nbuckets; b++) {
			struct bucket *d = &dst->b[b];
			struct bucket *s = &src->b[b];

			d->_mark.gen = dst->b[b].oldest_gen = s->mark.gen;
			d->gen_valid = s->gen_valid;

			if (metadata_only &&
			    (s->mark.data_type == BCH_DATA_user ||
			     s->mark.data_type == BCH_DATA_cached))
				d->_mark = s->mark;
		}
	};

	percpu_up_write(&c->mark_lock);

	return 0;
}

static int bch2_gc_reflink_done_initial_fn(struct bch_fs *c, struct bkey_s_c k)
{
	struct reflink_gc *r;
	const __le64 *refcount = bkey_refcount_c(k);
	char buf[200];
	int ret = 0;

	if (!refcount)
		return 0;

	r = genradix_ptr(&c->reflink_gc_table, c->reflink_gc_idx++);
	if (!r)
		return -ENOMEM;

	if (!r ||
	    r->offset != k.k->p.offset ||
	    r->size != k.k->size) {
		bch_err(c, "unexpected inconsistency walking reflink table at gc finish");
		return -EINVAL;
	}

	if (fsck_err_on(r->refcount != le64_to_cpu(*refcount), c,
			"reflink key has wrong refcount:\n"
			"  %s\n"
			"  should be %u",
			(bch2_bkey_val_to_text(&PBUF(buf), c, k), buf),
			r->refcount)) {
		struct bkey_i *new;

		new = kmalloc(bkey_bytes(k.k), GFP_KERNEL);
		if (!new) {
			ret = -ENOMEM;
			goto fsck_err;
		}

		bkey_reassemble(new, k);

		if (!r->refcount) {
			new->k.type = KEY_TYPE_deleted;
			new->k.size = 0;
		} else {
			*bkey_refcount(new) = cpu_to_le64(r->refcount);
		}

		ret = bch2_journal_key_insert(c, BTREE_ID_reflink, 0, new);
		if (ret)
			kfree(new);
	}
fsck_err:
	return ret;
}

static int bch2_gc_reflink_done(struct bch_fs *c, bool initial,
				bool metadata_only)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct reflink_gc *r;
	size_t idx = 0;
	char buf[200];
	int ret = 0;

	if (metadata_only)
		return 0;

	if (initial) {
		c->reflink_gc_idx = 0;

		ret = bch2_btree_and_journal_walk(c, BTREE_ID_reflink,
				bch2_gc_reflink_done_initial_fn);
		goto out;
	}

	bch2_trans_init(&trans, c, 0, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_reflink, POS_MIN,
			   BTREE_ITER_PREFETCH, k, ret) {
		const __le64 *refcount = bkey_refcount_c(k);

		if (!refcount)
			continue;

		r = genradix_ptr(&c->reflink_gc_table, idx);
		if (!r ||
		    r->offset != k.k->p.offset ||
		    r->size != k.k->size) {
			bch_err(c, "unexpected inconsistency walking reflink table at gc finish");
			ret = -EINVAL;
			break;
		}

		if (fsck_err_on(r->refcount != le64_to_cpu(*refcount), c,
				"reflink key has wrong refcount:\n"
				"  %s\n"
				"  should be %u",
				(bch2_bkey_val_to_text(&PBUF(buf), c, k), buf),
				r->refcount)) {
			struct bkey_i *new;

			new = kmalloc(bkey_bytes(k.k), GFP_KERNEL);
			if (!new) {
				ret = -ENOMEM;
				break;
			}

			bkey_reassemble(new, k);

			if (!r->refcount)
				new->k.type = KEY_TYPE_deleted;
			else
				*bkey_refcount(new) = cpu_to_le64(r->refcount);

			ret = __bch2_trans_do(&trans, NULL, NULL, 0,
					__bch2_btree_insert(&trans, BTREE_ID_reflink, new));
			kfree(new);

			if (ret)
				break;
		}
	}
fsck_err:
	bch2_trans_iter_put(&trans, iter);
	bch2_trans_exit(&trans);
out:
	genradix_free(&c->reflink_gc_table);
	c->reflink_gc_nr = 0;
	return ret;
}

static int bch2_gc_reflink_start_initial_fn(struct bch_fs *c, struct bkey_s_c k)
{

	struct reflink_gc *r;
	const __le64 *refcount = bkey_refcount_c(k);

	if (!refcount)
		return 0;

	r = genradix_ptr_alloc(&c->reflink_gc_table, c->reflink_gc_nr++,
			       GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	r->offset	= k.k->p.offset;
	r->size		= k.k->size;
	r->refcount	= 0;
	return 0;
}

static int bch2_gc_reflink_start(struct bch_fs *c, bool initial,
				 bool metadata_only)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct reflink_gc *r;
	int ret;

	if (metadata_only)
		return 0;

	genradix_free(&c->reflink_gc_table);
	c->reflink_gc_nr = 0;

	if (initial)
		return bch2_btree_and_journal_walk(c, BTREE_ID_reflink,
				bch2_gc_reflink_start_initial_fn);

	bch2_trans_init(&trans, c, 0, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_reflink, POS_MIN,
			   BTREE_ITER_PREFETCH, k, ret) {
		const __le64 *refcount = bkey_refcount_c(k);

		if (!refcount)
			continue;

		r = genradix_ptr_alloc(&c->reflink_gc_table, c->reflink_gc_nr++,
				       GFP_KERNEL);
		if (!r) {
			ret = -ENOMEM;
			break;
		}

		r->offset	= k.k->p.offset;
		r->size		= k.k->size;
		r->refcount	= 0;
	}
	bch2_trans_iter_put(&trans, iter);

	bch2_trans_exit(&trans);
	return 0;
}

/**
 * bch2_gc - walk _all_ references to buckets, and recompute them:
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
	struct bch_dev *ca;
	u64 start_time = local_clock();
	unsigned i, iter = 0;
	int ret;

	lockdep_assert_held(&c->state_lock);
	trace_gc_start(c);

	down_write(&c->gc_lock);

	/* flush interior btree updates: */
	closure_wait_event(&c->btree_interior_update_wait,
			   !bch2_btree_interior_updates_nr_pending(c));
again:
	ret   = bch2_gc_start(c, metadata_only) ?:
		bch2_gc_reflink_start(c, initial, metadata_only);
	if (ret)
		goto out;

	bch2_mark_superblocks(c);

	if (test_bit(BCH_FS_TOPOLOGY_ERROR, &c->flags) &&
	    !test_bit(BCH_FS_INITIAL_GC_DONE, &c->flags) &&
	    c->opts.fix_errors != FSCK_OPT_NO) {
		bch_info(c, "starting topology repair pass");
		ret = bch2_repair_topology(c);
		if (ret)
			goto out;
		bch_info(c, "topology repair pass done");

		set_bit(BCH_FS_TOPOLOGY_REPAIR_DONE, &c->flags);
	}

	ret = bch2_gc_btrees(c, initial, metadata_only);

	if (ret == FSCK_ERR_START_TOPOLOGY_REPAIR &&
	    !test_bit(BCH_FS_TOPOLOGY_REPAIR_DONE, &c->flags) &&
	    !test_bit(BCH_FS_INITIAL_GC_DONE, &c->flags)) {
		set_bit(BCH_FS_NEED_ANOTHER_GC, &c->flags);
		ret = 0;
	}

	if (ret == FSCK_ERR_START_TOPOLOGY_REPAIR)
		ret = FSCK_ERR_EXIT;

	if (ret)
		goto out;

#if 0
	bch2_mark_pending_btree_node_frees(c);
#endif
	c->gc_count++;

	if (test_bit(BCH_FS_NEED_ANOTHER_GC, &c->flags) ||
	    (!iter && bch2_test_restart_gc)) {
		/*
		 * XXX: make sure gens we fixed got saved
		 */
		if (iter++ <= 2) {
			bch_info(c, "Second GC pass needed, restarting:");
			clear_bit(BCH_FS_NEED_ANOTHER_GC, &c->flags);
			__gc_pos_set(c, gc_phase(GC_PHASE_NOT_RUNNING));

			percpu_down_write(&c->mark_lock);
			bch2_gc_free(c);
			percpu_up_write(&c->mark_lock);
			/* flush fsck errors, reset counters */
			bch2_flush_fsck_errs(c);

			goto again;
		}

		bch_info(c, "Unable to fix bucket gens, looping");
		ret = -EINVAL;
	}
out:
	if (!ret) {
		bch2_journal_block(&c->journal);

		percpu_down_write(&c->mark_lock);
		ret   = bch2_gc_reflink_done(c, initial, metadata_only) ?:
			bch2_gc_done(c, initial, metadata_only);

		bch2_journal_unblock(&c->journal);
	} else {
		percpu_down_write(&c->mark_lock);
	}

	/* Indicates that gc is no longer in progress: */
	__gc_pos_set(c, gc_phase(GC_PHASE_NOT_RUNNING));

	bch2_gc_free(c);
	percpu_up_write(&c->mark_lock);

	up_write(&c->gc_lock);

	trace_gc_end(c);
	bch2_time_stats_update(&c->times[BCH_TIME_btree_gc], start_time);

	/*
	 * Wake up allocator in case it was waiting for buckets
	 * because of not being able to inc gens
	 */
	for_each_member_device(ca, c, i)
		bch2_wake_allocator(ca);

	/*
	 * At startup, allocations can happen directly instead of via the
	 * allocator thread - issue wakeup in case they blocked on gc_lock:
	 */
	closure_wake_up(&c->freelist_wait);
	return ret;
}

static bool gc_btree_gens_key(struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const struct bch_extent_ptr *ptr;

	percpu_down_read(&c->mark_lock);
	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
		struct bucket *g = PTR_BUCKET(ca, ptr, false);

		if (gen_after(g->mark.gen, ptr->gen) > 16) {
			percpu_up_read(&c->mark_lock);
			return true;
		}
	}

	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);
		struct bucket *g = PTR_BUCKET(ca, ptr, false);

		if (gen_after(g->gc_gen, ptr->gen))
			g->gc_gen = ptr->gen;
	}
	percpu_up_read(&c->mark_lock);

	return false;
}

/*
 * For recalculating oldest gen, we only need to walk keys in leaf nodes; btree
 * node pointers currently never have cached pointers that can become stale:
 */
static int bch2_gc_btree_gens(struct bch_fs *c, enum btree_id btree_id)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_buf sk;
	int ret = 0, commit_err = 0;

	bch2_bkey_buf_init(&sk);
	bch2_trans_init(&trans, c, 0, 0);

	iter = bch2_trans_get_iter(&trans, btree_id, POS_MIN,
				   BTREE_ITER_PREFETCH|
				   BTREE_ITER_NOT_EXTENTS|
				   BTREE_ITER_ALL_SNAPSHOTS);

	while ((bch2_trans_begin(&trans),
		k = bch2_btree_iter_peek(iter)).k) {
		ret = bkey_err(k);

		if (ret == -EINTR)
			continue;
		if (ret)
			break;

		c->gc_gens_pos = iter->pos;

		if (gc_btree_gens_key(c, k) && !commit_err) {
			bch2_bkey_buf_reassemble(&sk, c, k);
			bch2_extent_normalize(c, bkey_i_to_s(sk.k));


			commit_err =
				bch2_trans_update(&trans, iter, sk.k, 0) ?:
				bch2_trans_commit(&trans, NULL, NULL,
						       BTREE_INSERT_NOWAIT|
						       BTREE_INSERT_NOFAIL);
			if (commit_err == -EINTR) {
				commit_err = 0;
				continue;
			}
		}

		bch2_btree_iter_advance(iter);
	}
	bch2_trans_iter_put(&trans, iter);

	bch2_trans_exit(&trans);
	bch2_bkey_buf_exit(&sk, c);

	return ret;
}

int bch2_gc_gens(struct bch_fs *c)
{
	struct bch_dev *ca;
	struct bucket_array *buckets;
	struct bucket *g;
	unsigned i;
	int ret;

	/*
	 * Ideally we would be using state_lock and not gc_lock here, but that
	 * introduces a deadlock in the RO path - we currently take the state
	 * lock at the start of going RO, thus the gc thread may get stuck:
	 */
	down_read(&c->gc_lock);

	for_each_member_device(ca, c, i) {
		down_read(&ca->bucket_lock);
		buckets = bucket_array(ca);

		for_each_bucket(g, buckets)
			g->gc_gen = g->mark.gen;
		up_read(&ca->bucket_lock);
	}

	for (i = 0; i < BTREE_ID_NR; i++)
		if ((1 << i) & BTREE_ID_HAS_PTRS) {
			c->gc_gens_btree = i;
			c->gc_gens_pos = POS_MIN;
			ret = bch2_gc_btree_gens(c, i);
			if (ret) {
				bch_err(c, "error recalculating oldest_gen: %i", ret);
				goto err;
			}
		}

	for_each_member_device(ca, c, i) {
		down_read(&ca->bucket_lock);
		buckets = bucket_array(ca);

		for_each_bucket(g, buckets)
			g->oldest_gen = g->gc_gen;
		up_read(&ca->bucket_lock);
	}

	c->gc_gens_btree	= 0;
	c->gc_gens_pos		= POS_MIN;

	c->gc_count++;
err:
	up_read(&c->gc_lock);
	return ret;
}

static int bch2_gc_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last = atomic64_read(&clock->now);
	unsigned last_kick = atomic_read(&c->kick_gc);
	int ret;

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
		ret = bch2_gc_gens(c);
#endif
		if (ret < 0)
			bch_err(c, "btree gc failed: %i", ret);

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
		bch_err(c, "error creating gc thread: %li", PTR_ERR(p));
		return PTR_ERR(p);
	}

	get_task_struct(p);
	c->gc_thread = p;
	wake_up_process(p);
	return 0;
}
