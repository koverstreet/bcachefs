// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "error.h"
#include "extents.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "replicas.h"
#include "super-io.h"
#include "trace.h"

#include <linux/random.h>

/* Debug code: */

/*
 * Verify that child nodes correctly span parent node's range:
 */
static void btree_node_interior_verify(struct bch_fs *c, struct btree *b)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bpos next_node = b->data->min_key;
	struct btree_node_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_btree_ptr_v2 bp;
	struct bkey unpacked;
	char buf1[100], buf2[100];

	BUG_ON(!b->c.level);

	if (!test_bit(BCH_FS_BTREE_INTERIOR_REPLAY_DONE, &c->flags))
		return;

	bch2_btree_node_iter_init_from_start(&iter, b);

	while (1) {
		k = bch2_btree_node_iter_peek_unpack(&iter, b, &unpacked);
		if (k.k->type != KEY_TYPE_btree_ptr_v2)
			break;
		bp = bkey_s_c_to_btree_ptr_v2(k);

		if (bpos_cmp(next_node, bp.v->min_key)) {
			bch2_dump_btree_node(c, b);
			panic("expected next min_key %s got %s\n",
			      (bch2_bpos_to_text(&PBUF(buf1), next_node), buf1),
			      (bch2_bpos_to_text(&PBUF(buf2), bp.v->min_key), buf2));
		}

		bch2_btree_node_iter_advance(&iter, b);

		if (bch2_btree_node_iter_end(&iter)) {
			if (bpos_cmp(k.k->p, b->key.k.p)) {
				bch2_dump_btree_node(c, b);
				panic("expected end %s got %s\n",
				      (bch2_bpos_to_text(&PBUF(buf1), b->key.k.p), buf1),
				      (bch2_bpos_to_text(&PBUF(buf2), k.k->p), buf2));
			}
			break;
		}

		next_node = bpos_successor(k.k->p);
	}
#endif
}

/* Calculate ideal packed bkey format for new btree nodes: */

void __bch2_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct bkey_packed *k;
	struct bset_tree *t;
	struct bkey uk;

	for_each_bset(b, t)
		bset_tree_for_each_key(b, t, k)
			if (!bkey_deleted(k)) {
				uk = bkey_unpack_key(b, k);
				bch2_bkey_format_add_key(s, &uk);
			}
}

static struct bkey_format bch2_btree_calc_format(struct btree *b)
{
	struct bkey_format_state s;

	bch2_bkey_format_init(&s);
	bch2_bkey_format_add_pos(&s, b->data->min_key);
	bch2_bkey_format_add_pos(&s, b->data->max_key);
	__bch2_btree_calc_format(&s, b);

	return bch2_bkey_format_done(&s);
}

static size_t btree_node_u64s_with_format(struct btree *b,
					  struct bkey_format *new_f)
{
	struct bkey_format *old_f = &b->format;

	/* stupid integer promotion rules */
	ssize_t delta =
	    (((int) new_f->key_u64s - old_f->key_u64s) *
	     (int) b->nr.packed_keys) +
	    (((int) new_f->key_u64s - BKEY_U64s) *
	     (int) b->nr.unpacked_keys);

	BUG_ON(delta + b->nr.live_u64s < 0);

	return b->nr.live_u64s + delta;
}

/**
 * btree_node_format_fits - check if we could rewrite node with a new format
 *
 * This assumes all keys can pack with the new format -- it just checks if
 * the re-packed keys would fit inside the node itself.
 */
bool bch2_btree_node_format_fits(struct bch_fs *c, struct btree *b,
				 struct bkey_format *new_f)
{
	size_t u64s = btree_node_u64s_with_format(b, new_f);

	return __vstruct_bytes(struct btree_node, u64s) < btree_bytes(c);
}

/* Btree node freeing/allocation: */

static void __btree_node_free(struct bch_fs *c, struct btree *b)
{
	trace_btree_node_free(c, b);

	BUG_ON(btree_node_dirty(b));
	BUG_ON(btree_node_need_write(b));
	BUG_ON(b == btree_node_root(c, b));
	BUG_ON(b->ob.nr);
	BUG_ON(!list_empty(&b->write_blocked));
	BUG_ON(b->will_make_reachable);

	clear_btree_node_noevict(b);

	bch2_btree_node_hash_remove(&c->btree_cache, b);

	mutex_lock(&c->btree_cache.lock);
	list_move(&b->list, &c->btree_cache.freeable);
	mutex_unlock(&c->btree_cache.lock);
}

void bch2_btree_node_free_never_inserted(struct bch_fs *c, struct btree *b)
{
	struct open_buckets ob = b->ob;

	b->ob.nr = 0;

	clear_btree_node_dirty(c, b);

	btree_node_lock_type(c, b, SIX_LOCK_write);
	__btree_node_free(c, b);
	six_unlock_write(&b->c.lock);

	bch2_open_buckets_put(c, &ob);
}

void bch2_btree_node_free_inmem(struct bch_fs *c, struct btree *b,
				struct btree_iter *iter)
{
	struct btree_iter *linked;

	trans_for_each_iter(iter->trans, linked)
		BUG_ON(linked->l[b->c.level].b == b);

	six_lock_write(&b->c.lock, NULL, NULL);
	__btree_node_free(c, b);
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
}

static struct btree *__bch2_btree_node_alloc(struct bch_fs *c,
					     struct disk_reservation *res,
					     struct closure *cl,
					     unsigned flags)
{
	struct write_point *wp;
	struct btree *b;
	__BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;
	struct open_buckets ob = { .nr = 0 };
	struct bch_devs_list devs_have = (struct bch_devs_list) { 0 };
	unsigned nr_reserve;
	enum alloc_reserve alloc_reserve;

	if (flags & BTREE_INSERT_USE_RESERVE) {
		nr_reserve	= 0;
		alloc_reserve	= RESERVE_BTREE_MOVINGGC;
	} else {
		nr_reserve	= BTREE_NODE_RESERVE;
		alloc_reserve	= RESERVE_BTREE;
	}

	mutex_lock(&c->btree_reserve_cache_lock);
	if (c->btree_reserve_cache_nr > nr_reserve) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		ob = a->ob;
		bkey_copy(&tmp.k, &a->k);
		mutex_unlock(&c->btree_reserve_cache_lock);
		goto mem_alloc;
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

retry:
	wp = bch2_alloc_sectors_start(c,
				      c->opts.metadata_target ?:
				      c->opts.foreground_target,
				      0,
				      writepoint_ptr(&c->btree_write_point),
				      &devs_have,
				      res->nr_replicas,
				      c->opts.metadata_replicas_required,
				      alloc_reserve, 0, cl);
	if (IS_ERR(wp))
		return ERR_CAST(wp);

	if (wp->sectors_free < c->opts.btree_node_size) {
		struct open_bucket *ob;
		unsigned i;

		open_bucket_for_each(c, &wp->ptrs, ob, i)
			if (ob->sectors_free < c->opts.btree_node_size)
				ob->sectors_free = 0;

		bch2_alloc_sectors_done(c, wp);
		goto retry;
	}

	if (c->sb.features & (1ULL << BCH_FEATURE_btree_ptr_v2))
		bkey_btree_ptr_v2_init(&tmp.k);
	else
		bkey_btree_ptr_init(&tmp.k);

	bch2_alloc_sectors_append_ptrs(c, wp, &tmp.k, c->opts.btree_node_size);

	bch2_open_bucket_get(c, wp, &ob);
	bch2_alloc_sectors_done(c, wp);
mem_alloc:
	b = bch2_btree_node_mem_alloc(c);

	/* we hold cannibalize_lock: */
	BUG_ON(IS_ERR(b));
	BUG_ON(b->ob.nr);

	bkey_copy(&b->key, &tmp.k);
	b->ob = ob;

	return b;
}

static struct btree *bch2_btree_node_alloc(struct btree_update *as, unsigned level)
{
	struct bch_fs *c = as->c;
	struct btree *b;
	int ret;

	BUG_ON(level >= BTREE_MAX_DEPTH);
	BUG_ON(!as->nr_prealloc_nodes);

	b = as->prealloc_nodes[--as->nr_prealloc_nodes];

	set_btree_node_accessed(b);
	set_btree_node_dirty(c, b);
	set_btree_node_need_write(b);

	bch2_bset_init_first(b, &b->data->keys);
	b->c.level	= level;
	b->c.btree_id	= as->btree_id;
	b->version_ondisk = c->sb.version;

	memset(&b->nr, 0, sizeof(b->nr));
	b->data->magic = cpu_to_le64(bset_magic(c));
	memset(&b->data->_ptr, 0, sizeof(b->data->_ptr));
	b->data->flags = 0;
	SET_BTREE_NODE_ID(b->data, as->btree_id);
	SET_BTREE_NODE_LEVEL(b->data, level);

	if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
		struct bkey_i_btree_ptr_v2 *bp = bkey_i_to_btree_ptr_v2(&b->key);

		bp->v.mem_ptr		= 0;
		bp->v.seq		= b->data->keys.seq;
		bp->v.sectors_written	= 0;
	}

	SET_BTREE_NODE_NEW_EXTENT_OVERWRITE(b->data, true);

	bch2_btree_build_aux_trees(b);

	ret = bch2_btree_node_hash_insert(&c->btree_cache, b, level, as->btree_id);
	BUG_ON(ret);

	trace_btree_node_alloc(c, b);
	return b;
}

static void btree_set_min(struct btree *b, struct bpos pos)
{
	if (b->key.k.type == KEY_TYPE_btree_ptr_v2)
		bkey_i_to_btree_ptr_v2(&b->key)->v.min_key = pos;
	b->data->min_key = pos;
}

static void btree_set_max(struct btree *b, struct bpos pos)
{
	b->key.k.p = pos;
	b->data->max_key = pos;
}

struct btree *__bch2_btree_node_alloc_replacement(struct btree_update *as,
						  struct btree *b,
						  struct bkey_format format)
{
	struct btree *n;

	n = bch2_btree_node_alloc(as, b->c.level);

	SET_BTREE_NODE_SEQ(n->data, BTREE_NODE_SEQ(b->data) + 1);

	btree_set_min(n, b->data->min_key);
	btree_set_max(n, b->data->max_key);

	n->data->format		= format;
	btree_node_set_format(n, format);

	bch2_btree_sort_into(as->c, n, b);

	btree_node_reset_sib_u64s(n);

	n->key.k.p = b->key.k.p;
	return n;
}

static struct btree *bch2_btree_node_alloc_replacement(struct btree_update *as,
						       struct btree *b)
{
	struct bkey_format new_f = bch2_btree_calc_format(b);

	/*
	 * The keys might expand with the new format - if they wouldn't fit in
	 * the btree node anymore, use the old format for now:
	 */
	if (!bch2_btree_node_format_fits(as->c, b, &new_f))
		new_f = b->format;

	return __bch2_btree_node_alloc_replacement(as, b, new_f);
}

static struct btree *__btree_root_alloc(struct btree_update *as, unsigned level)
{
	struct btree *b = bch2_btree_node_alloc(as, level);

	btree_set_min(b, POS_MIN);
	btree_set_max(b, POS_MAX);
	b->data->format = bch2_btree_calc_format(b);

	btree_node_set_format(b, b->data->format);
	bch2_btree_build_aux_trees(b);

	bch2_btree_update_add_new_node(as, b);
	six_unlock_write(&b->c.lock);

	return b;
}

static void bch2_btree_reserve_put(struct btree_update *as)
{
	struct bch_fs *c = as->c;

	mutex_lock(&c->btree_reserve_cache_lock);

	while (as->nr_prealloc_nodes) {
		struct btree *b = as->prealloc_nodes[--as->nr_prealloc_nodes];

		six_unlock_write(&b->c.lock);

		if (c->btree_reserve_cache_nr <
		    ARRAY_SIZE(c->btree_reserve_cache)) {
			struct btree_alloc *a =
				&c->btree_reserve_cache[c->btree_reserve_cache_nr++];

			a->ob = b->ob;
			b->ob.nr = 0;
			bkey_copy(&a->k, &b->key);
		} else {
			bch2_open_buckets_put(c, &b->ob);
		}

		btree_node_lock_type(c, b, SIX_LOCK_write);
		__btree_node_free(c, b);
		six_unlock_write(&b->c.lock);

		six_unlock_intent(&b->c.lock);
	}

	mutex_unlock(&c->btree_reserve_cache_lock);
}

static int bch2_btree_reserve_get(struct btree_update *as, unsigned nr_nodes,
				  unsigned flags, struct closure *cl)
{
	struct bch_fs *c = as->c;
	struct btree *b;
	int ret;

	BUG_ON(nr_nodes > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	ret = bch2_btree_cache_cannibalize_lock(c, cl);
	if (ret)
		return ret;

	while (as->nr_prealloc_nodes < nr_nodes) {
		b = __bch2_btree_node_alloc(c, &as->disk_res,
					    flags & BTREE_INSERT_NOWAIT
					    ? NULL : cl, flags);
		if (IS_ERR(b)) {
			ret = PTR_ERR(b);
			goto err_free;
		}

		as->prealloc_nodes[as->nr_prealloc_nodes++] = b;
	}

	bch2_btree_cache_cannibalize_unlock(c);
	return 0;
err_free:
	bch2_btree_cache_cannibalize_unlock(c);
	trace_btree_reserve_get_fail(c, nr_nodes, cl);
	return ret;
}

/* Asynchronous interior node update machinery */

static void bch2_btree_update_free(struct btree_update *as)
{
	struct bch_fs *c = as->c;

	if (as->took_gc_lock)
		up_read(&c->gc_lock);
	as->took_gc_lock = false;

	bch2_journal_preres_put(&c->journal, &as->journal_preres);

	bch2_journal_pin_drop(&c->journal, &as->journal);
	bch2_journal_pin_flush(&c->journal, &as->journal);
	bch2_disk_reservation_put(c, &as->disk_res);
	bch2_btree_reserve_put(as);

	mutex_lock(&c->btree_interior_update_lock);
	list_del(&as->unwritten_list);
	list_del(&as->list);
	mutex_unlock(&c->btree_interior_update_lock);

	closure_debug_destroy(&as->cl);
	mempool_free(as, &c->btree_interior_update_pool);

	closure_wake_up(&c->btree_interior_update_wait);
}

static void btree_update_will_delete_key(struct btree_update *as,
					 struct bkey_i *k)
{
	BUG_ON(bch2_keylist_u64s(&as->old_keys) + k->k.u64s >
	       ARRAY_SIZE(as->_old_keys));
	bch2_keylist_add(&as->old_keys, k);
}

static void btree_update_will_add_key(struct btree_update *as,
				      struct bkey_i *k)
{
	BUG_ON(bch2_keylist_u64s(&as->new_keys) + k->k.u64s >
	       ARRAY_SIZE(as->_new_keys));
	bch2_keylist_add(&as->new_keys, k);
}

/*
 * The transactional part of an interior btree node update, where we journal the
 * update we did to the interior node and update alloc info:
 */
static int btree_update_nodes_written_trans(struct btree_trans *trans,
					    struct btree_update *as)
{
	struct bkey_i *k;
	int ret;

	trans->extra_journal_entries = (void *) &as->journal_entries[0];
	trans->extra_journal_entry_u64s = as->journal_u64s;
	trans->journal_pin = &as->journal;

	for_each_keylist_key(&as->new_keys, k) {
		ret = bch2_trans_mark_key(trans,
					  bkey_s_c_null,
					  bkey_i_to_s_c(k),
					  0, 0, BTREE_TRIGGER_INSERT);
		if (ret)
			return ret;
	}

	for_each_keylist_key(&as->old_keys, k) {
		ret = bch2_trans_mark_key(trans,
					  bkey_i_to_s_c(k),
					  bkey_s_c_null,
					  0, 0, BTREE_TRIGGER_OVERWRITE);
		if (ret)
			return ret;
	}

	return 0;
}

static void btree_update_nodes_written(struct btree_update *as)
{
	struct bch_fs *c = as->c;
	struct btree *b = as->b;
	struct btree_trans trans;
	u64 journal_seq = 0;
	unsigned i;
	int ret;

	/*
	 * If we're already in an error state, it might be because a btree node
	 * was never written, and we might be trying to free that same btree
	 * node here, but it won't have been marked as allocated and we'll see
	 * spurious disk usage inconsistencies in the transactional part below
	 * if we don't skip it:
	 */
	ret = bch2_journal_error(&c->journal);
	if (ret)
		goto err;

	BUG_ON(!journal_pin_active(&as->journal));

	/*
	 * We did an update to a parent node where the pointers we added pointed
	 * to child nodes that weren't written yet: now, the child nodes have
	 * been written so we can write out the update to the interior node.
	 */

	/*
	 * We can't call into journal reclaim here: we'd block on the journal
	 * reclaim lock, but we may need to release the open buckets we have
	 * pinned in order for other btree updates to make forward progress, and
	 * journal reclaim does btree updates when flushing bkey_cached entries,
	 * which may require allocations as well.
	 */
	bch2_trans_init(&trans, c, 0, 512);
	ret = __bch2_trans_do(&trans, &as->disk_res, &journal_seq,
			      BTREE_INSERT_NOFAIL|
			      BTREE_INSERT_NOCHECK_RW|
			      BTREE_INSERT_JOURNAL_RECLAIM|
			      BTREE_INSERT_JOURNAL_RESERVED,
			      btree_update_nodes_written_trans(&trans, as));
	bch2_trans_exit(&trans);

	bch2_fs_fatal_err_on(ret && !bch2_journal_error(&c->journal), c,
			     "error %i in btree_update_nodes_written()", ret);
err:
	if (b) {
		/*
		 * @b is the node we did the final insert into:
		 *
		 * On failure to get a journal reservation, we still have to
		 * unblock the write and allow most of the write path to happen
		 * so that shutdown works, but the i->journal_seq mechanism
		 * won't work to prevent the btree write from being visible (we
		 * didn't get a journal sequence number) - instead
		 * __bch2_btree_node_write() doesn't do the actual write if
		 * we're in journal error state:
		 */

		btree_node_lock_type(c, b, SIX_LOCK_intent);
		btree_node_lock_type(c, b, SIX_LOCK_write);
		mutex_lock(&c->btree_interior_update_lock);

		list_del(&as->write_blocked_list);

		/*
		 * Node might have been freed, recheck under
		 * btree_interior_update_lock:
		 */
		if (as->b == b) {
			struct bset *i = btree_bset_last(b);

			BUG_ON(!b->c.level);
			BUG_ON(!btree_node_dirty(b));

			if (!ret) {
				i->journal_seq = cpu_to_le64(
					max(journal_seq,
					    le64_to_cpu(i->journal_seq)));

				bch2_btree_add_journal_pin(c, b, journal_seq);
			} else {
				/*
				 * If we didn't get a journal sequence number we
				 * can't write this btree node, because recovery
				 * won't know to ignore this write:
				 */
				set_btree_node_never_write(b);
			}
		}

		mutex_unlock(&c->btree_interior_update_lock);
		six_unlock_write(&b->c.lock);

		btree_node_write_if_need(c, b, SIX_LOCK_intent);
		six_unlock_intent(&b->c.lock);
	}

	bch2_journal_pin_drop(&c->journal, &as->journal);

	bch2_journal_preres_put(&c->journal, &as->journal_preres);

	mutex_lock(&c->btree_interior_update_lock);
	for (i = 0; i < as->nr_new_nodes; i++) {
		b = as->new_nodes[i];

		BUG_ON(b->will_make_reachable != (unsigned long) as);
		b->will_make_reachable = 0;
	}
	mutex_unlock(&c->btree_interior_update_lock);

	for (i = 0; i < as->nr_new_nodes; i++) {
		b = as->new_nodes[i];

		btree_node_lock_type(c, b, SIX_LOCK_read);
		btree_node_write_if_need(c, b, SIX_LOCK_read);
		six_unlock_read(&b->c.lock);
	}

	for (i = 0; i < as->nr_open_buckets; i++)
		bch2_open_bucket_put(c, c->open_buckets + as->open_buckets[i]);

	bch2_btree_update_free(as);
}

static void btree_interior_update_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, btree_interior_update_work);
	struct btree_update *as;

	while (1) {
		mutex_lock(&c->btree_interior_update_lock);
		as = list_first_entry_or_null(&c->btree_interior_updates_unwritten,
					      struct btree_update, unwritten_list);
		if (as && !as->nodes_written)
			as = NULL;
		mutex_unlock(&c->btree_interior_update_lock);

		if (!as)
			break;

		btree_update_nodes_written(as);
	}
}

static void btree_update_set_nodes_written(struct closure *cl)
{
	struct btree_update *as = container_of(cl, struct btree_update, cl);
	struct bch_fs *c = as->c;

	mutex_lock(&c->btree_interior_update_lock);
	as->nodes_written = true;
	mutex_unlock(&c->btree_interior_update_lock);

	queue_work(c->btree_interior_update_worker, &c->btree_interior_update_work);
}

/*
 * We're updating @b with pointers to nodes that haven't finished writing yet:
 * block @b from being written until @as completes
 */
static void btree_update_updated_node(struct btree_update *as, struct btree *b)
{
	struct bch_fs *c = as->c;

	mutex_lock(&c->btree_interior_update_lock);
	list_add_tail(&as->unwritten_list, &c->btree_interior_updates_unwritten);

	BUG_ON(as->mode != BTREE_INTERIOR_NO_UPDATE);
	BUG_ON(!btree_node_dirty(b));

	as->mode	= BTREE_INTERIOR_UPDATING_NODE;
	as->b		= b;
	list_add(&as->write_blocked_list, &b->write_blocked);

	mutex_unlock(&c->btree_interior_update_lock);
}

static void btree_update_reparent(struct btree_update *as,
				  struct btree_update *child)
{
	struct bch_fs *c = as->c;

	lockdep_assert_held(&c->btree_interior_update_lock);

	child->b = NULL;
	child->mode = BTREE_INTERIOR_UPDATING_AS;

	bch2_journal_pin_copy(&c->journal, &as->journal, &child->journal, NULL);
}

static void btree_update_updated_root(struct btree_update *as, struct btree *b)
{
	struct bkey_i *insert = &b->key;
	struct bch_fs *c = as->c;

	BUG_ON(as->mode != BTREE_INTERIOR_NO_UPDATE);

	BUG_ON(as->journal_u64s + jset_u64s(insert->k.u64s) >
	       ARRAY_SIZE(as->journal_entries));

	as->journal_u64s +=
		journal_entry_set((void *) &as->journal_entries[as->journal_u64s],
				  BCH_JSET_ENTRY_btree_root,
				  b->c.btree_id, b->c.level,
				  insert, insert->k.u64s);

	mutex_lock(&c->btree_interior_update_lock);
	list_add_tail(&as->unwritten_list, &c->btree_interior_updates_unwritten);

	as->mode	= BTREE_INTERIOR_UPDATING_ROOT;
	mutex_unlock(&c->btree_interior_update_lock);
}

/*
 * bch2_btree_update_add_new_node:
 *
 * This causes @as to wait on @b to be written, before it gets to
 * bch2_btree_update_nodes_written
 *
 * Additionally, it sets b->will_make_reachable to prevent any additional writes
 * to @b from happening besides the first until @b is reachable on disk
 *
 * And it adds @b to the list of @as's new nodes, so that we can update sector
 * counts in bch2_btree_update_nodes_written:
 */
void bch2_btree_update_add_new_node(struct btree_update *as, struct btree *b)
{
	struct bch_fs *c = as->c;

	closure_get(&as->cl);

	mutex_lock(&c->btree_interior_update_lock);
	BUG_ON(as->nr_new_nodes >= ARRAY_SIZE(as->new_nodes));
	BUG_ON(b->will_make_reachable);

	as->new_nodes[as->nr_new_nodes++] = b;
	b->will_make_reachable = 1UL|(unsigned long) as;

	mutex_unlock(&c->btree_interior_update_lock);

	btree_update_will_add_key(as, &b->key);
}

/*
 * returns true if @b was a new node
 */
static void btree_update_drop_new_node(struct bch_fs *c, struct btree *b)
{
	struct btree_update *as;
	unsigned long v;
	unsigned i;

	mutex_lock(&c->btree_interior_update_lock);
	/*
	 * When b->will_make_reachable != 0, it owns a ref on as->cl that's
	 * dropped when it gets written by bch2_btree_complete_write - the
	 * xchg() is for synchronization with bch2_btree_complete_write:
	 */
	v = xchg(&b->will_make_reachable, 0);
	as = (struct btree_update *) (v & ~1UL);

	if (!as) {
		mutex_unlock(&c->btree_interior_update_lock);
		return;
	}

	for (i = 0; i < as->nr_new_nodes; i++)
		if (as->new_nodes[i] == b)
			goto found;

	BUG();
found:
	array_remove_item(as->new_nodes, as->nr_new_nodes, i);
	mutex_unlock(&c->btree_interior_update_lock);

	if (v & 1)
		closure_put(&as->cl);
}

void bch2_btree_update_get_open_buckets(struct btree_update *as, struct btree *b)
{
	while (b->ob.nr)
		as->open_buckets[as->nr_open_buckets++] =
			b->ob.v[--b->ob.nr];
}

/*
 * @b is being split/rewritten: it may have pointers to not-yet-written btree
 * nodes and thus outstanding btree_updates - redirect @b's
 * btree_updates to point to this btree_update:
 */
void bch2_btree_interior_update_will_free_node(struct btree_update *as,
					       struct btree *b)
{
	struct bch_fs *c = as->c;
	struct btree_update *p, *n;
	struct btree_write *w;

	set_btree_node_dying(b);

	if (btree_node_fake(b))
		return;

	mutex_lock(&c->btree_interior_update_lock);

	/*
	 * Does this node have any btree_update operations preventing
	 * it from being written?
	 *
	 * If so, redirect them to point to this btree_update: we can
	 * write out our new nodes, but we won't make them visible until those
	 * operations complete
	 */
	list_for_each_entry_safe(p, n, &b->write_blocked, write_blocked_list) {
		list_del_init(&p->write_blocked_list);
		btree_update_reparent(as, p);

		/*
		 * for flush_held_btree_writes() waiting on updates to flush or
		 * nodes to be writeable:
		 */
		closure_wake_up(&c->btree_interior_update_wait);
	}

	clear_btree_node_dirty(c, b);
	clear_btree_node_need_write(b);

	/*
	 * Does this node have unwritten data that has a pin on the journal?
	 *
	 * If so, transfer that pin to the btree_update operation -
	 * note that if we're freeing multiple nodes, we only need to keep the
	 * oldest pin of any of the nodes we're freeing. We'll release the pin
	 * when the new nodes are persistent and reachable on disk:
	 */
	w = btree_current_write(b);
	bch2_journal_pin_copy(&c->journal, &as->journal, &w->journal, NULL);
	bch2_journal_pin_drop(&c->journal, &w->journal);

	w = btree_prev_write(b);
	bch2_journal_pin_copy(&c->journal, &as->journal, &w->journal, NULL);
	bch2_journal_pin_drop(&c->journal, &w->journal);

	mutex_unlock(&c->btree_interior_update_lock);

	/*
	 * Is this a node that isn't reachable on disk yet?
	 *
	 * Nodes that aren't reachable yet have writes blocked until they're
	 * reachable - now that we've cancelled any pending writes and moved
	 * things waiting on that write to wait on this update, we can drop this
	 * node from the list of nodes that the other update is making
	 * reachable, prior to freeing it:
	 */
	btree_update_drop_new_node(c, b);

	btree_update_will_delete_key(as, &b->key);

	/*
	 * XXX: Waiting on io with btree node locks held, we don't want to be
	 * doing this. We can't have btree writes happening after the space has
	 * been freed, but we really only need to block before
	 * btree_update_nodes_written_trans() happens.
	 */
	btree_node_wait_on_io(b);
}

void bch2_btree_update_done(struct btree_update *as)
{
	BUG_ON(as->mode == BTREE_INTERIOR_NO_UPDATE);

	if (as->took_gc_lock)
		up_read(&as->c->gc_lock);
	as->took_gc_lock = false;

	bch2_btree_reserve_put(as);

	continue_at(&as->cl, btree_update_set_nodes_written,
		    as->c->btree_interior_update_worker);
}

struct btree_update *
bch2_btree_update_start(struct btree_iter *iter, unsigned level,
			unsigned nr_nodes, unsigned flags)
{
	struct btree_trans *trans = iter->trans;
	struct bch_fs *c = trans->c;
	struct btree_update *as;
	struct closure cl;
	int disk_res_flags = (flags & BTREE_INSERT_NOFAIL)
		? BCH_DISK_RESERVATION_NOFAIL : 0;
	int journal_flags = 0;
	int ret = 0;

	if (flags & BTREE_INSERT_JOURNAL_RESERVED)
		journal_flags |= JOURNAL_RES_GET_RESERVED;

	closure_init_stack(&cl);
retry:
	/*
	 * This check isn't necessary for correctness - it's just to potentially
	 * prevent us from doing a lot of work that'll end up being wasted:
	 */
	ret = bch2_journal_error(&c->journal);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * XXX: figure out how far we might need to split,
	 * instead of locking/reserving all the way to the root:
	 */
	if (!bch2_btree_iter_upgrade(iter, U8_MAX)) {
		trace_trans_restart_iter_upgrade(trans->ip);
		return ERR_PTR(-EINTR);
	}

	if (flags & BTREE_INSERT_GC_LOCK_HELD)
		lockdep_assert_held(&c->gc_lock);
	else if (!down_read_trylock(&c->gc_lock)) {
		if (flags & BTREE_INSERT_NOUNLOCK)
			return ERR_PTR(-EINTR);

		bch2_trans_unlock(trans);
		down_read(&c->gc_lock);
		if (!bch2_trans_relock(trans)) {
			up_read(&c->gc_lock);
			return ERR_PTR(-EINTR);
		}
	}

	as = mempool_alloc(&c->btree_interior_update_pool, GFP_NOIO);
	memset(as, 0, sizeof(*as));
	closure_init(&as->cl, NULL);
	as->c		= c;
	as->mode	= BTREE_INTERIOR_NO_UPDATE;
	as->took_gc_lock = !(flags & BTREE_INSERT_GC_LOCK_HELD);
	as->btree_id	= iter->btree_id;
	INIT_LIST_HEAD(&as->list);
	INIT_LIST_HEAD(&as->unwritten_list);
	INIT_LIST_HEAD(&as->write_blocked_list);
	bch2_keylist_init(&as->old_keys, as->_old_keys);
	bch2_keylist_init(&as->new_keys, as->_new_keys);
	bch2_keylist_init(&as->parent_keys, as->inline_keys);

	ret = bch2_journal_preres_get(&c->journal, &as->journal_preres,
				      BTREE_UPDATE_JOURNAL_RES,
				      journal_flags|JOURNAL_RES_GET_NONBLOCK);
	if (ret == -EAGAIN) {
		/*
		 * this would be cleaner if bch2_journal_preres_get() took a
		 * closure argument
		 */
		if (flags & BTREE_INSERT_NOUNLOCK) {
			trace_trans_restart_journal_preres_get(trans->ip);
			ret = -EINTR;
			goto err;
		}

		bch2_trans_unlock(trans);

		if (flags & BTREE_INSERT_JOURNAL_RECLAIM) {
			bch2_btree_update_free(as);
			return ERR_PTR(ret);
		}

		ret = bch2_journal_preres_get(&c->journal, &as->journal_preres,
				BTREE_UPDATE_JOURNAL_RES,
				journal_flags);
		if (ret) {
			trace_trans_restart_journal_preres_get(trans->ip);
			goto err;
		}

		if (!bch2_trans_relock(trans)) {
			ret = -EINTR;
			goto err;
		}
	}

	ret = bch2_disk_reservation_get(c, &as->disk_res,
			nr_nodes * c->opts.btree_node_size,
			c->opts.metadata_replicas,
			disk_res_flags);
	if (ret)
		goto err;

	ret = bch2_btree_reserve_get(as, nr_nodes, flags,
		!(flags & BTREE_INSERT_NOUNLOCK) ? &cl : NULL);
	if (ret)
		goto err;

	bch2_journal_pin_add(&c->journal,
			     atomic64_read(&c->journal.seq),
			     &as->journal, NULL);

	mutex_lock(&c->btree_interior_update_lock);
	list_add_tail(&as->list, &c->btree_interior_update_list);
	mutex_unlock(&c->btree_interior_update_lock);

	return as;
err:
	bch2_btree_update_free(as);

	if (ret == -EAGAIN) {
		BUG_ON(flags & BTREE_INSERT_NOUNLOCK);

		bch2_trans_unlock(trans);
		closure_sync(&cl);
		ret = -EINTR;
	}

	if (ret == -EINTR && bch2_trans_relock(trans))
		goto retry;

	return ERR_PTR(ret);
}

/* Btree root updates: */

static void bch2_btree_set_root_inmem(struct bch_fs *c, struct btree *b)
{
	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache.lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache.lock);

	if (b->c.level)
		six_lock_pcpu_alloc(&b->c.lock);
	else
		six_lock_pcpu_free(&b->c.lock);

	mutex_lock(&c->btree_root_lock);
	BUG_ON(btree_node_root(c, b) &&
	       (b->c.level < btree_node_root(c, b)->c.level ||
		!btree_node_dying(btree_node_root(c, b))));

	btree_node_root(c, b) = b;
	mutex_unlock(&c->btree_root_lock);

	bch2_recalc_btree_reserve(c);
}

/**
 * bch_btree_set_root - update the root in memory and on disk
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks. However, you must hold an intent lock on the
 * old root.
 *
 * Note: This allocates a journal entry but doesn't add any keys to
 * it.  All the btree roots are part of every journal write, so there
 * is nothing new to be done.  This just guarantees that there is a
 * journal write.
 */
static void bch2_btree_set_root(struct btree_update *as, struct btree *b,
				struct btree_iter *iter)
{
	struct bch_fs *c = as->c;
	struct btree *old;

	trace_btree_set_root(c, b);
	BUG_ON(!b->written &&
	       !test_bit(BCH_FS_HOLD_BTREE_WRITES, &c->flags));

	old = btree_node_root(c, b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	bch2_btree_node_lock_write(old, iter);

	bch2_btree_set_root_inmem(c, b);

	btree_update_updated_root(as, b);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	bch2_btree_node_unlock_write(old, iter);
}

/* Interior node updates: */

static void bch2_insert_fixup_btree_ptr(struct btree_update *as, struct btree *b,
					struct btree_iter *iter,
					struct bkey_i *insert,
					struct btree_node_iter *node_iter)
{
	struct bch_fs *c = as->c;
	struct bkey_packed *k;
	const char *invalid;

	invalid = bch2_bkey_invalid(c, bkey_i_to_s_c(insert), btree_node_type(b)) ?:
		bch2_bkey_in_btree_node(b, bkey_i_to_s_c(insert));
	if (invalid) {
		char buf[160];

		bch2_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(insert));
		bch2_fs_inconsistent(c, "inserting invalid bkey %s: %s", buf, invalid);
		dump_stack();
	}

	BUG_ON(as->journal_u64s + jset_u64s(insert->k.u64s) >
	       ARRAY_SIZE(as->journal_entries));

	as->journal_u64s +=
		journal_entry_set((void *) &as->journal_entries[as->journal_u64s],
				  BCH_JSET_ENTRY_btree_keys,
				  b->c.btree_id, b->c.level,
				  insert, insert->k.u64s);

	while ((k = bch2_btree_node_iter_peek_all(node_iter, b)) &&
	       bkey_iter_pos_cmp(b, k, &insert->k.p) < 0)
		bch2_btree_node_iter_advance(node_iter, b);

	bch2_btree_bset_insert_key(iter, b, node_iter, insert);
	set_btree_node_dirty(c, b);
	set_btree_node_need_write(b);
}

static void
__bch2_btree_insert_keys_interior(struct btree_update *as, struct btree *b,
				  struct btree_iter *iter, struct keylist *keys,
				  struct btree_node_iter node_iter)
{
	struct bkey_i *insert = bch2_keylist_front(keys);
	struct bkey_packed *k;

	BUG_ON(btree_node_type(b) != BKEY_TYPE_btree);

	while ((k = bch2_btree_node_iter_prev_all(&node_iter, b)) &&
	       (bkey_cmp_left_packed(b, k, &insert->k.p) >= 0))
		;

	while (!bch2_keylist_empty(keys)) {
		bch2_insert_fixup_btree_ptr(as, b, iter,
				bch2_keylist_front(keys), &node_iter);
		bch2_keylist_pop_front(keys);
	}
}

/*
 * Move keys from n1 (original replacement node, now lower node) to n2 (higher
 * node)
 */
static struct btree *__btree_split_node(struct btree_update *as,
					struct btree *n1,
					struct btree_iter *iter)
{
	struct bkey_format_state s;
	size_t nr_packed = 0, nr_unpacked = 0;
	struct btree *n2;
	struct bset *set1, *set2;
	struct bkey_packed *k, *set2_start, *set2_end, *out, *prev = NULL;
	struct bpos n1_pos;

	n2 = bch2_btree_node_alloc(as, n1->c.level);
	bch2_btree_update_add_new_node(as, n2);

	n2->data->max_key	= n1->data->max_key;
	n2->data->format	= n1->format;
	SET_BTREE_NODE_SEQ(n2->data, BTREE_NODE_SEQ(n1->data));
	n2->key.k.p = n1->key.k.p;

	set1 = btree_bset_first(n1);
	set2 = btree_bset_first(n2);

	/*
	 * Has to be a linear search because we don't have an auxiliary
	 * search tree yet
	 */
	k = set1->start;
	while (1) {
		struct bkey_packed *n = bkey_next(k);

		if (n == vstruct_last(set1))
			break;
		if (k->_data - set1->_data >= (le16_to_cpu(set1->u64s) * 3) / 5)
			break;

		if (bkey_packed(k))
			nr_packed++;
		else
			nr_unpacked++;

		prev = k;
		k = n;
	}

	BUG_ON(!prev);
	set2_start	= k;
	set2_end	= vstruct_last(set1);

	set1->u64s = cpu_to_le16((u64 *) set2_start - set1->_data);
	set_btree_bset_end(n1, n1->set);

	n1->nr.live_u64s	= le16_to_cpu(set1->u64s);
	n1->nr.bset_u64s[0]	= le16_to_cpu(set1->u64s);
	n1->nr.packed_keys	= nr_packed;
	n1->nr.unpacked_keys	= nr_unpacked;

	n1_pos = bkey_unpack_pos(n1, prev);
	if (as->c->sb.version < bcachefs_metadata_version_snapshot)
		n1_pos.snapshot = U32_MAX;

	btree_set_max(n1, n1_pos);
	btree_set_min(n2, bpos_successor(n1->key.k.p));

	bch2_bkey_format_init(&s);
	bch2_bkey_format_add_pos(&s, n2->data->min_key);
	bch2_bkey_format_add_pos(&s, n2->data->max_key);

	for (k = set2_start; k != set2_end; k = bkey_next(k)) {
		struct bkey uk = bkey_unpack_key(n1, k);
		bch2_bkey_format_add_key(&s, &uk);
	}

	n2->data->format = bch2_bkey_format_done(&s);
	btree_node_set_format(n2, n2->data->format);

	out = set2->start;
	memset(&n2->nr, 0, sizeof(n2->nr));

	for (k = set2_start; k != set2_end; k = bkey_next(k)) {
		BUG_ON(!bch2_bkey_transform(&n2->format, out, bkey_packed(k)
				       ? &n1->format : &bch2_bkey_format_current, k));
		out->format = KEY_FORMAT_LOCAL_BTREE;
		btree_keys_account_key_add(&n2->nr, 0, out);
		out = bkey_next(out);
	}

	set2->u64s = cpu_to_le16((u64 *) out - set2->_data);
	set_btree_bset_end(n2, n2->set);

	BUG_ON(!set1->u64s);
	BUG_ON(!set2->u64s);

	btree_node_reset_sib_u64s(n1);
	btree_node_reset_sib_u64s(n2);

	bch2_verify_btree_nr_keys(n1);
	bch2_verify_btree_nr_keys(n2);

	if (n1->c.level) {
		btree_node_interior_verify(as->c, n1);
		btree_node_interior_verify(as->c, n2);
	}

	return n2;
}

/*
 * For updates to interior nodes, we've got to do the insert before we split
 * because the stuff we're inserting has to be inserted atomically. Post split,
 * the keys might have to go in different nodes and the split would no longer be
 * atomic.
 *
 * Worse, if the insert is from btree node coalescing, if we do the insert after
 * we do the split (and pick the pivot) - the pivot we pick might be between
 * nodes that were coalesced, and thus in the middle of a child node post
 * coalescing:
 */
static void btree_split_insert_keys(struct btree_update *as, struct btree *b,
				    struct btree_iter *iter,
				    struct keylist *keys)
{
	struct btree_node_iter node_iter;
	struct bkey_i *k = bch2_keylist_front(keys);
	struct bkey_packed *src, *dst, *n;
	struct bset *i;

	bch2_btree_node_iter_init(&node_iter, b, &k->k.p);

	__bch2_btree_insert_keys_interior(as, b, iter, keys, node_iter);

	/*
	 * We can't tolerate whiteouts here - with whiteouts there can be
	 * duplicate keys, and it would be rather bad if we picked a duplicate
	 * for the pivot:
	 */
	i = btree_bset_first(b);
	src = dst = i->start;
	while (src != vstruct_last(i)) {
		n = bkey_next(src);
		if (!bkey_deleted(src)) {
			memmove_u64s_down(dst, src, src->u64s);
			dst = bkey_next(dst);
		}
		src = n;
	}

	/* Also clear out the unwritten whiteouts area: */
	b->whiteout_u64s = 0;

	i->u64s = cpu_to_le16((u64 *) dst - i->_data);
	set_btree_bset_end(b, b->set);

	BUG_ON(b->nsets != 1 ||
	       b->nr.live_u64s != le16_to_cpu(btree_bset_first(b)->u64s));

	btree_node_interior_verify(as->c, b);
}

static void btree_split(struct btree_update *as, struct btree *b,
			struct btree_iter *iter, struct keylist *keys,
			unsigned flags)
{
	struct bch_fs *c = as->c;
	struct btree *parent = btree_node_parent(iter, b);
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	u64 start_time = local_clock();

	BUG_ON(!parent && (b != btree_node_root(c, b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(c, b)->c.level));

	bch2_btree_interior_update_will_free_node(as, b);

	n1 = bch2_btree_node_alloc_replacement(as, b);
	bch2_btree_update_add_new_node(as, n1);

	if (keys)
		btree_split_insert_keys(as, n1, iter, keys);

	if (bset_u64s(&n1->set[0]) > BTREE_SPLIT_THRESHOLD(c)) {
		trace_btree_split(c, b);

		n2 = __btree_split_node(as, n1, iter);

		bch2_btree_build_aux_trees(n2);
		bch2_btree_build_aux_trees(n1);
		six_unlock_write(&n2->c.lock);
		six_unlock_write(&n1->c.lock);

		bch2_btree_node_write(c, n2, SIX_LOCK_intent);

		/*
		 * Note that on recursive parent_keys == keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		bch2_keylist_add(&as->parent_keys, &n1->key);
		bch2_keylist_add(&as->parent_keys, &n2->key);

		if (!parent) {
			/* Depth increases, make a new root */
			n3 = __btree_root_alloc(as, b->c.level + 1);

			n3->sib_u64s[0] = U16_MAX;
			n3->sib_u64s[1] = U16_MAX;

			btree_split_insert_keys(as, n3, iter, &as->parent_keys);

			bch2_btree_node_write(c, n3, SIX_LOCK_intent);
		}
	} else {
		trace_btree_compact(c, b);

		bch2_btree_build_aux_trees(n1);
		six_unlock_write(&n1->c.lock);

		if (parent)
			bch2_keylist_add(&as->parent_keys, &n1->key);
	}

	bch2_btree_node_write(c, n1, SIX_LOCK_intent);

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		bch2_btree_insert_node(as, parent, iter, &as->parent_keys, flags);
	} else if (n3) {
		bch2_btree_set_root(as, n3, iter);
	} else {
		/* Root filled up but didn't need to be split */
		bch2_btree_set_root(as, n1, iter);
	}

	bch2_btree_update_get_open_buckets(as, n1);
	if (n2)
		bch2_btree_update_get_open_buckets(as, n2);
	if (n3)
		bch2_btree_update_get_open_buckets(as, n3);

	/* Successful split, update the iterator to point to the new nodes: */

	six_lock_increment(&b->c.lock, SIX_LOCK_intent);
	bch2_btree_iter_node_drop(iter, b);
	if (n3)
		bch2_btree_iter_node_replace(iter, n3);
	if (n2)
		bch2_btree_iter_node_replace(iter, n2);
	bch2_btree_iter_node_replace(iter, n1);

	/*
	 * The old node must be freed (in memory) _before_ unlocking the new
	 * nodes - else another thread could re-acquire a read lock on the old
	 * node after another thread has locked and updated the new node, thus
	 * seeing stale data:
	 */
	bch2_btree_node_free_inmem(c, b, iter);

	if (n3)
		six_unlock_intent(&n3->c.lock);
	if (n2)
		six_unlock_intent(&n2->c.lock);
	six_unlock_intent(&n1->c.lock);

	bch2_btree_trans_verify_locks(iter->trans);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_split],
			       start_time);
}

static void
bch2_btree_insert_keys_interior(struct btree_update *as, struct btree *b,
				struct btree_iter *iter, struct keylist *keys)
{
	struct btree_iter *linked;

	__bch2_btree_insert_keys_interior(as, b, iter, keys, iter->l[b->c.level].iter);

	btree_update_updated_node(as, b);

	trans_for_each_iter_with_node(iter->trans, b, linked)
		bch2_btree_node_iter_peek(&linked->l[b->c.level].iter, b);

	bch2_btree_trans_verify_iters(iter->trans, b);
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 *
 * @iter:		btree iterator
 * @keys:		list of keys to insert
 * @hook:		insert callback
 * @persistent:		if not null, @persistent will wait on journal write
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
void bch2_btree_insert_node(struct btree_update *as, struct btree *b,
			    struct btree_iter *iter, struct keylist *keys,
			    unsigned flags)
{
	struct bch_fs *c = as->c;
	int old_u64s = le16_to_cpu(btree_bset_last(b)->u64s);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

	lockdep_assert_held(&c->gc_lock);
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(c, b)->c.level));
	BUG_ON(!b->c.level);
	BUG_ON(!as || as->b);
	bch2_verify_keylist_sorted(keys);

	bch2_btree_node_lock_for_insert(c, b, iter);

	if (!bch2_btree_node_insert_fits(c, b, bch2_keylist_u64s(keys))) {
		bch2_btree_node_unlock_write(b, iter);
		goto split;
	}

	btree_node_interior_verify(c, b);

	bch2_btree_insert_keys_interior(as, b, iter, keys);

	live_u64s_added = (int) b->nr.live_u64s - old_live_u64s;
	u64s_added = (int) le16_to_cpu(btree_bset_last(b)->u64s) - old_u64s;

	if (b->sib_u64s[0] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[0] = max(0, (int) b->sib_u64s[0] + live_u64s_added);
	if (b->sib_u64s[1] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[1] = max(0, (int) b->sib_u64s[1] + live_u64s_added);

	if (u64s_added > live_u64s_added &&
	    bch2_maybe_compact_whiteouts(c, b))
		bch2_btree_iter_reinit_node(iter, b);

	bch2_btree_node_unlock_write(b, iter);

	btree_node_interior_verify(c, b);
	return;
split:
	btree_split(as, b, iter, keys, flags);
}

int bch2_btree_split_leaf(struct bch_fs *c, struct btree_iter *iter,
			  unsigned flags)
{
	struct btree *b = iter_l(iter)->b;
	struct btree_update *as;
	unsigned l;
	int ret = 0;

	as = bch2_btree_update_start(iter, iter->level,
		btree_update_reserve_required(c, b), flags);
	if (IS_ERR(as))
		return PTR_ERR(as);

	btree_split(as, b, iter, NULL, flags);
	bch2_btree_update_done(as);

	for (l = iter->level + 1; btree_iter_node(iter, l) && !ret; l++)
		ret = bch2_foreground_maybe_merge(c, iter, l, flags);

	return ret;
}

int __bch2_foreground_maybe_merge(struct bch_fs *c,
				  struct btree_iter *iter,
				  unsigned level,
				  unsigned flags,
				  enum btree_node_sibling sib)
{
	struct btree_trans *trans = iter->trans;
	struct btree_iter *sib_iter = NULL;
	struct btree_update *as;
	struct bkey_format_state new_s;
	struct bkey_format new_f;
	struct bkey_i delete;
	struct btree *b, *m, *n, *prev, *next, *parent;
	struct bpos sib_pos;
	size_t sib_u64s;
	int ret = 0, ret2 = 0;

	BUG_ON(!btree_node_locked(iter, level));
retry:
	ret = bch2_btree_iter_traverse(iter);
	if (ret)
		goto err;

	BUG_ON(!btree_node_locked(iter, level));

	b = iter->l[level].b;

	if ((sib == btree_prev_sib && !bpos_cmp(b->data->min_key, POS_MIN)) ||
	    (sib == btree_next_sib && !bpos_cmp(b->data->max_key, POS_MAX))) {
		b->sib_u64s[sib] = U16_MAX;
		goto out;
	}

	sib_pos = sib == btree_prev_sib
		? bpos_predecessor(b->data->min_key)
		: bpos_successor(b->data->max_key);

	sib_iter = bch2_trans_get_node_iter(trans, iter->btree_id,
					    sib_pos, U8_MAX, level,
					    BTREE_ITER_INTENT);
	ret = bch2_btree_iter_traverse(sib_iter);
	if (ret)
		goto err;

	m = sib_iter->l[level].b;

	if (btree_node_parent(iter, b) !=
	    btree_node_parent(sib_iter, m)) {
		b->sib_u64s[sib] = U16_MAX;
		goto out;
	}

	if (sib == btree_prev_sib) {
		prev = m;
		next = b;
	} else {
		prev = b;
		next = m;
	}

	if (bkey_cmp(bpos_successor(prev->data->max_key), next->data->min_key)) {
		char buf1[100], buf2[100];

		bch2_bpos_to_text(&PBUF(buf1), prev->data->max_key);
		bch2_bpos_to_text(&PBUF(buf2), next->data->min_key);
		bch_err(c,
			"btree topology error in btree merge:\n"
			"  prev ends at   %s\n"
			"  next starts at %s",
			buf1, buf2);
		bch2_topology_error(c);
		ret = -EIO;
		goto err;
	}

	bch2_bkey_format_init(&new_s);
	bch2_bkey_format_add_pos(&new_s, prev->data->min_key);
	__bch2_btree_calc_format(&new_s, prev);
	__bch2_btree_calc_format(&new_s, next);
	bch2_bkey_format_add_pos(&new_s, next->data->max_key);
	new_f = bch2_bkey_format_done(&new_s);

	sib_u64s = btree_node_u64s_with_format(b, &new_f) +
		btree_node_u64s_with_format(m, &new_f);

	if (sib_u64s > BTREE_FOREGROUND_MERGE_HYSTERESIS(c)) {
		sib_u64s -= BTREE_FOREGROUND_MERGE_HYSTERESIS(c);
		sib_u64s /= 2;
		sib_u64s += BTREE_FOREGROUND_MERGE_HYSTERESIS(c);
	}

	sib_u64s = min(sib_u64s, btree_max_u64s(c));
	sib_u64s = min(sib_u64s, (size_t) U16_MAX - 1);
	b->sib_u64s[sib] = sib_u64s;

	if (b->sib_u64s[sib] > c->btree_foreground_merge_threshold)
		goto out;

	parent = btree_node_parent(iter, b);
	as = bch2_btree_update_start(iter, level,
			 btree_update_reserve_required(c, parent) + 1,
			 flags|
			 BTREE_INSERT_NOFAIL|
			 BTREE_INSERT_USE_RESERVE);
	ret = PTR_ERR_OR_ZERO(as);
	if (ret)
		goto err;

	trace_btree_merge(c, b);

	bch2_btree_interior_update_will_free_node(as, b);
	bch2_btree_interior_update_will_free_node(as, m);

	n = bch2_btree_node_alloc(as, b->c.level);
	bch2_btree_update_add_new_node(as, n);

	btree_set_min(n, prev->data->min_key);
	btree_set_max(n, next->data->max_key);
	n->data->format		= new_f;

	btree_node_set_format(n, new_f);

	bch2_btree_sort_into(c, n, prev);
	bch2_btree_sort_into(c, n, next);

	bch2_btree_build_aux_trees(n);
	six_unlock_write(&n->c.lock);

	bkey_init(&delete.k);
	delete.k.p = prev->key.k.p;
	bch2_keylist_add(&as->parent_keys, &delete);
	bch2_keylist_add(&as->parent_keys, &n->key);

	bch2_btree_node_write(c, n, SIX_LOCK_intent);

	bch2_btree_insert_node(as, parent, iter, &as->parent_keys, flags);

	bch2_btree_update_get_open_buckets(as, n);

	six_lock_increment(&b->c.lock, SIX_LOCK_intent);
	six_lock_increment(&m->c.lock, SIX_LOCK_intent);
	bch2_btree_iter_node_drop(iter, b);
	bch2_btree_iter_node_drop(iter, m);

	bch2_btree_iter_node_replace(iter, n);

	bch2_btree_trans_verify_iters(trans, n);

	bch2_btree_node_free_inmem(c, b, iter);
	bch2_btree_node_free_inmem(c, m, iter);

	six_unlock_intent(&n->c.lock);

	bch2_btree_update_done(as);
out:
	bch2_btree_trans_verify_locks(trans);
	bch2_trans_iter_free(trans, sib_iter);

	/*
	 * Don't downgrade locks here: we're called after successful insert,
	 * and the caller will downgrade locks after a successful insert
	 * anyways (in case e.g. a split was required first)
	 *
	 * And we're also called when inserting into interior nodes in the
	 * split path, and downgrading to read locks in there is potentially
	 * confusing:
	 */
	return ret ?: ret2;
err:
	bch2_trans_iter_put(trans, sib_iter);
	sib_iter = NULL;

	if (ret == -EINTR && bch2_trans_relock(trans))
		goto retry;

	if (ret == -EINTR && !(flags & BTREE_INSERT_NOUNLOCK)) {
		ret2 = ret;
		ret = bch2_btree_iter_traverse_all(trans);
		if (!ret)
			goto retry;
	}

	goto out;
}

/**
 * bch_btree_node_rewrite - Rewrite/move a btree node
 */
int bch2_btree_node_rewrite(struct bch_fs *c, struct btree_iter *iter,
			    __le64 seq, unsigned flags)
{
	struct btree *b, *n, *parent;
	struct btree_update *as;
	int ret;

	flags |= BTREE_INSERT_NOFAIL;
retry:
	ret = bch2_btree_iter_traverse(iter);
	if (ret)
		goto out;

	b = bch2_btree_iter_peek_node(iter);
	if (!b || b->data->keys.seq != seq)
		goto out;

	parent = btree_node_parent(iter, b);
	as = bch2_btree_update_start(iter, b->c.level,
		(parent
		 ? btree_update_reserve_required(c, parent)
		 : 0) + 1,
		flags);
	ret = PTR_ERR_OR_ZERO(as);
	if (ret == -EINTR)
		goto retry;
	if (ret) {
		trace_btree_gc_rewrite_node_fail(c, b);
		goto out;
	}

	bch2_btree_interior_update_will_free_node(as, b);

	n = bch2_btree_node_alloc_replacement(as, b);
	bch2_btree_update_add_new_node(as, n);

	bch2_btree_build_aux_trees(n);
	six_unlock_write(&n->c.lock);

	trace_btree_gc_rewrite_node(c, b);

	bch2_btree_node_write(c, n, SIX_LOCK_intent);

	if (parent) {
		bch2_keylist_add(&as->parent_keys, &n->key);
		bch2_btree_insert_node(as, parent, iter, &as->parent_keys, flags);
	} else {
		bch2_btree_set_root(as, n, iter);
	}

	bch2_btree_update_get_open_buckets(as, n);

	six_lock_increment(&b->c.lock, SIX_LOCK_intent);
	bch2_btree_iter_node_drop(iter, b);
	bch2_btree_iter_node_replace(iter, n);
	bch2_btree_node_free_inmem(c, b, iter);
	six_unlock_intent(&n->c.lock);

	bch2_btree_update_done(as);
out:
	bch2_btree_iter_downgrade(iter);
	return ret;
}

struct async_btree_rewrite {
	struct bch_fs		*c;
	struct work_struct	work;
	enum btree_id		btree_id;
	unsigned		level;
	struct bpos		pos;
	__le64			seq;
};

void async_btree_node_rewrite_work(struct work_struct *work)
{
	struct async_btree_rewrite *a =
		container_of(work, struct async_btree_rewrite, work);
	struct bch_fs *c = a->c;
	struct btree_trans trans;
	struct btree_iter *iter;

	bch2_trans_init(&trans, c, 0, 0);
	iter = bch2_trans_get_node_iter(&trans, a->btree_id, a->pos,
					BTREE_MAX_DEPTH, a->level, 0);
	bch2_btree_node_rewrite(c, iter, a->seq, 0);
	bch2_trans_iter_put(&trans, iter);
	bch2_trans_exit(&trans);
	percpu_ref_put(&c->writes);
	kfree(a);
}

void bch2_btree_node_rewrite_async(struct bch_fs *c, struct btree *b)
{
	struct async_btree_rewrite *a;

	if (!test_bit(BCH_FS_BTREE_INTERIOR_REPLAY_DONE, &c->flags))
		return;

	if (!percpu_ref_tryget(&c->writes))
		return;

	a = kmalloc(sizeof(*a), GFP_NOFS);
	if (!a) {
		percpu_ref_put(&c->writes);
		return;
	}

	a->c		= c;
	a->btree_id	= b->c.btree_id;
	a->level	= b->c.level;
	a->pos		= b->key.k.p;
	a->seq		= b->data->keys.seq;

	INIT_WORK(&a->work, async_btree_node_rewrite_work);
	queue_work(c->btree_interior_update_worker, &a->work);
}

static void __bch2_btree_node_update_key(struct bch_fs *c,
					 struct btree_update *as,
					 struct btree_iter *iter,
					 struct btree *b, struct btree *new_hash,
					 struct bkey_i *new_key)
{
	struct btree *parent;
	int ret;

	btree_update_will_delete_key(as, &b->key);
	btree_update_will_add_key(as, new_key);

	parent = btree_node_parent(iter, b);
	if (parent) {
		if (new_hash) {
			bkey_copy(&new_hash->key, new_key);
			ret = bch2_btree_node_hash_insert(&c->btree_cache,
					new_hash, b->c.level, b->c.btree_id);
			BUG_ON(ret);
		}

		bch2_keylist_add(&as->parent_keys, new_key);
		bch2_btree_insert_node(as, parent, iter, &as->parent_keys, 0);

		if (new_hash) {
			mutex_lock(&c->btree_cache.lock);
			bch2_btree_node_hash_remove(&c->btree_cache, new_hash);

			bch2_btree_node_hash_remove(&c->btree_cache, b);

			bkey_copy(&b->key, new_key);
			ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
			BUG_ON(ret);
			mutex_unlock(&c->btree_cache.lock);
		} else {
			bkey_copy(&b->key, new_key);
		}
	} else {
		BUG_ON(btree_node_root(c, b) != b);

		bch2_btree_node_lock_write(b, iter);
		bkey_copy(&b->key, new_key);

		if (btree_ptr_hash_val(&b->key) != b->hash_val) {
			mutex_lock(&c->btree_cache.lock);
			bch2_btree_node_hash_remove(&c->btree_cache, b);

			ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
			BUG_ON(ret);
			mutex_unlock(&c->btree_cache.lock);
		}

		btree_update_updated_root(as, b);
		bch2_btree_node_unlock_write(b, iter);
	}

	bch2_btree_update_done(as);
}

int bch2_btree_node_update_key(struct bch_fs *c, struct btree_iter *iter,
			       struct btree *b,
			       struct bkey_i *new_key)
{
	struct btree *parent = btree_node_parent(iter, b);
	struct btree_update *as = NULL;
	struct btree *new_hash = NULL;
	struct closure cl;
	int ret = 0;

	closure_init_stack(&cl);

	/*
	 * check btree_ptr_hash_val() after @b is locked by
	 * btree_iter_traverse():
	 */
	if (btree_ptr_hash_val(new_key) != b->hash_val) {
		ret = bch2_btree_cache_cannibalize_lock(c, &cl);
		if (ret) {
			bch2_trans_unlock(iter->trans);
			closure_sync(&cl);
			if (!bch2_trans_relock(iter->trans))
				return -EINTR;
		}

		new_hash = bch2_btree_node_mem_alloc(c);
	}

	as = bch2_btree_update_start(iter, b->c.level,
		parent ? btree_update_reserve_required(c, parent) : 0,
		BTREE_INSERT_NOFAIL);
	if (IS_ERR(as)) {
		ret = PTR_ERR(as);
		goto err;
	}

	__bch2_btree_node_update_key(c, as, iter, b, new_hash, new_key);

	bch2_btree_iter_downgrade(iter);
err:
	if (new_hash) {
		mutex_lock(&c->btree_cache.lock);
		list_move(&new_hash->list, &c->btree_cache.freeable);
		mutex_unlock(&c->btree_cache.lock);

		six_unlock_write(&new_hash->c.lock);
		six_unlock_intent(&new_hash->c.lock);
	}
	closure_sync(&cl);
	bch2_btree_cache_cannibalize_unlock(c);
	return ret;
}

/* Init code: */

/*
 * Only for filesystem bringup, when first reading the btree roots or allocating
 * btree roots when initializing a new filesystem:
 */
void bch2_btree_set_root_for_read(struct bch_fs *c, struct btree *b)
{
	BUG_ON(btree_node_root(c, b));

	bch2_btree_set_root_inmem(c, b);
}

void bch2_btree_root_alloc(struct bch_fs *c, enum btree_id id)
{
	struct closure cl;
	struct btree *b;
	int ret;

	closure_init_stack(&cl);

	do {
		ret = bch2_btree_cache_cannibalize_lock(c, &cl);
		closure_sync(&cl);
	} while (ret);

	b = bch2_btree_node_mem_alloc(c);
	bch2_btree_cache_cannibalize_unlock(c);

	set_btree_node_fake(b);
	set_btree_node_need_rewrite(b);
	b->c.level	= 0;
	b->c.btree_id	= id;

	bkey_btree_ptr_init(&b->key);
	b->key.k.p = POS_MAX;
	*((u64 *) bkey_i_to_btree_ptr(&b->key)->v.start) = U64_MAX - id;

	bch2_bset_init_first(b, &b->data->keys);
	bch2_btree_build_aux_trees(b);

	b->data->flags = 0;
	btree_set_min(b, POS_MIN);
	btree_set_max(b, POS_MAX);
	b->data->format = bch2_btree_calc_format(b);
	btree_node_set_format(b, b->data->format);

	ret = bch2_btree_node_hash_insert(&c->btree_cache, b,
					  b->c.level, b->c.btree_id);
	BUG_ON(ret);

	bch2_btree_set_root_inmem(c, b);

	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
}

void bch2_btree_updates_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct btree_update *as;

	mutex_lock(&c->btree_interior_update_lock);
	list_for_each_entry(as, &c->btree_interior_update_list, list)
		pr_buf(out, "%p m %u w %u r %u j %llu\n",
		       as,
		       as->mode,
		       as->nodes_written,
		       atomic_read(&as->cl.remaining) & CLOSURE_REMAINING_MASK,
		       as->journal.seq);
	mutex_unlock(&c->btree_interior_update_lock);
}

size_t bch2_btree_interior_updates_nr_pending(struct bch_fs *c)
{
	size_t ret = 0;
	struct list_head *i;

	mutex_lock(&c->btree_interior_update_lock);
	list_for_each(i, &c->btree_interior_update_list)
		ret++;
	mutex_unlock(&c->btree_interior_update_lock);

	return ret;
}

void bch2_journal_entries_to_btree_roots(struct bch_fs *c, struct jset *jset)
{
	struct btree_root *r;
	struct jset_entry *entry;

	mutex_lock(&c->btree_root_lock);

	vstruct_for_each(jset, entry)
		if (entry->type == BCH_JSET_ENTRY_btree_root) {
			r = &c->btree_roots[entry->btree_id];
			r->level = entry->level;
			r->alive = true;
			bkey_copy(&r->key, &entry->start[0]);
		}

	mutex_unlock(&c->btree_root_lock);
}

struct jset_entry *
bch2_btree_roots_to_journal_entries(struct bch_fs *c,
				    struct jset_entry *start,
				    struct jset_entry *end)
{
	struct jset_entry *entry;
	unsigned long have = 0;
	unsigned i;

	for (entry = start; entry < end; entry = vstruct_next(entry))
		if (entry->type == BCH_JSET_ENTRY_btree_root)
			__set_bit(entry->btree_id, &have);

	mutex_lock(&c->btree_root_lock);

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i].alive && !test_bit(i, &have)) {
			journal_entry_set(end,
					  BCH_JSET_ENTRY_btree_root,
					  i, c->btree_roots[i].level,
					  &c->btree_roots[i].key,
					  c->btree_roots[i].key.u64s);
			end = vstruct_next(end);
		}

	mutex_unlock(&c->btree_root_lock);

	return end;
}

void bch2_fs_btree_interior_update_exit(struct bch_fs *c)
{
	if (c->btree_interior_update_worker)
		destroy_workqueue(c->btree_interior_update_worker);
	mempool_exit(&c->btree_interior_update_pool);
}

int bch2_fs_btree_interior_update_init(struct bch_fs *c)
{
	mutex_init(&c->btree_reserve_cache_lock);
	INIT_LIST_HEAD(&c->btree_interior_update_list);
	INIT_LIST_HEAD(&c->btree_interior_updates_unwritten);
	mutex_init(&c->btree_interior_update_lock);
	INIT_WORK(&c->btree_interior_update_work, btree_interior_update_work);

	c->btree_interior_update_worker =
		alloc_workqueue("btree_update", WQ_UNBOUND|WQ_MEM_RECLAIM, 1);
	if (!c->btree_interior_update_worker)
		return -ENOMEM;

	return mempool_init_kmalloc_pool(&c->btree_interior_update_pool, 1,
					 sizeof(struct btree_update));
}
