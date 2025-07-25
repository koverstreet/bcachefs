// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "bkey_buf.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_journal_iter.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "clock.h"
#include "disk_groups.h"
#include "enumerated_ref.h"
#include "error.h"
#include "extents.h"
#include "io_write.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "recovery_passes.h"
#include "replicas.h"
#include "sb-members.h"
#include "super-io.h"
#include "trace.h"

#include <linux/random.h>

static const char * const bch2_btree_update_modes[] = {
#define x(t) #t,
	BTREE_UPDATE_MODES()
#undef x
	NULL
};

static void bch2_btree_update_to_text(struct printbuf *, struct btree_update *);

static int bch2_btree_insert_node(struct btree_update *, struct btree_trans *,
				  btree_path_idx_t, struct btree *, struct keylist *);
static void bch2_btree_update_add_new_node(struct btree_update *, struct btree *);

/*
 * Verify that child nodes correctly span parent node's range:
 */
int bch2_btree_node_check_topology(struct btree_trans *trans, struct btree *b)
{
	struct bch_fs *c = trans->c;
	struct bpos node_min = b->key.k.type == KEY_TYPE_btree_ptr_v2
		? bkey_i_to_btree_ptr_v2(&b->key)->v.min_key
		: b->data->min_key;
	struct btree_and_journal_iter iter;
	struct bkey_s_c k;
	CLASS(printbuf, buf)();
	struct bkey_buf prev;
	int ret = 0;

	BUG_ON(b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	       !bpos_eq(bkey_i_to_btree_ptr_v2(&b->key)->v.min_key,
			b->data->min_key));

	bch2_bkey_buf_init(&prev);
	bkey_init(&prev.k->k);
	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);

	if (b == btree_node_root(c, b)) {
		if (!bpos_eq(b->data->min_key, POS_MIN)) {
			bch2_log_msg_start(c, &buf);
			prt_printf(&buf, "btree root with incorrect min_key: ");
			bch2_bpos_to_text(&buf, b->data->min_key);
			prt_newline(&buf);

			bch2_count_fsck_err(c, btree_root_bad_min_key, &buf);
			goto err;
		}

		if (!bpos_eq(b->data->max_key, SPOS_MAX)) {
			bch2_log_msg_start(c, &buf);
			prt_printf(&buf, "btree root with incorrect max_key: ");
			bch2_bpos_to_text(&buf, b->data->max_key);
			prt_newline(&buf);

			bch2_count_fsck_err(c, btree_root_bad_max_key, &buf);
			goto err;
		}
	}

	if (!b->c.level)
		goto out;

	while ((k = bch2_btree_and_journal_iter_peek(&iter)).k) {
		if (k.k->type != KEY_TYPE_btree_ptr_v2)
			goto out;

		struct bkey_s_c_btree_ptr_v2 bp = bkey_s_c_to_btree_ptr_v2(k);

		struct bpos expected_min = bkey_deleted(&prev.k->k)
			? node_min
			: bpos_successor(prev.k->k.p);

		if (!bpos_eq(expected_min, bp.v->min_key)) {
			prt_str(&buf, "end of prev node doesn't match start of next node");
			prt_str(&buf, "\nprev ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(prev.k));
			prt_str(&buf, "\nnext ");
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);

			bch2_count_fsck_err(c, btree_node_topology_bad_min_key, &buf);
			goto err;
		}

		bch2_bkey_buf_reassemble(&prev, c, k);
		bch2_btree_and_journal_iter_advance(&iter);
	}

	if (bkey_deleted(&prev.k->k)) {
		prt_printf(&buf, "empty interior node\n");
		bch2_count_fsck_err(c, btree_node_topology_empty_interior_node, &buf);
		goto err;
	}

	if (!bpos_eq(prev.k->k.p, b->key.k.p)) {
		prt_str(&buf, "last child node doesn't end at end of parent node\nchild: ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(prev.k));
		prt_newline(&buf);

		bch2_count_fsck_err(c, btree_node_topology_bad_max_key, &buf);
		goto err;
	}
out:
	bch2_btree_and_journal_iter_exit(&iter);
	bch2_bkey_buf_exit(&prev, c);
	return ret;
err:
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_char(&buf, ' ');
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
	prt_newline(&buf);

	ret = __bch2_topology_error(c, &buf);
	bch2_print_str(c, KERN_ERR, buf.buf);
	BUG_ON(!ret);
	goto out;
}

/* Calculate ideal packed bkey format for new btree nodes: */

static void __bch2_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct bkey_packed *k;
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

static size_t btree_node_u64s_with_format(struct btree_nr_keys nr,
					  struct bkey_format *old_f,
					  struct bkey_format *new_f)
{
	/* stupid integer promotion rules */
	ssize_t delta =
	    (((int) new_f->key_u64s - old_f->key_u64s) *
	     (int) nr.packed_keys) +
	    (((int) new_f->key_u64s - BKEY_U64s) *
	     (int) nr.unpacked_keys);

	BUG_ON(delta + nr.live_u64s < 0);

	return nr.live_u64s + delta;
}

/**
 * bch2_btree_node_format_fits - check if we could rewrite node with a new format
 *
 * @c:		filesystem handle
 * @b:		btree node to rewrite
 * @nr:		number of keys for new node (i.e. b->nr)
 * @new_f:	bkey format to translate keys to
 *
 * Returns: true if all re-packed keys will be able to fit in a new node.
 *
 * Assumes all keys will successfully pack with the new format.
 */
static bool bch2_btree_node_format_fits(struct bch_fs *c, struct btree *b,
				 struct btree_nr_keys nr,
				 struct bkey_format *new_f)
{
	size_t u64s = btree_node_u64s_with_format(nr, &b->format, new_f);

	return __vstruct_bytes(struct btree_node, u64s) < btree_buf_bytes(b);
}

/* Btree node freeing/allocation: */

static void __btree_node_free(struct btree_trans *trans, struct btree *b)
{
	struct bch_fs *c = trans->c;

	trace_btree_node(c, b, btree_node_free);

	BUG_ON(btree_node_write_blocked(b));
	BUG_ON(btree_node_dirty(b));
	BUG_ON(btree_node_need_write(b));
	BUG_ON(b == btree_node_root(c, b));
	BUG_ON(b->ob.nr);
	BUG_ON(!list_empty(&b->write_blocked));
	BUG_ON(b->will_make_reachable);

	clear_btree_node_noevict(b);
}

static void bch2_btree_node_free_inmem(struct btree_trans *trans,
				       struct btree_path *path,
				       struct btree *b)
{
	struct bch_fs *c = trans->c;

	bch2_btree_node_lock_write_nofail(trans, path, &b->c);

	__btree_node_free(trans, b);

	scoped_guard(mutex, &c->btree_cache.lock)
		bch2_btree_node_hash_remove(&c->btree_cache, b);

	six_unlock_write(&b->c.lock);
	mark_btree_node_locked_noreset(path, b->c.level, BTREE_NODE_INTENT_LOCKED);

	bch2_trans_node_drop(trans, b);
}

static void bch2_btree_node_free_never_used(struct btree_update *as,
					    struct btree_trans *trans,
					    struct btree *b)
{
	struct bch_fs *c = as->c;
	struct prealloc_nodes *p = &as->prealloc_nodes[b->c.lock.readers != NULL];

	BUG_ON(!list_empty(&b->write_blocked));
	BUG_ON(b->will_make_reachable != (1UL|(unsigned long) as));

	b->will_make_reachable = 0;
	closure_put(&as->cl);

	clear_btree_node_will_make_reachable(b);
	clear_btree_node_accessed(b);
	clear_btree_node_dirty_acct(c, b);
	clear_btree_node_need_write(b);

	scoped_guard(mutex, &c->btree_cache.lock)
		__bch2_btree_node_hash_remove(&c->btree_cache, b);

	BUG_ON(p->nr >= ARRAY_SIZE(p->b));
	p->b[p->nr++] = b;

	six_unlock_intent(&b->c.lock);

	bch2_trans_node_drop(trans, b);
}

static bool can_use_btree_node(struct bch_fs *c,
			       struct disk_reservation *res,
			       unsigned target,
			       struct bkey_s_c k)
{
	if (!bch2_bkey_devs_rw(c, k))
		return false;

	if (target && !bch2_bkey_in_target(c, k, target))
		return false;

	unsigned durability = bch2_bkey_durability(c, k);

	if (durability >= res->nr_replicas)
		return true;

	struct bch_devs_mask devs = target_rw_devs(c, BCH_DATA_btree, target);

	guard(rcu)();

	unsigned durability_available = 0, i;
	for_each_set_bit(i, devs.d, BCH_SB_MEMBERS_MAX) {
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, i);
		if (ca)
			durability_available += ca->mi.durability;
	}

	return durability >= durability_available;
}

static struct btree *__bch2_btree_node_alloc(struct btree_trans *trans,
					     struct disk_reservation *res,
					     struct closure *cl,
					     bool interior_node,
					     unsigned target,
					     enum bch_trans_commit_flags flags)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp;
	struct btree *b;
	struct bch_devs_list devs_have = (struct bch_devs_list) { 0 };
	enum bch_watermark watermark = flags & BCH_WATERMARK_MASK;
	unsigned nr_reserve = watermark < BCH_WATERMARK_reclaim
		? BTREE_NODE_RESERVE
		: 0;
	int ret;

	b = bch2_btree_node_mem_alloc(trans, interior_node);
	if (IS_ERR(b))
		return b;

	BUG_ON(b->ob.nr);

	mutex_lock(&c->btree_reserve_cache_lock);
	if (c->btree_reserve_cache_nr > nr_reserve) {
		for (struct btree_alloc *a = c->btree_reserve_cache;
		     a < c->btree_reserve_cache + c->btree_reserve_cache_nr;) {
			/* check if it has sufficient durability */

			if (!can_use_btree_node(c, res, target, bkey_i_to_s_c(&a->k))) {
				bch2_open_buckets_put(c, &a->ob);
				*a = c->btree_reserve_cache[--c->btree_reserve_cache_nr];
				continue;
			}

			bkey_copy(&b->key, &a->k);
			b->ob = a->ob;
			*a = c->btree_reserve_cache[--c->btree_reserve_cache_nr];
			mutex_unlock(&c->btree_reserve_cache_lock);
			goto out;
		}
	}
	mutex_unlock(&c->btree_reserve_cache_lock);
retry:
	ret = bch2_alloc_sectors_start_trans(trans,
				      target ?:
				      c->opts.metadata_target ?:
				      c->opts.foreground_target,
				      0,
				      writepoint_ptr(&c->btree_write_point),
				      &devs_have,
				      res->nr_replicas,
				      min(res->nr_replicas,
					  c->opts.metadata_replicas_required),
				      watermark,
				      target ? BCH_WRITE_only_specified_devs : 0,
				      cl, &wp);
	if (unlikely(ret))
		goto err;

	if (wp->sectors_free < btree_sectors(c)) {
		struct open_bucket *ob;
		unsigned i;

		open_bucket_for_each(c, &wp->ptrs, ob, i)
			if (ob->sectors_free < btree_sectors(c))
				ob->sectors_free = 0;

		bch2_alloc_sectors_done(c, wp);
		goto retry;
	}

	bkey_btree_ptr_v2_init(&b->key);
	bch2_alloc_sectors_append_ptrs(c, wp, &b->key, btree_sectors(c), false);

	bch2_open_bucket_get(c, wp, &b->ob);
	bch2_alloc_sectors_done(c, wp);
out:
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);

	return b;
err:
	bch2_btree_node_to_freelist(c, b);
	return ERR_PTR(ret);
}

static struct btree *bch2_btree_node_alloc(struct btree_update *as,
					   struct btree_trans *trans,
					   unsigned level)
{
	struct bch_fs *c = as->c;
	struct btree *b;
	struct prealloc_nodes *p = &as->prealloc_nodes[!!level];
	int ret;

	BUG_ON(level >= BTREE_MAX_DEPTH);
	BUG_ON(!p->nr);

	b = p->b[--p->nr];

	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_intent);
	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_write);

	set_btree_node_accessed(b);
	set_btree_node_dirty_acct(c, b);
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

	trace_btree_node(c, b, btree_node_alloc);
	bch2_increment_clock(c, btree_sectors(c), WRITE);
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

static struct btree *bch2_btree_node_alloc_replacement(struct btree_update *as,
						       struct btree_trans *trans,
						       struct btree *b)
{
	struct btree *n = bch2_btree_node_alloc(as, trans, b->c.level);
	struct bkey_format format = bch2_btree_calc_format(b);

	/*
	 * The keys might expand with the new format - if they wouldn't fit in
	 * the btree node anymore, use the old format for now:
	 */
	if (!bch2_btree_node_format_fits(as->c, b, b->nr, &format))
		format = b->format;

	SET_BTREE_NODE_SEQ(n->data, BTREE_NODE_SEQ(b->data) + 1);

	btree_set_min(n, b->data->min_key);
	btree_set_max(n, b->data->max_key);

	n->data->format		= format;
	btree_node_set_format(n, format);

	bch2_btree_sort_into(as->c, n, b);

	btree_node_reset_sib_u64s(n);
	return n;
}

static struct btree *__btree_root_alloc(struct btree_update *as,
				struct btree_trans *trans, unsigned level)
{
	struct btree *b = bch2_btree_node_alloc(as, trans, level);

	btree_set_min(b, POS_MIN);
	btree_set_max(b, SPOS_MAX);
	b->data->format = bch2_btree_calc_format(b);

	btree_node_set_format(b, b->data->format);
	bch2_btree_build_aux_trees(b);

	return b;
}

static void bch2_btree_reserve_put(struct btree_update *as, struct btree_trans *trans)
{
	struct bch_fs *c = as->c;
	struct prealloc_nodes *p;

	for (p = as->prealloc_nodes;
	     p < as->prealloc_nodes + ARRAY_SIZE(as->prealloc_nodes);
	     p++) {
		while (p->nr) {
			struct btree *b = p->b[--p->nr];

			mutex_lock(&c->btree_reserve_cache_lock);

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

			mutex_unlock(&c->btree_reserve_cache_lock);

			btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_intent);
			btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_write);
			__btree_node_free(trans, b);
			bch2_btree_node_to_freelist(c, b);
		}
	}
}

static int bch2_btree_reserve_get(struct btree_trans *trans,
				  struct btree_update *as,
				  unsigned nr_nodes[2],
				  unsigned target,
				  unsigned flags,
				  struct closure *cl)
{
	BUG_ON(nr_nodes[0] + nr_nodes[1] > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	int ret = bch2_btree_cache_cannibalize_lock(trans, cl);
	if (ret)
		return ret;

	for (unsigned interior = 0; interior < 2; interior++) {
		struct prealloc_nodes *p = as->prealloc_nodes + interior;

		while (p->nr < nr_nodes[interior]) {
			struct btree *b = __bch2_btree_node_alloc(trans, &as->disk_res,
							cl, interior, target, flags);
			ret = PTR_ERR_OR_ZERO(b);
			if (ret)
				goto err;

			p->b[p->nr++] = b;
		}
	}
err:
	bch2_btree_cache_cannibalize_unlock(trans);
	return ret;
}

/* Asynchronous interior node update machinery */

static void bch2_btree_update_free(struct btree_update *as, struct btree_trans *trans)
{
	struct bch_fs *c = as->c;

	if (as->took_gc_lock)
		up_read(&c->gc_lock);
	as->took_gc_lock = false;

	bch2_journal_pin_drop(&c->journal, &as->journal);
	bch2_journal_pin_flush(&c->journal, &as->journal);
	bch2_disk_reservation_put(c, &as->disk_res);
	bch2_btree_reserve_put(as, trans);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_interior_update_total],
			       as->start_time);

	guard(mutex)(&c->btree_interior_update_lock);

	list_del(&as->unwritten_list);
	list_del(&as->list);

	closure_debug_destroy(&as->cl);
	mempool_free(as, &c->btree_interior_update_pool);

	/*
	 * Have to do the wakeup with btree_interior_update_lock still held,
	 * since being on btree_interior_update_list is our ref on @c:
	 */
	closure_wake_up(&c->btree_interior_update_wait);
}

static void btree_update_add_key(struct btree_update *as,
				 struct keylist *keys, struct btree *b)
{
	struct bkey_i *k = &b->key;

	BUG_ON(bch2_keylist_u64s(keys) + k->k.u64s >
	       ARRAY_SIZE(as->_old_keys));

	bkey_copy(keys->top, k);
	bkey_i_to_btree_ptr_v2(keys->top)->v.mem_ptr = b->c.level + 1;

	bch2_keylist_push(keys);
}

static bool btree_update_new_nodes_marked_sb(struct btree_update *as)
{
	for_each_keylist_key(&as->new_keys, k)
		if (!bch2_dev_btree_bitmap_marked(as->c, bkey_i_to_s_c(k)))
			return false;
	return true;
}

static void btree_update_new_nodes_mark_sb(struct btree_update *as)
{
	struct bch_fs *c = as->c;

	guard(mutex)(&c->sb_lock);
	for_each_keylist_key(&as->new_keys, k)
		bch2_dev_btree_bitmap_mark(c, bkey_i_to_s_c(k));

	bch2_write_super(c);
}

/*
 * The transactional part of an interior btree node update, where we journal the
 * update we did to the interior node and update alloc info:
 */
static int btree_update_nodes_written_trans(struct btree_trans *trans,
					    struct btree_update *as)
{
	struct jset_entry *e = bch2_trans_jset_entry_alloc(trans, as->journal_u64s);
	int ret = PTR_ERR_OR_ZERO(e);
	if (ret)
		return ret;

	memcpy(e, as->journal_entries, as->journal_u64s * sizeof(u64));

	trans->journal_pin = &as->journal;

	for_each_keylist_key(&as->old_keys, k) {
		unsigned level = bkey_i_to_btree_ptr_v2(k)->v.mem_ptr;

		ret = bch2_key_trigger_old(trans, as->btree_id, level, bkey_i_to_s_c(k),
					   BTREE_TRIGGER_transactional);
		if (ret)
			return ret;
	}

	for_each_keylist_key(&as->new_keys, k) {
		unsigned level = bkey_i_to_btree_ptr_v2(k)->v.mem_ptr;

		ret = bch2_key_trigger_new(trans, as->btree_id, level, bkey_i_to_s(k),
					   BTREE_TRIGGER_transactional);
		if (ret)
			return ret;
	}

	return 0;
}

/* If the node has been reused, we might be reading uninitialized memory - that's fine: */
static noinline __no_kmsan_checks bool btree_node_seq_matches(struct btree *b, __le64 seq)
{
	struct btree_node *b_data = READ_ONCE(b->data);

	return (b_data ? b_data->keys.seq : 0) == seq;
}

static void btree_update_nodes_written(struct btree_update *as)
{
	struct bch_fs *c = as->c;
	struct btree *b;
	CLASS(btree_trans, trans)(c);
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

	if (!btree_update_new_nodes_marked_sb(as))
		btree_update_new_nodes_mark_sb(as);

	/*
	 * Wait for any in flight writes to finish before we free the old nodes
	 * on disk. But we haven't pinned those old nodes in the btree cache,
	 * they might have already been evicted.
	 *
	 * The update we're completing deleted references to those nodes from the
	 * btree, so we know if they've been evicted they can't be pulled back in.
	 * We just have to check if the nodes we have pointers to are still those
	 * old nodes, and haven't been reused.
	 *
	 * This can't be done locklessly because the data buffer might have been
	 * vmalloc allocated, and they're not RCU freed. We also need the
	 * __no_kmsan_checks annotation because even with the btree node read
	 * lock, nothing tells us that the data buffer has been initialized (if
	 * the btree node has been reused for a different node, and the data
	 * buffer swapped for a new data buffer).
	 */
	for (i = 0; i < as->nr_old_nodes; i++) {
		b = as->old_nodes[i];

		bch2_trans_begin(trans);
		btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);
		bool seq_matches = btree_node_seq_matches(b, as->old_nodes_seq[i]);
		six_unlock_read(&b->c.lock);
		bch2_trans_unlock_long(trans);

		if (seq_matches)
			wait_on_bit_io(&b->flags, BTREE_NODE_write_in_flight_inner,
				       TASK_UNINTERRUPTIBLE);
	}

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
	ret = commit_do(trans, &as->disk_res, &journal_seq,
			BCH_WATERMARK_interior_updates|
			BCH_TRANS_COMMIT_no_enospc|
			BCH_TRANS_COMMIT_no_check_rw|
			BCH_TRANS_COMMIT_journal_reclaim,
			btree_update_nodes_written_trans(trans, as));
	bch2_trans_unlock(trans);

	bch2_fs_fatal_err_on(ret && !bch2_journal_error(&c->journal), c,
			     "%s", bch2_err_str(ret));
err:
	/*
	 * Ensure transaction is unlocked before using btree_node_lock_nopath()
	 * (the use of which is always suspect, we need to work on removing this
	 * in the future)
	 *
	 * It should be, but bch2_path_get_unlocked_mut() -> bch2_path_get()
	 * calls bch2_path_upgrade(), before we call path_make_mut(), so we may
	 * rarely end up with a locked path besides the one we have here:
	 */
	bch2_trans_unlock(trans);
	bch2_trans_begin(trans);

	/*
	 * We have to be careful because another thread might be getting ready
	 * to free as->b and calling btree_update_reparent() on us - we'll
	 * recheck under btree_update_lock below:
	 */
	b = READ_ONCE(as->b);
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

		btree_path_idx_t path_idx = bch2_path_get_unlocked_mut(trans,
						as->btree_id, b->c.level, b->key.k.p);
		struct btree_path *path = trans->paths + path_idx;
		btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_intent);
		mark_btree_node_locked(trans, path, b->c.level, BTREE_NODE_INTENT_LOCKED);
		path->l[b->c.level].lock_seq = six_lock_seq(&b->c.lock);
		path->l[b->c.level].b = b;

		bch2_btree_node_lock_write_nofail(trans, path, &b->c);

		mutex_lock(&c->btree_interior_update_lock);

		list_del(&as->write_blocked_list);
		if (list_empty(&b->write_blocked))
			clear_btree_node_write_blocked(b);

		/*
		 * Node might have been freed, recheck under
		 * btree_interior_update_lock:
		 */
		if (as->b == b) {
			BUG_ON(!b->c.level);
			BUG_ON(!btree_node_dirty(b));

			if (!ret) {
				struct bset *last = btree_bset_last(b);

				last->journal_seq = cpu_to_le64(
							     max(journal_seq,
								 le64_to_cpu(last->journal_seq)));

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

		mark_btree_node_locked_noreset(path, b->c.level, BTREE_NODE_INTENT_LOCKED);
		six_unlock_write(&b->c.lock);

		btree_node_write_if_need(trans, b, SIX_LOCK_intent);
		btree_node_unlock(trans, path, b->c.level);
		bch2_path_put(trans, path_idx, true);
	}

	bch2_journal_pin_drop(&c->journal, &as->journal);

	scoped_guard(mutex, &c->btree_interior_update_lock) {
		for (i = 0; i < as->nr_new_nodes; i++) {
			b = as->new_nodes[i];

			BUG_ON(b->will_make_reachable != (unsigned long) as);
			b->will_make_reachable = 0;
			clear_btree_node_will_make_reachable(b);
		}
	}

	for (i = 0; i < as->nr_new_nodes; i++) {
		b = as->new_nodes[i];

		btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);
		btree_node_write_if_need(trans, b, SIX_LOCK_read);
		six_unlock_read(&b->c.lock);
	}

	for (i = 0; i < as->nr_open_buckets; i++)
		bch2_open_bucket_put(c, c->open_buckets + as->open_buckets[i]);

	bch2_btree_update_free(as, trans);
}

static void btree_interior_update_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, btree_interior_update_work);
	struct btree_update *as;

	while (1) {
		scoped_guard(mutex, &c->btree_interior_update_lock) {
			as = list_first_entry_or_null(&c->btree_interior_updates_unwritten,
						      struct btree_update, unwritten_list);
			if (as && !as->nodes_written)
				as = NULL;
		}

		if (!as)
			break;

		btree_update_nodes_written(as);
	}
}

static CLOSURE_CALLBACK(btree_update_set_nodes_written)
{
	closure_type(as, struct btree_update, cl);
	struct bch_fs *c = as->c;

	scoped_guard(mutex, &c->btree_interior_update_lock)
		as->nodes_written = true;

	queue_work(c->btree_interior_update_worker, &c->btree_interior_update_work);
}

/*
 * We're updating @b with pointers to nodes that haven't finished writing yet:
 * block @b from being written until @as completes
 */
static void btree_update_updated_node(struct btree_update *as, struct btree *b)
{
	struct bch_fs *c = as->c;

	BUG_ON(as->mode != BTREE_UPDATE_none);
	BUG_ON(as->update_level_end < b->c.level);
	BUG_ON(!btree_node_dirty(b));
	BUG_ON(!b->c.level);

	guard(mutex)(&c->btree_interior_update_lock);
	list_add_tail(&as->unwritten_list, &c->btree_interior_updates_unwritten);

	as->mode	= BTREE_UPDATE_node;
	as->b		= b;
	as->update_level_end = b->c.level;

	set_btree_node_write_blocked(b);
	list_add(&as->write_blocked_list, &b->write_blocked);
}

static int bch2_update_reparent_journal_pin_flush(struct journal *j,
				struct journal_entry_pin *_pin, u64 seq)
{
	return 0;
}

static void btree_update_reparent(struct btree_update *as,
				  struct btree_update *child)
{
	struct bch_fs *c = as->c;

	lockdep_assert_held(&c->btree_interior_update_lock);

	child->b = NULL;
	child->mode = BTREE_UPDATE_update;

	bch2_journal_pin_copy(&c->journal, &as->journal, &child->journal,
			      bch2_update_reparent_journal_pin_flush);
}

static void btree_update_updated_root(struct btree_update *as, struct btree *b)
{
	struct bkey_i *insert = &b->key;
	struct bch_fs *c = as->c;

	BUG_ON(as->mode != BTREE_UPDATE_none);

	BUG_ON(as->journal_u64s + jset_u64s(insert->k.u64s) >
	       ARRAY_SIZE(as->journal_entries));

	as->journal_u64s +=
		journal_entry_set((void *) &as->journal_entries[as->journal_u64s],
				  BCH_JSET_ENTRY_btree_root,
				  b->c.btree_id, b->c.level,
				  insert, insert->k.u64s);

	scoped_guard(mutex, &c->btree_interior_update_lock) {
		list_add_tail(&as->unwritten_list, &c->btree_interior_updates_unwritten);

		as->mode	= BTREE_UPDATE_root;
	}
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
static void bch2_btree_update_add_new_node(struct btree_update *as, struct btree *b)
{
	struct bch_fs *c = as->c;

	closure_get(&as->cl);

	guard(mutex)(&c->btree_interior_update_lock);

	BUG_ON(as->nr_new_nodes >= ARRAY_SIZE(as->new_nodes));
	BUG_ON(b->will_make_reachable);

	as->new_nodes[as->nr_new_nodes++] = b;
	b->will_make_reachable = 1UL|(unsigned long) as;
	set_btree_node_will_make_reachable(b);

	btree_update_add_key(as, &as->new_keys, b);

	if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
		unsigned bytes = vstruct_end(&b->data->keys) - (void *) b->data;
		unsigned sectors = round_up(bytes, block_bytes(c)) >> 9;

		bkey_i_to_btree_ptr_v2(&b->key)->v.sectors_written =
			cpu_to_le16(sectors);
	}
}

/*
 * returns true if @b was a new node
 */
static void btree_update_drop_new_node(struct bch_fs *c, struct btree *b)
{
	struct btree_update *as;
	unsigned long v;

	scoped_guard(mutex, &c->btree_interior_update_lock) {
		/*
		 * When b->will_make_reachable != 0, it owns a ref on as->cl that's
		 * dropped when it gets written by bch2_btree_complete_write - the
		 * xchg() is for synchronization with bch2_btree_complete_write:
		 */
		v = xchg(&b->will_make_reachable, 0);
		clear_btree_node_will_make_reachable(b);
		as = (struct btree_update *) (v & ~1UL);

		if (!as)
			return;

		unsigned i;
		for (i = 0; i < as->nr_new_nodes; i++)
			if (as->new_nodes[i] == b)
				goto found;

		BUG();
	found:
		array_remove_item(as->new_nodes, as->nr_new_nodes, i);
	}

	if (v & 1)
		closure_put(&as->cl);
}

static void bch2_btree_update_get_open_buckets(struct btree_update *as, struct btree *b)
{
	while (b->ob.nr)
		as->open_buckets[as->nr_open_buckets++] =
			b->ob.v[--b->ob.nr];
}

static int bch2_btree_update_will_free_node_journal_pin_flush(struct journal *j,
				struct journal_entry_pin *_pin, u64 seq)
{
	return 0;
}

/*
 * @b is being split/rewritten: it may have pointers to not-yet-written btree
 * nodes and thus outstanding btree_updates - redirect @b's
 * btree_updates to point to this btree_update:
 */
static void bch2_btree_interior_update_will_free_node(struct btree_update *as,
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

	clear_btree_node_dirty_acct(c, b);
	clear_btree_node_need_write(b);
	clear_btree_node_write_blocked(b);

	/*
	 * Does this node have unwritten data that has a pin on the journal?
	 *
	 * If so, transfer that pin to the btree_update operation -
	 * note that if we're freeing multiple nodes, we only need to keep the
	 * oldest pin of any of the nodes we're freeing. We'll release the pin
	 * when the new nodes are persistent and reachable on disk:
	 */
	w = btree_current_write(b);
	bch2_journal_pin_copy(&c->journal, &as->journal, &w->journal,
			      bch2_btree_update_will_free_node_journal_pin_flush);
	bch2_journal_pin_drop(&c->journal, &w->journal);

	w = btree_prev_write(b);
	bch2_journal_pin_copy(&c->journal, &as->journal, &w->journal,
			      bch2_btree_update_will_free_node_journal_pin_flush);
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

	btree_update_add_key(as, &as->old_keys, b);

	as->old_nodes[as->nr_old_nodes] = b;
	as->old_nodes_seq[as->nr_old_nodes] = b->data->keys.seq;
	as->nr_old_nodes++;
}

static void bch2_btree_update_done(struct btree_update *as, struct btree_trans *trans)
{
	struct bch_fs *c = as->c;
	u64 start_time = as->start_time;

	BUG_ON(as->mode == BTREE_UPDATE_none);

	if (as->took_gc_lock)
		up_read(&as->c->gc_lock);
	as->took_gc_lock = false;

	bch2_btree_reserve_put(as, trans);

	continue_at(&as->cl, btree_update_set_nodes_written,
		    as->c->btree_interior_update_worker);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_interior_update_foreground],
			       start_time);
}

static const char * const btree_node_reawrite_reason_strs[] = {
#define x(n)	#n,
	BTREE_NODE_REWRITE_REASON()
#undef x
	NULL,
};

static struct btree_update *
bch2_btree_update_start(struct btree_trans *trans, struct btree_path *path,
			unsigned level_start, bool split,
			unsigned target,
			enum bch_trans_commit_flags flags)
{
	struct bch_fs *c = trans->c;
	struct btree_update *as;
	u64 start_time = local_clock();
	int disk_res_flags = (flags & BCH_TRANS_COMMIT_no_enospc)
		? BCH_DISK_RESERVATION_NOFAIL : 0;
	unsigned nr_nodes[2] = { 0, 0 };
	unsigned level_end = level_start;
	enum bch_watermark watermark = flags & BCH_WATERMARK_MASK;
	int ret = 0;
	u32 restart_count = trans->restart_count;

	BUG_ON(!path->should_be_locked);

	if (watermark == BCH_WATERMARK_copygc)
		watermark = BCH_WATERMARK_btree_copygc;
	if (watermark < BCH_WATERMARK_btree)
		watermark = BCH_WATERMARK_btree;

	flags &= ~BCH_WATERMARK_MASK;
	flags |= watermark;

	if (watermark < BCH_WATERMARK_reclaim &&
	    test_bit(JOURNAL_space_low, &c->journal.flags)) {
		if (flags & BCH_TRANS_COMMIT_journal_reclaim)
			return ERR_PTR(-BCH_ERR_journal_reclaim_would_deadlock);

		ret = drop_locks_do(trans,
			({ wait_event(c->journal.wait, !test_bit(JOURNAL_space_low, &c->journal.flags)); 0; }));
		if (ret)
			return ERR_PTR(ret);
	}

	while (1) {
		nr_nodes[!!level_end] += 1 + split;
		level_end++;

		ret = bch2_btree_path_upgrade(trans, path, level_end + 1);
		if (ret)
			return ERR_PTR(ret);

		if (!btree_path_node(path, level_end)) {
			/* Allocating new root? */
			nr_nodes[1] += split;
			level_end = BTREE_MAX_DEPTH;
			break;
		}

		/*
		 * Always check for space for two keys, even if we won't have to
		 * split at prior level - it might have been a merge instead:
		 */
		if (bch2_btree_node_insert_fits(path->l[level_end].b,
						BKEY_BTREE_PTR_U64s_MAX * 2))
			break;

		split = path->l[level_end].b->nr.live_u64s > BTREE_SPLIT_THRESHOLD(c);
	}

	if (!down_read_trylock(&c->gc_lock)) {
		ret = drop_locks_do(trans, (down_read(&c->gc_lock), 0));
		if (ret) {
			up_read(&c->gc_lock);
			return ERR_PTR(ret);
		}
	}

	as = mempool_alloc(&c->btree_interior_update_pool, GFP_NOFS);
	memset(as, 0, sizeof(*as));
	closure_init(&as->cl, NULL);
	as->c			= c;
	as->start_time		= start_time;
	as->ip_started		= _RET_IP_;
	as->mode		= BTREE_UPDATE_none;
	as->flags		= flags;
	as->took_gc_lock	= true;
	as->btree_id		= path->btree_id;
	as->update_level_start	= level_start;
	as->update_level_end	= level_end;
	INIT_LIST_HEAD(&as->list);
	INIT_LIST_HEAD(&as->unwritten_list);
	INIT_LIST_HEAD(&as->write_blocked_list);
	bch2_keylist_init(&as->old_keys, as->_old_keys);
	bch2_keylist_init(&as->new_keys, as->_new_keys);
	bch2_keylist_init(&as->parent_keys, as->inline_keys);

	scoped_guard(mutex, &c->btree_interior_update_lock)
		list_add_tail(&as->list, &c->btree_interior_update_list);

	struct btree *b = btree_path_node(path, path->level);
	as->node_start	= b->data->min_key;
	as->node_end	= b->data->max_key;
	as->node_needed_rewrite = btree_node_rewrite_reason(b);
	as->node_written = b->written;
	as->node_sectors = btree_buf_bytes(b) >> 9;
	as->node_remaining = __bch2_btree_u64s_remaining(b,
				btree_bkey_last(b, bset_tree_last(b)));

	/*
	 * We don't want to allocate if we're in an error state, that can cause
	 * deadlock on emergency shutdown due to open buckets getting stuck in
	 * the btree_reserve_cache after allocator shutdown has cleared it out.
	 * This check needs to come after adding us to the btree_interior_update
	 * list but before calling bch2_btree_reserve_get, to synchronize with
	 * __bch2_fs_read_only().
	 */
	ret = bch2_journal_error(&c->journal);
	if (ret)
		goto err;

	ret = bch2_disk_reservation_get(c, &as->disk_res,
			(nr_nodes[0] + nr_nodes[1]) * btree_sectors(c),
			READ_ONCE(c->opts.metadata_replicas),
			disk_res_flags);
	if (ret)
		goto err;

	ret = bch2_btree_reserve_get(trans, as, nr_nodes, target, flags, NULL);
	if (bch2_err_matches(ret, ENOSPC) ||
	    bch2_err_matches(ret, ENOMEM)) {
		struct closure cl;

		/*
		 * XXX: this should probably be a separate BTREE_INSERT_NONBLOCK
		 * flag
		 */
		if (bch2_err_matches(ret, ENOSPC) &&
		    (flags & BCH_TRANS_COMMIT_journal_reclaim) &&
		    watermark < BCH_WATERMARK_reclaim) {
			ret = bch_err_throw(c, journal_reclaim_would_deadlock);
			goto err;
		}

		closure_init_stack(&cl);

		do {
			ret = bch2_btree_reserve_get(trans, as, nr_nodes, target, flags, &cl);
			if (!bch2_err_matches(ret, BCH_ERR_operation_blocked))
				break;
			bch2_trans_unlock(trans);
			bch2_wait_on_allocator(c, &cl);
		} while (1);
	}

	if (ret) {
		trace_and_count(c, btree_reserve_get_fail, trans->fn,
				_RET_IP_, nr_nodes[0] + nr_nodes[1], ret);
		goto err;
	}

	ret = bch2_trans_relock(trans);
	if (ret)
		goto err;

	bch2_trans_verify_not_restarted(trans, restart_count);
	return as;
err:
	bch2_btree_update_free(as, trans);
	if (!bch2_err_matches(ret, ENOSPC) &&
	    !bch2_err_matches(ret, EROFS) &&
	    ret != -BCH_ERR_journal_reclaim_would_deadlock &&
	    ret != -BCH_ERR_journal_shutdown)
		bch_err_fn_ratelimited(c, ret);
	return ERR_PTR(ret);
}

/* Btree root updates: */

static void bch2_btree_set_root_inmem(struct bch_fs *c, struct btree *b)
{
	/* Root nodes cannot be reaped */
	scoped_guard(mutex, &c->btree_cache.lock)
		list_del_init(&b->list);

	scoped_guard(mutex, &c->btree_root_lock)
		bch2_btree_id_root(c, b->c.btree_id)->b = b;

	bch2_recalc_btree_reserve(c);
}

static int bch2_btree_set_root(struct btree_update *as,
			       struct btree_trans *trans,
			       struct btree_path *path,
			       struct btree *b,
			       bool nofail)
{
	struct bch_fs *c = as->c;

	trace_btree_node(c, b, btree_node_set_root);

	struct btree *old = btree_node_root(c, b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	if (nofail) {
		bch2_btree_node_lock_write_nofail(trans, path, &old->c);
	} else {
		int ret = bch2_btree_node_lock_write(trans, path, &old->c);
		if (ret)
			return ret;
	}

	bch2_btree_set_root_inmem(c, b);

	btree_update_updated_root(as, b);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	bch2_btree_node_unlock_write(trans, path, old);
	return 0;
}

/* Interior node updates: */

static void bch2_insert_fixup_btree_ptr(struct btree_update *as,
					struct btree_trans *trans,
					struct btree_path *path,
					struct btree *b,
					struct btree_node_iter *node_iter,
					struct bkey_i *insert)
{
	struct bch_fs *c = as->c;
	struct bkey_packed *k;
	CLASS(printbuf, buf)();
	unsigned long old, new;

	BUG_ON(insert->k.type == KEY_TYPE_btree_ptr_v2 &&
	       !btree_ptr_sectors_written(bkey_i_to_s_c(insert)));

	if (unlikely(!test_bit(JOURNAL_replay_done, &c->journal.flags)))
		bch2_journal_key_overwritten(c, b->c.btree_id, b->c.level, insert->k.p);

	struct bkey_validate_context from = (struct bkey_validate_context) {
		.from	= BKEY_VALIDATE_btree_node,
		.level	= b->c.level,
		.btree	= b->c.btree_id,
		.flags	= BCH_VALIDATE_commit,
	};
	if (bch2_bkey_validate(c, bkey_i_to_s_c(insert), from) ?:
	    bch2_bkey_in_btree_node(c, b, bkey_i_to_s_c(insert), from)) {
		bch2_fs_inconsistent(c, "%s: inserting invalid bkey", __func__);
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

	bch2_btree_bset_insert_key(trans, path, b, node_iter, insert);
	set_btree_node_dirty_acct(c, b);

	old = READ_ONCE(b->flags);
	do {
		new = old;

		new &= ~BTREE_WRITE_TYPE_MASK;
		new |= BTREE_WRITE_interior;
		new |= 1 << BTREE_NODE_need_write;
	} while (!try_cmpxchg(&b->flags, &old, new));
}

static int
bch2_btree_insert_keys_interior(struct btree_update *as,
				struct btree_trans *trans,
				struct btree_path *path,
				struct btree *b,
				struct btree_node_iter node_iter,
				struct keylist *keys)
{
	struct bkey_i *insert = bch2_keylist_front(keys);
	struct bkey_packed *k;

	BUG_ON(btree_node_type(b) != BKEY_TYPE_btree);

	while ((k = bch2_btree_node_iter_prev_all(&node_iter, b)) &&
	       (bkey_cmp_left_packed(b, k, &insert->k.p) >= 0))
		;

	for (;
	     insert != keys->top && bpos_le(insert->k.p, b->key.k.p);
	     insert = bkey_next(insert))
		bch2_insert_fixup_btree_ptr(as, trans, path, b, &node_iter, insert);

	int ret = bch2_btree_node_check_topology(trans, b);
	if (ret) {
		CLASS(printbuf, buf)();

		for (struct bkey_i *k = keys->keys;
		     k != insert;
		     k = bkey_next(k)) {
			bch2_bkey_val_to_text(&buf, trans->c, bkey_i_to_s_c(k));
			prt_newline(&buf);
		}

		bch2_fs_fatal_error(as->c, "%ps -> %s(): check_topology error %s: inserted keys\n%s",
				    (void *) _RET_IP_, __func__, bch2_err_str(ret), buf.buf);
		dump_stack();
		return ret;
	}

	memmove_u64s_down(keys->keys, insert, keys->top_p - insert->_data);
	keys->top_p -= insert->_data - keys->keys_p;
	return 0;
}

static bool key_deleted_in_insert(struct keylist *insert_keys, struct bpos pos)
{
	if (insert_keys)
		for_each_keylist_key(insert_keys, k)
			if (bkey_deleted(&k->k) && bpos_eq(k->k.p, pos))
				return true;
	return false;
}

/*
 * Move keys from n1 (original replacement node, now lower node) to n2 (higher
 * node)
 */
static void __btree_split_node(struct btree_update *as,
			       struct btree_trans *trans,
			       struct btree *b,
			       struct btree *n[2],
			       struct keylist *insert_keys)
{
	struct bkey_packed *k;
	struct bpos n1_pos = POS_MIN;
	struct btree_node_iter iter;
	struct bset *bsets[2];
	struct bkey_format_state format[2];
	struct bkey_packed *out[2];
	struct bkey uk;
	unsigned u64s, n1_u64s = (b->nr.live_u64s * 3) / 5;
	struct { unsigned nr_keys, val_u64s; } nr_keys[2];
	int i;

	memset(&nr_keys, 0, sizeof(nr_keys));

	for (i = 0; i < 2; i++) {
		BUG_ON(n[i]->nsets != 1);

		bsets[i] = btree_bset_first(n[i]);
		out[i] = bsets[i]->start;

		SET_BTREE_NODE_SEQ(n[i]->data, BTREE_NODE_SEQ(b->data) + 1);
		bch2_bkey_format_init(&format[i]);
	}

	u64s = 0;
	for_each_btree_node_key(b, k, &iter) {
		if (bkey_deleted(k))
			continue;

		uk = bkey_unpack_key(b, k);

		if (b->c.level &&
		    u64s < n1_u64s &&
		    u64s + k->u64s >= n1_u64s &&
		    (bch2_key_deleted_in_journal(trans, b->c.btree_id, b->c.level, uk.p) ||
		     key_deleted_in_insert(insert_keys, uk.p)))
			n1_u64s += k->u64s;

		i = u64s >= n1_u64s;
		u64s += k->u64s;
		if (!i)
			n1_pos = uk.p;
		bch2_bkey_format_add_key(&format[i], &uk);

		nr_keys[i].nr_keys++;
		nr_keys[i].val_u64s += bkeyp_val_u64s(&b->format, k);
	}

	btree_set_min(n[0], b->data->min_key);
	btree_set_max(n[0], n1_pos);
	btree_set_min(n[1], bpos_successor(n1_pos));
	btree_set_max(n[1], b->data->max_key);

	for (i = 0; i < 2; i++) {
		bch2_bkey_format_add_pos(&format[i], n[i]->data->min_key);
		bch2_bkey_format_add_pos(&format[i], n[i]->data->max_key);

		n[i]->data->format = bch2_bkey_format_done(&format[i]);

		unsigned u64s = nr_keys[i].nr_keys * n[i]->data->format.key_u64s +
			nr_keys[i].val_u64s;
		if (__vstruct_bytes(struct btree_node, u64s) > btree_buf_bytes(b))
			n[i]->data->format = b->format;

		btree_node_set_format(n[i], n[i]->data->format);
	}

	u64s = 0;
	for_each_btree_node_key(b, k, &iter) {
		if (bkey_deleted(k))
			continue;

		i = u64s >= n1_u64s;
		u64s += k->u64s;

		if (bch2_bkey_transform(&n[i]->format, out[i], bkey_packed(k)
					? &b->format: &bch2_bkey_format_current, k))
			out[i]->format = KEY_FORMAT_LOCAL_BTREE;
		else
			bch2_bkey_unpack(b, (void *) out[i], k);

		out[i]->needs_whiteout = false;

		btree_keys_account_key_add(&n[i]->nr, 0, out[i]);
		out[i] = bkey_p_next(out[i]);
	}

	for (i = 0; i < 2; i++) {
		bsets[i]->u64s = cpu_to_le16((u64 *) out[i] - bsets[i]->_data);

		BUG_ON(!bsets[i]->u64s);

		set_btree_bset_end(n[i], n[i]->set);

		btree_node_reset_sib_u64s(n[i]);

		bch2_verify_btree_nr_keys(n[i]);

		BUG_ON(bch2_btree_node_check_topology(trans, n[i]));
	}
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
static int btree_split_insert_keys(struct btree_update *as,
				   struct btree_trans *trans,
				   btree_path_idx_t path_idx,
				   struct btree *b,
				   struct keylist *keys)
{
	struct btree_path *path = trans->paths + path_idx;

	if (!bch2_keylist_empty(keys) &&
	    bpos_le(bch2_keylist_front(keys)->k.p, b->data->max_key)) {
		struct btree_node_iter node_iter;

		bch2_btree_node_iter_init(&node_iter, b, &bch2_keylist_front(keys)->k.p);

		int ret = bch2_btree_insert_keys_interior(as, trans, path, b, node_iter, keys);
		if (ret)
			return ret;
	}

	return 0;
}

static int btree_split(struct btree_update *as, struct btree_trans *trans,
		       btree_path_idx_t path, struct btree *b,
		       struct keylist *keys)
{
	struct bch_fs *c = as->c;
	struct btree *parent = btree_node_parent(trans->paths + path, b);
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	btree_path_idx_t path1 = 0, path2 = 0;
	u64 start_time = local_clock();
	int ret = 0;

	bch2_verify_btree_nr_keys(b);
	BUG_ON(!parent && (b != btree_node_root(c, b)));
	BUG_ON(parent && !btree_node_intent_locked(trans->paths + path, b->c.level + 1));

	ret = bch2_btree_node_check_topology(trans, b);
	if (ret)
		return ret;

	if (b->nr.live_u64s > BTREE_SPLIT_THRESHOLD(c)) {
		struct btree *n[2];

		trace_btree_node(c, b, btree_node_split);

		n[0] = n1 = bch2_btree_node_alloc(as, trans, b->c.level);
		n[1] = n2 = bch2_btree_node_alloc(as, trans, b->c.level);

		__btree_split_node(as, trans, b, n, keys);

		if (keys) {
			ret =   btree_split_insert_keys(as, trans, path, n1, keys) ?:
				btree_split_insert_keys(as, trans, path, n2, keys);
			if (ret)
				goto err;
			BUG_ON(!bch2_keylist_empty(keys));
		}

		bch2_btree_build_aux_trees(n2);
		bch2_btree_build_aux_trees(n1);

		bch2_btree_update_add_new_node(as, n1);
		bch2_btree_update_add_new_node(as, n2);
		six_unlock_write(&n2->c.lock);
		six_unlock_write(&n1->c.lock);

		path1 = bch2_path_get_unlocked_mut(trans, as->btree_id, n1->c.level, n1->key.k.p);
		six_lock_increment(&n1->c.lock, SIX_LOCK_intent);
		mark_btree_node_locked(trans, trans->paths + path1, n1->c.level, BTREE_NODE_INTENT_LOCKED);
		bch2_btree_path_level_init(trans, trans->paths + path1, n1);

		path2 = bch2_path_get_unlocked_mut(trans, as->btree_id, n2->c.level, n2->key.k.p);
		six_lock_increment(&n2->c.lock, SIX_LOCK_intent);
		mark_btree_node_locked(trans, trans->paths + path2, n2->c.level, BTREE_NODE_INTENT_LOCKED);
		bch2_btree_path_level_init(trans, trans->paths + path2, n2);

		/*
		 * Note that on recursive parent_keys == keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		bch2_keylist_add(&as->parent_keys, &n1->key);
		bch2_keylist_add(&as->parent_keys, &n2->key);

		if (!parent) {
			/* Depth increases, make a new root */
			n3 = __btree_root_alloc(as, trans, b->c.level + 1);

			bch2_btree_update_add_new_node(as, n3);
			six_unlock_write(&n3->c.lock);

			trans->paths[path2].locks_want++;
			BUG_ON(btree_node_locked(trans->paths + path2, n3->c.level));
			six_lock_increment(&n3->c.lock, SIX_LOCK_intent);
			mark_btree_node_locked(trans, trans->paths + path2, n3->c.level, BTREE_NODE_INTENT_LOCKED);
			bch2_btree_path_level_init(trans, trans->paths + path2, n3);

			n3->sib_u64s[0] = U16_MAX;
			n3->sib_u64s[1] = U16_MAX;

			ret = btree_split_insert_keys(as, trans, path, n3, &as->parent_keys);
			if (ret)
				goto err;
		}
	} else {
		trace_btree_node(c, b, btree_node_compact);

		n1 = bch2_btree_node_alloc_replacement(as, trans, b);

		if (keys) {
			ret = btree_split_insert_keys(as, trans, path, n1, keys);
			if (ret)
				goto err;
			BUG_ON(!bch2_keylist_empty(keys));
		}

		bch2_btree_build_aux_trees(n1);
		bch2_btree_update_add_new_node(as, n1);
		six_unlock_write(&n1->c.lock);

		path1 = bch2_path_get_unlocked_mut(trans, as->btree_id, n1->c.level, n1->key.k.p);
		six_lock_increment(&n1->c.lock, SIX_LOCK_intent);
		mark_btree_node_locked(trans, trans->paths + path1, n1->c.level, BTREE_NODE_INTENT_LOCKED);
		bch2_btree_path_level_init(trans, trans->paths + path1, n1);

		if (parent)
			bch2_keylist_add(&as->parent_keys, &n1->key);
	}

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		ret = bch2_btree_insert_node(as, trans, path, parent, &as->parent_keys);
	} else if (n3) {
		ret = bch2_btree_set_root(as, trans, trans->paths + path, n3, false);
	} else {
		/* Root filled up but didn't need to be split */
		ret = bch2_btree_set_root(as, trans, trans->paths + path, n1, false);
	}

	if (ret)
		goto err;

	bch2_btree_interior_update_will_free_node(as, b);

	if (n3) {
		bch2_btree_update_get_open_buckets(as, n3);
		bch2_btree_node_write_trans(trans, n3, SIX_LOCK_intent, 0);
	}
	if (n2) {
		bch2_btree_update_get_open_buckets(as, n2);
		bch2_btree_node_write_trans(trans, n2, SIX_LOCK_intent, 0);
	}
	bch2_btree_update_get_open_buckets(as, n1);
	bch2_btree_node_write_trans(trans, n1, SIX_LOCK_intent, 0);

	/*
	 * The old node must be freed (in memory) _before_ unlocking the new
	 * nodes - else another thread could re-acquire a read lock on the old
	 * node after another thread has locked and updated the new node, thus
	 * seeing stale data:
	 */
	bch2_btree_node_free_inmem(trans, trans->paths + path, b);

	if (n3)
		bch2_trans_node_add(trans, trans->paths + path, n3);
	if (n2)
		bch2_trans_node_add(trans, trans->paths + path2, n2);
	bch2_trans_node_add(trans, trans->paths + path1, n1);

	if (n3)
		six_unlock_intent(&n3->c.lock);
	if (n2)
		six_unlock_intent(&n2->c.lock);
	six_unlock_intent(&n1->c.lock);
out:
	if (path2) {
		__bch2_btree_path_unlock(trans, trans->paths + path2);
		bch2_path_put(trans, path2, true);
	}
	if (path1) {
		__bch2_btree_path_unlock(trans, trans->paths + path1);
		bch2_path_put(trans, path1, true);
	}

	bch2_trans_verify_locks(trans);

	bch2_time_stats_update(&c->times[n2
			       ? BCH_TIME_btree_node_split
			       : BCH_TIME_btree_node_compact],
			       start_time);
	return ret;
err:
	if (n3)
		bch2_btree_node_free_never_used(as, trans, n3);
	if (n2)
		bch2_btree_node_free_never_used(as, trans, n2);
	bch2_btree_node_free_never_used(as, trans, n1);
	goto out;
}

/**
 * bch2_btree_insert_node - insert bkeys into a given btree node
 *
 * @as:			btree_update object
 * @trans:		btree_trans object
 * @path_idx:		path that points to current node
 * @b:			node to insert keys into
 * @keys:		list of keys to insert
 *
 * Returns: 0 on success, typically transaction restart error on failure
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
static int bch2_btree_insert_node(struct btree_update *as, struct btree_trans *trans,
				  btree_path_idx_t path_idx, struct btree *b,
				  struct keylist *keys)
{
	struct bch_fs *c = as->c;
	struct btree_path *path = trans->paths + path_idx, *linked;
	unsigned i;
	int old_u64s = le16_to_cpu(btree_bset_last(b)->u64s);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;
	int ret;

	lockdep_assert_held(&c->gc_lock);
	BUG_ON(!b->c.level);
	BUG_ON(!as || as->b);
	bch2_verify_keylist_sorted(keys);

	if (!btree_node_intent_locked(path, b->c.level)) {
		CLASS(printbuf, buf)();
		bch2_log_msg_start(c, &buf);
		prt_printf(&buf, "%s(): node not locked at level %u\n",
			   __func__, b->c.level);
		bch2_btree_update_to_text(&buf, as);
		bch2_btree_path_to_text(&buf, trans, path_idx);
		bch2_fs_emergency_read_only2(c, &buf);

		bch2_print_str(c, KERN_ERR, buf.buf);
		return -EIO;
	}

	ret = bch2_btree_node_lock_write(trans, path, &b->c);
	if (ret)
		return ret;

	bch2_btree_node_prep_for_write(trans, path, b);

	if (!bch2_btree_node_insert_fits(b, bch2_keylist_u64s(keys))) {
		bch2_btree_node_unlock_write(trans, path, b);
		goto split;
	}


	ret =   bch2_btree_node_check_topology(trans, b) ?:
		bch2_btree_insert_keys_interior(as, trans, path, b,
					path->l[b->c.level].iter, keys);
	if (ret) {
		bch2_btree_node_unlock_write(trans, path, b);
		return ret;
	}

	trans_for_each_path_with_node(trans, b, linked, i)
		bch2_btree_node_iter_peek(&linked->l[b->c.level].iter, b);

	bch2_trans_verify_paths(trans);

	live_u64s_added = (int) b->nr.live_u64s - old_live_u64s;
	u64s_added = (int) le16_to_cpu(btree_bset_last(b)->u64s) - old_u64s;

	if (b->sib_u64s[0] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[0] = max(0, (int) b->sib_u64s[0] + live_u64s_added);
	if (b->sib_u64s[1] != U16_MAX && live_u64s_added < 0)
		b->sib_u64s[1] = max(0, (int) b->sib_u64s[1] + live_u64s_added);

	if (u64s_added > live_u64s_added &&
	    bch2_maybe_compact_whiteouts(c, b))
		bch2_trans_node_reinit_iter(trans, b);

	btree_update_updated_node(as, b);
	bch2_btree_node_unlock_write(trans, path, b);
	return 0;
split:
	/*
	 * We could attempt to avoid the transaction restart, by calling
	 * bch2_btree_path_upgrade() and allocating more nodes:
	 */
	if (b->c.level >= as->update_level_end) {
		trace_and_count(c, trans_restart_split_race, trans, _THIS_IP_, b);
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_split_race);
	}

	return btree_split(as, trans, path_idx, b, keys);
}

int bch2_btree_split_leaf(struct btree_trans *trans,
			  btree_path_idx_t path,
			  unsigned flags)
{
	/* btree_split & merge may both cause paths array to be reallocated */
	struct btree *b = path_l(trans->paths + path)->b;
	struct btree_update *as;
	unsigned l;
	int ret = 0;

	as = bch2_btree_update_start(trans, trans->paths + path,
				     trans->paths[path].level,
				     true, 0, flags);
	if (IS_ERR(as))
		return PTR_ERR(as);

	ret = btree_split(as, trans, path, b, NULL);
	if (ret) {
		bch2_btree_update_free(as, trans);
		return ret;
	}

	bch2_btree_update_done(as, trans);

	for (l = trans->paths[path].level + 1;
	     btree_node_intent_locked(&trans->paths[path], l) && !ret;
	     l++)
		ret = bch2_foreground_maybe_merge(trans, path, l, flags);

	return ret;
}

static void __btree_increase_depth(struct btree_update *as, struct btree_trans *trans,
				   btree_path_idx_t path_idx)
{
	struct bch_fs *c = as->c;
	struct btree_path *path = trans->paths + path_idx;
	struct btree *n, *b = bch2_btree_id_root(c, path->btree_id)->b;

	BUG_ON(!btree_node_locked(path, b->c.level));

	n = __btree_root_alloc(as, trans, b->c.level + 1);

	bch2_btree_update_add_new_node(as, n);
	six_unlock_write(&n->c.lock);

	path->locks_want++;
	BUG_ON(btree_node_locked(path, n->c.level));
	six_lock_increment(&n->c.lock, SIX_LOCK_intent);
	mark_btree_node_locked(trans, path, n->c.level, BTREE_NODE_INTENT_LOCKED);
	bch2_btree_path_level_init(trans, path, n);

	n->sib_u64s[0] = U16_MAX;
	n->sib_u64s[1] = U16_MAX;

	bch2_keylist_add(&as->parent_keys, &b->key);
	btree_split_insert_keys(as, trans, path_idx, n, &as->parent_keys);

	int ret = bch2_btree_set_root(as, trans, path, n, true);
	BUG_ON(ret);

	bch2_btree_update_get_open_buckets(as, n);
	bch2_btree_node_write_trans(trans, n, SIX_LOCK_intent, 0);
	bch2_trans_node_add(trans, path, n);
	six_unlock_intent(&n->c.lock);

	scoped_guard(mutex, &c->btree_cache.lock)
		list_add_tail(&b->list, &c->btree_cache.live[btree_node_pinned(b)].list);

	bch2_trans_verify_locks(trans);
}

int bch2_btree_increase_depth(struct btree_trans *trans, btree_path_idx_t path, unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct btree *b = bch2_btree_id_root(c, trans->paths[path].btree_id)->b;

	if (btree_node_fake(b))
		return bch2_btree_split_leaf(trans, path, flags);

	struct btree_update *as =
		bch2_btree_update_start(trans, trans->paths + path, b->c.level,
					true, 0, flags);
	if (IS_ERR(as))
		return PTR_ERR(as);

	__btree_increase_depth(as, trans, path);
	bch2_btree_update_done(as, trans);
	return 0;
}

int __bch2_foreground_maybe_merge(struct btree_trans *trans,
				  btree_path_idx_t path,
				  unsigned level,
				  unsigned flags,
				  enum btree_node_sibling sib)
{
	struct bch_fs *c = trans->c;
	struct btree_update *as;
	struct bkey_format_state new_s;
	struct bkey_format new_f;
	struct bkey_i delete;
	struct btree *b, *m, *n, *prev, *next, *parent;
	struct bpos sib_pos;
	size_t sib_u64s;
	enum btree_id btree = trans->paths[path].btree_id;
	btree_path_idx_t sib_path = 0, new_path = 0;
	u64 start_time = local_clock();
	int ret = 0;

	bch2_trans_verify_not_unlocked_or_in_restart(trans);
	BUG_ON(!trans->paths[path].should_be_locked);
	BUG_ON(!btree_node_locked(&trans->paths[path], level));

	/*
	 * Work around a deadlock caused by the btree write buffer not doing
	 * merges and leaving tons of merges for us to do - we really don't need
	 * to be doing merges at all from the interior update path, and if the
	 * interior update path is generating too many new interior updates we
	 * deadlock:
	 */
	if ((flags & BCH_WATERMARK_MASK) == BCH_WATERMARK_interior_updates)
		return 0;

	if ((flags & BCH_WATERMARK_MASK) <= BCH_WATERMARK_reclaim) {
		flags &= ~BCH_WATERMARK_MASK;
		flags |= BCH_WATERMARK_btree;
		flags |= BCH_TRANS_COMMIT_journal_reclaim;
	}

	b = trans->paths[path].l[level].b;

	if ((sib == btree_prev_sib && bpos_eq(b->data->min_key, POS_MIN)) ||
	    (sib == btree_next_sib && bpos_eq(b->data->max_key, SPOS_MAX))) {
		b->sib_u64s[sib] = U16_MAX;
		return 0;
	}

	sib_pos = sib == btree_prev_sib
		? bpos_predecessor(b->data->min_key)
		: bpos_successor(b->data->max_key);

	sib_path = bch2_path_get(trans, btree, sib_pos,
				 U8_MAX, level, BTREE_ITER_intent, _THIS_IP_);
	ret = bch2_btree_path_traverse(trans, sib_path, false);
	if (ret)
		goto err;

	btree_path_set_should_be_locked(trans, trans->paths + sib_path);

	m = trans->paths[sib_path].l[level].b;

	if (btree_node_parent(trans->paths + path, b) !=
	    btree_node_parent(trans->paths + sib_path, m)) {
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

	if (!bpos_eq(bpos_successor(prev->data->max_key), next->data->min_key)) {
		CLASS(printbuf, buf)();

		printbuf_indent_add_nextline(&buf, 2);
		prt_printf(&buf, "%s(): ", __func__);
		ret = __bch2_topology_error(c, &buf);
		prt_newline(&buf);

		prt_printf(&buf, "prev ends at   ");
		bch2_bpos_to_text(&buf, prev->data->max_key);
		prt_newline(&buf);

		prt_printf(&buf, "next starts at ");
		bch2_bpos_to_text(&buf, next->data->min_key);

		bch_err(c, "%s", buf.buf);
		goto err;
	}

	bch2_bkey_format_init(&new_s);
	bch2_bkey_format_add_pos(&new_s, prev->data->min_key);
	__bch2_btree_calc_format(&new_s, prev);
	__bch2_btree_calc_format(&new_s, next);
	bch2_bkey_format_add_pos(&new_s, next->data->max_key);
	new_f = bch2_bkey_format_done(&new_s);

	sib_u64s = btree_node_u64s_with_format(b->nr, &b->format, &new_f) +
		btree_node_u64s_with_format(m->nr, &m->format, &new_f);

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

	parent = btree_node_parent(trans->paths + path, b);
	as = bch2_btree_update_start(trans, trans->paths + path, level, false,
				     0, BCH_TRANS_COMMIT_no_enospc|flags);
	ret = PTR_ERR_OR_ZERO(as);
	if (ret)
		goto err;

	as->node_start	= prev->data->min_key;
	as->node_end	= next->data->max_key;

	trace_btree_node(c, b, btree_node_merge);

	n = bch2_btree_node_alloc(as, trans, b->c.level);

	SET_BTREE_NODE_SEQ(n->data,
			   max(BTREE_NODE_SEQ(b->data),
			       BTREE_NODE_SEQ(m->data)) + 1);

	btree_set_min(n, prev->data->min_key);
	btree_set_max(n, next->data->max_key);

	n->data->format	 = new_f;
	btree_node_set_format(n, new_f);

	bch2_btree_sort_into(c, n, prev);
	bch2_btree_sort_into(c, n, next);

	bch2_btree_build_aux_trees(n);
	bch2_btree_update_add_new_node(as, n);
	six_unlock_write(&n->c.lock);

	new_path = bch2_path_get_unlocked_mut(trans, btree, n->c.level, n->key.k.p);
	six_lock_increment(&n->c.lock, SIX_LOCK_intent);
	mark_btree_node_locked(trans, trans->paths + new_path, n->c.level, BTREE_NODE_INTENT_LOCKED);
	bch2_btree_path_level_init(trans, trans->paths + new_path, n);

	bkey_init(&delete.k);
	delete.k.p = prev->key.k.p;
	bch2_keylist_add(&as->parent_keys, &delete);
	bch2_keylist_add(&as->parent_keys, &n->key);

	bch2_trans_verify_paths(trans);

	ret = bch2_btree_insert_node(as, trans, path, parent, &as->parent_keys);
	if (ret)
		goto err_free_update;

	bch2_btree_interior_update_will_free_node(as, b);
	bch2_btree_interior_update_will_free_node(as, m);

	bch2_trans_verify_paths(trans);

	bch2_btree_update_get_open_buckets(as, n);
	bch2_btree_node_write_trans(trans, n, SIX_LOCK_intent, 0);

	bch2_btree_node_free_inmem(trans, trans->paths + path, b);
	bch2_btree_node_free_inmem(trans, trans->paths + sib_path, m);

	bch2_trans_node_add(trans, trans->paths + path, n);

	bch2_trans_verify_paths(trans);

	six_unlock_intent(&n->c.lock);

	bch2_btree_update_done(as, trans);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_merge], start_time);
out:
err:
	if (new_path)
		bch2_path_put(trans, new_path, true);
	bch2_path_put(trans, sib_path, true);
	bch2_trans_verify_locks(trans);
	if (ret == -BCH_ERR_journal_reclaim_would_deadlock)
		ret = 0;
	if (!ret)
		ret = bch2_trans_relock(trans);
	return ret;
err_free_update:
	bch2_btree_node_free_never_used(as, trans, n);
	bch2_btree_update_free(as, trans);
	goto out;
}

static int get_iter_to_node(struct btree_trans *trans, struct btree_iter *iter,
			    struct btree *b)
{
	bch2_trans_node_iter_init(trans, iter, b->c.btree_id, b->key.k.p,
				  BTREE_MAX_DEPTH, b->c.level,
				  BTREE_ITER_intent);
	int ret = bch2_btree_iter_traverse(trans, iter);
	if (ret)
		goto err;

	/* has node been freed? */
	if (btree_iter_path(trans, iter)->l[b->c.level].b != b) {
		/* node has been freed: */
		BUG_ON(!btree_node_dying(b));
		ret = bch_err_throw(trans->c, btree_node_dying);
		goto err;
	}

	BUG_ON(!btree_node_hashed(b));
	return 0;
err:
	bch2_trans_iter_exit(trans, iter);
	return ret;
}

int bch2_btree_node_rewrite(struct btree_trans *trans,
			    struct btree_iter *iter,
			    struct btree *b,
			    unsigned target,
			    enum bch_trans_commit_flags flags)
{
	struct bch_fs *c = trans->c;
	struct btree *n, *parent;
	struct btree_update *as;
	btree_path_idx_t new_path = 0;
	int ret;

	flags |= BCH_TRANS_COMMIT_no_enospc;

	struct btree_path *path = btree_iter_path(trans, iter);
	parent = btree_node_parent(path, b);
	as = bch2_btree_update_start(trans, path, b->c.level,
				     false, target, flags);
	ret = PTR_ERR_OR_ZERO(as);
	if (ret)
		goto out;

	n = bch2_btree_node_alloc_replacement(as, trans, b);

	bch2_btree_build_aux_trees(n);
	bch2_btree_update_add_new_node(as, n);
	six_unlock_write(&n->c.lock);

	new_path = bch2_path_get_unlocked_mut(trans, iter->btree_id, n->c.level, n->key.k.p);
	six_lock_increment(&n->c.lock, SIX_LOCK_intent);
	mark_btree_node_locked(trans, trans->paths + new_path, n->c.level, BTREE_NODE_INTENT_LOCKED);
	bch2_btree_path_level_init(trans, trans->paths + new_path, n);

	if (parent) {
		bch2_keylist_add(&as->parent_keys, &n->key);
		ret = bch2_btree_insert_node(as, trans, iter->path, parent, &as->parent_keys);
	} else {
		ret = bch2_btree_set_root(as, trans, btree_iter_path(trans, iter), n, false);
	}

	if (ret)
		goto err;

	trace_btree_node(c, b, btree_node_rewrite);

	bch2_btree_interior_update_will_free_node(as, b);

	bch2_btree_update_get_open_buckets(as, n);
	bch2_btree_node_write_trans(trans, n, SIX_LOCK_intent, 0);

	bch2_btree_node_free_inmem(trans, btree_iter_path(trans, iter), b);

	bch2_trans_node_add(trans, trans->paths + iter->path, n);
	six_unlock_intent(&n->c.lock);

	bch2_btree_update_done(as, trans);
out:
	if (new_path)
		bch2_path_put(trans, new_path, true);
	bch2_trans_downgrade(trans);
	return ret;
err:
	bch2_btree_node_free_never_used(as, trans, n);
	bch2_btree_update_free(as, trans);
	goto out;
}

int bch2_btree_node_rewrite_key(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bkey_i *k,
				enum bch_trans_commit_flags flags)
{
	struct btree_iter iter;
	bch2_trans_node_iter_init(trans, &iter,
				  btree, k->k.p,
				  BTREE_MAX_DEPTH, level, 0);
	struct btree *b = bch2_btree_iter_peek_node(trans, &iter);
	int ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		goto out;

	bool found = b && btree_ptr_hash_val(&b->key) == btree_ptr_hash_val(k);
	ret = found
		? bch2_btree_node_rewrite(trans, &iter, b, 0, flags)
		: -ENOENT;
out:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_btree_node_rewrite_pos(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bpos pos,
				unsigned target,
				enum bch_trans_commit_flags flags)
{
	BUG_ON(!level);

	/* Traverse one depth lower to get a pointer to the node itself: */
	struct btree_iter iter;
	bch2_trans_node_iter_init(trans, &iter, btree, pos, 0, level - 1, 0);
	struct btree *b = bch2_btree_iter_peek_node(trans, &iter);
	int ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		goto err;

	ret = bch2_btree_node_rewrite(trans, &iter, b, target, flags);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_btree_node_rewrite_key_get_iter(struct btree_trans *trans,
					 struct btree *b,
					 enum bch_trans_commit_flags flags)
{
	struct btree_iter iter;
	int ret = get_iter_to_node(trans, &iter, b);
	if (ret)
		return ret == -BCH_ERR_btree_node_dying ? 0 : ret;

	ret = bch2_btree_node_rewrite(trans, &iter, b, 0, flags);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

struct async_btree_rewrite {
	struct bch_fs		*c;
	struct work_struct	work;
	struct list_head	list;
	enum btree_id		btree_id;
	unsigned		level;
	struct bkey_buf		key;
};

static void async_btree_node_rewrite_work(struct work_struct *work)
{
	struct async_btree_rewrite *a =
		container_of(work, struct async_btree_rewrite, work);
	struct bch_fs *c = a->c;

	int ret = bch2_trans_do(c, bch2_btree_node_rewrite_key(trans,
						a->btree_id, a->level, a->key.k, 0));
	if (!bch2_err_matches(ret, ENOENT) &&
	    !bch2_err_matches(ret, EROFS))
		bch_err_fn_ratelimited(c, ret);

	scoped_guard(spinlock, &c->btree_node_rewrites_lock)
		list_del(&a->list);

	closure_wake_up(&c->btree_node_rewrites_wait);

	bch2_bkey_buf_exit(&a->key, c);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_node_rewrite);
	kfree(a);
}

void bch2_btree_node_rewrite_async(struct bch_fs *c, struct btree *b)
{
	struct async_btree_rewrite *a = kmalloc(sizeof(*a), GFP_NOFS);
	if (!a)
		return;

	a->c		= c;
	a->btree_id	= b->c.btree_id;
	a->level	= b->c.level;
	INIT_WORK(&a->work, async_btree_node_rewrite_work);

	bch2_bkey_buf_init(&a->key);
	bch2_bkey_buf_copy(&a->key, c, &b->key);

	bool now = false, pending = false;

	scoped_guard(spinlock, &c->btree_node_rewrites_lock) {
		if (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_journal_replay) &&
		    enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_node_rewrite)) {
			list_add(&a->list, &c->btree_node_rewrites);
			now = true;
		} else if (!test_bit(BCH_FS_may_go_rw, &c->flags)) {
			list_add(&a->list, &c->btree_node_rewrites_pending);
			pending = true;
		}
	}

	if (now) {
		queue_work(c->btree_node_rewrite_worker, &a->work);
	} else if (pending) {
		/* bch2_do_pending_node_rewrites will execute */
	} else {
		bch2_bkey_buf_exit(&a->key, c);
		kfree(a);
	}
}

void bch2_async_btree_node_rewrites_flush(struct bch_fs *c)
{
	closure_wait_event(&c->btree_node_rewrites_wait,
			   list_empty(&c->btree_node_rewrites));
}

void bch2_do_pending_node_rewrites(struct bch_fs *c)
{
	while (1) {
		struct async_btree_rewrite *a;

		scoped_guard(spinlock, &c->btree_node_rewrites_lock) {
			a = list_pop_entry(&c->btree_node_rewrites_pending,
					   struct async_btree_rewrite, list);
			if (a)
				list_add(&a->list, &c->btree_node_rewrites);
		}

		if (!a)
			break;

		enumerated_ref_get(&c->writes, BCH_WRITE_REF_node_rewrite);
		queue_work(c->btree_node_rewrite_worker, &a->work);
	}
}

void bch2_free_pending_node_rewrites(struct bch_fs *c)
{
	while (1) {
		struct async_btree_rewrite *a;

		scoped_guard(spinlock, &c->btree_node_rewrites_lock)
			a = list_pop_entry(&c->btree_node_rewrites_pending,
					   struct async_btree_rewrite, list);

		if (!a)
			break;

		bch2_bkey_buf_exit(&a->key, c);
		kfree(a);
	}
}

static int __bch2_btree_node_update_key(struct btree_trans *trans,
					struct btree_iter *iter,
					struct btree *b, struct btree *new_hash,
					struct bkey_i *new_key,
					unsigned commit_flags,
					bool skip_triggers)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter2 = {};
	struct btree *parent;
	int ret;

	if (!skip_triggers) {
		ret   = bch2_key_trigger_old(trans, b->c.btree_id, b->c.level + 1,
					     bkey_i_to_s_c(&b->key),
					     BTREE_TRIGGER_transactional) ?:
			bch2_key_trigger_new(trans, b->c.btree_id, b->c.level + 1,
					     bkey_i_to_s(new_key),
					     BTREE_TRIGGER_transactional);
		if (ret)
			return ret;
	}

	if (new_hash) {
		bkey_copy(&new_hash->key, new_key);
		ret = bch2_btree_node_hash_insert(&c->btree_cache,
				new_hash, b->c.level, b->c.btree_id);
		BUG_ON(ret);
	}

	parent = btree_node_parent(btree_iter_path(trans, iter), b);
	if (parent) {
		bch2_trans_copy_iter(trans, &iter2, iter);

		iter2.path = bch2_btree_path_make_mut(trans, iter2.path,
				iter2.flags & BTREE_ITER_intent,
				_THIS_IP_);

		struct btree_path *path2 = btree_iter_path(trans, &iter2);
		BUG_ON(path2->level != b->c.level);
		BUG_ON(!bpos_eq(path2->pos, new_key->k.p));

		btree_path_set_level_up(trans, path2);

		trans->paths_sorted = false;

		ret   = bch2_btree_iter_traverse(trans, &iter2) ?:
			bch2_trans_update(trans, &iter2, new_key, BTREE_TRIGGER_norun);
		if (ret)
			goto err;
	} else {
		BUG_ON(btree_node_root(c, b) != b);

		struct jset_entry *e = bch2_trans_jset_entry_alloc(trans,
				       jset_u64s(new_key->k.u64s));
		ret = PTR_ERR_OR_ZERO(e);
		if (ret)
			return ret;

		journal_entry_set(e,
				  BCH_JSET_ENTRY_btree_root,
				  b->c.btree_id, b->c.level,
				  new_key, new_key->k.u64s);
	}

	ret = bch2_trans_commit(trans, NULL, NULL, commit_flags);
	if (ret)
		goto err;

	bch2_btree_node_lock_write_nofail(trans, btree_iter_path(trans, iter), &b->c);

	if (new_hash) {
		guard(mutex)(&c->btree_cache.lock);
		bch2_btree_node_hash_remove(&c->btree_cache, new_hash);

		__bch2_btree_node_hash_remove(&c->btree_cache, b);

		bkey_copy(&b->key, new_key);
		ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
		BUG_ON(ret);
	} else {
		bkey_copy(&b->key, new_key);
	}

	bch2_btree_node_unlock_write(trans, btree_iter_path(trans, iter), b);
out:
	bch2_trans_iter_exit(trans, &iter2);
	return ret;
err:
	if (new_hash) {
		guard(mutex)(&c->btree_cache.lock);
		bch2_btree_node_hash_remove(&c->btree_cache, b);
	}
	goto out;
}

int bch2_btree_node_update_key(struct btree_trans *trans, struct btree_iter *iter,
			       struct btree *b, struct bkey_i *new_key,
			       unsigned commit_flags, bool skip_triggers)
{
	struct bch_fs *c = trans->c;
	struct btree *new_hash = NULL;
	struct btree_path *path = btree_iter_path(trans, iter);
	struct closure cl;
	int ret = 0;

	ret = bch2_btree_path_upgrade(trans, path, b->c.level + 1);
	if (ret)
		return ret;

	closure_init_stack(&cl);

	/*
	 * check btree_ptr_hash_val() after @b is locked by
	 * btree_iter_traverse():
	 */
	if (btree_ptr_hash_val(new_key) != b->hash_val) {
		ret = bch2_btree_cache_cannibalize_lock(trans, &cl);
		if (ret) {
			ret = drop_locks_do(trans, (closure_sync(&cl), 0));
			if (ret)
				return ret;
		}

		new_hash = bch2_btree_node_mem_alloc(trans, false);
		ret = PTR_ERR_OR_ZERO(new_hash);
		if (ret)
			goto err;
	}

	path->intent_ref++;
	ret = __bch2_btree_node_update_key(trans, iter, b, new_hash, new_key,
					   commit_flags, skip_triggers);
	--path->intent_ref;

	if (new_hash)
		bch2_btree_node_to_freelist(c, new_hash);
err:
	closure_sync(&cl);
	bch2_btree_cache_cannibalize_unlock(trans);
	return ret;
}

int bch2_btree_node_update_key_get_iter(struct btree_trans *trans,
					struct btree *b, struct bkey_i *new_key,
					unsigned commit_flags, bool skip_triggers)
{
	struct btree_iter iter;
	int ret = get_iter_to_node(trans, &iter, b);
	if (ret)
		return ret == -BCH_ERR_btree_node_dying ? 0 : ret;

	bch2_bkey_drop_ptrs(bkey_i_to_s(new_key), ptr,
			    !bch2_bkey_has_device(bkey_i_to_s(&b->key), ptr->dev));

	ret = bch2_btree_node_update_key(trans, &iter, b, new_key,
					 commit_flags, skip_triggers);
	bch2_trans_iter_exit(trans, &iter);
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

int bch2_btree_root_alloc_fake_trans(struct btree_trans *trans, enum btree_id id, unsigned level)
{
	struct bch_fs *c = trans->c;
	struct closure cl;
	struct btree *b;
	int ret;

	closure_init_stack(&cl);

	do {
		ret = bch2_btree_cache_cannibalize_lock(trans, &cl);
		closure_sync(&cl);
	} while (ret);

	b = bch2_btree_node_mem_alloc(trans, false);
	bch2_btree_cache_cannibalize_unlock(trans);

	ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		return ret;

	set_btree_node_fake(b);
	set_btree_node_need_rewrite(b);
	b->c.level	= level;
	b->c.btree_id	= id;

	bkey_btree_ptr_init(&b->key);
	b->key.k.p = SPOS_MAX;
	*((u64 *) bkey_i_to_btree_ptr(&b->key)->v.start) = U64_MAX - id;

	bch2_bset_init_first(b, &b->data->keys);
	bch2_btree_build_aux_trees(b);

	b->data->flags = 0;
	btree_set_min(b, POS_MIN);
	btree_set_max(b, SPOS_MAX);
	b->data->format = bch2_btree_calc_format(b);
	btree_node_set_format(b, b->data->format);

	ret = bch2_btree_node_hash_insert(&c->btree_cache, b,
					  b->c.level, b->c.btree_id);
	BUG_ON(ret);

	bch2_btree_set_root_inmem(c, b);

	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
	return 0;
}

void bch2_btree_root_alloc_fake(struct bch_fs *c, enum btree_id id, unsigned level)
{
	CLASS(btree_trans, trans)(c);
	lockrestart_do(trans, bch2_btree_root_alloc_fake_trans(trans, id, level));
}

static void bch2_btree_update_to_text(struct printbuf *out, struct btree_update *as)
{
	prt_printf(out, "%ps: ", (void *) as->ip_started);
	bch2_trans_commit_flags_to_text(out, as->flags);

	prt_str(out, " ");
	bch2_btree_id_to_text(out, as->btree_id);
	prt_printf(out, " l=%u-%u ",
		   as->update_level_start,
		   as->update_level_end);
	bch2_bpos_to_text(out, as->node_start);
	prt_char(out, ' ');
	bch2_bpos_to_text(out, as->node_end);
	prt_printf(out, "\nwritten %u/%u u64s_remaining %u need_rewrite %s",
		   as->node_written,
		   as->node_sectors,
		   as->node_remaining,
		   btree_node_reawrite_reason_strs[as->node_needed_rewrite]);

	prt_printf(out, "\nmode=%s nodes_written=%u cl.remaining=%u journal_seq=%llu\n",
		   bch2_btree_update_modes[as->mode],
		   as->nodes_written,
		   closure_nr_remaining(&as->cl),
		   as->journal.seq);
}

void bch2_btree_updates_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct btree_update *as;

	guard(mutex)(&c->btree_interior_update_lock);
	list_for_each_entry(as, &c->btree_interior_update_list, list)
		bch2_btree_update_to_text(out, as);
}

static bool bch2_btree_interior_updates_pending(struct bch_fs *c)
{
	guard(mutex)(&c->btree_interior_update_lock);
	return !list_empty(&c->btree_interior_update_list);
}

bool bch2_btree_interior_updates_flush(struct bch_fs *c)
{
	bool ret = bch2_btree_interior_updates_pending(c);

	if (ret)
		closure_wait_event(&c->btree_interior_update_wait,
				   !bch2_btree_interior_updates_pending(c));
	return ret;
}

void bch2_journal_entry_to_btree_root(struct bch_fs *c, struct jset_entry *entry)
{
	struct btree_root *r = bch2_btree_id_root(c, entry->btree_id);

	guard(mutex)(&c->btree_interior_update_lock);

	r->level = entry->level;
	r->alive = true;
	bkey_copy(&r->key, (struct bkey_i *) entry->start);
}

struct jset_entry *
bch2_btree_roots_to_journal_entries(struct bch_fs *c,
				    struct jset_entry *end,
				    unsigned long skip)
{
	guard(mutex)(&c->btree_interior_update_lock);

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (r->alive && !test_bit(i, &skip)) {
			journal_entry_set(end, BCH_JSET_ENTRY_btree_root,
					  i, r->level, &r->key, r->key.k.u64s);
			end = vstruct_next(end);
		}
	}

	return end;
}

static void bch2_btree_alloc_to_text(struct printbuf *out,
				     struct bch_fs *c,
				     struct btree_alloc *a)
{
	printbuf_indent_add(out, 2);
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&a->k));
	prt_newline(out);

	struct open_bucket *ob;
	unsigned i;
	open_bucket_for_each(c, &a->ob, ob, i)
		bch2_open_bucket_to_text(out, c, ob);

	printbuf_indent_sub(out, 2);
}

void bch2_btree_reserve_cache_to_text(struct printbuf *out, struct bch_fs *c)
{
	for (unsigned i = 0; i < c->btree_reserve_cache_nr; i++)
		bch2_btree_alloc_to_text(out, c, &c->btree_reserve_cache[i]);
}

void bch2_fs_btree_interior_update_exit(struct bch_fs *c)
{
	WARN_ON(!list_empty(&c->btree_node_rewrites));
	WARN_ON(!list_empty(&c->btree_node_rewrites_pending));

	if (c->btree_node_rewrite_worker)
		destroy_workqueue(c->btree_node_rewrite_worker);
	if (c->btree_interior_update_worker)
		destroy_workqueue(c->btree_interior_update_worker);
	mempool_exit(&c->btree_interior_update_pool);
}

void bch2_fs_btree_interior_update_init_early(struct bch_fs *c)
{
	mutex_init(&c->btree_reserve_cache_lock);
	INIT_LIST_HEAD(&c->btree_interior_update_list);
	INIT_LIST_HEAD(&c->btree_interior_updates_unwritten);
	mutex_init(&c->btree_interior_update_lock);
	INIT_WORK(&c->btree_interior_update_work, btree_interior_update_work);

	INIT_LIST_HEAD(&c->btree_node_rewrites);
	INIT_LIST_HEAD(&c->btree_node_rewrites_pending);
	spin_lock_init(&c->btree_node_rewrites_lock);
}

int bch2_fs_btree_interior_update_init(struct bch_fs *c)
{
	c->btree_interior_update_worker =
		alloc_workqueue("btree_update", WQ_UNBOUND|WQ_MEM_RECLAIM, 8);
	if (!c->btree_interior_update_worker)
		return bch_err_throw(c, ENOMEM_btree_interior_update_worker_init);

	c->btree_node_rewrite_worker =
		alloc_ordered_workqueue("btree_node_rewrite", WQ_UNBOUND);
	if (!c->btree_node_rewrite_worker)
		return bch_err_throw(c, ENOMEM_btree_interior_update_worker_init);

	if (mempool_init_kmalloc_pool(&c->btree_interior_update_pool, 1,
				      sizeof(struct btree_update)))
		return bch_err_throw(c, ENOMEM_btree_interior_update_pool_init);

	return 0;
}
