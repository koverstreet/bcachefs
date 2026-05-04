// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/replicas.h"

#include "btree/bkey_buf.h"
#include "btree/bkey_methods.h"
#include "btree/cache.h"
#include "btree/check.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/iter.h"
#include "btree/journal_overlay.h"
#include "btree/locking.h"
#include "btree/read.h"
#include "btree/sort.h"
#include "btree/write.h"

#include "data/extents.h"
#include "data/keylist.h"
#include "data/reconcile/trigger.h"
#include "data/write.h"

#include "init/error.h"
#include "init/fs.h"
#include "init/passes.h"

#include "journal/journal.h"
#include "journal/reclaim.h"

#include "sb/counters.h"
#include "sb/members.h"
#include "sb/io.h"

#include "util/clock.h"
#include "util/enumerated_ref.h"

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

static int btree_node_topology_err(struct bch_fs *c, struct btree *b, struct printbuf *out)
{
	prt_printf(out, "in parent node:\n");
	bch2_btree_pos_to_text(out, c, b);
	prt_newline(out);
	int ret = __bch2_topology_error(c, out);

	bch2_prt_task_backtrace(out, current, 1, GFP_KERNEL);
	return ret;
}

/*
 * Verify that child nodes correctly span parent node's range:
 */
int bch2_btree_node_check_topology_msg(struct btree_trans *trans, struct btree *b, struct printbuf *out)
{
	struct bch_fs *c = trans->c;
	struct bpos node_min = b->key.k.type == KEY_TYPE_btree_ptr_v2
		? bkey_i_to_btree_ptr_v2(&b->key)->v.min_key
		: b->data->min_key;

	BUG_ON(b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	       !bpos_eq(bkey_i_to_btree_ptr_v2(&b->key)->v.min_key,
			b->data->min_key));

	struct bkey_buf prev __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&prev);

	struct btree_and_journal_iter iter __cleanup(bch2_btree_and_journal_iter_exit);
	bch2_btree_and_journal_iter_init_node_iter(trans, &iter, b);

	/*
	 * Don't use btree_node_is_root(): we're called by btree split, after
	 * creating a new root but before setting it
	 */
	if (b == btree_node_root(c, b)) {
		if (!bpos_eq(b->data->min_key, POS_MIN)) {
			prt_printf(out, "btree root with incorrect min_key: ");
			bch2_bpos_to_text(out, b->data->min_key);
			prt_newline(out);

			bch2_count_fsck_err(c, btree_root_bad_min_key, out);
			return btree_node_topology_err(c, b, out);
		}

		if (!bpos_eq(b->data->max_key, SPOS_MAX)) {
			prt_printf(out, "btree root with incorrect max_key: ");
			bch2_bpos_to_text(out, b->data->max_key);
			prt_newline(out);

			bch2_count_fsck_err(c, btree_root_bad_max_key, out);
			return btree_node_topology_err(c, b, out);
		}
	}

	if (!b->c.level)
		return 0;

	struct bkey_s_c k;
	while ((k = bch2_btree_and_journal_iter_peek(c, &iter)).k) {
		if (k.k->type != KEY_TYPE_btree_ptr_v2)
			return 0;

		struct bkey_s_c_btree_ptr_v2 bp = bkey_s_c_to_btree_ptr_v2(k);

		struct bpos expected_min = bkey_deleted(&prev.k->k)
			? node_min
			: bpos_successor(prev.k->k.p);

		if (!bpos_eq(expected_min, bp.v->min_key)) {
			prt_str(out, "end of prev node doesn't match start of next node");
			prt_str(out, "\nprev ");
			bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(prev.k));
			prt_str(out, "\nnext ");
			bch2_bkey_val_to_text(out, c, k);
			prt_newline(out);

			bch2_count_fsck_err(c, btree_node_topology_bad_min_key, out);
			return btree_node_topology_err(c, b, out);
		}

		bch2_bkey_buf_reassemble(&prev, k);
		bch2_btree_and_journal_iter_advance(&iter);
	}

	if (bkey_deleted(&prev.k->k)) {
		prt_printf(out, "empty interior node\n");
		bch2_count_fsck_err(c, btree_node_topology_empty_interior_node, out);
		return btree_node_topology_err(c, b, out);
	}

	if (!bpos_eq(prev.k->k.p, b->key.k.p)) {
		prt_str(out, "last child node doesn't end at end of parent node\nchild: ");
		bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(prev.k));
		prt_newline(out);

		bch2_count_fsck_err(c, btree_node_topology_bad_max_key, out);
		return btree_node_topology_err(c, b, out);
	}

	return 0;
}

int bch2_btree_node_check_topology(struct btree_trans *trans, struct btree *b)
{
	CLASS(bch_log_msg, msg)(trans->c);
	msg.m.suppress = true;

	return bch2_btree_node_check_topology_msg(trans, b, &msg.m);
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

	clear_btree_node_permanent(b);
	clear_btree_node_noevict(b);
}

static void bch2_btree_node_free_inmem(struct btree_trans *trans,
				       struct btree_path *path,
				       struct btree *b)
{
	struct bch_fs *c = trans->c;

	BUG_ON(!btree_node_write_locked(path, b->c.level));

	__btree_node_free(trans, b);

	bch2_btree_node_transition_state(&c->btree.cache, b, BTREE_NODE_CACHE_FREEABLE);

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
	clear_btree_node_dirty(b);
	clear_btree_node_need_write(b);

	bch2_btree_node_transition_state(&c->btree.cache, b, BTREE_NODE_CACHE_NONE);

	BUG_ON(p->nr >= ARRAY_SIZE(p->b));
	p->b[p->nr++] = b;

	/*
	 * Callers enter with intent+write held; @b stays intent+write-locked
	 * on prealloc_nodes so consumers (bch2_btree_node_alloc from prealloc,
	 * bch2_btree_reserve_put) can use it without re-taking locks.
	 *
	 * bch2_trans_node_drop() below releases any path-held locks on @b; for
	 * each such path, bump the recurse counts so its unlock decrements the
	 * recurse rather than the actual hold — leaving @b's locks held by the
	 * original (raw) reference from bch2_btree_node_alloc.
	 */
	struct btree_path *path;
	unsigned i;
	trans_for_each_path(trans, path, i)
		if (path->l[b->c.level].b == b)
			six_lock_increment(&b->c.lock, SIX_LOCK_write);

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

	unsigned durability = bch2_btree_ptr_durability(c, k).online;

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
					     bool interior_node,
					     struct alloc_request *req)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp;
	struct btree *b;
	int ret;

	b = bch2_btree_node_mem_alloc(trans, interior_node);
	if (IS_ERR(b))
		return b;

	BUG_ON(b->ob.nr);
retry:
	ret = bch2_alloc_sectors_req(trans, req,
				     writepoint_ptr(&c->allocator.btree_write_point),
				     &wp);
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

	mutex_lock(&c->btree.reserve_cache.lock);
	while (c->btree.reserve_cache.nr) {
		struct btree_alloc *a = c->btree.reserve_cache.data + --c->btree.reserve_cache.nr;

		/* check if it has sufficient durability */

		if (can_use_btree_node(c, res,
				       req->flags & BCH_WRITE_only_specified_devs ? req->target : 0,
				       bkey_i_to_s_c(&a->k))) {
			bkey_copy(&b->key, &a->k);
			b->ob = a->ob;
			mutex_unlock(&c->btree.reserve_cache.lock);
			goto out;
		}

		bch2_open_buckets_put(c, &a->ob);
	}
	mutex_unlock(&c->btree.reserve_cache.lock);

	bkey_btree_ptr_v2_init(&b->key);
	bch2_alloc_sectors_append_ptrs(c, wp, &b->key, btree_sectors(c), false);

	bch2_open_bucket_get(c, wp, &b->ob);
out:
	bch2_alloc_sectors_done(c, wp);
	/*
	 * Leave both intent and write held: nodes on the prealloc list stay
	 * locked (they aren't reachable to any other trans — not yet hashed
	 * in, or freshly hash-removed — so holding write blocks nothing).
	 * Consumers can use them without any lock-take at pop time.
	 */

	return b;
err:
	bch2_btree_node_transition_state(&c->btree.cache, b, BTREE_NODE_CACHE_FREEABLE);
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
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

	/* Both intent and write were held across parking on prealloc_nodes. */

	set_btree_node_accessed(b);
	bch2_btree_node_set_dirty(c, b);
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

	ret = bch2_btree_node_transition_state(&c->btree.cache, b, btree_node_live_state(b));
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

			mutex_lock(&c->btree.reserve_cache.lock);

			if (c->btree.reserve_cache.nr <
			    ARRAY_SIZE(c->btree.reserve_cache.data)) {
				struct btree_alloc *a =
					&c->btree.reserve_cache.data[c->btree.reserve_cache.nr++];

				a->ob = b->ob;
				b->ob.nr = 0;
				bkey_copy(&a->k, &b->key);
			} else {
				bch2_open_buckets_put(c, &b->ob);
			}

			mutex_unlock(&c->btree.reserve_cache.lock);

			/* Both intent and write were held across prealloc. */
			__btree_node_free(trans, b);
			bch2_btree_node_transition_state(&c->btree.cache, b,
							 BTREE_NODE_CACHE_FREEABLE);
			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);
		}
	}
}

static int bch2_btree_reserve_get(struct btree_trans *trans,
				  struct btree_update *as,
				  unsigned nr_nodes[2],
				  struct alloc_request *req)
{
	BUG_ON(nr_nodes[0] + nr_nodes[1] > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	try(bch2_btree_cache_cannibalize_lock(trans, req->cl));

	int ret = 0;
	for (unsigned interior = 0; interior < 2; interior++) {
		struct prealloc_nodes *p = as->prealloc_nodes + interior;

		while (p->nr < nr_nodes[interior]) {
			struct btree *b = __bch2_btree_node_alloc(trans, &as->disk_res,
								  interior, req);
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

	bch2_trans_unlock_write(trans);

	if (as->took_gc_lock)
		up_read(&c->gc.lock);
	as->took_gc_lock = false;

	bch2_journal_pin_drop(&c->journal, &as->journal);
	bch2_journal_pin_flush(&c->journal, &as->journal);
	bch2_disk_reservation_put(c, &as->disk_res);
	bch2_btree_reserve_put(as, trans);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_interior_update_total],
			       as->start_time);

	guard(mutex)(&c->btree.interior_updates.lock);

	list_del(&as->unwritten_list);
	list_del(&as->list);

	closure_debug_destroy(&as->cl);
	mempool_free(as, &c->btree.interior_updates.pool);

	/*
	 * Have to do the wakeup with btree_interior_update_lock still held,
	 * since being on btree_interior_update_list is our ref on @c:
	 */
	closure_wake_up(&c->btree.interior_updates.wait);
}

static void bch2_btree_update_add_key(btree_update_nodes *nodes,
				      unsigned level, struct bkey_i *k)
{
	BUG_ON(darray_make_room(nodes, 1));

	struct btree_update_node *n = &darray_top(*nodes);
	nodes->nr++;

	*n = (struct btree_update_node) { .level = level };
	bkey_copy(&n->key, k);
}

static void bch2_btree_update_add_node(struct bch_fs *c, btree_update_nodes *nodes, struct btree *b)
{
	BUG_ON(darray_make_room(nodes, 1));

	struct btree_update_node *n = &darray_top(*nodes);
	nodes->nr++;

	n->b		= b;
	n->level	= b->c.level;
	n->seq		= b->data->keys.seq;
	n->root		= b == btree_node_root(c, b);
	bkey_copy(&n->key, &b->key);
}

static bool btree_update_new_nodes_marked_sb(struct btree_update *as)
{
	darray_for_each(as->new_nodes, i)
		if (!bch2_dev_btree_bitmap_marked(as->c, bkey_i_to_s_c(&i->key)))
			return false;
	return true;
}

static void btree_update_new_nodes_mark_sb(struct btree_update *as)
{
	struct bch_fs *c = as->c;

	guard(memalloc_flags)(PF_MEMALLOC_NOFS);
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;
	darray_for_each(as->new_nodes, i)
		bch2_dev_btree_bitmap_mark_locked(c, bkey_i_to_s_c(&i->key), &write_sb);

	if (write_sb)
		bch2_write_super(c);
}

static void bkey_strip_reconcile(const struct bch_fs *c, struct bkey_s k)
{
	if (bkey_deleted(k.k))
		return;

	bool dropped;
	do {
		dropped = false;

		struct bkey_ptrs ptrs = bch2_bkey_ptrs(k);
		union bch_extent_entry *entry;
		bkey_extent_entry_for_each(ptrs, entry)
			if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile ||
			    extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile_bp) {
				extent_entry_drop(c, k, entry);
				dropped = true;
				break;
			}
	} while (dropped);

	bch2_bkey_drop_ptrs_noerror(k, p, entry, p.ptr.dev == BCH_SB_MEMBER_INVALID);

	BUG_ON(!bch2_bkey_nr_dirty_ptrs(c, k.s_c));
}

static bool bkey_has_reconcile(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile ||
		    (extent_entry_type(entry) == BCH_EXTENT_ENTRY_ptr &&
		     entry->ptr.dev == BCH_SB_MEMBER_INVALID))
			return true;
	return false;
}

/*
 * The transactional part of an interior btree node update, where we journal the
 * update we did to the interior node and update alloc info:
 */
static int btree_update_nodes_written_trans(struct btree_trans *trans,
					    struct btree_update *as)
{
	struct bch_fs *c = trans->c;
	struct bch_inode_opts opts;
	bch2_inode_opts_get(as->c, &opts, true);

	/*
	 * Our caller uses BCH_TRANS_COMMIT_no_check_rw, so after emergency
	 * read-only nothing else gates this path. Bail explicitly: running the
	 * alloc info triggers below for an interior update whose journal half
	 * won't land underflows bucket sector counts.
	 */
	try(bch2_journal_error(&c->journal));

	trans->journal_pin = &as->journal;

	darray_for_each(as->old_nodes, i) {
		try(bch2_key_trigger_old(trans, as->btree_id, i->level + 1, bkey_i_to_s_c(&i->key),
					 BTREE_TRIGGER_transactional));

		journal_entry_set(errptr_try(bch2_trans_jset_entry_alloc(trans,
									 jset_u64s(i->key.k.u64s))),
				  BCH_JSET_ENTRY_overwrite,
				  as->btree_id,
				  i->level + 1,
				  &i->key, i->key.k.u64s);
	}

	darray_for_each(as->new_nodes, i) {
		i->update_node_key = false;
		bkey_strip_reconcile(c, bkey_i_to_s(&i->key));

		try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, &i->key,
						  SET_NEEDS_RECONCILE_foreground, 0));

		/*
		 * This is not strictly the best way of doing this, what we
		 * really want is a flag for 'did
		 * bch2_bkey_set_needs_reconcile() change anything, and do we
		 * need to update the node key'; there's no reason we couldn't
		 * be calling bch2_bkey_set_needs_reconcile() at node allocation
		 * time to better handle the case where we have to pad with
		 * invalid pointers because we don't currently have devices
		 * available to meet the desired replication level.
		 */

		if (bkey_has_reconcile(c, bkey_i_to_s_c(&i->key))) {
			CLASS(btree_iter_uninit, iter)(trans);
			int ret = bch2_btree_node_get_iter(trans, &iter, i->b);
			if (ret && ret != -BCH_ERR_btree_node_dying)
				return ret;
			if (!ret)
				i->update_node_key = true;
			else
				bkey_strip_reconcile(c, bkey_i_to_s(&i->key));
		}

		try(bch2_key_trigger_new(trans, as->btree_id, i->level + 1, bkey_i_to_s(&i->key),
					 BTREE_TRIGGER_transactional));

		if (!i->update_node_key || i->root) {
			journal_entry_set(errptr_try(bch2_trans_jset_entry_alloc(trans,
									jset_u64s(i->key.k.u64s))),
					  i->root
					  ? BCH_JSET_ENTRY_btree_root
					  : BCH_JSET_ENTRY_btree_keys,
					  as->btree_id,
					  i->root ? i->level : i->level + 1,
					  &i->key, i->key.k.u64s);
		} else {
			CLASS(btree_node_iter, parent_iter)(trans,
							    as->btree_id,
							    i->key.k.p,
							    0,
							    i->level + 1,
							    BTREE_ITER_intent);
			try(bch2_btree_iter_traverse(&parent_iter));
			/*
			 * XXX: we shouldn't be logging overwrites here, need a
			 * flag for that
			 */
			try(bch2_trans_update(trans, &parent_iter, &i->key, BTREE_TRIGGER_norun));
		}
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
	CLASS(btree_trans, trans)(c);
	u64 journal_seq = 0;
	int ret = 0;

	if (!btree_update_new_nodes_marked_sb(as)) {
		bch2_trans_unlock_long(trans);
		btree_update_new_nodes_mark_sb(as);
	}

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
	darray_for_each(as->old_nodes, i) {
		bool seq_matches = false;

		ret = lockrestart_do(trans, ({
			btree_path_idx_t path_idx;
			int _ret = bch2_btree_node_lock_with_path(trans, &i->b->c,
								  SIX_LOCK_read, &path_idx);
			if (!_ret) {
				seq_matches = btree_node_seq_matches(i->b, i->seq);
				bch2_btree_node_unlock_with_path(trans, path_idx,
								 i->b->c.level);
			}
			_ret;
		}));
		bch2_trans_unlock_long(trans);

		if (seq_matches)
			wait_on_bit_io(&i->b->flags, BTREE_NODE_write_in_flight_inner,
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

	bch2_trans_unlock(trans);
	/*
	 * btree_interior_update_commit_lock is needed for synchronization with
	 * btree_node_update_key(): having the lock be at the filesystem level
	 * sucks, we'll need to watch for contention
	 */
	scoped_guard(mutex, &c->btree.interior_updates.commit_lock) {
		ret = commit_do(trans, &as->disk_res, &journal_seq,
				BCH_WATERMARK_interior_updates|
				BCH_TRANS_COMMIT_no_enospc|
				BCH_TRANS_COMMIT_no_check_rw|
				BCH_TRANS_COMMIT_journal_reclaim,
				btree_update_nodes_written_trans(trans, as));
		bch2_fs_fatal_err_on(ret && !bch2_journal_error(&c->journal),
				     c, "%s", bch2_err_str(ret));
		/*
		 * Clear will_make_reachable while we still hold intent locks on
		 * all our new nodes, to avoid racing with
		 * btree_node_update_key():
		 */
		darray_for_each(as->new_nodes, i) {
			if (i->update_node_key)
				bkey_copy(&i->b->key, &i->key);

			if (i->b) {
				BUG_ON(i->b->will_make_reachable != (unsigned long) as);
				i->b->will_make_reachable = 0;
				clear_btree_node_will_make_reachable(i->b);
			}
		}
	}

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
	struct btree *b = READ_ONCE(as->b);
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
		lockrestart_do(trans, ({
			btree_path_idx_t path_idx;
			int _ret = bch2_btree_node_lock_with_path(trans, &b->c,
							SIX_LOCK_intent, &path_idx);
			if (!_ret) {
				struct btree_path *path = trans->paths + path_idx;

				_ret = bch2_btree_node_lock_write(trans, path, &b->c);
				if (_ret) {
					bch2_btree_node_unlock_with_path(trans, path_idx,
									 b->c.level);
				} else {
					mutex_lock(&c->btree.interior_updates.lock);

					list_del(&as->write_blocked_list);
					if (list_empty(&b->write_blocked))
						clear_btree_node_write_blocked(b);

					/*
					 * Node might have been freed, recheck under
					 * btree_interior_updates.lock:
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
							 * If we didn't get a journal sequence
							 * number we can't write this btree node,
							 * because recovery won't know to ignore
							 * this write:
							 */
							set_btree_node_never_write(b);
						}
					}

					mutex_unlock(&c->btree.interior_updates.lock);

					mark_btree_node_locked_noreset(path, b->c.level,
								       BTREE_NODE_INTENT_LOCKED);
					six_unlock_write(&b->c.lock);

					btree_node_write_if_need(trans, b, SIX_LOCK_intent);
					bch2_btree_node_unlock_with_path(trans, path_idx,
									 b->c.level);
				}
			}
			_ret;
		}));
	}

	bch2_journal_pin_drop(&c->journal, &as->journal);

	darray_for_each(as->new_nodes, i)
		if (i->b) {
			lockrestart_do(trans, ({
				btree_path_idx_t path_idx;
				int _ret = bch2_btree_node_lock_with_path(trans, &i->b->c,
							SIX_LOCK_read, &path_idx);
				if (!_ret) {
					btree_node_write_if_need(trans, i->b, SIX_LOCK_read);
					bch2_btree_node_unlock_with_path(trans, path_idx,
									 i->b->c.level);
				}
				_ret;
			}));
		}

	for (unsigned i = 0; i < as->nr_open_buckets; i++)
		bch2_open_bucket_put(c, c->allocator.open_buckets + as->open_buckets[i]);

	bch2_btree_update_free(as, trans);
}

static void btree_interior_update_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, btree.interior_updates.work);
	struct btree_update *as;

	while (1) {
		scoped_guard(mutex, &c->btree.interior_updates.lock) {
			as = list_first_entry_or_null(&c->btree.interior_updates.unwritten,
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

	scoped_guard(mutex, &c->btree.interior_updates.lock)
		as->nodes_written = true;

	queue_work(c->btree.interior_updates.worker, &c->btree.interior_updates.work);
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

	guard(mutex)(&c->btree.interior_updates.lock);
	list_add_tail(&as->unwritten_list, &c->btree.interior_updates.unwritten);

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

	lockdep_assert_held(&c->btree.interior_updates.lock);

	child->b = NULL;
	child->mode = BTREE_UPDATE_update;

	bch2_journal_pin_copy(&c->journal, &as->journal, &child->journal,
			      bch2_update_reparent_journal_pin_flush);
}

static void btree_update_updated_root(struct btree_update *as, struct btree *b)
{
	struct bch_fs *c = as->c;

	BUG_ON(as->mode != BTREE_UPDATE_none);
	as->mode = BTREE_UPDATE_root;

	scoped_guard(mutex, &c->btree.interior_updates.lock)
		list_add_tail(&as->unwritten_list, &c->btree.interior_updates.unwritten);
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

	guard(mutex)(&c->btree.interior_updates.lock);

	BUG_ON(b->will_make_reachable);

	b->will_make_reachable = 1UL|(unsigned long) as;
	set_btree_node_will_make_reachable(b);

	if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
		unsigned bytes = vstruct_end(&b->data->keys) - (void *) b->data;
		unsigned sectors = round_up(bytes, block_bytes(c)) >> 9;

		bkey_i_to_btree_ptr_v2(&b->key)->v.sectors_written =
			cpu_to_le16(sectors);
	}
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

	mutex_lock(&c->btree.interior_updates.lock);

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
		closure_wake_up(&c->btree.interior_updates.wait);
	}

	clear_btree_node_dirty(b);
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

	mutex_unlock(&c->btree.interior_updates.lock);

	bch2_btree_update_add_node(c, &as->old_nodes, b);
}

static void bch2_btree_update_done(struct btree_update *as, struct btree_trans *trans)
{
	struct bch_fs *c = as->c;
	u64 start_time = as->start_time;

	bch2_trans_unlock_write(trans);

	BUG_ON(as->mode == BTREE_UPDATE_none);

	if (as->took_gc_lock)
		up_read(&as->c->gc.lock);
	as->took_gc_lock = false;

	bch2_btree_reserve_put(as, trans);

	continue_at(&as->cl, btree_update_set_nodes_written,
		    as->c->btree.interior_updates.worker);

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
			enum bch_trans_commit_flags commit_flags,
			enum bch_write_flags write_flags)
{
	struct bch_fs *c = trans->c;
	struct btree_update *as;
	u64 start_time = local_clock();
	int disk_res_flags = (commit_flags & BCH_TRANS_COMMIT_no_enospc)
		? BCH_DISK_RESERVATION_NOFAIL : 0;
	unsigned nr_nodes[2] = { 0, 0 };
	unsigned level_end = level_start;
	enum bch_watermark watermark = commit_flags & BCH_WATERMARK_MASK;
	struct alloc_request *req __free(alloc_request_put) = NULL;
	int ret = 0;
	u32 restart_count = trans->restart_count;

	BUG_ON(!path->should_be_locked);

	if (watermark == BCH_WATERMARK_stripe) {
		watermark = BCH_WATERMARK_normal;
		commit_flags &= ~BCH_WATERMARK_MASK;
		commit_flags |= watermark;
	}

	if (watermark < BCH_WATERMARK_reclaim &&
	    journal_low_on_space(&c->journal)) {
		if (commit_flags & BCH_TRANS_COMMIT_journal_reclaim)
			return ERR_PTR(-BCH_ERR_journal_reclaim_would_deadlock);

		ret = drop_locks_do(trans,
			({ wait_event(c->journal.wait, !journal_low_on_space(&c->journal)); 0; }));
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

	if (!down_read_trylock(&c->gc.lock)) {
		ret = drop_locks_do(trans, (down_read(&c->gc.lock), 0));
		if (ret) {
			up_read(&c->gc.lock);
			return ERR_PTR(ret);
		}
	}

	as = mempool_alloc(&c->btree.interior_updates.pool, GFP_NOFS);
	memset(as, 0, sizeof(*as));
	closure_init(&as->cl, NULL);
	as->c			= c;
	as->start_time		= start_time;
	as->ip_started		= _RET_IP_;
	as->mode		= BTREE_UPDATE_none;
	as->flags		= commit_flags;
	as->took_gc_lock	= true;
	as->btree_id		= path->btree_id;
	as->update_level_start	= level_start;
	as->update_level_end	= level_end;
	INIT_LIST_HEAD(&as->list);
	INIT_LIST_HEAD(&as->unwritten_list);
	INIT_LIST_HEAD(&as->write_blocked_list);
	darray_init(&as->old_nodes);
	darray_init(&as->new_nodes);
	bch2_keylist_init(&as->parent_keys, as->inline_keys);

	scoped_guard(mutex, &c->btree.interior_updates.lock)
		list_add_tail(&as->list, &c->btree.interior_updates.list);

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

	struct bch_devs_list devs_have = (struct bch_devs_list) { 0 };
	req = alloc_request_get(trans,
				target ?:
				c->opts.metadata_target ?:
				c->opts.foreground_target,
				false,
				&devs_have,
				as->disk_res.nr_replicas,
				as->disk_res.nr_replicas,
				watermark,
				write_flags,
				NULL);
	ret = PTR_ERR_OR_ZERO(req);
	if (ret)
		goto err;

	ret = bch2_btree_reserve_get(trans, as, nr_nodes, req);
	if (bch2_err_matches(ret, EAGAIN) ||
	    bch2_err_matches(ret, ENOMEM)) {
		/*
		 * XXX: this should probably be a separate BTREE_INSERT_NONBLOCK
		 * flag
		 */
		if (bch2_err_matches(ret, ENOSPC) &&
		    (commit_flags & BCH_TRANS_COMMIT_journal_reclaim) &&
		    watermark < BCH_WATERMARK_reclaim) {
			ret = bch_err_throw(c, journal_reclaim_would_deadlock);
			goto err;
		}

		CLASS(closure_stack, cl)();
		req->cl = &cl;

		do {
			ret = bch2_btree_reserve_get(trans, as, nr_nodes, req);
			if (!bch2_err_matches(ret, BCH_ERR_operation_blocked))
				break;
			bch2_trans_unlock(trans);
			bch2_wait_on_allocator(c, req, ret, &cl);
		} while (1);

		/*
		 * Don't block with btree locks held
		 *
		 * It would be nice if we could remove closures from waitlists
		 * without waking up the waitlist:
		 */
		if (closure_nr_remaining(&cl) > 1)
			bch2_trans_unlock(trans);
	}

	if (ret) {
		event_inc_trace(c, btree_reserve_get_fail, buf, ({
			prt_printf(&buf, "%s\n", trans->fn);
			prt_printf(&buf, "need %u ret %s\n",
				   nr_nodes[0] + nr_nodes[1], bch2_err_str(ret));
		}));
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
	/*
	 * Root nodes cannot be reaped. The flag (rather than off-list
	 * placement) is the mechanism: the reclaim path checks
	 * btree_node_permanent and skips. Roots stay on bc->list,
	 * counted normally; cache_exit's teardown sweep finds them.
	 */
	scoped_guard(mutex, &c->btree.cache.lock)
		set_btree_node_permanent(b);

	scoped_guard(mutex, &c->btree.cache.root_lock)
		bch2_btree_id_root(c, b->c.btree_id)->b = b;

	bch2_recalc_btree_reserve(c);
}

static int bch2_btree_set_root(struct btree_update *as,
			       struct btree_trans *trans,
			       struct btree_path *path,
			       struct btree *b)
{
	struct bch_fs *c = as->c;

	trace_btree_node(c, b, btree_node_set_root);

	struct btree *old = btree_node_root(c, b);

	BUG_ON(!btree_node_write_locked(path, old->c.level));

	bch2_btree_set_root_inmem(c, b);

	btree_update_updated_root(as, b);
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
	unsigned long old, new;

	BUG_ON(insert->k.type == KEY_TYPE_btree_ptr_v2 &&
	       !btree_ptr_sectors_written(bkey_i_to_s_c(insert)));

	if (unlikely(!test_bit(JOURNAL_replay_done, &c->journal.flags))) {
		guard(mutex)(&c->journal_keys.overwrite_lock);
		bch2_journal_key_check_or_overwrite(c, b->c.btree_id, b->c.level,
						    insert->k.p, false);
	}

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

	while ((k = bch2_btree_node_iter_peek_all(node_iter, b)) &&
	       bkey_iter_pos_cmp(b, k, &insert->k.p) < 0)
		bch2_btree_node_iter_advance(node_iter, b);

	bch2_btree_bset_insert_key(trans, path, b, node_iter, insert);
	if (!btree_node_dirty(b))
		bch2_btree_node_set_dirty(c, b);

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

	CLASS(bch_log_msg, msg)(as->c);
	msg.m.suppress = true;

	int ret = bch2_btree_node_check_topology_msg(trans, b, &msg.m);
	if (ret) {
		prt_str(&msg.m, "inserted keys\n");

		scoped_guard(printbuf_indent, &msg.m)
			for (struct bkey_i *k = keys->keys;
			     k != insert;
			     k = bkey_next(k)) {
				bch2_bkey_val_to_text(&msg.m, trans->c, bkey_i_to_s_c(k));
				prt_newline(&msg.m);
			}

		bch2_prt_task_backtrace(&msg.m, current, 0, GFP_KERNEL);
		bch2_fs_emergency_read_only(as->c, &msg.m);
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
 * btree_merge_node: src/dst representation shared by btree_pack_into_dsts
 * and the foreground merge code, so that 1->2 split / 2->1 / 3->1 / 3->2 / N->M
 * variants share one shape. Ownership: every entry's path is put by the
 * destructor on scope exit, but the destructor only runs for darrays declared
 * with CLASS() — short-lived stack darrays (e.g. the splitter's single-source
 * wrapper) can leave path_idx zero without consequence.
 */
/*
 * @b is NULL for srcs whose path is held but not yet traversed (deferred
 * fill): the cheap pre-check uses @live_u64s to gate the merge attempt
 * before paying for the disk read. Once the estimate-based gate passes, the
 * caller traverses the deferred path, populates @b, and refreshes
 * @live_u64s from b->nr.live_u64s.
 */
struct btree_merge_node {
	struct btree_trans	*trans;
	struct btree		*b;
	btree_path_idx_t	path_idx;
	u16			live_u64s;
	struct bkey_format	format;
	struct bpos		max_key;
};

static void btree_merge_node_put(struct btree_merge_node n)
{
	if (n.path_idx)
		bch2_path_put(n.trans, n.path_idx, true);
}

DEFINE_DARRAY_NAMED_FREE_ITEM(darray_merge_node, struct btree_merge_node,
			      btree_merge_node_put);

static bool find_balanced_split(struct btree_trans *trans,
				darray_merge_node *srcs,
				darray_merge_node *dsts,
				struct keylist *insert_keys,
				struct bkey_format *fallback_format,
				unsigned n1_target_u64s,
				size_t split_thresh);

/*
 * Pack core: take dsts whose .format and .max_key were populated by the
 * caller (find_balanced_split for split, compute_merge for merge) and pack
 * every src key into the appropriate dst, partitioning by key.p vs
 * dsts[0].max_key. dsts[i].b must be allocated.
 */
static void btree_pack_into_dsts(struct btree_update *as,
				 struct btree_trans *trans,
				 darray_merge_node *srcs,
				 darray_merge_node *dsts)
{
	struct btree *first_b = srcs->data[0].b;
	struct bset *bsets[2];
	struct bkey_packed *out[2];
	struct bkey_packed *k;
	struct btree_node_iter iter;
	struct bpos pivot = dsts->data[0].max_key;
	u64 max_seq = 0;

	BUG_ON(dsts->nr != 2);

	darray_for_each(*srcs, s)
		max_seq = max(max_seq, BTREE_NODE_SEQ(s->b->data));

	btree_set_min(dsts->data[0].b, first_b->data->min_key);
	btree_set_max(dsts->data[0].b, dsts->data[0].max_key);
	btree_set_min(dsts->data[1].b, bpos_successor(pivot));
	btree_set_max(dsts->data[1].b, dsts->data[1].max_key);

	for (unsigned i = 0; i < 2; i++) {
		struct btree *n = dsts->data[i].b;

		BUG_ON(n->nsets != 1);

		bsets[i] = btree_bset_first(n);
		out[i] = bsets[i]->start;

		SET_BTREE_NODE_SEQ(n->data, max_seq + 1);

		n->data->format = dsts->data[i].format;
		btree_node_set_format(n, n->data->format);
	}

	darray_for_each(*srcs, s) {
		struct btree *src_b = s->b;

		for_each_btree_node_key(src_b, k, &iter) {
			if (bkey_deleted(k))
				continue;

			struct bkey uk = bkey_unpack_key(src_b, k);
			unsigned i = bpos_le(uk.p, pivot) ? 0 : 1;

			struct btree *n = dsts->data[i].b;

			if (bch2_bkey_transform(&n->format, out[i], bkey_packed(k)
						? &src_b->format : &bch2_bkey_format_current, k))
				out[i]->format = KEY_FORMAT_LOCAL_BTREE;
			else
				bch2_bkey_unpack(src_b, (void *) out[i], k);

			out[i]->needs_whiteout = false;

			btree_keys_account_key_add(&n->nr, 0, out[i]);
			out[i] = bkey_p_next(out[i]);
		}
	}

	for (unsigned i = 0; i < 2; i++) {
		struct btree *n = dsts->data[i].b;

		bsets[i]->u64s = cpu_to_le16((u64 *) out[i] - bsets[i]->_data);

		BUG_ON(!bsets[i]->u64s);

		set_btree_bset_end(n, n->set);

		btree_node_reset_sib_u64s(n);

		bch2_verify_btree_nr_keys(n);

		BUG_ON(bch2_btree_node_check_topology(trans, n));
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

		bch2_btree_node_iter_init(trans->c, b, &node_iter, &bch2_keylist_front(keys)->k.p);

		try(bch2_btree_insert_keys_interior(as, trans, path, b, node_iter, keys));
	}

	return 0;
}

static void btree_node_op_log(struct printbuf *out, struct bch_fs *c,
			      struct btree *b,
			      darray_merge_node *srcs,
			      darray_merge_node *dsts)
{
	size_t max = btree_max_u64s(c);

	darray_for_each(*srcs, s) {
		prt_printf(out, "src %zu: ", (size_t) (s - srcs->data));
		if (s->b) {
			bch2_btree_pos_to_text(out, c, s->b);
			prt_newline(out);

			prt_printf(out, " live=%u (%zu%%) whiteout=%u remaining=%zu sib_u64s=[%u,%u]",
				   s->live_u64s,
				   (size_t) s->live_u64s * 100 / max,
				   s->b->whiteout_u64s,
				   bch2_btree_keys_u64s_remaining(s->b),
				   s->b->sib_u64s[0], s->b->sib_u64s[1]);
			prt_newline(out);
			printbuf_indent_add(out, 2);
			prt_str(out, "format: ");
			bch2_bkey_format_to_text(out, &s->b->format);
			prt_newline(out);
			printbuf_indent_sub(out, 2);
		} else {
			prt_printf(out, "(evicted) live=%u (%zu%%)",
				   s->live_u64s,
				   (size_t) s->live_u64s * 100 / max);
			prt_newline(out);
		}
	}

	darray_for_each(*dsts, d) {
		prt_printf(out, "dst %zu: ", (size_t) (d - dsts->data));
		bch2_btree_pos_to_text(out, c, d->b);
		prt_newline(out);

		prt_printf(out, " live=%u (%zu%%) whiteout=%u remaining=%zu sib_u64s=[%u,%u]",
			   d->b->nr.live_u64s,
			   (size_t) d->b->nr.live_u64s * 100 / max,
			   d->b->whiteout_u64s,
			   bch2_btree_keys_u64s_remaining(d->b),
			   d->b->sib_u64s[0], d->b->sib_u64s[1]);
		prt_newline(out);
		printbuf_indent_add(out, 2);
		prt_str(out, "format: ");
		bch2_bkey_format_to_text(out, &d->b->format);
		prt_newline(out);
		printbuf_indent_sub(out, 2);
	}
}

static int btree_split(struct btree_update *as, struct btree_trans *trans,
		       btree_path_idx_t path, struct btree *b,
		       struct keylist *keys)
{
	struct bch_fs *c = as->c;
	struct btree *parent = btree_node_parent(trans->paths + path, b);
	struct btree *n3 = NULL;
	u64 start_time = local_clock();
	int ret = 0;

	struct btree_merge_node dst_storage[2] = {};
	darray_merge_node dsts = {
		.data = dst_storage, .nr = 0, .size = 2,
	};

	bch2_verify_btree_nr_keys(b);
	BUG_ON(!parent && !btree_node_is_root(c, b));
	BUG_ON(parent && !btree_node_intent_locked(trans->paths + path, b->c.level + 1));

	try(bch2_btree_node_check_topology(trans, b));

	/* If we're splitting because an insert hit btree_node_full, compact
	 * is only useful if the failed key would actually fit afterwards.
	 * Otherwise we'd loop: compact produces same live_u64s, retry hits
	 * btree_node_full again. Two distinct cases:
	 *  - parent recursion (keys != NULL): the new keys are merged into
	 *    the post-compact bset directly, so we just need the combined
	 *    data to fit in the buffer.
	 *  - leaf retry (keys == NULL): the failed key arrives via trans
	 *    restart, going into a follow-on bset on the new node. Account
	 *    for write rounding (each bset write rounds up to block_bytes,
	 *    so a node whose live data rounds up to fill the whole sector
	 *    budget leaves no room for the follow-on bset).
	 */
	bool must_split = keys
		? b->nr.live_u64s + bch2_keylist_u64s(keys) > btree_max_u64s(c)
		: as->new_key_u64s &&
		  !bch2_btree_node_compact_fits(c, b, as->new_key_u64s);

	if (must_split || b->nr.live_u64s > BTREE_SPLIT_THRESHOLD(c)) {
		struct btree_merge_node split_src = { .trans = trans, .b = b };
		darray_merge_node split_srcs = {
			.data = &split_src, .nr = 1, .size = 1,
		};

		BUG_ON(!find_balanced_split(trans, &split_srcs, &dsts, keys,
					    &b->format,
					    (b->nr.live_u64s * 3) / 5, SIZE_MAX));

		darray_for_each(dsts, d) {
			d->trans = trans;
			d->b = bch2_btree_node_alloc(as, trans, b->c.level);
		}

		btree_pack_into_dsts(as, trans, &split_srcs, &dsts);

		if (keys) {
			ret =   btree_split_insert_keys(as, trans, path, dsts.data[0].b, keys) ?:
				btree_split_insert_keys(as, trans, path, dsts.data[1].b, keys);
			if (ret)
				goto err;
			BUG_ON(!bch2_keylist_empty(keys));
		}

		darray_for_each_reverse(dsts, d)
			bch2_btree_build_aux_trees(d->b);

		darray_for_each(dsts, d) {
			bch2_btree_update_add_new_node(as, d->b);

			d->path_idx = bch2_path_get_unlocked_mut(trans, as->btree_id,
								 d->b->c.level, d->b->key.k.p, false);
			mark_btree_node_locked(trans, trans->paths + d->path_idx,
					       d->b->c.level, BTREE_NODE_WRITE_LOCKED);
			bch2_btree_path_level_init(trans, trans->paths + d->path_idx, d->b);
		}

		/*
		 * Note that on recursive parent_keys == keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		darray_for_each(dsts, d)
			bch2_keylist_add(&as->parent_keys, &d->b->key);

		if (!parent) {
			/* Depth increases, make a new root */
			btree_path_idx_t path2 = dsts.data[1].path_idx;

			n3 = __btree_root_alloc(as, trans, b->c.level + 1);

			bch2_btree_update_add_new_node(as, n3);

			trans->paths[path2].locks_want++;
			BUG_ON(btree_node_locked(trans->paths + path2, n3->c.level));
			mark_btree_node_locked(trans, trans->paths + path2, n3->c.level, BTREE_NODE_WRITE_LOCKED);
			bch2_btree_path_level_init(trans, trans->paths + path2, n3);

			n3->sib_u64s[0] = U16_MAX;
			n3->sib_u64s[1] = U16_MAX;

			ret = btree_split_insert_keys(as, trans, path, n3, &as->parent_keys);
			if (ret)
				goto err;
		}
	} else {
		BUG_ON(darray_push(&dsts, ((struct btree_merge_node) {
			trans, bch2_btree_node_alloc_replacement(as, trans, b), 0,
		})));
		struct btree_merge_node *d = &dsts.data[0];

		if (keys) {
			ret = btree_split_insert_keys(as, trans, path, d->b, keys);
			if (ret)
				goto err;
			BUG_ON(!bch2_keylist_empty(keys));
		}

		bch2_btree_build_aux_trees(d->b);
		bch2_btree_update_add_new_node(as, d->b);

		d->path_idx = bch2_path_get_unlocked_mut(trans, as->btree_id,
							 d->b->c.level, d->b->key.k.p, false);
		mark_btree_node_locked(trans, trans->paths + d->path_idx,
				       d->b->c.level, BTREE_NODE_WRITE_LOCKED);
		bch2_btree_path_level_init(trans, trans->paths + d->path_idx, d->b);

		if (parent)
			bch2_keylist_add(&as->parent_keys, &d->b->key);
	}

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		ret = bch2_btree_insert_node(as, trans, path, parent, &as->parent_keys);
	} else if (n3) {
		ret = bch2_btree_set_root(as, trans, trans->paths + path, n3);
	} else {
		/* Root filled up but didn't need to be split */
		ret = bch2_btree_set_root(as, trans, trans->paths + path, dsts.data[0].b);
	}

	if (ret)
		goto err;

	{
		struct btree_merge_node src = { .b = b, .live_u64s = b->nr.live_u64s };
		darray_merge_node srcs = {
			.data = &src, .nr = 1, .size = 1,
		};

		if (dsts.nr == 2)
			event_inc_trace(c, btree_node_split, buf, ({
				btree_node_op_log(&buf, c, b, &srcs, &dsts);
			}));
		else
			event_inc_trace(c, btree_node_compact, buf, ({
				btree_node_op_log(&buf, c, b, &srcs, &dsts);
			}));
	}

	bch2_btree_interior_update_will_free_node(as, b);

	if (n3) {
		bch2_btree_update_get_open_buckets(as, n3);
		bch2_btree_node_write_trans(trans, n3, SIX_LOCK_write, 0);
		bch2_btree_update_add_node(c, &as->new_nodes, n3);
	}
	darray_for_each_reverse(dsts, d) {
		bch2_btree_update_get_open_buckets(as, d->b);
		bch2_btree_node_write_trans(trans, d->b, SIX_LOCK_write, 0);
		bch2_btree_update_add_node(c, &as->new_nodes, d->b);
	}

	/*
	 * The old node must be freed (in memory) _before_ unlocking the new
	 * nodes - else another thread could re-acquire a read lock on the old
	 * node after another thread has locked and updated the new node, thus
	 * seeing stale data:
	 */
	bch2_btree_node_free_inmem(trans, trans->paths + path, b);

	if (n3)
		bch2_trans_node_add(trans, trans->paths + path, n3);
	darray_for_each_reverse(dsts, d)
		bch2_trans_node_add(trans, trans->paths + d->path_idx, d->b);

out:
	darray_for_each_reverse(dsts, d) {
		if (d->path_idx) {
			__bch2_btree_path_unlock(trans, trans->paths + d->path_idx);
			bch2_path_put(trans, d->path_idx, true);
		}
	}

	bch2_trans_verify_locks(trans);

	bch2_time_stats_update(&c->times[dsts.nr == 2
			       ? BCH_TIME_btree_node_split
			       : BCH_TIME_btree_node_compact],
			       start_time);
	return ret;
err:
	if (n3)
		bch2_btree_node_free_never_used(as, trans, n3);
	darray_for_each_reverse(dsts, d)
		bch2_btree_node_free_never_used(as, trans, d->b);
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

	lockdep_assert_held(&c->gc.lock);
	BUG_ON(!b->c.level);
	BUG_ON(!as || as->b);
	bch2_verify_keylist_sorted(keys);

	if (!btree_node_intent_locked(path, b->c.level)) {
		CLASS(bch_log_msg, msg)(c);
		prt_printf(&msg.m, "%s(): node not locked at level %u\n",
			   __func__, b->c.level);
		bch2_btree_update_to_text(&msg.m, as);
		bch2_btree_path_to_text(&msg.m, trans, path_idx, path);
		bch2_fs_emergency_read_only(c, &msg.m);
		return -EIO;
	}

	try(bch2_btree_node_lock_write(trans, path, &b->c));

	bch2_btree_node_prep_for_write(trans, path, b);

	if (!bch2_btree_node_insert_fits(b, bch2_keylist_u64s(keys)))
		goto split;

	ret =   bch2_btree_node_check_topology(trans, b) ?:
		bch2_btree_insert_keys_interior(as, trans, path, b,
					path->l[b->c.level].iter, keys);
	if (ret)
		goto out_unlock;

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

	bch2_trans_revalidate_updates_in_node(trans, b);
	return 0;
split:
	/*
	 * We could attempt to avoid the transaction restart, by calling
	 * bch2_btree_path_upgrade() and allocating more nodes:
	 */
	if (b->c.level >= as->update_level_end) {
		event_inc_trace(c, trans_restart_split_race, buf, ({
			prt_printf(&buf, "%s\n", trans->fn);
			prt_printf(&buf, "l=%u written %u/%u u64s remaining %zu",
				   b->c.level,
				   b->written,
				   btree_blocks(c),
				   bch2_btree_keys_u64s_remaining(b));
		}));

		ret = btree_trans_restart(trans, BCH_ERR_transaction_restart_split_race);
		goto out_unlock;
	}

	ret = btree_split(as, trans, path_idx, b, keys);
out_unlock:
	bch2_trans_verify_locks(trans);
	return ret;
}

int bch2_btree_split_leaf(struct btree_trans *trans,
			  btree_path_idx_t path,
			  unsigned new_key_u64s,
			  enum bch_trans_commit_flags flags)
{
	/* btree_split & merge may both cause paths array to be reallocated */
	struct btree *b = path_l(trans->paths + path)->b;
	struct btree_update *as;
	unsigned l;
	int ret = 0;


	as = bch2_btree_update_start(trans, trans->paths + path,
				     trans->paths[path].level,
				     true, 0, flags, 0);
	if (IS_ERR(as))
		return PTR_ERR(as);

	as->new_key_u64s = new_key_u64s;

	ret = bch2_btree_node_lock_write(trans, trans->paths + path, &b->c);
	if (ret)
		goto err;

	ret = btree_split(as, trans, path, b, NULL);
	if (ret)
		goto err;

	bch2_btree_update_done(as, trans);

	for (l = trans->paths[path].level + 1;
	     btree_node_intent_locked(&trans->paths[path], l) && !ret;
	     l++)
		ret = bch2_foreground_maybe_merge(trans, path, l, flags, 0, NULL);

	return ret;
err:
	bch2_btree_update_free(as, trans);
	return ret;
}

static int __btree_increase_depth(struct btree_update *as, struct btree_trans *trans,
				   btree_path_idx_t path_idx)
{
	struct bch_fs *c = as->c;
	struct btree_path *path = trans->paths + path_idx;
	struct btree *b = bch2_btree_id_root(c, path->btree_id)->b;

	int ret = bch2_btree_node_lock_write(trans, path, &b->c);
	if (ret)
		return ret;

	struct btree *n = __btree_root_alloc(as, trans, b->c.level + 1);

	bch2_btree_update_add_new_node(as, n);

	path->locks_want++;
	BUG_ON(btree_node_locked(path, n->c.level));
	mark_btree_node_locked(trans, path, n->c.level, BTREE_NODE_WRITE_LOCKED);
	bch2_btree_path_level_init(trans, path, n);

	n->sib_u64s[0] = U16_MAX;
	n->sib_u64s[1] = U16_MAX;

	bch2_keylist_add(&as->parent_keys, &b->key);
	btree_split_insert_keys(as, trans, path_idx, n, &as->parent_keys);

	ret = bch2_btree_set_root(as, trans, path, n);
	if (ret) {
		bch2_btree_node_free_never_used(as, trans, n);
		return ret;
	}

	bch2_btree_update_get_open_buckets(as, n);
	bch2_btree_node_write_trans(trans, n, SIX_LOCK_write, 0);
	bch2_btree_update_add_node(c, &as->new_nodes, n);
	bch2_trans_node_add(trans, path, n);

	bch2_btree_node_unlock_write(trans, path, b);

	/*
	 * Old root is no longer a root: clearing permanent makes it
	 * eligible for reclaim again. The node stayed hashed and on
	 * bc->list throughout its tenure as root (it was protected by
	 * the flag, not by being off-list), so no list/hash work is
	 * needed here.
	 */
	scoped_guard(mutex, &c->btree.cache.lock)
		clear_btree_node_permanent(b);

	bch2_trans_verify_locks(trans);
	return 0;
}

int bch2_btree_increase_depth(struct btree_trans *trans, btree_path_idx_t path, unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct btree *b = bch2_btree_id_root(c, trans->paths[path].btree_id)->b;

	if (btree_node_fake(b))
		return bch2_btree_split_leaf(trans, path, 0, flags);

	struct btree_update *as =
		bch2_btree_update_start(trans, trans->paths + path, b->c.level,
					true, 0, flags, 0);
	if (IS_ERR(as))
		return PTR_ERR(as);

	int ret = __btree_increase_depth(as, trans, path);
	if (ret) {
		bch2_btree_update_free(as, trans);
		return ret;
	}

	bch2_btree_update_done(as, trans);
	return 0;
}

/*
 * Verify each pair of consecutive source nodes is contiguous: the
 * successor of prev's max_key must equal next's min_key. Anything
 * else is btree topology corruption and we bail before committing
 * anything.
 */
static int btree_merge_topology_check(struct bch_fs *c, darray_merge_node *srcs)
{
	for (struct btree_merge_node *s = srcs->data + 1; s < srcs->data + srcs->nr; s++) {
		struct btree *prev = s[-1].b, *next = s[0].b;

		if (bpos_eq(bpos_successor(prev->data->max_key), next->data->min_key))
			continue;

		CLASS(bch_log_msg, msg)(c);

		prt_str(&msg.m, "btree node merge: end of prev node doesn't match start of next node\n");

		prt_printf(&msg.m, "prev ends at   ");
		bch2_bpos_to_text(&msg.m, prev->data->max_key);
		prt_newline(&msg.m);

		prt_printf(&msg.m, "next starts at ");
		bch2_bpos_to_text(&msg.m, next->data->min_key);
		prt_newline(&msg.m);

		return __bch2_topology_error(c, &msg.m);
	}
	return 0;
}

/*
 * Try to fetch @pivot's sibling on side @sib and push it onto @dst:
 *   1. Skip if pivot is at the btree boundary on this side
 *   2. Skip if pivot->sib_u64s[sib] (cached estimate) exceeds @threshold
 *   3. Get + traverse a path at the sibling's position. Try nofill first;
 *      on miss, look up the evicted-size hash table via the parent's
 *      now-locked iter. If we get an estimate, push with @b NULL and
 *      defer the real traverse until after the caller's size check.
 *      Otherwise pay for the real read.
 *   4. Skip if sibling has a different parent (only when @b is set —
 *      deferred srcs validate parent post-fill; the post-update_start
 *      recheck catches the rest).
 *
 * On boundary or different-parent skip, sets pivot->sib_u64s[sib] = U16_MAX
 * so future calls bail cheaply at step 2.
 *
 * Capacity in @dst must already be reserved by the caller.
 *
 * Returns:
 *   0       on push or any skip
 *   < 0     real error (trans restart from path traverse); path
 *           is put before returning
 */
static int btree_merge_push_pos(struct btree_trans *trans,
				darray_merge_node *dst,
				enum btree_id btree_id,
				unsigned level,
				btree_path_idx_t pivot_path,
				enum btree_node_sibling sib)
{
	struct btree *pivot	= trans->paths[pivot_path].l[level].b;
	struct btree *parent	= trans->paths[pivot_path].l[level + 1].b;

	if ((sib == btree_prev_sib && bpos_eq(pivot->data->min_key, POS_MIN)) ||
	    (sib == btree_next_sib && bpos_eq(pivot->data->max_key, SPOS_MAX))) {
		pivot->sib_u64s[sib] = U16_MAX;
		return 0;
	}

	struct bch_fs *c = trans->c;

	if (pivot->sib_u64s[sib] > c->btree.foreground_merge_threshold)
		return 0;

	struct bpos pos = sib == btree_prev_sib
		? bpos_predecessor(pivot->data->min_key)
		: bpos_successor(pivot->data->max_key);

	btree_path_idx_t path = bch2_path_get(trans, btree_id, pos,
					      level + 1, level,
					      BTREE_ITER_intent, _RET_IP_);

	int ret = bch2_btree_path_traverse(trans, path, BTREE_ITER_nofill);
	struct btree *b = NULL;
	u16 live_u64s = 0;

	if (!ret) {
		b = trans->paths[path].l[level].b;
		live_u64s = b->nr.live_u64s;
	} else if (bch2_err_matches(ret, BCH_ERR_no_btree_node_nofill)) {
		/*
		 * Nofill failure dropped all of the path's locks, but left
		 * l[level + 1].b pointing at the parent. Relock the parent
		 * so we can read its iter for the sibling's btree pointer
		 * and check the evicted-size hash before paying for a real
		 * read. If the relock fails (parent's lock_seq advanced) or
		 * the hash misses, fall through to a real traverse.
		 *
		 * The sibling path's locks_want only covers @level, so the
		 * level+1 lock we just acquired is outside its want range
		 * and would trip bch2_btree_path_verify_locks. Drop it once
		 * we've copied the sibling's btree_ptr off the parent.
		 */
		if (!bch2_btree_node_relock(trans, trans->paths + path, level + 1)) {
			bch2_path_put(trans, path, true);
			return btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_node_reused);
		}

		struct btree *sib_parent = trans->paths[path].l[level + 1].b;
		struct bkey_packed *sib_packed =
			bch2_btree_node_iter_peek_all(&trans->paths[path].l[level + 1].iter,
						      sib_parent);

		if (!sib_packed) {
			btree_node_unlock(trans, trans->paths + path, level + 1);
			bch2_path_put(trans, path, true);
			return 0;
		}

		struct bkey unpacked;
		struct bkey_s_c sib_k = bkey_disassemble(sib_parent, sib_packed, &unpacked);
		BKEY_PADDED_ONSTACK(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;
		bkey_reassemble(&tmp.k, sib_k);

		btree_node_unlock(trans, trans->paths + path, level + 1);

		u64 hash = btree_ptr_hash_val(&tmp.k);
		u16 est;
		if (hash && bch2_btree_evicted_size_lookup(c, hash, &est)) {
			live_u64s = est;
		} else {
			ret = bch2_btree_path_traverse(trans, path, 0);
			if (ret) {
				bch2_path_put(trans, path, true);
				return ret;
			}
			b = trans->paths[path].l[level].b;
			live_u64s = b->nr.live_u64s;
		}
	} else {
		bch2_path_put(trans, path, true);
		return ret;
	}

	if (b && btree_node_parent(trans->paths + path, b) != parent) {
		bch2_path_put(trans, path, true);
		pivot->sib_u64s[sib] = U16_MAX;
		return 0;
	}

	if (b)
		btree_path_set_should_be_locked(trans, trans->paths + path);

	BUG_ON(darray_push(dst, ((struct btree_merge_node) { trans, b, path, live_u64s })));
	return 0;
}

static size_t merge_node_u64s_and_format(darray_merge_node *nodes, struct bkey_format *new_f)
{
	bool have_all = true;
	darray_for_each(*nodes, s)
		if (!s->b)
			have_all = false;

	size_t total_u64s = 0;
	if (have_all) {
		struct bkey_format_state new_s;
		bch2_bkey_format_init(&new_s);
		bch2_bkey_format_add_pos(&new_s, nodes->data[0].b->data->min_key);
		darray_for_each(*nodes, s)
			__bch2_btree_calc_format(&new_s, s->b);
		bch2_bkey_format_add_pos(&new_s, darray_last(*nodes).b->data->max_key);
		*new_f = bch2_bkey_format_done(&new_s);

		darray_for_each(*nodes, s)
			total_u64s += btree_node_u64s_with_format(s->b->nr, &s->b->format, new_f);
	} else {
		darray_for_each(*nodes, s)
			total_u64s += s->live_u64s;
	}
	return total_u64s;
}

static void merge_fail_reset_sib_u64s_at(struct bch_fs *c, struct btree *b,
					 enum btree_node_sibling sib,
					 unsigned sib_live_u64s)
{
	unsigned sib_u64s = b->nr.live_u64s + sib_live_u64s;

	if (sib_u64s > BTREE_FOREGROUND_MERGE_HYSTERESIS(c))
		sib_u64s -= (sib_u64s - BTREE_FOREGROUND_MERGE_HYSTERESIS(c)) / 2;

	sib_u64s = min(sib_u64s, (unsigned) U16_MAX - 1);

	b->sib_u64s[sib] = sib_u64s;
}

static void merge_fail_reset_sib_u64s(struct bch_fs *c, struct btree *b,
				      struct btree_merge_node *s)
{
	if (s->b == b)
		return;

	/*
	 * For deferred srcs (b == NULL), use the path's pos to determine
	 * which side it's on — pos was set to bpos_predecessor/successor of
	 * the pivot's keyspace at bch2_path_get time, so it never overlaps.
	 */
	enum btree_node_sibling sib = s->b
		? (bpos_lt(s->b->key.k.p, b->key.k.p) ? btree_prev_sib : btree_next_sib)
		: (bpos_lt(s->trans->paths[s->path_idx].pos, b->data->min_key) ? btree_prev_sib : btree_next_sib);

	merge_fail_reset_sib_u64s_at(c, b, sib, s->live_u64s);
}

/*
 * Per-candidate scratch for find_balanced_split's iteration. After the best
 * candidate is picked, its pivot/format pair is committed onto the dsts
 * entries' .max_key/.format and this struct is discarded.
 */
struct split_layout {
	struct bpos		pivot;
	struct bkey_format	format[2];
	size_t			size[2];
};

/*
 * Walk every src key once and produce a split_layout: per-side format /
 * size / pivot. Two pivot policies:
 *
 *   @n1_target_u64s == 0: static @pivot, partition by key.p <= pivot.
 *   @n1_target_u64s != 0: running u64s, place keys on side[0] until cumulative
 *     reaches @n1_target_u64s. On interior nodes shift past a deleted-in-journal
 *     or deleted-in-@insert_keys cross-key (parent reference can't point at a
 *     to-be-deleted key). The eventual pivot is the last unshifted side[0] key.
 */
static void predict_split(struct btree_trans *trans,
			  darray_merge_node *srcs,
			  struct keylist *insert_keys,
			  unsigned n1_target_u64s,
			  struct bpos pivot,
			  struct split_layout *out)
{
	struct bkey_format_state state[2];
	struct { unsigned nr_keys, val_u64s; } counts[2];
	struct bkey_packed *k;
	struct btree_node_iter iter;
	unsigned u64s = 0, n1_u64s = n1_target_u64s;

	memset(counts, 0, sizeof(counts));
	bch2_bkey_format_init(&state[0]);
	bch2_bkey_format_init(&state[1]);

	if (n1_target_u64s)
		pivot = POS_MIN;

	darray_for_each(*srcs, s) {
		struct btree *src_b = s->b;

		for_each_btree_node_key(src_b, k, &iter) {
			if (bkey_deleted(k))
				continue;

			struct bkey uk = bkey_unpack_key(src_b, k);
			unsigned i;

			if (n1_target_u64s) {
				bool shifted = src_b->c.level &&
					u64s < n1_u64s &&
					u64s + k->u64s >= n1_u64s &&
					(bch2_key_deleted_in_journal(trans, src_b->c.btree_id, src_b->c.level, uk.p) ||
					 key_deleted_in_insert(insert_keys, uk.p));
				if (shifted)
					n1_u64s += k->u64s;

				i = u64s >= n1_u64s;
				u64s += k->u64s;
				if (!i && !shifted)
					pivot = uk.p;
			} else {
				i = bpos_le(uk.p, pivot) ? 0 : 1;
			}

			bch2_bkey_format_add_key(&state[i], &uk);
			counts[i].nr_keys++;
			counts[i].val_u64s += bkeyp_val_u64s(&src_b->format, k);
		}
	}

	bch2_bkey_format_add_pos(&state[0], srcs->data[0].b->data->min_key);
	bch2_bkey_format_add_pos(&state[0], pivot);
	bch2_bkey_format_add_pos(&state[1], bpos_successor(pivot));
	bch2_bkey_format_add_pos(&state[1], darray_last(*srcs).b->data->max_key);

	out->pivot = pivot;
	for (unsigned i = 0; i < 2; i++) {
		out->format[i] = bch2_bkey_format_done(&state[i]);
		out->size[i] = counts[i].nr_keys * out->format[i].key_u64s +
			       counts[i].val_u64s;
	}
}

/*
 * Pick a split pivot for @srcs and commit per-side .format / .max_key onto
 * @dsts (2 placeholder entries pushed; .b filled by caller).
 *
 * Splitter: @n1_target_u64s != 0 — single layout via predict_split's running
 * mode (journal-delete-aware shift uses @insert_keys + @trans). Accepted
 * unconditionally; caller is committed to splitting.
 *
 * Merger: @n1_target_u64s == 0 — three candidates (natural breaks at
 * srcs[0]/srcs[nr-2] max_key + mid-stream at total_live/2), pick the one
 * minimizing max(size[0], size[1]) with non-empty sides. Bail if best
 * exceeds @split_thresh.
 *
 * @fallback_format (optional) replaces a per-side predicted format that
 * overflows the node buf; mergers gate at split_thresh < btree_max so they
 * pass NULL. Returns false on bail.
 */
static bool find_balanced_split(struct btree_trans *trans,
				darray_merge_node *srcs,
				darray_merge_node *dsts,
				struct keylist *insert_keys,
				struct bkey_format *fallback_format,
				unsigned n1_target_u64s,
				size_t split_thresh)
{
	struct split_layout best = {};
	bool have_best = false;

	if (n1_target_u64s) {
		predict_split(trans, srcs, insert_keys, n1_target_u64s, POS_MIN, &best);
		have_best = true;
	} else {
		struct bpos candidates[3];
		unsigned nr_candidates = 0;

		candidates[nr_candidates++] = srcs->data[0].b->data->max_key;
		if (srcs->nr >= 3)
			candidates[nr_candidates++] = srcs->data[srcs->nr - 2].b->data->max_key;

		size_t total_live = 0;
		darray_for_each(*srcs, s)
			total_live += s->b->nr.live_u64s;

		size_t target = total_live / 2;
		size_t curr = 0;
		struct bkey_packed *k;
		struct btree_node_iter iter;
		darray_for_each(*srcs, s) {
			bool found = false;
			for_each_btree_node_key(s->b, k, &iter) {
				if (bkey_deleted(k))
					continue;
				curr += k->u64s;
				if (curr >= target) {
					struct bkey uk = bkey_unpack_key(s->b, k);
					candidates[nr_candidates++] = uk.p;
					found = true;
					break;
				}
			}
			if (found)
				break;
		}

		for (unsigned i = 0; i < nr_candidates; i++) {
			struct split_layout cand;
			predict_split(NULL, srcs, NULL, 0, candidates[i], &cand);

			/*
			 * Empty-side candidate scores 0 on its empty side and
			 * would beat a balanced candidate whose far side
			 * inherits a wide format from the trailing src's
			 * max_key. Reject before the min-worst comparison.
			 */
			if (!cand.size[0] || !cand.size[1])
				continue;

			size_t cand_worst = max(cand.size[0], cand.size[1]);
			size_t best_worst = have_best ? max(best.size[0], best.size[1]) : SIZE_MAX;

			if (cand_worst < best_worst) {
				best = cand;
				have_best = true;
			}
		}
	}

	if (!have_best || max(best.size[0], best.size[1]) > split_thresh)
		return false;

	if (fallback_format) {
		size_t buf_bytes = btree_buf_bytes(srcs->data[0].b);

		for (unsigned i = 0; i < 2; i++)
			if (__vstruct_bytes(struct btree_node, best.size[i]) > buf_bytes)
				best.format[i] = *fallback_format;
	}

	BUG_ON(darray_push(dsts, ((struct btree_merge_node) {
		.format = best.format[0],
		.max_key = best.pivot,
	})));
	BUG_ON(darray_push(dsts, ((struct btree_merge_node) {
		.format = best.format[1],
		.max_key = darray_last(*srcs).b->data->max_key,
	})));
	return true;
}

/*
 * Decide how many dsts the merge should produce and, if @dsts is non-NULL
 * (have-all mode: every src has ->b set), populate @dsts entries with the
 * per-dst format and max_key the pack core will read.
 *
 * Returns nr_dsts. Returns srcs->nr (the bail signal) if either the merge
 * cannot fit in fewer dsts than srcs, or — in have-all mode — find_balanced_split
 * found no candidate pivot whose worst dst stays under split_thresh.
 */
static unsigned compute_merge(struct bch_fs *c, struct btree *b,
			      darray_merge_node *srcs,
			      darray_merge_node *dsts,
			      struct bkey_format *new_f)
{
	size_t total_u64s = merge_node_u64s_and_format(srcs, new_f);
	/*
	 * Choose dst count: one node if everything packs into max, two nodes
	 * (pack via btree_pack_into_dsts) if 3 srcs overflow but fit in 2x max.
	 * Anything else falls through to the bail check below.
	 *
	 * Strict less-than: bch2_btree_node_format_fits() and the write path
	 * both treat btree_max_u64s as an open upper bound (the +8 varint slop
	 * in btree_node_write tips a node packed at exact-max into overflow).
	 */
	unsigned nr_dsts = max(1, DIV_ROUND_UP(total_u64s,
					       BTREE_FOREGROUND_MERGE_HIGHER_THRESHOLD(c)));

	if (nr_dsts >= srcs->nr) {
		if (srcs->nr == 3) {
			struct btree_merge_node *remove =
				srcs->data[0].live_u64s > darray_last(*srcs).live_u64s
				? srcs->data : &darray_last(*srcs);

			merge_fail_reset_sib_u64s(c, b, remove);
			btree_merge_node_put(*remove);
			darray_remove_item(srcs, remove);

			total_u64s = merge_node_u64s_and_format(srcs, new_f);

			nr_dsts = max(1, DIV_ROUND_UP(total_u64s, btree_max_u64s(c) / 2));
		}
	}

	if (nr_dsts >= srcs->nr) {
		darray_for_each(*srcs, s)
			merge_fail_reset_sib_u64s(c, b, s);
		return nr_dsts;
	}

	if (!dsts)
		return nr_dsts;

	if (nr_dsts == 1) {
		BUG_ON(darray_push(dsts, ((struct btree_merge_node) {
			.format	 = *new_f,
			.max_key = darray_last(*srcs).b->data->max_key,
		})));
	} else if (!find_balanced_split(srcs->data[0].trans, srcs, dsts,
					NULL, NULL, 0, BTREE_SPLIT_THRESHOLD(c))) {
		/*
		 * 2-way split is infeasible (no candidate keeps both sides
		 * non-empty under split_thresh). Empty trailing srcs can force
		 * total_u64s above HIGHER_THRESHOLD via format bloat from a
		 * POS_MAX max_key, even though the actual key count fits in a
		 * single node. If it does fit, fall through to a 1-dst merge
		 * rather than abandon the consolidation.
		 */
		if (__vstruct_bytes(struct btree_node, total_u64s) <
		    btree_buf_bytes(b)) {
			nr_dsts = 1;
			BUG_ON(darray_push(dsts, ((struct btree_merge_node) {
				.format	 = *new_f,
				.max_key = darray_last(*srcs).b->data->max_key,
			})));
		} else {
			darray_for_each(*srcs, s)
				merge_fail_reset_sib_u64s(c, b, s);
			return srcs->nr;
		}
	}

	return nr_dsts;
}

int __bch2_foreground_maybe_merge(struct btree_trans *trans,
				  btree_path_idx_t path,
				  unsigned level,
				  enum bch_trans_commit_flags flags,
				  u64 *merge_count)
{
	struct bch_fs *c = trans->c;
	struct btree_update *as = NULL;
	enum btree_id btree = trans->paths[path].btree_id;
	u64 start_time = local_clock();
	int ret = 0;

	CLASS(darray_merge_node, srcs)();
	CLASS(darray_merge_node, dsts)();

	try(darray_make_room(&srcs, 3));
	try(darray_make_room(&dsts, 2));

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

	struct btree *b = trans->paths[path].l[level].b;

	if (bpos_eq(b->data->min_key, POS_MIN))
		b->sib_u64s[btree_prev_sib] = U16_MAX;
	if (bpos_eq(b->data->max_key, SPOS_MAX))
		b->sib_u64s[btree_next_sib] = U16_MAX;

	/*
	 * Push srcs in left-to-right order so srcs is naturally sorted: prev
	 * sibling first (if merging left), then caller's node, then next
	 * sibling (if merging right). The caller's path takes an extra ref so
	 * the destructor can put it uniformly with helper-acquired paths.
	 */
	try(btree_merge_push_pos(trans, &srcs, btree, level, path, btree_prev_sib));

	__btree_path_get(trans, trans->paths + path, true);
	BUG_ON(darray_push(&srcs, ((struct btree_merge_node) {
		trans, b, path, b->nr.live_u64s,
	})));

	try(btree_merge_push_pos(trans, &srcs, btree, level, path, btree_next_sib));

	if (srcs.nr == 1)
		return 0;

	event_inc_trace(c, btree_node_merge_attempt, buf, ({
		unsigned total_u64s = 0;
		darray_for_each(srcs, s) {
			if (s->b)
				bch2_btree_pos_to_text(&buf, c, s->b);
			else
				prt_str(&buf, "(evicted node)");
			prt_printf(&buf, "\nlive u64s %u (%zu%% full)\n",
				   s->live_u64s,
				   s->live_u64s * 100 / btree_max_u64s(c));
			total_u64s += s->live_u64s;
		}

		prt_printf(&buf, "Pivot sib_u64s %u %u threshold %u\n",
			   b->sib_u64s[btree_prev_sib],
			   b->sib_u64s[btree_next_sib],
			   c->btree.foreground_merge_threshold);
		bch2_btree_pos_to_text(&buf, c, b);

		prt_printf(&buf, "\ntotal_u64s %u per-node max %zu nr_dsts %un",
			   total_u64s, BTREE_FOREGROUND_MERGE_HIGHER_THRESHOLD(c),
			   max_t(unsigned, 1,
				 DIV_ROUND_UP(total_u64s, BTREE_FOREGROUND_MERGE_HIGHER_THRESHOLD(c))));
	}));

	struct bkey_format new_f;
	unsigned nr_dsts = compute_merge(c, b, &srcs, NULL, &new_f);
	if (nr_dsts >= srcs.nr)
		goto out;

	/*
	 * Estimate-based gate said the merge will fit — fill (or re-traverse)
	 * any srcs whose path isn't currently should_be_locked. Deferred srcs
	 * pushed without a real read fall here; so do any srcs whose locks
	 * may have been dropped since push (a !should_be_locked path won't
	 * get relocked by unlock/relock cycles).
	 *
	 * On parent-identity mismatch, poison that side's cached estimate
	 * and drop the src — saves us the bch2_btree_update_start cost that
	 * the post-update_start recheck would otherwise discover.
	 */
	for (unsigned i = 0; i < srcs.nr;) {
		struct btree_merge_node *s = &srcs.data[i];

		if (trans->paths[s->path_idx].should_be_locked) {
			i++;
			continue;
		}

		ret = bch2_btree_path_traverse(trans, s->path_idx, 0);
		if (ret)
			goto err;

		s->b = trans->paths[s->path_idx].l[level].b;
		s->live_u64s = s->b->nr.live_u64s;

		if (btree_node_parent(trans->paths + s->path_idx, s->b) !=
		    trans->paths[path].l[level + 1].b) {
			enum btree_node_sibling bad =
				bpos_lt(s->b->data->max_key, b->data->min_key)
				? btree_prev_sib
				: btree_next_sib;
			b->sib_u64s[bad] = U16_MAX;
			btree_merge_node_put(*s);
			darray_remove_item(&srcs, s);
			continue;
		}

		btree_path_set_should_be_locked(trans, trans->paths + s->path_idx);
		i++;
	}

	try(btree_merge_topology_check(c, &srcs));

	if (srcs.nr == 1)
		goto out;

	/*
	 * Post deferred-fill, every surviving src must have ->b set so that
	 * compute_merge() / merge_node_u64s_and_format() takes the precise
	 * format-aware path. The estimate-only fallback (sum of live_u64s)
	 * doesn't account for format growth on repack and would let an
	 * infeasible merge through, blowing up later in btree_pack_into_dsts
	 * or sort_into.
	 */
	darray_for_each(srcs, s)
		BUG_ON(!s->b);

	nr_dsts = compute_merge(c, b, &srcs, &dsts, &new_f);
	if (nr_dsts >= srcs.nr)
		goto out;

	BUG_ON(nr_dsts > 2);

	as = bch2_btree_update_start(trans, trans->paths + path, level, nr_dsts == 2,
				     0, BCH_TRANS_COMMIT_no_enospc|flags, 0);
	ret = PTR_ERR_OR_ZERO(as);
	if (ret) {
		as = NULL;
		goto err;
	}

	/*
	 * update_start upgraded path's locks to cover parent nodes; re-read
	 * parent and re-verify all srcs still share it. The earlier check in
	 * btree_merge_push_pos() was racy because parents weren't locked.
	 *
	 * On mismatch, identify which side the bad sibling is on by bpos
	 * comparison and poison just that side's cached estimate.
	 */
	struct btree *parent = btree_node_parent(trans->paths + path, b);
	darray_for_each(srcs, s) {
		if (s->path_idx == path)
			continue;
		if (btree_node_parent(trans->paths + s->path_idx, s->b) != parent) {
			enum btree_node_sibling bad_sib =
				bpos_lt(s->b->data->max_key, b->data->min_key)
					? btree_prev_sib
					: btree_next_sib;
			b->sib_u64s[bad_sib] = U16_MAX;
			bch2_btree_update_free(as, trans);
			as = NULL;
			ret = 0;
			goto out;
		}
	}

	as->node_start	= srcs.data[0].b->data->min_key;
	as->node_end	= srcs.data[srcs.nr - 1].b->data->max_key;

	darray_for_each(srcs, s) {
		ret = bch2_btree_node_lock_write(trans, trans->paths + s->path_idx, &s->b->c);
		if (ret)
			goto err_free_update;
	}

	/*
	 * Allocate destination nodes: 1 for plain N->1, 2 for the 3->2 case.
	 * compute_merge() already populated dsts entries with their per-dst
	 * format and max_key — here we just attach trans + a freshly allocated
	 * btree node to each. path_idx is filled in after the pack since each
	 * dst's key.k.p (== max_key) is set inside btree_set_max().
	 */
	darray_for_each(dsts, d) {
		d->trans = trans;
		d->b = bch2_btree_node_alloc(as, trans, level);
	}

	if (nr_dsts == 1) {
		struct btree *n = dsts.data[0].b;
		u64 max_seq = 0;

		darray_for_each(srcs, s)
			max_seq = max(max_seq, BTREE_NODE_SEQ(s->b->data));
		SET_BTREE_NODE_SEQ(n->data, max_seq + 1);

		btree_set_min(n, srcs.data[0].b->data->min_key);
		btree_set_max(n, dsts.data[0].max_key);

		n->data->format = dsts.data[0].format;
		btree_node_set_format(n, n->data->format);

		darray_for_each(srcs, s)
			bch2_btree_sort_into(c, n, s->b);

		ret = bch2_btree_node_check_topology(trans, n);
		BUG_ON(ret);

		btree_node_reset_sib_u64s(n);
	} else {
		btree_pack_into_dsts(as, trans, &srcs, &dsts);
	}

	/*
	 * Diagnostic: each dst's packed content must fit in btree_buf_bytes
	 * with room for the +8 varint slop in btree_node_write. Mirrors
	 * bch2_btree_node_format_fits()'s strict-less-than check.
	 */
	darray_for_each(dsts, d)
		BUG_ON(__vstruct_bytes(struct btree_node, d->b->data->u64s) >=
		       btree_buf_bytes(d->b));

	darray_for_each(dsts, d) {
		bch2_btree_build_aux_trees(d->b);
		bch2_btree_update_add_new_node(as, d->b);

		d->path_idx = bch2_path_get_unlocked_mut(trans, btree,
							 d->b->c.level, d->b->key.k.p, false);
		six_lock_increment(&d->b->c.lock, SIX_LOCK_intent);
		mark_btree_node_locked(trans, trans->paths + d->path_idx,
				       d->b->c.level, BTREE_NODE_WRITE_LOCKED);
		bch2_btree_path_level_init(trans, trans->paths + d->path_idx, d->b);
	}

	/*
	 * Conceptually: every src becomes a delete, every dst becomes a new
	 * key, sorted and deduped (a new key at the same .p as a delete
	 * subsumes the delete). For N -> 1 the last src's .p equals the dst's
	 * .p (the dst's max_key was set to the last src's max_key), so the
	 * last src's delete is the only one that gets dropped.
	 *
	 * Both parent_keys (the in-memory parent update) and new_nodes (the
	 * journal record) need each surviving delete; emit them together.
	 */
	struct btree_merge_node *src = srcs.data;
	struct btree_merge_node *dst = dsts.data;
	while (src || dst) {
		if (src && dst && bpos_eq(src->b->key.k.p, dst->b->key.k.p)) {
			bch2_btree_update_add_node(c, &as->new_nodes, dst->b);
			bch2_keylist_add(&as->parent_keys, &dst->b->key);
			src++;
			dst++;
		} else if (src && (dst ? bpos_lt(src->b->key.k.p, dst->b->key.k.p) : true)) {
			struct bkey_i delete;
			bkey_init(&delete.k);
			delete.k.p = src->b->key.k.p;
			bch2_keylist_add(&as->parent_keys, &delete);
			bch2_btree_update_add_key(&as->new_nodes, level, &delete);
			src++;
		} else {
			bch2_btree_update_add_node(c, &as->new_nodes, dst->b);
			bch2_keylist_add(&as->parent_keys, &dst->b->key);
			dst++;
		}

		if (src == srcs.data + srcs.nr)
			src = NULL;
		if (dst == dsts.data + dsts.nr)
			dst = NULL;
	}

	bch2_trans_verify_paths(trans);

	ret = bch2_btree_insert_node(as, trans, path, parent, &as->parent_keys);
	if (ret)
		goto err_free_new_node;

	event_inc_trace(c, btree_node_merge, buf, ({
		btree_node_op_log(&buf, c, b, &srcs, &dsts);
	}));

	darray_for_each(srcs, s)
		bch2_btree_interior_update_will_free_node(as, s->b);

	bch2_trans_verify_paths(trans);

	darray_for_each(dsts, d) {
		bch2_btree_update_get_open_buckets(as, d->b);
		bch2_btree_node_write_trans(trans, d->b, SIX_LOCK_write, 0);
	}

	darray_for_each(srcs, s)
		bch2_btree_node_free_inmem(trans, trans->paths + s->path_idx, s->b);

	darray_for_each(dsts, d)
		bch2_trans_node_add(trans, trans->paths + d->path_idx, d->b);

	bch2_trans_verify_paths(trans);

	darray_for_each(dsts, d)
		six_unlock_intent(&d->b->c.lock);

	bch2_btree_update_done(as, trans);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_merge], start_time);

	if (merge_count)
		(*merge_count)++;
out:
err:
	bch2_trans_verify_locks(trans);
	if (ret == -BCH_ERR_journal_reclaim_would_deadlock)
		ret = 0;
	if (!ret)
		ret = bch2_trans_relock(trans);
	return ret;
err_free_new_node:
	darray_for_each(dsts, d)
		bch2_btree_node_free_never_used(as, trans, d->b);
err_free_update:
	darray_for_each_reverse(srcs, s)
		if (btree_node_write_locked(trans->paths + s->path_idx, s->b->c.level))
			bch2_btree_node_unlock_write(trans, trans->paths + s->path_idx, s->b);
	if (as)
		bch2_btree_update_free(as, trans);
	goto out;
}

int bch2_btree_node_get_iter(struct btree_trans *trans, struct btree_iter *iter, struct btree *b)
{
	bch2_trans_node_iter_init(trans, iter, b->c.btree_id, b->key.k.p,
				  BTREE_MAX_DEPTH, b->c.level,
				  BTREE_ITER_intent);
	try(bch2_btree_iter_traverse(iter));

	/* has node been freed? */
	if (btree_iter_path(trans, iter)->l[b->c.level].b != b) {
		/* node has been freed: */
		BUG_ON(!btree_node_dying(b));
		return bch_err_throw(trans->c, btree_node_dying);
	}

	BUG_ON(!btree_node_hashed(b));
	return 0;
}

static int bch2_btree_node_rewrite(struct btree_trans *trans,
				   struct btree_iter *iter,
				   struct btree *b,
				   unsigned target,
				   enum bch_trans_commit_flags commit_flags,
				   enum bch_write_flags write_flags)
{
	BUG_ON(btree_node_fake(b));

	struct bch_fs *c = trans->c;
	struct btree *parent;
	btree_path_idx_t new_path = 0;

	commit_flags |= BCH_TRANS_COMMIT_no_enospc;

	struct btree_path *path = btree_iter_path(trans, iter);
	parent = btree_node_parent(path, b);
	struct btree_update *as =
		bch2_btree_update_start(trans, path, b->c.level, false, target,
					commit_flags, write_flags);
	int ret = PTR_ERR_OR_ZERO(as);
	if (ret)
		goto out;

	ret = bch2_btree_node_lock_write(trans, path, &b->c);
	if (ret)
		goto err_free_update;

	struct btree *n = bch2_btree_node_alloc_replacement(as, trans, b);

	bch2_btree_build_aux_trees(n);
	bch2_btree_update_add_new_node(as, n);

	new_path = bch2_path_get_unlocked_mut(trans, iter->btree_id, n->c.level, n->key.k.p, false);
	mark_btree_node_locked(trans, trans->paths + new_path, n->c.level, BTREE_NODE_WRITE_LOCKED);
	bch2_btree_path_level_init(trans, trans->paths + new_path, n);

	if (parent) {
		bch2_keylist_add(&as->parent_keys, &n->key);
		ret = bch2_btree_insert_node(as, trans, iter->path, parent, &as->parent_keys);
	} else {
		ret = bch2_btree_set_root(as, trans, btree_iter_path(trans, iter), n);
	}

	if (ret)
		goto err_free_node;

	trace_btree_node(c, b, btree_node_rewrite);

	bch2_btree_interior_update_will_free_node(as, b);

	bch2_btree_update_get_open_buckets(as, n);
	bch2_btree_node_write_trans(trans, n, SIX_LOCK_write, 0);
	bch2_btree_update_add_node(c, &as->new_nodes, n);

	bch2_btree_node_free_inmem(trans, btree_iter_path(trans, iter), b);

	bch2_trans_node_add(trans, trans->paths + iter->path, n);

	bch2_btree_update_done(as, trans);
out:
	if (new_path)
		bch2_path_put(trans, new_path, true);
	bch2_trans_downgrade(trans);
	return ret;
err_free_node:
	bch2_btree_node_free_never_used(as, trans, n);
err_free_update:
	bch2_btree_update_free(as, trans);
	goto out;
}

int bch2_btree_node_rewrite_key(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bkey_i *k,
				enum bch_trans_commit_flags flags)
{
	CLASS(btree_node_iter, iter)(trans, btree, k->k.p, BTREE_MAX_DEPTH, level, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	bool found = b && btree_ptr_hash_val(&b->key) == btree_ptr_hash_val(k);
	return found
		? bch2_btree_node_rewrite(trans, &iter, b, 0, flags, 0)
		: -ENOENT;
}

static int bch2_btree_node_merge_key(struct btree_trans *trans,
				     enum btree_id btree, unsigned level,
				     struct bkey_i *k,
				     enum btree_iter_update_trigger_flags flags)
{
	CLASS(btree_node_iter, iter)(trans, btree, k->k.p, level + 1, level, flags);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	bool found = b && btree_ptr_hash_val(&b->key) == btree_ptr_hash_val(k);
	return found
		? bch2_foreground_maybe_merge(trans, iter.path, level, 0, 0, NULL)
		: -ENOENT;
}

int bch2_btree_node_rewrite_pos(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bpos pos,
				unsigned target,
				enum bch_trans_commit_flags commit_flags,
				enum bch_write_flags write_flags)
{
	BUG_ON(!level);

	/* Traverse one depth lower to get a pointer to the node itself: */
	CLASS(btree_node_iter, iter)(trans, btree, pos, 0, level - 1, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	return bch2_btree_node_rewrite(trans, &iter, b, target, commit_flags, write_flags);
}

struct async_btree_rewrite {
	struct bch_fs		*c;
	struct work_struct	work;
	struct list_head	list;
	enum btree_id		btree_id;
	unsigned		level;
	enum async_btree_op	op;
	struct bkey_buf		key;
};

static void async_btree_node_rewrite_work(struct work_struct *work)
{
	struct async_btree_rewrite *a =
		container_of(work, struct async_btree_rewrite, work);
	struct bch_fs *c = a->c;

	int ret = bch2_trans_do(c, a->op == ASYNC_BTREE_rewrite
		? bch2_btree_node_rewrite_key(trans, a->btree_id, a->level, a->key.k, 0)
		: bch2_btree_node_merge_key(trans, a->btree_id, a->level, a->key.k,
					    a->op == ASYNC_BTREE_merge_no_read ? BTREE_ITER_nofill : 0));
	if (!bch2_err_matches(ret, ENOENT) &&
	    !bch2_err_matches(ret, EROFS) &&
	    !bch2_err_matches(ret, BCH_ERR_no_btree_node_nofill))
		bch_err_fn_ratelimited(c, ret);

	scoped_guard(spinlock, &c->btree.node_rewrites.lock)
		list_del(&a->list);

	closure_wake_up(&c->btree.node_rewrites.wait);

	bch2_bkey_buf_exit(&a->key);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_node_rewrite);
	kfree(a);
}

void bch2_async_btree_op(struct bch_fs *c, struct btree *b,
				enum async_btree_op op)
{
	struct async_btree_rewrite *a = kzalloc(sizeof(*a), GFP_NOFS);
	if (!a)
		return;

	a->c		= c;
	a->btree_id	= b->c.btree_id;
	a->level	= b->c.level;
	a->op		= op;
	INIT_WORK(&a->work, async_btree_node_rewrite_work);

	bch2_bkey_buf_init(&a->key);
	bch2_bkey_buf_copy(&a->key, &b->key);

	bool now = false, pending = false;

	scoped_guard(spinlock, &c->btree.node_rewrites.lock) {
		if (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_journal_replay) &&
		    enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_node_rewrite)) {
			list_add(&a->list, &c->btree.node_rewrites.list);
			now = true;
		} else if (!test_bit(BCH_FS_may_go_rw, &c->flags)) {
			list_add(&a->list, &c->btree.node_rewrites.pending);
			pending = true;
		}
	}

	if (now) {
		queue_work(c->btree.node_rewrites.worker, &a->work);
	} else if (pending) {
		/* bch2_do_pending_node_rewrites will execute */
	} else {
		bch2_bkey_buf_exit(&a->key);
		kfree(a);
	}
}

void bch2_async_btree_node_rewrites_flush(struct bch_fs *c)
{
	closure_wait_event(&c->btree.node_rewrites.wait,
			   list_empty(&c->btree.node_rewrites.list));
}

void bch2_do_pending_node_rewrites(struct bch_fs *c)
{
	while (1) {
		struct async_btree_rewrite *a;

		scoped_guard(spinlock, &c->btree.node_rewrites.lock) {
			a = list_pop_entry(&c->btree.node_rewrites.pending,
					   struct async_btree_rewrite, list);
			if (a)
				list_add(&a->list, &c->btree.node_rewrites.list);
		}

		if (!a)
			break;

		enumerated_ref_get(&c->writes, BCH_WRITE_REF_node_rewrite);
		queue_work(c->btree.node_rewrites.worker, &a->work);
	}
}

void bch2_free_pending_node_rewrites(struct bch_fs *c)
{
	while (1) {
		struct async_btree_rewrite *a;

		scoped_guard(spinlock, &c->btree.node_rewrites.lock)
			a = list_pop_entry(&c->btree.node_rewrites.pending,
					   struct async_btree_rewrite, list);

		if (!a)
			break;

		bch2_bkey_buf_exit(&a->key);
		kfree(a);
	}
}

static int __bch2_btree_node_update_key(struct btree_trans *trans,
					struct btree_iter *iter,
					struct btree *b,
					struct bkey_i *new_key,
					unsigned commit_flags,
					bool skip_triggers)
{
	struct bch_fs *c = trans->c;
	unsigned level = b->c.level;

	struct btree_path *path = btree_iter_path(trans, iter);
	BUG_ON(path->l[b->c.level].b != b);
	BUG_ON(!btree_node_intent_locked(path, b->c.level));

	if (!btree_node_will_make_reachable(b)) {
		if (!btree_node_is_root(c, b)) {
			CLASS(btree_node_iter, parent_iter)(trans,
							    b->c.btree_id,
							    b->key.k.p,
							    0,
							    b->c.level + 1,
							    BTREE_ITER_intent);

			try(bch2_btree_iter_traverse(&parent_iter));
			try(bch2_trans_update(trans, &parent_iter, new_key, skip_triggers ? BTREE_TRIGGER_norun : 0));
		} else {
			if (!skip_triggers)
				try(bch2_key_trigger(trans, b->c.btree_id, b->c.level + 1,
						     bkey_i_to_s_c(&b->key),
						     bkey_i_to_s(new_key),
						     BTREE_TRIGGER_insert|
						     BTREE_TRIGGER_overwrite|
						     BTREE_TRIGGER_transactional));

			journal_entry_set(errptr_try(bch2_trans_jset_entry_alloc(trans,
										 jset_u64s(b->key.k.u64s))),
					  BCH_JSET_ENTRY_overwrite,
					  b->c.btree_id, b->c.level + 1,
					  &b->key, b->key.k.u64s);

			journal_entry_set(errptr_try(bch2_trans_jset_entry_alloc(trans,
										 jset_u64s(new_key->k.u64s))),
					  BCH_JSET_ENTRY_btree_root,
					  b->c.btree_id, b->c.level,
					  new_key, new_key->k.u64s);

			/*
			 * propagated back to c->btree.roots[].key by
			 * bch2_journal_entry_to_btree_root() incorrect for
			 */
		}

		CLASS(disk_reservation, res)(c);
		try(bch2_trans_commit(trans, &res.r, NULL, commit_flags));

		struct btree *new_b = btree_iter_path(trans, iter)->l[level].b;
		if (new_b != b) {
			/*
			 * We were asked to update the key for a node that was
			 * also modified during the commit (due to triggers),
			 * and that node was freed:
			 */
			BUG_ON(!btree_node_will_make_reachable(new_b));
			return 0;
		}

		bch2_btree_node_lock_write_nofail(trans, btree_iter_path(trans, iter), &b->c);
		bkey_copy(&b->key, new_key);
		bch2_btree_node_unlock_write(trans, btree_iter_path(trans, iter), b);
	} else {
		try(bch2_trans_mutex_lock(trans, &c->btree.interior_updates.commit_lock));

		if (!btree_node_will_make_reachable(b)) {
			mutex_unlock(&c->btree.interior_updates.commit_lock);
			return bch_err_throw(c, transaction_restart_nested);
		}

		struct btree_update *as = (void *) (READ_ONCE(b->will_make_reachable) & ~1UL);
		struct btree_update_node *n = darray_find_p(as->new_nodes, i, i->b == b);

		bch2_btree_node_lock_write_nofail(trans, btree_iter_path(trans, iter), &b->c);
		bkey_copy(&b->key, new_key);
		bch2_btree_node_unlock_write(trans, btree_iter_path(trans, iter), b);

		bkey_copy(&n->key, new_key);
		mutex_unlock(&c->btree.interior_updates.commit_lock);
	}
	return 0;
}

int bch2_btree_node_update_key(struct btree_trans *trans, struct btree_iter *iter,
			       struct btree *b, struct bkey_i *new_key,
			       unsigned commit_flags, bool skip_triggers)
{
	BUG_ON(btree_node_fake(b));

	struct btree_path *path = btree_iter_path(trans, iter);

	/*
	 * Awkward - we can't rely on caller specifying BTREE_ITER_intent, and
	 * the commit will downgrade locks
	 */

	try(bch2_btree_path_upgrade(trans, path, b->c.level + 1));

	path->intent_ref++;
	int ret = __bch2_btree_node_update_key(trans, iter, b, new_key,
					       commit_flags, skip_triggers);
	--path->intent_ref;
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
	struct btree *b;
	int ret;

	CLASS(closure_stack, cl)();

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

	ret = bch2_btree_node_transition_state(&c->btree.cache, b, btree_node_live_state(b));
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

	guard(mutex)(&c->btree.interior_updates.lock);
	list_for_each_entry(as, &c->btree.interior_updates.list, list)
		bch2_btree_update_to_text(out, as);
}

bool bch2_btree_interior_updates_flush(struct bch_fs *c)
{
	bool ret = bch2_btree_interior_updates_pending(c);

	if (ret)
		closure_wait_event(&c->btree.interior_updates.wait,
				   !bch2_btree_interior_updates_pending(c));
	return ret;
}

void bch2_journal_entry_to_btree_root(struct bch_fs *c, struct jset_entry *entry)
{
	struct btree_root *r = bch2_btree_id_root(c, entry->btree_id);

	guard(mutex)(&c->btree.interior_updates.lock);

	r->level = entry->level;
	r->alive = true;
	bkey_copy(&r->key, (struct bkey_i *) entry->start);
}

struct jset_entry *
bch2_btree_roots_to_journal_entries(struct bch_fs *c,
				    struct jset_entry *end,
				    unsigned long skip)
{
	guard(mutex)(&c->btree.interior_updates.lock);

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
	guard(printbuf_indent)(out);
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&a->k));
	prt_newline(out);

	struct open_bucket *ob;
	unsigned i;
	open_bucket_for_each(c, &a->ob, ob, i)
		bch2_open_bucket_to_text(out, c, ob);
}

void bch2_btree_reserve_cache_to_text(struct printbuf *out, struct bch_fs *c)
{
	for (unsigned i = 0; i < c->btree.reserve_cache.nr; i++)
		bch2_btree_alloc_to_text(out, c, &c->btree.reserve_cache.data[i]);
}

void bch2_fs_btree_interior_update_exit(struct bch_fs *c)
{
	WARN_ON(!list_empty(&c->btree.node_rewrites.list));
	WARN_ON(!list_empty(&c->btree.node_rewrites.pending));

	if (c->btree.node_rewrites.worker)
		destroy_workqueue(c->btree.node_rewrites.worker);
	if (c->btree.interior_updates.worker)
		destroy_workqueue(c->btree.interior_updates.worker);
	mempool_exit(&c->btree.interior_updates.pool);
}

void bch2_fs_btree_interior_update_init_early(struct bch_fs *c)
{
	mutex_init(&c->btree.reserve_cache.lock);
	INIT_LIST_HEAD(&c->btree.interior_updates.list);
	INIT_LIST_HEAD(&c->btree.interior_updates.unwritten);
	mutex_init(&c->btree.interior_updates.lock);
	mutex_init(&c->btree.interior_updates.commit_lock);
	INIT_WORK(&c->btree.interior_updates.work, btree_interior_update_work);

	INIT_LIST_HEAD(&c->btree.node_rewrites.list);
	INIT_LIST_HEAD(&c->btree.node_rewrites.pending);
	spin_lock_init(&c->btree.node_rewrites.lock);
}

int bch2_fs_btree_interior_update_init(struct bch_fs *c)
{
	c->btree.interior_updates.worker =
		alloc_workqueue("btree_update", WQ_UNBOUND|WQ_MEM_RECLAIM, 8);
	if (!c->btree.interior_updates.worker)
		return bch_err_throw(c, ENOMEM_btree_interior_update_worker_init);

	c->btree.node_rewrites.worker =
		alloc_ordered_workqueue("btree_node_rewrite", WQ_UNBOUND);
	if (!c->btree.node_rewrites.worker)
		return bch_err_throw(c, ENOMEM_btree_interior_update_worker_init);

	if (mempool_init_kmalloc_pool(&c->btree.interior_updates.pool, 1,
				      sizeof(struct btree_update)))
		return bch_err_throw(c, ENOMEM_btree_interior_update_pool_init);

	return 0;
}
