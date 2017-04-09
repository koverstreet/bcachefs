
#include "bcachefs.h"
#include "alloc.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "extents.h"
#include "journal.h"
#include "keylist.h"
#include "super-io.h"

#include <linux/random.h>
#include <linux/sort.h>
#include <trace/events/bcachefs.h>

static void btree_interior_update_updated_root(struct bch_fs *,
					       struct btree_interior_update *,
					       enum btree_id);

/* Calculate ideal packed bkey format for new btree nodes: */

void __bch2_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct bkey_packed *k;
	struct bset_tree *t;
	struct bkey uk;

	bch2_bkey_format_add_pos(s, b->data->min_key);

	for_each_bset(b, t)
		for (k = btree_bkey_first(b, t);
		     k != btree_bkey_last(b, t);
		     k = bkey_next(k))
			if (!bkey_whiteout(k)) {
				uk = bkey_unpack_key(b, k);
				bch2_bkey_format_add_key(s, &uk);
			}
}

static struct bkey_format bch2_btree_calc_format(struct btree *b)
{
	struct bkey_format_state s;

	bch2_bkey_format_init(&s);
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

/*
 * We're doing the index update that makes @b unreachable, update stuff to
 * reflect that:
 *
 * Must be called _before_ btree_interior_update_updated_root() or
 * btree_interior_update_updated_btree:
 */
static void bch2_btree_node_free_index(struct bch_fs *c, struct btree *b,
				      enum btree_id id, struct bkey_s_c k,
				      struct bch_fs_usage *stats)
{
	struct btree_interior_update *as;
	struct pending_btree_node_free *d;

	mutex_lock(&c->btree_interior_update_lock);

	for_each_pending_btree_node_free(c, as, d)
		if (!bkey_cmp(k.k->p, d->key.k.p) &&
		    bkey_val_bytes(k.k) == bkey_val_bytes(&d->key.k) &&
		    !memcmp(k.v, &d->key.v, bkey_val_bytes(k.k)))
			goto found;

	BUG();
found:
	d->index_update_done = true;

	/*
	 * Btree nodes are accounted as freed in bch_alloc_stats when they're
	 * freed from the index:
	 */
	stats->s[S_COMPRESSED][S_META]	 -= c->sb.btree_node_size;
	stats->s[S_UNCOMPRESSED][S_META] -= c->sb.btree_node_size;

	/*
	 * We're dropping @k from the btree, but it's still live until the
	 * index update is persistent so we need to keep a reference around for
	 * mark and sweep to find - that's primarily what the
	 * btree_node_pending_free list is for.
	 *
	 * So here (when we set index_update_done = true), we're moving an
	 * existing reference to a different part of the larger "gc keyspace" -
	 * and the new position comes after the old position, since GC marks
	 * the pending free list after it walks the btree.
	 *
	 * If we move the reference while mark and sweep is _between_ the old
	 * and the new position, mark and sweep will see the reference twice
	 * and it'll get double accounted - so check for that here and subtract
	 * to cancel out one of mark and sweep's markings if necessary:
	 */

	/*
	 * bch2_mark_key() compares the current gc pos to the pos we're
	 * moving this reference from, hence one comparison here:
	 */
	if (gc_pos_cmp(c->gc_pos, gc_phase(GC_PHASE_PENDING_DELETE)) < 0) {
		struct bch_fs_usage tmp = { 0 };

		bch2_mark_key(c, bkey_i_to_s_c(&d->key),
			     -c->sb.btree_node_size, true, b
			     ? gc_pos_btree_node(b)
			     : gc_pos_btree_root(id),
			     &tmp, 0);
		/*
		 * Don't apply tmp - pending deletes aren't tracked in
		 * bch_alloc_stats:
		 */
	}

	mutex_unlock(&c->btree_interior_update_lock);
}

static void __btree_node_free(struct bch_fs *c, struct btree *b,
			      struct btree_iter *iter)
{
	trace_btree_node_free(c, b);

	BUG_ON(btree_node_dirty(b));
	BUG_ON(btree_node_need_write(b));
	BUG_ON(b == btree_node_root(c, b));
	BUG_ON(b->ob);
	BUG_ON(!list_empty(&b->write_blocked));
	BUG_ON(!list_empty(&b->reachable));

	clear_btree_node_noevict(b);

	six_lock_write(&b->lock);

	bch2_btree_node_hash_remove(c, b);

	mutex_lock(&c->btree_cache_lock);
	list_move(&b->list, &c->btree_cache_freeable);
	mutex_unlock(&c->btree_cache_lock);

	/*
	 * By using six_unlock_write() directly instead of
	 * bch2_btree_node_unlock_write(), we don't update the iterator's
	 * sequence numbers and cause future bch2_btree_node_relock() calls to
	 * fail:
	 */
	six_unlock_write(&b->lock);
}

void bch2_btree_node_free_never_inserted(struct bch_fs *c, struct btree *b)
{
	struct open_bucket *ob = b->ob;

	b->ob = NULL;

	clear_btree_node_dirty(b);

	__btree_node_free(c, b, NULL);

	bch2_open_bucket_put(c, ob);
}

void bch2_btree_node_free_inmem(struct btree_iter *iter, struct btree *b)
{
	bch2_btree_iter_node_drop_linked(iter, b);

	__btree_node_free(iter->c, b, iter);

	bch2_btree_iter_node_drop(iter, b);
}

static void bch2_btree_node_free_ondisk(struct bch_fs *c,
				       struct pending_btree_node_free *pending)
{
	struct bch_fs_usage stats = { 0 };

	BUG_ON(!pending->index_update_done);

	bch2_mark_key(c, bkey_i_to_s_c(&pending->key),
		     -c->sb.btree_node_size, true,
		     gc_phase(GC_PHASE_PENDING_DELETE),
		     &stats, 0);
	/*
	 * Don't apply stats - pending deletes aren't tracked in
	 * bch_alloc_stats:
	 */
}

void bch2_btree_open_bucket_put(struct bch_fs *c, struct btree *b)
{
	bch2_open_bucket_put(c, b->ob);
	b->ob = NULL;
}

static struct btree *__bch2_btree_node_alloc(struct bch_fs *c,
					    bool use_reserve,
					    struct disk_reservation *res,
					    struct closure *cl)
{
	BKEY_PADDED(k) tmp;
	struct open_bucket *ob;
	struct btree *b;
	unsigned reserve = use_reserve ? 0 : BTREE_NODE_RESERVE;

	mutex_lock(&c->btree_reserve_cache_lock);
	if (c->btree_reserve_cache_nr > reserve) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		ob = a->ob;
		bkey_copy(&tmp.k, &a->k);
		mutex_unlock(&c->btree_reserve_cache_lock);
		goto mem_alloc;
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

retry:
	/* alloc_sectors is weird, I suppose */
	bkey_extent_init(&tmp.k);
	tmp.k.k.size = c->sb.btree_node_size,

	ob = bch2_alloc_sectors(c, &c->btree_write_point,
			       bkey_i_to_extent(&tmp.k),
			       res->nr_replicas,
			       c->opts.metadata_replicas_required,
			       use_reserve ? RESERVE_BTREE : RESERVE_NONE,
			       cl);
	if (IS_ERR(ob))
		return ERR_CAST(ob);

	if (tmp.k.k.size < c->sb.btree_node_size) {
		bch2_open_bucket_put(c, ob);
		goto retry;
	}
mem_alloc:
	b = bch2_btree_node_mem_alloc(c);

	/* we hold cannibalize_lock: */
	BUG_ON(IS_ERR(b));
	BUG_ON(b->ob);

	bkey_copy(&b->key, &tmp.k);
	b->key.k.size = 0;
	b->ob = ob;

	return b;
}

static struct btree *bch2_btree_node_alloc(struct bch_fs *c,
					  unsigned level, enum btree_id id,
					  struct btree_reserve *reserve)
{
	struct btree *b;

	BUG_ON(!reserve->nr);

	b = reserve->b[--reserve->nr];

	BUG_ON(bch2_btree_node_hash_insert(c, b, level, id));

	set_btree_node_accessed(b);
	set_btree_node_dirty(b);

	bch2_bset_init_first(b, &b->data->keys);
	memset(&b->nr, 0, sizeof(b->nr));
	b->data->magic = cpu_to_le64(bset_magic(c));
	b->data->flags = 0;
	SET_BTREE_NODE_ID(b->data, id);
	SET_BTREE_NODE_LEVEL(b->data, level);
	b->data->ptr = bkey_i_to_extent(&b->key)->v.start->ptr;

	bch2_btree_build_aux_trees(b);

	bch2_check_mark_super(c, &b->key, true);

	trace_btree_node_alloc(c, b);
	return b;
}

struct btree *__bch2_btree_node_alloc_replacement(struct bch_fs *c,
						  struct btree *b,
						  struct bkey_format format,
						  struct btree_reserve *reserve)
{
	struct btree *n;

	n = bch2_btree_node_alloc(c, b->level, b->btree_id, reserve);

	n->data->min_key	= b->data->min_key;
	n->data->max_key	= b->data->max_key;
	n->data->format		= format;

	btree_node_set_format(n, format);

	bch2_btree_sort_into(c, n, b);

	btree_node_reset_sib_u64s(n);

	n->key.k.p = b->key.k.p;
	return n;
}

static struct btree *bch2_btree_node_alloc_replacement(struct bch_fs *c,
						struct btree *b,
						struct btree_reserve *reserve)
{
	struct bkey_format new_f = bch2_btree_calc_format(b);

	/*
	 * The keys might expand with the new format - if they wouldn't fit in
	 * the btree node anymore, use the old format for now:
	 */
	if (!bch2_btree_node_format_fits(c, b, &new_f))
		new_f = b->format;

	return __bch2_btree_node_alloc_replacement(c, b, new_f, reserve);
}

static void bch2_btree_set_root_inmem(struct bch_fs *c, struct btree *b,
				     struct btree_reserve *btree_reserve)
{
	struct btree *old = btree_node_root(c, b);

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	mutex_lock(&c->btree_root_lock);
	btree_node_root(c, b) = b;
	mutex_unlock(&c->btree_root_lock);

	if (btree_reserve) {
		/*
		 * New allocation (we're not being called because we're in
		 * bch2_btree_root_read()) - do marking while holding
		 * btree_root_lock:
		 */
		struct bch_fs_usage stats = { 0 };

		bch2_mark_key(c, bkey_i_to_s_c(&b->key),
			     c->sb.btree_node_size, true,
			     gc_pos_btree_root(b->btree_id),
			     &stats, 0);

		if (old)
			bch2_btree_node_free_index(c, NULL, old->btree_id,
						  bkey_i_to_s_c(&old->key),
						  &stats);
		bch2_fs_usage_apply(c, &stats, &btree_reserve->disk_res,
				   gc_pos_btree_root(b->btree_id));
	}

	bch2_recalc_btree_reserve(c);
}

static void bch2_btree_set_root_ondisk(struct bch_fs *c, struct btree *b)
{
	struct btree_root *r = &c->btree_roots[b->btree_id];

	mutex_lock(&c->btree_root_lock);

	BUG_ON(b != r->b);
	bkey_copy(&r->key, &b->key);
	r->level = b->level;
	r->alive = true;

	mutex_unlock(&c->btree_root_lock);
}

/*
 * Only for filesystem bringup, when first reading the btree roots or allocating
 * btree roots when initializing a new filesystem:
 */
void bch2_btree_set_root_initial(struct bch_fs *c, struct btree *b,
				struct btree_reserve *btree_reserve)
{
	BUG_ON(btree_node_root(c, b));

	bch2_btree_set_root_inmem(c, b, btree_reserve);
	bch2_btree_set_root_ondisk(c, b);
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
static void bch2_btree_set_root(struct btree_iter *iter, struct btree *b,
			       struct btree_interior_update *as,
			       struct btree_reserve *btree_reserve)
{
	struct bch_fs *c = iter->c;
	struct btree *old;

	trace_btree_set_root(c, b);
	BUG_ON(!b->written);

	old = btree_node_root(c, b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	bch2_btree_node_lock_write(old, iter);

	bch2_btree_set_root_inmem(c, b, btree_reserve);

	btree_interior_update_updated_root(c, as, iter->btree_id);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	bch2_btree_node_unlock_write(old, iter);
}

static struct btree *__btree_root_alloc(struct bch_fs *c, unsigned level,
					enum btree_id id,
					struct btree_reserve *reserve)
{
	struct btree *b = bch2_btree_node_alloc(c, level, id, reserve);

	b->data->min_key = POS_MIN;
	b->data->max_key = POS_MAX;
	b->data->format = bch2_btree_calc_format(b);
	b->key.k.p = POS_MAX;

	btree_node_set_format(b, b->data->format);
	bch2_btree_build_aux_trees(b);

	six_unlock_write(&b->lock);

	return b;
}

void bch2_btree_reserve_put(struct bch_fs *c, struct btree_reserve *reserve)
{
	bch2_disk_reservation_put(c, &reserve->disk_res);

	mutex_lock(&c->btree_reserve_cache_lock);

	while (reserve->nr) {
		struct btree *b = reserve->b[--reserve->nr];

		six_unlock_write(&b->lock);

		if (c->btree_reserve_cache_nr <
		    ARRAY_SIZE(c->btree_reserve_cache)) {
			struct btree_alloc *a =
				&c->btree_reserve_cache[c->btree_reserve_cache_nr++];

			a->ob = b->ob;
			b->ob = NULL;
			bkey_copy(&a->k, &b->key);
		} else {
			bch2_open_bucket_put(c, b->ob);
			b->ob = NULL;
		}

		__btree_node_free(c, b, NULL);

		six_unlock_intent(&b->lock);
	}

	mutex_unlock(&c->btree_reserve_cache_lock);

	mempool_free(reserve, &c->btree_reserve_pool);
}

static struct btree_reserve *__bch2_btree_reserve_get(struct bch_fs *c,
						     unsigned nr_nodes,
						     unsigned flags,
						     struct closure *cl)
{
	struct btree_reserve *reserve;
	struct btree *b;
	struct disk_reservation disk_res = { 0, 0 };
	unsigned sectors = nr_nodes * c->sb.btree_node_size;
	int ret, disk_res_flags = BCH_DISK_RESERVATION_GC_LOCK_HELD|
		BCH_DISK_RESERVATION_METADATA;

	if (flags & BTREE_INSERT_NOFAIL)
		disk_res_flags |= BCH_DISK_RESERVATION_NOFAIL;

	/*
	 * This check isn't necessary for correctness - it's just to potentially
	 * prevent us from doing a lot of work that'll end up being wasted:
	 */
	ret = bch2_journal_error(&c->journal);
	if (ret)
		return ERR_PTR(ret);

	if (bch2_disk_reservation_get(c, &disk_res, sectors, disk_res_flags))
		return ERR_PTR(-ENOSPC);

	BUG_ON(nr_nodes > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	ret = bch2_btree_node_cannibalize_lock(c, cl);
	if (ret) {
		bch2_disk_reservation_put(c, &disk_res);
		return ERR_PTR(ret);
	}

	reserve = mempool_alloc(&c->btree_reserve_pool, GFP_NOIO);

	reserve->disk_res = disk_res;
	reserve->nr = 0;

	while (reserve->nr < nr_nodes) {
		b = __bch2_btree_node_alloc(c, flags & BTREE_INSERT_USE_RESERVE,
					   &disk_res, cl);
		if (IS_ERR(b)) {
			ret = PTR_ERR(b);
			goto err_free;
		}

		reserve->b[reserve->nr++] = b;
	}

	bch2_btree_node_cannibalize_unlock(c);
	return reserve;
err_free:
	bch2_btree_reserve_put(c, reserve);
	bch2_btree_node_cannibalize_unlock(c);
	trace_btree_reserve_get_fail(c, nr_nodes, cl);
	return ERR_PTR(ret);
}

struct btree_reserve *bch2_btree_reserve_get(struct bch_fs *c,
					    struct btree *b,
					    unsigned extra_nodes,
					    unsigned flags,
					    struct closure *cl)
{
	unsigned depth = btree_node_root(c, b)->level - b->level;
	unsigned nr_nodes = btree_reserve_required_nodes(depth) + extra_nodes;

	return __bch2_btree_reserve_get(c, nr_nodes, flags, cl);
}

int bch2_btree_root_alloc(struct bch_fs *c, enum btree_id id,
			 struct closure *writes)
{
	struct closure cl;
	struct btree_reserve *reserve;
	struct btree *b;
	LIST_HEAD(reachable_list);

	closure_init_stack(&cl);

	while (1) {
		/* XXX haven't calculated capacity yet :/ */
		reserve = __bch2_btree_reserve_get(c, 1, 0, &cl);
		if (!IS_ERR(reserve))
			break;

		if (PTR_ERR(reserve) == -ENOSPC)
			return PTR_ERR(reserve);

		closure_sync(&cl);
	}

	b = __btree_root_alloc(c, 0, id, reserve);
	list_add(&b->reachable, &reachable_list);

	bch2_btree_node_write(c, b, writes, SIX_LOCK_intent);

	bch2_btree_set_root_initial(c, b, reserve);
	bch2_btree_open_bucket_put(c, b);

	list_del_init(&b->reachable);
	six_unlock_intent(&b->lock);

	bch2_btree_reserve_put(c, reserve);

	return 0;
}

static void bch2_insert_fixup_btree_ptr(struct btree_iter *iter,
				       struct btree *b,
				       struct bkey_i *insert,
				       struct btree_node_iter *node_iter,
				       struct disk_reservation *disk_res)
{
	struct bch_fs *c = iter->c;
	struct bch_fs_usage stats = { 0 };
	struct bkey_packed *k;
	struct bkey tmp;

	if (bkey_extent_is_data(&insert->k))
		bch2_mark_key(c, bkey_i_to_s_c(insert),
			     c->sb.btree_node_size, true,
			     gc_pos_btree_node(b), &stats, 0);

	while ((k = bch2_btree_node_iter_peek_all(node_iter, b)) &&
	       !btree_iter_pos_cmp_packed(b, &insert->k.p, k, false))
		bch2_btree_node_iter_advance(node_iter, b);

	/*
	 * If we're overwriting, look up pending delete and mark so that gc
	 * marks it on the pending delete list:
	 */
	if (k && !bkey_cmp_packed(b, k, &insert->k))
		bch2_btree_node_free_index(c, b, iter->btree_id,
					  bkey_disassemble(b, k, &tmp),
					  &stats);

	bch2_fs_usage_apply(c, &stats, disk_res, gc_pos_btree_node(b));

	bch2_btree_bset_insert_key(iter, b, node_iter, insert);
	set_btree_node_dirty(b);
	set_btree_node_need_write(b);
}

/* Inserting into a given leaf node (last stage of insert): */

/* Handle overwrites and do insert, for non extents: */
bool bch2_btree_bset_insert_key(struct btree_iter *iter,
			       struct btree *b,
			       struct btree_node_iter *node_iter,
			       struct bkey_i *insert)
{
	const struct bkey_format *f = &b->format;
	struct bkey_packed *k;
	struct bset_tree *t;
	unsigned clobber_u64s;

	EBUG_ON(btree_node_just_written(b));
	EBUG_ON(bset_written(b, btree_bset_last(b)));
	EBUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	EBUG_ON(bkey_cmp(bkey_start_pos(&insert->k), b->data->min_key) < 0 ||
		bkey_cmp(insert->k.p, b->data->max_key) > 0);
	BUG_ON(insert->k.u64s > bch_btree_keys_u64s_remaining(iter->c, b));

	k = bch2_btree_node_iter_peek_all(node_iter, b);
	if (k && !bkey_cmp_packed(b, k, &insert->k)) {
		BUG_ON(bkey_whiteout(k));

		t = bch2_bkey_to_bset(b, k);

		if (bset_unwritten(b, bset(b, t)) &&
		    bkey_val_u64s(&insert->k) == bkeyp_val_u64s(f, k)) {
			BUG_ON(bkey_whiteout(k) != bkey_whiteout(&insert->k));

			k->type = insert->k.type;
			memcpy_u64s(bkeyp_val(f, k), &insert->v,
				    bkey_val_u64s(&insert->k));
			return true;
		}

		insert->k.needs_whiteout = k->needs_whiteout;

		btree_keys_account_key_drop(&b->nr, t - b->set, k);

		if (t == bset_tree_last(b)) {
			clobber_u64s = k->u64s;

			/*
			 * If we're deleting, and the key we're deleting doesn't
			 * need a whiteout (it wasn't overwriting a key that had
			 * been written to disk) - just delete it:
			 */
			if (bkey_whiteout(&insert->k) && !k->needs_whiteout) {
				bch2_bset_delete(b, k, clobber_u64s);
				bch2_btree_node_iter_fix(iter, b, node_iter, t,
							k, clobber_u64s, 0);
				return true;
			}

			goto overwrite;
		}

		k->type = KEY_TYPE_DELETED;
		bch2_btree_node_iter_fix(iter, b, node_iter, t, k,
					k->u64s, k->u64s);

		if (bkey_whiteout(&insert->k)) {
			reserve_whiteout(b, t, k);
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

	t = bset_tree_last(b);
	k = bch2_btree_node_iter_bset_pos(node_iter, b, t);
	clobber_u64s = 0;
overwrite:
	bch2_bset_insert(b, node_iter, k, insert, clobber_u64s);
	if (k->u64s != clobber_u64s || bkey_whiteout(&insert->k))
		bch2_btree_node_iter_fix(iter, b, node_iter, t, k,
					clobber_u64s, k->u64s);
	return true;
}

static void __btree_node_flush(struct journal *j, struct journal_entry_pin *pin,
			       unsigned i, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[i]);

	six_lock_read(&b->lock);
	bch2_btree_node_write_dirty(c, b, NULL,
			(btree_current_write(b) == w &&
			 w->journal.pin_list == journal_seq_pin(j, seq)));
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

void bch2_btree_journal_key(struct btree_insert *trans,
			   struct btree_iter *iter,
			   struct bkey_i *insert)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct btree *b = iter->nodes[0];
	struct btree_write *w = btree_current_write(b);

	EBUG_ON(iter->level || b->level);
	EBUG_ON(!trans->journal_res.ref &&
		test_bit(JOURNAL_REPLAY_DONE, &j->flags));

	if (!journal_pin_active(&w->journal))
		bch2_journal_pin_add(j, &trans->journal_res,
				     &w->journal,
				     btree_node_write_idx(b) == 0
				     ? btree_node_flush0
				     : btree_node_flush1);

	if (trans->journal_res.ref) {
		u64 seq = trans->journal_res.seq;
		bool needs_whiteout = insert->k.needs_whiteout;

		/*
		 * have a bug where we're seeing an extent with an invalid crc
		 * entry in the journal, trying to track it down:
		 */
		BUG_ON(bch2_bkey_invalid(c, b->btree_id, bkey_i_to_s_c(insert)));

		/* ick */
		insert->k.needs_whiteout = false;
		bch2_journal_add_keys(j, &trans->journal_res,
				     b->btree_id, insert);
		insert->k.needs_whiteout = needs_whiteout;

		if (trans->journal_seq)
			*trans->journal_seq = seq;
		btree_bset_last(b)->journal_seq = cpu_to_le64(seq);
	}

	if (!btree_node_dirty(b))
		set_btree_node_dirty(b);
}

static enum btree_insert_ret
bch2_insert_fixup_key(struct btree_insert *trans,
		     struct btree_insert_entry *insert)
{
	struct btree_iter *iter = insert->iter;

	BUG_ON(iter->level);

	if (bch2_btree_bset_insert_key(iter,
				      iter->nodes[0],
				      &iter->node_iters[0],
				      insert->k))
		bch2_btree_journal_key(trans, iter, insert->k);

	trans->did_work = true;
	return BTREE_INSERT_OK;
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_i *k;

	for_each_keylist_key(l, k)
		BUG_ON(bkey_next(k) != l->top &&
		       bkey_cmp(k->k.p, bkey_next(k)->k.p) >= 0);
#endif
}

static void btree_node_lock_for_insert(struct btree *b, struct btree_iter *iter)
{
	struct bch_fs *c = iter->c;

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

/* Asynchronous interior node update machinery */

struct btree_interior_update *
bch2_btree_interior_update_alloc(struct bch_fs *c)
{
	struct btree_interior_update *as;

	as = mempool_alloc(&c->btree_interior_update_pool, GFP_NOIO);
	memset(as, 0, sizeof(*as));
	closure_init(&as->cl, &c->cl);
	as->c		= c;
	as->mode	= BTREE_INTERIOR_NO_UPDATE;
	INIT_LIST_HEAD(&as->write_blocked_list);
	INIT_LIST_HEAD(&as->reachable_list);

	bch2_keylist_init(&as->parent_keys, as->inline_keys,
			 ARRAY_SIZE(as->inline_keys));

	mutex_lock(&c->btree_interior_update_lock);
	list_add(&as->list, &c->btree_interior_update_list);
	mutex_unlock(&c->btree_interior_update_lock);

	return as;
}

static void btree_interior_update_free(struct closure *cl)
{
	struct btree_interior_update *as =
		container_of(cl, struct btree_interior_update, cl);

	mempool_free(as, &as->c->btree_interior_update_pool);
}

static void btree_interior_update_nodes_reachable(struct closure *cl)
{
	struct btree_interior_update *as =
		container_of(cl, struct btree_interior_update, cl);
	struct bch_fs *c = as->c;
	unsigned i;

	bch2_journal_pin_drop(&c->journal, &as->journal);

	mutex_lock(&c->btree_interior_update_lock);

	while (!list_empty(&as->reachable_list)) {
		struct btree *b = list_first_entry(&as->reachable_list,
						   struct btree, reachable);
		list_del_init(&b->reachable);
		mutex_unlock(&c->btree_interior_update_lock);

		six_lock_read(&b->lock);
		bch2_btree_node_write_dirty(c, b, NULL, btree_node_need_write(b));
		six_unlock_read(&b->lock);
		mutex_lock(&c->btree_interior_update_lock);
	}

	for (i = 0; i < as->nr_pending; i++)
		bch2_btree_node_free_ondisk(c, &as->pending[i]);
	as->nr_pending = 0;

	list_del(&as->list);
	mutex_unlock(&c->btree_interior_update_lock);

	closure_wake_up(&as->wait);

	closure_return_with_destructor(cl, btree_interior_update_free);
}

static void btree_interior_update_nodes_written(struct closure *cl)
{
	struct btree_interior_update *as =
		container_of(cl, struct btree_interior_update, cl);
	struct bch_fs *c = as->c;
	struct btree *b;

	if (bch2_journal_error(&c->journal)) {
		/* XXX what? */
		/* we don't want to free the nodes on disk, that's what */
	}

	/* XXX: missing error handling, damnit */

	/* check for journal error, bail out if we flushed */

	/*
	 * We did an update to a parent node where the pointers we added pointed
	 * to child nodes that weren't written yet: now, the child nodes have
	 * been written so we can write out the update to the interior node.
	 */
retry:
	mutex_lock(&c->btree_interior_update_lock);
	switch (as->mode) {
	case BTREE_INTERIOR_NO_UPDATE:
		BUG();
	case BTREE_INTERIOR_UPDATING_NODE:
		/* The usual case: */
		b = READ_ONCE(as->b);

		if (!six_trylock_read(&b->lock)) {
			mutex_unlock(&c->btree_interior_update_lock);
			six_lock_read(&b->lock);
			six_unlock_read(&b->lock);
			goto retry;
		}

		BUG_ON(!btree_node_dirty(b));
		closure_wait(&btree_current_write(b)->wait, cl);

		list_del(&as->write_blocked_list);
		mutex_unlock(&c->btree_interior_update_lock);

		bch2_btree_node_write_dirty(c, b, NULL,
					    btree_node_need_write(b));
		six_unlock_read(&b->lock);
		break;

	case BTREE_INTERIOR_UPDATING_AS:
		/*
		 * The btree node we originally updated has been freed and is
		 * being rewritten - so we need to write anything here, we just
		 * need to signal to that btree_interior_update that it's ok to make the
		 * new replacement node visible:
		 */
		closure_put(&as->parent_as->cl);

		/*
		 * and then we have to wait on that btree_interior_update to finish:
		 */
		closure_wait(&as->parent_as->wait, cl);
		mutex_unlock(&c->btree_interior_update_lock);
		break;

	case BTREE_INTERIOR_UPDATING_ROOT:
		/* b is the new btree root: */
		b = READ_ONCE(as->b);

		if (!six_trylock_read(&b->lock)) {
			mutex_unlock(&c->btree_interior_update_lock);
			six_lock_read(&b->lock);
			six_unlock_read(&b->lock);
			goto retry;
		}

		BUG_ON(c->btree_roots[b->btree_id].as != as);
		c->btree_roots[b->btree_id].as = NULL;

		bch2_btree_set_root_ondisk(c, b);

		/*
		 * We don't have to wait anything anything here (before
		 * btree_interior_update_nodes_reachable frees the old nodes
		 * ondisk) - we've ensured that the very next journal write will
		 * have the pointer to the new root, and before the allocator
		 * can reuse the old nodes it'll have to do a journal commit:
		 */
		six_unlock_read(&b->lock);
		mutex_unlock(&c->btree_interior_update_lock);
		break;
	}

	continue_at(cl, btree_interior_update_nodes_reachable, system_wq);
}

/*
 * We're updating @b with pointers to nodes that haven't finished writing yet:
 * block @b from being written until @as completes
 */
static void btree_interior_update_updated_btree(struct bch_fs *c,
						struct btree_interior_update *as,
						struct btree *b)
{
	mutex_lock(&c->btree_interior_update_lock);

	BUG_ON(as->mode != BTREE_INTERIOR_NO_UPDATE);
	BUG_ON(!btree_node_dirty(b));

	as->mode = BTREE_INTERIOR_UPDATING_NODE;
	as->b = b;
	list_add(&as->write_blocked_list, &b->write_blocked);

	mutex_unlock(&c->btree_interior_update_lock);

	bch2_journal_wait_on_seq(&c->journal, as->journal_seq, &as->cl);

	continue_at(&as->cl, btree_interior_update_nodes_written,
		    system_freezable_wq);
}

static void btree_interior_update_reparent(struct btree_interior_update *as,
					   struct btree_interior_update *child)
{
	child->b = NULL;
	child->mode = BTREE_INTERIOR_UPDATING_AS;
	child->parent_as = as;
	closure_get(&as->cl);
}

static void btree_interior_update_updated_root(struct bch_fs *c,
					       struct btree_interior_update *as,
					       enum btree_id btree_id)
{
	struct btree_root *r = &c->btree_roots[btree_id];

	mutex_lock(&c->btree_interior_update_lock);

	BUG_ON(as->mode != BTREE_INTERIOR_NO_UPDATE);

	/*
	 * Old root might not be persistent yet - if so, redirect its
	 * btree_interior_update operation to point to us:
	 */
	if (r->as)
		btree_interior_update_reparent(as, r->as);

	as->mode = BTREE_INTERIOR_UPDATING_ROOT;
	as->b = r->b;
	r->as = as;

	mutex_unlock(&c->btree_interior_update_lock);

	continue_at(&as->cl, btree_interior_update_nodes_written,
		    system_freezable_wq);
}

static void interior_update_flush(struct journal *j,
			struct journal_entry_pin *pin, u64 seq)
{
	struct btree_interior_update *as =
		container_of(pin, struct btree_interior_update, journal);

	bch2_journal_flush_seq_async(j, as->journal_seq, NULL);
}

/*
 * @b is being split/rewritten: it may have pointers to not-yet-written btree
 * nodes and thus outstanding btree_interior_updates - redirect @b's
 * btree_interior_updates to point to this btree_interior_update:
 */
void bch2_btree_interior_update_will_free_node(struct bch_fs *c,
					      struct btree_interior_update *as,
					      struct btree *b)
{
	struct closure *cl, *cl_n;
	struct btree_interior_update *p, *n;
	struct pending_btree_node_free *d;
	struct btree_write *w;
	struct bset_tree *t;

	/*
	 * Does this node have data that hasn't been written in the journal?
	 *
	 * If so, we have to wait for the corresponding journal entry to be
	 * written before making the new nodes reachable - we can't just carry
	 * over the bset->journal_seq tracking, since we'll be mixing those keys
	 * in with keys that aren't in the journal anymore:
	 */
	for_each_bset(b, t)
		as->journal_seq = max(as->journal_seq, bset(b, t)->journal_seq);

	mutex_lock(&c->btree_interior_update_lock);

	/* Add this node to the list of nodes being freed: */
	BUG_ON(as->nr_pending >= ARRAY_SIZE(as->pending));

	d = &as->pending[as->nr_pending++];
	d->index_update_done	= false;
	d->seq			= b->data->keys.seq;
	d->btree_id		= b->btree_id;
	d->level		= b->level;
	bkey_copy(&d->key, &b->key);

	/*
	 * Does this node have any btree_interior_update operations preventing
	 * it from being written?
	 *
	 * If so, redirect them to point to this btree_interior_update: we can
	 * write out our new nodes, but we won't make them visible until those
	 * operations complete
	 */
	list_for_each_entry_safe(p, n, &b->write_blocked, write_blocked_list) {
		list_del(&p->write_blocked_list);
		btree_interior_update_reparent(as, p);
	}

	clear_btree_node_dirty(b);
	clear_btree_node_need_write(b);
	w = btree_current_write(b);

	llist_for_each_entry_safe(cl, cl_n, llist_del_all(&w->wait.list), list)
		llist_add(&cl->list, &as->wait.list);

	/*
	 * Does this node have unwritten data that has a pin on the journal?
	 *
	 * If so, transfer that pin to the btree_interior_update operation -
	 * note that if we're freeing multiple nodes, we only need to keep the
	 * oldest pin of any of the nodes we're freeing. We'll release the pin
	 * when the new nodes are persistent and reachable on disk:
	 */
	bch2_journal_pin_add_if_older(&c->journal, &w->journal,
				      &as->journal, interior_update_flush);
	bch2_journal_pin_drop(&c->journal, &w->journal);

	if (!list_empty(&b->reachable))
		list_del_init(&b->reachable);

	mutex_unlock(&c->btree_interior_update_lock);
}

static void btree_node_interior_verify(struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey_packed *k;

	BUG_ON(!b->level);

	bch2_btree_node_iter_init(&iter, b, b->key.k.p, false, false);
#if 1
	BUG_ON(!(k = bch2_btree_node_iter_peek(&iter, b)) ||
	       bkey_cmp_left_packed(b, k, &b->key.k.p));

	BUG_ON((bch2_btree_node_iter_advance(&iter, b),
		!bch2_btree_node_iter_end(&iter)));
#else
	const char *msg;

	msg = "not found";
	k = bch2_btree_node_iter_peek(&iter, b);
	if (!k)
		goto err;

	msg = "isn't what it should be";
	if (bkey_cmp_left_packed(b, k, &b->key.k.p))
		goto err;

	bch2_btree_node_iter_advance(&iter, b);

	msg = "isn't last key";
	if (!bch2_btree_node_iter_end(&iter))
		goto err;
	return;
err:
	bch2_dump_btree_node(b);
	printk(KERN_ERR "last key %llu:%llu %s\n", b->key.k.p.inode,
	       b->key.k.p.offset, msg);
	BUG();
#endif
}

static enum btree_insert_ret
bch2_btree_insert_keys_interior(struct btree *b,
			       struct btree_iter *iter,
			       struct keylist *insert_keys,
			       struct btree_interior_update *as,
			       struct btree_reserve *res)
{
	struct bch_fs *c = iter->c;
	struct btree_iter *linked;
	struct btree_node_iter node_iter;
	struct bkey_i *insert = bch2_keylist_front(insert_keys);
	struct bkey_packed *k;

	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(c, b)->level));
	BUG_ON(!b->level);
	BUG_ON(!as || as->b);
	verify_keys_sorted(insert_keys);

	btree_node_lock_for_insert(b, iter);

	if (bch_keylist_u64s(insert_keys) >
	    bch_btree_keys_u64s_remaining(c, b)) {
		bch2_btree_node_unlock_write(b, iter);
		return BTREE_INSERT_BTREE_NODE_FULL;
	}

	/* Don't screw up @iter's position: */
	node_iter = iter->node_iters[b->level];

	/*
	 * btree_split(), btree_gc_coalesce() will insert keys before
	 * the iterator's current position - they know the keys go in
	 * the node the iterator points to:
	 */
	while ((k = bch2_btree_node_iter_prev_all(&node_iter, b)) &&
	       (bkey_cmp_packed(b, k, &insert->k) >= 0))
		;

	while (!bch2_keylist_empty(insert_keys)) {
		insert = bch2_keylist_front(insert_keys);

		bch2_insert_fixup_btree_ptr(iter, b, insert,
					   &node_iter, &res->disk_res);
		bch2_keylist_pop_front(insert_keys);
	}

	btree_interior_update_updated_btree(c, as, b);

	for_each_linked_btree_node(iter, b, linked)
		bch2_btree_node_iter_peek(&linked->node_iters[b->level],
					 b);
	bch2_btree_node_iter_peek(&iter->node_iters[b->level], b);

	bch2_btree_iter_verify(iter, b);

	if (bch2_maybe_compact_whiteouts(c, b))
		bch2_btree_iter_reinit_node(iter, b);

	bch2_btree_node_unlock_write(b, iter);

	btree_node_interior_verify(b);
	return BTREE_INSERT_OK;
}

/*
 * Move keys from n1 (original replacement node, now lower node) to n2 (higher
 * node)
 */
static struct btree *__btree_split_node(struct btree_iter *iter, struct btree *n1,
					struct btree_reserve *reserve,
					struct btree_interior_update *as)
{
	size_t nr_packed = 0, nr_unpacked = 0;
	struct btree *n2;
	struct bset *set1, *set2;
	struct bkey_packed *k, *prev = NULL;

	n2 = bch2_btree_node_alloc(iter->c, n1->level, iter->btree_id, reserve);
	list_add(&n2->reachable, &as->reachable_list);

	n2->data->max_key	= n1->data->max_key;
	n2->data->format	= n1->format;
	n2->key.k.p = n1->key.k.p;

	btree_node_set_format(n2, n2->data->format);

	set1 = btree_bset_first(n1);
	set2 = btree_bset_first(n2);

	/*
	 * Has to be a linear search because we don't have an auxiliary
	 * search tree yet
	 */
	k = set1->start;
	while (1) {
		if (bkey_next(k) == vstruct_last(set1))
			break;
		if (k->_data - set1->_data >= (le16_to_cpu(set1->u64s) * 3) / 5)
			break;

		if (bkey_packed(k))
			nr_packed++;
		else
			nr_unpacked++;

		prev = k;
		k = bkey_next(k);
	}

	BUG_ON(!prev);

	n1->key.k.p = bkey_unpack_pos(n1, prev);
	n1->data->max_key = n1->key.k.p;
	n2->data->min_key =
		btree_type_successor(n1->btree_id, n1->key.k.p);

	set2->u64s = cpu_to_le16((u64 *) vstruct_end(set1) - (u64 *) k);
	set1->u64s = cpu_to_le16(le16_to_cpu(set1->u64s) - le16_to_cpu(set2->u64s));

	set_btree_bset_end(n1, n1->set);
	set_btree_bset_end(n2, n2->set);

	n2->nr.live_u64s	= le16_to_cpu(set2->u64s);
	n2->nr.bset_u64s[0]	= le16_to_cpu(set2->u64s);
	n2->nr.packed_keys	= n1->nr.packed_keys - nr_packed;
	n2->nr.unpacked_keys	= n1->nr.unpacked_keys - nr_unpacked;

	n1->nr.live_u64s	= le16_to_cpu(set1->u64s);
	n1->nr.bset_u64s[0]	= le16_to_cpu(set1->u64s);
	n1->nr.packed_keys	= nr_packed;
	n1->nr.unpacked_keys	= nr_unpacked;

	BUG_ON(!set1->u64s);
	BUG_ON(!set2->u64s);

	memcpy_u64s(set2->start,
		    vstruct_end(set1),
		    le16_to_cpu(set2->u64s));

	btree_node_reset_sib_u64s(n1);
	btree_node_reset_sib_u64s(n2);

	bch2_verify_btree_nr_keys(n1);
	bch2_verify_btree_nr_keys(n2);

	if (n1->level) {
		btree_node_interior_verify(n1);
		btree_node_interior_verify(n2);
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
static void btree_split_insert_keys(struct btree_iter *iter, struct btree *b,
				    struct keylist *keys,
				    struct btree_reserve *res)
{
	struct btree_node_iter node_iter;
	struct bkey_i *k = bch2_keylist_front(keys);
	struct bkey_packed *p;
	struct bset *i;

	BUG_ON(btree_node_type(b) != BKEY_TYPE_BTREE);

	bch2_btree_node_iter_init(&node_iter, b, k->k.p, false, false);

	while (!bch2_keylist_empty(keys)) {
		k = bch2_keylist_front(keys);

		BUG_ON(bch_keylist_u64s(keys) >
		       bch_btree_keys_u64s_remaining(iter->c, b));
		BUG_ON(bkey_cmp(k->k.p, b->data->min_key) < 0);
		BUG_ON(bkey_cmp(k->k.p, b->data->max_key) > 0);

		bch2_insert_fixup_btree_ptr(iter, b, k, &node_iter, &res->disk_res);
		bch2_keylist_pop_front(keys);
	}

	/*
	 * We can't tolerate whiteouts here - with whiteouts there can be
	 * duplicate keys, and it would be rather bad if we picked a duplicate
	 * for the pivot:
	 */
	i = btree_bset_first(b);
	p = i->start;
	while (p != vstruct_last(i))
		if (bkey_deleted(p)) {
			le16_add_cpu(&i->u64s, -p->u64s);
			set_btree_bset_end(b, b->set);
			memmove_u64s_down(p, bkey_next(p),
					  (u64 *) vstruct_last(i) -
					  (u64 *) p);
		} else
			p = bkey_next(p);

	BUG_ON(b->nsets != 1 ||
	       b->nr.live_u64s != le16_to_cpu(btree_bset_first(b)->u64s));

	btree_node_interior_verify(b);
}

static void btree_split(struct btree *b, struct btree_iter *iter,
			struct keylist *insert_keys,
			struct btree_reserve *reserve,
			struct btree_interior_update *as)
{
	struct bch_fs *c = iter->c;
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	u64 start_time = local_clock();

	BUG_ON(!parent && (b != btree_node_root(c, b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(c, b)->level));

	bch2_btree_interior_update_will_free_node(c, as, b);

	n1 = bch2_btree_node_alloc_replacement(c, b, reserve);
	list_add(&n1->reachable, &as->reachable_list);

	if (b->level)
		btree_split_insert_keys(iter, n1, insert_keys, reserve);

	if (vstruct_blocks(n1->data, c->block_bits) > BTREE_SPLIT_THRESHOLD(c)) {
		trace_btree_node_split(c, b, b->nr.live_u64s);

		n2 = __btree_split_node(iter, n1, reserve, as);

		bch2_btree_build_aux_trees(n2);
		bch2_btree_build_aux_trees(n1);
		six_unlock_write(&n2->lock);
		six_unlock_write(&n1->lock);

		bch2_btree_node_write(c, n2, &as->cl, SIX_LOCK_intent);

		/*
		 * Note that on recursive parent_keys == insert_keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		bch2_keylist_add(&as->parent_keys, &n1->key);
		bch2_keylist_add(&as->parent_keys, &n2->key);

		if (!parent) {
			/* Depth increases, make a new root */
			n3 = __btree_root_alloc(c, b->level + 1,
						iter->btree_id,
						reserve);
			list_add(&n3->reachable, &as->reachable_list);

			n3->sib_u64s[0] = U16_MAX;
			n3->sib_u64s[1] = U16_MAX;

			btree_split_insert_keys(iter, n3, &as->parent_keys,
						reserve);
			bch2_btree_node_write(c, n3, &as->cl, SIX_LOCK_intent);
		}
	} else {
		trace_btree_node_compact(c, b, b->nr.live_u64s);

		bch2_btree_build_aux_trees(n1);
		six_unlock_write(&n1->lock);

		bch2_keylist_add(&as->parent_keys, &n1->key);
	}

	bch2_btree_node_write(c, n1, &as->cl, SIX_LOCK_intent);

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		bch2_btree_insert_node(parent, iter, &as->parent_keys,
				      reserve, as);
	} else if (n3) {
		bch2_btree_set_root(iter, n3, as, reserve);
	} else {
		/* Root filled up but didn't need to be split */
		bch2_btree_set_root(iter, n1, as, reserve);
	}

	bch2_btree_open_bucket_put(c, n1);
	if (n2)
		bch2_btree_open_bucket_put(c, n2);
	if (n3)
		bch2_btree_open_bucket_put(c, n3);

	/*
	 * Note - at this point other linked iterators could still have @b read
	 * locked; we're depending on the bch2_btree_iter_node_replace() calls
	 * below removing all references to @b so we don't return with other
	 * iterators pointing to a node they have locked that's been freed.
	 *
	 * We have to free the node first because the bch2_iter_node_replace()
	 * calls will drop _our_ iterator's reference - and intent lock - to @b.
	 */
	bch2_btree_node_free_inmem(iter, b);

	/* Successful split, update the iterator to point to the new nodes: */

	if (n3)
		bch2_btree_iter_node_replace(iter, n3);
	if (n2)
		bch2_btree_iter_node_replace(iter, n2);
	bch2_btree_iter_node_replace(iter, n1);

	bch2_time_stats_update(&c->btree_split_time, start_time);
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @hook:		insert callback
 * @persistent:		if not null, @persistent will wait on journal write
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
void bch2_btree_insert_node(struct btree *b,
			   struct btree_iter *iter,
			   struct keylist *insert_keys,
			   struct btree_reserve *reserve,
			   struct btree_interior_update *as)
{
	BUG_ON(!b->level);
	BUG_ON(!reserve || !as);

	switch (bch2_btree_insert_keys_interior(b, iter, insert_keys,
					       as, reserve)) {
	case BTREE_INSERT_OK:
		break;
	case BTREE_INSERT_BTREE_NODE_FULL:
		btree_split(b, iter, insert_keys, reserve, as);
		break;
	default:
		BUG();
	}
}

static int bch2_btree_split_leaf(struct btree_iter *iter, unsigned flags)
{
	struct bch_fs *c = iter->c;
	struct btree *b = iter->nodes[0];
	struct btree_reserve *reserve;
	struct btree_interior_update *as;
	struct closure cl;
	int ret = 0;

	closure_init_stack(&cl);

	/* Hack, because gc and splitting nodes doesn't mix yet: */
	if (!down_read_trylock(&c->gc_lock)) {
		bch2_btree_iter_unlock(iter);
		down_read(&c->gc_lock);
	}

	/*
	 * XXX: figure out how far we might need to split,
	 * instead of locking/reserving all the way to the root:
	 */
	if (!bch2_btree_iter_set_locks_want(iter, U8_MAX)) {
		ret = -EINTR;
		goto out;
	}

	reserve = bch2_btree_reserve_get(c, b, 0, flags, &cl);
	if (IS_ERR(reserve)) {
		ret = PTR_ERR(reserve);
		if (ret == -EAGAIN) {
			bch2_btree_iter_unlock(iter);
			up_read(&c->gc_lock);
			closure_sync(&cl);
			return -EINTR;
		}
		goto out;
	}

	as = bch2_btree_interior_update_alloc(c);

	btree_split(b, iter, NULL, reserve, as);
	bch2_btree_reserve_put(c, reserve);

	bch2_btree_iter_set_locks_want(iter, 1);
out:
	up_read(&c->gc_lock);
	return ret;
}

enum btree_node_sibling {
	btree_prev_sib,
	btree_next_sib,
};

static struct btree *btree_node_get_sibling(struct btree_iter *iter,
					    struct btree *b,
					    enum btree_node_sibling sib)
{
	struct btree *parent;
	struct btree_node_iter node_iter;
	struct bkey_packed *k;
	BKEY_PADDED(k) tmp;
	struct btree *ret;
	unsigned level = b->level;

	parent = iter->nodes[level + 1];
	if (!parent)
		return NULL;

	if (!bch2_btree_node_relock(iter, level + 1)) {
		bch2_btree_iter_set_locks_want(iter, level + 2);
		return ERR_PTR(-EINTR);
	}

	node_iter = iter->node_iters[parent->level];

	k = bch2_btree_node_iter_peek_all(&node_iter, parent);
	BUG_ON(bkey_cmp_left_packed(parent, k, &b->key.k.p));

	do {
		k = sib == btree_prev_sib
			? bch2_btree_node_iter_prev_all(&node_iter, parent)
			: (bch2_btree_node_iter_advance(&node_iter, parent),
			   bch2_btree_node_iter_peek_all(&node_iter, parent));
		if (!k)
			return NULL;
	} while (bkey_deleted(k));

	bch2_bkey_unpack(parent, &tmp.k, k);

	ret = bch2_btree_node_get(iter, &tmp.k, level, SIX_LOCK_intent);

	if (IS_ERR(ret) && PTR_ERR(ret) == -EINTR) {
		btree_node_unlock(iter, level);
		ret = bch2_btree_node_get(iter, &tmp.k, level, SIX_LOCK_intent);
	}

	if (!IS_ERR(ret) && !bch2_btree_node_relock(iter, level)) {
		six_unlock_intent(&ret->lock);
		ret = ERR_PTR(-EINTR);
	}

	return ret;
}

static int __foreground_maybe_merge(struct btree_iter *iter,
				    enum btree_node_sibling sib)
{
	struct bch_fs *c = iter->c;
	struct btree_reserve *reserve;
	struct btree_interior_update *as;
	struct bkey_format_state new_s;
	struct bkey_format new_f;
	struct bkey_i delete;
	struct btree *b, *m, *n, *prev, *next, *parent;
	struct closure cl;
	size_t sib_u64s;
	int ret = 0;

	closure_init_stack(&cl);
retry:
	if (!bch2_btree_node_relock(iter, iter->level))
		return 0;

	b = iter->nodes[iter->level];

	parent = iter->nodes[b->level + 1];
	if (!parent)
		return 0;

	if (b->sib_u64s[sib] > BTREE_FOREGROUND_MERGE_THRESHOLD(c))
		return 0;

	/* XXX: can't be holding read locks */
	m = btree_node_get_sibling(iter, b, sib);
	if (IS_ERR(m)) {
		ret = PTR_ERR(m);
		goto out;
	}

	/* NULL means no sibling: */
	if (!m) {
		b->sib_u64s[sib] = U16_MAX;
		return 0;
	}

	if (sib == btree_prev_sib) {
		prev = m;
		next = b;
	} else {
		prev = b;
		next = m;
	}

	bch2_bkey_format_init(&new_s);
	__bch2_btree_calc_format(&new_s, b);
	__bch2_btree_calc_format(&new_s, m);
	new_f = bch2_bkey_format_done(&new_s);

	sib_u64s = btree_node_u64s_with_format(b, &new_f) +
		btree_node_u64s_with_format(m, &new_f);

	if (sib_u64s > BTREE_FOREGROUND_MERGE_HYSTERESIS(c)) {
		sib_u64s -= BTREE_FOREGROUND_MERGE_HYSTERESIS(c);
		sib_u64s /= 2;
		sib_u64s += BTREE_FOREGROUND_MERGE_HYSTERESIS(c);
	}

	sib_u64s = min(sib_u64s, btree_max_u64s(c));
	b->sib_u64s[sib] = sib_u64s;

	if (b->sib_u64s[sib] > BTREE_FOREGROUND_MERGE_THRESHOLD(c)) {
		six_unlock_intent(&m->lock);
		return 0;
	}

	/* We're changing btree topology, doesn't mix with gc: */
	if (!down_read_trylock(&c->gc_lock)) {
		six_unlock_intent(&m->lock);
		bch2_btree_iter_unlock(iter);

		down_read(&c->gc_lock);
		up_read(&c->gc_lock);
		ret = -EINTR;
		goto out;
	}

	if (!bch2_btree_iter_set_locks_want(iter, U8_MAX)) {
		ret = -EINTR;
		goto out_unlock;
	}

	reserve = bch2_btree_reserve_get(c, b, 0,
					BTREE_INSERT_NOFAIL|
					BTREE_INSERT_USE_RESERVE,
					&cl);
	if (IS_ERR(reserve)) {
		ret = PTR_ERR(reserve);
		goto out_unlock;
	}

	as = bch2_btree_interior_update_alloc(c);

	bch2_btree_interior_update_will_free_node(c, as, b);
	bch2_btree_interior_update_will_free_node(c, as, m);

	n = bch2_btree_node_alloc(c, b->level, b->btree_id, reserve);
	list_add(&n->reachable, &as->reachable_list);

	n->data->min_key	= prev->data->min_key;
	n->data->max_key	= next->data->max_key;
	n->data->format		= new_f;
	n->key.k.p		= next->key.k.p;

	btree_node_set_format(n, new_f);

	bch2_btree_sort_into(c, n, prev);
	bch2_btree_sort_into(c, n, next);

	bch2_btree_build_aux_trees(n);
	six_unlock_write(&n->lock);

	bkey_init(&delete.k);
	delete.k.p = prev->key.k.p;
	bch2_keylist_add(&as->parent_keys, &delete);
	bch2_keylist_add(&as->parent_keys, &n->key);

	bch2_btree_node_write(c, n, &as->cl, SIX_LOCK_intent);

	bch2_btree_insert_node(parent, iter, &as->parent_keys, reserve, as);

	bch2_btree_open_bucket_put(c, n);
	bch2_btree_node_free_inmem(iter, b);
	bch2_btree_node_free_inmem(iter, m);
	bch2_btree_iter_node_replace(iter, n);

	bch2_btree_iter_verify(iter, n);

	bch2_btree_reserve_put(c, reserve);
out_unlock:
	if (ret != -EINTR && ret != -EAGAIN)
		bch2_btree_iter_set_locks_want(iter, 1);
	six_unlock_intent(&m->lock);
	up_read(&c->gc_lock);
out:
	if (ret == -EAGAIN || ret == -EINTR) {
		bch2_btree_iter_unlock(iter);
		ret = -EINTR;
	}

	closure_sync(&cl);

	if (ret == -EINTR) {
		ret = bch2_btree_iter_traverse(iter);
		if (!ret)
			goto retry;
	}

	return ret;
}

static int inline foreground_maybe_merge(struct btree_iter *iter,
					 enum btree_node_sibling sib)
{
	struct bch_fs *c = iter->c;
	struct btree *b;

	if (!btree_node_locked(iter, iter->level))
		return 0;

	b = iter->nodes[iter->level];
	if (b->sib_u64s[sib] > BTREE_FOREGROUND_MERGE_THRESHOLD(c))
		return 0;

	return __foreground_maybe_merge(iter, sib);
}

/**
 * btree_insert_key - insert a key one key into a leaf node
 */
static enum btree_insert_ret
btree_insert_key(struct btree_insert *trans,
		 struct btree_insert_entry *insert)
{
	struct bch_fs *c = trans->c;
	struct btree_iter *iter = insert->iter;
	struct btree *b = iter->nodes[0];
	enum btree_insert_ret ret;
	int old_u64s = le16_to_cpu(btree_bset_last(b)->u64s);
	int old_live_u64s = b->nr.live_u64s;
	int live_u64s_added, u64s_added;

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
	    bch2_maybe_compact_whiteouts(iter->c, b))
		bch2_btree_iter_reinit_node(iter, b);

	trace_btree_insert_key(c, b, insert->k);
	return ret;
}

static bool same_leaf_as_prev(struct btree_insert *trans,
			      struct btree_insert_entry *i)
{
	/*
	 * Because we sorted the transaction entries, if multiple iterators
	 * point to the same leaf node they'll always be adjacent now:
	 */
	return i != trans->entries &&
		i[0].iter->nodes[0] == i[-1].iter->nodes[0];
}

#define trans_for_each_entry(trans, i)					\
	for ((i) = (trans)->entries; (i) < (trans)->entries + (trans)->nr; (i)++)

static void multi_lock_write(struct btree_insert *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_entry(trans, i)
		if (!same_leaf_as_prev(trans, i))
			btree_node_lock_for_insert(i->iter->nodes[0], i->iter);
}

static void multi_unlock_write(struct btree_insert *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_entry(trans, i)
		if (!same_leaf_as_prev(trans, i))
			bch2_btree_node_unlock_write(i->iter->nodes[0], i->iter);
}

static int btree_trans_entry_cmp(const void *_l, const void *_r)
{
	const struct btree_insert_entry *l = _l;
	const struct btree_insert_entry *r = _r;

	return btree_iter_cmp(l->iter, r->iter);
}

/* Normal update interface: */

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
	struct btree_iter *split = NULL;
	bool cycle_gc_lock = false;
	unsigned u64s;
	int ret;

	trans_for_each_entry(trans, i) {
		EBUG_ON(i->iter->level);
		EBUG_ON(bkey_cmp(bkey_start_pos(&i->k->k), i->iter->pos));
	}

	sort(trans->entries, trans->nr, sizeof(trans->entries[0]),
	     btree_trans_entry_cmp, NULL);

	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return -EROFS;
retry_locks:
	ret = -EINTR;
	trans_for_each_entry(trans, i)
		if (!bch2_btree_iter_set_locks_want(i->iter, 1))
			goto err;
retry:
	trans->did_work = false;
	u64s = 0;
	trans_for_each_entry(trans, i)
		if (!i->done)
			u64s += jset_u64s(i->k->k.u64s + i->extra_res);

	memset(&trans->journal_res, 0, sizeof(trans->journal_res));

	ret = !(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)
		? bch2_journal_res_get(&c->journal,
				      &trans->journal_res,
				      u64s, u64s)
		: 0;
	if (ret)
		goto err;

	multi_lock_write(trans);

	u64s = 0;
	trans_for_each_entry(trans, i) {
		/* Multiple inserts might go to same leaf: */
		if (!same_leaf_as_prev(trans, i))
			u64s = 0;

		/*
		 * bch2_btree_node_insert_fits() must be called under write lock:
		 * with only an intent lock, another thread can still call
		 * bch2_btree_node_write(), converting an unwritten bset to a
		 * written one
		 */
		if (!i->done) {
			u64s += i->k->k.u64s + i->extra_res;
			if (!bch2_btree_node_insert_fits(c,
					i->iter->nodes[0], u64s)) {
				split = i->iter;
				goto unlock;
			}
		}
	}

	ret = 0;
	split = NULL;
	cycle_gc_lock = false;

	trans_for_each_entry(trans, i) {
		if (i->done)
			continue;

		switch (btree_insert_key(trans, i)) {
		case BTREE_INSERT_OK:
			i->done = true;
			break;
		case BTREE_INSERT_JOURNAL_RES_FULL:
		case BTREE_INSERT_NEED_TRAVERSE:
			ret = -EINTR;
			break;
		case BTREE_INSERT_NEED_RESCHED:
			ret = -EAGAIN;
			break;
		case BTREE_INSERT_BTREE_NODE_FULL:
			split = i->iter;
			break;
		case BTREE_INSERT_ENOSPC:
			ret = -ENOSPC;
			break;
		case BTREE_INSERT_NEED_GC_LOCK:
			cycle_gc_lock = true;
			ret = -EINTR;
			break;
		default:
			BUG();
		}

		if (!trans->did_work && (ret || split))
			break;
	}
unlock:
	multi_unlock_write(trans);
	bch2_journal_res_put(&c->journal, &trans->journal_res);

	if (split)
		goto split;
	if (ret)
		goto err;

	/*
	 * hack: iterators are inconsistent when they hit end of leaf, until
	 * traversed again
	 */
	trans_for_each_entry(trans, i)
		if (i->iter->at_end_of_leaf)
			goto out;

	trans_for_each_entry(trans, i)
		if (!same_leaf_as_prev(trans, i)) {
			foreground_maybe_merge(i->iter, btree_prev_sib);
			foreground_maybe_merge(i->iter, btree_next_sib);
		}
out:
	/* make sure we didn't lose an error: */
	if (!ret && IS_ENABLED(CONFIG_BCACHEFS_DEBUG))
		trans_for_each_entry(trans, i)
			BUG_ON(!i->done);

	percpu_ref_put(&c->writes);
	return ret;
split:
	/*
	 * have to drop journal res before splitting, because splitting means
	 * allocating new btree nodes, and holding a journal reservation
	 * potentially blocks the allocator:
	 */
	ret = bch2_btree_split_leaf(split, trans->flags);
	if (ret)
		goto err;
	/*
	 * if the split didn't have to drop locks the insert will still be
	 * atomic (in the BTREE_INSERT_ATOMIC sense, what the caller peeked()
	 * and is overwriting won't have changed)
	 */
	goto retry_locks;
err:
	if (cycle_gc_lock) {
		down_read(&c->gc_lock);
		up_read(&c->gc_lock);
	}

	if (ret == -EINTR) {
		trans_for_each_entry(trans, i) {
			int ret2 = bch2_btree_iter_traverse(i->iter);
			if (ret2) {
				ret = ret2;
				goto out;
			}
		}

		/*
		 * BTREE_ITER_ATOMIC means we have to return -EINTR if we
		 * dropped locks:
		 */
		if (!(trans->flags & BTREE_INSERT_ATOMIC))
			goto retry;
	}

	goto out;
}

int bch2_btree_insert_list_at(struct btree_iter *iter,
			     struct keylist *keys,
			     struct disk_reservation *disk_res,
			     struct extent_insert_hook *hook,
			     u64 *journal_seq, unsigned flags)
{
	BUG_ON(flags & BTREE_INSERT_ATOMIC);
	BUG_ON(bch2_keylist_empty(keys));
	verify_keys_sorted(keys);

	while (!bch2_keylist_empty(keys)) {
		/* need to traverse between each insert */
		int ret = bch2_btree_iter_traverse(iter);
		if (ret)
			return ret;

		ret = bch2_btree_insert_at(iter->c, disk_res, hook,
				journal_seq, flags,
				BTREE_INSERT_ENTRY(iter, bch2_keylist_front(keys)));
		if (ret)
			return ret;

		bch2_keylist_pop_front(keys);
	}

	return 0;
}

/**
 * bch_btree_insert_check_key - insert dummy key into btree
 *
 * We insert a random key on a cache miss, then compare exchange on it
 * once the cache promotion or backing device read completes. This
 * ensures that if this key is written to after the read, the read will
 * lose and not overwrite the key with stale data.
 *
 * Return values:
 * -EAGAIN: @iter->cl was put on a waitlist waiting for btree node allocation
 * -EINTR: btree node was changed while upgrading to write lock
 */
int bch2_btree_insert_check_key(struct btree_iter *iter,
			       struct bkey_i *check_key)
{
	struct bpos saved_pos = iter->pos;
	struct bkey_i_cookie *cookie;
	BKEY_PADDED(key) tmp;
	int ret;

	BUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&check_key->k)));

	check_key->k.type = KEY_TYPE_COOKIE;
	set_bkey_val_bytes(&check_key->k, sizeof(struct bch_cookie));

	cookie = bkey_i_to_cookie(check_key);
	get_random_bytes(&cookie->v, sizeof(cookie->v));

	bkey_copy(&tmp.key, check_key);

	ret = bch2_btree_insert_at(iter->c, NULL, NULL, NULL,
				  BTREE_INSERT_ATOMIC,
				  BTREE_INSERT_ENTRY(iter, &tmp.key));

	bch2_btree_iter_rewind(iter, saved_pos);

	return ret;
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
		     struct extent_insert_hook *hook,
		     u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	int ret, ret2;

	bch2_btree_iter_init_intent(&iter, c, id, bkey_start_pos(&k->k));

	ret = bch2_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch2_btree_insert_at(c, disk_res, hook, journal_seq, flags,
				  BTREE_INSERT_ENTRY(&iter, k));
out:	ret2 = bch2_btree_iter_unlock(&iter);

	return ret ?: ret2;
}

/**
 * bch_btree_update - like bch2_btree_insert(), but asserts that we're
 * overwriting an existing key
 */
int bch2_btree_update(struct bch_fs *c, enum btree_id id,
		     struct bkey_i *k, u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c u;
	int ret;

	EBUG_ON(id == BTREE_ID_EXTENTS);

	bch2_btree_iter_init_intent(&iter, c, id, k->k.p);

	u = bch2_btree_iter_peek_with_holes(&iter);
	ret = btree_iter_err(u);
	if (ret)
		return ret;

	if (bkey_deleted(u.k)) {
		bch2_btree_iter_unlock(&iter);
		return -ENOENT;
	}

	ret = bch2_btree_insert_at(c, NULL, NULL, journal_seq, 0,
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
			   struct bpos start,
			   struct bpos end,
			   struct bversion version,
			   struct disk_reservation *disk_res,
			   struct extent_insert_hook *hook,
			   u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch2_btree_iter_init_intent(&iter, c, id, start);

	while ((k = bch2_btree_iter_peek(&iter)).k &&
	       !(ret = btree_iter_err(k))) {
		unsigned max_sectors = KEY_SIZE_MAX & (~0 << c->block_bits);
		/* really shouldn't be using a bare, unpadded bkey_i */
		struct bkey_i delete;

		if (bkey_cmp(iter.pos, end) >= 0)
			break;

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
		delete.k.version = version;

		if (iter.is_extents) {
			/*
			 * The extents btree is special - KEY_TYPE_DISCARD is
			 * used for deletions, not KEY_TYPE_DELETED. This is an
			 * internal implementation detail that probably
			 * shouldn't be exposed (internally, KEY_TYPE_DELETED is
			 * used as a proxy for k->size == 0):
			 */
			delete.k.type = KEY_TYPE_DISCARD;

			/* create the biggest key we can */
			bch2_key_resize(&delete.k, max_sectors);
			bch2_cut_back(end, &delete.k);
		}

		ret = bch2_btree_insert_at(c, disk_res, hook, journal_seq,
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(&iter, &delete));
		if (ret)
			break;

		bch2_btree_iter_cond_resched(&iter);
	}

	bch2_btree_iter_unlock(&iter);
	return ret;
}

/**
 * bch_btree_node_rewrite - Rewrite/move a btree node
 *
 * Returns 0 on success, -EINTR or -EAGAIN on failure (i.e.
 * btree_check_reserve() has to wait)
 */
int bch2_btree_node_rewrite(struct btree_iter *iter, struct btree *b,
			   struct closure *cl)
{
	struct bch_fs *c = iter->c;
	struct btree *n, *parent = iter->nodes[b->level + 1];
	struct btree_reserve *reserve;
	struct btree_interior_update *as;
	unsigned flags = BTREE_INSERT_NOFAIL;

	/*
	 * if caller is going to wait if allocating reserve fails, then this is
	 * a rewrite that must succeed:
	 */
	if (cl)
		flags |= BTREE_INSERT_USE_RESERVE;

	if (!bch2_btree_iter_set_locks_want(iter, U8_MAX))
		return -EINTR;

	reserve = bch2_btree_reserve_get(c, b, 0, flags, cl);
	if (IS_ERR(reserve)) {
		trace_btree_gc_rewrite_node_fail(c, b);
		return PTR_ERR(reserve);
	}

	as = bch2_btree_interior_update_alloc(c);

	bch2_btree_interior_update_will_free_node(c, as, b);

	n = bch2_btree_node_alloc_replacement(c, b, reserve);
	list_add(&n->reachable, &as->reachable_list);

	bch2_btree_build_aux_trees(n);
	six_unlock_write(&n->lock);

	trace_btree_gc_rewrite_node(c, b);

	bch2_btree_node_write(c, n, &as->cl, SIX_LOCK_intent);

	if (parent) {
		bch2_btree_insert_node(parent, iter,
				      &keylist_single(&n->key),
				      reserve, as);
	} else {
		bch2_btree_set_root(iter, n, as, reserve);
	}

	bch2_btree_open_bucket_put(c, n);

	bch2_btree_node_free_inmem(iter, b);

	BUG_ON(!bch2_btree_iter_node_replace(iter, n));

	bch2_btree_reserve_put(c, reserve);
	return 0;
}
