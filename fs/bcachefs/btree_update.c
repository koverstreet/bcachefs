
#include "bcache.h"
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
#include "super.h"

#include <linux/random.h>
#include <linux/sort.h>
#include <trace/events/bcachefs.h>

static void btree_interior_update_updated_root(struct cache_set *,
					       struct btree_interior_update *,
					       enum btree_id);

/* Calculate ideal packed bkey format for new btree nodes: */

void __bch_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey unpacked;
	struct bkey_s_c k;

	for_each_btree_node_key_unpack(&b->keys, k, &iter, &unpacked)
		bch_bkey_format_add_key(s, k.k);
}

static struct bkey_format bch_btree_calc_format(struct btree *b)
{
	struct bkey_format_state s;

	bch_bkey_format_init(&s);
	__bch_btree_calc_format(&s, b);

	return bch_bkey_format_done(&s);
}

/**
 * btree_node_format_fits - check if we could rewrite node with a new format
 *
 * This assumes all keys can pack with the new format -- it just checks if
 * the re-packed keys would fit inside the node itself.
 */
bool bch_btree_node_format_fits(struct btree *b, struct bkey_format *new_f)
{
	struct bkey_format *old_f = &b->keys.format;

	/* stupid integer promotion rules */
	ssize_t new_u64s =
	    (((int) new_f->key_u64s - old_f->key_u64s) *
	     (int) b->keys.nr.packed_keys) +
	    (((int) new_f->key_u64s - BKEY_U64s) *
	     (int) b->keys.nr.unpacked_keys);

	bch_verify_btree_nr_keys(&b->keys);

	BUG_ON(new_u64s + b->keys.nr.live_u64s < 0);

	return __set_bytes(b->data, b->keys.nr.live_u64s + new_u64s) <
		PAGE_SIZE << b->keys.page_order;
}

/* Btree node freeing/allocation: */

/*
 * We're doing the index update that makes @b unreachable, update stuff to
 * reflect that:
 *
 * Must be called _before_ btree_interior_update_updated_root() or
 * btree_interior_update_updated_btree:
 */
static void bch_btree_node_free_index(struct cache_set *c, struct btree *b,
				      enum btree_id id, struct bkey_s_c k,
				      struct bucket_stats_cache_set *stats)
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
	 * Btree nodes are accounted as freed in cache_set_stats when they're
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
	 * bch_mark_key() compares the current gc pos to the pos we're
	 * moving this reference from, hence one comparison here:
	 */
	if (gc_pos_cmp(c->gc_pos, gc_phase(GC_PHASE_PENDING_DELETE)) < 0) {
		struct bucket_stats_cache_set tmp = { 0 };

		bch_mark_key(c, bkey_i_to_s_c(&d->key),
			     -c->sb.btree_node_size, true, b
			     ? gc_pos_btree_node(b)
			     : gc_pos_btree_root(id),
			     &tmp);
		/*
		 * Don't apply tmp - pending deletes aren't tracked in
		 * cache_set_stats:
		 */
	}

	mutex_unlock(&c->btree_interior_update_lock);
}

static void __btree_node_free(struct cache_set *c, struct btree *b,
			      struct btree_iter *iter)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));
	BUG_ON(b->ob);
	BUG_ON(!list_empty(&b->write_blocked));

	six_lock_write(&b->lock);

	if (btree_node_dirty(b))
		bch_btree_complete_write(c, b, btree_current_write(b));
	clear_btree_node_dirty(b);
	cancel_delayed_work(&b->work);

	mca_hash_remove(c, b);

	mutex_lock(&c->btree_cache_lock);
	list_move(&b->list, &c->btree_cache_freeable);
	mutex_unlock(&c->btree_cache_lock);

	/*
	 * By using six_unlock_write() directly instead of
	 * btree_node_unlock_write(), we don't update the iterator's sequence
	 * numbers and cause future btree_node_relock() calls to fail:
	 */
	six_unlock_write(&b->lock);
}

void bch_btree_node_free_never_inserted(struct cache_set *c, struct btree *b)
{
	struct open_bucket *ob = b->ob;

	b->ob = NULL;

	__btree_node_free(c, b, NULL);

	bch_open_bucket_put(c, ob);
}

void bch_btree_node_free_inmem(struct btree_iter *iter, struct btree *b)
{
	bch_btree_iter_node_drop_linked(iter, b);

	__btree_node_free(iter->c, b, iter);

	bch_btree_iter_node_drop(iter, b);
}

static void bch_btree_node_free_ondisk(struct cache_set *c,
				       struct pending_btree_node_free *pending)
{
	struct bucket_stats_cache_set stats = { 0 };

	BUG_ON(!pending->index_update_done);

	bch_mark_key(c, bkey_i_to_s_c(&pending->key),
		     -c->sb.btree_node_size, true,
		     gc_phase(GC_PHASE_PENDING_DELETE),
		     &stats);
	/*
	 * Don't apply stats - pending deletes aren't tracked in
	 * cache_set_stats:
	 */
}

void btree_open_bucket_put(struct cache_set *c, struct btree *b)
{
	bch_open_bucket_put(c, b->ob);
	b->ob = NULL;
}

static struct btree *__bch_btree_node_alloc(struct cache_set *c,
					    struct disk_reservation *res,
					    struct closure *cl)
{
	BKEY_PADDED(k) tmp;
	struct open_bucket *ob;
	struct btree *b;

	mutex_lock(&c->btree_reserve_cache_lock);
	if (c->btree_reserve_cache_nr) {
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

	ob = bch_alloc_sectors(c, &c->btree_write_point,
			       bkey_i_to_extent(&tmp.k),
			       res->nr_replicas, cl);
	if (IS_ERR(ob))
		return ERR_CAST(ob);

	if (tmp.k.k.size < c->sb.btree_node_size) {
		bch_open_bucket_put(c, ob);
		goto retry;
	}
mem_alloc:
	b = mca_alloc(c, NULL);

	/* we hold cannibalize_lock: */
	BUG_ON(IS_ERR(b));
	BUG_ON(b->ob);

	bkey_copy(&b->key, &tmp.k);
	b->key.k.size = 0;
	b->ob = ob;

	return b;
}

static struct btree *bch_btree_node_alloc(struct cache_set *c,
					  unsigned level, enum btree_id id,
					  struct btree_reserve *reserve)
{
	struct btree *b;

	BUG_ON(!reserve->nr);

	b = reserve->b[--reserve->nr];

	BUG_ON(mca_hash_insert(c, b, level, id));

	set_btree_node_accessed(b);
	set_btree_node_dirty(b);

	bch_bset_init_first(&b->keys, &b->data->keys);
	b->data->magic = cpu_to_le64(bset_magic(&c->disk_sb));
	SET_BSET_BTREE_LEVEL(&b->data->keys, level);

	bch_check_mark_super(c, &b->key, true);

	trace_bcache_btree_node_alloc(b);
	return b;
}

struct btree *__btree_node_alloc_replacement(struct cache_set *c,
					     struct btree *b,
					     struct bkey_format format,
					     struct btree_reserve *reserve)
{
	struct btree *n;

	n = bch_btree_node_alloc(c, b->level, b->btree_id, reserve);

	n->data->min_key	= b->data->min_key;
	n->data->max_key	= b->data->max_key;
	n->data->format		= format;
	n->keys.format		= format;

	bch_btree_sort_into(&n->keys, &b->keys,
			    b->keys.ops->key_normalize,
			    &c->sort);

	n->key.k.p = b->key.k.p;
	trace_bcache_btree_node_alloc_replacement(b, n);

	return n;
}

struct btree *btree_node_alloc_replacement(struct cache_set *c,
					   struct btree *b,
					   struct btree_reserve *reserve)
{
	struct bkey_format new_f = bch_btree_calc_format(b);

	/*
	 * The keys might expand with the new format - if they wouldn't fit in
	 * the btree node anymore, use the old format for now:
	 */
	if (!bch_btree_node_format_fits(b, &new_f))
		new_f = b->keys.format;

	return __btree_node_alloc_replacement(c, b, new_f, reserve);
}

static void bch_btree_set_root_inmem(struct cache_set *c, struct btree *b,
				     struct btree_reserve *btree_reserve)
{
	struct btree *old = btree_node_root(b);

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	mutex_lock(&c->btree_root_lock);
	btree_node_root(b) = b;
	mutex_unlock(&c->btree_root_lock);

	if (btree_reserve) {
		/*
		 * New allocation (we're not being called because we're in
		 * bch_btree_root_read()) - do marking while holding
		 * btree_root_lock:
		 */
		struct bucket_stats_cache_set stats = { 0 };

		bch_mark_key(c, bkey_i_to_s_c(&b->key),
			     c->sb.btree_node_size, true,
			     gc_pos_btree_root(b->btree_id),
			     &stats);

		if (old)
			bch_btree_node_free_index(c, NULL, old->btree_id,
						  bkey_i_to_s_c(&old->key),
						  &stats);
		bch_cache_set_stats_apply(c, &stats, &btree_reserve->disk_res,
					  gc_pos_btree_root(b->btree_id));
	}

	bch_recalc_btree_reserve(c);
}

static void bch_btree_set_root_ondisk(struct cache_set *c, struct btree *b)
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
 * Only for cache set bringup, when first reading the btree roots or allocating
 * btree roots when initializing a new cache set:
 */
void bch_btree_set_root_initial(struct cache_set *c, struct btree *b,
				struct btree_reserve *btree_reserve)
{
	BUG_ON(btree_node_root(b));

	bch_btree_set_root_inmem(c, b, btree_reserve);
	bch_btree_set_root_ondisk(c, b);
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
static void bch_btree_set_root(struct btree_iter *iter, struct btree *b,
			       struct btree_interior_update *as,
			       struct btree_reserve *btree_reserve)
{
	struct cache_set *c = iter->c;
	struct btree *old;

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	btree_node_lock_write(old, iter);

	bch_btree_set_root_inmem(c, b, btree_reserve);

	btree_interior_update_updated_root(c, as, iter->btree_id);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	btree_node_unlock_write(old, iter);
}

static struct btree *__btree_root_alloc(struct cache_set *c, unsigned level,
					enum btree_id id,
					struct btree_reserve *reserve)
{
	struct btree *b = bch_btree_node_alloc(c, level, id, reserve);

	b->data->min_key = POS_MIN;
	b->data->max_key = POS_MAX;
	b->data->format = bch_btree_calc_format(b);
	b->key.k.p = POS_MAX;

	six_unlock_write(&b->lock);

	return b;
}

void bch_btree_reserve_put(struct cache_set *c, struct btree_reserve *reserve)
{
	bch_disk_reservation_put(c, &reserve->disk_res);

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
			bch_open_bucket_put(c, b->ob);
			b->ob = NULL;
		}

		__btree_node_free(c, b, NULL);

		six_unlock_intent(&b->lock);
	}

	mutex_unlock(&c->btree_reserve_cache_lock);

	mempool_free(reserve, &c->btree_reserve_pool);
}

static struct btree_reserve *__bch_btree_reserve_get(struct cache_set *c,
					bool check_enospc,
					unsigned nr_nodes,
					struct closure *cl)
{
	struct btree_reserve *reserve;
	struct btree *b;
	struct disk_reservation disk_res = { 0, 0 };
	unsigned sectors = nr_nodes * c->sb.btree_node_size;
	int ret, flags = BCH_DISK_RESERVATION_GC_LOCK_HELD|
		BCH_DISK_RESERVATION_METADATA;

	if (!check_enospc)
		flags |= BCH_DISK_RESERVATION_NOFAIL;

	/*
	 * This check isn't necessary for correctness - it's just to potentially
	 * prevent us from doing a lot of work that'll end up being wasted:
	 */
	ret = bch_journal_error(&c->journal);
	if (ret)
		return ERR_PTR(ret);

	if (bch_disk_reservation_get(c, &disk_res, sectors, flags))
		return ERR_PTR(-ENOSPC);

	BUG_ON(nr_nodes > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	ret = mca_cannibalize_lock(c, cl);
	if (ret) {
		bch_disk_reservation_put(c, &disk_res);
		return ERR_PTR(ret);
	}

	reserve = mempool_alloc(&c->btree_reserve_pool, GFP_NOIO);

	reserve->disk_res = disk_res;
	reserve->nr = 0;

	while (reserve->nr < nr_nodes) {
		b = __bch_btree_node_alloc(c, &disk_res, cl);
		if (IS_ERR(b)) {
			ret = PTR_ERR(b);
			goto err_free;
		}

		reserve->b[reserve->nr++] = b;
	}

	mca_cannibalize_unlock(c);
	return reserve;
err_free:
	bch_btree_reserve_put(c, reserve);
	mca_cannibalize_unlock(c);
	trace_bcache_btree_reserve_get_fail(c, nr_nodes, cl);
	return ERR_PTR(ret);
}

struct btree_reserve *bch_btree_reserve_get(struct cache_set *c,
					    struct btree *b,
					    unsigned extra_nodes,
					    bool check_enospc,
					    struct closure *cl)
{
	unsigned depth = btree_node_root(b)->level - b->level;
	unsigned nr_nodes = btree_reserve_required_nodes(depth) + extra_nodes;

	return __bch_btree_reserve_get(c, check_enospc,
				       nr_nodes, cl);

}

int bch_btree_root_alloc(struct cache_set *c, enum btree_id id,
			 struct closure *writes)
{
	struct closure cl;
	struct btree_reserve *reserve;
	struct btree *b;

	closure_init_stack(&cl);

	while (1) {
		/* XXX haven't calculated capacity yet :/ */
		reserve = __bch_btree_reserve_get(c, false, 1, &cl);
		if (!IS_ERR(reserve))
			break;

		if (PTR_ERR(reserve) == -ENOSPC)
			return PTR_ERR(reserve);

		closure_sync(&cl);
	}

	b = __btree_root_alloc(c, 0, id, reserve);

	bch_btree_node_write(b, writes, NULL);

	bch_btree_set_root_initial(c, b, reserve);
	btree_open_bucket_put(c, b);
	six_unlock_intent(&b->lock);

	bch_btree_reserve_put(c, reserve);

	return 0;
}

static void bch_insert_fixup_btree_ptr(struct btree_iter *iter,
				       struct btree *b,
				       struct bkey_i *insert,
				       struct btree_node_iter *node_iter,
				       struct disk_reservation *disk_res)
{
	struct cache_set *c = iter->c;
	const struct bkey_format *f = &b->keys.format;
	struct bucket_stats_cache_set stats = { 0 };
	struct bkey_packed *k;
	struct bkey tmp;

	if (bkey_extent_is_data(&insert->k))
		bch_mark_key(c, bkey_i_to_s_c(insert),
			     c->sb.btree_node_size, true,
			     gc_pos_btree_node(b), &stats);

	while ((k = bch_btree_node_iter_peek_all(node_iter, &b->keys)) &&
	       !btree_iter_pos_cmp_packed(f, insert->k.p, k, false))
		bch_btree_node_iter_advance(node_iter, &b->keys);

	/*
	 * If we're overwriting, look up pending delete and mark so that gc
	 * marks it on the pending delete list:
	 */
	if (k && !bkey_cmp_packed(f, k, &insert->k))
		bch_btree_node_free_index(c, b, iter->btree_id,
					  bkey_disassemble(f, k, &tmp),
					  &stats);

	bch_cache_set_stats_apply(c, &stats, disk_res, gc_pos_btree_node(b));

	bch_btree_bset_insert_key(iter, b, node_iter, insert);
	set_btree_node_dirty(b);
}

/* Inserting into a given leaf node (last stage of insert): */

/* Wrapper around bch_bset_insert() that fixes linked iterators: */
void bch_btree_bset_insert(struct btree_iter *iter,
			   struct btree *b,
			   struct btree_node_iter *node_iter,
			   struct bkey_i *insert)
{
	struct bkey_packed *where;

	EBUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	EBUG_ON(insert->k.u64s > bch_btree_keys_u64s_remaining(iter->c, b));
	EBUG_ON(bkey_cmp(bkey_start_pos(&insert->k), b->data->min_key) < 0 ||
		bkey_cmp(insert->k.p, b->data->max_key) > 0);

	/*
	 * Note: when we're called from btree_split(), @b is not in @iter - and
	 * thus we can't use the node iter in @iter either, that's why it's
	 * passed in separately. This isn't an issue for the linked iterators,
	 * though.
	 */

	where = bch_bset_insert(&b->keys, node_iter, insert);

	bch_btree_node_iter_fix(iter, b, node_iter,
				bset_tree_last(&b->keys),
				where, false);
}

/* Handle overwrites and do insert, for non extents: */
void bch_btree_bset_insert_key(struct btree_iter *iter,
			       struct btree *b,
			       struct btree_node_iter *node_iter,
			       struct bkey_i *insert)
{
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	struct bset_tree *t;

	k = bch_btree_node_iter_peek_all(node_iter, &b->keys);
	if (k && !bkey_cmp_packed(f, k, &insert->k)) {
		t = bch_bkey_to_bset(&b->keys, k);

		if (bch_bset_try_overwrite(&b->keys, node_iter, t, k, insert)) {
			bch_btree_iter_verify(iter, b);
			return;
		}

		if (!bkey_packed_is_whiteout(&b->keys, k))
			btree_keys_account_key_drop(&b->keys.nr,
						t - b->keys.set, k);

		k->type = KEY_TYPE_DELETED;
		bch_btree_node_iter_fix(iter, b, node_iter, t, k, true);

		if (t == bset_tree_last(&b->keys) && bkey_deleted(&insert->k))
			return;
	}

	bch_btree_bset_insert(iter, b, node_iter, insert);
}

static void btree_node_flush(struct journal *j, struct journal_entry_pin *pin)
{
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[w->index]);

	six_lock_read(&b->lock);
	/*
	 * Reusing a btree node can race with the journal reclaim code calling
	 * the journal pin flush fn, and there's no good fix for this: we don't
	 * really want journal_pin_drop() to block until the flush fn is no
	 * longer running, because journal_pin_drop() is called from the btree
	 * node write endio function, and we can't wait on the flush fn to
	 * finish running in mca_reap() - where we make reused btree nodes ready
	 * to use again - because there, we're holding the lock this function
	 * needs - deadlock.
	 *
	 * So, the b->level check is a hack so we don't try to write nodes we
	 * shouldn't:
	 */
	if (!b->level)
		__bch_btree_node_write(b, NULL, w->index);
	six_unlock_read(&b->lock);
}

void bch_btree_journal_key(struct btree_iter *iter,
			   struct bkey_i *insert,
			   struct journal_res *res)
{
	struct cache_set *c = iter->c;
	struct journal *j = &c->journal;
	struct btree *b = iter->nodes[0];
	struct btree_write *w = btree_current_write(b);

	EBUG_ON(iter->level || b->level);
	EBUG_ON(!res->ref && test_bit(JOURNAL_REPLAY_DONE, &j->flags));

	if (!journal_pin_active(&w->journal))
		bch_journal_pin_add(j, &w->journal, btree_node_flush);

	if (res->ref) {
		bch_journal_add_keys(j, res, b->btree_id, insert);
		btree_bset_last(b)->journal_seq =
			cpu_to_le64(bch_journal_res_seq(j, res));
	}

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (c->btree_flush_delay)
			queue_delayed_work(system_freezable_wq, &b->work,
					   c->btree_flush_delay * HZ);
	}
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
	struct cache_set *c = iter->c;
relock:
	btree_node_lock_write(b, iter);

	BUG_ON(&write_block(b)->keys < btree_bset_last(b));

	/*
	 * If the last bset has been written, initialize a new one - check after
	 * taking the write lock because it can be written with only a read
	 * lock:
	 */
	if (b->written != c->sb.btree_node_size &&
	    &write_block(b)->keys > btree_bset_last(b)) {
		btree_node_unlock_write(b, iter);
		bch_btree_init_next(c, b, iter);
		goto relock;
	}
}

/* Asynchronous interior node update machinery */

struct btree_interior_update *
bch_btree_interior_update_alloc(struct cache_set *c)
{
	struct btree_interior_update *as;

	as = mempool_alloc(&c->btree_interior_update_pool, GFP_NOIO);
	memset(as, 0, sizeof(*as));
	closure_init(&as->cl, &c->cl);
	as->c		= c;
	as->mode	= BTREE_INTERIOR_NO_UPDATE;

	bch_keylist_init(&as->parent_keys, as->inline_keys,
			 ARRAY_SIZE(as->inline_keys));

	mutex_lock(&c->btree_interior_update_lock);
	list_add(&as->list, &c->btree_interior_update_list);
	mutex_unlock(&c->btree_interior_update_lock);

	return as;
}

static void btree_interior_update_free(struct closure *cl)
{
	struct btree_interior_update *as = container_of(cl, struct btree_interior_update, cl);

	mempool_free(as, &as->c->btree_interior_update_pool);
}

static void btree_interior_update_nodes_reachable(struct closure *cl)
{
	struct btree_interior_update *as =
		container_of(cl, struct btree_interior_update, cl);
	struct cache_set *c = as->c;
	unsigned i;

	bch_journal_pin_drop(&c->journal, &as->journal);

	mutex_lock(&c->btree_interior_update_lock);

	for (i = 0; i < as->nr_pending; i++)
		bch_btree_node_free_ondisk(c, &as->pending[i]);
	as->nr_pending = 0;

	mutex_unlock(&c->btree_interior_update_lock);

	mutex_lock(&c->btree_interior_update_lock);
	list_del(&as->list);
	mutex_unlock(&c->btree_interior_update_lock);

	closure_wake_up(&as->wait);

	closure_return_with_destructor(cl, btree_interior_update_free);
}

static void btree_interior_update_nodes_written(struct closure *cl)
{
	struct btree_interior_update *as =
		container_of(cl, struct btree_interior_update, cl);
	struct cache_set *c = as->c;
	struct btree *b;

	if (bch_journal_error(&c->journal)) {
		/* XXX what? */
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

		if (list_empty(&b->write_blocked))
			__bch_btree_node_write(b, NULL, -1);
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

		bch_btree_set_root_ondisk(c, b);

		/*
		 * We don't have to wait anything anything here (before
		 * btree_interior_update_nodes_reachable frees the old nodes
		 * ondisk) - we've ensured that the very next journal write will
		 * have the pointer to the new root, and before the allocator
		 * can reuse the old nodes it'll have to do a journal commit:
		 */
		six_unlock_read(&b->lock);
	}
	mutex_unlock(&c->btree_interior_update_lock);

	continue_at(cl, btree_interior_update_nodes_reachable, system_wq);
}

/*
 * We're updating @b with pointers to nodes that haven't finished writing yet:
 * block @b from being written until @as completes
 */
static void btree_interior_update_updated_btree(struct cache_set *c,
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

	bch_journal_flush_seq_async(&c->journal, as->journal_seq, &as->cl);

	continue_at(&as->cl, btree_interior_update_nodes_written,
		    system_freezable_wq);
}

static void btree_interior_update_updated_root(struct cache_set *c,
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
	if (r->as) {
		BUG_ON(r->as->mode != BTREE_INTERIOR_UPDATING_ROOT);

		r->as->b = NULL;
		r->as->mode = BTREE_INTERIOR_UPDATING_AS;
		r->as->parent_as = as;
		closure_get(&as->cl);
	}

	as->mode = BTREE_INTERIOR_UPDATING_ROOT;
	as->b = r->b;
	r->as = as;

	mutex_unlock(&c->btree_interior_update_lock);

	bch_journal_flush_seq_async(&c->journal, as->journal_seq, &as->cl);

	continue_at(&as->cl, btree_interior_update_nodes_written,
		    system_freezable_wq);
}

/*
 * @b is being split/rewritten: it may have pointers to not-yet-written btree
 * nodes and thus outstanding btree_interior_updates - redirect @b's
 * btree_interior_updates to point to this btree_interior_update:
 */
void bch_btree_interior_update_will_free_node(struct cache_set *c,
					      struct btree_interior_update *as,
					      struct btree *b)
{
	struct btree_interior_update *p, *n;
	struct pending_btree_node_free *d;
	struct bset_tree *t;

	/*
	 * Does this node have data that hasn't been written in the journal?
	 *
	 * If so, we have to wait for the corresponding journal entry to be
	 * written before making the new nodes reachable - we can't just carry
	 * over the bset->journal_seq tracking, since we'll be mixing those keys
	 * in with keys that aren't in the journal anymore:
	 */
	for (t = b->keys.set; t <= b->keys.set + b->keys.nsets; t++)
		as->journal_seq = max(as->journal_seq, t->data->journal_seq);

	/*
	 * Does this node have unwritten data that has a pin on the journal?
	 *
	 * If so, transfer that pin to the btree_interior_update operation -
	 * note that if we're freeing multiple nodes, we only need to keep the
	 * oldest pin of any of the nodes we're freeing. We'll release the pin
	 * when the new nodes are persistent and reachable on disk:
	 */
	bch_journal_pin_add_if_older(&c->journal,
				     &b->writes[0].journal,
				     &as->journal, NULL);
	bch_journal_pin_add_if_older(&c->journal,
				     &b->writes[1].journal,
				     &as->journal, NULL);

	mutex_lock(&c->btree_interior_update_lock);

	/*
	 * Does this node have any btree_interior_update operations preventing
	 * it from being written?
	 *
	 * If so, redirect them to point to this btree_interior_update: we can
	 * write out our new nodes, but we won't make them visible until those
	 * operations complete
	 */
	list_for_each_entry_safe(p, n, &b->write_blocked, write_blocked_list) {
		BUG_ON(p->mode != BTREE_INTERIOR_UPDATING_NODE);

		p->mode = BTREE_INTERIOR_UPDATING_AS;
		list_del(&p->write_blocked_list);
		p->b = NULL;
		p->parent_as = as;
		closure_get(&as->cl);
	}

	/* Add this node to the list of nodes being freed: */
	BUG_ON(as->nr_pending >= ARRAY_SIZE(as->pending));

	d = &as->pending[as->nr_pending++];
	d->index_update_done	= false;
	d->seq			= b->data->keys.seq;
	d->btree_id		= b->btree_id;
	d->level		= b->level;
	bkey_copy(&d->key, &b->key);

	mutex_unlock(&c->btree_interior_update_lock);
}

static void btree_node_interior_verify(struct btree *b)
{
	const struct bkey_format *f = &b->keys.format;
	struct btree_node_iter iter;
	struct bkey_packed *k;

	BUG_ON(!b->level);

	bch_btree_node_iter_init(&iter, &b->keys, b->key.k.p, false);
#if 1
	BUG_ON(!(k = bch_btree_node_iter_peek(&iter, &b->keys)) ||
	       bkey_cmp_left_packed(f, k, b->key.k.p));

	BUG_ON((bch_btree_node_iter_advance(&iter, &b->keys),
		!bch_btree_node_iter_end(&iter)));
#else
	const char *msg;

	msg = "not found";
	k = bch_btree_node_iter_peek(&iter, &b->keys);
	if (!k)
		goto err;

	msg = "isn't what it should be";
	if (bkey_cmp_left_packed(f, k, b->key.k.p))
		goto err;

	bch_btree_node_iter_advance(&iter, &b->keys);

	msg = "isn't last key";
	if (!bch_btree_node_iter_end(&iter))
		goto err;
	return;
err:
	bch_dump_bucket(&b->keys);
	printk(KERN_ERR "last key %llu:%llu %s\n", b->key.k.p.inode,
	       b->key.k.p.offset, msg);
	BUG();
#endif
}

static enum btree_insert_ret
bch_btree_insert_keys_interior(struct btree *b,
			       struct btree_iter *iter,
			       struct keylist *insert_keys,
			       struct btree_interior_update *as,
			       struct btree_reserve *res)
{
	struct btree_node_iter node_iter;
	const struct bkey_format *f = &b->keys.format;
	struct bkey_i *insert = bch_keylist_front(insert_keys);
	struct bkey_packed *k;

	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(!b->level);
	BUG_ON(!as || as->b);
	verify_keys_sorted(insert_keys);

	btree_node_lock_for_insert(b, iter);

	if (bch_keylist_u64s(insert_keys) >
	    bch_btree_keys_u64s_remaining(iter->c, b)) {
		btree_node_unlock_write(b, iter);
		return BTREE_INSERT_BTREE_NODE_FULL;
	}

	/* Don't screw up @iter's position: */
	node_iter = iter->node_iters[b->level];

	/*
	 * btree_split(), btree_gc_coalesce() will insert keys before
	 * the iterator's current position - they know the keys go in
	 * the node the iterator points to:
	 */
	while ((k = bch_btree_node_iter_prev_all(&node_iter, &b->keys)) &&
	       (bkey_cmp_packed(f, k, &insert->k) >= 0))
		;

	while (!bch_keylist_empty(insert_keys)) {
		insert = bch_keylist_front(insert_keys);

		bch_insert_fixup_btree_ptr(iter, b, insert,
					   &node_iter, &res->disk_res);
		bch_keylist_pop_front(insert_keys);
	}

	btree_interior_update_updated_btree(iter->c, as, b);

	if (bch_maybe_compact_deleted_keys(&b->keys))
		bch_btree_iter_reinit_node(iter, b);

	btree_node_unlock_write(b, iter);

	btree_node_interior_verify(b);
	return BTREE_INSERT_OK;
}

/*
 * Move keys from n1 (original replacement node, now lower node) to n2 (higher
 * node)
 */
static struct btree *__btree_split_node(struct btree_iter *iter, struct btree *n1,
					struct btree_reserve *reserve)
{
	size_t nr_packed = 0, nr_unpacked = 0;
	struct btree *n2;
	struct bset *set1, *set2;
	struct bkey_packed *k;

	n2 = bch_btree_node_alloc(iter->c, n1->level, iter->btree_id, reserve);
	n2->data->max_key	= n1->data->max_key;
	n2->keys.format		= n1->keys.format;
	n2->key.k.p = n1->key.k.p;

	set1 = btree_bset_first(n1);
	set2 = btree_bset_first(n2);

	/*
	 * Has to be a linear search because we don't have an auxiliary
	 * search tree yet
	 */
	k = set1->start;
	while (1) {
		if (bkey_packed(k))
			nr_packed++;
		else
			nr_unpacked++;
		if (k->_data - set1->_data >= (le16_to_cpu(set1->u64s) * 3) / 5)
			break;
		k = bkey_next(k);
	}

	n1->key.k.p = bkey_unpack_key(&n1->keys.format, k).p;
	k = bkey_next(k);

	n1->data->max_key = n1->key.k.p;
	n2->data->min_key =
		btree_type_successor(n1->btree_id, n1->key.k.p);

	set2->u64s = cpu_to_le16((u64 *) bset_bkey_last(set1) - (u64 *) k);
	set1->u64s = cpu_to_le16(le16_to_cpu(set1->u64s) - le16_to_cpu(set2->u64s));

	n2->keys.nr.live_u64s		= le16_to_cpu(set2->u64s);
	n2->keys.nr.bset_u64s[0]	= le16_to_cpu(set2->u64s);
	n2->keys.nr.packed_keys
		= n1->keys.nr.packed_keys - nr_packed;
	n2->keys.nr.unpacked_keys
		= n1->keys.nr.unpacked_keys - nr_unpacked;

	n1->keys.nr.live_u64s		= le16_to_cpu(set1->u64s);
	n1->keys.nr.bset_u64s[0]	= le16_to_cpu(set1->u64s);
	n1->keys.nr.packed_keys		= nr_packed;
	n1->keys.nr.unpacked_keys	= nr_unpacked;

	BUG_ON(!set1->u64s);
	BUG_ON(!set2->u64s);

	memcpy(set2->start,
	       bset_bkey_last(set1),
	       le16_to_cpu(set2->u64s) * sizeof(u64));

	n1->keys.set->size = 0;
	n1->keys.set->extra = BSET_AUX_TREE_NONE_VAL;
	n2->keys.set->size = 0;
	n2->keys.set->extra = BSET_AUX_TREE_NONE_VAL;

	six_unlock_write(&n2->lock);

	bch_verify_btree_nr_keys(&n1->keys);
	bch_verify_btree_nr_keys(&n2->keys);

	if (n1->level) {
		btree_node_interior_verify(n1);
		btree_node_interior_verify(n2);
	}

	return n2;
}

static void btree_split_insert_keys(struct btree_iter *iter, struct btree *b,
				    struct keylist *keys,
				    struct btree_reserve *res,
				    bool is_last)
{
	struct btree_node_iter node_iter;
	struct bkey_i *k = bch_keylist_front(keys);

	BUG_ON(!b->level);
	BUG_ON(b->keys.ops->is_extents);

	bch_btree_node_iter_init(&node_iter, &b->keys, k->k.p, false);

	six_lock_write(&b->lock);

	while (!bch_keylist_empty(keys)) {
		k = bch_keylist_front(keys);

		BUG_ON(bch_keylist_u64s(keys) >
		       bch_btree_keys_u64s_remaining(iter->c, b));
		BUG_ON(bkey_cmp(k->k.p, b->data->min_key) < 0);

		if (bkey_cmp(k->k.p, b->key.k.p) > 0) {
			BUG_ON(is_last);
			break;
		}

		bch_insert_fixup_btree_ptr(iter, b, k, &node_iter, &res->disk_res);
		bch_keylist_pop_front(keys);
	}

	six_unlock_write(&b->lock);

	btree_node_interior_verify(b);
}

static void btree_split(struct btree *b, struct btree_iter *iter,
			struct keylist *insert_keys,
			struct btree_reserve *reserve,
			struct btree_interior_update *as)
{
	struct cache_set *c = iter->c;
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	uint64_t start_time = local_clock();
	unsigned u64s_to_insert = b->level
		? bch_keylist_u64s(insert_keys) : 0;

	BUG_ON(!parent && (b != btree_node_root(b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));

	bch_btree_interior_update_will_free_node(c, as, b);

	n1 = btree_node_alloc_replacement(c, b, reserve);

	/*
	 * For updates to interior nodes, we've got to do the insert
	 * before we split because the stuff we're inserting has to be
	 * inserted atomically. Post split, the keys might have to go in
	 * different nodes and the split would no longer be atomic.
	 *
	 * Worse, if the insert is from btree node coalescing, if we do the
	 * insert after we do the split (and pick the pivot) - the pivot we pick
	 * might be between nodes that were coalesced, and thus in the middle of
	 * a child node post coalescing:
	 */
	if (b->level) {
		struct bkey_packed *k;
		struct bset *i;

		six_unlock_write(&n1->lock);
		btree_split_insert_keys(iter, n1, insert_keys, reserve, true);
		six_lock_write(&n1->lock);

		/*
		 * There might be duplicate (deleted) keys after the
		 * bch_btree_insert_keys() call - we need to remove them before
		 * we split, as it would be rather bad if we picked a duplicate
		 * for the pivot.
		 *
		 * Additionally, inserting might overwrite a bunch of existing
		 * keys (i.e. a big discard when there were a bunch of small
		 * extents previously) - we might not want to split after the
		 * insert. Splitting a node that's too small to be split would
		 * be bad (if the node had only one key, we wouldn't be able to
		 * assign the new node a key different from the original node)
		 */
		i = btree_bset_first(n1);
		k = i->start;
		while (k != bset_bkey_last(i))
			if (bkey_deleted(k)) {
				i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
				memmove(k, bkey_next(k),
					(void *) bset_bkey_last(i) -
					(void *) k);
			} else
				k = bkey_next(k);

		btree_node_interior_verify(n1);
	}

	if (__set_blocks(n1->data,
			 le16_to_cpu(n1->data->keys.u64s) + u64s_to_insert,
			 block_bytes(n1->c)) > btree_blocks(c) * 3 / 4) {
		trace_bcache_btree_node_split(b, le16_to_cpu(btree_bset_first(n1)->u64s));

		n2 = __btree_split_node(iter, n1, reserve);
		six_unlock_write(&n1->lock);

		bch_btree_node_write(n2, &as->cl, NULL);

		/*
		 * Note that on recursive parent_keys == insert_keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		bch_keylist_add(&as->parent_keys, &n1->key);
		bch_keylist_add(&as->parent_keys, &n2->key);

		if (!parent) {
			/* Depth increases, make a new root */
			n3 = __btree_root_alloc(c, b->level + 1,
						iter->btree_id,
						reserve);

			btree_split_insert_keys(iter, n3, &as->parent_keys,
						reserve, true);
			bch_btree_node_write(n3, &as->cl, NULL);
		}
	} else {
		trace_bcache_btree_node_compact(b, le16_to_cpu(btree_bset_first(n1)->u64s));
		six_unlock_write(&n1->lock);

		bch_keylist_add(&as->parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, &as->cl, NULL);

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		bch_btree_insert_node(parent, iter, &as->parent_keys,
				      reserve, as);
	} else if (n3) {
		bch_btree_set_root(iter, n3, as, reserve);
	} else {
		/* Root filled up but didn't need to be split */
		bch_btree_set_root(iter, n1, as, reserve);
	}

	btree_open_bucket_put(c, n1);
	if (n2)
		btree_open_bucket_put(c, n2);
	if (n3)
		btree_open_bucket_put(c, n3);

	/*
	 * Note - at this point other linked iterators could still have @b read
	 * locked; we're depending on the bch_btree_iter_node_replace() calls
	 * below removing all references to @b so we don't return with other
	 * iterators pointing to a node they have locked that's been freed.
	 *
	 * We have to free the node first because the bch_iter_node_replace()
	 * calls will drop _our_ iterator's reference - and intent lock - to @b.
	 */
	bch_btree_node_free_inmem(iter, b);

	/* Successful split, update the iterator to point to the new nodes: */

	if (n3)
		bch_btree_iter_node_replace(iter, n3);
	if (n2)
		bch_btree_iter_node_replace(iter, n2);
	bch_btree_iter_node_replace(iter, n1);

	bch_time_stats_update(&c->btree_split_time, start_time);
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
void bch_btree_insert_node(struct btree *b,
			   struct btree_iter *iter,
			   struct keylist *insert_keys,
			   struct btree_reserve *reserve,
			   struct btree_interior_update *as)
{
	BUG_ON(!b->level);
	BUG_ON(!reserve || !as);

	switch (bch_btree_insert_keys_interior(b, iter, insert_keys,
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

static int bch_btree_split_leaf(struct btree_iter *iter, unsigned flags,
				struct closure *cl)
{
	struct btree_iter *linked;
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];
	struct btree_reserve *reserve;
	struct btree_interior_update *as;
	int ret = 0;

	/* Hack, because gc and splitting nodes doesn't mix yet: */
	if (!down_read_trylock(&c->gc_lock)) {
		bch_btree_iter_unlock(iter);
		down_read(&c->gc_lock);
	}

	/*
	 * XXX: figure out how far we might need to split,
	 * instead of locking/reserving all the way to the root:
	 */
	iter->locks_want = U8_MAX;

	if (!bch_btree_iter_upgrade(iter)) {
		ret = -EINTR;
		goto out_get_locks;
	}

	reserve = bch_btree_reserve_get(c, b, 0,
			!(flags & BTREE_INSERT_NOFAIL), cl);
	if (IS_ERR(reserve)) {
		ret = PTR_ERR(reserve);
		goto out_get_locks;
	}

	as = bch_btree_interior_update_alloc(c);

	btree_split(b, iter, NULL, reserve, as);
	bch_btree_reserve_put(c, reserve);

	iter->locks_want = 1;

	for_each_linked_btree_iter(iter, linked)
		if (linked->btree_id == iter->btree_id &&
		    btree_iter_cmp(linked, iter) <= 0)
			linked->locks_want = 1;
out:
	up_read(&c->gc_lock);
	return ret;
out_get_locks:
	/* Lock ordering... */
	for_each_linked_btree_iter(iter, linked)
		if (linked->btree_id == iter->btree_id &&
		    btree_iter_cmp(linked, iter) <= 0) {
			unsigned i;

			for (i = 0; i < BTREE_MAX_DEPTH; i++) {
				btree_node_unlock(linked, i);
				linked->lock_seq[i]--;
			}
			linked->locks_want = U8_MAX;
		}
	goto out;
}

/**
 * btree_insert_key - insert a key one key into a leaf node
 */
static enum btree_insert_ret
btree_insert_key(struct btree_insert *trans,
		 struct btree_insert_entry *insert,
		 struct journal_res *res)
{
	struct btree_iter *iter = insert->iter;
	struct btree *b = iter->nodes[0];
	enum btree_insert_ret ret;
	int old_u64s = le16_to_cpu(btree_bset_last(b)->u64s);
	int old_live_u64s = b->keys.nr.live_u64s;
	int live_u64s_added, u64s_added;

	ret = !b->keys.ops->is_extents
		? bch_insert_fixup_key(trans, insert, res)
		: bch_insert_fixup_extent(trans, insert, res);

	live_u64s_added = (int) b->keys.nr.live_u64s - old_live_u64s;
	u64s_added = (int) le16_to_cpu(btree_bset_last(b)->u64s) - old_u64s;

	if (u64s_added > live_u64s_added &&
	    bch_maybe_compact_deleted_keys(&b->keys))
		bch_btree_iter_reinit_node(iter, b);

	trace_bcache_btree_insert_key(b, insert->k);
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
			btree_node_unlock_write(i->iter->nodes[0], i->iter);
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
 * -EROFS: cache set read only
 * -EIO: journal or btree node IO error
 */
int __bch_btree_insert_at(struct btree_insert *trans, u64 *journal_seq)
{
	struct cache_set *c = trans->c;
	struct journal_res res = { 0, 0 };
	struct btree_insert_entry *i;
	struct btree_iter *split = NULL;
	struct closure cl;
	bool cycle_gc_lock = false;
	unsigned u64s;
	int ret;

	closure_init_stack(&cl);

	trans_for_each_entry(trans, i) {
		EBUG_ON(i->iter->level);
		EBUG_ON(bkey_cmp(bkey_start_pos(&i->k->k), i->iter->pos));
	}

	sort(trans->entries, trans->nr, sizeof(trans->entries[0]),
	     btree_trans_entry_cmp, NULL);

	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return -EROFS;

	trans_for_each_entry(trans, i) {
		i->iter->locks_want = max_t(int, i->iter->locks_want, 1);
		if (unlikely(!bch_btree_iter_upgrade(i->iter))) {
			ret = -EINTR;
			goto err;
		}
	}
retry:
	trans->did_work = false;
	u64s = 0;
	trans_for_each_entry(trans, i)
		if (!i->done)
			u64s += jset_u64s(i->k->k.u64s);

	ret = !(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)
		? bch_journal_res_get(&c->journal, &res, u64s, u64s)
		: 0;
	if (ret)
		goto err;

	multi_lock_write(trans);

	u64s = 0;
	trans_for_each_entry(trans, i) {
		/* Multiple inserts might go to same leaf: */
		if (!same_leaf_as_prev(trans, i))
			u64s = 0;

		if (!i->done) {
			u64s += i->k->k.u64s;
			if (!bch_btree_node_insert_fits(c,
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

		switch (btree_insert_key(trans, i, &res)) {
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
	bch_journal_res_put(&c->journal, &res, journal_seq);

	if (split)
		goto split;
	if (ret)
		goto err;

	trans_for_each_entry(trans, i)
		if (!same_leaf_as_prev(trans, i))
			bch_btree_node_write_lazy(i->iter->nodes[0], i->iter);
out:
	percpu_ref_put(&c->writes);
	return ret;
split:
	/*
	 * have to drop journal res before splitting, because splitting means
	 * allocating new btree nodes, and holding a journal reservation
	 * potentially blocks the allocator:
	 */
	ret = bch_btree_split_leaf(split, trans->flags, &cl);
	if (ret)
		goto err;

	/*
	 * if the split didn't have to drop locks the insert will still be
	 * atomic (in the BTREE_INSERT_ATOMIC sense, what the caller peeked()
	 * and is overwriting won't have changed)
	 */
	goto retry;
err:
	if (ret == -EAGAIN) {
		struct btree_iter *linked;

		for_each_linked_btree_iter(split, linked)
			bch_btree_iter_unlock(linked);
		bch_btree_iter_unlock(split);

		closure_sync(&cl);
		ret = -EINTR;
	}

	if (cycle_gc_lock) {
		down_read(&c->gc_lock);
		up_read(&c->gc_lock);
	}

	/*
	 * Main rule is, BTREE_INSERT_ATOMIC means we can't call
	 * bch_btree_iter_traverse(), because if we have to we either dropped
	 * locks or we need a different btree node (different than the one the
	 * caller was looking at).
	 *
	 * BTREE_INSERT_ATOMIC doesn't mean anything w.r.t. journal
	 * reservations:
	 */
	if (ret == -EINTR && !(trans->flags & BTREE_INSERT_ATOMIC)) {
		trans_for_each_entry(trans, i) {
			ret = bch_btree_iter_traverse(i->iter);
			if (ret)
				goto out;
		}

		ret = 0;
	}

	if (!ret)
		goto retry;

	goto out;
}

int bch_btree_insert_list_at(struct btree_iter *iter,
			     struct keylist *keys,
			     struct disk_reservation *disk_res,
			     struct extent_insert_hook *hook,
			     u64 *journal_seq, unsigned flags)
{
	BUG_ON(flags & BTREE_INSERT_ATOMIC);
	BUG_ON(bch_keylist_empty(keys));
	verify_keys_sorted(keys);

	while (!bch_keylist_empty(keys)) {
		/* need to traverse between each insert */
		int ret = bch_btree_iter_traverse(iter);
		if (ret)
			return ret;

		ret = bch_btree_insert_at(iter->c, disk_res, hook,
				journal_seq, flags,
				BTREE_INSERT_ENTRY(iter, bch_keylist_front(keys)));
		if (ret)
			return ret;

		bch_keylist_pop_front(keys);
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
int bch_btree_insert_check_key(struct btree_iter *iter,
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

	ret = bch_btree_insert_at(iter->c, NULL, NULL, NULL,
				  BTREE_INSERT_ATOMIC,
				  BTREE_INSERT_ENTRY(iter, &tmp.key));

	bch_btree_iter_rewind(iter, saved_pos);

	return ret;
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct cache_set
 * @id:			btree to insert into
 * @insert_keys:	list of keys to insert
 * @hook:		insert callback
 */
int bch_btree_insert(struct cache_set *c, enum btree_id id,
		     struct bkey_i *k,
		     struct disk_reservation *disk_res,
		     struct extent_insert_hook *hook,
		     u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	int ret, ret2;

	bch_btree_iter_init_intent(&iter, c, id, bkey_start_pos(&k->k));

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch_btree_insert_at(c, disk_res, hook, journal_seq, flags,
				  BTREE_INSERT_ENTRY(&iter, k));
out:	ret2 = bch_btree_iter_unlock(&iter);

	return ret ?: ret2;
}

/**
 * bch_btree_update - like bch_btree_insert(), but asserts that we're
 * overwriting an existing key
 */
int bch_btree_update(struct cache_set *c, enum btree_id id,
		     struct bkey_i *k, u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c u;
	int ret, ret2;

	EBUG_ON(id == BTREE_ID_EXTENTS);

	bch_btree_iter_init_intent(&iter, c, id, k->k.p);

	u = bch_btree_iter_peek_with_holes(&iter);

	if (!u.k || bkey_deleted(u.k))
		return -ENOENT;

	ret = bch_btree_insert_at(c, NULL, NULL, journal_seq, 0,
				  BTREE_INSERT_ENTRY(&iter, k));
	ret2 = bch_btree_iter_unlock(&iter);

	return ret ?: ret2;
}

/*
 * bch_btree_delete_range - delete everything within a given range
 *
 * Range is a half open interval - [start, end)
 */
int bch_btree_delete_range(struct cache_set *c, enum btree_id id,
			   struct bpos start,
			   struct bpos end,
			   u64 version,
			   struct disk_reservation *disk_res,
			   struct extent_insert_hook *hook,
			   u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch_btree_iter_init_intent(&iter, c, id, start);

	while ((k = bch_btree_iter_peek(&iter)).k) {
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
		 * (bch_btree_iter_peek() does guarantee that iter.pos >=
		 * bkey_start_pos(k.k)).
		 */
		delete.k.p = iter.pos;
		delete.k.version = version;

		if (iter.nodes[0]->keys.ops->is_extents) {
			/*
			 * The extents btree is special - KEY_TYPE_DISCARD is
			 * used for deletions, not KEY_TYPE_DELETED. This is an
			 * internal implementation detail that probably
			 * shouldn't be exposed (internally, KEY_TYPE_DELETED is
			 * used as a proxy for k->size == 0):
			 */
			delete.k.type = KEY_TYPE_DISCARD;

			/* create the biggest key we can */
			bch_key_resize(&delete.k, max_sectors);
			bch_cut_back(end, &delete.k);
		}

		ret = bch_btree_insert_at(c, disk_res, hook, journal_seq,
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(&iter, &delete));
		if (ret)
			break;

		bch_btree_iter_cond_resched(&iter);
	}

	return bch_btree_iter_unlock(&iter) ?: ret;
}

/**
 * bch_btree_node_rewrite - Rewrite/move a btree node
 *
 * Returns 0 on success, -EINTR or -EAGAIN on failure (i.e.
 * btree_check_reserve() has to wait)
 */
int bch_btree_node_rewrite(struct btree_iter *iter, struct btree *b,
			   struct closure *cl)
{
	struct cache_set *c = iter->c;
	struct btree *n, *parent = iter->nodes[b->level + 1];
	struct btree_reserve *reserve;
	struct btree_interior_update *as;

	iter->locks_want = U8_MAX;
	if (!bch_btree_iter_upgrade(iter))
		return -EINTR;

	reserve = bch_btree_reserve_get(c, b, 1, false, cl);
	if (IS_ERR(reserve)) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return PTR_ERR(reserve);
	}

	as = bch_btree_interior_update_alloc(c);

	bch_btree_interior_update_will_free_node(c, as, b);

	n = btree_node_alloc_replacement(c, b, reserve);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write(n, &as->cl, NULL);

	if (parent) {
		bch_btree_insert_node(parent, iter,
				      &keylist_single(&n->key),
				      reserve, as);
	} else {
		bch_btree_set_root(iter, n, as, reserve);
	}

	btree_open_bucket_put(c, n);

	bch_btree_node_free_inmem(iter, b);

	BUG_ON(!bch_btree_iter_node_replace(iter, n));

	bch_btree_reserve_put(c, reserve);
	return 0;
}
