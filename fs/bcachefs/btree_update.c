
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
#include <trace/events/bcachefs.h>

static void async_split_updated_root(struct async_split *,
				     struct btree *);

/* Calculate ideal packed bkey format for new btree nodes: */

void __bch_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey unpacked;
	struct bkey_s_c k;

	for_each_btree_node_key_unpack(&b->keys, k, &iter, &unpacked)
		bch_bkey_format_add_key(s, k.k);

	if (b->keys.ops->is_extents) {
		/*
		 * Extents need special consideration because of
		 * bch_insert_fixup_extent() - they have to be modified in
		 * place, and successfully repack, when insert an overlapping
		 * extent:
		 */
		bch_bkey_format_add_pos(s, b->data->min_key);
		bch_bkey_format_add_pos(s, b->data->max_key);

		/*
		 * If we span multiple inodes, need to be able to store an
		 * offset of 0:
		 */
		if (s->field_min[BKEY_FIELD_INODE] !=
		    s->field_max[BKEY_FIELD_INODE])
			s->field_min[BKEY_FIELD_OFFSET] = 0;

		/* Make sure we can store a size of 0: */
		s->field_min[BKEY_FIELD_SIZE] = 0;
	}
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
 * @b is going to be freed, allocate a pending_btree_node_free in @as:
 */
void bch_btree_node_free_start(struct cache_set *c,
			       struct async_split *as,
			       struct btree *b)
{
	struct pending_btree_node_free *d;

	BUG_ON(as->nr_pending >= ARRAY_SIZE(as->pending));
	d = &as->pending[as->nr_pending++];

	d->index_update_done = false;
	bkey_copy(&d->key, &b->key);

	mutex_lock(&c->btree_node_pending_free_lock);
	list_add(&d->list, &c->btree_node_pending_free);
	mutex_unlock(&c->btree_node_pending_free_lock);
}

/*
 * We're doing the index update that makes @b unreachable, update stuff to
 * reflect that:
 *
 * Must be called _before_ async_split_updated_root() or
 * async_split_updated_btree:
 */
static void bch_btree_node_free_index(struct cache_set *c, struct btree *b,
				      enum btree_id id, struct bkey_s_c k,
				      struct bucket_stats_cache_set *stats)
{
	struct pending_btree_node_free *d;

	mutex_lock(&c->btree_node_pending_free_lock);

	list_for_each_entry(d, &c->btree_node_pending_free, list)
		if (!bkey_cmp(k.k->p, d->key.k.p) &&
		    bkey_val_bytes(k.k) == bkey_val_bytes(&d->key.k) &&
		    !memcmp(k.v, &d->key.v, bkey_val_bytes(k.k)))
			goto found;

	BUG();
found:
	d->index_update_done = true;

	/*
	 * We're dropping @k from the btree, but it's still live until the index
	 * update is persistent so we need to keep a reference around for mark
	 * and sweep to find - that's primarily what the btree_node_pending_free
	 * list is for.
	 *
	 * So here (when we set index_update_done = true), we're moving an
	 * existing reference to a different part of the larger "gc keyspace" -
	 * and the new position comes after the old position, since GC marks the
	 * pending free list after it walks the btree.
	 *
	 * If we move the reference while mark and sweep is _between_ the old
	 * and the new position, mark and sweep will see the reference twice and
	 * it'll get double accounted - so check for that here and subtract to
	 * cancel out one of mark and sweep's markings if necessary:
	 */

	/*
	 * bch_mark_key() compares the current gc pos to the pos we're
	 * moving this reference from, hence one comparison here:
	 */
	if (gc_pos_cmp(c->gc_pos, gc_phase(GC_PHASE_PENDING_DELETE)) < 0)
		bch_mark_key(c, bkey_i_to_s_c(&d->key),
			     -c->sb.btree_node_size, true, true, b
			     ? gc_pos_btree_node(b)
			     : gc_pos_btree_root(id),
			     stats);

	mutex_unlock(&c->btree_node_pending_free_lock);
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

	if (!list_empty_careful(&b->journal_seq_blacklisted)) {
		mutex_lock(&c->journal.blacklist_lock);
		list_del_init(&b->journal_seq_blacklisted);
		mutex_unlock(&c->journal.blacklist_lock);
	}

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

	mutex_lock(&c->btree_node_pending_free_lock);
	list_del(&pending->list);

	bch_mark_key(c, bkey_i_to_s_c(&pending->key),
		     -c->sb.btree_node_size, true, true,
		     gc_phase(GC_PHASE_PENDING_DELETE),
		     &stats);

	/* Already accounted for in cache_set_stats - don't apply @stats: */

	mutex_unlock(&c->btree_node_pending_free_lock);
}

void btree_open_bucket_put(struct cache_set *c, struct btree *b)
{
	bch_open_bucket_put(c, b->ob);
	b->ob = NULL;
}

static struct btree *__bch_btree_node_alloc(struct cache_set *c,
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
			       c->opts.metadata_replicas, cl);
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

	b->accessed = 1;
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
				 struct bucket_stats_cache_set *stats)
{
	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;

	bch_mark_key(c, bkey_i_to_s_c(&b->key),
		     c->sb.btree_node_size, true, true,
		     gc_pos_btree_root(b->btree_id),
		     stats);
	spin_unlock(&c->btree_root_lock);

	bch_recalc_btree_reserve(c);
}

static void bch_btree_set_root_ondisk(struct cache_set *c, struct btree *b)
{
	struct btree_root *r = &c->btree_roots[b->btree_id];

	spin_lock(&c->btree_root_lock);

	BUG_ON(b != r->b);
	bkey_copy(&r->key, &b->key);
	r->level = b->level;
	r->alive = true;

	spin_unlock(&c->btree_root_lock);
}

/*
 * Only for cache set bringup, when first reading the btree roots or allocating
 * btree roots when initializing a new cache set:
 */
void bch_btree_set_root_initial(struct cache_set *c, struct btree *b,
				struct btree_reserve *btree_reserve)
{
	struct bucket_stats_cache_set stats = { 0 };

	BUG_ON(btree_node_root(b));

	bch_btree_set_root_inmem(c, b, &stats);
	bch_btree_set_root_ondisk(c, b);

	if (btree_reserve)
		bch_cache_set_stats_apply(c, &stats, &btree_reserve->disk_res);
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
			       struct async_split *as,
			       struct btree_reserve *btree_reserve)
{
	struct bucket_stats_cache_set stats = { 0 };
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

	bch_btree_set_root_inmem(c, b, &stats);

	bch_btree_node_free_index(c, NULL, old->btree_id,
				  bkey_i_to_s_c(&old->key),
				  &stats);

	async_split_updated_root(as, b);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	btree_node_unlock_write(old, iter);

	stats.sectors_meta -= c->sb.btree_node_size;
	bch_cache_set_stats_apply(c, &stats, &btree_reserve->disk_res);
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
	int ret;

	if (__bch_disk_reservation_get(c, &disk_res, sectors,
				       check_enospc, true))
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
		b = __bch_btree_node_alloc(c, cl);
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
					    struct btree_iter *iter,
					    unsigned extra_nodes,
					    bool check_enospc)
{
	unsigned depth = btree_node_root(b)->level - b->level;
	unsigned nr_nodes = btree_reserve_required_nodes(depth) + extra_nodes;

	return __bch_btree_reserve_get(c, check_enospc, nr_nodes,
				       iter ? &iter->cl : NULL);

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

static bool bch_insert_fixup_btree_ptr(struct btree_iter *iter,
				       struct btree *b,
				       struct bkey_i *insert,
				       struct btree_node_iter *node_iter,
				       struct disk_reservation *disk_res)
{
	struct cache_set *c = iter->c;
	const struct bkey_format *f = &b->keys.format;
	struct bucket_stats_cache_set stats = { 0 };
	struct bkey_packed *k;
	int cmp;

	bch_btree_node_iter_verify(node_iter, &b->keys);
	EBUG_ON((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
		(bkey_deleted(k)
		 ? bkey_cmp_packed(f, k, &insert->k) > 0
		 : bkey_cmp_packed(f, k, &insert->k) >= 0));

	if (bkey_extent_is_data(&insert->k))
		bch_mark_key(c, bkey_i_to_s_c(insert),
			     c->sb.btree_node_size, true, true,
			     gc_pos_btree_node(b), &stats);

	while ((k = bch_btree_node_iter_peek_all(node_iter, &b->keys))) {
		struct bkey tmp;
		struct bkey_s_c u = bkey_disassemble(f, k, &tmp);

		cmp = bkey_cmp(u.k->p, insert->k.p);
		if (cmp > 0)
			break;

		if (!cmp && !bkey_deleted(k)) {
			bch_btree_node_free_index(c, b, iter->btree_id,
						  u, &stats);
			/*
			 * Look up pending delete, mark so that gc marks it on
			 * the pending delete list
			 */
			k->type = KEY_TYPE_DELETED;
			btree_keys_account_key_drop(&b->keys.nr, k);
			stats.sectors_meta -= c->sb.btree_node_size;
		}

		bch_btree_node_iter_next_all(node_iter, &b->keys);
	}

	bch_btree_bset_insert(iter, b, node_iter, insert);
	set_btree_node_dirty(b);

	bch_cache_set_stats_apply(c, &stats, disk_res);
	return true;
}

/* Inserting into a given leaf node (last stage of insert): */

/* Wrapper around bch_bset_insert() that fixes linked iterators: */
void bch_btree_bset_insert(struct btree_iter *iter,
			   struct btree *b,
			   struct btree_node_iter *node_iter,
			   struct bkey_i *insert)
{
	struct btree_iter *linked;
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

	if (where) {
		bch_btree_node_iter_fix(iter, &b->keys, node_iter, where);

		for_each_linked_btree_node(iter, b, linked)
			bch_btree_node_iter_fix(linked, &b->keys,
					&linked->node_iters[b->level],
					where);
	} else {
		bch_btree_node_iter_sort(node_iter, &b->keys);

		for_each_linked_btree_node(iter, b, linked)
			bch_btree_node_iter_sort(&linked->node_iters[b->level],
						 &b->keys);
	}

	bch_btree_node_iter_verify(node_iter, &b->keys);

	for_each_linked_btree_node(iter, b, linked)
		bch_btree_node_iter_verify(&linked->node_iters[b->level],
					   &b->keys);
}

static void btree_node_flush(struct journal_entry_pin *pin)
{
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[w->index]);

	six_lock_read(&b->lock);
	__bch_btree_node_write(b, NULL, w->index);
	six_unlock_read(&b->lock);
}

/**
 * bch_btree_insert_and_journal - insert a non-overlapping key into a btree node
 *
 * This is called from bch_insert_fixup_extent() and bch_insert_fixup_key()
 *
 * The insert is journalled.
 */
void bch_btree_insert_and_journal(struct btree_iter *iter,
				  struct bkey_i *insert,
				  struct journal_res *res)
{
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];

	EBUG_ON(iter->level || b->level);

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (c->btree_flush_delay)
			schedule_delayed_work(&b->work,
					      c->btree_flush_delay * HZ);
	}

	if (res->ref ||
	    !test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags)) {
		struct btree_write *w = btree_current_write(b);

		if (!w->have_pin) {
			journal_pin_add(&c->journal,
					c->journal.cur_pin_list,
					&w->journal,
					btree_node_flush);
			w->have_pin = true;
		}
	}

	if (res->ref) {
		bch_journal_add_keys(&c->journal, res, b->btree_id,
				     insert, b->level);
		btree_bset_last(b)->journal_seq = cpu_to_le64(c->journal.seq);
	}

	bch_btree_bset_insert(iter, b, node_iter, insert);
}

/**
 * btree_insert_key - insert a key into a btree node, handling overlapping extents.
 *
 * The insert is journalled.
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for for exchange (+ stats)
 * @res:		journal reservation
 * @flags:		BTREE_INSERT_NO_MARK_KEY
 *
 * Inserts the first key from @insert_keys
 *
 * Returns true if an insert was actually done and @b was modified - false on a
 * failed replace operation
 */
static void btree_insert_key(struct btree_iter *iter, struct btree *b,
			     struct btree_node_iter *node_iter,
			     struct keylist *insert_keys,
			     struct disk_reservation *disk_res,
			     struct btree_insert_hook *hook,
			     struct journal_res *res,
			     unsigned flags)
{
	struct bkey_i *insert = bch_keylist_front(insert_keys), *orig = insert;
	BKEY_PADDED(key) temp;
	s64 oldsize = bch_count_data(&b->keys);

	bch_btree_node_iter_verify(node_iter, &b->keys);
	BUG_ON(b->level);
	BUG_ON(iter->nodes[0] != b || &iter->node_iters[0] != node_iter);

	if (!b->keys.ops->is_extents) {
		bch_insert_fixup_key(iter, insert, hook, res);
		bch_keylist_dequeue(insert_keys);
	} else {
		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert->k.p, b->key.k.p) > 0)
			bch_cut_back(b->key.k.p, &insert->k);

		bch_insert_fixup_extent(iter, insert, disk_res,
					hook, res, flags);

		bch_cut_front(iter->pos, orig);
		if (orig->k.size == 0)
			bch_keylist_dequeue(insert_keys);
	}

	bch_count_data_verify(&b->keys, oldsize);

	trace_bcache_btree_insert_key(b, insert);
}

enum btree_insert_status {
	BTREE_INSERT_OK,
	BTREE_INSERT_NEED_SPLIT,
	BTREE_INSERT_ERROR,
};

static bool __have_enough_space(struct cache_set *c, struct btree *b,
				unsigned u64s)
{
	/*
	 * For updates to extents, bch_insert_fixup_extent()
	 * needs room for at least three keys to make forward
	 * progress.
	 */
	u64s = b->keys.ops->is_extents ? BKEY_EXTENT_U64s_MAX * 3 : u64s;

	return u64s <= bch_btree_keys_u64s_remaining(c, b);

}

static bool have_enough_space(struct cache_set *c, struct btree *b,
			      struct keylist *insert_keys)
{
	return __have_enough_space(c, b, b->level
			? bch_keylist_nkeys(insert_keys)
			: bch_keylist_front(insert_keys)->k.u64s);
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_i *k;

	for (k = l->bot;
	     k < l->top && bkey_next(k) < l->top;
	     k = bkey_next(k))
		BUG_ON(bkey_cmp(k->k.p, bkey_next(k)->k.p) >= 0);
#endif
}

static void btree_node_lock_for_insert(struct btree *b, struct btree_iter *iter)
{
relock:
	btree_node_lock_write(b, iter);

	BUG_ON(&write_block(iter->c, b)->keys < btree_bset_last(b));

	/*
	 * If the last bset has been written, initialize a new one - check after
	 * taking the write lock because it can be written with only a read
	 * lock:
	 */
	if (b->written != btree_blocks(iter->c) &&
	    &write_block(iter->c, b)->keys > btree_bset_last(b)) {
		btree_node_unlock_write(b, iter);
		bch_btree_init_next(iter->c, b, iter);
		goto relock;
	}
}

/* Asynchronous interior node update machinery */

struct async_split *__bch_async_split_alloc(struct btree *nodes[],
					    unsigned nr_nodes,
					    struct btree_iter *iter)
{
	struct cache_set *c = iter->c;
	struct async_split *as;
	struct journal_entry_pin_list *pin_list = NULL;
	unsigned i, pin_idx = UINT_MAX;

	as = mempool_alloc(&c->btree_async_split_pool, GFP_NOIO);
	closure_init(&as->cl, &c->cl);
	as->c		= c;
	as->mode	= ASYNC_SPLIT_NO_UPDATE;
	as->b		= NULL;
	as->parent_as	= NULL;
	as->nr_pending	= 0;
	init_llist_head(&as->wait.list);

	bch_keylist_init(&as->parent_keys, as->inline_keys,
			 ARRAY_SIZE(as->inline_keys));

	/* block btree node from being written and write_idx changing: */
	for (i = 0; i < nr_nodes; i++) {
		/*
		 * It's not legal to call btree_node_lock_write() when @iter
		 * does not point to nodes[i] - which happens in
		 * bch_coalesce_nodes(), unfortunately.
		 *
		 * So far this is the only place where we have this issue:
		 */
		if (iter->nodes[nodes[i]->level] == nodes[i])
			btree_node_lock_write(nodes[i], iter);
		else
			six_lock_write(&nodes[i]->lock);
	}

	for (i = 0; i < nr_nodes; i++) {
		struct btree_write *w = btree_current_write(nodes[i]);

		if (w->have_pin) {
			unsigned idx = fifo_entry_idx(&c->journal.pin,
						      w->journal.pin_list);

			if (idx < pin_idx) {
				pin_list = w->journal.pin_list;
				pin_idx = idx;
			}
		}
	}

	if (!pin_list) {
		/*
		 * We don't have a journal reservation to block cur_pin_list
		 * from changing, need to use a barrier to make sure it points
		 * to an initialised pin_list:
		 */
		pin_list = c->journal.cur_pin_list;
		smp_rmb();
	}

	journal_pin_add(&c->journal, pin_list, &as->journal, NULL);

	for (i = 0; i < nr_nodes; i++) {
		if (iter->nodes[nodes[i]->level] == nodes[i])
			btree_node_unlock_write(nodes[i], iter);
		else
			six_unlock_write(&nodes[i]->lock);
	}

	return as;
}

struct async_split *bch_async_split_alloc(struct btree *b, struct btree_iter *iter)
{
	return __bch_async_split_alloc(&b, 1, iter);
}

static void async_split_free(struct closure *cl)
{
	struct async_split *as = container_of(cl, struct async_split, cl);

	mempool_free(as, &as->c->btree_async_split_pool);
}

static void async_split_pointers_written(struct closure *cl)
{
	struct async_split *as = container_of(cl, struct async_split, cl);
	struct cache_set *c = as->c;
	unsigned i;

	closure_wake_up(&as->wait);

	journal_pin_drop(&c->journal, &as->journal);

	for (i = 0; i < as->nr_pending; i++)
		bch_btree_node_free_ondisk(c, &as->pending[i]);

	closure_return_with_destructor(cl, async_split_free);
}

static void async_split_nodes_written(struct closure *cl)
{
	struct async_split *as = container_of(cl, struct async_split, cl);
	struct cache_set *c = as->c;
	struct btree *b;

	/*
	 * We did an update to a parent node where the pointers we added pointed
	 * to child nodes that weren't written yet: now, the child nodes have
	 * been written so we can write out the update to the interior node.
	 */

retry:
	mutex_lock(&c->async_split_lock);
	switch (as->mode) {
	case ASYNC_SPLIT_NO_UPDATE:
		BUG();
	case ASYNC_SPLIT_UPDATING_BTREE:
		/* The usual case: */
		b = READ_ONCE(as->b);

		if (!six_trylock_read(&b->lock)) {
			mutex_unlock(&c->async_split_lock);
			six_lock_read(&b->lock);
			six_unlock_read(&b->lock);
			goto retry;
		}

		BUG_ON(!btree_node_dirty(b));
		closure_wait(&btree_current_write(b)->wait, cl);

		list_del(&as->list);

		if (list_empty(&b->write_blocked))
			__bch_btree_node_write(b, NULL, -1);
		six_unlock_read(&b->lock);
		break;

	case ASYNC_SPLIT_UPDATING_AS:
		/*
		 * The btree node we originally updated has been freed and is
		 * being rewritten - so we need to write anything here, we just
		 * need to signal to that async_split that it's ok to make the
		 * new replacement node visible:
		 */
		closure_put(&as->parent_as->cl);

		/*
		 * and then we have to wait on that async_split to finish:
		 */
		closure_wait(&as->parent_as->wait, cl);
		break;

	case ASYNC_SPLIT_UPDATING_ROOT:
		/* b is the new btree root: */
		b = READ_ONCE(as->b);

		if (!six_trylock_read(&b->lock)) {
			mutex_unlock(&c->async_split_lock);
			six_lock_read(&b->lock);
			six_unlock_read(&b->lock);
			goto retry;
		}

		BUG_ON(c->btree_roots[b->btree_id].as != as);
		c->btree_roots[b->btree_id].as = NULL;

		bch_btree_set_root_ondisk(c, b);

		/*
		 * We don't have to wait anything anything here (before
		 * async_split_pointers_written frees the old nodes ondisk) -
		 * we've ensured that the very next journal write will have the
		 * pointer to the new root, and before the allocator can reuse
		 * the old nodes it'll have to do a journal commit:
		 */
		six_unlock_read(&b->lock);
	}
	mutex_unlock(&c->async_split_lock);

	continue_at(cl, async_split_pointers_written, system_wq);
}

/*
 * We're updating @b with pointers to nodes that haven't finished writing yet:
 * block @b from being written until @as completes
 */
static void async_split_updated_btree(struct async_split *as,
				      struct btree *b)
{
	mutex_lock(&as->c->async_split_lock);

	BUG_ON(as->mode != ASYNC_SPLIT_NO_UPDATE);
	BUG_ON(!btree_node_dirty(b));

	as->mode = ASYNC_SPLIT_UPDATING_BTREE;
	as->b = b;
	list_add(&as->list, &b->write_blocked);

	mutex_unlock(&as->c->async_split_lock);

	continue_at(&as->cl, async_split_nodes_written, system_wq);
}

static void async_split_updated_root(struct async_split *as,
				     struct btree *b)
{
	struct btree_root *r = &as->c->btree_roots[b->btree_id];

	/*
	 * XXX: if there's an outstanding async_split updating the root, we
	 * have to do the dance with the old one
	 */

	mutex_lock(&as->c->async_split_lock);

	if (r->as) {
		BUG_ON(r->as->mode != ASYNC_SPLIT_UPDATING_ROOT);

		r->as->b = NULL;
		r->as->mode = ASYNC_SPLIT_UPDATING_AS;
		r->as->parent_as = as;
		closure_get(&as->cl);
	}

	BUG_ON(as->mode != ASYNC_SPLIT_NO_UPDATE);
	as->mode = ASYNC_SPLIT_UPDATING_ROOT;
	as->b = b;
	r->as = as;

	mutex_unlock(&as->c->async_split_lock);

	continue_at(&as->cl, async_split_nodes_written, system_wq);
}

/*
 * @b is being split/rewritten: it may have pointers to not-yet-written btree
 * nodes and thus outstanding async_splits - redirect @b's async_splits to point
 * to this async_split:
 */
static void async_split_will_free_node(struct async_split *as,
				       struct btree *b)
{
	mutex_lock(&as->c->async_split_lock);

	while (!list_empty(&b->write_blocked)) {
		struct async_split *p =
			list_first_entry(&b->write_blocked,
					 struct async_split, list);

		BUG_ON(p->mode != ASYNC_SPLIT_UPDATING_BTREE);

		p->mode = ASYNC_SPLIT_UPDATING_AS;
		list_del(&p->list);
		p->b = NULL;
		p->parent_as = as;
		closure_get(&as->cl);
	}

	mutex_unlock(&as->c->async_split_lock);
}

static void btree_node_interior_verify(struct btree *b)
{
	const struct bkey_format *f = &b->keys.format;
	struct btree_node_iter iter;
	struct bkey_packed *k;

	BUG_ON(!b->level);

	bch_btree_node_iter_init(&iter, &b->keys, b->key.k.p, false);
#if 1
	BUG_ON(!(k = bch_btree_node_iter_next(&iter, &b->keys)) ||
	       bkey_cmp_left_packed(f, k, b->key.k.p) ||
	       bch_btree_node_iter_peek(&iter, &b->keys));
#else
	const char *msg;

	msg = "not found";
	k = bch_btree_node_iter_next(&iter, &b->keys);
	if (!k)
		goto err;

	msg = "isn't what it should be";
	if (bkey_cmp_left_packed(f, k, b->key.k.p))
		goto err;

	msg = "isn't last key";
	if (bch_btree_node_iter_peek(&iter, &b->keys))
		goto err;
	return;
err:
	bch_dump_bucket(&b->keys);
	printk(KERN_ERR "last key %llu:%llu %s\n", b->key.k.p.inode,
	       b->key.k.p.offset, msg);
	BUG();
#endif
}

static void btree_insert_keys_checks(struct btree_iter *iter, struct btree *b)
{
	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(!b->written);
}

static enum btree_insert_status
bch_btree_insert_keys_interior(struct btree *b,
			       struct btree_iter *iter,
			       struct keylist *insert_keys,
			       struct async_split *as,
			       struct btree_reserve *res)
{
	struct btree_node_iter *node_iter = &iter->node_iters[b->level];
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	bool inserted = false;

	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(!b->level);
	BUG_ON(!as || as->b);

	btree_insert_keys_checks(iter, b);
	verify_keys_sorted(insert_keys);

	btree_node_lock_for_insert(b, iter);

	if (!have_enough_space(iter->c, b, insert_keys)) {
		btree_node_unlock_write(b, iter);
		return BTREE_INSERT_NEED_SPLIT;
	}

	while (!bch_keylist_empty(insert_keys)) {
		struct bkey_i *insert = bch_keylist_front(insert_keys);

		/*
		 * btree_split(), btree_gc_coalesce() will insert keys before
		 * the iterator's current position - they know the keys go in
		 * the node the iterator points to:
		 */
		while ((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
		       (bkey_cmp_packed(f, k, &insert->k) >= 0))
			;

		bch_insert_fixup_btree_ptr(iter, b, insert,
					   node_iter, &res->disk_res);
		inserted = true;
		bch_keylist_dequeue(insert_keys);
	}

	BUG_ON(!inserted);
	async_split_updated_btree(as, b);

	btree_node_unlock_write(b, iter);

	/*
	 * insert_fixup_btree_ptr() will advance the node iterator to _after_
	 * the last key it inserted, which is not what we want
	 */

	while ((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
	       (bkey_cmp_left_packed(f, k, iter->pos) >= 0))
		;

	btree_node_interior_verify(b);

	return BTREE_INSERT_OK;
}

/**
 * bch_btree_insert_keys - insert keys from @insert_keys into btree node @b,
 * until the node is full.
 *
 * If keys couldn't be inserted because @b was full, the caller must split @b
 * and bch_btree_insert_keys() will be called again from btree_split().
 *
 * Caller must either be holding an intent lock on this node only, or intent
 * locks on all nodes all the way up to the root. Caller must not be holding
 * read locks on any nodes.
 */
static enum btree_insert_status
bch_btree_insert_keys_leaf(struct btree *b,
			   struct btree_iter *iter,
			   struct keylist *insert_keys,
			   struct disk_reservation *disk_res,
			   struct btree_insert_hook *hook,
			   u64 *journal_seq,
			   unsigned flags)
{
	bool done = false, need_split = false;
	struct journal_res res = { 0, 0 };
	struct bkey_i *k = bch_keylist_front(insert_keys);

	BUG_ON(b->level);

	btree_insert_keys_checks(iter, b);
	verify_keys_sorted(insert_keys);

	while (!done && !bch_keylist_empty(insert_keys)) {
		/*
		 * We need room to insert at least two keys in the journal
		 * reservation -- the insert key itself, as well as a subset
		 * of it, in the bkey_cmpxchg() or handle_existing_key_newer()
		 * cases
		 */
		unsigned n_min = bch_keylist_front(insert_keys)->k.u64s;
		unsigned n_max = bch_keylist_nkeys(insert_keys);

		unsigned actual_min = jset_u64s(n_min) * 2;
		unsigned actual_max = max_t(unsigned, actual_min,
					    jset_u64s(n_max));

		if (test_bit(JOURNAL_REPLAY_DONE, &iter->c->journal.flags) &&
		    bch_journal_res_get(&iter->c->journal, &res,
					actual_min, actual_max))
			return BTREE_INSERT_ERROR;

		btree_node_lock_for_insert(b, iter);

		while (!bch_keylist_empty(insert_keys)) {
			k = bch_keylist_front(insert_keys);

			EBUG_ON(bkey_cmp(bkey_start_pos(&k->k), iter->pos));

			/* finished for this node */
			if (b->keys.ops->is_extents
			    ? bkey_cmp(bkey_start_pos(&k->k), b->key.k.p) >= 0
			    : bkey_cmp(k->k.p, b->key.k.p) > 0) {
				done = true;
				break;
			}

			if (!have_enough_space(iter->c, b, insert_keys)) {
				done = true;
				need_split = true;
				break;
			}

			if (journal_res_full(&res, &k->k))
				break;

			btree_insert_key(iter, b, &iter->node_iters[b->level],
					 insert_keys, disk_res,
					 hook, &res, flags);
		}

		btree_node_unlock_write(b, iter);

		if (res.ref)
			bch_journal_res_put(&iter->c->journal, &res,
					    journal_seq);
	}

	bch_btree_node_write_lazy(b, iter);

	return need_split ? BTREE_INSERT_NEED_SPLIT : BTREE_INSERT_OK;
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

	n2->keys.nr.live_u64s = le16_to_cpu(set2->u64s);
	n2->keys.nr.packed_keys
		= n1->keys.nr.packed_keys - nr_packed;
	n2->keys.nr.unpacked_keys
		= n1->keys.nr.unpacked_keys - nr_unpacked;

	n1->keys.nr.live_u64s = le16_to_cpu(set1->u64s);
	n1->keys.nr.packed_keys = nr_packed;
	n1->keys.nr.unpacked_keys = nr_unpacked;

	BUG_ON(!set1->u64s);
	BUG_ON(!set2->u64s);

	memcpy(set2->start,
	       bset_bkey_last(set1),
	       le16_to_cpu(set2->u64s) * sizeof(u64));

	n1->keys.set->size = 0;
	n1->keys.set->extra = BSET_TREE_NONE_VAL;
	n2->keys.set->size = 0;
	n2->keys.set->extra = BSET_TREE_NONE_VAL;

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

		BUG_ON(!have_enough_space(iter->c, b, keys));
		BUG_ON(bkey_cmp(k->k.p, b->data->min_key) < 0);

		if (bkey_cmp(k->k.p, b->key.k.p) > 0) {
			BUG_ON(is_last);
			break;
		}

		bch_insert_fixup_btree_ptr(iter, b, k, &node_iter, &res->disk_res);
		bch_keylist_dequeue(keys);
	}

	six_unlock_write(&b->lock);

	btree_node_interior_verify(b);
}

static void btree_split(struct btree *b, struct btree_iter *iter,
			struct keylist *insert_keys,
			struct btree_reserve *reserve,
			struct async_split *as)
{
	struct cache_set *c = iter->c;
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	uint64_t start_time = local_clock();
	unsigned u64s_to_insert = b->level
		? bch_keylist_nkeys(insert_keys) : 0;

	BUG_ON(!parent && (b != btree_node_root(b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));

	async_split_will_free_node(as, b);

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

	bch_btree_node_free_start(c, as, b);

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
 * @flags:		BTREE_INSERT_NO_MARK_KEY
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
void bch_btree_insert_node(struct btree *b,
			   struct btree_iter *iter,
			   struct keylist *insert_keys,
			   struct btree_reserve *reserve,
			   struct async_split *as)
{
	BUG_ON(!b->level);
	BUG_ON(!reserve || !as);

	switch (bch_btree_insert_keys_interior(b, iter, insert_keys,
					       as, reserve)) {
	case BTREE_INSERT_OK:
		break;
	case BTREE_INSERT_NEED_SPLIT:
		btree_split(b, iter, insert_keys, reserve, as);
		break;
	default:
		BUG();
	}
}

/* Normal update interface: */

static int bch_btree_split_leaf(struct btree_iter *iter, unsigned flags)
{
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];
	struct btree_reserve *reserve;
	struct async_split *as;
	int ret = -EINTR;

	/* Hack, because gc and splitting nodes doesn't mix yet: */
	if (!down_read_trylock(&c->gc_lock)) {
		bch_btree_iter_unlock(iter);
		down_read(&c->gc_lock);
	}

	/*
	 * XXX: figure out how far we might need to split,
	 * instead of locking/reserving all the way to the root:
	 */
	iter->locks_want = BTREE_MAX_DEPTH;
	if (!bch_btree_iter_upgrade(iter))
		goto out_unlock;

	reserve = bch_btree_reserve_get(c, b, iter, 0,
					!(flags & BTREE_INSERT_NOFAIL));
	if (IS_ERR(reserve)) {
		ret = PTR_ERR(reserve);
		goto out_unlock;
	}

	as = bch_async_split_alloc(b, iter);
	if (!as) {
		ret = -EIO;
		goto out_put_reserve;
	}

	btree_split(b, iter, NULL, reserve, as);
	ret = 0;

out_put_reserve:
	bch_btree_reserve_put(c, reserve);
out_unlock:
	up_read(&c->gc_lock);
	return ret;
}

/**
 * bch_btree_insert_at - insert bkeys starting at a given btree node
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @hook:		insert callback
 * @persistent:		if not null, @persistent will wait on journal write
 * @flags:		BTREE_INSERT_ATOMIC | BTREE_INSERT_NO_MARK_KEY
 *
 * This is top level for common btree insertion/index update code. The control
 * flow goes roughly like:
 *
 * bch_btree_insert_at -- split keys that span interior nodes
 *   bch_btree_insert_node -- split btree nodes when full
 *     btree_split
 *     bch_btree_insert_keys -- get and put journal reservations
 *       btree_insert_key -- call fixup and remove key from keylist
 *         bch_insert_fixup_extent -- handle overlapping extents
 *           bch_btree_insert_and_journal -- add the key to the journal
 *             bch_bset_insert -- actually insert into the bset
 *
 * This function will split keys that span multiple nodes, calling
 * bch_btree_insert_node() for each one. It will not return until all keys
 * have been inserted, or an insert has failed.
 *
 * @persistent will only wait on the journal write if the full keylist was
 * inserted.
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again. Only returned
 *  if passed BTREE_INSERT_ATOMIC.
 * -EROFS: cache set read only
 * -EIO: journal or btree node IO error
 */
int bch_btree_insert_at(struct btree_iter *iter,
			struct keylist *insert_keys,
			struct disk_reservation *disk_res,
			struct btree_insert_hook *hook,
			u64 *journal_seq, unsigned flags)
{
	int ret = -EINTR;

	BUG_ON(iter->level);

	if (unlikely(!percpu_ref_tryget(&iter->c->writes)))
		return -EROFS;

	iter->locks_want = 0;
	if (unlikely(!bch_btree_iter_upgrade(iter)))
		goto traverse;

	while (1) {
		EBUG_ON(bkey_cmp(bkey_start_pos(&bch_keylist_front(insert_keys)->k),
				 iter->pos));

		switch (bch_btree_insert_keys_leaf(iter->nodes[0], iter,
					insert_keys, disk_res,
					hook, journal_seq, flags)) {
		case BTREE_INSERT_OK:
			ret = 0;
			break;
		case BTREE_INSERT_NEED_SPLIT:
			ret = bch_btree_split_leaf(iter, flags);
			break;
		case BTREE_INSERT_ERROR:
			/* Journal error, so we couldn't get a journal reservation: */
			ret = -EIO;
			break;
		default:
			BUG();
		}

		/*
		 * We don't test against success because we might have
		 * successfully inserted the keys on the keylist, but have more
		 * to insert in the next leaf node:
		 */
		if (likely(bch_keylist_empty(insert_keys))) {
			BUG_ON(ret);
			break;
		}

		/*
		 * -EAGAIN means we have to drop locks and wait on
		 *  mca_cannibalize_lock - btree_iter_unlock() does this
		 */
		if (ret == -EAGAIN) {
			bch_btree_iter_unlock(iter);
			ret = -EINTR;
		}

		if (ret && ret != -EINTR)
			break;
traverse:
		/*
		 * Can't retry, make sure we return an error:
		 */
		if (flags & BTREE_INSERT_ATOMIC) {
			ret = ret ?: -EINTR;
			break;
		}

		ret = bch_btree_iter_traverse(iter);
		if (ret)
			break;
	}
	percpu_ref_put(&iter->c->writes);

	return ret;
}

static void multi_lock_write(struct btree_insert_multi *first,
			     struct btree_insert_multi *m)
{
	/*
	 * Because we sorted the transaction entries, if multiple iterators
	 * point to the same leaf node they'll always be adjacent now:
	 */
	if (m != first &&
	    (m[0].iter->nodes[0] == m[-1].iter->nodes[0]))
		return; /* already locked */

	btree_node_lock_for_insert(m->iter->nodes[0], m->iter);
}

static void multi_unlock_write(struct btree_insert_multi *first,
			       struct btree_insert_multi *m)
{
	if (m != first &&
	    (m[0].iter->nodes[0] == m[-1].iter->nodes[0]))
		return; /* already locked */

	btree_node_unlock_write(m->iter->nodes[0], m->iter);
}

int bch_btree_insert_at_multi(struct btree_insert_multi *m, unsigned nr,
			      u64 *journal_seq, unsigned flags)
{
	struct cache_set *c = m[0].iter->c;
	struct journal_res res = { 0, 0 };
	struct btree_insert_multi *i;
	struct btree_iter *split;
	unsigned u64s = 0;
	bool swapped;
	int ret;

	for (i = m; i < m + nr; i++)
		EBUG_ON(bkey_cmp(bkey_start_pos(&i->k->k), i->iter->pos));

	/* Sort transaction entries by iterator position, for lock ordering: */
	do {
		swapped = false;

		for (i = m; i + 1 < m + nr; i++)
			if (bkey_cmp(i[0].iter->pos, i[1].iter->pos) > 0) {
				swap(i[0], i[1]);
				swapped = true;
			}
	} while (swapped);

	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return -EROFS;

	for (i = m; i < m + nr; i++)
		u64s += jset_u64s(i->k->k.u64s);

	for (i = m; i < m + nr; i++) {
		i->iter->locks_want = 0;
		if (unlikely(!bch_btree_iter_upgrade(i->iter))) {
			ret = -EINTR;
			goto err;
		}
	}
retry:
	ret = bch_journal_res_get(&c->journal, &res, u64s, u64s);
	if (ret)
		goto err;

	for (i = m; i < m + nr; i++) {
		multi_lock_write(m, i);

		/*
		 * Check against total, not just the key for this iterator,
		 * because multiple inserts might be going to the same node:
		 */
		if (!__have_enough_space(c, i->iter->nodes[0], u64s))
			goto split;
	}

	for (i = m; i < m + nr; i++)
		btree_insert_key(i->iter, i->iter->nodes[0],
				 &i->iter->node_iters[0],
				 &keylist_single(i->k),
				 NULL, NULL,
				 &res, flags);

	do {
		multi_unlock_write(m, --i);
	} while (i != m);

	bch_journal_res_put(&c->journal, &res, journal_seq);

	for (i = m; i < m + nr; i++) {
		if (i != m &&
		    (i[0].iter->nodes[0] == i[-1].iter->nodes[0]))
			continue;

		bch_btree_node_write_lazy(i->iter->nodes[0], i->iter);
	}

out:
	percpu_ref_put(&c->writes);
	return ret;
split:
	split = i->iter;
	do {
		multi_unlock_write(m, i);
	} while (i-- != m);

	/*
	 * XXX: Do we need to drop our journal res for the split?
	 *
	 * yes, because otherwise we're potentially blocking other things that
	 * need the journal, which includes the allocator - and we're going to
	 * be allocating new nodes in the split
	 */
	bch_journal_res_put(&c->journal, &res, journal_seq);

	ret = bch_btree_split_leaf(split, flags);
	if (ret)
		goto err;
	goto retry;
err:
	if (ret == -EAGAIN) {
		for (i = m; i < m + nr; i++)
			bch_btree_iter_unlock(i->iter);
		ret = -EINTR;
	}
	goto out;
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

	check_key->k.type = KEY_TYPE_COOKIE;
	set_bkey_val_bytes(&check_key->k, sizeof(struct bch_cookie));

	cookie = bkey_i_to_cookie(check_key);
	get_random_bytes(&cookie->v, sizeof(cookie->v));

	bkey_copy(&tmp.key, check_key);

	bch_btree_iter_rewind(iter, bkey_start_pos(&check_key->k));

	ret = bch_btree_insert_at(iter, &keylist_single(&tmp.key),
				  NULL, NULL, NULL, BTREE_INSERT_ATOMIC);

	bch_btree_iter_set_pos(iter, saved_pos);

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
		     struct keylist *keys,
		     struct disk_reservation *disk_res,
		     struct btree_insert_hook *hook,
		     u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	int ret, ret2;

	bch_btree_iter_init_intent(&iter, c, id,
				   bkey_start_pos(&bch_keylist_front(keys)->k));

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch_btree_insert_at(&iter, keys, disk_res,
				  hook, journal_seq, flags);
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

	ret = bch_btree_insert_at(&iter, &keylist_single(k), NULL,
				  NULL, journal_seq, 0);
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
			   struct btree_insert_hook *hook,
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

		ret = bch_btree_insert_at(&iter, &keylist_single(&delete),
					  NULL, hook, journal_seq,
					  BTREE_INSERT_NOFAIL);
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
int bch_btree_node_rewrite(struct btree *b, struct btree_iter *iter, bool wait)
{
	struct cache_set *c = iter->c;
	struct btree *n, *parent = iter->nodes[b->level + 1];
	struct btree_reserve *reserve;
	struct async_split *as;

	iter->locks_want = BTREE_MAX_DEPTH;
	if (!bch_btree_iter_upgrade(iter))
		return -EINTR;

	reserve = bch_btree_reserve_get(c, b, wait ? iter : NULL, 1, true);
	if (IS_ERR(reserve)) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return PTR_ERR(reserve);
	}

	as = bch_async_split_alloc(b, iter);
	if (!as) {
		bch_btree_reserve_put(c, reserve);
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return -EIO;
	}

	n = btree_node_alloc_replacement(c, b, reserve);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write(n, &as->cl, NULL);

	bch_btree_node_free_start(c, as, b);

	if (parent) {
		bch_btree_insert_node(parent, iter,
					    &keylist_single(&n->key),
					    reserve, as);
	} else {
		bch_btree_set_root(iter, n, as, reserve);
	}

	btree_open_bucket_put(iter->c, n);

	bch_btree_node_free_inmem(iter, b);

	BUG_ON(!bch_btree_iter_node_replace(iter, n));

	bch_btree_reserve_put(c, reserve);
	return 0;
}
