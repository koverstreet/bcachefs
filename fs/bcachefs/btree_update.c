
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

/* Calculate ideal packed bkey format for new btree nodes: */

void __bch_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey_tup tup;

	for_each_btree_node_key_unpack(&b->keys, &tup, &iter)
		bch_bkey_format_add_key(s, &tup.k);

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

void bch_pending_btree_node_free_init(struct cache_set *c,
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

static void bch_pending_btree_node_free_insert_done(struct cache_set *c,
						    struct btree *b,
						    enum btree_id id,
						    struct bkey_s_c k)
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

	if (gc_pos_cmp(c->gc_pos, gc_phase(GC_PHASE_PENDING_DELETE)) < 0)
		bch_mark_pointers(c, bkey_i_to_s_c_extent(&d->key),
				  -CACHE_BTREE_NODE_SIZE(&c->sb),
				  false, true, false, b
				  ? gc_pos_btree_node(b)
				  : gc_pos_btree_root(id));

	mutex_unlock(&c->btree_node_pending_free_lock);
}

static void __btree_node_free(struct cache_set *c, struct btree *b,
			      struct btree_iter *iter)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));
	BUG_ON(b->ob);
	BUG_ON(atomic_read(&b->write_blocked));

	/* Cause future btree_node_relock() calls to fail: */
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

	six_unlock_write(&b->lock);
}

void bch_btree_node_free_never_inserted(struct cache_set *c, struct btree *b)
{
	struct open_bucket *ob = b->ob;

	b->ob = NULL;

	__btree_node_free(c, b, NULL);

	bch_open_bucket_put(c, ob);
}

void bch_btree_node_free(struct btree_iter *iter, struct btree *b)
{
	__btree_node_free(iter->c, b, iter);
}

static void bch_btree_node_free_ondisk(struct cache_set *c,
				       struct pending_btree_node_free *pending)
{
	BUG_ON(!pending->index_update_done);

	mutex_lock(&c->btree_node_pending_free_lock);
	list_del(&pending->list);

	bch_mark_pointers(c, bkey_i_to_s_c_extent(&pending->key),
			  -CACHE_BTREE_NODE_SIZE(&c->sb), false, true,
			  false, gc_phase(GC_PHASE_PENDING_DELETE));

	mutex_unlock(&c->btree_node_pending_free_lock);
}

void btree_open_bucket_put(struct cache_set *c, struct btree *b)
{
	bch_open_bucket_put(c, b->ob);
	b->ob = NULL;
}

static struct btree *__bch_btree_node_alloc(struct cache_set *c,
					    bool check_enospc,
					    struct closure *cl)
{
	BKEY_PADDED(k) tmp;
	struct open_bucket *ob;
	struct btree *b;
retry:
	/* alloc_sectors is weird, I suppose */
	bkey_extent_init(&tmp.k);
	tmp.k.k.size = CACHE_BTREE_NODE_SIZE(&c->sb),

	ob = bch_alloc_sectors(c, &c->btree_write_point, &tmp.k,
			       check_enospc, cl);
	if (IS_ERR(ob))
		return ERR_CAST(ob);

	if (tmp.k.k.size < CACHE_BTREE_NODE_SIZE(&c->sb)) {
		bch_open_bucket_put(c, ob);
		goto retry;
	}

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
	b->data->magic = bset_magic(&c->sb);
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

static void __bch_btree_set_root(struct cache_set *c, struct btree *b)
{
	bool stale;

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;

	stale = bch_mark_pointers(c, bkey_i_to_s_c_extent(&b->key),
				  CACHE_BTREE_NODE_SIZE(&c->sb), true, true,
				  false, gc_pos_btree_root(b->btree_id));
	BUG_ON(stale);
	spin_unlock(&c->btree_root_lock);

	bch_recalc_btree_reserve(c);
}

/*
 * Only for cache set bringup, when first reading the btree roots or allocating
 * btree roots when initializing a new cache set:
 */
void bch_btree_set_root_initial(struct cache_set *c, struct btree *b)
{
	BUG_ON(btree_node_root(b));

	__bch_btree_set_root(c, b);
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
static int bch_btree_set_root(struct btree_iter *iter, struct btree *b,
			      struct journal_res *res)
{
	struct cache_set *c = iter->c;
	struct btree *old;
	u64 seq;

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	btree_node_lock_write(old, iter);

	__bch_btree_set_root(c, b);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	btree_node_unlock_write(old, iter);

	bch_pending_btree_node_free_insert_done(c, NULL, old->btree_id,
						bkey_i_to_s_c(&old->key));

	/*
	 * Ensure new btree root is persistent (reachable via the
	 * journal) before returning and the caller unlocking it:
	 */
	seq = c->journal.seq;
	bch_journal_res_put(&c->journal, res, NULL);

	return bch_journal_flush_seq(&c->journal, seq);
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
	while (reserve->nr) {
		struct btree *b = reserve->b[--reserve->nr];

		six_unlock_write(&b->lock);
		bch_btree_node_free_never_inserted(c, b);
		six_unlock_intent(&b->lock);
	}

	mempool_free(reserve, &c->btree_reserve_pool);
}

static struct btree_reserve *__bch_btree_reserve_get(struct cache_set *c,
					bool check_enospc,
					unsigned nr_nodes,
					struct closure *cl)
{
	struct btree_reserve *reserve;
	struct btree *b;
	int ret;

	BUG_ON(nr_nodes > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	ret = mca_cannibalize_lock(c, cl);
	if (ret)
		return ERR_PTR(ret);

	reserve = mempool_alloc(&c->btree_reserve_pool, GFP_NOIO);

	reserve->nr = 0;

	while (reserve->nr < nr_nodes) {
		b = __bch_btree_node_alloc(c, check_enospc, cl);
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
		reserve = __bch_btree_reserve_get(c, true, 1, &cl);
		if (!IS_ERR(reserve))
			break;

		if (PTR_ERR(reserve) == -ENOSPC)
			return PTR_ERR(reserve);

		closure_sync(&cl);
	}

	b = __btree_root_alloc(c, 0, id, reserve);
	bch_btree_reserve_put(c, reserve);

	bch_btree_node_write(b, writes, NULL);

	bch_btree_set_root_initial(c, b);
	btree_open_bucket_put(c, b);
	six_unlock_intent(&b->lock);

	return 0;
}

static bool bch_insert_fixup_btree_ptr(struct btree_iter *iter,
				       struct btree *b,
				       struct bkey_i *insert,
				       struct btree_node_iter *node_iter,
				       struct bch_replace_info *replace,
				       struct bpos *done,
				       struct journal_res *res)
{
	struct cache_set *c = iter->c;
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	int cmp;

	BUG_ON(replace);
	EBUG_ON((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
		(bkey_deleted(k)
		 ? bkey_cmp_packed(f, k, &insert->k) > 0
		 : bkey_cmp_packed(f, k, &insert->k) >= 0));

	if (bkey_extent_is_data(&insert->k)) {
		bool stale;

		stale = bch_mark_pointers(c, bkey_i_to_s_c_extent(insert),
					  CACHE_BTREE_NODE_SIZE(&c->sb),
					  true, true, false,
					  gc_pos_btree_node(b));
		BUG_ON(stale);
	}

	while ((k = bch_btree_node_iter_peek_all(node_iter, &b->keys))) {
		struct bkey_tup tup;
		struct bkey_s_c u;

		bkey_disassemble(&tup, f, k);
		u = bkey_tup_to_s_c(&tup);

		cmp = bkey_cmp(u.k->p, insert->k.p);
		if (cmp > 0)
			break;

		if (!cmp && !bkey_deleted(k)) {
			bch_pending_btree_node_free_insert_done(c, b, b->btree_id, u);
			/*
			 * Look up pending delete, mark so that gc marks it on
			 * the pending delete list
			 */
			k->type = KEY_TYPE_DELETED;
			btree_keys_account_key_drop(&b->keys.nr, k);
		}

		bch_btree_node_iter_next_all(node_iter, &b->keys);
	}

	bch_btree_insert_and_journal(iter, b, node_iter, insert, res);
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
 * This is called from bch_insert_fixup_extent().
 *
 * The insert is journalled.
 */
void bch_btree_insert_and_journal(struct btree_iter *iter,
				  struct btree *b,
				  struct btree_node_iter *node_iter,
				  struct bkey_i *insert,
				  struct journal_res *res)
{
	struct cache_set *c = iter->c;

	bch_btree_bset_insert(iter, b, node_iter, insert);

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (!b->level && c->btree_flush_delay)
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
		btree_bset_last(b)->journal_seq = c->journal.seq;
	}
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
 * @flags:		FAIL_IF_STALE
 *
 * Inserts the first key from @insert_keys
 *
 * Returns true if an insert was actually done and @b was modified - false on a
 * failed replace operation
 */
static bool btree_insert_key(struct btree_iter *iter, struct btree *b,
			     struct btree_node_iter *node_iter,
			     struct keylist *insert_keys,
			     struct bch_replace_info *replace,
			     struct journal_res *res,
			     unsigned flags)
{
	bool dequeue = false;
	struct bkey_i *insert = bch_keylist_front(insert_keys), *orig = insert;
	BKEY_PADDED(key) temp;
	struct bpos done;
	s64 oldsize = bch_count_data(&b->keys);
	bool do_insert;

	BUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	bch_btree_node_iter_verify(node_iter, &b->keys);

	if (b->level) {
		do_insert = bch_insert_fixup_btree_ptr(iter, b, insert,
						       node_iter, replace,
						       &done, res);
		dequeue = true;
	} else if (!b->keys.ops->is_extents) {

		do_insert = bch_insert_fixup_key(iter, b, insert, node_iter,
						 replace, &done,
						 res);
		dequeue = true;
	} else {
		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert->k.p, b->key.k.p) > 0)
			bch_cut_back(b->key.k.p, &insert->k);

		do_insert = bch_insert_fixup_extent(iter, b, insert,
						    node_iter, replace, &done,
						    res, flags);
		bch_cut_front(done, orig);
		dequeue = (orig->k.size == 0);

		bch_btree_iter_set_pos(iter, done);
	}

	if (dequeue)
		bch_keylist_dequeue(insert_keys);

	bch_count_data_verify(&b->keys, oldsize);

	trace_bcache_btree_insert_key(b, insert, replace != NULL, do_insert);

	return do_insert;
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
	u64s = b->keys.ops->is_extents ? BKEY_EXTENT_MAX_U64s * 3 : u64s;

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
	struct journal_res res;
	struct journal_entry_pin_list *pin_list = NULL;
	unsigned i, pin_idx = UINT_MAX;

	memset(&res, 0, sizeof(res));

	/*
	 * must get journal res before getting a journal pin (else we deadlock)
	 */
	if (bch_journal_res_get(&c->journal, &res,
				jset_u64s(0), jset_u64s(0)))
		return NULL;

	as = mempool_alloc(&c->btree_async_split_pool, GFP_NOIO);
	closure_init(&as->cl, &c->cl);
	as->c		= c;
	as->b		= NULL;
	as->res		= res;
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

static void async_split_update_done(struct closure *cl)
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

static void async_split_writes_done(struct closure *cl)
{
	struct async_split *as = container_of(cl, struct async_split, cl);
	struct btree *b = as->b;

	/* Writes are finished, persist pointers to new nodes: */

	/* XXX: error handling */

	if (b) {
		six_lock_read(&b->lock);
		if (atomic_dec_and_test(&b->write_blocked)) {
			if (!b->as) {
				closure_wait(&btree_current_write(b)->wait, cl);
				__bch_btree_node_write(b, NULL, -1);
			} else {
				closure_wait(&b->as->wait, cl);
				/* XXX: do stuff with journal pin, btree node
				 * freeing */
				closure_put(&b->as->cl);
				b->as = NULL;
			}
		}
		six_unlock_read(&b->lock);
	}

	continue_at(cl, async_split_update_done, system_wq);
}

static enum btree_insert_status
bch_btree_insert_keys_interior(struct btree *b,
			       struct btree_iter *iter,
			       struct keylist *insert_keys,
			       struct bch_replace_info *replace,
			       u64 *journal_seq,
			       struct async_split *as,
			       unsigned flags)
{
	struct btree_node_iter *node_iter = &iter->node_iters[b->level];
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	struct journal_res res = { 0, 0 };

	BUG_ON(replace);
	BUG_ON(journal_seq);
	BUG_ON(!as);
	BUG_ON(as->b);

	btree_node_lock_for_insert(b, iter);

	if (!have_enough_space(iter->c, b, insert_keys)) {
		btree_node_unlock_write(b, iter);
		return BTREE_INSERT_NEED_SPLIT;
	}

	/* not using the journal reservation, drop it now before blocking: */
	bch_journal_res_put(&iter->c->journal, &as->res, NULL);

	as->b = b;
	atomic_inc(&b->write_blocked);

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

		btree_insert_key(iter, b, node_iter, insert_keys,
				 NULL, &res, flags);
	}

	btree_node_unlock_write(b, iter);

	/*
	 * insert_fixup_btree_ptr() will advance the node iterator to _after_
	 * the last key it inserted, which is not what we want
	 */

	while ((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
	       (bkey_cmp_left_packed(f, k, iter->pos) >= 0))
		;

	continue_at_noreturn(&as->cl, async_split_writes_done, system_wq);

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
			   struct bch_replace_info *replace,
			   u64 *journal_seq,
			   struct async_split *as,
			   unsigned flags)
{
	bool done = false, inserted = false, need_split = false;
	struct journal_res res = { 0, 0 };
	struct bkey_i *k = bch_keylist_front(insert_keys);

	BUG_ON(as);

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

			if (btree_insert_key(iter, b,
					     &iter->node_iters[b->level],
					     insert_keys, replace,
					     &res, flags))
				inserted = true;
		}

		btree_node_unlock_write(b, iter);

		if (res.ref)
			bch_journal_res_put(&iter->c->journal, &res,
					    journal_seq);
	}

	if (inserted)
		bch_btree_node_write_lazy(b, iter);

	return need_split ? BTREE_INSERT_NEED_SPLIT : BTREE_INSERT_OK;
}

static enum btree_insert_status
bch_btree_insert_keys(struct btree *b,
		      struct btree_iter *iter,
		      struct keylist *insert_keys,
		      struct bch_replace_info *replace,
		      u64 *journal_seq,
		      struct async_split *as,
		      unsigned flags)
{
	verify_keys_sorted(insert_keys);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!b->written);

	return (!b->level
		? bch_btree_insert_keys_leaf
		: bch_btree_insert_keys_interior)(b, iter, insert_keys,
						  replace, journal_seq,
						  as, flags);
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
		if (k->_data - set1->_data >= (set1->u64s * 3) / 5)
			break;
		k = bkey_next(k);
	}

	n1->key.k.p = bkey_unpack_key(&n1->keys.format, k).p;
	k = bkey_next(k);

	n1->data->max_key = n1->key.k.p;
	n2->data->min_key =
		btree_type_successor(n1->btree_id, n1->key.k.p);

	set2->u64s = (u64 *) bset_bkey_last(set1) - (u64 *) k;
	set1->u64s -= set2->u64s;

	n2->keys.nr.live_u64s = set2->u64s;
	n2->keys.nr.packed_keys
		= n1->keys.nr.packed_keys - nr_packed;
	n2->keys.nr.unpacked_keys
		= n1->keys.nr.unpacked_keys - nr_unpacked;

	n1->keys.nr.live_u64s = set1->u64s;
	n1->keys.nr.packed_keys = nr_packed;
	n1->keys.nr.unpacked_keys = nr_unpacked;

	BUG_ON(!set1->u64s);
	BUG_ON(!set2->u64s);

	memcpy(set2->start,
	       bset_bkey_last(set1),
	       set2->u64s * sizeof(u64));

	n1->keys.set->size = 0;
	n1->keys.set->extra = BSET_TREE_NONE_VAL;
	n2->keys.set->size = 0;
	n2->keys.set->extra = BSET_TREE_NONE_VAL;

	six_unlock_write(&n2->lock);

	bch_verify_btree_nr_keys(&n1->keys);
	bch_verify_btree_nr_keys(&n2->keys);

	return n2;
}

static void btree_split_insert_keys(struct btree_iter *iter, struct btree *b,
				    struct keylist *keys, bool is_last)
{
	struct journal_res res = { 0, 0 };
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

		btree_insert_key(iter, b, &node_iter, keys,
				 NULL, &res, 0);
	}

	six_unlock_write(&b->lock);
}

static int btree_split(struct btree *b, struct btree_iter *iter,
		       struct keylist *insert_keys, unsigned flags,
		       struct btree_reserve *reserve,
		       struct async_split *as)
{
	struct cache_set *c = iter->c;
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	uint64_t start_time = local_clock();
	unsigned u64s_to_insert = b->level
		? bch_keylist_nkeys(insert_keys) : 0;
	int ret;

	BUG_ON(!parent && (b != btree_node_root(b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));

	if (atomic_read(&b->write_blocked)) {
		/* recheck with write lock held: */
		btree_node_lock_write(b, iter);
		if (atomic_read(&b->write_blocked)) {
			b->as = as;
			closure_get(&as->cl);
		}
		btree_node_unlock_write(b, iter);
	}

	n1 = btree_node_alloc_replacement(c, b, reserve);

	if (__set_blocks(n1->data,
			 n1->data->keys.u64s + u64s_to_insert,
			 block_bytes(n1->c)) > btree_blocks(c) * 3 / 4) {
		trace_bcache_btree_node_split(b, btree_bset_first(n1)->u64s);

		n2 = __btree_split_node(iter, n1, reserve);
		six_unlock_write(&n1->lock);

		/*
		 * For updates to interior nodes, we've got to do the insert
		 * before we split because the stuff we're inserting has to be
		 * inserted atomically. Post split, the keys might have to go in
		 * different nodes and the split would no longer be atomic.
		 */
		if (b->level) {
			btree_split_insert_keys(iter, n1, insert_keys, false);
			btree_split_insert_keys(iter, n2, insert_keys, true);
		}

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

			btree_split_insert_keys(iter, n3, &as->parent_keys, true);
			bch_btree_node_write(n3, &as->cl, NULL);
		}
	} else {
		trace_bcache_btree_node_compact(b, btree_bset_first(n1)->u64s);
		six_unlock_write(&n1->lock);

		if (b->level)
			btree_split_insert_keys(iter, n1, insert_keys, true);

		bch_keylist_add(&as->parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, &as->cl, NULL);

	bch_pending_btree_node_free_init(c, as, b);

	/* New nodes all written, now make them visible: */

	if (parent) {
		/* Split a non root node */
		ret = bch_btree_insert_node(parent, iter, &as->parent_keys,
					    NULL, NULL, BTREE_INSERT_NOFAIL,
					    reserve, as);
		if (ret)
			goto err;
	} else {
		/* Wait on journal flush and btree node writes: */
		closure_sync(&as->cl);

		/* Check for journal error after waiting on the journal flush: */
		if (bch_journal_error(&c->journal) ||
		    test_bit(CACHE_SET_BTREE_WRITE_ERROR, &c->flags))
			goto err;

		if (n3) {
			ret = bch_btree_set_root(iter, n3, &as->res);
			if (ret)
				goto err;
		} else {
			/* Root filled up but didn't need to be split */
			ret = bch_btree_set_root(iter, n1, &as->res);
			if (ret)
				goto err;
		}

		continue_at_noreturn(&as->cl, async_split_writes_done,
				     system_wq);
	}

	btree_open_bucket_put(c, n1);
	if (n2)
		btree_open_bucket_put(c, n2);
	if (n3)
		btree_open_bucket_put(c, n3);

	bch_btree_node_free(iter, b);
	bch_btree_iter_node_drop(iter, b);

	/* Successful split, update the iterator to point to the new nodes: */

	if (n3)
		bch_btree_iter_node_replace(iter, n3);
	if (n2)
		bch_btree_iter_node_replace(iter, n2);
	bch_btree_iter_node_replace(iter, n1);

	bch_time_stats_update(&c->btree_split_time, start_time);
	return 0;
err:
	/* IO error: */
	if (n3) {
		bch_btree_node_free_never_inserted(c, n3);
		six_unlock_intent(&n3->lock);
	}
	if (n2) {
		bch_btree_node_free_never_inserted(c, n2);
		six_unlock_intent(&n2->lock);
	}
	bch_btree_node_free_never_inserted(c, n1);
	six_unlock_intent(&n1->lock);
	return -EIO;
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @flags:		FAIL_IF_STALE
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
int bch_btree_insert_node(struct btree *b,
			  struct btree_iter *iter,
			  struct keylist *insert_keys,
			  struct bch_replace_info *replace,
			  u64 *journal_seq, unsigned flags,
			  struct btree_reserve *reserve,
			  struct async_split *as)
{
	struct cache_set *c = iter->c;
	int ret;

	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(b->level &&
	       !btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(b->level && replace);
	BUG_ON(b->level && (!reserve || !as));
	BUG_ON(!b->level && (reserve || as));
	BUG_ON(!b->written);
	verify_keys_sorted(insert_keys);

	if (replace)
		flags |= FAIL_IF_STALE;

	switch (bch_btree_insert_keys(b, iter, insert_keys, replace,
				      journal_seq, as, flags)) {
	case BTREE_INSERT_OK:
		return 0;

	case BTREE_INSERT_NEED_SPLIT:
		if (!b->level) {
			/*
			 * XXX: figure out how far we might need to split,
			 * instead of locking/reserving all the way to the root:
			 */

			iter->locks_want = BTREE_MAX_DEPTH;
			if (!bch_btree_iter_upgrade(iter))
				return -EINTR;

			reserve = bch_btree_reserve_get(c, b, iter, 0,
						!(flags & BTREE_INSERT_NOFAIL));
			if (IS_ERR(reserve))
				return PTR_ERR(reserve);

			as = bch_async_split_alloc(b, iter);
			if (!as) {
				bch_btree_reserve_put(c, reserve);
				return -EIO;
			}

			/* Hack, because gc and splitting nodes doesn't mix yet: */
			down_read(&c->gc_lock);
		}

		ret = btree_split(b, iter, insert_keys, flags, reserve, as);

		if (!b->level) {
			up_read(&c->gc_lock);
			bch_btree_reserve_put(c, reserve);
		}

		return ret;

	case BTREE_INSERT_ERROR:
		/* Journal error, so we couldn't get a journal reservation: */
		return -EIO;
	default:
		BUG();
	}
}

/* Normal update interface: */

/**
 * bch_btree_insert_at - insert bkeys starting at a given btree node
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @flags:		BTREE_INSERT_ATOMIC | FAIL_IF_STALE
 *
 * The FAIL_IF_STALE flag is set automatically if @replace is not NULL.
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
			struct bch_replace_info *replace,
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
		ret = bch_btree_insert_node(iter->nodes[0], iter, insert_keys,
					    replace, journal_seq, flags,
					    NULL, NULL);

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
		BUG_ON(!btree_insert_key(i->iter, i->iter->nodes[0],
					 &i->iter->node_iters[0],
					 &keylist_single(i->k), NULL,
					 &res, flags));

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

	{
		struct btree *b = split->nodes[0];
		struct btree_reserve *reserve;
		struct async_split *as;

		/*
		 * XXX: figure out how far we might need to split,
		 * instead of locking/reserving all the way to the root:
		 */
		split->locks_want = BTREE_MAX_DEPTH;
		if (!bch_btree_iter_upgrade(split)) {
			ret = -EINTR;
			goto err;
		}

		reserve = bch_btree_reserve_get(c, b, split, 0,
					    !(flags & BTREE_INSERT_NOFAIL));
		if (IS_ERR(reserve)) {
			ret = PTR_ERR(reserve);
			goto err;
		}

		as = bch_async_split_alloc(b, split);
		if (!as) {
			bch_btree_reserve_put(c, reserve);
			ret = -EIO;
			goto err;
		}

		down_read(&c->gc_lock);
		ret = btree_split(b, split, NULL, flags, reserve, as);
		up_read(&c->gc_lock);

		bch_btree_reserve_put(c, reserve);

		if (ret)
			goto err;
		goto retry;
	}
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
				  NULL, NULL, BTREE_INSERT_ATOMIC);

	bch_btree_iter_set_pos(iter, saved_pos);

	return ret;
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct cache_set
 * @id:			btree to insert into
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 */
int bch_btree_insert(struct cache_set *c, enum btree_id id,
		     struct keylist *keys, struct bch_replace_info *replace,
		     u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	int ret, ret2;

	bch_btree_iter_init_intent(&iter, c, id,
				   bkey_start_pos(&bch_keylist_front(keys)->k));

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch_btree_insert_at(&iter, keys, replace,
				  journal_seq, flags);
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
				  journal_seq, 0);
	ret2 = bch_btree_iter_unlock(&iter);

	return ret ?: ret2;
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
	int ret;

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
	bch_pending_btree_node_free_init(c, as, b);

	if (parent) {
		ret = bch_btree_insert_node(parent, iter,
					    &keylist_single(&n->key),
					    NULL, NULL,
					    BTREE_INSERT_NOFAIL,
					    reserve, as);
		BUG_ON(ret);
	} else {
		closure_sync(&as->cl);

		if (bch_journal_error(&c->journal) ||
		    btree_node_write_error(n)) {
			bch_btree_node_free_never_inserted(c, n);
			six_unlock_intent(&n->lock);
			return -EIO;
		}

		bch_btree_set_root(iter, n, &as->res);

		continue_at_noreturn(&as->cl, async_split_writes_done,
				     system_wq);
	}

	btree_open_bucket_put(iter->c, n);

	bch_btree_node_free(iter, b);
	bch_btree_iter_node_drop(iter, b);

	BUG_ON(!bch_btree_iter_node_replace(iter, n));

	bch_btree_reserve_put(c, reserve);
	return 0;
}
