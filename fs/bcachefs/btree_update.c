
#include "bcache.h"
#include "alloc.h"
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

/* Node allocation: */

static void __btree_node_free(struct cache_set *c, struct btree *b,
			      struct btree_iter *iter)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));
	BUG_ON(b->ob);

	/* Cause future btree_node_relock() calls to fail: */
	btree_node_lock_write(b, iter);

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

	btree_node_unlock_write(b, iter);
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
	BKEY_PADDED(k) tmp;

	bkey_copy(&tmp.k, &b->key);

	__btree_node_free(iter->c, b, iter);

	/* XXX: this isn't right */
	bch_mark_pointers(iter->c, b, bkey_i_to_s_c_extent(&tmp.k),
			  -CACHE_BTREE_NODE_SIZE(&iter->c->sb),
			  false, true, false);
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
	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;

	if (b->btree_id != c->gc_cur_btree
	    ? b->btree_id < c->gc_cur_btree
	    : b->level <= c->gc_cur_level) {
		bool stale = bch_mark_pointers(c, NULL,
					       bkey_i_to_s_c_extent(&b->key),
					       CACHE_BTREE_NODE_SIZE(&c->sb),
					       true, true, false);

		BUG_ON(stale);
	}
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
static int bch_btree_set_root(struct btree_iter *iter, struct btree *b)
{
	struct btree *old;

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);

	/*
	 * Ensure no one is using the old root while we switch to the
	 * new root:
	 */
	btree_node_lock_write(old, iter);

	__bch_btree_set_root(iter->c, b);

	/*
	 * Unlock old root after new root is visible:
	 *
	 * The new root isn't persistent, but that's ok: we still have
	 * an intent lock on the new root, and any updates that would
	 * depend on the new root would have to update the new root.
	 */
	btree_node_unlock_write(old, iter);

	/*
	 * Ensure new btree root is persistent (reachable via the
	 * journal) before returning and the caller unlocking it:
	 */
	return bch_journal_meta(&iter->c->journal);
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

/* Wrapper around bch_bset_insert() that fixes linked iterators: */
void bch_btree_bset_insert(struct btree_iter *iter,
			   struct btree *b,
			   struct btree_node_iter *node_iter,
			   struct bkey_i *insert)
{
	struct btree_iter *linked;
	struct bkey_packed *where = NULL;

	BUG_ON(insert->k.u64s > bch_btree_keys_u64s_remaining(b));

	bch_bset_insert(&b->keys, node_iter, insert, &where);

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[b->level] == b) {
			if (where)
				bch_btree_fix_linked_iter(linked, b, where);
			bch_btree_node_iter_sort(&linked->node_iters[b->level],
						 &b->keys);
		}
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
				  struct journal_res *res,
				  u64 *journal_seq)
{
	struct cache_set *c = iter->c;

	bch_btree_bset_insert(iter, b, node_iter, insert);

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
		btree_bset_last(b)->journal_seq = c->journal.seq;
		if (journal_seq)
			*journal_seq = iter->c->journal.seq;
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
			     u64 *journal_seq, unsigned flags)
{
	bool dequeue = false;
	struct bkey_i *insert = bch_keylist_front(insert_keys), *orig = insert;
	BKEY_PADDED(key) temp;
	struct bpos done;
	s64 newsize, oldsize = bch_count_data(&b->keys);
	bool do_insert;

	BUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	bch_btree_node_iter_verify(node_iter, &b->keys);

	if (b->level) {
		BUG_ON(bkey_cmp(insert->k.p, b->key.k.p) > 0);

		do_insert = bch_insert_fixup_btree_ptr(iter, b, insert,
						       node_iter, replace, &done,
						       res, journal_seq);
		dequeue = true;
	} else if (!b->keys.ops->is_extents) {
		BUG_ON(bkey_cmp(insert->k.p, b->key.k.p) > 0);

		do_insert = bch_insert_fixup_key(iter, b, insert, node_iter,
						 replace, &done,
						 res, journal_seq);
		dequeue = true;
	} else {
		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert->k.p, b->key.k.p) > 0)
			bch_cut_back(b->key.k.p, &insert->k);

		do_insert = bch_insert_fixup_extent(iter, b, insert,
						    node_iter, replace, &done,
						    res, journal_seq, flags);
		bch_cut_front(done, orig);
		dequeue = (orig->k.size == 0);

		bch_btree_iter_set_pos(iter, done);
	}

	if (dequeue)
		bch_keylist_dequeue(insert_keys);

	newsize = bch_count_data(&b->keys);
	BUG_ON(newsize != -1 && newsize < oldsize);

	trace_bcache_btree_insert_key(b, insert, replace != NULL, do_insert);

	return do_insert;
}

enum btree_insert_status {
	BTREE_INSERT_OK,
	BTREE_INSERT_NEED_SPLIT,
	BTREE_INSERT_ERROR,
};

static bool have_enough_space(struct btree *b, struct keylist *insert_keys)
{
	/*
	 * For updates to interior nodes, everything on the
	 * keylist has to be inserted atomically.
	 *
	 * For updates to extents, bch_insert_fixup_extent()
	 * needs room for at least three keys to make forward
	 * progress.
	 */
	unsigned u64s = b->level
		? bch_keylist_nkeys(insert_keys)
		: b->keys.ops->is_extents
		? BKEY_EXTENT_MAX_U64s * 3
		: bch_keylist_front(insert_keys)->k.u64s;

	return u64s <= bch_btree_keys_u64s_remaining(b);
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_i *k;

	for (k = l->bot;
	     k < l->top && bkey_next(k) < l->top;
	     k = bkey_next(k))
		BUG_ON(bkey_cmp(k->k.p, bkey_next(k)->k.p) > 0);
#endif
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
bch_btree_insert_keys(struct btree *b,
		      struct btree_iter *iter,
		      struct keylist *insert_keys,
		      struct bch_replace_info *replace,
		      u64 *journal_seq, unsigned flags)
{
	bool done = false, inserted = false, need_split = false;
	struct journal_res res = { 0, 0 };
	struct bkey_i *k = bch_keylist_front(insert_keys);

	verify_keys_sorted(insert_keys);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(iter->nodes[b->level] != b);

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

		if (!b->level &&
		    test_bit(JOURNAL_REPLAY_DONE, &iter->c->journal.flags)) {
			if (bch_journal_res_get(&iter->c->journal, &res,
						actual_min, actual_max))
				return BTREE_INSERT_ERROR;
		}

		/* just wrote a set? */
		if (btree_node_need_init_next(b))
do_init_next:		bch_btree_init_next(iter->c, b, iter);

		btree_node_lock_write(b, iter);

		/*
		 * Recheck after taking the write lock, because it can be set
		 * (because of the btree node being written) with only a read
		 * lock:
		 */
		if (btree_node_need_init_next(b)) {
			btree_node_unlock_write(b, iter);
			goto do_init_next;
		}

		while (!bch_keylist_empty(insert_keys)) {
			k = bch_keylist_front(insert_keys);

			BUG_ON(!b->level &&
			       bkey_cmp(bkey_start_pos(&k->k), iter->pos) < 0);

			/* finished for this node */
			if (b->keys.ops->is_extents
			    ? bkey_cmp(bkey_start_pos(&k->k), b->key.k.p) >= 0
			    : bkey_cmp(k->k.p, b->key.k.p) > 0) {
				done = true;
				break;
			}

			if (!have_enough_space(b, insert_keys)) {
				done = true;
				need_split = true;
				break;
			}

			if (!b->level && journal_res_full(&res, &k->k))
				break;

			if (btree_insert_key(iter, b,
					     &iter->node_iters[b->level],
					     insert_keys, replace,
					     &res, journal_seq, flags))
				inserted = true;
		}

		btree_node_unlock_write(b, iter);

		if (res.ref)
			bch_journal_res_put(&iter->c->journal, &res);
	}

	if (inserted && b->written) {
		/*
		 * Force write if set is too big (or if it's an interior
		 * node, since those aren't journalled yet)
		 */
		if (b->level)
			bch_btree_node_write_sync(b, iter);
		else {
			struct btree_node_entry *bne =
				container_of(btree_bset_last(b),
					     struct btree_node_entry, keys);
			unsigned long bytes = __set_bytes(bne, bne->keys.u64s);

			if ((max(round_up(bytes, block_bytes(iter->c)),
				 PAGE_SIZE) - bytes < 48 ||
			     bytes > 16 << 10) &&
			    b->io_mutex.count > 0)
				bch_btree_node_write(b, NULL, iter);
		}
	}

	BUG_ON(!bch_keylist_empty(insert_keys) && inserted && b->level);

	return need_split ? BTREE_INSERT_NEED_SPLIT : BTREE_INSERT_OK;
}

struct btree_split_state {
	struct closure		stack_cl;
	struct keylist		parent_keys;
	/*
	 * Enough room for btree_split's keys without realloc - btree node
	 * pointers never have crc/compression info, so we only need to acount
	 * for the pointers for three keys
	 */
	u64			inline_keys[BKEY_BTREE_PTR_U64s_MAX * 3];
	struct btree_reserve	*reserve;
};

static int __bch_btree_insert_node(struct btree *, struct btree_iter *,
				   struct keylist *, struct bch_replace_info *,
				   u64 *, unsigned, struct btree_split_state *);

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
	n2->keys.set->size = 0;

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

	btree_node_lock_write(b, iter);

	while (!bch_keylist_empty(keys)) {
		k = bch_keylist_front(keys);

		BUG_ON(!have_enough_space(b, keys));
		BUG_ON(bkey_cmp(k->k.p, b->data->min_key) < 0);

		if (bkey_cmp(k->k.p, b->key.k.p) > 0) {
			BUG_ON(is_last);
			break;
		}

		btree_insert_key(iter, b, &node_iter, keys,
				 NULL, &res, NULL, 0);
	}

	btree_node_unlock_write(b, iter);
}

static int btree_split(struct btree *b, struct btree_iter *iter,
		       struct keylist *insert_keys, unsigned flags,
		       struct btree_split_state *state)
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

	bch_btree_node_flush_journal_entries(c, b, &state->stack_cl);

	n1 = btree_node_alloc_replacement(c, b, state->reserve);

	if (__set_blocks(n1->data,
			 n1->data->keys.u64s + u64s_to_insert,
			 block_bytes(n1->c)) > btree_blocks(c) * 3 / 4) {
		trace_bcache_btree_node_split(b, btree_bset_first(n1)->u64s);

		n2 = __btree_split_node(iter, n1, state->reserve);
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

		bch_btree_node_write(n2, &state->stack_cl, NULL);

		/*
		 * Just created a new node - if gc is still going to visit the
		 * old node, but not the node we just created, mark it:
		 */
		btree_node_lock_write(b, iter);
		if (gc_will_visit_node(c, n2) &&
		    !gc_will_visit_node(c, n1))
			btree_gc_mark_node(c, n1);
		btree_node_unlock_write(b, iter);

		/*
		 * Note that on recursive parent_keys == insert_keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (which we did with btree_split_insert_keys() above)
		 */
		bch_keylist_add(&state->parent_keys, &n1->key);
		bch_keylist_add(&state->parent_keys, &n2->key);

		if (!parent) {
			/* Depth increases, make a new root */
			n3 = __btree_root_alloc(c, b->level + 1,
						iter->btree_id,
						state->reserve);

			btree_split_insert_keys(iter, n3, &state->parent_keys, true);
			bch_btree_node_write(n3, &state->stack_cl, NULL);
		}
	} else {
		trace_bcache_btree_node_compact(b, btree_bset_first(n1)->u64s);
		six_unlock_write(&n1->lock);

		if (b->level)
			btree_split_insert_keys(iter, n1, insert_keys, true);

		bch_keylist_add(&state->parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, &state->stack_cl, NULL);

	/* Wait on journal flush and btree node writes: */
	closure_sync(&state->stack_cl);

	/* Check for journal error after waiting on the journal flush: */
	if (bch_journal_error(&c->journal) ||
	    (n3 && btree_node_write_error(n3)) ||
	    (n2 && btree_node_write_error(n2)) ||
	    btree_node_write_error(n1))
		goto err;

	/* New nodes all written, now make them visible: */

	if (n3) {
		ret = bch_btree_set_root(iter, n3);
		if (ret)
			goto err;
	} else if (!parent) {
		/* Root filled up but didn't need to be split */
		ret = bch_btree_set_root(iter, n1);
		if (ret)
			goto err;

		/* Drop key we ended up not using: */
		bch_keylist_init(&state->parent_keys,
				 state->inline_keys,
				 ARRAY_SIZE(state->inline_keys));
	} else {
		/* Split a non root node */
		ret = __bch_btree_insert_node(parent, iter, &state->parent_keys,
					      NULL, NULL, BTREE_INSERT_NOFAIL,
					      state);
		if (ret)
			goto err;
	}

	BUG_ON(!bch_keylist_empty(&state->parent_keys));

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

static int __bch_btree_insert_node(struct btree *b,
				   struct btree_iter *iter,
				   struct keylist *insert_keys,
				   struct bch_replace_info *replace,
				   u64 *journal_seq, unsigned flags,
				   struct btree_split_state *state)
{
	int ret;

	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(b->level &&
	       !btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(b->level && replace);
	BUG_ON(b->level && !state->reserve);
	BUG_ON(!b->written);

	switch (bch_btree_insert_keys(b, iter, insert_keys, replace,
				      journal_seq, flags)) {
	case BTREE_INSERT_OK:
		return 0;

	case BTREE_INSERT_NEED_SPLIT:
		if (!b->level) {
			struct btree_reserve *res;

			BUG_ON(state->reserve);

			/*
			 * XXX: figure out how far we might need to split,
			 * instead of locking/reserving all the way to the root:
			 */

			iter->locks_want = BTREE_MAX_DEPTH;
			if (!bch_btree_iter_upgrade(iter))
				return -EINTR;

			res = bch_btree_reserve_get(iter->c, b, iter, 0,
						!(flags & BTREE_INSERT_NOFAIL));
			if (IS_ERR(res))
				return PTR_ERR(res);

			state->reserve = res;
		}

		ret = btree_split(b, iter, insert_keys, flags, state);

		if (!b->level) {
			bch_btree_reserve_put(iter->c, state->reserve);
			state->reserve = NULL;
		}

		return ret;

	case BTREE_INSERT_ERROR:
		/* Journal error, so we couldn't get a journal reservation: */
		return -EIO;
	default:
		BUG();
	}
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
inline
int bch_btree_insert_node(struct btree *b,
			  struct btree_iter *iter,
			  struct keylist *insert_keys,
			  struct bch_replace_info *replace,
			  u64 *journal_seq, unsigned flags,
			  struct btree_reserve *reserve)
{
	struct btree_split_state state;

	closure_init_stack(&state.stack_cl);
	bch_keylist_init(&state.parent_keys,
			 state.inline_keys,
			 ARRAY_SIZE(state.inline_keys));
	state.reserve = reserve;

	if (replace)
		flags |= FAIL_IF_STALE;

	return __bch_btree_insert_node(b, iter, insert_keys, replace,
				       journal_seq, flags, &state);
}

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
					    replace, journal_seq, flags, NULL);

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

		bch_btree_iter_set_pos(iter,
			bkey_start_pos(&bch_keylist_front(insert_keys)->k));

		ret = bch_btree_iter_traverse(iter);
		if (ret)
			break;
	}
	percpu_ref_put(&iter->c->writes);

	return ret;
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
	struct closure cl;
	int ret;

	closure_init_stack(&cl);

	iter->locks_want = BTREE_MAX_DEPTH;
	if (!bch_btree_iter_upgrade(iter))
		return -EINTR;

	reserve = bch_btree_reserve_get(c, b, wait ? iter : NULL, 1, true);
	if (IS_ERR(reserve)) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return PTR_ERR(reserve);
	}

	bch_btree_node_flush_journal_entries(c, b, &cl);

	n = btree_node_alloc_replacement(c, b, reserve);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write(n, &cl, NULL);
	closure_sync(&cl);

	if (bch_journal_error(&c->journal) ||
	    btree_node_write_error(n)) {
		bch_btree_node_free_never_inserted(c, n);
		six_unlock_intent(&n->lock);
		return -EIO;
	}

	if (parent) {
		ret = bch_btree_insert_node(parent, iter,
					    &keylist_single(&n->key),
					    NULL, NULL,
					    BTREE_INSERT_NOFAIL,
					    reserve);
		BUG_ON(ret);
	} else {
		bch_btree_set_root(iter, n);
	}

	btree_open_bucket_put(iter->c, n);

	bch_btree_node_free(iter, b);
	bch_btree_iter_node_drop(iter, b);

	BUG_ON(!bch_btree_iter_node_replace(iter, n));

	bch_btree_reserve_put(c, reserve);
	return 0;
}
