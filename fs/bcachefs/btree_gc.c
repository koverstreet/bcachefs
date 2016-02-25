/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "bkey_methods.h"
#include "btree_locking.h"
#include "btree_update.h"
#include "btree_io.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <trace/events/bcachefs.h>

struct range_checks {
	struct range_level {
		struct bpos	min;
		struct bpos	max;
	}			l[BTREE_MAX_DEPTH];
};

static void btree_node_range_checks_init(struct range_checks *r)
{
	unsigned i;

	for (i = 0; i < BTREE_MAX_DEPTH; i++)
		r->l[i].min = r->l[i].max = POS_MIN;
}

static void btree_node_range_checks(struct cache_set *c, struct btree *b,
				    struct range_checks *r)
{
	struct range_level *l = &r->l[b->level];

	struct bpos expected_min = bkey_cmp(l->min, l->max)
		? btree_type_successor(b->btree_id, l->max)
		: l->max;

	cache_set_inconsistent_on(bkey_cmp(b->data->min_key,
					   expected_min), c,
		"btree node has incorrect min key: %llu:%llu != %llu:%llu",
		b->data->min_key.inode,
		b->data->min_key.offset,
		expected_min.inode,
		expected_min.offset);

	l->max = b->data->max_key;

	if (b->level) {
		l = &r->l[b->level - 1];

		cache_set_inconsistent_on(bkey_cmp(b->data->min_key,
						   l->min), c,
			"btree node min doesn't match min of child nodes: %llu:%llu != %llu:%llu",
			b->data->min_key.inode,
			b->data->min_key.offset,
			l->min.inode,
			l->min.offset);

		cache_set_inconsistent_on(bkey_cmp(b->data->max_key,
						   l->max), c,
			"btree node max doesn't match max of child nodes: %llu:%llu != %llu:%llu",
			b->data->max_key.inode,
			b->data->max_key.offset,
			l->max.inode,
			l->max.offset);

		if (bkey_cmp(b->data->max_key, POS_MAX))
			l->min = l->max =
				btree_type_successor(b->btree_id,
						     b->data->max_key);
	}
}

u8 bch_btree_key_recalc_oldest_gen(struct cache_set *c, struct bkey_s_c k)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;
	u8 max_stale = 0;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

		rcu_read_lock();

		extent_for_each_ptr(e, ptr)
			if (ptr->dev < MAX_CACHES_PER_SET)
				__set_bit(ptr->dev, c->cache_slots_used);

		extent_for_each_online_device(c, e, ptr, ca) {
			struct bucket *g = PTR_BUCKET(ca, ptr);

			if (__gen_after(g->oldest_gen, ptr->gen))
				g->oldest_gen = ptr->gen;

			max_stale = max(max_stale, ptr_stale(ca, ptr));
		}

		rcu_read_unlock();
	}

	return max_stale;
}

/*
 * For runtime mark and sweep:
 */
static u8 __bch_btree_mark_key(struct cache_set *c, enum bkey_type type,
			       struct bkey_s_c k)
{
	switch (type) {
	case BKEY_TYPE_BTREE:
	case BKEY_TYPE_EXTENTS:
		if (bkey_extent_is_data(k.k)) {
			struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

			bch_mark_pointers(c, e,
					  type == BKEY_TYPE_BTREE
					  ? c->sb.btree_node_size
					  : e.k->size, false,
					  type == BKEY_TYPE_BTREE,
					  true, GC_POS_MIN);
		}

		return bch_btree_key_recalc_oldest_gen(c, k);
	default:
		BUG();
	}
}

static u8 btree_mark_key(struct cache_set *c, struct btree *b,
			 struct bkey_s_c k)
{
	return __bch_btree_mark_key(c, btree_node_type(b), k);
}

/*
 * For initial cache set bringup:
 */
u8 __bch_btree_mark_key_initial(struct cache_set *c, enum bkey_type type,
				struct bkey_s_c k)
{

	switch (type) {
	case BKEY_TYPE_BTREE:
	case BKEY_TYPE_EXTENTS:
		if (k.k->type == BCH_RESERVATION)
			atomic64_add(k.k->size, &c->sectors_reserved);

		return __bch_btree_mark_key(c, type, k);
	default:
		BUG();
	}

}

static u8 btree_mark_key_initial(struct cache_set *c, struct btree *b,
				 struct bkey_s_c k)
{
	return __bch_btree_mark_key_initial(c, btree_node_type(b), k);
}

static bool btree_gc_mark_node(struct cache_set *c, struct btree *b)
{
	if (btree_node_has_ptrs(b)) {
		struct btree_node_iter iter;
		struct bkey unpacked;
		struct bkey_s_c k;
		u8 stale = 0;

		for_each_btree_node_key_unpack(&b->keys, k, &iter, &unpacked) {
			bkey_debugcheck(c, b, k);

			stale = max(stale, btree_mark_key(c, b, k));
		}

		if (btree_gc_rewrite_disabled(c))
			return false;

		if (stale > 10)
			return true;
	}

	if (btree_gc_always_rewrite(c))
		return true;

	return false;
}

static inline void __gc_pos_set(struct cache_set *c, struct gc_pos new_pos)
{
	write_seqcount_begin(&c->gc_pos_lock);
	c->gc_pos = new_pos;
	write_seqcount_end(&c->gc_pos_lock);
}

static inline void gc_pos_set(struct cache_set *c, struct gc_pos new_pos)
{
	BUG_ON(gc_pos_cmp(new_pos, c->gc_pos) <= 0);
	__gc_pos_set(c, new_pos);
}

static int bch_gc_btree(struct cache_set *c, enum btree_id btree_id)
{
	struct btree_iter iter;
	struct btree *b;
	bool should_rewrite;
	struct range_checks r;

	btree_node_range_checks_init(&r);

	for_each_btree_node(&iter, c, btree_id, POS_MIN, b) {
		btree_node_range_checks(c, b, &r);

		bch_verify_btree_nr_keys(&b->keys);

		should_rewrite = btree_gc_mark_node(c, b);

		gc_pos_set(c, gc_pos_btree_node(b));

		if (should_rewrite)
			bch_btree_node_rewrite(b, &iter, false);

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);

	spin_lock(&c->btree_root_lock);

	b = c->btree_roots[btree_id];
	__bch_btree_mark_key(c, BKEY_TYPE_BTREE, bkey_i_to_s_c(&b->key));
	gc_pos_set(c, gc_pos_btree_root(b->btree_id));

	spin_unlock(&c->btree_root_lock);
	return 0;
}

static void bch_mark_allocator_buckets(struct cache_set *c)
{
	struct cache *ca;
	struct open_bucket *ob;
	size_t i, j, iter;
	unsigned ci;

	for_each_cache(ca, c, ci) {
		spin_lock(&ca->freelist_lock);

		fifo_for_each_entry(i, &ca->free_inc, iter)
			bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each_entry(i, &ca->free[j], iter)
				bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		spin_unlock(&ca->freelist_lock);
	}

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++) {
		const struct bch_extent_ptr *ptr;

		mutex_lock(&ob->lock);
		rcu_read_lock();
		open_bucket_for_each_online_device(c, ob, ptr, ca)
			bch_mark_alloc_bucket(ca, PTR_BUCKET(ca, ptr));
		rcu_read_unlock();
		mutex_unlock(&ob->lock);
	}
}

/*
 * Mark non btree metadata - prios, journal
 */
static void bch_mark_metadata(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	for_each_cache(ca, c, i) {
		unsigned j;
		u64 *i;

		for (j = 0; j < bch_nr_journal_buckets(ca->disk_sb.sb); j++)
			bch_mark_metadata_bucket(ca,
					&ca->buckets[journal_bucket(ca, j)],
						 true);

		spin_lock(&ca->prio_buckets_lock);

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			bch_mark_metadata_bucket(ca, &ca->buckets[*i], true);

		spin_unlock(&ca->prio_buckets_lock);
	}
}

static void bch_mark_pending_btree_node_frees(struct cache_set *c)
{
	struct pending_btree_node_free *d;

	mutex_lock(&c->btree_node_pending_free_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_PENDING_DELETE));

	list_for_each_entry(d, &c->btree_node_pending_free, list)
		if (d->index_update_done)
			bch_mark_pointers(c, bkey_i_to_s_c_extent(&d->key),
					  c->sb.btree_node_size,
					  false, true,
					  true, GC_POS_MIN);
	mutex_unlock(&c->btree_node_pending_free_lock);
}

static void bch_mark_scan_keylists(struct cache_set *c)
{
	struct scan_keylist *kl;

	mutex_lock(&c->gc_scan_keylist_lock);

	/* What the goddamn fuck? */
	list_for_each_entry(kl, &c->gc_scan_keylists, mark_list) {
		if (kl->owner == NULL)
			bch_keylist_recalc_oldest_gens(c, kl);
		else
			bch_queue_recalc_oldest_gens(c, kl->owner);
	}

	mutex_unlock(&c->gc_scan_keylist_lock);
}

/**
 * bch_gc - recompute bucket marks and oldest_gen, rewrite btree nodes
 */
void bch_gc(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *g;
	u64 start_time = local_clock();
	unsigned i;

	/*
	 * Walk _all_ references to buckets, and recompute them:
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

	memset(c->cache_slots_used, 0, sizeof(c->cache_slots_used));

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		return;

	trace_bcache_gc_start(c);
	down_write(&c->gc_lock);

	/* Save a copy of the existing bucket stats while we recompute them: */
	for_each_cache(ca, c, i)
		ca->bucket_stats_cached = __bucket_stats_read(ca);

	/* Indicates to buckets code that gc is now in progress: */
	__gc_pos_set(c, GC_POS_MIN);

	/* Clear bucket marks: */
	for_each_cache(ca, c, i)
		for_each_bucket(g, ca) {
			g->oldest_gen = ca->bucket_gens[g - ca->buckets];
			bch_mark_free_bucket(ca, g);
		}

	/* Walk allocator's references: */
	bch_mark_allocator_buckets(c);

	/* Walk btree: */
	while (c->gc_pos.phase < (int) BTREE_ID_NR) {
		int ret = c->btree_roots[c->gc_pos.phase]
			? bch_gc_btree(c, (int) c->gc_pos.phase)
			: 0;

		if (ret) {
			pr_err("btree gc failed with %d!", ret);
			set_bit(CACHE_SET_GC_FAILURE, &c->flags);
			up_write(&c->gc_lock);
			return;
		}

		gc_pos_set(c, gc_phase(c->gc_pos.phase + 1));
	}

	bch_mark_metadata(c);
	bch_mark_pending_btree_node_frees(c);
	bch_writeback_recalc_oldest_gens(c);
	bch_mark_scan_keylists(c);

	for_each_cache(ca, c, i)
		atomic_long_set(&ca->saturated_count, 0);

	/* Indicates that gc is no longer in progress: */
	gc_pos_set(c, gc_phase(GC_PHASE_DONE));

	up_write(&c->gc_lock);
	trace_bcache_gc_end(c);
	bch_time_stats_update(&c->btree_gc_time, start_time);
}

/* Btree coalescing */

static void recalc_packed_keys(struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey_packed *k;

	memset(&b->keys.nr, 0, sizeof(b->keys.nr));

	for_each_btree_node_key(&b->keys, k, &iter)
		btree_keys_account_key_add(&b->keys.nr, k);
}

static void bch_coalesce_nodes(struct btree *old_nodes[GC_MERGE_NODES],
			       struct btree_iter *iter)
{
	struct btree *parent = iter->nodes[old_nodes[0]->level + 1];
	struct cache_set *c = iter->c;
	unsigned i, nr_old_nodes, nr_new_nodes, u64s = 0;
	unsigned blocks = btree_blocks(c) * 2 / 3;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct async_split *as;
	struct btree_reserve *res;
	struct keylist keylist;
	struct bkey_format_state format_state;
	struct bkey_format new_format;
	int ret;

	memset(new_nodes, 0, sizeof(new_nodes));
	bch_keylist_init(&keylist, NULL, 0);

	/* Count keys that are not deleted */
	for (i = 0; i < GC_MERGE_NODES && old_nodes[i]; i++)
		u64s += old_nodes[i]->keys.nr.live_u64s;

	nr_old_nodes = nr_new_nodes = i;

	/* Check if all keys in @old_nodes could fit in one fewer node */
	if (nr_old_nodes <= 1 ||
	    __set_blocks(old_nodes[0]->data,
			 DIV_ROUND_UP(u64s, nr_old_nodes - 1),
			 block_bytes(c)) > blocks)
		return;

	res = bch_btree_reserve_get(c, parent, NULL, nr_old_nodes, false);
	if (IS_ERR(res))
		return;

	if (bch_keylist_realloc(&keylist,
			(BKEY_U64s + BKEY_EXTENT_U64s_MAX) * nr_old_nodes)) {
		trace_bcache_btree_gc_coalesce_fail(c);
		goto out;
	}

	trace_bcache_btree_gc_coalesce(parent, nr_old_nodes);

	/* Find a format that all keys in @old_nodes can pack into */
	bch_bkey_format_init(&format_state);

	for (i = 0; i < nr_old_nodes; i++)
		__bch_btree_calc_format(&format_state, old_nodes[i]);

	new_format = bch_bkey_format_done(&format_state);

	/* Check if repacking would make any nodes too big to fit */
	for (i = 0; i < nr_old_nodes; i++)
		if (!bch_btree_node_format_fits(old_nodes[i], &new_format)) {
			trace_bcache_btree_gc_coalesce_fail(c);
			goto out;
		}

	as = __bch_async_split_alloc(old_nodes, nr_old_nodes, iter);
	if (!as) {
		trace_bcache_btree_gc_coalesce_fail(c);
		goto out;
	}

	/* Repack everything with @new_format and sort down to one bset */
	for (i = 0; i < nr_old_nodes; i++)
		new_nodes[i] = __btree_node_alloc_replacement(c, old_nodes[i],
							      new_format, res);

	/*
	 * Conceptually we concatenate the nodes together and slice them
	 * up at different boundaries.
	 */
	for (i = nr_new_nodes - 1; i > 0; --i) {
		struct btree *n1 = new_nodes[i];
		struct btree *n2 = new_nodes[i - 1];

		struct bset *s1 = btree_bset_first(n1);
		struct bset *s2 = btree_bset_first(n2);
		struct bkey_packed *k, *last = NULL;

		/* Calculate how many keys from @n2 we could fit inside @n1 */
		u64s = 0;

		for (k = s2->start;
		     k < bset_bkey_last(s2) &&
		     __set_blocks(n1->data, le16_to_cpu(s1->u64s) + u64s + k->u64s,
				  block_bytes(c)) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			u64s += k->u64s;
		}

		if (u64s == le16_to_cpu(s2->u64s)) {
			/* n2 fits entirely in n1 */
			n1->key.k.p = n1->data->max_key = n2->data->max_key;

			memcpy(bset_bkey_last(s1),
			       s2->start,
			       le16_to_cpu(s2->u64s) * sizeof(u64));
			le16_add_cpu(&s1->u64s, le16_to_cpu(s2->u64s));

			six_unlock_write(&n2->lock);
			bch_btree_node_free_never_inserted(c, n2);
			six_unlock_intent(&n2->lock);

			memmove(new_nodes + i - 1,
				new_nodes + i,
				sizeof(new_nodes[0]) * (nr_new_nodes - i));
			new_nodes[--nr_new_nodes] = NULL;
		} else if (u64s) {
			/* move part of n2 into n1 */
			n1->key.k.p = n1->data->max_key =
				bkey_unpack_key(&n1->keys.format, last).p;

			n2->data->min_key =
				btree_type_successor(iter->btree_id,
						     n1->data->max_key);

			memcpy(bset_bkey_last(s1),
			       s2->start,
			       u64s * sizeof(u64));
			le16_add_cpu(&s1->u64s, u64s);

			memmove(s2->start,
				bset_bkey_idx(s2, u64s),
				(le16_to_cpu(s2->u64s) - u64s) * sizeof(u64));
			s2->u64s = cpu_to_le16(le16_to_cpu(s2->u64s) - u64s);
		}
	}

	for (i = 0; i < nr_new_nodes; i++) {
		struct btree *n = new_nodes[i];

		recalc_packed_keys(n);
		six_unlock_write(&n->lock);
		bch_btree_node_write(n, &as->cl, NULL);
	}

	/*
	 * The keys for the old nodes get deleted. We don't want to insert keys
	 * that compare equal to the keys for the new nodes we'll also be
	 * inserting - we can't because keys on a keylist must be strictly
	 * greater than the previous keys, and we also don't need to since the
	 * key for the new node will serve the same purpose (overwriting the key
	 * for the old node).
	 */
	for (i = 0; i < nr_old_nodes; i++) {
		struct bkey_i delete;
		unsigned j;

		bch_pending_btree_node_free_init(c, as, old_nodes[i]);

		for (j = 0; j < nr_new_nodes; j++)
			if (!bkey_cmp(old_nodes[i]->key.k.p,
				      new_nodes[j]->key.k.p))
				goto next;

		bkey_init(&delete.k);
		delete.k.p = old_nodes[i]->key.k.p;
		bch_keylist_add_in_order(&keylist, &delete);
next:
		i = i;
	}

	/*
	 * Keys for the new nodes get inserted: bch_btree_insert_keys() only
	 * does the lookup once and thus expects the keys to be in sorted order
	 * so we have to make sure the new keys are correctly ordered with
	 * respect to the deleted keys added in the previous loop
	 */
	for (i = 0; i < nr_new_nodes; i++)
		bch_keylist_add_in_order(&keylist, &new_nodes[i]->key);

	/* Insert the newly coalesced nodes */
	ret = bch_btree_insert_node(parent, iter, &keylist, res, as);
	if (ret)
		goto err;

	BUG_ON(!bch_keylist_empty(&keylist));

	BUG_ON(iter->nodes[old_nodes[0]->level] != old_nodes[0]);

	BUG_ON(!bch_btree_iter_node_replace(iter, new_nodes[0]));

	for (i = 0; i < nr_new_nodes; i++)
		btree_open_bucket_put(c, new_nodes[i]);

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < nr_old_nodes; i++) {
		bch_btree_node_free(iter, old_nodes[i]);
		six_unlock_intent(&old_nodes[i]->lock);

		/*
		 * the index update might have triggered a split, in which case
		 * the nodes we coalesced - the new nodes we just created -
		 * might not be sibling nodes anymore - don't add them to the
		 * sliding window (except the first):
		 */
		if (!i) {
			old_nodes[i] = new_nodes[i];
		} else {
			old_nodes[i] = NULL;
			if (new_nodes[i])
				six_unlock_intent(&new_nodes[i]->lock);
		}
	}
out:
	bch_keylist_free(&keylist);
	bch_btree_reserve_put(c, res);
	return;
err:
	for (i = 0; i < nr_new_nodes; i++) {
		bch_btree_node_free_never_inserted(c, new_nodes[i]);
		six_unlock_intent(&new_nodes[i]->lock);
	}
	goto out;
}

static int bch_coalesce_btree(struct cache_set *c, enum btree_id btree_id)
{
	struct btree_iter iter;
	struct btree *b;
	unsigned i;

	/* Sliding window of adjacent btree nodes */
	struct btree *merge[GC_MERGE_NODES];
	u32 lock_seq[GC_MERGE_NODES];

	/*
	 * XXX: We don't have a good way of positively matching on sibling nodes
	 * that have the same parent - this code works by handling the cases
	 * where they might not have the same parent, and is thus fragile. Ugh.
	 *
	 * Perhaps redo this to use multiple linked iterators?
	 */
	memset(merge, 0, sizeof(merge));

	bch_btree_iter_init(&iter, c, btree_id, POS_MIN);
	iter.is_extents = false;
	iter.locks_want = BTREE_MAX_DEPTH;

	for (b = bch_btree_iter_peek_node(&iter);
	     b;
	     b = bch_btree_iter_next_node(&iter)) {
		memmove(merge + 1, merge,
			sizeof(merge) - sizeof(merge[0]));
		memmove(lock_seq + 1, lock_seq,
			sizeof(lock_seq) - sizeof(lock_seq[0]));

		merge[0] = b;

		for (i = 1; i < GC_MERGE_NODES; i++) {
			if (!merge[i] ||
			    !six_relock_intent(&merge[i]->lock, lock_seq[i]))
				break;

			if (merge[i]->level != merge[0]->level) {
				six_unlock_intent(&merge[i]->lock);
				break;
			}
		}
		memset(merge + i, 0, (GC_MERGE_NODES - i) * sizeof(merge[0]));

		bch_coalesce_nodes(merge, &iter);

		for (i = 1; i < GC_MERGE_NODES && merge[i]; i++) {
			lock_seq[i] = merge[i]->lock.state.seq;
			six_unlock_intent(&merge[i]->lock);
		}

		lock_seq[0] = merge[0]->lock.state.seq;

		if (test_bit(CACHE_SET_GC_STOPPING, &c->flags)) {
			bch_btree_iter_unlock(&iter);
			return -ESHUTDOWN;
		}

		bch_btree_iter_cond_resched(&iter);

		/*
		 * If the parent node wasn't relocked, it might have been split
		 * and the nodes in our sliding window might not have the same
		 * parent anymore - blow away the sliding window:
		 */
		if (iter.nodes[iter.level + 1] &&
		    !btree_node_intent_locked(&iter, iter.level + 1))
			memset(merge + 1, 0,
			       (GC_MERGE_NODES - 1) * sizeof(merge[0]));
	}
	return bch_btree_iter_unlock(&iter);
}

/**
 * bch_coalesce - coalesce adjacent nodes with low occupancy
 */
static void bch_coalesce(struct cache_set *c)
{
	u64 start_time = local_clock();
	enum btree_id id;

	if (btree_gc_coalesce_disabled(c))
		return;

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		return;

	trace_bcache_gc_coalesce_start(c);

	for (id = 0; id < BTREE_ID_NR; id++) {
		int ret = c->btree_roots[id]
			? bch_coalesce_btree(c, id)
			: 0;

		if (ret) {
			if (ret != -ESHUTDOWN)
				pr_err("btree coalescing failed with %d!", ret);
			set_bit(CACHE_SET_GC_FAILURE, &c->flags);
			return;
		}
	}

	bch_time_stats_update(&c->btree_coalesce_time, start_time);

	debug_check_no_locks_held();

	trace_bcache_gc_coalesce_end(c);
}

static int bch_gc_thread(void *arg)
{
	struct cache_set *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last = atomic_long_read(&clock->now);
	unsigned last_kick = atomic_read(&c->kick_gc);
	struct cache *ca;
	unsigned i;

	while (1) {
		unsigned long next = last + c->capacity / 16;

		while (atomic_long_read(&clock->now) < next) {
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop()) {
				__set_current_state(TASK_RUNNING);
				return 0;
			}

			if (atomic_read(&c->kick_gc) != last_kick) {
				__set_current_state(TASK_RUNNING);
				break;
			}

			bch_io_clock_schedule_timeout(clock, next);
			try_to_freeze();
		}

		last = atomic_long_read(&clock->now);
		last_kick = atomic_read(&c->kick_gc);
		bch_gc(c);

		/*
		 * Wake up allocator in case it was waiting for buckets
		 * because of not being able to inc gens
		 */
		for_each_cache(ca, c, i)
			bch_wake_allocator(ca);

		bch_coalesce(c);

		debug_check_no_locks_held();
	}

	return 0;
}

void bch_gc_thread_stop(struct cache_set *c)
{
	set_bit(CACHE_SET_GC_STOPPING, &c->flags);

	if (!IS_ERR_OR_NULL(c->gc_thread))
		kthread_stop(c->gc_thread);
}

int bch_gc_thread_start(struct cache_set *c)
{
	clear_bit(CACHE_SET_GC_STOPPING, &c->flags);

	c->gc_thread = kthread_create(bch_gc_thread, c, "bcache_gc");
	if (IS_ERR(c->gc_thread))
		return PTR_ERR(c->gc_thread);

	wake_up_process(c->gc_thread);
	return 0;
}

/* Initial GC computes bucket marks during startup */

static void bch_initial_gc_btree(struct cache_set *c, enum btree_id id)
{
	struct btree_iter iter;
	struct btree *b;
	struct range_checks r;

	btree_node_range_checks_init(&r);

	if (!c->btree_roots[id])
		return;

	for_each_btree_node(&iter, c, id, POS_MIN, b) {
		btree_node_range_checks(c, b, &r);

		if (btree_node_has_ptrs(b)) {
			struct btree_node_iter node_iter;
			struct bkey unpacked;
			struct bkey_s_c k;

			for_each_btree_node_key_unpack(&b->keys, k,
						       &node_iter, &unpacked)
				btree_mark_key_initial(c, b, k);
		}

		__bch_btree_mark_key_initial(c, BKEY_TYPE_BTREE,
					     bkey_i_to_s_c(&b->key));

		bch_btree_iter_cond_resched(&iter);
	}

	bch_btree_iter_unlock(&iter);
}

int bch_initial_gc(struct cache_set *c, struct list_head *journal)
{
	enum btree_id id;

	if (journal) {
		for (id = 0; id < BTREE_ID_NR; id++)
			bch_initial_gc_btree(c, id);

		bch_journal_mark(c, journal);
	}

	bch_mark_metadata(c);
	gc_pos_set(c, gc_phase(GC_PHASE_DONE));
	set_bit(CACHE_SET_INITIAL_GC_DONE, &c->flags);

	return 0;
}
