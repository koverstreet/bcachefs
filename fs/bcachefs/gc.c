/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "buckets.h"
#include "debug.h"
#include "extents.h"
#include "gc.h"
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

u8 bch_btree_key_recalc_oldest_gen(struct cache_set *c, const struct bkey *k)
{
	u8 max_stale = 0;
	struct cache *ca;
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		if (PTR_DEV(k, i) < MAX_CACHES_PER_SET)
			__set_bit(PTR_DEV(k, i), c->cache_slots_used);

		if ((ca = PTR_CACHE(c, k, i))) {
			struct bucket *g = PTR_BUCKET(c, ca, k, i);

			if (__gen_after(g->oldest_gen, PTR_GEN(k, i)))
				g->oldest_gen = PTR_GEN(k, i);

			max_stale = max(max_stale, ptr_stale(c, ca, k, i));
		}
	}

	return max_stale;
}

u8 __bch_btree_mark_key(struct cache_set *c, int level, const struct bkey *k)
{
	u8 max_stale;
	struct cache *ca;
	unsigned i;

	if (KEY_DELETED(k))
		return 0;

	rcu_read_lock();

	max_stale = bch_btree_key_recalc_oldest_gen(c, k);

	if (level) {
		for (i = 0; i < bch_extent_ptrs(k); i++)
			if ((ca = PTR_CACHE(c, k, i)))
				bch_mark_metadata_bucket(ca,
					PTR_BUCKET(c, ca, k, i), true);
	} else {
		__bch_add_sectors(c, NULL, k, KEY_START(k), KEY_SIZE(k), false);
	}

	rcu_read_unlock();

	return max_stale;
}

static u8 btree_mark_key(struct cache_set *c, struct btree *b,
			 const struct bkey *k)
{
	return __bch_btree_mark_key(c, b->level, k);
}

/* Only the extent btree has leafs whose keys point to data */
static inline bool btree_node_has_ptrs(struct btree *b)
{
	return b->btree_id == BTREE_ID_EXTENTS || b->level > 0;
}

bool btree_gc_mark_node(struct cache_set *c, struct btree *b,
			struct gc_stat *stat)
{
	struct bset_tree *t;

	for (t = b->keys.set; t <= &b->keys.set[b->keys.nsets]; t++)
		btree_bug_on(t->size &&
			     bset_written(&b->keys, t) &&
			     bkey_cmp(&b->key, &t->end) < 0,
			     b, "found short btree key in gc");

	if (stat)
		stat->nodes++;

	/* only actually needed for the root */
	__bch_btree_mark_key(c, b->level + 1, &b->key);

	if (btree_node_has_ptrs(b)) {
		u8 stale = 0;
		unsigned keys = 0, good_keys = 0, u64s;
		struct bkey *k;
		struct btree_node_iter iter;

		for_each_btree_node_key(&b->keys, k, &iter) {
			bkey_debugcheck(&b->keys, k);

			stale = max(stale, btree_mark_key(c, b, k));
			keys++;

			if (KEY_WIPED(k)) {
				good_keys++;
				if (stat)
					stat->nkeys++;
			} else {
				u64s = bch_extent_nr_ptrs_after_normalize(c, k);
				if (u64s) {
					good_keys++;
					if (stat) {
						stat->key_bytes += KEY_U64s(k);
						stat->nkeys++;
						stat->data += KEY_SIZE(k);
					}
				}
			}
		}

		if (c->gc_rewrite_disabled)
			return false;

		if (stale > 10)
			return true;

		if ((keys - good_keys) * 2 > keys)
			return true;
	}

	if (c->gc_always_rewrite)
		return true;

	return false;
}

static int bch_gc_btree(struct cache_set *c, enum btree_id btree_id,
			struct gc_stat *stat)
{
	struct btree_iter iter;
	struct btree *b;
	bool should_rewrite;

	bch_btree_iter_init(&iter, c, btree_id, NULL);
	iter.is_extents = false;
	iter.locks_want = BTREE_MAX_DEPTH;

	for (b = bch_btree_iter_peek_node(&iter);
	     b;
	     b = bch_btree_iter_next_node(&iter)) {
		verify_nr_live_keys(&b->keys);

		should_rewrite = btree_gc_mark_node(c, b, stat);

		BUG_ON(bkey_cmp(&c->gc_cur_key, &b->key) > 0);
		BUG_ON(!gc_will_visit_node(c, b));

		write_seqlock(&c->gc_cur_lock);
		c->gc_cur_level = b->level;
		bkey_copy_key(&c->gc_cur_key, &b->key);
		write_sequnlock(&c->gc_cur_lock);

		BUG_ON(gc_will_visit_node(c, b));

		if (should_rewrite)
			bch_btree_node_rewrite(b, &iter, false);

		if (test_bit(CACHE_SET_STOPPING, &c->flags)) {
			bch_btree_iter_unlock(&iter);
			return -ESHUTDOWN;
		}

		bch_btree_iter_cond_resched(&iter);
	}
	return bch_btree_iter_unlock(&iter);
}

static void bch_mark_allocator_buckets(struct cache_set *c)
{
	struct cache *ca;
	struct open_bucket *b;
	size_t i, j, iter;
	unsigned ci;

	for_each_cache(ca, c, ci) {
		spin_lock(&ca->freelist_lock);

		fifo_for_each(i, &ca->free_inc, iter)
			bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		spin_unlock(&ca->freelist_lock);
	}

	spin_lock(&c->open_buckets_lock);
	rcu_read_lock();

	list_for_each_entry(b, &c->open_buckets_open, list) {
		spin_lock(&b->lock);
		for (i = 0; i < bch_extent_ptrs(&b->key); i++)
			if ((ca = PTR_CACHE(c, &b->key, i)))
				bch_mark_alloc_bucket(ca,
					PTR_BUCKET(c, ca, &b->key, i));
		spin_unlock(&b->lock);
	}

	rcu_read_unlock();
	spin_unlock(&c->open_buckets_lock);
}

static void bch_gc_start(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *g;
	unsigned i;

	write_seqlock(&c->gc_cur_lock);
	for_each_cache(ca, c, i)
		ca->bucket_stats_cached = __bucket_stats_read(ca);

	c->gc_cur_btree = 0;
	c->gc_cur_level = 0;
	c->gc_cur_key = ZERO_KEY;
	write_sequnlock(&c->gc_cur_lock);

	memset(c->cache_slots_used, 0, sizeof(c->cache_slots_used));

	for_each_cache(ca, c, i)
		for_each_bucket(g, ca) {
			g->oldest_gen = ca->bucket_gens[g - ca->buckets];
			bch_mark_free_bucket(ca, g);
		}

	/*
	 * must happen before traversing the btree, as pointers move from open
	 * buckets into the btree - if we race and an open_bucket has been freed
	 * before we marked it, it's in the btree now
	 */
	bch_mark_allocator_buckets(c);
}

static void bch_gc_finish(struct cache_set *c)
{
	struct cache *ca;
	struct scan_keylist *kl;
	unsigned i;

	bch_writeback_recalc_oldest_gens(c);

	mutex_lock(&c->gc_scan_keylist_lock);

	list_for_each_entry(kl, &c->gc_scan_keylists, mark_list) {
		if (kl->owner == NULL)
			bch_keylist_recalc_oldest_gens(c, kl);
		else
			bch_queue_recalc_oldest_gens(c, kl->owner);
	}

	mutex_unlock(&c->gc_scan_keylist_lock);

	for_each_cache(ca, c, i) {
		unsigned j;
		u64 *i;

		for (j = 0; j < bch_nr_journal_buckets(&ca->sb); j++)
			bch_mark_metadata_bucket(ca,
					&ca->buckets[journal_bucket(ca, j)],
						 true);

		spin_lock(&ca->prio_buckets_lock);

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			bch_mark_metadata_bucket(ca, &ca->buckets[*i], true);

		spin_unlock(&ca->prio_buckets_lock);

		atomic_long_set(&ca->saturated_count, 0);
		ca->inc_gen_needs_gc = 0;
	}

	set_gc_sectors(c);

	write_seqlock(&c->gc_cur_lock);
	c->gc_cur_btree = BTREE_ID_NR + 1;
	write_sequnlock(&c->gc_cur_lock);

	/*
	 * Setting gc_cur_btree marks gc as finished, and the allocator threads
	 * will now see the new buckets_available - wake them up in case they
	 * were waiting on it
	 */

	for_each_cache(ca, c, i)
		bch_wake_allocator(ca);
}

/**
 * bch_gc - recompute bucket marks and oldest_gen, rewrite btree nodes
 */
void bch_gc(struct cache_set *c)
{
	struct gc_stat stats;
	u64 start_time = local_clock();

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		return;

	trace_bcache_gc_start(c);

	memset(&stats, 0, sizeof(struct gc_stat));

	down_write(&c->gc_lock);
	bch_gc_start(c);

	while (c->gc_cur_btree < BTREE_ID_NR) {
		int ret = c->btree_roots[c->gc_cur_btree]
			? bch_gc_btree(c, c->gc_cur_btree, &stats)
			: 0;

		if (ret) {
			if (ret != -ESHUTDOWN)
				pr_err("btree gc failed with %d!", ret);

			write_seqlock(&c->gc_cur_lock);
			c->gc_cur_btree = BTREE_ID_NR + 1;
			c->gc_cur_level = 0;
			c->gc_cur_key = ZERO_KEY;
			write_sequnlock(&c->gc_cur_lock);

			set_bit(CACHE_SET_GC_FAILURE, &c->flags);
			up_write(&c->gc_lock);
			return;
		}

		write_seqlock(&c->gc_cur_lock);
		c->gc_cur_btree++;
		c->gc_cur_level = 0;
		c->gc_cur_key = ZERO_KEY;
		write_sequnlock(&c->gc_cur_lock);
	}

	bch_gc_finish(c);
	up_write(&c->gc_lock);

	bch_time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(u64);
	stats.data	<<= 9;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));

	debug_check_no_locks_held();

	trace_bcache_gc_end(c);
}

/* Btree coalescing */

static void bch_coalesce_nodes(struct btree *old_nodes[GC_MERGE_NODES],
			       struct btree_iter *iter)
{
	struct btree *parent = iter->nodes[old_nodes[0]->level + 1];
	struct cache_set *c = iter->c;
	unsigned i, nr_old_nodes, nr_new_nodes, keys = 0;
	unsigned blocks = btree_blocks(c) * 2 / 3;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct keylist keylist;
	struct closure cl;
	struct bkey saved_pos;
	int ret;

	if (c->gc_coalesce_disabled)
		return;

	memset(new_nodes, 0, sizeof(new_nodes));
	bch_keylist_init(&keylist);
	closure_init_stack(&cl);

	for (i = 0; i < GC_MERGE_NODES && old_nodes[i]; i++)
		keys += old_nodes[i]->keys.nr_live_keys;

	nr_old_nodes = nr_new_nodes = i;

	if (nr_old_nodes <= 1 ||
	    __set_blocks(old_nodes[0]->keys.set[0].data,
			 DIV_ROUND_UP(keys, nr_old_nodes - 1),
			 block_bytes(c)) > blocks)
		return;

	if (btree_check_reserve(parent, NULL, iter->btree_id, nr_old_nodes) ||
	    bch_keylist_realloc(&keylist,
			(BKEY_U64s + BKEY_EXTENT_MAX_U64s) * nr_old_nodes)) {
		trace_bcache_btree_gc_coalesce_fail(c);
		return;
	}

	trace_bcache_btree_gc_coalesce(parent, nr_old_nodes);

	for (i = 0; i < nr_old_nodes; i++)
		new_nodes[i] = btree_node_alloc_replacement(old_nodes[i],
							    iter->btree_id);

	/*
	 * Conceptually we concatenate the nodes together and slice them
	 * up at different boundaries.
	 */
	for (i = nr_new_nodes - 1; i > 0; --i) {
		struct bset *n1 = btree_bset_first(new_nodes[i]);
		struct bset *n2 = btree_bset_first(new_nodes[i - 1]);
		struct bkey *k, *last = NULL;

		keys = 0;

		for (k = n2->start;
		     k < bset_bkey_last(n2) &&
		     __set_blocks(n1, n1->keys + keys + KEY_U64s(k),
				  block_bytes(c)) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			keys += KEY_U64s(k);
		}

		if (keys == n2->keys) {
			/* n2 fits entirely in n1 */
			bkey_copy_key(&new_nodes[i]->key,
				      &new_nodes[i - 1]->key);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       n2->keys * sizeof(u64));
			n1->keys += n2->keys;

			six_unlock_write(&new_nodes[i - 1]->lock);
			btree_node_free(new_nodes[i - 1]);
			six_unlock_intent(&new_nodes[i - 1]->lock);

			memmove(new_nodes + i - 1,
				new_nodes + i,
				sizeof(new_nodes[0]) * (nr_new_nodes - i));
			new_nodes[--nr_new_nodes] = NULL;
		} else if (keys) {
			/* move part of n2 into n1 */
			bkey_copy_key(&new_nodes[i]->key, last);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       keys * sizeof(u64));
			n1->keys += keys;

			memmove(n2->start,
				bset_bkey_idx(n2, keys),
				(n2->keys - keys) * sizeof(u64));
			n2->keys -= keys;
		}
	}

	for (i = 0; i < nr_new_nodes; i++) {
		new_nodes[i]->keys.nr_live_keys =
			new_nodes[i]->keys.set[0].data->keys;

		six_unlock_write(&new_nodes[i]->lock);
		bch_btree_node_write(new_nodes[i], &cl, NULL);
	}

	/* Wait for all the writes to finish */
	closure_sync(&cl);

	/* The keys for the old nodes get deleted */
	for (i = nr_old_nodes - 1; i > 0; --i) {
		*keylist.top = old_nodes[i]->key;
		bch_set_extent_ptrs(keylist.top, 0);
		SET_KEY_DELETED(keylist.top, 1);

		bch_keylist_enqueue(&keylist);
	}

	/*
	 * Keys for the new nodes get inserted: bch_btree_insert_keys() only
	 * does the lookup once and thus expects the keys to be in sorted order
	 */
	for (i = 0; i < nr_new_nodes; i++)
		bch_keylist_add_in_order(&keylist, &new_nodes[i]->key);

	/* hack: */
	saved_pos = iter->pos;
	iter->pos = *bch_keylist_front(&keylist);
	btree_iter_node_set(iter, parent);

	/* Insert the newly coalesced nodes */
	ret = bch_btree_insert_node(parent, iter, &keylist,
				    NULL, NULL, iter->btree_id);
	BUG_ON(ret || !bch_keylist_empty(&keylist));

	iter->pos = saved_pos;

	BUG_ON(iter->nodes[old_nodes[0]->level] != old_nodes[0]);

	btree_iter_node_set(iter, new_nodes[0]);

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < nr_old_nodes; i++) {
		btree_node_free(old_nodes[i]);
		six_unlock_intent(&old_nodes[i]->lock);
		old_nodes[i] = new_nodes[i];
	}

	bch_keylist_free(&keylist);
}

static int bch_coalesce_btree(struct cache_set *c, enum btree_id btree_id)
{
	struct btree_iter iter;
	struct btree *b;
	unsigned i;

	/* Sliding window of adjacent btree nodes */
	struct btree *merge[GC_MERGE_NODES];
	u32 lock_seq[GC_MERGE_NODES];

	memset(merge, 0, sizeof(merge));

	bch_btree_iter_init(&iter, c, btree_id, NULL);
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

		if (test_bit(CACHE_SET_STOPPING, &c->flags)) {
			bch_btree_iter_unlock(&iter);
			return -ESHUTDOWN;
		}

		bch_btree_iter_cond_resched(&iter);
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

	while (1) {
		bch_gc(c);
		bch_coalesce(c);

		/* Set task to interruptible first so that if someone wakes us
		 * up while we're finishing up, we will start another GC pass
		 * immediately */
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		try_to_freeze();
		schedule();
	}

	return 0;
}

int bch_gc_thread_start(struct cache_set *c)
{
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

	if (!c->btree_roots[id])
		return;

	for_each_btree_node(&iter, c, id, NULL, b) {
		if (btree_node_has_ptrs(b)) {
			struct btree_node_iter node_iter;
			struct bkey *k;

			for_each_btree_node_key(&b->keys, k, &node_iter)
				btree_mark_key(c, b, k);
		}

		__bch_btree_mark_key(c, iter.level + 1, &b->key);

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

	bch_gc_finish(c);
	return 0;
}
