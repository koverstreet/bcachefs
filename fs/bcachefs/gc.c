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

u8 bch_btree_key_recalc_oldest_gen(struct cache_set *c,
				   struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;
	u8 max_stale = 0;

	extent_for_each_ptr(e, ptr)
		if (PTR_DEV(ptr) < MAX_CACHES_PER_SET)
			__set_bit(PTR_DEV(ptr), c->cache_slots_used);

	extent_for_each_online_device(c, e, ptr, ca) {
		struct bucket *g = PTR_BUCKET(ca, ptr);

		if (__gen_after(g->oldest_gen, PTR_GEN(ptr)))
			g->oldest_gen = PTR_GEN(ptr);

		max_stale = max(max_stale, ptr_stale(ca, ptr));
	}

	return max_stale;
}

u8 __bch_btree_mark_key(struct cache_set *c, int level, struct bkey_s_c k)
{
	struct bkey_s_c_extent e;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;
	u8 max_stale;

	switch (k.k->type) {
	case BCH_EXTENT:
		e = bkey_s_c_to_extent(k);

		rcu_read_lock();

		max_stale = bch_btree_key_recalc_oldest_gen(c, e);

		if (level) {
			extent_for_each_online_device(c, e, ptr, ca)
				bch_mark_metadata_bucket(ca,
						PTR_BUCKET(ca, ptr), true);
		} else {
			__bch_add_sectors(c, NULL, e, bkey_start_offset(e.k),
					  e.k->size, false);
		}

		rcu_read_unlock();

		return max_stale;
	default:
		return 0;
	}
}

static u8 btree_mark_key(struct cache_set *c, struct btree *b,
			 struct bkey_s_c k)
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
	struct bkey_format *f = &b->keys.format;
	struct bset_tree *t;

	for (t = b->keys.set; t <= &b->keys.set[b->keys.nsets]; t++)
		btree_bug_on(t->size &&
			     bset_written(&b->keys, t) &&
			     bkey_cmp_packed(f, &b->key.k, &t->end) < 0,
			     b, "found short btree key in gc");

	if (stat)
		stat->nodes++;

	/* only actually needed for the root */
	__bch_btree_mark_key(c, b->level + 1, bkey_i_to_s_c(&b->key));

	if (btree_node_has_ptrs(b)) {
		struct btree_node_iter iter;
		struct bkey_packed *k;
		struct bkey_tup tup;
		unsigned keys = 0, good_keys = 0, u64s;
		u8 stale = 0;

		for_each_btree_node_key(&b->keys, k, &iter) {
			bkey_disassemble(&tup, f, k);

			bkey_debugcheck(c, b, bkey_tup_to_s_c(&tup));

			stale = max(stale,
				    btree_mark_key(c, b,
						   bkey_tup_to_s_c(&tup)));
			keys++;

			u64s = bch_extent_nr_ptrs_after_normalize(c, b, k);
			if (stat && u64s) {
				good_keys++;

				stat->key_bytes += k->u64s;
				stat->nkeys++;
				stat->data += tup.k.size;
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
	struct bpos next_min = POS_MIN;

	bch_btree_iter_init(&iter, c, btree_id, POS_MIN);
	iter.is_extents = false;
	iter.locks_want = BTREE_MAX_DEPTH;

	for (b = bch_btree_iter_peek_node(&iter);
	     b;
	     b = bch_btree_iter_next_node(&iter)) {
		if (!b->level) {
			cache_set_bug_on(bkey_cmp(b->data->min_key, next_min),
				c,
				"btree node has incorrect min key: %llu:%llu != %llu:%llu",
				b->data->min_key.inode,
				b->data->min_key.offset,
				next_min.inode,
				next_min.offset);

			if (bkey_cmp(b->data->max_key, POS_MAX))
				next_min =
					__bch_btree_iter_advance_pos(&iter,
							b->data->max_key);
		}

		bch_verify_btree_keys_accounting(&b->keys);

		should_rewrite = btree_gc_mark_node(c, b, stat);

		BUG_ON(bkey_cmp(c->gc_cur_pos, b->key.k.p) > 0);
		BUG_ON(!gc_will_visit_node(c, b));

		write_seqlock(&c->gc_cur_lock);
		c->gc_cur_level = b->level;
		c->gc_cur_pos = b->key.k.p;
		write_sequnlock(&c->gc_cur_lock);

		BUG_ON(gc_will_visit_node(c, b));

		if (should_rewrite)
			bch_btree_node_rewrite(b, &iter, false);

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

		fifo_for_each_entry(i, &ca->free_inc, iter)
			bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each_entry(i, &ca->free[j], iter)
				bch_mark_alloc_bucket(ca, &ca->buckets[i]);

		spin_unlock(&ca->freelist_lock);
	}

	spin_lock(&c->open_buckets_lock);
	rcu_read_lock();

	list_for_each_entry(b, &c->open_buckets_open, list) {
		struct bkey_s_c_extent e;
		const struct bch_extent_ptr *ptr;

		spin_lock(&b->lock);
		e = bkey_i_to_s_c_extent(&b->key);
		extent_for_each_online_device(c, e, ptr, ca)
			bch_mark_alloc_bucket(ca, PTR_BUCKET(ca, ptr));
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
	c->gc_cur_pos	= POS_MIN;
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
			pr_err("btree gc failed with %d!", ret);
			set_bit(CACHE_SET_GC_FAILURE, &c->flags);
			up_write(&c->gc_lock);
			return;
		}

		write_seqlock(&c->gc_cur_lock);
		c->gc_cur_btree++;
		c->gc_cur_level = 0;
		c->gc_cur_pos	= POS_MIN;
		write_sequnlock(&c->gc_cur_lock);
	}

	bch_gc_finish(c);
	up_write(&c->gc_lock);

	bch_time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(u64);
	stats.data	<<= 9;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));

	trace_bcache_gc_end(c);
}

/* Btree coalescing */

static void recalc_packed_keys(struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey_packed *k;

	b->keys.nr_packed_keys = 0;
	b->keys.nr_unpacked_keys = 0;

	for_each_btree_node_key(&b->keys, k, &iter)
		if (bkey_packed(k))
			b->keys.nr_packed_keys++;
		else
			b->keys.nr_unpacked_keys++;
}

static void bch_coalesce_nodes(struct btree *old_nodes[GC_MERGE_NODES],
			       struct btree_iter *iter)
{
	struct btree *parent = iter->nodes[old_nodes[0]->level + 1];
	struct cache_set *c = iter->c;
	unsigned i, nr_old_nodes, nr_new_nodes, u64s = 0;
	unsigned blocks = btree_blocks(c) * 2 / 3;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct keylist keylist;
	struct closure cl;
	struct bpos saved_pos;
	struct bkey_format_state format_state;
	struct bkey_format new_format;
	int ret;

	if (c->gc_coalesce_disabled)
		return;

	memset(new_nodes, 0, sizeof(new_nodes));
	bch_keylist_init(&keylist);
	closure_init_stack(&cl);

	/* Count keys that are not deleted */
	for (i = 0; i < GC_MERGE_NODES && old_nodes[i]; i++)
		u64s += old_nodes[i]->keys.nr_live_u64s;

	nr_old_nodes = nr_new_nodes = i;

	/* Check if all keys in @old_nodes could fit in one fewer node */
	if (nr_old_nodes <= 1 ||
	    __set_blocks(old_nodes[0]->data,
			 DIV_ROUND_UP(u64s, nr_old_nodes - 1),
			 block_bytes(c)) > blocks)
		return;

	if (btree_check_reserve(c, parent, NULL, iter->btree_id,
				nr_old_nodes, false) ||
	    bch_keylist_realloc(&keylist,
			(BKEY_U64s + BKEY_EXTENT_MAX_U64s) * nr_old_nodes)) {
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
		if (!btree_node_format_fits(old_nodes[i], &new_format)) {
			trace_bcache_btree_gc_coalesce_fail(c);
			goto out;
		}

	for (i = 0; i < nr_old_nodes; i++) {
		closure_sync(&cl);
		bch_btree_push_journal_seq(c, old_nodes[i], &cl);
	}

	/* Repack everything with @new_format and sort down to one bset */
	for (i = 0; i < nr_old_nodes; i++)
		new_nodes[i] = __btree_node_alloc_replacement(c, old_nodes[i],
							      new_format);

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
		     __set_blocks(n1->data, s1->u64s + u64s + k->u64s,
				  block_bytes(c)) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			u64s += k->u64s;
		}

		if (u64s == s2->u64s) {
			/* n2 fits entirely in n1 */
			n1->key.k.p = n1->data->max_key = n2->data->max_key;

			memcpy(bset_bkey_last(s1),
			       s2->start,
			       s2->u64s * sizeof(u64));
			s1->u64s += s2->u64s;

			six_unlock_write(&n2->lock);
			btree_node_free(c, n2);
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
				__bch_btree_iter_advance_pos(iter,
						n1->data->max_key);

			memcpy(bset_bkey_last(s1),
			       s2->start,
			       u64s * sizeof(u64));
			s1->u64s += u64s;

			memmove(s2->start,
				bset_bkey_idx(s2, u64s),
				(s2->u64s - u64s) * sizeof(u64));
			s2->u64s -= u64s;
		}
	}

	for (i = 0; i < nr_new_nodes; i++) {
		struct btree *n = new_nodes[i];

		n->keys.nr_live_u64s = n->keys.set->data->u64s;
		recalc_packed_keys(n);
		six_unlock_write(&n->lock);
		bch_btree_node_write(n, &cl, NULL);
	}

	/* Wait for all the writes to finish */
	closure_sync(&cl);

	/*
	 * The keys for the old nodes get deleted. We don't need a deleted
	 * key for old_nodes[0], since new_nodes[0] must have the same key
	 */
	for (i = nr_old_nodes - 1; i > 0; --i) {
		*keylist.top = old_nodes[i]->key;
		set_bkey_deleted(&keylist.top->k);

		bch_keylist_enqueue(&keylist);
	}

	/*
	 * Keys for the new nodes get inserted: bch_btree_insert_keys() only
	 * does the lookup once and thus expects the keys to be in sorted order
	 * so we have to make sure the new keys are correctly ordered with
	 * respect to the deleted keys added in the previous loop
	 */
	for (i = 0; i < nr_new_nodes; i++)
		bch_keylist_add_in_order(&keylist, &new_nodes[i]->key);

	/* hack: */
	saved_pos = iter->pos;
	iter->pos = bch_keylist_front(&keylist)->k.p;
	btree_iter_node_set(iter, parent);

	/* Insert the newly coalesced nodes */
	ret = bch_btree_insert_node(parent, iter, &keylist,
				    NULL, NULL, BTREE_INSERT_NOFAIL);
	BUG_ON(ret || !bch_keylist_empty(&keylist));

	iter->pos = saved_pos;

	BUG_ON(iter->nodes[old_nodes[0]->level] != old_nodes[0]);

	btree_iter_node_set(iter, new_nodes[0]);

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < nr_old_nodes; i++) {
		btree_node_free(c, old_nodes[i]);
		six_unlock_intent(&old_nodes[i]->lock);
		old_nodes[i] = new_nodes[i];
	}
out:
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
	struct cache *ca;
	unsigned i;

	while (1) {
		bch_gc(c);
		bch_coalesce(c);

		debug_check_no_locks_held();

		set_current_state(TASK_INTERRUPTIBLE);

		/*
		 * Wake up allocator in case it was waiting for buckets
		 * because of not being able to inc gens
		 */
		for_each_cache(ca, c, i)
			bch_wake_allocator(ca);

		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}

		schedule();
		try_to_freeze();
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

	for_each_btree_node(&iter, c, id, POS_MIN, b) {
		if (btree_node_has_ptrs(b)) {
			struct btree_node_iter node_iter;
			struct bkey_tup tup;

			for_each_btree_node_key_unpack(&b->keys, &tup,
						       &node_iter)
				btree_mark_key(c, b, bkey_tup_to_s_c(&tup));
		}

		__bch_btree_mark_key(c, iter.level + 1,
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

	bch_gc_finish(c);

	set_bit(CACHE_SET_INITIAL_GC_DONE, &c->flags);
	return 0;
}
