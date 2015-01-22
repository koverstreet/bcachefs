/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"

#include <trace/events/bcachefs.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

/* Moving GC - IO loop */

static bool moving_pred(struct scan_keylist *kl, const struct bkey *k)
{
	struct cache *ca = container_of(kl, struct cache,
					moving_gc_queue.keys);
	struct cache_set *c = ca->set;
	const struct bkey_i_extent *e;
	const struct bch_extent_ptr *ptr;
	bool ret = false;

	switch (k->type) {
	case BCH_EXTENT:
		e = bkey_i_to_extent_c(k);

		rcu_read_lock();
		extent_for_each_ptr(e, ptr)
			if (PTR_CACHE(c, ptr) == ca &&
			    PTR_BUCKET(ca, ptr)->copygc_gen)
				ret = true;
		rcu_read_unlock();

		return ret;
	default:
		return false;
	}
}

static int issue_moving_gc_move(struct moving_queue *q,
				struct moving_context *ctxt,
				const struct bkey *k)
{
	struct cache *ca = container_of(q, struct cache, moving_gc_queue);
	struct cache_set *c = ca->set;
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	const struct bch_extent_ptr *ptr;
	struct moving_io *io;
	struct write_point *wp;
	unsigned gen;
	bool cached = EXTENT_CACHED(&e->v);
	u64 sort_key;

	extent_for_each_ptr(e, ptr)
		if ((ca->sb.nr_this_dev == PTR_DEV(ptr)) &&
		    (gen = PTR_BUCKET(ca, ptr)->copygc_gen)) {
			gen--;
			BUG_ON(gen > ARRAY_SIZE(ca->gc_buckets));
			wp = &ca->gc_buckets[gen];
			sort_key = PTR_OFFSET(ptr);
			goto found;
		}

	bch_scan_keylist_dequeue(&q->keys);
	return 0;

found:
	io = moving_io_alloc(k);
	if (!io) {
		trace_bcache_moving_gc_alloc_fail(c, k->size);
		return -ENOMEM;
	}

	/*
	 * This also copies k into both insert_key and replace_key.
	 * Notice that we must preserve the cached status of the
	 * key here, since extent_drop_ptr() might delete the
	 * first pointer, losing the cached status
	 */
	bch_write_op_init(&io->op, c, &io->bio.bio, wp, k, k,
			  cached ? BCH_WRITE_CACHED : 0);
	io->op.btree_alloc_reserve = RESERVE_MOVINGGC_BTREE;
	io->sort_key		   = sort_key;

	bch_extent_drop_ptr(&io->op.insert_key, ptr - e->v.ptr);

	trace_bcache_gc_copy(k);

	/*
	 * IMPORTANT: We must call bch_data_move before we dequeue so
	 * that the key can always be found in either the pending list
	 * in the moving queue or in the scan keylist list in the
	 * moving queue.
	 * If we reorder, there is a window where a key is not found
	 * by btree gc marking.
	 */
	bch_data_move(q, ctxt, io);
	bch_scan_keylist_dequeue(&q->keys);
	return 0;
}

static void read_moving(struct cache *ca, struct moving_context *ctxt)
{
	struct bkey *k;
	bool again;

	bch_ratelimit_reset(&ca->moving_gc_pd.rate);

	do {
		again = false;

		while (!bch_moving_context_wait(ctxt)) {
			if (bch_queue_full(&ca->moving_gc_queue)) {
				if (ca->moving_gc_queue.rotational) {
					again = true;
					break;
				} else {
					bch_moving_wait(ctxt);
					continue;
				}
			}

			k = bch_scan_keylist_next_rescan(
				ca->set,
				&ca->moving_gc_queue.keys,
				&ctxt->last_scanned,
				POS_MAX,
				moving_pred);

			if (k == NULL)
				break;

			if (issue_moving_gc_move(&ca->moving_gc_queue,
						 ctxt, k)) {
				/*
				 * Memory allocation failed; we will wait for
				 * all queued moves to finish and continue
				 * scanning starting from the same key
				 */
				again = true;
				break;
			}
		}

		bch_queue_run(&ca->moving_gc_queue, ctxt);
	} while (again);
}

static bool bch_moving_gc(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket *g;
	bool moved = false;

	u64 sectors_to_move, sectors_gen, gen_current, sectors_total;
	size_t buckets_to_move, buckets_unused = 0;
	struct bucket_heap_entry e;
	unsigned sectors_used, i;
	int reserve_sectors;

	struct moving_context ctxt;

	bch_moving_context_init(&ctxt, &ca->moving_gc_pd.rate,
				MOVING_PURPOSE_COPY_GC);

	/*
	 * We won't fill up the moving GC reserve completely if the data
	 * being copied is from different generations. In the worst case,
	 * there will be NUM_GC_GENS buckets of internal fragmentation
	 */

	spin_lock(&ca->freelist_lock);
	reserve_sectors = ca->sb.bucket_size *
		(fifo_used(&ca->free[RESERVE_MOVINGGC]) - NUM_GC_GENS);
	spin_unlock(&ca->freelist_lock);

	if (reserve_sectors < (int) ca->sb.block_size) {
		trace_bcache_moving_gc_reserve_empty(ca);
		return false;
	}

	trace_bcache_moving_gc_start(ca);

	/*
	 * Find buckets with lowest sector counts, skipping completely
	 * empty buckets, by building a maxheap sorted by sector count,
	 * and repeatedly replacing the maximum element until all
	 * buckets have been visited.
	 */

	mutex_lock(&ca->heap_lock);
	ca->heap.used = 0;
	for_each_bucket(g, ca) {
		g->copygc_gen = 0;

		if (bucket_unused(g)) {
			buckets_unused++;
			continue;
		}

		if (g->mark.owned_by_allocator ||
		    g->mark.is_metadata)
			continue;

		sectors_used = bucket_sectors_used(g);

		if (sectors_used >= ca->sb.bucket_size)
			continue;

		bucket_heap_push(ca, g, sectors_used);
	}

	sectors_to_move = 0;
	for (i = 0; i < ca->heap.used; i++)
		sectors_to_move += ca->heap.data[i].val;

	if (ca->heap.used < ca->heap.size / 4 &&
	    sectors_to_move < reserve_sectors) {
		mutex_unlock(&ca->heap_lock);
		trace_bcache_moving_gc_no_work(ca);
		return false;
	}

	while (sectors_to_move > reserve_sectors) {
		BUG_ON(!heap_pop(&ca->heap, e, bucket_min_cmp));
		sectors_to_move -= e.val;
	}

	buckets_to_move = ca->heap.used;

	if (sectors_to_move)
		moved = true;

	/*
	 * resort by write_prio to group into generations, attempts to
	 * keep hot and cold data in the same locality.
	 */

	mutex_lock(&ca->set->bucket_lock);
	for (i = 0; i < ca->heap.used; i++) {
		struct bucket_heap_entry *e = &ca->heap.data[i];

		e->val = (c->prio_clock[WRITE].hand - e->g->write_prio);
	}

	heap_resort(&ca->heap, bucket_max_cmp);

	sectors_gen = sectors_to_move / NUM_GC_GENS;
	gen_current = 1;
	sectors_total = 0;

	while (heap_pop(&ca->heap, e, bucket_max_cmp)) {
		sectors_total += bucket_sectors_used(e.g);
		e.g->copygc_gen = gen_current;
		if (gen_current < NUM_GC_GENS &&
		    sectors_total >= sectors_gen * gen_current)
			gen_current++;
	}
	mutex_unlock(&ca->set->bucket_lock);

	mutex_unlock(&ca->heap_lock);

	read_moving(ca, &ctxt);

	trace_bcache_moving_gc_end(ca, ctxt.sectors_moved, ctxt.keys_moved,
				buckets_to_move);

	return moved;
}

static int bch_moving_gc_thread(void *arg)
{
	struct cache *ca = arg;
	struct cache_set *c = ca->set;
	unsigned long last = jiffies;

	do {
		if (kthread_wait_freezable(c->copy_gc_enabled))
			break;

		bch_moving_gc(ca);
	} while (!bch_kthread_loop_ratelimit(&last,
					     c->btree_scan_ratelimit * HZ));

	return 0;
}

#define MOVING_GC_KEYS_MAX_SIZE	DFLT_SCAN_KEYLIST_MAX_SIZE
#define MOVING_GC_NR 64
#define MOVING_GC_READ_NR 32
#define MOVING_GC_WRITE_NR 32

void bch_moving_init_cache(struct cache *ca)
{
	bch_pd_controller_init(&ca->moving_gc_pd);
	bch_queue_init(&ca->moving_gc_queue,
		       ca->set,
		       MOVING_GC_KEYS_MAX_SIZE,
		       MOVING_GC_NR,
		       MOVING_GC_READ_NR,
		       MOVING_GC_WRITE_NR);

	ca->moving_gc_pd.d_term = 0;
}

int bch_moving_gc_thread_start(struct cache *ca)
{
	struct task_struct *t;
	int ret;

	/* The moving gc read thread must be stopped */
	BUG_ON(ca->moving_gc_read != NULL);

	ret = bch_queue_start(&ca->moving_gc_queue,
			      "bch_copygc_write");
	if (ret)
		return ret;

	t = kthread_create(bch_moving_gc_thread, ca, "bch_copygc_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->moving_gc_read = t;
	wake_up_process(ca->moving_gc_read);

	return 0;
}

void bch_moving_gc_stop(struct cache *ca)
{
	bch_queue_stop(&ca->moving_gc_queue);
	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	if (ca->moving_gc_read)
		kthread_stop(ca->moving_gc_read);
	ca->moving_gc_read = NULL;
}

void bch_moving_gc_destroy(struct cache *ca)
{
	bch_queue_destroy(&ca->moving_gc_queue);
}
