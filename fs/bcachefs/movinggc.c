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
#include "keybuf.h"
#include "move.h"
#include "movinggc.h"

#include <trace/events/bcachefs.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

/* Rate limiting */

#define GC_TARGET_PERCENT 5 /* 5% reclaimable space */

static void __update_gc_rate(struct cache *ca)
{
	u64 total, target;
	unsigned bucket_bits;

	bucket_bits = ca->set->bucket_bits + 9;
	total = ca->sb.nbuckets - ca->sb.first_bucket;
	target = total * GC_TARGET_PERCENT / 100;

	bch_pd_controller_update(&ca->moving_gc_pd,
				 target << bucket_bits,
				 buckets_available_cache(ca) << bucket_bits);
}

static void update_gc_rate(struct work_struct *work)
{
	struct cache *ca = container_of(to_delayed_work(work),
					struct cache,
					moving_gc_pd.update);
	__update_gc_rate(ca);

	schedule_delayed_work(&ca->moving_gc_pd.update,
			      ca->moving_gc_pd.update_seconds * HZ);
}

/* Moving GC - IO loop */

static bool moving_pred(struct keybuf *buf, struct bkey *k)
{
	struct cache *ca = container_of(buf, struct cache,
					moving_gc_keys);
	struct cache_set *c = ca->set;
	bool ret = false;
	unsigned i;

	rcu_read_lock();
	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_CACHE(c, k, i) == ca &&
		    PTR_BUCKET(c, ca, k, i)->copygc_gen)
			ret = true;
	rcu_read_unlock();

	return ret;
}

static void read_moving(struct cache *ca, struct moving_io_stats *stats)
{
	struct cache_set *c = ca->set;
	struct keybuf_key *w;
	struct moving_io *io;
	struct closure cl;
	struct write_point *wp;
	unsigned ptr, gen;

	closure_init_stack(&cl);
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	ca->moving_gc_keys.last_scanned = ZERO_KEY;

	/* XXX: if we error, background writeback could stall indefinitely */

	while (!bch_ratelimit_wait_freezable_stoppable(&ca->moving_gc_pd.rate,
						       &cl)) {
		w = bch_keybuf_next_rescan(c, &ca->moving_gc_keys,
					   &MAX_KEY, moving_pred);
		if (!w)
			break;

		for (ptr = 0; ptr < bch_extent_ptrs(&w->key); ptr++)
			if ((ca->sb.nr_this_dev == PTR_DEV(&w->key, ptr)) &&
			    (gen = PTR_BUCKET(c, ca, &w->key,
					      ptr)->copygc_gen)) {
				gen--;
				BUG_ON(gen > ARRAY_SIZE(ca->gc_buckets));
				wp = &ca->gc_buckets[gen];
				goto found;
			}

		bch_keybuf_put(&ca->moving_gc_keys, w);
		continue;
found:
		io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io) {
			trace_bcache_moving_gc_alloc_fail(c, KEY_SIZE(&w->key));
			bch_keybuf_put(&ca->moving_gc_keys, w);
			break;
		}

		io->w			= w;
		io->keybuf		= &ca->moving_gc_keys;
		io->stats		= stats;

		bch_write_op_init(&io->op, c, &io->bio.bio, wp,
				  false, false, false,
				  &io->w->key, &io->w->key);
		io->op.io_wq		= ca->moving_gc_write;
		io->op.btree_alloc_reserve = RESERVE_MOVINGGC_BTREE;

		bch_extent_drop_ptr(&io->op.insert_key, ptr);

		trace_bcache_gc_copy(&w->key);

		bch_ratelimit_increment(&ca->moving_gc_pd.rate,
					KEY_SIZE(&w->key) << 9);

		closure_call(&io->cl, bch_data_move, NULL, &cl);
	}

	closure_sync(&cl);
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
	struct moving_io_stats stats;

	memset(&stats, 0, sizeof(stats));

	/*
	 * We won't fill up the moving GC reserve completely if the data
	 * being copied is from different generations. In the worst case,
	 * there will be NUM_GC_GENS buckets of internal fragmentation
	 */

	spin_lock(&ca->freelist_lock);
	reserve_sectors = ca->sb.bucket_size *
		(fifo_used(&ca->free[RESERVE_MOVINGGC]) - NUM_GC_GENS);
	spin_unlock(&ca->freelist_lock);

	if (reserve_sectors < (int) ca->sb.block_size)
		return false;

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

		sectors_used = bucket_sectors_used(g);

		if (g->mark.owned_by_allocator ||
		    g->mark.is_metadata)
			continue;

		bucket_heap_push(ca, g, sectors_used);
	}

	sectors_to_move = 0;
	for (i = 0; i < ca->heap.used; i++)
		sectors_to_move += ca->heap.data[i].val;

	if (buckets_unused > ca->reserve_buckets_count + ca->sb.nbuckets / 10) {
		mutex_unlock(&ca->heap_lock);
		return false;
	}

	if (ca->heap.used < ca->heap.size / 4 &&
	    sectors_to_move < reserve_sectors) {
		mutex_unlock(&ca->heap_lock);
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

	read_moving(ca, &stats);

	trace_bcache_moving_gc_end(ca, stats.sectors_moved, stats.keys_moved,
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

void bch_moving_gc_stop(struct cache *ca)
{
	cancel_delayed_work_sync(&ca->moving_gc_pd.update);

	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	if (ca->moving_gc_read)
		kthread_stop(ca->moving_gc_read);
	ca->moving_gc_read = NULL;

	if (ca->moving_gc_write)
		destroy_workqueue(ca->moving_gc_write);
	ca->moving_gc_write = NULL;
}

int bch_moving_gc_thread_start(struct cache *ca)
{
	struct task_struct *t;

	ca->moving_gc_write = alloc_workqueue("bch_copygc_write",
					      WQ_UNBOUND|WQ_MEM_RECLAIM, 1);
	if (!ca->moving_gc_write)
		return -ENOMEM;

	t = kthread_create(bch_moving_gc_thread, ca, "bch_copygc_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->moving_gc_read = t;
	wake_up_process(ca->moving_gc_read);
	bch_pd_controller_start(&ca->moving_gc_pd);

	ca->moving_gc_pd.d_term = 0;

	return 0;
}

void bch_moving_init_cache(struct cache *ca)
{
	bch_keybuf_init(&ca->moving_gc_keys);
	INIT_DELAYED_WORK(&ca->moving_gc_pd.update, update_gc_rate);
}
