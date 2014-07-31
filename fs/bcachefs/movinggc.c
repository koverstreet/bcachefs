/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
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
	u64 total = 0, target;
	unsigned bucket_bits;

	total = ca->sb.nbuckets * ca->sb.bucket_size;
	target = total * GC_TARGET_PERCENT / 100;
	bucket_bits = ca->set->bucket_bits + 9;

	bch_pd_controller_update(&ca->moving_gc_pd,
				 target << 9,
				 buckets_available_cache(ca) << bucket_bits);
	ca->moving_gc_pd.rate.rate = UINT_MAX;
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
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i) &&
		    PTR_BUCKET(c, k, i)->copygc_gen &&
		    PTR_CACHE(c, k, i) == ca)
			return true;

	return false;
}

static void read_moving(struct cache *ca, struct moving_io_stats *stats)
{
	struct cache_set *c = ca->set;
	struct keybuf_key *w;
	struct moving_io *io;
	struct closure cl;

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

		io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io)
			goto err;

		w->private		= io;
		io->w			= w;
		io->keybuf		= &ca->moving_gc_keys;
		io->stats		= stats;

		bch_data_insert_op_init(&io->op, c, &io->bio.bio, 0,
					false, false, false,
					&io->w->key, &io->w->key);
		io->op.moving_gc	= true;

		trace_bcache_gc_copy(&w->key);

		bch_ratelimit_increment(&ca->moving_gc_pd.rate,
					KEY_SIZE(&w->key) << 9);

		closure_call(&io->cl, bch_data_move, NULL, &cl);
	}

	if (0) {
err:		if (!IS_ERR_OR_NULL(w->private))
			kfree(w->private);

		bch_keybuf_del(&ca->moving_gc_keys, w);
	}

	closure_sync(&cl);
}

static bool bucket_sectors_cmp(struct bucket *l, struct bucket *r)
{
	return bucket_sectors_used(l) < bucket_sectors_used(r);
}

static unsigned bucket_sectors_heap_top(struct cache *ca)
{
	struct bucket *b;
	lockdep_assert_held(&ca->heap_lock);
	return (b = heap_peek(&ca->heap)) ? bucket_sectors_used(b) : 0;
}

#define bucket_w_prio(b) (c->prio_clock[WRITE].hand - b->write_prio)

#define bucket_write_prio_max_cmp(l, r)	(bucket_w_prio(l) > bucket_w_prio(r))

static bool bch_moving_gc(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket *b;
	bool moved = false;

	unsigned bucket_move_threshold =
		ca->sb.bucket_size - (ca->sb.bucket_size >> 3);
	u64 sectors_to_move = 0, sectors_gen, gen_current, sectors_total;
	size_t buckets_to_move, buckets_unused = 0;
	int reserve_sectors;
	struct moving_io_stats stats;

	memset(&stats, 0, sizeof(stats));

	mutex_lock(&c->bucket_lock);

	/* We won't fill up the moving GC reserve completely if the data
	 * being copied is from different generations. In the worst case,
	 * there will be NUM_GC_GENS buckets of internal fragmentation */
	reserve_sectors = ca->sb.bucket_size *
		(fifo_used(&ca->free[RESERVE_MOVINGGC]) - NUM_GC_GENS);
	mutex_unlock(&c->bucket_lock);

	if (reserve_sectors < (int) ca->sb.block_size)
		return false;

	trace_bcache_moving_gc_start(ca);

	/*
	 * sorts out smallest buckets into the gc heap, and then shrinks
	 * the heap to fit into a reasonable amount of reserve sectors
	 */

	mutex_lock(&ca->heap_lock);
	ca->heap.used = 0;
	for_each_bucket(b, ca) {
		b->copygc_gen = 0;

		if (bucket_unused(b)) {
			buckets_unused++;
			continue;
		}

		if (b->mark.owned_by_allocator ||
		    b->mark.is_metadata ||
		    bucket_sectors_used(b) >= bucket_move_threshold)
			continue;

		if (!heap_full(&ca->heap)) {
			sectors_to_move += bucket_sectors_used(b);
			heap_add(&ca->heap, b, bucket_sectors_cmp);
		} else if (bucket_sectors_cmp(b, heap_peek(&ca->heap))) {
			sectors_to_move -= bucket_sectors_heap_top(ca);
			sectors_to_move += bucket_sectors_used(b);

			ca->heap.data[0] = b;
			heap_sift(&ca->heap, 0, bucket_sectors_cmp);
		}
	}

	if ((buckets_unused > ca->sb.nbuckets / 10) ||
	    (ca->heap.used < ca->heap.size / 4 &&
	     sectors_to_move < reserve_sectors)) {
		mutex_unlock(&ca->heap_lock);
		return false;
	}

	while (sectors_to_move > reserve_sectors) {
		heap_pop(&ca->heap, b, bucket_sectors_cmp);
		sectors_to_move -= bucket_sectors_used(b);
	}

	buckets_to_move = ca->heap.used;

	if (sectors_to_move)
		moved = true;

	/*
	 * resort by write_prio to group into generations, attempts to
	 * keep hot and cold data in the same locality.
	 */

	heap_resort(&ca->heap, bucket_write_prio_max_cmp);

	sectors_gen = sectors_to_move / NUM_GC_GENS;
	gen_current = 1;
	sectors_total = 0;

	while (heap_pop(&ca->heap, b, bucket_write_prio_max_cmp)) {
		sectors_total += bucket_sectors_used(b);
		b->copygc_gen = gen_current;
		if (gen_current < NUM_GC_GENS &&
		    sectors_total >= sectors_gen * gen_current)
			gen_current++;
	}

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
		wake_up_gc(c, false);
	} while (!bch_kthread_loop_ratelimit(&last,
					     c->btree_scan_ratelimit * HZ));

	return 0;
}

int bch_moving_gc_thread_start(struct cache *ca)
{
	char moving_gc_name[16];

	snprintf(moving_gc_name, sizeof(moving_gc_name),
		"bcache_mv/%s", ca->bdev->bd_disk->disk_name);

	BUG_ON(ca->moving_gc_thread);
	ca->moving_gc_thread = kthread_create(bch_moving_gc_thread, ca,
						moving_gc_name);
	if (IS_ERR(ca->moving_gc_thread))
		return PTR_ERR(ca->moving_gc_thread);

	wake_up_process(ca->moving_gc_thread);

	bch_pd_controller_start(&ca->moving_gc_pd);

	ca->moving_gc_pd.d_term = 0;

	return 0;
}

void bch_moving_init_cache(struct cache *ca)
{
	bch_keybuf_init(&ca->moving_gc_keys);
	INIT_DELAYED_WORK(&ca->moving_gc_pd.update, update_gc_rate);
}
