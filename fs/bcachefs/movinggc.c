/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "extents.h"
#include "keybuf.h"
#include "move.h"

#include <trace/events/bcachefs.h>
#include <linux/kthread.h>

/* Rate limiting */

#define GC_TARGET_PERCENT 5 /* 5% reclaimable space */

static void __update_gc_rate(struct cache_set *c)
{
	u64 total = 0, target;

	/*
	 * XXX: Currently this is setting a rate based on the cache_set as
	 *      a whole. Later we will want to have individual rates for
	 *      each cache.
	 */

	total = c->nbuckets * c->sb.bucket_size;
	target = total * GC_TARGET_PERCENT / 100;

	bch_pd_controller_update(&c->moving_gc_pd,
				 target << 9,
				 buckets_available(c) << (c->bucket_bits + 9));
}

static void update_gc_rate(struct work_struct *work)
{
	struct cache_set *c = container_of(to_delayed_work(work),
					   struct cache_set,
					   moving_gc_pd.update);
	__update_gc_rate(c);

	schedule_delayed_work(&c->moving_gc_pd.update,
			      c->moving_gc_pd.update_seconds * HZ);
}

/* Moving GC - IO loop */

static bool moving_pred(struct keybuf *buf, struct bkey *k)
{
	struct cache_set *c = container_of(buf, struct cache_set,
					   moving_gc_keys);
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i) &&
		    GC_GEN(PTR_BUCKET(c, k, i)))
			return true;

	return false;
}

static void read_moving(struct cache_set *c)
{
	struct keybuf_key *w;
	struct moving_io *io;
	struct closure cl;

	closure_init_stack(&cl);
	bch_ratelimit_reset(&c->moving_gc_pd.rate);

	/* XXX: if we error, background writeback could stall indefinitely */

	while (!bch_ratelimit_wait_freezable_stoppable(&c->moving_gc_pd.rate,
						       &cl)) {
		w = bch_keybuf_next_rescan(c, &c->moving_gc_keys,
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
		io->keybuf		= &c->moving_gc_keys;

		bch_data_insert_op_init(&io->op, c, c->moving_gc_wq,
					&io->bio.bio, 0,
					false, false, false,
					&io->w->key, &io->w->key);
		io->op.moving_gc	= true;

		trace_bcache_gc_copy(&w->key);

		bch_ratelimit_increment(&c->moving_gc_pd.rate,
					KEY_SIZE(&w->key) << 9);

		closure_call(&io->cl, bch_data_move, NULL, &cl);
	}

	if (0) {
err:		if (!IS_ERR_OR_NULL(w->private))
			kfree(w->private);

		bch_keybuf_del(&c->moving_gc_keys, w);
	}

	closure_sync(&cl);
}

static bool bucket_sectors_cmp(struct bucket *l, struct bucket *r)
{
	return GC_SECTORS_USED(l) < GC_SECTORS_USED(r);
}

static unsigned bucket_sectors_heap_top(struct cache *ca)
{
	struct bucket *b;
	return (b = heap_peek(&ca->heap)) ? GC_SECTORS_USED(b) : 0;
}

#define bucket_w_prio(b) (c->write_clock.hand - b->write_prio)

#define bucket_write_prio_max_cmp(l, r)	(bucket_w_prio(l) > bucket_w_prio(r))

bool bch_moving_gc(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *b;
	unsigned i;
	bool moved = false;

	if (!c->copy_gc_enabled)
		return false;

	mutex_lock(&c->bucket_lock);

	for_each_cache(ca, c, i) {
		unsigned bucket_move_threshold =
			ca->sb.bucket_size - (ca->sb.bucket_size >> 3);
		unsigned sectors_to_move = 0, sectors_gen,
			 gen_current, sectors_total;
		int reserve_sectors = ca->sb.bucket_size *
			(fifo_used(&ca->free[RESERVE_MOVINGGC]) - NUM_GC_GENS);

		if (reserve_sectors < (int) ca->sb.block_size)
			continue;

		/*
		 * sorts out smallest buckets into the gc heap, and then shrinks
		 * the heap to fit into a reasonable amount of reserve sectors
		 */

		ca->heap.used = 0;
		for_each_bucket(b, ca) {
			SET_GC_GEN(b, 0);

			if (GC_MARK(b) == GC_MARK_METADATA ||
			    !GC_SECTORS_USED(b) ||
			    GC_SECTORS_USED(b) >= bucket_move_threshold)
				continue;

			if (!heap_full(&ca->heap)) {
				sectors_to_move += GC_SECTORS_USED(b);
				heap_add(&ca->heap, b, bucket_sectors_cmp);
			} else if (bucket_sectors_cmp(b,
						      heap_peek(&ca->heap))) {
				sectors_to_move -= bucket_sectors_heap_top(ca);
				sectors_to_move += GC_SECTORS_USED(b);

				ca->heap.data[0] = b;
				heap_sift(&ca->heap, 0, bucket_sectors_cmp);
			}
		}

		while (sectors_to_move > reserve_sectors) {
			heap_pop(&ca->heap, b, bucket_sectors_cmp);
			sectors_to_move -= GC_SECTORS_USED(b);
		}

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
			sectors_total += GC_SECTORS_USED(b);
			SET_GC_GEN(b, gen_current);

			if (gen_current < NUM_GC_GENS &&
			    sectors_total >= sectors_gen * gen_current)
				gen_current++;
		}
	}

	mutex_unlock(&c->bucket_lock);

	c->moving_gc_keys.last_scanned = ZERO_KEY;

	read_moving(c);
	return moved;
}

void bch_moving_init_cache_set(struct cache_set *c)
{
	bch_keybuf_init(&c->moving_gc_keys);
	INIT_DELAYED_WORK(&c->moving_gc_pd.update, update_gc_rate);
}
