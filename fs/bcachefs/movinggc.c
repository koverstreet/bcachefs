/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"

#include <trace/events/bcachefs.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/wait.h>

/* Moving GC - IO loop */

static const struct bch_extent_ptr *moving_pred(struct bch_dev *ca,
						struct bkey_s_c k)
{
	const struct bch_extent_ptr *ptr;

	if (bkey_extent_is_data(k.k) &&
	    (ptr = bch2_extent_has_device(bkey_s_c_to_extent(k),
					 ca->dev_idx)) &&
	    PTR_BUCKET(ca, ptr)->mark.copygc)
		return ptr;

	return NULL;
}

static int issue_moving_gc_move(struct bch_dev *ca,
				struct moving_context *ctxt,
				struct bkey_s_c k)
{
	struct bch_fs *c = ca->fs;
	const struct bch_extent_ptr *ptr;
	int ret;

	ptr = moving_pred(ca, k);
	if (!ptr) /* We raced - bucket's been reused */
		return 0;

	ret = bch2_data_move(c, ctxt, &ca->copygc_write_point, k, ptr);
	if (!ret)
		trace_gc_copy(k.k);
	else
		trace_moving_gc_alloc_fail(c, k.k->size);
	return ret;
}

static void read_moving(struct bch_dev *ca, size_t buckets_to_move,
			u64 sectors_to_move)
{
	struct bch_fs *c = ca->fs;
	struct bucket *g;
	struct moving_context ctxt;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 sectors_not_moved = 0;
	size_t buckets_not_moved = 0;

	bch2_ratelimit_reset(&ca->moving_gc_pd.rate);
	bch2_move_ctxt_init(&ctxt, &ca->moving_gc_pd.rate,
				SECTORS_IN_FLIGHT_PER_DEVICE);
	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

	while (1) {
		if (kthread_should_stop())
			goto out;
		if (bch2_move_ctxt_wait(&ctxt))
			goto out;
		k = bch2_btree_iter_peek(&iter);
		if (!k.k)
			break;
		if (btree_iter_err(k))
			goto out;

		if (!moving_pred(ca, k))
			goto next;

		if (issue_moving_gc_move(ca, &ctxt, k)) {
			bch2_btree_iter_unlock(&iter);

			/* memory allocation failure, wait for some IO to finish */
			bch2_move_ctxt_wait_for_io(&ctxt);
			continue;
		}
next:
		bch2_btree_iter_advance_pos(&iter);
		//bch2_btree_iter_cond_resched(&iter);

		/* unlock before calling moving_context_wait() */
		bch2_btree_iter_unlock(&iter);
		cond_resched();
	}

	bch2_btree_iter_unlock(&iter);
	bch2_move_ctxt_exit(&ctxt);
	trace_moving_gc_end(ca, ctxt.sectors_moved, ctxt.keys_moved,
				   buckets_to_move);

	/* don't check this if we bailed out early: */
	for_each_bucket(g, ca)
		if (g->mark.copygc && bucket_sectors_used(g)) {
			sectors_not_moved += bucket_sectors_used(g);
			buckets_not_moved++;
		}

	if (sectors_not_moved)
		bch_warn(c, "copygc finished but %llu/%llu sectors, %zu/%zu buckets not moved",
			 sectors_not_moved, sectors_to_move,
			 buckets_not_moved, buckets_to_move);
	return;
out:
	bch2_btree_iter_unlock(&iter);
	bch2_move_ctxt_exit(&ctxt);
	trace_moving_gc_end(ca, ctxt.sectors_moved, ctxt.keys_moved,
				   buckets_to_move);
}

static bool have_copygc_reserve(struct bch_dev *ca)
{
	bool ret;

	spin_lock(&ca->freelist_lock);
	ret = fifo_used(&ca->free[RESERVE_MOVINGGC]) >=
		COPYGC_BUCKETS_PER_ITER(ca);
	spin_unlock(&ca->freelist_lock);

	return ret;
}

static void bch2_moving_gc(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bucket *g;
	struct bucket_mark new;
	u64 sectors_to_move;
	size_t buckets_to_move, buckets_unused = 0;
	struct bucket_heap_entry e;
	unsigned sectors_used, i;
	int reserve_sectors;

	if (!have_copygc_reserve(ca)) {
		struct closure cl;

		closure_init_stack(&cl);
		while (1) {
			closure_wait(&c->freelist_wait, &cl);
			if (have_copygc_reserve(ca))
				break;
			closure_sync(&cl);
		}
		closure_wake_up(&c->freelist_wait);
	}

	reserve_sectors = COPYGC_SECTORS_PER_ITER(ca);

	trace_moving_gc_start(ca);

	/*
	 * Find buckets with lowest sector counts, skipping completely
	 * empty buckets, by building a maxheap sorted by sector count,
	 * and repeatedly replacing the maximum element until all
	 * buckets have been visited.
	 */

	/*
	 * We need bucket marks to be up to date, so gc can't be recalculating
	 * them, and we don't want the allocator invalidating a bucket after
	 * we've decided to evacuate it but before we set copygc:
	 */
	down_read(&c->gc_lock);
	mutex_lock(&ca->heap_lock);
	mutex_lock(&ca->fs->bucket_lock);

	ca->heap.used = 0;
	for_each_bucket(g, ca) {
		bucket_cmpxchg(g, new, new.copygc = 0);

		if (bucket_unused(g)) {
			buckets_unused++;
			continue;
		}

		if (g->mark.owned_by_allocator ||
		    g->mark.data_type != BUCKET_DATA)
			continue;

		sectors_used = bucket_sectors_used(g);

		if (sectors_used >= ca->mi.bucket_size)
			continue;

		bucket_heap_push(ca, g, sectors_used);
	}

	sectors_to_move = 0;
	for (i = 0; i < ca->heap.used; i++)
		sectors_to_move += ca->heap.data[i].val;

	while (sectors_to_move > COPYGC_SECTORS_PER_ITER(ca)) {
		BUG_ON(!heap_pop(&ca->heap, e, bucket_min_cmp));
		sectors_to_move -= e.val;
	}

	for (i = 0; i < ca->heap.used; i++)
		bucket_cmpxchg(ca->heap.data[i].g, new, new.copygc = 1);

	buckets_to_move = ca->heap.used;

	mutex_unlock(&ca->fs->bucket_lock);
	mutex_unlock(&ca->heap_lock);
	up_read(&c->gc_lock);

	read_moving(ca, buckets_to_move, sectors_to_move);
}

static int bch2_moving_gc_thread(void *arg)
{
	struct bch_dev *ca = arg;
	struct bch_fs *c = ca->fs;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last;
	u64 available, want, next;

	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->copy_gc_enabled))
			break;

		last = atomic_long_read(&clock->now);
		/*
		 * don't start copygc until less than half the gc reserve is
		 * available:
		 */
		available = dev_buckets_available(ca);
		want = div64_u64((ca->mi.nbuckets - ca->mi.first_bucket) *
				 c->opts.gc_reserve_percent, 200);
		if (available > want) {
			next = last + (available - want) *
				ca->mi.bucket_size;
			bch2_kthread_io_clock_wait(clock, next);
			continue;
		}

		bch2_moving_gc(ca);
	}

	return 0;
}

void bch2_moving_gc_stop(struct bch_dev *ca)
{
	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch2_ratelimit_reset(&ca->moving_gc_pd.rate);

	if (ca->moving_gc_read)
		kthread_stop(ca->moving_gc_read);
	ca->moving_gc_read = NULL;
}

int bch2_moving_gc_start(struct bch_dev *ca)
{
	struct task_struct *t;

	BUG_ON(ca->moving_gc_read);

	if (ca->fs->opts.nochanges)
		return 0;

	if (bch2_fs_init_fault("moving_gc_start"))
		return -ENOMEM;

	t = kthread_create(bch2_moving_gc_thread, ca, "bch_copygc_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->moving_gc_read = t;
	wake_up_process(ca->moving_gc_read);

	return 0;
}

void bch2_dev_moving_gc_init(struct bch_dev *ca)
{
	bch2_pd_controller_init(&ca->moving_gc_pd);
	ca->moving_gc_pd.d_term = 0;
}
