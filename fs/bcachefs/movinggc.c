/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "btree_iter.h"
#include "btree_update.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "eytzinger.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "super-io.h"

#include <trace/events/bcachefs.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/sort.h>
#include <linux/wait.h>

/*
 * We can't use the entire copygc reserve in one iteration of copygc: we may
 * need the buckets we're freeing up to go back into the copygc reserve to make
 * forward progress, but if the copygc reserve is full they'll be available for
 * any allocation - and it's possible that in a given iteration, we free up most
 * of the buckets we're going to free before we allocate most of the buckets
 * we're going to allocate.
 *
 * If we only use half of the reserve per iteration, then in steady state we'll
 * always have room in the reserve for the buckets we're going to need in the
 * next iteration:
 */
#define COPYGC_BUCKETS_PER_ITER(ca)					\
	((ca)->free[RESERVE_MOVINGGC].size / 2)

/*
 * Max sectors to move per iteration: Have to take into account internal
 * fragmentation from the multiple write points for each generation:
 */
#define COPYGC_SECTORS_PER_ITER(ca)					\
	((ca)->mi.bucket_size *	COPYGC_BUCKETS_PER_ITER(ca))


static int bucket_idx_cmp(const void *_l, const void *_r, size_t size)
{
	const struct bucket_heap_entry *l = _l;
	const struct bucket_heap_entry *r = _r;

	if (l->bucket < r->bucket)
		return -1;
	if (l->bucket > r->bucket)
		return 1;
	return 0;
}

static const struct bch_extent_ptr *moving_pred(struct bch_dev *ca,
						struct bkey_s_c k)
{
	bucket_heap *h = &ca->copygc_heap;
	const struct bch_extent_ptr *ptr;

	if (bkey_extent_is_data(k.k) &&
	    (ptr = bch2_extent_has_device(bkey_s_c_to_extent(k),
					  ca->dev_idx))) {
		struct bucket_heap_entry search = {
			.bucket = PTR_BUCKET_NR(ca, ptr)
		};

		size_t i = eytzinger0_find(h->data, h->used,
					   sizeof(h->data[0]),
					   bucket_idx_cmp, &search);

		if (i < h->used)
			return ptr;
	}

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

	ret = bch2_data_move(c, ctxt, &ca->self,
			     writepoint_ptr(&ca->copygc_write_point),
			     BTREE_INSERT_USE_RESERVE, ca->dev_idx, k);
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
	bucket_heap *h = &ca->copygc_heap;
	struct moving_context ctxt;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 sectors_not_moved = 0;
	size_t buckets_not_moved = 0;
	struct bucket_heap_entry *i;

	bch2_ratelimit_reset(&ca->copygc_pd.rate);
	bch2_move_ctxt_init(&ctxt, &ca->copygc_pd.rate,
				SECTORS_IN_FLIGHT_PER_DEVICE);
	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_PREFETCH);

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
	for (i = h->data; i < h->data + h->used; i++) {
		struct bucket_mark m = READ_ONCE(ca->buckets[i->bucket].mark);

		if (i->mark.gen == m.gen && bucket_sectors_used(m)) {
			sectors_not_moved += bucket_sectors_used(m);
			buckets_not_moved++;
		}
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

static inline int sectors_used_cmp(bucket_heap *heap,
				   struct bucket_heap_entry l,
				   struct bucket_heap_entry r)
{
	return bucket_sectors_used(l.mark) - bucket_sectors_used(r.mark);
}

static void bch2_copygc(struct bch_fs *c, struct bch_dev *ca)
{
	struct bucket *g;
	u64 sectors_to_move = 0;
	size_t buckets_to_move, buckets_unused = 0;
	struct bucket_heap_entry e, *i;

	closure_wait_event(&c->freelist_wait, have_copygc_reserve(ca));

	trace_moving_gc_start(ca);

	/*
	 * Find buckets with lowest sector counts, skipping completely
	 * empty buckets, by building a maxheap sorted by sector count,
	 * and repeatedly replacing the maximum element until all
	 * buckets have been visited.
	 */

	/*
	 * We need bucket marks to be up to date - gc can't be recalculating
	 * them:
	 */
	down_read(&c->gc_lock);
	ca->copygc_heap.used = 0;
	for_each_bucket(g, ca) {
		struct bucket_mark m = READ_ONCE(g->mark);
		struct bucket_heap_entry e = { g - ca->buckets, m };

		if (bucket_unused(m)) {
			buckets_unused++;
			continue;
		}

		if (m.owned_by_allocator ||
		    m.data_type != BUCKET_DATA)
			continue;

		if (bucket_sectors_used(m) >= ca->mi.bucket_size)
			continue;

		heap_add_or_replace(&ca->copygc_heap, e, -sectors_used_cmp);
	}
	up_read(&c->gc_lock);

	for (i = ca->copygc_heap.data;
	     i < ca->copygc_heap.data + ca->copygc_heap.used;
	     i++)
		sectors_to_move += bucket_sectors_used(i->mark);

	while (sectors_to_move > COPYGC_SECTORS_PER_ITER(ca)) {
		BUG_ON(!heap_pop(&ca->copygc_heap, e, -sectors_used_cmp));
		sectors_to_move -= bucket_sectors_used(e.mark);
	}

	buckets_to_move = ca->copygc_heap.used;

	eytzinger0_sort(ca->copygc_heap.data,
			ca->copygc_heap.used,
			sizeof(ca->copygc_heap.data[0]),
			bucket_idx_cmp, NULL);

	read_moving(ca, buckets_to_move, sectors_to_move);
}

static int bch2_copygc_thread(void *arg)
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
		available = dev_buckets_available(c, ca);
		want = div64_u64((ca->mi.nbuckets - ca->mi.first_bucket) *
				 c->opts.gc_reserve_percent, 200);
		if (available > want) {
			next = last + (available - want) *
				ca->mi.bucket_size;
			bch2_kthread_io_clock_wait(clock, next);
			continue;
		}

		bch2_copygc(c, ca);
	}

	return 0;
}

void bch2_copygc_stop(struct bch_dev *ca)
{
	ca->copygc_pd.rate.rate = UINT_MAX;
	bch2_ratelimit_reset(&ca->copygc_pd.rate);

	if (ca->copygc_thread)
		kthread_stop(ca->copygc_thread);
	ca->copygc_thread = NULL;
}

int bch2_copygc_start(struct bch_fs *c, struct bch_dev *ca)
{
	struct task_struct *t;

	BUG_ON(ca->copygc_thread);

	if (c->opts.nochanges)
		return 0;

	if (bch2_fs_init_fault("copygc_start"))
		return -ENOMEM;

	t = kthread_create(bch2_copygc_thread, ca, "bch_copygc");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->copygc_thread = t;
	wake_up_process(ca->copygc_thread);

	return 0;
}

void bch2_dev_copygc_init(struct bch_dev *ca)
{
	bch2_pd_controller_init(&ca->copygc_pd);
	ca->copygc_pd.d_term = 0;
}
