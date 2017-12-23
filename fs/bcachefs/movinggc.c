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

static inline int sectors_used_cmp(copygc_heap *heap,
				   struct copygc_heap_entry l,
				   struct copygc_heap_entry r)
{
	return bucket_sectors_used(l.mark) - bucket_sectors_used(r.mark);
}

static int bucket_offset_cmp(const void *_l, const void *_r, size_t size)
{
	const struct copygc_heap_entry *l = _l;
	const struct copygc_heap_entry *r = _r;

	return (l->offset > r->offset) - (l->offset < r->offset);
}

static bool copygc_pred(void *arg, struct bkey_s_c_extent e)
{
	struct bch_dev *ca = arg;
	copygc_heap *h = &ca->copygc_heap;
	const struct bch_extent_ptr *ptr =
		bch2_extent_has_device(e, ca->dev_idx);

	if (ptr) {
		struct copygc_heap_entry search = { .offset = ptr->offset };

		size_t i = eytzinger0_find_le(h->data, h->used,
					      sizeof(h->data[0]),
					      bucket_offset_cmp, &search);

		return (i >= 0 &&
			ptr->offset < h->data[i].offset + ca->mi.bucket_size &&
			ptr->gen == h->data[i].mark.gen);
	}

	return false;
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

static void bch2_copygc(struct bch_fs *c, struct bch_dev *ca)
{
	copygc_heap *h = &ca->copygc_heap;
	struct copygc_heap_entry e, *i;
	struct bucket *g;
	u64 keys_moved, sectors_moved;
	u64 sectors_to_move = 0, sectors_not_moved = 0;
	u64 buckets_to_move, buckets_not_moved = 0;
	int ret;

	closure_wait_event(&c->freelist_wait, have_copygc_reserve(ca));

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
	h->used = 0;
	for_each_bucket(g, ca) {
		struct bucket_mark m = READ_ONCE(g->mark);
		struct copygc_heap_entry e;

		if (m.owned_by_allocator ||
		    m.data_type != BCH_DATA_USER ||
		    !bucket_sectors_used(m) ||
		    bucket_sectors_used(m) >= ca->mi.bucket_size)
			continue;

		e = (struct copygc_heap_entry) {
			.offset = bucket_to_sector(ca, g - ca->buckets),
			.mark	= m
		};
		heap_add_or_replace(h, e, -sectors_used_cmp);
	}
	up_read(&c->gc_lock);

	for (i = h->data; i < h->data + h->used; i++)
		sectors_to_move += bucket_sectors_used(i->mark);

	while (sectors_to_move > COPYGC_SECTORS_PER_ITER(ca)) {
		BUG_ON(!heap_pop(h, e, -sectors_used_cmp));
		sectors_to_move -= bucket_sectors_used(e.mark);
	}

	buckets_to_move = h->used;

	if (!buckets_to_move)
		return;

	eytzinger0_sort(h->data, h->used,
			sizeof(h->data[0]),
			bucket_offset_cmp, NULL);

	ret = bch2_move_data(c, &ca->copygc_pd.rate,
			     SECTORS_IN_FLIGHT_PER_DEVICE,
			     &ca->self,
			     writepoint_ptr(&ca->copygc_write_point),
			     BTREE_INSERT_USE_RESERVE,
			     ca->dev_idx,
			     copygc_pred, ca,
			     &keys_moved,
			     &sectors_moved);

	for (i = h->data; i < h->data + h->used; i++) {
		size_t bucket = sector_to_bucket(ca, i->offset);
		struct bucket_mark m = READ_ONCE(ca->buckets[bucket].mark);

		if (i->mark.gen == m.gen && bucket_sectors_used(m)) {
			sectors_not_moved += bucket_sectors_used(m);
			buckets_not_moved++;
		}
	}

	if (sectors_not_moved && !ret)
		bch_warn(c, "copygc finished but %llu/%llu sectors, %llu/%llu buckets not moved",
			 sectors_not_moved, sectors_to_move,
			 buckets_not_moved, buckets_to_move);

	trace_copygc(ca,
		     sectors_moved, sectors_not_moved,
		     buckets_to_move, buckets_not_moved);
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
