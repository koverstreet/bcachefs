/*
 * Primary bucket allocation code
 *
 * Copyright 2012 Google, Inc.
 *
 * Allocation in bcache is done in terms of buckets:
 *
 * Each bucket has associated an 8 bit gen; this gen corresponds to the gen in
 * btree pointers - they must match for the pointer to be considered valid.
 *
 * Thus (assuming a bucket has no dirty data or metadata in it) we can reuse a
 * bucket simply by incrementing its gen.
 *
 * The gens (along with the priorities; it's really the gens are important but
 * the code is named as if it's the priorities) are written in an arbitrary list
 * of buckets on disk, with a pointer to them in the journal header.
 *
 * When we invalidate a bucket, we have to write its new gen to disk and wait
 * for that write to complete before we use it - otherwise after a crash we
 * could have pointers that appeared to be good but pointed to data that had
 * been overwritten.
 *
 * Since the gens and priorities are all stored contiguously on disk, we can
 * batch this up: We fill up the free_inc list with freshly invalidated buckets,
 * call prio_write(), and when prio_write() finishes we pull buckets off the
 * free_inc list and optionally discard them.
 *
 * free_inc isn't the only freelist - if it was, we'd often to sleep while
 * priorities and gens were being written before we could allocate. c->free is a
 * smaller freelist, and buckets on that list are always ready to be used.
 *
 * If we've got discards enabled, that happens when a bucket moves from the
 * free_inc list to the free list.
 *
 * It's important to ensure that gens don't wrap around - with respect to
 * either the oldest gen in the btree or the gen on disk. This is quite
 * difficult to do in practice, but we explicitly guard against it anyways - if
 * a bucket is in danger of wrapping around we simply skip invalidating it that
 * time around, and we garbage collect or rewrite the priorities sooner than we
 * would have otherwise.
 *
 * bch_bucket_alloc() allocates a single bucket from a specific cache.
 *
 * bch_bucket_alloc_set() allocates one or more buckets from different caches
 * out of a cache set.
 *
 * invalidate_buckets() drives all the processes described above. It's called
 * from bch_bucket_alloc() and a few other places that need to make sure free
 * buckets are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <trace/events/bcachefs.h>

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree (last_gc).
 */

static inline u8 bucket_gc_gen(struct cache *ca, size_t r)
{
	return ca->bucket_gens[r] - ca->buckets[r].last_gc;
}

#define BUCKET_GC_GEN_MAX	96U

/**
 * alloc_failed - kick off external processes to free up buckets
 *
 * We couldn't find enough buckets in invalidate_buckets(). Ask
 * btree GC to run, hoping it will find more clean buckets.
 */
static void alloc_failed(struct cache *ca)
{
	struct cache_set *c = ca->set;
	unsigned i, gc_count;

	gc_count = bch_gc_count(c);

	/* Journal replay shouldn't run out of buckets, but the allocator
	 * might fail to find more buckets to invalidate once it fills up
	 * free lists. If this happens, bch_run_cache_set() will kick off
	 * a btree GC and wake us up after journal replay completes. */
	if (!test_bit(CACHE_SET_RUNNING, &c->flags))
		goto wait;

	/* Check if there are caches in higher tiers; we could potentially
	 * make room on our cache by tiering */
	for (i = CACHE_TIER(cache_member_info(ca)) + 1;
	     i < ARRAY_SIZE(c->cache_by_alloc);
	     i++)
		if (c->cache_by_alloc[i].nr_devices) {
			c->tiering_pd.rate.rate = UINT_MAX;
			bch_ratelimit_reset(&c->tiering_pd.rate);
			wake_up_process(c->tiering_read);
			trace_bcache_alloc_wake_tiering(ca);
			goto wait;
		}

	/* If this is the highest tier cache, just do a btree GC */
	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	wake_up_process(ca->moving_gc_read);
	trace_bcache_alloc_wake_moving(ca);

wait:
	mutex_unlock(&c->bucket_lock);
	bch_wait_for_next_gc(c, gc_count);
	mutex_lock(&c->bucket_lock);
}

/* Bucket heap / gen */

void bch_recalc_min_prio(struct cache *ca, int rw)
{
	struct cache_set *c = ca->set;
	struct prio_clock *clock = &c->prio_clock[rw];
	struct bucket *g;
	u16 max_delta = 1;
	unsigned i;

	/* Determine min prio for this particular cache */
	for_each_bucket(g, ca)
		max_delta = max(max_delta, (u16) (clock->hand - g->prio[rw]));

	ca->min_prio[rw] = clock->hand - max_delta;

	/*
	 * This may possibly increase the min prio for the whole cache, check
	 * that as well.
	 */
	max_delta = 1;

	for_each_cache(ca, c, i)
		max_delta = max(max_delta,
				(u16) (clock->hand - ca->min_prio[rw]));

	clock->min_prio = clock->hand - max_delta;
}

static void bch_rescale_prios(struct cache_set *c, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];
	struct cache *ca;
	struct bucket *g;
	unsigned i;

	trace_bcache_rescale_prios(c);

	for_each_cache(ca, c, i) {
		for_each_bucket(g, ca)
			g->prio[rw] = clock->hand -
				(clock->hand - g->prio[rw]) / 2;

		bch_recalc_min_prio(ca, rw);
	}
}

void bch_increment_clock_slowpath(struct cache_set *c, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];
	long next = (c->nbuckets * c->sb.bucket_size) / 1024;
	long old, v = atomic_long_read(&clock->rescale);

	do {
		old = v;
		if (old >= 0)
			return;
	} while ((v = atomic_long_cmpxchg(&clock->rescale,
					  old, old + next)) != old);

	mutex_lock(&c->bucket_lock);

	clock->hand++;

	/* if clock cannot be advanced more, rescale prio */
	if (clock->hand == (u16) (clock->min_prio - 1))
		bch_rescale_prios(c, rw);

	mutex_unlock(&c->bucket_lock);
}

/*
 * Background allocation thread: scans for buckets to be invalidated,
 * invalidates them, rewrites prios/gens (marking them as invalidated on disk),
 * then optionally issues discard commands to the newly free buckets, then puts
 * them on the various freelists.
 */

static inline bool can_inc_bucket_gen(struct cache *ca, size_t r)
{
	return bucket_gc_gen(ca, r) < BUCKET_GC_GEN_MAX;
}

static bool bch_can_invalidate_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark mark = READ_ONCE(g->mark);

	BUG_ON(!ca->set->gc_mark_valid);
	return (!mark.owned_by_allocator &&
		!mark.is_metadata &&
		!mark.dirty_sectors &&
		can_inc_bucket_gen(ca, g - ca->buckets));
}

static void __bch_invalidate_one_bucket(struct cache *ca, struct bucket *g)
{
	lockdep_assert_held(&ca->set->bucket_lock);
	BUG_ON(!bch_can_invalidate_bucket(ca, g));

	/* Ordering matters: see bch_mark_data_bucket() */

	/* this is what makes ptrs to the bucket invalid */
	ca->bucket_gens[g - ca->buckets]++;
	/* bucket mark updates imply a write barrier */
	bch_mark_alloc_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;
	g->copygc_gen = 0;
}

static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *g)
{
	__bch_invalidate_one_bucket(ca, g);
	BUG_ON(!fifo_push(&ca->free_inc, g - ca->buckets));
}

/*
 * bch_prio_init - put some unused buckets directly on the prio freelist.
 *
 * This allows the allocator thread to get started - it needs freed buckets
 * to rewrite the prios and gens, and it needs to rewrite prios and gens in
 * order to free buckets.
 *
 * This is only safe for buckets that have no live data in them, which
 * there should always be some of when this function is called.
 */
void bch_prio_init(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *g;
	unsigned i;

	mutex_lock(&c->bucket_lock);

	for_each_cache(ca, c, i) {
		for_each_bucket(g, ca) {
			if (fifo_full(&ca->free[RESERVE_PRIO]))
				break;

			if (bch_can_invalidate_bucket(ca, g) &&
			    !g->mark.cached_sectors) {
				__bch_invalidate_one_bucket(ca, g);
				fifo_push(&ca->free[RESERVE_PRIO],
					  g - ca->buckets);
			}
		}
	}

	mutex_unlock(&c->bucket_lock);
}

/*
 * Determines what order we're going to reuse buckets, smallest bucket_prio()
 * first: we also take into account the number of sectors of live data in that
 * bucket, and in order for that multiply to make sense we have to scale bucket
 *
 * Thus, we scale the bucket priorities so that the prio farthest from the clock
 * is worth 1/8th of the closest.
 */

#define bucket_prio(g)							\
({									\
	u16 prio = g->read_prio - ca->min_prio[READ];			\
	prio = (prio * 7) / (ca->set->prio_clock[READ].hand -		\
			     ca->min_prio[READ]);			\
									\
	(prio + 1) * bucket_sectors_used(g);				\
})

#define bucket_max_cmp(l, r)	(bucket_prio(l) < bucket_prio(r))
#define bucket_min_cmp(l, r)	(bucket_prio(l) > bucket_prio(r))

static void invalidate_buckets_lru(struct cache *ca)
{
	struct bucket *g;

	mutex_lock(&ca->heap_lock);

	ca->heap.used = 0;

	bch_recalc_min_prio(ca, READ);
	bch_recalc_min_prio(ca, WRITE);

	for_each_bucket(g, ca) {
		if (!bch_can_invalidate_bucket(ca, g))
			continue;

		if (!heap_full(&ca->heap))
			heap_add(&ca->heap, g, bucket_max_cmp);
		else if (bucket_max_cmp(g, heap_peek(&ca->heap))) {
			ca->heap.data[0] = g;
			heap_sift(&ca->heap, 0, bucket_max_cmp);
		}
	}

	heap_resort(&ca->heap, bucket_min_cmp);

	while (!fifo_full(&ca->free_inc)) {
		if (!heap_pop(&ca->heap, g, bucket_min_cmp)) {
			/*
			 * We don't want to be calling invalidate_buckets()
			 * multiple times when it can't do anything
			 */
			mutex_unlock(&ca->heap_lock);
			alloc_failed(ca);
			return;
		}

		bch_invalidate_one_bucket(ca, g);
	}

	mutex_unlock(&ca->heap_lock);
}

static void invalidate_buckets_fifo(struct cache *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->sb.first_bucket ||
		    ca->fifo_last_bucket >= ca->sb.nbuckets)
			ca->fifo_last_bucket = ca->sb.first_bucket;

		g = ca->buckets + ca->fifo_last_bucket++;

		if (bch_can_invalidate_bucket(ca, g))
			bch_invalidate_one_bucket(ca, g);

		if (++checked >= ca->sb.nbuckets) {
			alloc_failed(ca);
			return;
		}
	}
}

static void invalidate_buckets_random(struct cache *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n;
		get_random_bytes(&n, sizeof(n));

		n %= (size_t) (ca->sb.nbuckets - ca->sb.first_bucket);
		n += ca->sb.first_bucket;

		g = ca->buckets + n;

		if (bch_can_invalidate_bucket(ca, g))
			bch_invalidate_one_bucket(ca, g);

		if (++checked >= ca->sb.nbuckets / 2) {
			alloc_failed(ca);
			return;
		}
	}
}

static void invalidate_buckets(struct cache *ca)
{
	BUG_ON(!ca->set->gc_mark_valid);

	switch (CACHE_REPLACEMENT(cache_member_info(ca))) {
	case CACHE_REPLACEMENT_LRU:
		invalidate_buckets_lru(ca);
		break;
	case CACHE_REPLACEMENT_FIFO:
		invalidate_buckets_fifo(ca);
		break;
	case CACHE_REPLACEMENT_RANDOM:
		invalidate_buckets_random(ca);
		break;
	}
}

#define allocator_wait(c, x, cond)					\
do {									\
	DEFINE_WAIT(__wait);						\
	while (1) {							\
		prepare_to_wait(&x, &__wait, TASK_INTERRUPTIBLE);	\
		if (cond)						\
			break;						\
									\
		mutex_unlock(&c->bucket_lock);				\
		if (kthread_should_stop())				\
			return 0;					\
		try_to_freeze();					\
		schedule();						\
		mutex_lock(&c->bucket_lock);				\
	}								\
	finish_wait(&x, &__wait);					\
} while (0)

static int bch_allocator_push(struct cache *ca, long bucket)
{
	unsigned i;

	/* Prios/gens are actually the most important reserve */
	if (fifo_push(&ca->free[RESERVE_PRIO], bucket))
		return true;

	for (i = 0; i < RESERVE_NR; i++)
		if (fifo_push(&ca->free[i], bucket))
			return true;

	return false;
}

/**
 * bch_allocator_thread - move buckets from free_inc to reserves
 *
 * The free_inc FIFO is populated by invalidate_buckets(), and
 * the reserves are depleted by bucket allocation. When we run out
 * of free_inc, try to invalidate some buckets and write out
 * prios and gens.
 */
static int bch_allocator_thread(void *arg)
{
	struct cache *ca = arg;
	struct cache_set *c = ca->set;

	mutex_lock(&c->bucket_lock);

	while (1) {
		/*
		 * First, we pull buckets off of the free_inc list, possibly
		 * issue discards to them, then we add the bucket to a
		 * free list:
		 */
		while (!fifo_empty(&ca->free_inc)) {
			long bucket = fifo_peek(&ca->free_inc);

			/*
			 * Don't remove from free_inc until after it's added
			 * to freelist, so gc doesn't miss it while we've
			 * dropped bucket lock
			 */

			if (CACHE_DISCARD(cache_member_info(ca)) &&
			    blk_queue_discard(bdev_get_queue(ca->bdev))) {
				mutex_unlock(&c->bucket_lock);
				blkdev_issue_discard(ca->bdev,
					bucket_to_sector(c, bucket),
					ca->sb.bucket_size, GFP_KERNEL, 0);
				mutex_lock(&c->bucket_lock);
			}

			/*
			 * Wait for someone to allocate a bucket if all
			 * reserves are full:
			 */
			allocator_wait(c, ca->fifo_wait,
					bch_allocator_push(ca, bucket));
			fifo_pop(&ca->free_inc, bucket);

			closure_wake_up(&c->bucket_wait);
		}

		/* We've run out of free buckets! */

retry_invalidate:
		/* Wait for in-progress GC to finish if there is one */
		allocator_wait(c, c->gc_wait, c->gc_mark_valid);

		/*
		 * Find some buckets that we can invalidate, either they're
		 * completely unused, or only contain clean data that's been
		 * written back to the backing device or another cache tier
		 */
		invalidate_buckets(ca);

		if (CACHE_SYNC(&ca->set->sb)) {
			trace_bcache_alloc_batch(ca,
						fifo_used(&ca->free_inc),
						ca->free_inc.size);

			/*
			 * If we didn't invalidate enough buckets to fill up
			 * free_inc, try to invalidate some more. This will
			 * limit the amount of metadata writes we issue below
			 */
			if (!fifo_full(&ca->free_inc))
				goto retry_invalidate;

			/*
			 * free_inc is full of newly-invalidated buckets, must
			 * write out prios and gens before they can be re-used
			 */
			bch_prio_write(ca);
		}
	}
}

/* Allocation */

int bch_bucket_wait(struct cache_set *c, enum alloc_reserve reserve,
		    struct closure *cl)
{
	lockdep_assert_held(&c->bucket_lock);

	/* If we're waiting on buckets in one of these special reserves,
	 * it means tiering or moving GC is out of space. In this case, we
	 * kick btree GC immediately. Usually the allocator thread is
	 * responsible for kicking btree GC, but in this case it might be
	 * waiting for us to make progress, so we have to do this ourselves
	 * to avoid deadlock. */
	switch (reserve) {
	case RESERVE_MOVINGGC:
	case RESERVE_MOVINGGC_BTREE:
	case RESERVE_TIERING_BTREE:
		wake_up_gc(c, true);
		break;
	default:
		break;
	}

	if (cl) {
		closure_wait(&c->bucket_wait, cl);
		return -EAGAIN;
	}

	return -ENOSPC;
}

long bch_bucket_alloc(struct cache *ca, enum alloc_reserve reserve,
		      struct closure *cl)
{
	struct cache_member *mi = cache_member_info(ca);
	bool meta = reserve <= RESERVE_METADATA_LAST;
	struct bucket *g;
	long r;

	lockdep_assert_held(&ca->set->bucket_lock);

	/* fastpath */
	if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
	    fifo_pop(&ca->free[reserve], r))
		goto out;

	trace_bcache_bucket_alloc_fail(ca, reserve, cl);

	return bch_bucket_wait(ca->set, reserve, cl);

out:
	wake_up(&ca->fifo_wait);

	trace_bcache_bucket_alloc(ca, reserve, cl);

	if (expensive_debug_checks(ca->set)) {
		size_t iter;
		long i;
		unsigned j;

		for (iter = 0; iter < prio_buckets(ca) * 2; iter++)
			BUG_ON(ca->prio_buckets[iter] == (uint64_t) r);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				BUG_ON(i == r);
		fifo_for_each(i, &ca->free_inc, iter)
			BUG_ON(i == r);
	}

	g = ca->buckets + r;

	if (meta)
		bch_mark_metadata_bucket(ca, g);

	if (reserve != RESERVE_PRIO &&
	    !(meta ? CACHE_HAS_METADATA : CACHE_HAS_DATA)(mi)) {
		(meta
		 ? SET_CACHE_HAS_METADATA
		 : SET_CACHE_HAS_DATA)(mi, true);

		bcache_write_super(ca->set);
	}

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;

	return r;
}

void __bch_bucket_free(struct cache *ca, struct bucket *g)
{
	lockdep_assert_held(&ca->set->bucket_lock);

	bch_mark_free_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;
}

void bch_bucket_free(struct cache_set *c, struct bkey *k)
{
	struct cache *ca;
	unsigned i;

	mutex_lock(&c->bucket_lock);
	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i)))
			__bch_bucket_free(ca, PTR_BUCKET(c, ca, k, i));

	rcu_read_unlock();
	mutex_unlock(&c->bucket_lock);
}

static void bch_bucket_free_never_used(struct cache_set *c, struct bkey *k)
{
	struct cache *ca;
	struct bucket *g;
	unsigned i;
	long r;

	mutex_lock(&c->bucket_lock);
	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i))) {
			r = PTR_BUCKET_NR(c, k, i);
			g = PTR_BUCKET(c, ca, k, i);

			if (!bch_allocator_push(ca, r))
				__bch_bucket_free(ca, g);
			else
				bch_mark_alloc_bucket(ca, g);
		}

	bch_set_extent_ptrs(k, 0);

	rcu_read_unlock();
	mutex_unlock(&c->bucket_lock);
}

static struct cache *bch_next_cache(struct cache_set *c,
				    enum alloc_reserve reserve,
				    int tier_idx, long *cache_used,
				    struct closure *cl)
{
	struct cache *device, **devices;
	size_t bucket_count = 0, rand;
	int i, nr_devices;

	/* first ptr allocation will always go to the specified tier,
	 * 2nd and greater can go to any. If one tier is significantly larger
	 * it is likely to go that tier. */

	if (tier_idx == -1) {
		/*
		 * Cast away __rcu - don't need rcu_dereference() because
		 * bucket_lock held
		 */
		devices = (struct cache **) c->cache;
		nr_devices = c->sb.nr_in_set;
	} else {
		struct cache_tier *tier = &c->cache_by_alloc[tier_idx];

		devices = tier->devices;
		nr_devices = tier->nr_devices;
	}

	for (i = 0; i < nr_devices; i++) {
		if (!devices[i])
			continue;

		if (test_bit(devices[i]->sb.nr_this_dev, cache_used))
			continue;

		bucket_count += buckets_free_cache(devices[i], reserve);
	}

	if (!bucket_count) {
		trace_bcache_bucket_alloc_set_fail(c, reserve, cl);
		return ERR_PTR(bch_bucket_wait(c, reserve, cl));
	}

	/*
	 * We create a weighted selection by using the number of free buckets
	 * in each cache. You can think of this like lining up the caches
	 * linearly so each as a given range, corresponding to the number of
	 * free buckets in that cache, and then randomly picking a number
	 * within that range.
	 */

	get_random_bytes(&rand, sizeof(rand));
	rand %= bucket_count;

	device = NULL;

	for (i = 0; i < nr_devices; i++) {
		if (!devices[i])
			continue;

		if (test_bit(devices[i]->sb.nr_this_dev, cache_used))
			continue;

		device = devices[i];
		bucket_count -= buckets_free_cache(device, reserve);

		if (rand >= bucket_count) {
			__set_bit(device->sb.nr_this_dev, cache_used);
			return device;
		}
	}

	/* If the bucket free counters changed while we were running, we might
	 * fall off the end, so just return the last cache device */
	__set_bit(device->sb.nr_this_dev, cache_used);
	return device;
}

int bch_bucket_alloc_set(struct cache_set *c, enum alloc_reserve reserve,
			 struct bkey *k, int n, unsigned tier_idx,
			 struct closure *cl)
{
	long caches_used[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	int i, ret;

	BUG_ON(tier_idx > ARRAY_SIZE(c->cache_by_alloc));
	BUG_ON(!n || n > BKEY_EXTENT_PTRS_MAX);

	bkey_init(k);
	memset(caches_used, 0, sizeof(caches_used));

	mutex_lock(&c->bucket_lock);

	/* sort by free space/prio of oldest data in caches */

	for (i = 0; i < n; i++) {
		struct cache *ca;
		long r;

		/* first ptr goes to the specified tier, the rest to any */
		ca = bch_next_cache(c, reserve, i == 0 ? tier_idx : -1,
				    caches_used, cl);

		if (IS_ERR_OR_NULL(ca)) {
			BUG_ON(!ca);
			ret = PTR_ERR(ca);
			goto err;
		}

		r = bch_bucket_alloc(ca, reserve, cl);
		if (r < 0) {
			ret = r;
			goto err;
		}

		k->val[i] = PTR(ca->bucket_gens[r],
				bucket_to_sector(c, r),
				ca->sb.nr_this_dev);

		bch_set_extent_ptrs(k, i + 1);
	}

	mutex_unlock(&c->bucket_lock);
	return 0;
err:
	mutex_unlock(&c->bucket_lock);
	bch_bucket_free_never_used(c, k);
	return ret;
}

static void __bch_open_bucket_put(struct cache_set *c, struct open_bucket *b)
{
	struct bkey *k = &b->key;
	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&c->open_buckets_lock);

	rcu_read_lock();
	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i)))
			bch_unmark_open_bucket(ca, PTR_BUCKET(c, ca, k, i));
	rcu_read_unlock();

	list_move(&b->list, &c->open_buckets_free);
	c->open_buckets_nr_free++;
	closure_wake_up(&c->open_buckets_wait);
}

void bch_open_bucket_put(struct cache_set *c, struct open_bucket *b)
{
	if (atomic_dec_and_test(&b->pin)) {
		spin_lock(&c->open_buckets_lock);
		__bch_open_bucket_put(c, b);
		spin_unlock(&c->open_buckets_lock);
	}
}

static struct open_bucket *bch_open_bucket_get(struct cache_set *c,
					       struct closure *cl)
{
	struct open_bucket *ret;

	spin_lock(&c->open_buckets_lock);

	if (c->open_buckets_nr_free) {
		BUG_ON(list_empty(&c->open_buckets_free));
		ret = list_first_entry(&c->open_buckets_free,
				       struct open_bucket, list);
		list_move(&ret->list, &c->open_buckets_open);
		atomic_set(&ret->pin, 1);
		ret->sectors_free = c->sb.bucket_size;
		bkey_init(&ret->key);
		c->open_buckets_nr_free--;
		trace_bcache_open_bucket_alloc(c, cl);
	} else {
		trace_bcache_open_bucket_alloc_fail(c, cl);

		if (cl) {
			closure_wait(&c->open_buckets_wait, cl);
			ret = ERR_PTR(-EAGAIN);
		} else
			ret = ERR_PTR(-ENOSPC);
	}

	spin_unlock(&c->open_buckets_lock);

	return ret;
}

static struct open_bucket *bch_open_bucket_alloc(struct cache_set *c,
						 struct write_point *wp,
						 struct closure *cl)
{
	int ret;
	struct open_bucket *b;

	b = bch_open_bucket_get(c, cl);
	if (IS_ERR_OR_NULL(b))
		return b;

	if (wp->ca) {
		long bucket;

		mutex_lock(&c->bucket_lock);

		bucket = bch_bucket_alloc(wp->ca, RESERVE_MOVINGGC, cl);
		if (bucket < 0) {
			ret = bucket;
			mutex_unlock(&c->bucket_lock);
			goto err;
		}

		b->key.val[0] = PTR(wp->ca->bucket_gens[bucket],
				    bucket_to_sector(wp->ca->set, bucket),
				    wp->ca->sb.nr_this_dev);
		bch_set_extent_ptrs(&b->key, 1);

		mutex_unlock(&c->bucket_lock);
	} else if (wp->tier) {
		ret = bch_bucket_alloc_set(c, RESERVE_NONE, &b->key, 1,
					   wp->tier - c->cache_by_alloc, cl);
		if (ret)
			goto err;
	} else {
		ret = bch_bucket_alloc_set(c, RESERVE_NONE, &b->key,
				CACHE_SET_DATA_REPLICAS_WANT(&c->sb),
				0, cl);
		if (ret)
			goto err;
	}

	return b;
err:
	bch_open_bucket_put(c, b);
	return ERR_PTR(ret);
}

/* Sector allocator */

static struct open_bucket *lock_and_refill_writepoint(struct cache_set *c,
						      struct write_point *wp,
						      struct closure *cl)
{
	struct open_bucket *b;

	while (1) {
		b = ACCESS_ONCE(wp->b);
		if (b) {
			spin_lock(&b->lock);
			if (wp->b == b)
				return b;

			spin_unlock(&b->lock);
		} else {
			b = bch_open_bucket_alloc(c, wp, cl);
			if (IS_ERR_OR_NULL(b))
				return b;

			spin_lock(&b->lock);
			if (!race_fault() &&
			    cmpxchg(&wp->b, NULL, b) == NULL)
				return b;
			spin_unlock(&b->lock);

			bch_bucket_free_never_used(c, &b->key);
			bch_open_bucket_put(c, b);
		}
	}
}

static void verify_not_stale(struct cache_set *c, struct bkey *k)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct cache *ca;
	unsigned ptr;

	rcu_read_lock();
	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++)
		if ((ca = PTR_CACHE(c, k, ptr)))
			BUG_ON(ptr_stale(c, ca, k, ptr));
	rcu_read_unlock();
#endif
}

/*
 * Allocates some space in the cache to write to, and k to point to the newly
 * allocated space, and updates KEY_SIZE(k) and KEY_OFFSET(k) (to point to the
 * end of the newly allocated space).
 *
 * May allocate fewer sectors than @sectors, KEY_SIZE(k) indicates how many
 * sectors were actually allocated.
 *
 * Return codes:
 * - -EAGAIN: closure was added to waitlist
 * - -ENOSPC: out of space and no closure provided
 *
 * @write_point - opaque identifier of where this write came from.
 *		  bcache uses ptr address of the task struct
 * @tier_idx - which tier this write is destined towards
 * @cl - closure to wait for a bucket
 */
struct open_bucket *bch_alloc_sectors(struct cache_set *c,
				      struct write_point *wp,
				      struct bkey *k,
				      struct closure *cl)
{
	struct open_bucket *b;
	unsigned i, sectors;

	b = lock_and_refill_writepoint(c, wp, cl);
	if (IS_ERR_OR_NULL(b))
		return b;

	BUG_ON(!b->sectors_free);

	verify_not_stale(c, &b->key);

	/* Set up the pointer to the space we're allocating: */
	memcpy(&k->val[bch_extent_ptrs(k)],
	       &b->key.val[0],
	       bch_extent_ptrs(&b->key) * sizeof(u64));

	bch_set_extent_ptrs(k, bch_extent_ptrs(k) + bch_extent_ptrs(&b->key));

	sectors = min_t(unsigned, KEY_SIZE(k), b->sectors_free);

	SET_KEY_OFFSET(k, KEY_START(k) + sectors);
	SET_KEY_SIZE(k, sectors);

	/* update open bucket for next time: */

	b->sectors_free	-= sectors;
	if (b->sectors_free)
		atomic_inc(&b->pin);
	else
		BUG_ON(xchg(&wp->b, NULL) != b);

	rcu_read_lock();
	for (i = 0; i < bch_extent_ptrs(&b->key); i++) {
		struct cache *ca;

		if (b->sectors_free)
			SET_PTR_OFFSET(&b->key, i,
				       PTR_OFFSET(&b->key, i) + sectors);

		if ((ca = PTR_CACHE(c, &b->key, i)))
			atomic_long_add(sectors, &ca->sectors_written);
	}
	rcu_read_unlock();

	spin_unlock(&b->lock);

	return b;
}

void bch_mark_open_buckets(struct cache_set *c)
{
	struct cache *ca;
	struct open_bucket *b;
	size_t i, j, iter;
	unsigned ci;

	lockdep_assert_held(&c->bucket_lock);

	for_each_cache(ca, c, ci) {
		for (i = 0; i < prio_buckets(ca) * 2; i++)
			if (ca->prio_buckets[i])
				bch_mark_alloc_bucket(ca,
					&ca->buckets[ca->prio_buckets[i]]);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				bch_mark_alloc_bucket(ca,
					&ca->buckets[i]);

		fifo_for_each(i, &ca->free_inc, iter)
			bch_mark_alloc_bucket(ca,
				&ca->buckets[i]);
	}

	spin_lock(&c->open_buckets_lock);
	rcu_read_lock();

	list_for_each_entry(b, &c->open_buckets_open, list)
		for (i = 0; i < bch_extent_ptrs(&b->key); i++)
			if ((ca = PTR_CACHE(c, &b->key, i)))
				bch_mark_alloc_bucket(ca,
					      PTR_BUCKET(c, ca, &b->key, i));

	rcu_read_unlock();
	spin_unlock(&c->open_buckets_lock);
}

/* Init */

void bch_open_buckets_init(struct cache_set *c)
{
	unsigned i;

	INIT_LIST_HEAD(&c->open_buckets_open);
	INIT_LIST_HEAD(&c->open_buckets_free);
	spin_lock_init(&c->open_buckets_lock);

	for (i = 0; i < ARRAY_SIZE(c->open_buckets); i++) {
		spin_lock_init(&c->open_buckets[i].lock);
		c->open_buckets_nr_free++;
		list_add(&c->open_buckets[i].list, &c->open_buckets_free);
	}

	for (i = 0; i < ARRAY_SIZE(c->cache_by_alloc); i++)
		c->cache_by_alloc[i].wp.tier = &c->cache_by_alloc[i];
}

int bch_cache_allocator_start(struct cache *ca)
{
	struct task_struct *k = kthread_run(bch_allocator_thread,
					    ca, "bcache_allocator");
	if (IS_ERR(k))
		return PTR_ERR(k);

	ca->alloc_thread = k;
	return 0;
}
