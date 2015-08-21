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
#include "io.h"
#include "journal.h"
#include "super.h"

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

/* Allocation groups: */

void bch_cache_group_remove_cache(struct cache_group *grp, struct cache *ca)
{
	unsigned i;

	write_seqcount_begin(&grp->lock);

	for (i = 0; i < grp->nr_devices; i++)
		if (grp->devices[i] == ca) {
			grp->nr_devices--;
			memmove(&grp->devices[i],
				&grp->devices[i + 1],
				(grp->nr_devices - i) * sizeof(ca));
			break;
		}

	write_seqcount_end(&grp->lock);
}

void bch_cache_group_add_cache(struct cache_group *grp, struct cache *ca)
{
	write_seqcount_begin(&grp->lock);
	BUG_ON(grp->nr_devices >= MAX_CACHES_PER_SET);

	rcu_assign_pointer(grp->devices[grp->nr_devices++], ca);
	write_seqcount_end(&grp->lock);
}

/*
 * Bucket priorities/gens:
 *
 * For each bucket, we store on disk its
   * 8 bit gen
   * 16 bit priority
 *
 * See alloc.c for an explanation of the gen. The priority is used to implement
 * lru (and in the future other) cache replacement policies; for most purposes
 * it's just an opaque integer.
 *
 * The gens and the priorities don't have a whole lot to do with each other, and
 * it's actually the gens that must be written out at specific times - it's no
 * big deal if the priorities don't get written, if we lose them we just reuse
 * buckets in suboptimal order.
 *
 * On disk they're stored in a packed array, and in as many buckets are required
 * to fit them all. The buckets we use to store them form a list; the journal
 * header points to the first bucket, the first bucket points to the second
 * bucket, et cetera.
 *
 * This code is used by the allocation code; periodically (whenever it runs out
 * of buckets to allocate from) the allocation code will invalidate some
 * buckets, but it can't use those buckets until their new gens are safely on
 * disk.
 */

static int prio_io(struct cache *ca, uint64_t bucket, int op)
{
	struct bio *bio = bch_bbio_alloc(ca->set);
	int ret;

	bio->bi_iter.bi_sector	= bucket * ca->sb.bucket_size;
	bio->bi_bdev		= ca->bdev;
	bio->bi_iter.bi_size	= bucket_bytes(ca);
	bio_set_op_attrs(bio, op, REQ_SYNC|REQ_META);
	bch_bio_map(bio, ca->disk_buckets);

	ret = submit_bio_wait(bio);

	bch_bbio_free(bio, ca->set);
	return ret;
}

static void bch_prio_write(struct cache *ca)
{
	int i, ret;
	struct closure cl;

	closure_init_stack(&cl);

	trace_bcache_prio_write_start(ca);

	atomic_long_add(ca->sb.bucket_size * prio_buckets(ca),
			&ca->meta_sectors_written);

	for (i = prio_buckets(ca) - 1; i >= 0; --i) {
		long r;
		struct bucket *g;
		struct prio_set *p = ca->disk_buckets;
		struct bucket_disk *d = p->data;
		struct bucket_disk *end = d + prios_per_bucket(ca);

		for (r = i * prios_per_bucket(ca);
		     r < ca->sb.nbuckets && d < end;
		     r++, d++) {
			g = ca->buckets + r;
			d->read_prio = cpu_to_le16(g->read_prio);
			d->write_prio = cpu_to_le16(g->write_prio);
			d->gen = ca->bucket_gens[r];
		}

		p->next_bucket	= ca->prio_buckets[i + 1];
		p->magic	= pset_magic(&ca->sb);

		SET_PSET_CSUM_TYPE(p, CACHE_PREFERRED_CSUM_TYPE(&ca->set->sb));
		p->csum		= bch_checksum(PSET_CSUM_TYPE(p),
					       &p->magic,
					       bucket_bytes(ca) - 8);

		spin_lock(&ca->prio_buckets_lock);
		r = bch_bucket_alloc(ca, RESERVE_PRIO);
		BUG_ON(r < 0);

		/*
		 * goes here before dropping prio_buckets_lock to guard against
		 * it getting gc'd from under us
		 */
		ca->prio_buckets[i] = r;
		spin_unlock(&ca->prio_buckets_lock);

		ret = prio_io(ca, r, REQ_OP_WRITE);
		cache_set_err_on(ret, ca->set, "writing priorities");
	}

	spin_lock(&ca->prio_buckets_lock);
	ca->prio_journal_bucket = ca->prio_buckets[0];
	spin_unlock(&ca->prio_buckets_lock);

	bch_journal_meta(ca->set, &cl);
	closure_sync(&cl);

	/*
	 * Don't want the old priorities to get garbage collected until after we
	 * finish writing the new ones, and they're journalled
	 */

	spin_lock(&ca->prio_buckets_lock);

	for (i = 0; i < prio_buckets(ca); i++) {
		if (ca->prio_last_buckets[i])
			__bch_bucket_free(ca,
				&ca->buckets[ca->prio_last_buckets[i]]);

		ca->prio_last_buckets[i] = ca->prio_buckets[i];
	}

	spin_unlock(&ca->prio_buckets_lock);

	trace_bcache_prio_write_end(ca);
}

const char *prio_read(struct cache *ca, u64 bucket)
{
	struct prio_set *p = ca->disk_buckets;
	struct bucket_disk *d = p->data + prios_per_bucket(ca), *end = d;
	size_t b;
	unsigned bucket_nr = 0;

	if (cache_set_init_fault("prio_read"))
		return "prio_read() dynamic fault";

	ca->prio_journal_bucket = bucket;

	for (b = 0; b < ca->sb.nbuckets; b++, d++) {
		if (d == end) {
			ca->prio_last_buckets[bucket_nr] = bucket;
			bucket_nr++;

			if (prio_io(ca, bucket, REQ_OP_READ))
				return "IO error reading priorities";

			if (p->magic != pset_magic(&ca->sb))
				return "bad magic reading priorities";

			if (p->csum != bch_checksum(PSET_CSUM_TYPE(p),
						    &p->magic,
						    bucket_bytes(ca) - 8))
				return "bad csum reading priorities";

			bucket = p->next_bucket;
			d = p->data;
		}

		ca->buckets[b].read_prio = le16_to_cpu(d->read_prio);
		ca->buckets[b].write_prio = le16_to_cpu(d->write_prio);
		ca->buckets[b].last_gc = d->gen;
		ca->bucket_gens[b] = d->gen;
	}

	return NULL;
}

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
 * wait_buckets_available - wait on reclaimable buckets
 *
 * If there aren't enough available buckets for invalidate_buckets(), kick
 * various things and wait.
 */
static int wait_buckets_available(struct cache *ca)
{
	struct cache_set *c = ca->set;
	unsigned i;
	int ret = 0;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			ret = -1;
			break;
		}

		if (ca->inc_gen_needs_gc > ca->free_inc.size) {
			if (c->gc_thread)
				wake_up_process(c->gc_thread);
			goto wait;
		}

		if (buckets_available_cache(ca) >= fifo_free(&ca->free_inc))
			break;

		/*
		 * Journal replay shouldn't run out of buckets, but the
		 * allocator might fail to find more buckets to invalidate once
		 * it fills up free lists.
		 */
		if (!test_bit(CACHE_SET_RUNNING, &c->flags))
			goto wait;

		if (atomic_long_read(&ca->saturated_count) >=
		    ca->free_inc.size << c->bucket_bits)
			wake_up_process(c->gc_thread);

		/*
		 * Check if there are caches in higher tiers; we could
		 * potentially make room on our cache by tiering
		 */
		for (i = CACHE_TIER(cache_member_info(ca)) + 1;
		     i < ARRAY_SIZE(c->cache_tiers);
		     i++)
			if (c->cache_tiers[i].nr_devices) {
				c->tiering_pd.rate.rate = UINT_MAX;
				bch_ratelimit_reset(&c->tiering_pd.rate);
				wake_up_process(c->tiering_read);
				trace_bcache_alloc_wake_tiering(ca);
			}

		/* If this is the highest tier cache, just do a btree GC */
		ca->moving_gc_pd.rate.rate = UINT_MAX;
		bch_ratelimit_reset(&ca->moving_gc_pd.rate);
		wake_up_process(ca->moving_gc_read);
		trace_bcache_alloc_wake_moving(ca);
wait:
		up_read(&c->gc_lock);
		schedule();
		down_read(&c->gc_lock);
	}

	__set_current_state(TASK_RUNNING);
	return ret;
}

static void verify_not_on_freelist(struct cache *ca, size_t bucket)
{
	if (expensive_debug_checks(ca->set)) {
		size_t iter;
		long i;
		unsigned j;

		for (iter = 0; iter < prio_buckets(ca) * 2; iter++)
			BUG_ON(ca->prio_buckets[iter] == bucket);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				BUG_ON(i == bucket);
		fifo_for_each(i, &ca->free_inc, iter)
			BUG_ON(i == bucket);
	}
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
	long next = c->capacity >> 10;
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
	if (!is_available_bucket(READ_ONCE(g->mark)))
		return false;

	if (!can_inc_bucket_gen(ca, g - ca->buckets)) {
		ca->inc_gen_needs_gc++;
		return false;
	}

	return true;
}

static void __bch_invalidate_one_bucket(struct cache *ca, struct bucket *g)
{
	lockdep_assert_held(&ca->freelist_lock);
	BUG_ON(!bch_can_invalidate_bucket(ca, g));

	/* Ordering matters: see bch_mark_data_bucket() */

	/* this is what makes ptrs to the bucket invalid */
	ca->bucket_gens[g - ca->buckets]++;
	/* bucket mark updates imply a write barrier */
	bch_mark_alloc_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;
	g->copygc_gen = 0;

	verify_not_on_freelist(ca, g - ca->buckets);
}

static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *g)
{
	spin_lock(&ca->freelist_lock);
	__bch_invalidate_one_bucket(ca, g);
	BUG_ON(!fifo_push(&ca->free_inc, g - ca->buckets));
	spin_unlock(&ca->freelist_lock);
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

static void invalidate_buckets_lru(struct cache *ca)
{
	struct bucket_heap_entry e;
	struct bucket *g;

	mutex_lock(&ca->heap_lock);

	ca->heap.used = 0;

	mutex_lock(&ca->set->bucket_lock);
	bch_recalc_min_prio(ca, READ);
	bch_recalc_min_prio(ca, WRITE);

	/*
	 * Find buckets with lowest read priority, by building a maxheap sorted
	 * by read priority and repeatedly replacing the maximum element until
	 * all buckets have been visited.
	 */
	for_each_bucket(g, ca) {
		if (!bch_can_invalidate_bucket(ca, g))
			continue;

		bucket_heap_push(ca, g, bucket_prio(g));
	}

	/* Sort in increasing order */
	heap_resort(&ca->heap, bucket_max_cmp);

	/*
	 * If we run out of buckets to invalidate, bch_allocator_thread() will
	 * kick stuff and retry us
	 */
	while (!fifo_full(&ca->free_inc) &&
	       heap_pop(&ca->heap, e, bucket_max_cmp))
		bch_invalidate_one_bucket(ca, e.g);

	mutex_unlock(&ca->set->bucket_lock);
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

		if (++checked >= ca->sb.nbuckets)
			return;
	}
}

static void invalidate_buckets_random(struct cache *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n = bch_rand_range(ca->sb.nbuckets -
					  ca->sb.first_bucket) +
			ca->sb.first_bucket;

		g = ca->buckets + n;

		if (bch_can_invalidate_bucket(ca, g))
			bch_invalidate_one_bucket(ca, g);

		if (++checked >= ca->sb.nbuckets / 2)
			return;
	}
}

static void invalidate_buckets(struct cache *ca)
{
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

static bool __bch_allocator_push(struct cache *ca, long bucket)
{
	unsigned i;

	/* Prios/gens are actually the most important reserve */
	if (fifo_push(&ca->free[RESERVE_PRIO], bucket))
		goto success;

	for (i = 0; i < RESERVE_NR; i++)
		if (fifo_push(&ca->free[i], bucket))
			goto success;

	return false;
success:
	closure_wake_up(&ca->set->bucket_wait);
	return true;
}

static bool bch_allocator_push(struct cache *ca, long bucket)
{
	bool ret;

	spin_lock(&ca->freelist_lock);
	ret = __bch_allocator_push(ca, bucket);
	if (ret)
		fifo_pop(&ca->free_inc, bucket);
	spin_unlock(&ca->freelist_lock);

	return ret;
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
			    blk_queue_discard(bdev_get_queue(ca->bdev)))
				blkdev_issue_discard(ca->bdev,
					bucket_to_sector(c, bucket),
					ca->sb.bucket_size, GFP_KERNEL, 0);

			while (1) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (bch_allocator_push(ca, bucket))
					break;

				if (kthread_should_stop())
					goto out;
				schedule();
			}

			__set_current_state(TASK_RUNNING);
		}

		/* We've run out of free buckets! */

		down_read(&c->gc_lock);

		do {
			if (wait_buckets_available(ca)) {
				up_read(&c->gc_lock);
				goto out;
			}

			/*
			 * Find some buckets that we can invalidate, either
			 * they're completely unused, or only contain clean data
			 * that's been written back to the backing device or
			 * another cache tier
			 */

			invalidate_buckets(ca);
			trace_bcache_alloc_batch(ca, fifo_used(&ca->free_inc),
						 ca->free_inc.size);
		} while (!fifo_full(&ca->free_inc));

		up_read(&c->gc_lock);

		/*
		 * free_inc is full of newly-invalidated buckets, must write out
		 * prios and gens before they can be re-used
		 */
		if (CACHE_SYNC(&ca->set->sb))
			bch_prio_write(ca);
	}
out:
	/*
	 * Avoid a race with bucket_stats_update() trying to wake us up after
	 * we've exited:
	 */
	synchronize_rcu();
	return 0;
}

/* Allocation */

long bch_bucket_alloc(struct cache *ca, enum alloc_reserve reserve)
{
	bool meta = reserve <= RESERVE_METADATA_LAST;
	struct bucket *g;
	long r;

	spin_lock(&ca->freelist_lock);
	if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
	    fifo_pop(&ca->free[reserve], r))
		goto out;

	spin_unlock(&ca->freelist_lock);
	return -ENOSPC;
out:
	verify_not_on_freelist(ca, r);
	trace_bcache_bucket_alloc(ca, reserve);
	spin_unlock(&ca->freelist_lock);

	bch_wake_allocator(ca);

	g = ca->buckets + r;

	if (meta)
		bch_mark_metadata_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;

	return r;
}

void __bch_bucket_free(struct cache *ca, struct bucket *g)
{
	bch_mark_free_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;
}

void bch_bucket_free(struct cache_set *c, struct bkey *k)
{
	struct cache *ca;
	unsigned i;

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i)))
			__bch_bucket_free(ca, PTR_BUCKET(c, ca, k, i));

	rcu_read_unlock();
}

static void bch_bucket_free_never_used(struct cache_set *c, struct bkey *k)
{
	struct cache *ca;
	struct bucket *g;
	unsigned i;
	long r;

	rcu_read_lock();

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if ((ca = PTR_CACHE(c, k, i))) {
			r = PTR_BUCKET_NR(c, k, i);
			g = PTR_BUCKET(c, ca, k, i);

			spin_lock(&ca->freelist_lock);
			verify_not_on_freelist(ca, r);

			if (__bch_allocator_push(ca, r))
				bch_mark_alloc_bucket(ca, g);
			else
				__bch_bucket_free(ca, g);
			spin_unlock(&ca->freelist_lock);
		}

	bch_set_extent_ptrs(k, 0);

	rcu_read_unlock();
}

static struct cache *bch_next_cache(struct cache_set *c,
				    enum alloc_reserve reserve,
				    struct cache_group *devs,
				    long *cache_used)
{
	struct cache *ca;
	size_t bucket_count = 0, rand;
	unsigned i;

	/*
	 * first ptr allocation will always go to the specified tier,
	 * 2nd and greater can go to any. If one tier is significantly larger
	 * it is likely to go that tier.
	 */

	for (i = 0; i < devs->nr_devices; i++) {
		if (!(ca = rcu_dereference(devs->devices[i])))
			continue;

		if (test_bit(ca->sb.nr_this_dev, cache_used))
			continue;

		bucket_count += buckets_free_cache(ca, reserve);
	}

	if (!bucket_count)
		return ERR_PTR(-ENOSPC);

	/*
	 * We create a weighted selection by using the number of free buckets
	 * in each cache. You can think of this like lining up the caches
	 * linearly so each as a given range, corresponding to the number of
	 * free buckets in that cache, and then randomly picking a number
	 * within that range.
	 */

	rand = bch_rand_range(bucket_count);

	for (i = 0; i < devs->nr_devices; i++) {
		if (!(ca = rcu_dereference(devs->devices[i])))
			continue;

		if (test_bit(ca->sb.nr_this_dev, cache_used))
			continue;

		bucket_count -= buckets_free_cache(ca, reserve);

		if (rand >= bucket_count)
			return ca;
	}

	/*
	 * If we fall off the end, it means we raced because of bucket counters
	 * changing - return NULL so __bch_bucket_alloc_set() knows to retry
	 */

	return NULL;
}

static int __bch_bucket_alloc_set(struct cache_set *c,
				  enum alloc_reserve reserve,
				  struct bkey *k, int n,
				  struct cache_group *devs)
{
	long caches_used[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	int i, ret;

	BUG_ON(!n || n > BKEY_EXTENT_PTRS_MAX);

	bkey_init(k);
	memset(caches_used, 0, sizeof(caches_used));

	rcu_read_lock();

	/* sort by free space/prio of oldest data in caches */

	for (i = 0; i < n; i++) {
		struct cache *ca;
		unsigned seq;
		long r;

		/* first ptr goes to the specified tier, the rest to any */
		do {
			struct cache_group *d;

			seq = read_seqcount_begin(&devs->lock);

			d = (!i && devs == &c->cache_all &&
			     c->cache_tiers[0].nr_devices)
				? &c->cache_tiers[0]
				: devs;

			ca = devs->nr_devices
				? bch_next_cache(c, reserve, d, caches_used)
				: ERR_PTR(-ENOSPC);

			/*
			 * If ca == NULL, we raced because of bucket counters
			 * changing
			 */
		} while (read_seqcount_retry(&devs->lock, seq) || !ca);

		if (IS_ERR(ca)) {
			ret = PTR_ERR(ca);
			goto err;
		}

		__set_bit(ca->sb.nr_this_dev, caches_used);

		r = bch_bucket_alloc(ca, reserve);
		if (r < 0) {
			ret = r;
			goto err;
		}

		k->val[i] = PTR(ca->bucket_gens[r],
				bucket_to_sector(c, r),
				ca->sb.nr_this_dev);
		bch_set_extent_ptrs(k, i + 1);
	}

	rcu_read_unlock();
	return 0;
err:
	rcu_read_unlock();
	bch_bucket_free_never_used(c, k);
	return ret;
}

int bch_bucket_alloc_set(struct cache_set *c, enum alloc_reserve reserve,
			 struct bkey *k, int n, struct cache_group *tier,
			 struct closure *cl)
{
	if (!__bch_bucket_alloc_set(c, reserve, k, n, tier))
		return 0;

	trace_bcache_bucket_alloc_set_fail(c, reserve, cl);

	if (!tier->nr_devices)
		return -ENOSPC;

	if (reserve == RESERVE_NONE &&
	    !cache_set_can_write(c))
		return -ENOSPC;

	if (cl) {
		closure_wait(&c->bucket_wait, cl);

		/* Must retry allocation after adding ourself to waitlist */

		if (!__bch_bucket_alloc_set(c, reserve, k, n, tier)) {
			closure_wake_up(&c->bucket_wait);
			return 0;
		}

		return -EAGAIN;
	}

	return -ENOSPC;
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

	spin_lock(&b->lock);

	if (wp->ca) {
		long bucket;

		bucket = bch_bucket_alloc(wp->ca, RESERVE_MOVINGGC);
		if (bucket < 0) {
			ret = bucket;
			goto err;
		}

		b->key.val[0] = PTR(wp->ca->bucket_gens[bucket],
				    bucket_to_sector(wp->ca->set, bucket),
				    wp->ca->sb.nr_this_dev);
		bch_set_extent_ptrs(&b->key, 1);
	} else if (wp->tier) {
		ret = bch_bucket_alloc_set(c, RESERVE_NONE, &b->key, 1,
					   wp->tier, cl);
		if (ret)
			goto err;
	} else {
		ret = bch_bucket_alloc_set(c, RESERVE_NONE, &b->key,
				CACHE_SET_DATA_REPLICAS_WANT(&c->sb),
				&c->cache_all, cl);
		if (ret)
			goto err;
	}

	return b;
err:
	spin_unlock(&b->lock);
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

			if (!race_fault() &&
			    cmpxchg(&wp->b, NULL, b) == NULL)
				return b;

			bch_bucket_free_never_used(c, &b->key);
			spin_unlock(&b->lock);
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

	bch_key_resize(k, sectors);

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

void bch_mark_allocator_buckets(struct cache_set *c)
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

	seqcount_init(&c->cache_all.lock);

	for (i = 0; i < ARRAY_SIZE(c->cache_tiers); i++) {
		seqcount_init(&c->cache_tiers[i].lock);
		c->tier_write_points[i].tier = &c->cache_tiers[i];
	}
}

/*
 * bch_cache_allocator_start - put some unused buckets directly on the prio
 * freelist, start allocator
 *
 * The allocator thread needs freed buckets to rewrite the prios and gens, and
 * it needs to rewrite prios and gens in order to free buckets.
 *
 * This is only safe for buckets that have no live data in them, which
 * there should always be some of when this function is called.
 */
const char *bch_cache_allocator_start(struct cache *ca)
{
	struct task_struct *k;
	struct bucket *g;

	for_each_bucket(g, ca) {
		spin_lock(&ca->freelist_lock);
		if (fifo_used(&ca->free_inc) >= prio_buckets(ca)) {
			spin_unlock(&ca->freelist_lock);
			goto done;
		}

		if (bch_can_invalidate_bucket(ca, g) &&
		    !g->mark.cached_sectors) {
			__bch_invalidate_one_bucket(ca, g);
			fifo_push(&ca->free_inc, g - ca->buckets);
		}

		spin_unlock(&ca->freelist_lock);
	}

	return "couldn't find enough available buckets to write prios";
done:
	k = kthread_create(bch_allocator_thread, ca, "bcache_allocator");
	if (IS_ERR(k))
		return "error starting allocator thread";

	ca->alloc_thread = k;
	wake_up_process(k);

	return NULL;
}
