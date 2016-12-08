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
 * free_inc isn't the only freelist - if it was, we'd often have to sleep while
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
#include "btree_update.h"
#include "buckets.h"
#include "checksum.h"
#include "clock.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "super.h"

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcachefs.h>

static size_t bch_bucket_alloc(struct cache *, enum alloc_reserve);
static void __bch_bucket_free(struct cache *, struct bucket *);

/* Allocation groups: */

void bch_cache_group_remove_cache(struct cache_group *grp, struct cache *ca)
{
	unsigned i;

	spin_lock(&grp->lock);

	for (i = 0; i < grp->nr_devices; i++)
		if (rcu_access_pointer(grp->d[i].dev) == ca) {
			grp->nr_devices--;
			memmove(&grp->d[i],
				&grp->d[i + 1],
				(grp->nr_devices - i) * sizeof(grp->d[0]));
			break;
		}

	spin_unlock(&grp->lock);
}

void bch_cache_group_add_cache(struct cache_group *grp, struct cache *ca)
{
	unsigned i;

	spin_lock(&grp->lock);
	for (i = 0; i < grp->nr_devices; i++)
		if (rcu_access_pointer(grp->d[i].dev) == ca)
			goto out;

	BUG_ON(grp->nr_devices >= MAX_CACHES_PER_SET);

	rcu_assign_pointer(grp->d[grp->nr_devices++].dev, ca);
out:
	spin_unlock(&grp->lock);
}

/* Ratelimiting/PD controllers */

static void pd_controllers_update(struct work_struct *work)
{
	struct cache_set *c = container_of(to_delayed_work(work),
					   struct cache_set,
					   pd_controllers_update);
	struct cache *ca;
	unsigned iter;
	int i;

	/* All units are in bytes */
	u64 tier_size[CACHE_TIERS];
	u64 tier_free[CACHE_TIERS];
	u64 tier_dirty[CACHE_TIERS];
	u64 tier0_can_free = 0;

	memset(tier_size, 0, sizeof(tier_size));
	memset(tier_free, 0, sizeof(tier_free));
	memset(tier_dirty, 0, sizeof(tier_dirty));

	rcu_read_lock();
	for (i = CACHE_TIERS - 1; i >= 0; --i)
		group_for_each_cache_rcu(ca, &c->cache_tiers[i], iter) {
			struct bucket_stats_cache stats = bch_bucket_stats_read_cache(ca);
			unsigned bucket_bits = ca->bucket_bits + 9;

			/*
			 * Bytes of internal fragmentation, which can be
			 * reclaimed by copy GC
			 */
			s64 fragmented = ((stats.buckets_dirty +
					   stats.buckets_cached) <<
					  bucket_bits) -
				((stats.sectors_dirty +
				  stats.sectors_cached) << 9);

			u64 dev_size = (ca->mi.nbuckets -
					ca->mi.first_bucket) << bucket_bits;

			u64 free = __buckets_free_cache(ca, stats) << bucket_bits;

			if (fragmented < 0)
				fragmented = 0;

			bch_pd_controller_update(&ca->moving_gc_pd,
						 free, fragmented, -1);

			if (i == 0)
				tier0_can_free += fragmented;

			tier_size[i] += dev_size;
			tier_free[i] += free;
			tier_dirty[i] += stats.buckets_dirty << bucket_bits;
		}
	rcu_read_unlock();

	if (tier_size[1]) {
		u64 target = div_u64(tier_size[0] * c->tiering_percent, 100);

		tier0_can_free = max_t(s64, 0, tier_dirty[0] - target);

		bch_pd_controller_update(&c->tiering_pd,
					 target,
					 tier_dirty[0],
					 -1);
	}

	/*
	 * Throttle foreground writes if tier 0 is running out of free buckets,
	 * and either tiering or copygc can free up space (but don't take both
	 * into account).
	 *
	 * Target will be small if there isn't any work to do - we don't want to
	 * throttle foreground writes if we currently have all the free space
	 * we're ever going to have.
	 *
	 * Otherwise, if there's work to do, try to keep 20% of tier0 available
	 * for foreground writes.
	 */
	bch_pd_controller_update(&c->foreground_write_pd,
				 min(tier0_can_free,
				     div_u64(tier_size[0] *
					     c->foreground_target_percent,
					     100)),
				 tier_free[0],
				 -1);

	schedule_delayed_work(&c->pd_controllers_update,
			      c->pd_controllers_update_seconds * HZ);
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
	bio_init(ca->bio_prio);
	bio_set_op_attrs(ca->bio_prio, op, REQ_SYNC|REQ_META);

	ca->bio_prio->bi_max_vecs	= bucket_pages(ca);
	ca->bio_prio->bi_io_vec		= ca->bio_prio->bi_inline_vecs;
	ca->bio_prio->bi_iter.bi_sector	= bucket * ca->mi.bucket_size;
	ca->bio_prio->bi_bdev		= ca->disk_sb.bdev;
	ca->bio_prio->bi_iter.bi_size	= bucket_bytes(ca);
	bch_bio_map(ca->bio_prio, ca->disk_buckets);

	return submit_bio_wait(ca->bio_prio);
}

static struct nonce prio_nonce(struct prio_set *p)
{
	return (struct nonce) {{
		[0] = 0,
		[1] = p->nonce[0],
		[2] = p->nonce[1],
		[3] = p->nonce[2]^BCH_NONCE_PRIO,
	}};
}

static int bch_prio_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct journal *j = &c->journal;
	struct journal_res res = { 0 };
	bool need_new_journal_entry;
	int i, ret;

	if (c->opts.nochanges)
		return 0;

	trace_bcache_prio_write_start(ca);

	atomic64_add(ca->mi.bucket_size * prio_buckets(ca),
		     &ca->meta_sectors_written);

	for (i = prio_buckets(ca) - 1; i >= 0; --i) {
		struct bucket *g;
		struct prio_set *p = ca->disk_buckets;
		struct bucket_disk *d = p->data;
		struct bucket_disk *end = d + prios_per_bucket(ca);
		size_t r;

		for (r = i * prios_per_bucket(ca);
		     r < ca->mi.nbuckets && d < end;
		     r++, d++) {
			g = ca->buckets + r;
			d->read_prio = cpu_to_le16(g->read_prio);
			d->write_prio = cpu_to_le16(g->write_prio);
			d->gen = ca->buckets[r].mark.gen;
		}

		p->next_bucket	= cpu_to_le64(ca->prio_buckets[i + 1]);
		p->magic	= cpu_to_le64(pset_magic(&c->disk_sb));
		get_random_bytes(&p->nonce, sizeof(p->nonce));

		spin_lock(&ca->prio_buckets_lock);
		r = bch_bucket_alloc(ca, RESERVE_PRIO);
		BUG_ON(!r);

		/*
		 * goes here before dropping prio_buckets_lock to guard against
		 * it getting gc'd from under us
		 */
		ca->prio_buckets[i] = r;
		bch_mark_metadata_bucket(ca, ca->buckets + r, false);
		spin_unlock(&ca->prio_buckets_lock);

		SET_PSET_CSUM_TYPE(p, bch_meta_checksum_type(c));

		bch_encrypt(c, PSET_CSUM_TYPE(p),
			    prio_nonce(p),
			    p->encrypted_start,
			    bucket_bytes(ca) -
			    offsetof(struct prio_set, encrypted_start));

		p->csum	 = bch_checksum(c, PSET_CSUM_TYPE(p),
					prio_nonce(p),
					(void *) p + sizeof(p->csum),
					bucket_bytes(ca) - sizeof(p->csum));

		ret = prio_io(ca, r, REQ_OP_WRITE);
		if (cache_fatal_io_err_on(ret, ca,
					  "prio write to bucket %zu", r) ||
		    bch_meta_write_fault("prio"))
			return ret;
	}

	spin_lock(&j->lock);
	j->prio_buckets[ca->sb.nr_this_dev] = cpu_to_le64(ca->prio_buckets[0]);
	j->nr_prio_buckets = max_t(unsigned,
				   ca->sb.nr_this_dev + 1,
				   j->nr_prio_buckets);
	spin_unlock(&j->lock);

	do {
		unsigned u64s = jset_u64s(0);

		ret = bch_journal_res_get(j, &res, u64s, u64s);
		if (ret)
			return ret;

		need_new_journal_entry = j->buf[res.idx].nr_prio_buckets <
			ca->sb.nr_this_dev + 1;
		bch_journal_res_put(j, &res);

		ret = bch_journal_flush_seq(j, res.seq);
		if (ret)
			return ret;
	} while (need_new_journal_entry);

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
	return 0;
}

int bch_prio_read(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct prio_set *p = ca->disk_buckets;
	struct bucket_disk *d = p->data + prios_per_bucket(ca), *end = d;
	struct bucket_mark new;
	struct bch_csum csum;
	unsigned bucket_nr = 0;
	u64 bucket, expect, got;
	size_t b;
	int ret = 0;

	spin_lock(&c->journal.lock);
	bucket = le64_to_cpu(c->journal.prio_buckets[ca->sb.nr_this_dev]);
	spin_unlock(&c->journal.lock);

	/*
	 * If the device hasn't been used yet, there won't be a prio bucket ptr
	 */
	if (!bucket)
		return 0;

	unfixable_fsck_err_on(bucket < ca->mi.first_bucket ||
			      bucket >= ca->mi.nbuckets, c,
			      "bad prio bucket %llu", bucket);

	for (b = 0; b < ca->mi.nbuckets; b++, d++) {
		if (d == end) {
			ca->prio_last_buckets[bucket_nr] = bucket;
			bucket_nr++;

			ret = prio_io(ca, bucket, REQ_OP_READ);
			if (cache_fatal_io_err_on(ret, ca,
					"prior read from bucket %llu",
					bucket) ||
			    bch_meta_read_fault("prio"))
				return -EIO;

			got = le64_to_cpu(p->magic);
			expect = pset_magic(&c->disk_sb);
			unfixable_fsck_err_on(got != expect, c,
				"bad magic (got %llu expect %llu) while reading prios from bucket %llu",
				got, expect, bucket);

			unfixable_fsck_err_on(PSET_CSUM_TYPE(p) >= BCH_CSUM_NR, c,
				"prio bucket with unknown csum type %llu bucket %lluu",
				PSET_CSUM_TYPE(p), bucket);

			csum = bch_checksum(c, PSET_CSUM_TYPE(p),
					    prio_nonce(p),
					    (void *) p + sizeof(p->csum),
					    bucket_bytes(ca) - sizeof(p->csum));
			unfixable_fsck_err_on(memcmp(&csum, &p->csum, sizeof(csum)), c,
				"bad checksum reading prios from bucket %llu",
				bucket);

			bch_encrypt(c, PSET_CSUM_TYPE(p),
				    prio_nonce(p),
				    p->encrypted_start,
				    bucket_bytes(ca) -
				    offsetof(struct prio_set, encrypted_start));

			bucket = le64_to_cpu(p->next_bucket);
			d = p->data;
		}

		ca->buckets[b].read_prio = le16_to_cpu(d->read_prio);
		ca->buckets[b].write_prio = le16_to_cpu(d->write_prio);

		bucket_cmpxchg(&ca->buckets[b], new, new.gen = d->gen);
	}
fsck_err:
	return 0;
}

#define BUCKET_GC_GEN_MAX	96U

/**
 * wait_buckets_available - wait on reclaimable buckets
 *
 * If there aren't enough available buckets to fill up free_inc, wait until
 * there are.
 */
static int wait_buckets_available(struct cache *ca)
{
	struct cache_set *c = ca->set;
	int ret = 0;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			ret = -1;
			break;
		}

		if (ca->inc_gen_needs_gc >= fifo_free(&ca->free_inc)) {
			if (c->gc_thread) {
				trace_bcache_gc_cannot_inc_gens(ca->set);
				atomic_inc(&c->kick_gc);
				wake_up_process(ca->set->gc_thread);
			}

			/*
			 * We are going to wait for GC to wake us up, even if
			 * bucket counters tell us enough buckets are available,
			 * because we are actually waiting for GC to rewrite
			 * nodes with stale pointers
			 */
		} else if (buckets_available_cache(ca) >=
			   fifo_free(&ca->free_inc))
			break;

		up_read(&ca->set->gc_lock);
		schedule();
		try_to_freeze();
		down_read(&ca->set->gc_lock);
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
			fifo_for_each_entry(i, &ca->free[j], iter)
				BUG_ON(i == bucket);
		fifo_for_each_entry(i, &ca->free_inc, iter)
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

static void bch_inc_clock_hand(struct io_timer *timer)
{
	struct prio_clock *clock = container_of(timer,
					struct prio_clock, rescale);
	struct cache_set *c = container_of(clock,
				struct cache_set, prio_clock[clock->rw]);
	u64 capacity;

	mutex_lock(&c->bucket_lock);

	clock->hand++;

	/* if clock cannot be advanced more, rescale prio */
	if (clock->hand == (u16) (clock->min_prio - 1))
		bch_rescale_prios(c, clock->rw);

	mutex_unlock(&c->bucket_lock);

	capacity = READ_ONCE(c->capacity);

	if (!capacity)
		return;

	/*
	 * we only increment when 0.1% of the cache_set has been read
	 * or written too, this determines if it's time
	 *
	 * XXX: we shouldn't really be going off of the capacity of devices in
	 * RW mode (that will be 0 when we're RO, yet we can still service
	 * reads)
	 */
	timer->expire += capacity >> 10;

	bch_io_timer_add(&c->io_clock[clock->rw], timer);
}

static void bch_prio_timer_init(struct cache_set *c, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];
	struct io_timer *timer = &clock->rescale;

	clock->rw	= rw;
	timer->fn	= bch_inc_clock_hand;
	timer->expire	= c->capacity >> 10;
}

/*
 * Background allocation thread: scans for buckets to be invalidated,
 * invalidates them, rewrites prios/gens (marking them as invalidated on disk),
 * then optionally issues discard commands to the newly free buckets, then puts
 * them on the various freelists.
 */

static inline bool can_inc_bucket_gen(struct cache *ca, struct bucket *g)
{
	return bucket_gc_gen(ca, g) < BUCKET_GC_GEN_MAX;
}

static bool bch_can_invalidate_bucket(struct cache *ca, struct bucket *g)
{
	if (!is_available_bucket(READ_ONCE(g->mark)))
		return false;

	if (bucket_gc_gen(ca, g) >= BUCKET_GC_GEN_MAX - 1)
		ca->inc_gen_needs_gc++;

	return can_inc_bucket_gen(ca, g);
}

static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *g)
{
	spin_lock(&ca->freelist_lock);

	bch_invalidate_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;

	verify_not_on_freelist(ca, g - ca->buckets);
	BUG_ON(!fifo_push(&ca->free_inc, g - ca->buckets));

	spin_unlock(&ca->freelist_lock);
}

/*
 * Determines what order we're going to reuse buckets, smallest bucket_key()
 * first.
 *
 *
 * - We take into account the read prio of the bucket, which gives us an
 *   indication of how hot the data is -- we scale the prio so that the prio
 *   farthest from the clock is worth 1/8th of the closest.
 *
 * - The number of sectors of cached data in the bucket, which gives us an
 *   indication of the cost in cache misses this eviction will cause.
 *
 * - The difference between the bucket's current gen and oldest gen of any
 *   pointer into it, which gives us an indication of the cost of an eventual
 *   btree GC to rewrite nodes with stale pointers.
 */

#define bucket_sort_key(g)						\
({									\
	unsigned long prio = g->read_prio - ca->min_prio[READ];		\
	prio = (prio * 7) / (ca->set->prio_clock[READ].hand -		\
			     ca->min_prio[READ]);			\
									\
	(((prio + 1) * bucket_sectors_used(g)) << 8) | bucket_gc_gen(ca, g);\
})

static void invalidate_buckets_lru(struct cache *ca)
{
	struct bucket_heap_entry e;
	struct bucket *g;
	unsigned i;

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

		bucket_heap_push(ca, g, bucket_sort_key(g));
	}

	/* Sort buckets by physical location on disk for better locality */
	for (i = 0; i < ca->heap.used; i++) {
		struct bucket_heap_entry *e = &ca->heap.data[i];

		e->val = e->g - ca->buckets;
	}

	heap_resort(&ca->heap, bucket_max_cmp);

	/*
	 * If we run out of buckets to invalidate, bch_allocator_thread() will
	 * kick stuff and retry us
	 */
	while (!fifo_full(&ca->free_inc) &&
	       heap_pop(&ca->heap, e, bucket_max_cmp)) {
		BUG_ON(!bch_can_invalidate_bucket(ca, e.g));
		bch_invalidate_one_bucket(ca, e.g);
	}

	mutex_unlock(&ca->set->bucket_lock);
	mutex_unlock(&ca->heap_lock);
}

static void invalidate_buckets_fifo(struct cache *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->mi.first_bucket ||
		    ca->fifo_last_bucket >= ca->mi.nbuckets)
			ca->fifo_last_bucket = ca->mi.first_bucket;

		g = ca->buckets + ca->fifo_last_bucket++;

		if (bch_can_invalidate_bucket(ca, g))
			bch_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets)
			return;
	}
}

static void invalidate_buckets_random(struct cache *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n = bch_rand_range(ca->mi.nbuckets -
					  ca->mi.first_bucket) +
			ca->mi.first_bucket;

		g = ca->buckets + n;

		if (bch_can_invalidate_bucket(ca, g))
			bch_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets / 2)
			return;
	}
}

static void invalidate_buckets(struct cache *ca)
{
	ca->inc_gen_needs_gc = 0;

	switch (ca->mi.replacement) {
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
	if (fifo_push(&ca->free[RESERVE_PRIO], bucket))
		goto success;

	if (fifo_push(&ca->free[RESERVE_MOVINGGC], bucket))
		goto success;

	if (fifo_push(&ca->free[RESERVE_BTREE], bucket))
		goto success;

	if (fifo_push(&ca->free[RESERVE_NONE], bucket))
		goto success;

	return false;
success:
	closure_wake_up(&ca->set->freelist_wait);
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

static void bch_find_empty_buckets(struct cache_set *c, struct cache *ca)
{
	u16 last_seq_ondisk = c->journal.last_seq_ondisk;
	struct bucket *g;

	for_each_bucket(g, ca) {
		struct bucket_mark m = READ_ONCE(g->mark);

		if (is_available_bucket(m) &&
		    !m.cached_sectors &&
		    !m.had_metadata &&
		    (!m.wait_on_journal ||
		     ((s16) last_seq_ondisk - (s16) m.journal_seq >= 0))) {
			spin_lock(&ca->freelist_lock);

			bch_mark_alloc_bucket(ca, g, true);
			g->read_prio = ca->set->prio_clock[READ].hand;
			g->write_prio = ca->set->prio_clock[WRITE].hand;

			verify_not_on_freelist(ca, g - ca->buckets);
			BUG_ON(!fifo_push(&ca->free_inc, g - ca->buckets));

			spin_unlock(&ca->freelist_lock);

			if (fifo_full(&ca->free_inc))
				break;
		}
	}
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
	int ret;

	set_freezable();

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

			if (ca->mi.discard &&
			    blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev)))
				blkdev_issue_discard(ca->disk_sb.bdev,
					bucket_to_sector(ca, bucket),
					ca->mi.bucket_size, GFP_NOIO, 0);

			while (1) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (bch_allocator_push(ca, bucket))
					break;

				if (kthread_should_stop()) {
					__set_current_state(TASK_RUNNING);
					goto out;
				}
				schedule();
				try_to_freeze();
			}

			__set_current_state(TASK_RUNNING);
		}

		down_read(&c->gc_lock);

		/*
		 * See if we have buckets we can reuse without invalidating them
		 * or forcing a journal commit:
		 */
		bch_find_empty_buckets(c, ca);

		if (fifo_used(&ca->free_inc) * 2 > ca->free_inc.size) {
			up_read(&c->gc_lock);
			continue;
		}

		/* We've run out of free buckets! */

		while (!fifo_full(&ca->free_inc)) {
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
		}

		up_read(&c->gc_lock);

		/*
		 * free_inc is full of newly-invalidated buckets, must write out
		 * prios and gens before they can be re-used
		 */
		ret = bch_prio_write(ca);
		if (ret) {
			/*
			 * Emergency read only - allocator thread has to
			 * shutdown.
			 *
			 * N.B. we better be going into RO mode, else
			 * allocations would hang indefinitely - whatever
			 * generated the error will have sent us into RO mode.
			 *
			 * Clear out the free_inc freelist so things are
			 * consistent-ish:
			 */
			spin_lock(&ca->freelist_lock);
			while (!fifo_empty(&ca->free_inc)) {
				long bucket;

				fifo_pop(&ca->free_inc, bucket);
				bch_mark_free_bucket(ca, ca->buckets + bucket);
			}
			spin_unlock(&ca->freelist_lock);
			goto out;
		}
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

/**
 * bch_bucket_alloc - allocate a single bucket from a specific device
 *
 * Returns index of bucket on success, 0 on failure
 * */
static size_t bch_bucket_alloc(struct cache *ca, enum alloc_reserve reserve)
{
	struct bucket *g;
	long r;

	spin_lock(&ca->freelist_lock);
	if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
	    fifo_pop(&ca->free[reserve], r))
		goto out;

	spin_unlock(&ca->freelist_lock);

	trace_bcache_bucket_alloc_fail(ca, reserve);
	return 0;
out:
	verify_not_on_freelist(ca, r);
	spin_unlock(&ca->freelist_lock);

	trace_bcache_bucket_alloc(ca, reserve);

	bch_wake_allocator(ca);

	g = ca->buckets + r;

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;

	return r;
}

static void __bch_bucket_free(struct cache *ca, struct bucket *g)
{
	bch_mark_free_bucket(ca, g);

	g->read_prio = ca->set->prio_clock[READ].hand;
	g->write_prio = ca->set->prio_clock[WRITE].hand;
}

enum bucket_alloc_ret {
	ALLOC_SUCCESS,
	NO_DEVICES,		/* -EROFS */
	FREELIST_EMPTY,		/* Allocator thread not keeping up */
};

static void recalc_alloc_group_weights(struct cache_set *c,
				       struct cache_group *devs)
{
	struct cache *ca;
	u64 available_buckets = 1; /* avoid a divide by zero... */
	unsigned i;

	for (i = 0; i < devs->nr_devices; i++) {
		ca = devs->d[i].dev;

		devs->d[i].weight = buckets_free_cache(ca);
		available_buckets += devs->d[i].weight;
	}

	for (i = 0; i < devs->nr_devices; i++) {
		const unsigned min_weight = U32_MAX >> 4;
		const unsigned max_weight = U32_MAX;

		devs->d[i].weight =
			min_weight +
			div64_u64(devs->d[i].weight *
				  devs->nr_devices *
				  (max_weight - min_weight),
				  available_buckets);
		devs->d[i].weight = min_t(u64, devs->d[i].weight, max_weight);
	}
}

static enum bucket_alloc_ret bch_bucket_alloc_group(struct cache_set *c,
						    struct open_bucket *ob,
						    enum alloc_reserve reserve,
						    unsigned nr_replicas,
						    struct cache_group *devs,
						    long *caches_used)
{
	enum bucket_alloc_ret ret;
	unsigned fail_idx = -1, i;
	unsigned available = 0;

	BUG_ON(nr_replicas > ARRAY_SIZE(ob->ptrs));

	if (ob->nr_ptrs >= nr_replicas)
		return ALLOC_SUCCESS;

	rcu_read_lock();
	spin_lock(&devs->lock);

	for (i = 0; i < devs->nr_devices; i++)
		available += !test_bit(devs->d[i].dev->sb.nr_this_dev,
				       caches_used);

	recalc_alloc_group_weights(c, devs);

	i = devs->cur_device;

	while (ob->nr_ptrs < nr_replicas) {
		struct cache *ca;
		u64 bucket;

		if (!available) {
			ret = NO_DEVICES;
			goto err;
		}

		i++;
		i %= devs->nr_devices;

		ret = FREELIST_EMPTY;
		if (i == fail_idx)
			goto err;

		ca = devs->d[i].dev;

		if (test_bit(ca->sb.nr_this_dev, caches_used))
			continue;

		if (fail_idx == -1 &&
		    get_random_int() > devs->d[i].weight)
			continue;

		bucket = bch_bucket_alloc(ca, reserve);
		if (!bucket) {
			if (fail_idx == -1)
				fail_idx = i;
			continue;
		}

		/*
		 * open_bucket_add_buckets expects new pointers at the head of
		 * the list:
		 */
		memmove(&ob->ptrs[1],
			&ob->ptrs[0],
			ob->nr_ptrs * sizeof(ob->ptrs[0]));
		memmove(&ob->ptr_offset[1],
			&ob->ptr_offset[0],
			ob->nr_ptrs * sizeof(ob->ptr_offset[0]));
		ob->nr_ptrs++;
		ob->ptrs[0] = (struct bch_extent_ptr) {
			.gen	= ca->buckets[bucket].mark.gen,
			.offset	= bucket_to_sector(ca, bucket),
			.dev	= ca->sb.nr_this_dev,
		};
		ob->ptr_offset[0] = 0;

		__set_bit(ca->sb.nr_this_dev, caches_used);
		available--;
		devs->cur_device = i;
	}

	ret = ALLOC_SUCCESS;
err:
	EBUG_ON(ret != ALLOC_SUCCESS && reserve == RESERVE_MOVINGGC);
	spin_unlock(&devs->lock);
	rcu_read_unlock();
	return ret;
}

static enum bucket_alloc_ret __bch_bucket_alloc_set(struct cache_set *c,
						    struct write_point *wp,
						    struct open_bucket *ob,
						    unsigned nr_replicas,
						    enum alloc_reserve reserve,
						    long *caches_used)
{
	/*
	 * this should implement policy - for a given type of allocation, decide
	 * which devices to allocate from:
	 *
	 * XXX: switch off wp->type and do something more intelligent here
	 */

	/* foreground writes: prefer tier 0: */
	if (wp->group == &c->cache_all)
		bch_bucket_alloc_group(c, ob, reserve, nr_replicas,
				       &c->cache_tiers[0], caches_used);

	return bch_bucket_alloc_group(c, ob, reserve, nr_replicas,
				      wp->group, caches_used);
}

static int bch_bucket_alloc_set(struct cache_set *c, struct write_point *wp,
				struct open_bucket *ob, unsigned nr_replicas,
				enum alloc_reserve reserve, long *caches_used,
				struct closure *cl)
{
	bool waiting = false;

	while (1) {
		switch (__bch_bucket_alloc_set(c, wp, ob, nr_replicas,
					       reserve, caches_used)) {
		case ALLOC_SUCCESS:
			if (waiting)
				closure_wake_up(&c->freelist_wait);

			return 0;

		case NO_DEVICES:
			if (waiting)
				closure_wake_up(&c->freelist_wait);
			return -EROFS;

		case FREELIST_EMPTY:
			if (!cl || waiting)
				trace_bcache_freelist_empty_fail(c,
							reserve, cl);

			if (!cl)
				return -ENOSPC;

			if (waiting)
				return -EAGAIN;

			/* Retry allocation after adding ourself to waitlist: */
			closure_wait(&c->freelist_wait, cl);
			waiting = true;
			break;
		default:
			BUG();
		}
	}
}

/* Open buckets: */

/*
 * Open buckets represent one or more buckets (on multiple devices) that are
 * currently being allocated from. They serve two purposes:
 *
 *  - They track buckets that have been partially allocated, allowing for
 *    sub-bucket sized allocations - they're used by the sector allocator below
 *
 *  - They provide a reference to the buckets they own that mark and sweep GC
 *    can find, until the new allocation has a pointer to it inserted into the
 *    btree
 *
 * When allocating some space with the sector allocator, the allocation comes
 * with a reference to an open bucket - the caller is required to put that
 * reference _after_ doing the index update that makes its allocation reachable.
 */

static void __bch_open_bucket_put(struct cache_set *c, struct open_bucket *ob)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	lockdep_assert_held(&c->open_buckets_lock);

	rcu_read_lock();
	open_bucket_for_each_online_device(c, ob, ptr, ca)
		bch_mark_alloc_bucket(ca, PTR_BUCKET(ca, ptr), false);
	rcu_read_unlock();

	ob->nr_ptrs = 0;

	list_move(&ob->list, &c->open_buckets_free);
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
					       unsigned nr_reserved,
					       struct closure *cl)
{
	struct open_bucket *ret;

	spin_lock(&c->open_buckets_lock);

	if (c->open_buckets_nr_free > nr_reserved) {
		BUG_ON(list_empty(&c->open_buckets_free));
		ret = list_first_entry(&c->open_buckets_free,
				       struct open_bucket, list);
		list_move(&ret->list, &c->open_buckets_open);
		BUG_ON(ret->nr_ptrs);

		atomic_set(&ret->pin, 1); /* XXX */
		ret->has_full_ptrs	= false;

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

static unsigned ob_ptr_sectors_free(struct open_bucket *ob,
				    struct cache_member_rcu *mi,
				    struct bch_extent_ptr *ptr)
{
	unsigned i = ptr - ob->ptrs;
	unsigned bucket_size = mi->m[ptr->dev].bucket_size;
	unsigned used = (ptr->offset & (bucket_size - 1)) +
		ob->ptr_offset[i];

	BUG_ON(used > bucket_size);

	return bucket_size - used;
}

static unsigned open_bucket_sectors_free(struct cache_set *c,
					 struct open_bucket *ob,
					 unsigned nr_replicas)
{
	struct cache_member_rcu *mi = cache_member_info_get(c);
	unsigned i, sectors_free = UINT_MAX;

	BUG_ON(nr_replicas > ob->nr_ptrs);

	for (i = 0; i < nr_replicas; i++)
		sectors_free = min(sectors_free,
				   ob_ptr_sectors_free(ob, mi, &ob->ptrs[i]));

	cache_member_info_put();

	return sectors_free != UINT_MAX ? sectors_free : 0;
}

static void open_bucket_copy_unused_ptrs(struct cache_set *c,
					 struct open_bucket *new,
					 struct open_bucket *old)
{
	struct cache_member_rcu *mi = cache_member_info_get(c);
	unsigned i;

	for (i = 0; i < old->nr_ptrs; i++)
		if (ob_ptr_sectors_free(old, mi, &old->ptrs[i])) {
			struct bch_extent_ptr tmp = old->ptrs[i];

			tmp.offset += old->ptr_offset[i];
			new->ptrs[new->nr_ptrs] = tmp;
			new->ptr_offset[new->nr_ptrs] = 0;
			new->nr_ptrs++;
		}
	cache_member_info_put();
}

static void verify_not_stale(struct cache_set *c, const struct open_bucket *ob)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	rcu_read_lock();
	open_bucket_for_each_online_device(c, ob, ptr, ca)
		BUG_ON(ptr_stale(ca, ptr));
	rcu_read_unlock();
#endif
}

/* Sector allocator */

static struct open_bucket *lock_writepoint(struct cache_set *c,
					   struct write_point *wp)
{
	struct open_bucket *ob;

	while ((ob = ACCESS_ONCE(wp->b))) {
		mutex_lock(&ob->lock);
		if (wp->b == ob)
			break;

		mutex_unlock(&ob->lock);
	}

	return ob;
}

static int open_bucket_add_buckets(struct cache_set *c,
				   struct write_point *wp,
				   struct open_bucket *ob,
				   unsigned nr_replicas,
				   enum alloc_reserve reserve,
				   struct closure *cl)
{
	long caches_used[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	int i, dst;

	/*
	 * We might be allocating pointers to add to an existing extent
	 * (tiering/copygc/migration) - if so, some of the pointers in our
	 * existing open bucket might duplicate devices we already have. This is
	 * moderately annoying.
	 */

	/* Short circuit all the fun stuff if posssible: */
	if (ob->nr_ptrs >= nr_replicas)
		return 0;

	memset(caches_used, 0, sizeof(caches_used));

	/*
	 * Shuffle pointers to devices we already have to the end:
	 * bch_bucket_alloc_set() will add new pointers to the statr of @b, and
	 * bch_alloc_sectors_done() will add the first nr_replicas ptrs to @e:
	 */
	for (i = dst = ob->nr_ptrs - 1; i >= 0; --i)
		if (__test_and_set_bit(ob->ptrs[i].dev, caches_used)) {
			if (i != dst) {
				swap(ob->ptrs[i], ob->ptrs[dst]);
				swap(ob->ptr_offset[i], ob->ptr_offset[dst]);
			}
			--dst;
			nr_replicas++;
		}

	return bch_bucket_alloc_set(c, wp, ob, nr_replicas,
				    reserve, caches_used, cl);
}

/*
 * Get us an open_bucket we can allocate from, return with it locked:
 */
struct open_bucket *bch_alloc_sectors_start(struct cache_set *c,
					    struct write_point *wp,
					    unsigned nr_replicas,
					    enum alloc_reserve reserve,
					    struct closure *cl)
{
	struct open_bucket *ob;
	unsigned open_buckets_reserved = wp == &c->btree_write_point
		? 0 : BTREE_NODE_RESERVE;
	int ret;

	BUG_ON(!wp->group);
	BUG_ON(!reserve);
	BUG_ON(!nr_replicas);
retry:
	ob = lock_writepoint(c, wp);

	/*
	 * If ob->sectors_free == 0, one or more of the buckets ob points to is
	 * full. We can't drop pointers from an open bucket - garbage collection
	 * still needs to find them; instead, we must allocate a new open bucket
	 * and copy any pointers to non-full buckets into the new open bucket.
	 */
	if (!ob || ob->has_full_ptrs) {
		struct open_bucket *new_ob;

		new_ob = bch_open_bucket_get(c, open_buckets_reserved, cl);
		if (IS_ERR(new_ob))
			return new_ob;

		mutex_lock(&new_ob->lock);

		/*
		 * We point the write point at the open_bucket before doing the
		 * allocation to avoid a race with shutdown:
		 */
		if (race_fault() ||
		    cmpxchg(&wp->b, ob, new_ob) != ob) {
			/* We raced: */
			mutex_unlock(&new_ob->lock);
			bch_open_bucket_put(c, new_ob);

			if (ob)
				mutex_unlock(&ob->lock);
			goto retry;
		}

		if (ob) {
			open_bucket_copy_unused_ptrs(c, new_ob, ob);
			mutex_unlock(&ob->lock);
			bch_open_bucket_put(c, ob);
		}

		ob = new_ob;
	}

	ret = open_bucket_add_buckets(c, wp, ob, nr_replicas,
				      reserve, cl);
	if (ret) {
		mutex_unlock(&ob->lock);
		return ERR_PTR(ret);
	}

	ob->sectors_free = open_bucket_sectors_free(c, ob, nr_replicas);

	BUG_ON(!ob->sectors_free);
	verify_not_stale(c, ob);

	return ob;
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch_alloc_sectors_append_ptrs(struct cache_set *c, struct bkey_i_extent *e,
				   unsigned nr_replicas, struct open_bucket *ob,
				   unsigned sectors)
{
	struct bch_extent_ptr tmp, *ptr;
	struct cache *ca;
	bool has_data = false;
	unsigned i;

	/*
	 * We're keeping any existing pointer k has, and appending new pointers:
	 * __bch_write() will only write to the pointers we add here:
	 */

	/*
	 * XXX: don't add pointers to devices @e already has
	 */
	BUG_ON(nr_replicas > ob->nr_ptrs);
	BUG_ON(sectors > ob->sectors_free);

	/* didn't use all the ptrs: */
	if (nr_replicas < ob->nr_ptrs)
		has_data = true;

	for (i = 0; i < nr_replicas; i++) {
		EBUG_ON(bch_extent_has_device(extent_i_to_s_c(e), ob->ptrs[i].dev));

		tmp = ob->ptrs[i];
		tmp.offset += ob->ptr_offset[i];
		extent_ptr_append(e, tmp);

		ob->ptr_offset[i] += sectors;
	}

	open_bucket_for_each_online_device(c, ob, ptr, ca)
		this_cpu_add(*ca->sectors_written, sectors);
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch_alloc_sectors_done(struct cache_set *c, struct write_point *wp,
			    struct open_bucket *ob)
{
	struct cache_member_rcu *mi = cache_member_info_get(c);
	bool has_data = false;
	unsigned i;

	for (i = 0; i < ob->nr_ptrs; i++) {
		if (!ob_ptr_sectors_free(ob, mi, &ob->ptrs[i]))
			ob->has_full_ptrs = true;
		else
			has_data = true;
	}

	cache_member_info_put();

	if (likely(has_data))
		atomic_inc(&ob->pin);
	else
		BUG_ON(xchg(&wp->b, NULL) != ob);

	mutex_unlock(&ob->lock);
}

/*
 * Allocates some space in the cache to write to, and k to point to the newly
 * allocated space, and updates k->size and k->offset (to point to the
 * end of the newly allocated space).
 *
 * May allocate fewer sectors than @sectors, k->size indicates how many
 * sectors were actually allocated.
 *
 * Return codes:
 * - -EAGAIN: closure was added to waitlist
 * - -ENOSPC: out of space and no closure provided
 *
 * @c  - cache set.
 * @wp - write point to use for allocating sectors.
 * @k  - key to return the allocated space information.
 * @cl - closure to wait for a bucket
 */
struct open_bucket *bch_alloc_sectors(struct cache_set *c,
				      struct write_point *wp,
				      struct bkey_i_extent *e,
				      unsigned nr_replicas,
				      enum alloc_reserve reserve,
				      struct closure *cl)
{
	struct open_bucket *ob;

	ob = bch_alloc_sectors_start(c, wp, nr_replicas, reserve, cl);
	if (IS_ERR_OR_NULL(ob))
		return ob;

	if (e->k.size > ob->sectors_free)
		bch_key_resize(&e->k, ob->sectors_free);

	bch_alloc_sectors_append_ptrs(c, e, nr_replicas, ob, e->k.size);

	bch_alloc_sectors_done(c, wp, ob);

	return ob;
}

/* Startup/shutdown (ro/rw): */

static void bch_recalc_capacity(struct cache_set *c)
{
	struct cache_group *tier = c->cache_tiers + ARRAY_SIZE(c->cache_tiers);
	struct cache *ca;
	u64 total_capacity, capacity = 0, reserved_sectors = 0;
	unsigned long ra_pages = 0;
	unsigned i, j;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i) {
		struct backing_dev_info *bdi =
			blk_get_backing_dev_info(ca->disk_sb.bdev);

		ra_pages += bdi->ra_pages;
	}

	c->bdi.ra_pages = ra_pages;

	/*
	 * Capacity of the cache set is the capacity of all the devices in the
	 * slowest (highest) tier - we don't include lower tier devices.
	 */
	for (tier = c->cache_tiers + ARRAY_SIZE(c->cache_tiers) - 1;
	     tier > c->cache_tiers && !tier->nr_devices;
	     --tier)
		;

	group_for_each_cache_rcu(ca, tier, i) {
		size_t reserve = 0;

		/*
		 * We need to reserve buckets (from the number
		 * of currently available buckets) against
		 * foreground writes so that mainly copygc can
		 * make forward progress.
		 *
		 * We need enough to refill the various reserves
		 * from scratch - copygc will use its entire
		 * reserve all at once, then run against when
		 * its reserve is refilled (from the formerly
		 * available buckets).
		 *
		 * This reserve is just used when considering if
		 * allocations for foreground writes must wait -
		 * not -ENOSPC calculations.
		 */
		for (j = 0; j < RESERVE_NONE; j++)
			reserve += ca->free[j].size;

		reserve += ca->free_inc.size;

		reserve += ARRAY_SIZE(c->write_points);

		if (ca->mi.tier)
			reserve += 1;	/* tiering write point */
		reserve += 1;		/* btree write point */

		reserved_sectors += reserve << ca->bucket_bits;

		capacity += (ca->mi.nbuckets -
			     ca->mi.first_bucket) <<
			ca->bucket_bits;
	}
	rcu_read_unlock();

	total_capacity = capacity;

	capacity *= (100 - c->opts.gc_reserve_percent);
	capacity = div64_u64(capacity, 100);

	BUG_ON(capacity + reserved_sectors > total_capacity);

	c->capacity = capacity;

	if (c->capacity) {
		bch_io_timer_add(&c->io_clock[READ],
				 &c->prio_clock[READ].rescale);
		bch_io_timer_add(&c->io_clock[WRITE],
				 &c->prio_clock[WRITE].rescale);
	} else {
		bch_io_timer_del(&c->io_clock[READ],
				 &c->prio_clock[READ].rescale);
		bch_io_timer_del(&c->io_clock[WRITE],
				 &c->prio_clock[WRITE].rescale);
	}

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->freelist_wait);
}

static void bch_stop_write_point(struct cache *ca,
				 struct write_point *wp)
{
	struct cache_set *c = ca->set;
	struct open_bucket *ob;
	struct bch_extent_ptr *ptr;

	ob = lock_writepoint(c, wp);
	if (!ob)
		return;

	for (ptr = ob->ptrs; ptr < ob->ptrs + ob->nr_ptrs; ptr++)
		if (ptr->dev == ca->sb.nr_this_dev)
			goto found;

	mutex_unlock(&ob->lock);
	return;
found:
	BUG_ON(xchg(&wp->b, NULL) != ob);
	mutex_unlock(&ob->lock);

	/* Drop writepoint's ref: */
	bch_open_bucket_put(c, ob);
}

static bool bch_dev_has_open_write_point(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bch_extent_ptr *ptr;
	struct open_bucket *ob;

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++)
		if (atomic_read(&ob->pin)) {
			mutex_lock(&ob->lock);
			for (ptr = ob->ptrs; ptr < ob->ptrs + ob->nr_ptrs; ptr++)
				if (ptr->dev == ca->sb.nr_this_dev) {
					mutex_unlock(&ob->lock);
					return true;
				}
			mutex_unlock(&ob->lock);
		}

	return false;
}

/* device goes ro: */
void bch_cache_allocator_stop(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_group *tier = &c->cache_tiers[ca->mi.tier];
	struct task_struct *p;
	struct closure cl;
	unsigned i;

	closure_init_stack(&cl);

	/* First, remove device from allocation groups: */

	bch_cache_group_remove_cache(tier, ca);
	bch_cache_group_remove_cache(&c->cache_all, ca);

	bch_recalc_capacity(c);

	/*
	 * Stopping the allocator thread comes after removing from allocation
	 * groups, else pending allocations will hang:
	 */

	p = ca->alloc_thread;
	ca->alloc_thread = NULL;
	smp_wmb();

	/*
	 * We need an rcu barrier between setting ca->alloc_thread = NULL and
	 * the thread shutting down to avoid a race with bucket_stats_update() -
	 * the allocator thread itself does a synchronize_rcu() on exit.
	 *
	 * XXX: it would be better to have the rcu barrier be asynchronous
	 * instead of blocking us here
	 */
	if (p) {
		kthread_stop(p);
		put_task_struct(p);
	}

	/* Next, close write points that point to this device... */

	for (i = 0; i < ARRAY_SIZE(c->write_points); i++)
		bch_stop_write_point(ca, &c->write_points[i]);

	bch_stop_write_point(ca, &ca->copygc_write_point);
	bch_stop_write_point(ca, &c->promote_write_point);
	bch_stop_write_point(ca, &ca->tiering_write_point);
	bch_stop_write_point(ca, &c->migration_write_point);
	bch_stop_write_point(ca, &c->btree_write_point);

	mutex_lock(&c->btree_reserve_cache_lock);
	while (c->btree_reserve_cache_nr) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		bch_open_bucket_put(c, a->ob);
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

	/* Avoid deadlocks.. */

	closure_wake_up(&c->freelist_wait);
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	while (1) {
		closure_wait(&c->open_buckets_wait, &cl);

		if (!bch_dev_has_open_write_point(ca)) {
			closure_wake_up(&c->open_buckets_wait);
			break;
		}

		closure_sync(&cl);
	}
}

/*
 * Startup the allocator thread for transition to RW mode:
 */
int bch_cache_allocator_start(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_group *tier = &c->cache_tiers[ca->mi.tier];
	struct task_struct *k;

	/*
	 * allocator thread already started?
	 */
	if (ca->alloc_thread)
		return 0;

	k = kthread_create(bch_allocator_thread, ca, "bcache_allocator");
	if (IS_ERR(k))
		return 0;

	get_task_struct(k);
	ca->alloc_thread = k;

	bch_cache_group_add_cache(tier, ca);
	bch_cache_group_add_cache(&c->cache_all, ca);

	bch_recalc_capacity(c);

	/*
	 * Don't wake up allocator thread until after adding device to
	 * allocator groups - otherwise, alloc thread could get a spurious
	 * -EROFS due to prio_write() -> journal_meta() not finding any devices:
	 */
	wake_up_process(k);
	return 0;
}

void bch_open_buckets_init(struct cache_set *c)
{
	unsigned i;

	INIT_LIST_HEAD(&c->open_buckets_open);
	INIT_LIST_HEAD(&c->open_buckets_free);
	spin_lock_init(&c->open_buckets_lock);
	bch_prio_timer_init(c, READ);
	bch_prio_timer_init(c, WRITE);

	/* open bucket 0 is a sentinal NULL: */
	mutex_init(&c->open_buckets[0].lock);
	INIT_LIST_HEAD(&c->open_buckets[0].list);

	for (i = 1; i < ARRAY_SIZE(c->open_buckets); i++) {
		mutex_init(&c->open_buckets[i].lock);
		c->open_buckets_nr_free++;
		list_add(&c->open_buckets[i].list, &c->open_buckets_free);
	}

	spin_lock_init(&c->cache_all.lock);

	for (i = 0; i < ARRAY_SIZE(c->write_points); i++) {
		c->write_points[i].throttle = true;
		c->write_points[i].group = &c->cache_tiers[0];
	}

	for (i = 0; i < ARRAY_SIZE(c->cache_tiers); i++)
		spin_lock_init(&c->cache_tiers[i].lock);

	c->promote_write_point.group = &c->cache_tiers[0];

	c->migration_write_point.group = &c->cache_all;

	c->btree_write_point.group = &c->cache_all;

	c->pd_controllers_update_seconds = 5;
	INIT_DELAYED_WORK(&c->pd_controllers_update, pd_controllers_update);

	spin_lock_init(&c->foreground_write_pd_lock);
	bch_pd_controller_init(&c->foreground_write_pd);
	/*
	 * We do not want the write rate to have an effect on the computed
	 * rate, for two reasons:
	 *
	 * We do not call bch_ratelimit_delay() at all if the write rate
	 * exceeds 1GB/s. In this case, the PD controller will think we are
	 * not "keeping up" and not change the rate.
	 */
	c->foreground_write_pd.backpressure = 0;
	init_timer(&c->foreground_write_wakeup);

	c->foreground_write_wakeup.data = (unsigned long) c;
	c->foreground_write_wakeup.function = bch_wake_delayed_writes;
}
