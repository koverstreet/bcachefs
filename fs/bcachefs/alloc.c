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
 * bch2_bucket_alloc() allocates a single bucket from a specific device.
 *
 * bch2_bucket_alloc_set() allocates one or more buckets from different devices
 * in a given filesystem.
 *
 * invalidate_buckets() drives all the processes described above. It's called
 * from bch2_bucket_alloc() and a few other places that need to make sure free
 * buckets are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

#include "bcachefs.h"
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
#include "super-io.h"

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcachefs.h>

static void __bch2_bucket_free(struct bch_dev *, struct bucket *);
static void bch2_recalc_min_prio(struct bch_dev *, int);

/* Allocation groups: */

void bch2_dev_group_remove(struct dev_group *grp, struct bch_dev *ca)
{
	unsigned i;

	spin_lock(&grp->lock);

	for (i = 0; i < grp->nr; i++)
		if (grp->d[i].dev == ca) {
			grp->nr--;
			memmove(&grp->d[i],
				&grp->d[i + 1],
				(grp->nr- i) * sizeof(grp->d[0]));
			break;
		}

	spin_unlock(&grp->lock);
}

void bch2_dev_group_add(struct dev_group *grp, struct bch_dev *ca)
{
	unsigned i;

	spin_lock(&grp->lock);
	for (i = 0; i < grp->nr; i++)
		if (grp->d[i].dev == ca)
			goto out;

	BUG_ON(grp->nr>= BCH_SB_MEMBERS_MAX);

	grp->d[grp->nr++].dev = ca;
out:
	spin_unlock(&grp->lock);
}

/* Ratelimiting/PD controllers */

static void pd_controllers_update(struct work_struct *work)
{
	struct bch_fs *c = container_of(to_delayed_work(work),
					   struct bch_fs,
					   pd_controllers_update);
	struct bch_dev *ca;
	unsigned i, iter;

	/* All units are in bytes */
	u64 faster_tiers_size	= 0;
	u64 faster_tiers_dirty	= 0;

	u64 fastest_tier_size	= 0;
	u64 fastest_tier_free	= 0;
	u64 copygc_can_free	= 0;

	rcu_read_lock();
	for (i = 0; i < ARRAY_SIZE(c->tiers); i++) {
		bch2_pd_controller_update(&c->tiers[i].pd,
				div_u64(faster_tiers_size *
					c->tiering_percent, 100),
				faster_tiers_dirty,
				-1);

		spin_lock(&c->tiers[i].devs.lock);
		group_for_each_dev(ca, &c->tiers[i].devs, iter) {
			struct bch_dev_usage stats = bch2_dev_usage_read(ca);
			unsigned bucket_bits = ca->bucket_bits + 9;

			u64 size = (ca->mi.nbuckets -
				    ca->mi.first_bucket) << bucket_bits;
			u64 dirty = stats.buckets_dirty << bucket_bits;
			u64 free = __dev_buckets_free(ca, stats) << bucket_bits;
			/*
			 * Bytes of internal fragmentation, which can be
			 * reclaimed by copy GC
			 */
			s64 fragmented = ((stats.buckets_dirty +
					   stats.buckets_cached) <<
					  bucket_bits) -
				((stats.sectors[S_DIRTY] +
				  stats.sectors[S_CACHED] ) << 9);

			fragmented = max(0LL, fragmented);

			bch2_pd_controller_update(&ca->moving_gc_pd,
						 free, fragmented, -1);

			faster_tiers_size		+= size;
			faster_tiers_dirty		+= dirty;

			if (!c->fastest_tier ||
			    c->fastest_tier == &c->tiers[i]) {
				fastest_tier_size	+= size;
				fastest_tier_free	+= free;
			}

			copygc_can_free			+= fragmented;
		}
		spin_unlock(&c->tiers[i].devs.lock);
	}

	rcu_read_unlock();

	/*
	 * Throttle foreground writes if tier 0 is running out of free buckets,
	 * and either tiering or copygc can free up space.
	 *
	 * Target will be small if there isn't any work to do - we don't want to
	 * throttle foreground writes if we currently have all the free space
	 * we're ever going to have.
	 *
	 * Otherwise, if there's work to do, try to keep 20% of tier0 available
	 * for foreground writes.
	 */
	if (c->fastest_tier)
		copygc_can_free = U64_MAX;

	bch2_pd_controller_update(&c->foreground_write_pd,
				 min(copygc_can_free,
				     div_u64(fastest_tier_size *
					     c->foreground_target_percent,
					     100)),
				 fastest_tier_free,
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

static int prio_io(struct bch_dev *ca, uint64_t bucket, int op)
{
	bio_init(ca->bio_prio);
	bio_set_op_attrs(ca->bio_prio, op, REQ_SYNC|REQ_META);

	ca->bio_prio->bi_max_vecs	= bucket_pages(ca);
	ca->bio_prio->bi_io_vec		= ca->bio_prio->bi_inline_vecs;
	ca->bio_prio->bi_iter.bi_sector	= bucket * ca->mi.bucket_size;
	ca->bio_prio->bi_bdev		= ca->disk_sb.bdev;
	ca->bio_prio->bi_iter.bi_size	= bucket_bytes(ca);
	bch2_bio_map(ca->bio_prio, ca->disk_buckets);

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

int bch2_prio_write(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct journal *j = &c->journal;
	struct journal_res res = { 0 };
	bool need_new_journal_entry;
	int i, ret = 0;

	if (c->opts.nochanges)
		return 0;

	mutex_lock(&ca->prio_write_lock);
	trace_prio_write_start(ca);

	ca->need_prio_write = false;

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
		p->magic	= cpu_to_le64(pset_magic(c));
		get_random_bytes(&p->nonce, sizeof(p->nonce));

		spin_lock(&ca->prio_buckets_lock);
		r = bch2_bucket_alloc(ca, RESERVE_PRIO);
		BUG_ON(!r);

		/*
		 * goes here before dropping prio_buckets_lock to guard against
		 * it getting gc'd from under us
		 */
		ca->prio_buckets[i] = r;
		bch2_mark_metadata_bucket(ca, ca->buckets + r,
					 BUCKET_PRIOS, false);
		spin_unlock(&ca->prio_buckets_lock);

		SET_PSET_CSUM_TYPE(p, bch2_meta_checksum_type(c));

		bch2_encrypt(c, PSET_CSUM_TYPE(p),
			    prio_nonce(p),
			    p->encrypted_start,
			    bucket_bytes(ca) -
			    offsetof(struct prio_set, encrypted_start));

		p->csum	 = bch2_checksum(c, PSET_CSUM_TYPE(p),
					prio_nonce(p),
					(void *) p + sizeof(p->csum),
					bucket_bytes(ca) - sizeof(p->csum));

		ret = prio_io(ca, r, REQ_OP_WRITE);
		if (bch2_dev_fatal_io_err_on(ret, ca,
					  "prio write to bucket %zu", r) ||
		    bch2_meta_write_fault("prio"))
			goto err;
	}

	spin_lock(&j->lock);
	j->prio_buckets[ca->dev_idx] = cpu_to_le64(ca->prio_buckets[0]);
	j->nr_prio_buckets = max_t(unsigned,
				   ca->dev_idx + 1,
				   j->nr_prio_buckets);
	spin_unlock(&j->lock);

	do {
		unsigned u64s = jset_u64s(0);

		if (!test_bit(JOURNAL_STARTED, &c->journal.flags))
			break;

		ret = bch2_journal_res_get(j, &res, u64s, u64s);
		if (ret)
			goto err;

		need_new_journal_entry = j->buf[res.idx].nr_prio_buckets <
			ca->dev_idx + 1;
		bch2_journal_res_put(j, &res);

		ret = bch2_journal_flush_seq(j, res.seq);
		if (ret)
			goto err;
	} while (need_new_journal_entry);

	/*
	 * Don't want the old priorities to get garbage collected until after we
	 * finish writing the new ones, and they're journalled
	 */

	spin_lock(&ca->prio_buckets_lock);

	for (i = 0; i < prio_buckets(ca); i++) {
		if (ca->prio_last_buckets[i])
			__bch2_bucket_free(ca,
				&ca->buckets[ca->prio_last_buckets[i]]);

		ca->prio_last_buckets[i] = ca->prio_buckets[i];
	}

	spin_unlock(&ca->prio_buckets_lock);

	trace_prio_write_end(ca);
err:
	mutex_unlock(&ca->prio_write_lock);
	return ret;
}

int bch2_prio_read(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct prio_set *p = ca->disk_buckets;
	struct bucket_disk *d = p->data + prios_per_bucket(ca), *end = d;
	struct bucket_mark new;
	struct bch_csum csum;
	unsigned bucket_nr = 0;
	u64 bucket, expect, got;
	size_t b;
	int ret = 0;

	if (ca->prio_read_done)
		return 0;

	ca->prio_read_done = true;

	spin_lock(&c->journal.lock);
	bucket = le64_to_cpu(c->journal.prio_buckets[ca->dev_idx]);
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
			if (bch2_dev_fatal_io_err_on(ret, ca,
					"prior read from bucket %llu",
					bucket) ||
			    bch2_meta_read_fault("prio"))
				return -EIO;

			got = le64_to_cpu(p->magic);
			expect = pset_magic(c);
			unfixable_fsck_err_on(got != expect, c,
				"bad magic (got %llu expect %llu) while reading prios from bucket %llu",
				got, expect, bucket);

			unfixable_fsck_err_on(PSET_CSUM_TYPE(p) >= BCH_CSUM_NR, c,
				"prio bucket with unknown csum type %llu bucket %lluu",
				PSET_CSUM_TYPE(p), bucket);

			csum = bch2_checksum(c, PSET_CSUM_TYPE(p),
					    prio_nonce(p),
					    (void *) p + sizeof(p->csum),
					    bucket_bytes(ca) - sizeof(p->csum));
			unfixable_fsck_err_on(bch2_crc_cmp(csum, p->csum), c,
				"bad checksum reading prios from bucket %llu",
				bucket);

			bch2_encrypt(c, PSET_CSUM_TYPE(p),
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

	mutex_lock(&c->bucket_lock);
	bch2_recalc_min_prio(ca, READ);
	bch2_recalc_min_prio(ca, WRITE);
	mutex_unlock(&c->bucket_lock);

	ret = 0;
fsck_err:
	return ret;
}

#define BUCKET_GC_GEN_MAX	96U

/**
 * wait_buckets_available - wait on reclaimable buckets
 *
 * If there aren't enough available buckets to fill up free_inc, wait until
 * there are.
 */
static int wait_buckets_available(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	int ret = 0;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			ret = -1;
			break;
		}

		if (ca->inc_gen_needs_gc >= fifo_free(&ca->free_inc)) {
			if (c->gc_thread) {
				trace_gc_cannot_inc_gens(ca->fs);
				atomic_inc(&c->kick_gc);
				wake_up_process(ca->fs->gc_thread);
			}

			/*
			 * We are going to wait for GC to wake us up, even if
			 * bucket counters tell us enough buckets are available,
			 * because we are actually waiting for GC to rewrite
			 * nodes with stale pointers
			 */
		} else if (dev_buckets_available(ca) >=
			   fifo_free(&ca->free_inc))
			break;

		up_read(&ca->fs->gc_lock);
		schedule();
		try_to_freeze();
		down_read(&ca->fs->gc_lock);
	}

	__set_current_state(TASK_RUNNING);
	return ret;
}

static void verify_not_on_freelist(struct bch_dev *ca, size_t bucket)
{
	if (expensive_debug_checks(ca->fs)) {
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

void bch2_recalc_min_prio(struct bch_dev *ca, int rw)
{
	struct bch_fs *c = ca->fs;
	struct prio_clock *clock = &c->prio_clock[rw];
	struct bucket *g;
	u16 max_delta = 1;
	unsigned i;

	lockdep_assert_held(&c->bucket_lock);

	/* Determine min prio for this particular cache */
	for_each_bucket(g, ca)
		max_delta = max(max_delta, (u16) (clock->hand - g->prio[rw]));

	ca->min_prio[rw] = clock->hand - max_delta;

	/*
	 * This may possibly increase the min prio for the whole cache, check
	 * that as well.
	 */
	max_delta = 1;

	for_each_member_device(ca, c, i)
		max_delta = max(max_delta,
				(u16) (clock->hand - ca->min_prio[rw]));

	clock->min_prio = clock->hand - max_delta;
}

static void bch2_rescale_prios(struct bch_fs *c, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];
	struct bch_dev *ca;
	struct bucket *g;
	unsigned i;

	trace_rescale_prios(c);

	for_each_member_device(ca, c, i) {
		for_each_bucket(g, ca)
			g->prio[rw] = clock->hand -
				(clock->hand - g->prio[rw]) / 2;

		bch2_recalc_min_prio(ca, rw);
	}
}

static void bch2_inc_clock_hand(struct io_timer *timer)
{
	struct prio_clock *clock = container_of(timer,
					struct prio_clock, rescale);
	struct bch_fs *c = container_of(clock,
				struct bch_fs, prio_clock[clock->rw]);
	u64 capacity;

	mutex_lock(&c->bucket_lock);

	clock->hand++;

	/* if clock cannot be advanced more, rescale prio */
	if (clock->hand == (u16) (clock->min_prio - 1))
		bch2_rescale_prios(c, clock->rw);

	mutex_unlock(&c->bucket_lock);

	capacity = READ_ONCE(c->capacity);

	if (!capacity)
		return;

	/*
	 * we only increment when 0.1% of the filesystem capacity has been read
	 * or written too, this determines if it's time
	 *
	 * XXX: we shouldn't really be going off of the capacity of devices in
	 * RW mode (that will be 0 when we're RO, yet we can still service
	 * reads)
	 */
	timer->expire += capacity >> 10;

	bch2_io_timer_add(&c->io_clock[clock->rw], timer);
}

static void bch2_prio_timer_init(struct bch_fs *c, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];
	struct io_timer *timer = &clock->rescale;

	clock->rw	= rw;
	timer->fn	= bch2_inc_clock_hand;
	timer->expire	= c->capacity >> 10;
}

/*
 * Background allocation thread: scans for buckets to be invalidated,
 * invalidates them, rewrites prios/gens (marking them as invalidated on disk),
 * then optionally issues discard commands to the newly free buckets, then puts
 * them on the various freelists.
 */

static inline bool can_inc_bucket_gen(struct bch_dev *ca, struct bucket *g)
{
	return bucket_gc_gen(ca, g) < BUCKET_GC_GEN_MAX;
}

static bool bch2_can_invalidate_bucket(struct bch_dev *ca, struct bucket *g)
{
	if (!is_available_bucket(READ_ONCE(g->mark)))
		return false;

	if (bucket_gc_gen(ca, g) >= BUCKET_GC_GEN_MAX - 1)
		ca->inc_gen_needs_gc++;

	return can_inc_bucket_gen(ca, g);
}

static void bch2_invalidate_one_bucket(struct bch_dev *ca, struct bucket *g)
{
	spin_lock(&ca->freelist_lock);

	bch2_invalidate_bucket(ca, g);

	g->read_prio = ca->fs->prio_clock[READ].hand;
	g->write_prio = ca->fs->prio_clock[WRITE].hand;

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
	prio = (prio * 7) / (ca->fs->prio_clock[READ].hand -		\
			     ca->min_prio[READ]);			\
									\
	(((prio + 1) * bucket_sectors_used(g)) << 8) | bucket_gc_gen(ca, g);\
})

static void invalidate_buckets_lru(struct bch_dev *ca)
{
	struct bucket_heap_entry e;
	struct bucket *g;
	unsigned i;

	mutex_lock(&ca->heap_lock);

	ca->heap.used = 0;

	mutex_lock(&ca->fs->bucket_lock);
	bch2_recalc_min_prio(ca, READ);
	bch2_recalc_min_prio(ca, WRITE);

	/*
	 * Find buckets with lowest read priority, by building a maxheap sorted
	 * by read priority and repeatedly replacing the maximum element until
	 * all buckets have been visited.
	 */
	for_each_bucket(g, ca) {
		if (!bch2_can_invalidate_bucket(ca, g))
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
	 * If we run out of buckets to invalidate, bch2_allocator_thread() will
	 * kick stuff and retry us
	 */
	while (!fifo_full(&ca->free_inc) &&
	       heap_pop(&ca->heap, e, bucket_max_cmp)) {
		BUG_ON(!bch2_can_invalidate_bucket(ca, e.g));
		bch2_invalidate_one_bucket(ca, e.g);
	}

	mutex_unlock(&ca->fs->bucket_lock);
	mutex_unlock(&ca->heap_lock);
}

static void invalidate_buckets_fifo(struct bch_dev *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->mi.first_bucket ||
		    ca->fifo_last_bucket >= ca->mi.nbuckets)
			ca->fifo_last_bucket = ca->mi.first_bucket;

		g = ca->buckets + ca->fifo_last_bucket++;

		if (bch2_can_invalidate_bucket(ca, g))
			bch2_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets)
			return;
	}
}

static void invalidate_buckets_random(struct bch_dev *ca)
{
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n = bch2_rand_range(ca->mi.nbuckets -
					  ca->mi.first_bucket) +
			ca->mi.first_bucket;

		g = ca->buckets + n;

		if (bch2_can_invalidate_bucket(ca, g))
			bch2_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets / 2)
			return;
	}
}

static void invalidate_buckets(struct bch_dev *ca)
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

static bool __bch2_allocator_push(struct bch_dev *ca, long bucket)
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
	closure_wake_up(&ca->fs->freelist_wait);
	return true;
}

static bool bch2_allocator_push(struct bch_dev *ca, long bucket)
{
	bool ret;

	spin_lock(&ca->freelist_lock);
	ret = __bch2_allocator_push(ca, bucket);
	if (ret)
		fifo_pop(&ca->free_inc, bucket);
	spin_unlock(&ca->freelist_lock);

	return ret;
}

static void bch2_find_empty_buckets(struct bch_fs *c, struct bch_dev *ca)
{
	u16 last_seq_ondisk = c->journal.last_seq_ondisk;
	struct bucket *g;

	for_each_bucket(g, ca) {
		struct bucket_mark m = READ_ONCE(g->mark);

		if (is_available_bucket(m) &&
		    !m.cached_sectors &&
		    !m.had_metadata &&
		    !bucket_needs_journal_commit(m, last_seq_ondisk)) {
			spin_lock(&ca->freelist_lock);

			bch2_mark_alloc_bucket(ca, g, true);
			g->read_prio = c->prio_clock[READ].hand;
			g->write_prio = c->prio_clock[WRITE].hand;

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
static int bch2_allocator_thread(void *arg)
{
	struct bch_dev *ca = arg;
	struct bch_fs *c = ca->fs;
	int ret;

	set_freezable();

	bch2_find_empty_buckets(c, ca);

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
				if (bch2_allocator_push(ca, bucket))
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
		//bch2_find_empty_buckets(c, ca);

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
			trace_alloc_batch(ca, fifo_used(&ca->free_inc),
						 ca->free_inc.size);
		}

		up_read(&c->gc_lock);

		/*
		 * free_inc is full of newly-invalidated buckets, must write out
		 * prios and gens before they can be re-used
		 */
		ret = bch2_prio_write(ca);
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
				bch2_mark_free_bucket(ca, ca->buckets + bucket);
			}
			spin_unlock(&ca->freelist_lock);
			goto out;
		}
	}
out:
	/*
	 * Avoid a race with bch2_usage_update() trying to wake us up after
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
size_t bch2_bucket_alloc(struct bch_dev *ca, enum alloc_reserve reserve)
{
	struct bucket *g;
	long r;

	spin_lock(&ca->freelist_lock);
	if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
	    fifo_pop(&ca->free[reserve], r))
		goto out;

	spin_unlock(&ca->freelist_lock);

	trace_bucket_alloc_fail(ca, reserve);
	return 0;
out:
	verify_not_on_freelist(ca, r);
	spin_unlock(&ca->freelist_lock);

	trace_bucket_alloc(ca, reserve);

	bch2_wake_allocator(ca);

	g = ca->buckets + r;

	g->read_prio = ca->fs->prio_clock[READ].hand;
	g->write_prio = ca->fs->prio_clock[WRITE].hand;

	return r;
}

static void __bch2_bucket_free(struct bch_dev *ca, struct bucket *g)
{
	bch2_mark_free_bucket(ca, g);

	g->read_prio = ca->fs->prio_clock[READ].hand;
	g->write_prio = ca->fs->prio_clock[WRITE].hand;
}

enum bucket_alloc_ret {
	ALLOC_SUCCESS,
	NO_DEVICES,		/* -EROFS */
	FREELIST_EMPTY,		/* Allocator thread not keeping up */
};

static void recalc_alloc_group_weights(struct bch_fs *c,
				       struct dev_group *devs)
{
	struct bch_dev *ca;
	u64 available_buckets = 1; /* avoid a divide by zero... */
	unsigned i;

	for (i = 0; i < devs->nr; i++) {
		ca = devs->d[i].dev;

		devs->d[i].weight = dev_buckets_free(ca);
		available_buckets += devs->d[i].weight;
	}

	for (i = 0; i < devs->nr; i++) {
		const unsigned min_weight = U32_MAX >> 4;
		const unsigned max_weight = U32_MAX;

		devs->d[i].weight =
			min_weight +
			div64_u64(devs->d[i].weight *
				  devs->nr *
				  (max_weight - min_weight),
				  available_buckets);
		devs->d[i].weight = min_t(u64, devs->d[i].weight, max_weight);
	}
}

static enum bucket_alloc_ret bch2_bucket_alloc_group(struct bch_fs *c,
						    struct open_bucket *ob,
						    enum alloc_reserve reserve,
						    unsigned nr_replicas,
						    struct dev_group *devs,
						    long *devs_used)
{
	enum bucket_alloc_ret ret;
	unsigned fail_idx = -1, i;
	unsigned available = 0;

	BUG_ON(nr_replicas > ARRAY_SIZE(ob->ptrs));

	if (ob->nr_ptrs >= nr_replicas)
		return ALLOC_SUCCESS;

	spin_lock(&devs->lock);

	for (i = 0; i < devs->nr; i++)
		available += !test_bit(devs->d[i].dev->dev_idx,
				       devs_used);

	recalc_alloc_group_weights(c, devs);

	i = devs->cur_device;

	while (ob->nr_ptrs < nr_replicas) {
		struct bch_dev *ca;
		u64 bucket;

		if (!available) {
			ret = NO_DEVICES;
			goto err;
		}

		i++;
		i %= devs->nr;

		ret = FREELIST_EMPTY;
		if (i == fail_idx)
			goto err;

		ca = devs->d[i].dev;

		if (test_bit(ca->dev_idx, devs_used))
			continue;

		if (fail_idx == -1 &&
		    get_random_int() > devs->d[i].weight)
			continue;

		bucket = bch2_bucket_alloc(ca, reserve);
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
			.dev	= ca->dev_idx,
		};
		ob->ptr_offset[0] = 0;

		__set_bit(ca->dev_idx, devs_used);
		available--;
		devs->cur_device = i;
	}

	ret = ALLOC_SUCCESS;
err:
	EBUG_ON(ret != ALLOC_SUCCESS && reserve == RESERVE_MOVINGGC);
	spin_unlock(&devs->lock);
	return ret;
}

static enum bucket_alloc_ret __bch2_bucket_alloc_set(struct bch_fs *c,
						    struct write_point *wp,
						    struct open_bucket *ob,
						    unsigned nr_replicas,
						    enum alloc_reserve reserve,
						    long *devs_used)
{
	struct bch_tier *tier;
	/*
	 * this should implement policy - for a given type of allocation, decide
	 * which devices to allocate from:
	 *
	 * XXX: switch off wp->type and do something more intelligent here
	 */
	if (wp->group)
		return bch2_bucket_alloc_group(c, ob, reserve, nr_replicas,
					      wp->group, devs_used);

	/* foreground writes: prefer fastest tier: */
	tier = READ_ONCE(c->fastest_tier);
	if (tier)
		bch2_bucket_alloc_group(c, ob, reserve, nr_replicas,
				       &tier->devs, devs_used);

	return bch2_bucket_alloc_group(c, ob, reserve, nr_replicas,
				      &c->all_devs, devs_used);
}

static int bch2_bucket_alloc_set(struct bch_fs *c, struct write_point *wp,
				struct open_bucket *ob, unsigned nr_replicas,
				enum alloc_reserve reserve, long *devs_used,
				struct closure *cl)
{
	bool waiting = false;

	while (1) {
		switch (__bch2_bucket_alloc_set(c, wp, ob, nr_replicas,
					       reserve, devs_used)) {
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
				trace_freelist_empty_fail(c,
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

static void __bch2_open_bucket_put(struct bch_fs *c, struct open_bucket *ob)
{
	const struct bch_extent_ptr *ptr;

	lockdep_assert_held(&c->open_buckets_lock);

	open_bucket_for_each_ptr(ob, ptr) {
		struct bch_dev *ca = c->devs[ptr->dev];

		bch2_mark_alloc_bucket(ca, PTR_BUCKET(ca, ptr), false);
	}

	ob->nr_ptrs = 0;

	list_move(&ob->list, &c->open_buckets_free);
	c->open_buckets_nr_free++;
	closure_wake_up(&c->open_buckets_wait);
}

void bch2_open_bucket_put(struct bch_fs *c, struct open_bucket *b)
{
	if (atomic_dec_and_test(&b->pin)) {
		spin_lock(&c->open_buckets_lock);
		__bch2_open_bucket_put(c, b);
		spin_unlock(&c->open_buckets_lock);
	}
}

static struct open_bucket *bch2_open_bucket_get(struct bch_fs *c,
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
		trace_open_bucket_alloc(c, cl);
	} else {
		trace_open_bucket_alloc_fail(c, cl);

		if (cl) {
			closure_wait(&c->open_buckets_wait, cl);
			ret = ERR_PTR(-EAGAIN);
		} else
			ret = ERR_PTR(-ENOSPC);
	}

	spin_unlock(&c->open_buckets_lock);

	return ret;
}

static unsigned ob_ptr_sectors_free(struct bch_fs *c,
				    struct open_bucket *ob,
				    struct bch_extent_ptr *ptr)
{
	struct bch_dev *ca = c->devs[ptr->dev];
	unsigned i = ptr - ob->ptrs;
	unsigned bucket_size = ca->mi.bucket_size;
	unsigned used = (ptr->offset & (bucket_size - 1)) +
		ob->ptr_offset[i];

	BUG_ON(used > bucket_size);

	return bucket_size - used;
}

static unsigned open_bucket_sectors_free(struct bch_fs *c,
					 struct open_bucket *ob,
					 unsigned nr_replicas)
{
	unsigned i, sectors_free = UINT_MAX;

	for (i = 0; i < min(nr_replicas, ob->nr_ptrs); i++)
		sectors_free = min(sectors_free,
				   ob_ptr_sectors_free(c, ob, &ob->ptrs[i]));

	return sectors_free != UINT_MAX ? sectors_free : 0;
}

static void open_bucket_copy_unused_ptrs(struct bch_fs *c,
					 struct open_bucket *new,
					 struct open_bucket *old)
{
	unsigned i;

	for (i = 0; i < old->nr_ptrs; i++)
		if (ob_ptr_sectors_free(c, old, &old->ptrs[i])) {
			struct bch_extent_ptr tmp = old->ptrs[i];

			tmp.offset += old->ptr_offset[i];
			new->ptrs[new->nr_ptrs] = tmp;
			new->ptr_offset[new->nr_ptrs] = 0;
			new->nr_ptrs++;
		}
}

static void verify_not_stale(struct bch_fs *c, const struct open_bucket *ob)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	const struct bch_extent_ptr *ptr;

	open_bucket_for_each_ptr(ob, ptr) {
		struct bch_dev *ca = c->devs[ptr->dev];

		BUG_ON(ptr_stale(ca, ptr));
	}
#endif
}

/* Sector allocator */

static struct open_bucket *lock_writepoint(struct bch_fs *c,
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

static int open_bucket_add_buckets(struct bch_fs *c,
				   struct write_point *wp,
				   struct open_bucket *ob,
				   unsigned nr_replicas,
				   unsigned nr_replicas_required,
				   enum alloc_reserve reserve,
				   struct closure *cl)
{
	long devs_used[BITS_TO_LONGS(BCH_SB_MEMBERS_MAX)];
	unsigned i;
	int ret;

	/*
	 * We might be allocating pointers to add to an existing extent
	 * (tiering/copygc/migration) - if so, some of the pointers in our
	 * existing open bucket might duplicate devices we already have. This is
	 * moderately annoying.
	 */

	/* Short circuit all the fun stuff if posssible: */
	if (ob->nr_ptrs >= nr_replicas)
		return 0;

	memset(devs_used, 0, sizeof(devs_used));

	for (i = 0; i < ob->nr_ptrs; i++)
		__set_bit(ob->ptrs[i].dev, devs_used);

	ret = bch2_bucket_alloc_set(c, wp, ob, nr_replicas,
				   reserve, devs_used, cl);

	if (ret == -EROFS &&
	    ob->nr_ptrs >= nr_replicas_required)
		ret = 0;

	return ret;
}

/*
 * Get us an open_bucket we can allocate from, return with it locked:
 */
struct open_bucket *bch2_alloc_sectors_start(struct bch_fs *c,
					     struct write_point *wp,
					     unsigned nr_replicas,
					     unsigned nr_replicas_required,
					     enum alloc_reserve reserve,
					     struct closure *cl)
{
	struct open_bucket *ob;
	unsigned open_buckets_reserved = wp == &c->btree_write_point
		? 0 : BTREE_NODE_RESERVE;
	int ret;

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

		new_ob = bch2_open_bucket_get(c, open_buckets_reserved, cl);
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
			bch2_open_bucket_put(c, new_ob);

			if (ob)
				mutex_unlock(&ob->lock);
			goto retry;
		}

		if (ob) {
			open_bucket_copy_unused_ptrs(c, new_ob, ob);
			mutex_unlock(&ob->lock);
			bch2_open_bucket_put(c, ob);
		}

		ob = new_ob;
	}

	ret = open_bucket_add_buckets(c, wp, ob, nr_replicas,
				      nr_replicas_required,
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
void bch2_alloc_sectors_append_ptrs(struct bch_fs *c, struct bkey_i_extent *e,
				    unsigned nr_replicas, struct open_bucket *ob,
				    unsigned sectors)
{
	struct bch_extent_ptr tmp;
	bool has_data = false;
	unsigned i;

	/*
	 * We're keeping any existing pointer k has, and appending new pointers:
	 * __bch2_write() will only write to the pointers we add here:
	 */

	BUG_ON(sectors > ob->sectors_free);

	/* didn't use all the ptrs: */
	if (nr_replicas < ob->nr_ptrs)
		has_data = true;

	for (i = 0; i < min(ob->nr_ptrs, nr_replicas); i++) {
		EBUG_ON(bch2_extent_has_device(extent_i_to_s_c(e), ob->ptrs[i].dev));

		tmp = ob->ptrs[i];
		tmp.cached = bkey_extent_is_cached(&e->k);
		tmp.offset += ob->ptr_offset[i];
		extent_ptr_append(e, tmp);

		ob->ptr_offset[i] += sectors;

		this_cpu_add(*c->devs[tmp.dev]->sectors_written, sectors);
	}
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch2_alloc_sectors_done(struct bch_fs *c, struct write_point *wp,
			    struct open_bucket *ob)
{
	bool has_data = false;
	unsigned i;

	for (i = 0; i < ob->nr_ptrs; i++) {
		if (!ob_ptr_sectors_free(c, ob, &ob->ptrs[i]))
			ob->has_full_ptrs = true;
		else
			has_data = true;
	}

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
 * @c  - filesystem.
 * @wp - write point to use for allocating sectors.
 * @k  - key to return the allocated space information.
 * @cl - closure to wait for a bucket
 */
struct open_bucket *bch2_alloc_sectors(struct bch_fs *c,
				       struct write_point *wp,
				       struct bkey_i_extent *e,
				       unsigned nr_replicas,
				       unsigned nr_replicas_required,
				       enum alloc_reserve reserve,
				       struct closure *cl)
{
	struct open_bucket *ob;

	ob = bch2_alloc_sectors_start(c, wp, nr_replicas,
				     nr_replicas_required,
				     reserve, cl);
	if (IS_ERR_OR_NULL(ob))
		return ob;

	if (e->k.size > ob->sectors_free)
		bch2_key_resize(&e->k, ob->sectors_free);

	bch2_alloc_sectors_append_ptrs(c, e, nr_replicas, ob, e->k.size);

	bch2_alloc_sectors_done(c, wp, ob);

	return ob;
}

/* Startup/shutdown (ro/rw): */

void bch2_recalc_capacity(struct bch_fs *c)
{
	struct bch_tier *fastest_tier = NULL, *slowest_tier = NULL, *tier;
	struct bch_dev *ca;
	u64 total_capacity, capacity = 0, reserved_sectors = 0;
	unsigned long ra_pages = 0;
	unsigned i, j;

	for_each_online_member(ca, c, i) {
		struct backing_dev_info *bdi =
			blk_get_backing_dev_info(ca->disk_sb.bdev);

		ra_pages += bdi->ra_pages;
	}

	c->bdi.ra_pages = ra_pages;

	/* Find fastest, slowest tiers with devices: */

	for (tier = c->tiers;
	     tier < c->tiers + ARRAY_SIZE(c->tiers); tier++) {
		if (!tier->devs.nr)
			continue;
		if (!fastest_tier)
			fastest_tier = tier;
		slowest_tier = tier;
	}

	c->fastest_tier = fastest_tier != slowest_tier ? fastest_tier : NULL;

	c->promote_write_point.group = &fastest_tier->devs;

	if (!fastest_tier)
		goto set_capacity;

	/*
	 * Capacity of the filesystem is the capacity of all the devices in the
	 * slowest (highest) tier - we don't include lower tier devices.
	 */
	spin_lock(&slowest_tier->devs.lock);
	group_for_each_dev(ca, &slowest_tier->devs, i) {
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
	spin_unlock(&slowest_tier->devs.lock);
set_capacity:
	total_capacity = capacity;

	capacity *= (100 - c->opts.gc_reserve_percent);
	capacity = div64_u64(capacity, 100);

	BUG_ON(capacity + reserved_sectors > total_capacity);

	c->capacity = capacity;

	if (c->capacity) {
		bch2_io_timer_add(&c->io_clock[READ],
				 &c->prio_clock[READ].rescale);
		bch2_io_timer_add(&c->io_clock[WRITE],
				 &c->prio_clock[WRITE].rescale);
	} else {
		bch2_io_timer_del(&c->io_clock[READ],
				 &c->prio_clock[READ].rescale);
		bch2_io_timer_del(&c->io_clock[WRITE],
				 &c->prio_clock[WRITE].rescale);
	}

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->freelist_wait);
}

static void bch2_stop_write_point(struct bch_dev *ca,
				 struct write_point *wp)
{
	struct bch_fs *c = ca->fs;
	struct open_bucket *ob;
	struct bch_extent_ptr *ptr;

	ob = lock_writepoint(c, wp);
	if (!ob)
		return;

	for (ptr = ob->ptrs; ptr < ob->ptrs + ob->nr_ptrs; ptr++)
		if (ptr->dev == ca->dev_idx)
			goto found;

	mutex_unlock(&ob->lock);
	return;
found:
	BUG_ON(xchg(&wp->b, NULL) != ob);
	mutex_unlock(&ob->lock);

	/* Drop writepoint's ref: */
	bch2_open_bucket_put(c, ob);
}

static bool bch2_dev_has_open_write_point(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bch_extent_ptr *ptr;
	struct open_bucket *ob;

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++)
		if (atomic_read(&ob->pin)) {
			mutex_lock(&ob->lock);
			for (ptr = ob->ptrs; ptr < ob->ptrs + ob->nr_ptrs; ptr++)
				if (ptr->dev == ca->dev_idx) {
					mutex_unlock(&ob->lock);
					return true;
				}
			mutex_unlock(&ob->lock);
		}

	return false;
}

/* device goes ro: */
void bch2_dev_allocator_stop(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct dev_group *tier = &c->tiers[ca->mi.tier].devs;
	struct task_struct *p;
	struct closure cl;
	unsigned i;

	closure_init_stack(&cl);

	/* First, remove device from allocation groups: */

	bch2_dev_group_remove(tier, ca);
	bch2_dev_group_remove(&c->all_devs, ca);

	bch2_recalc_capacity(c);

	/*
	 * Stopping the allocator thread comes after removing from allocation
	 * groups, else pending allocations will hang:
	 */

	p = ca->alloc_thread;
	ca->alloc_thread = NULL;
	smp_wmb();

	/*
	 * We need an rcu barrier between setting ca->alloc_thread = NULL and
	 * the thread shutting down to avoid a race with bch2_usage_update() -
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
		bch2_stop_write_point(ca, &c->write_points[i]);

	bch2_stop_write_point(ca, &ca->copygc_write_point);
	bch2_stop_write_point(ca, &c->promote_write_point);
	bch2_stop_write_point(ca, &ca->tiering_write_point);
	bch2_stop_write_point(ca, &c->migration_write_point);
	bch2_stop_write_point(ca, &c->btree_write_point);

	mutex_lock(&c->btree_reserve_cache_lock);
	while (c->btree_reserve_cache_nr) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		bch2_open_bucket_put(c, a->ob);
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

	/* Avoid deadlocks.. */

	closure_wake_up(&c->freelist_wait);
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	while (1) {
		closure_wait(&c->open_buckets_wait, &cl);

		if (!bch2_dev_has_open_write_point(ca)) {
			closure_wake_up(&c->open_buckets_wait);
			break;
		}

		closure_sync(&cl);
	}
}

/*
 * Startup the allocator thread for transition to RW mode:
 */
int bch2_dev_allocator_start(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct dev_group *tier = &c->tiers[ca->mi.tier].devs;
	struct bch_sb_field_journal *journal_buckets;
	bool has_journal;
	struct task_struct *k;

	/*
	 * allocator thread already started?
	 */
	if (ca->alloc_thread)
		return 0;

	k = kthread_create(bch2_allocator_thread, ca, "bcache_allocator");
	if (IS_ERR(k))
		return 0;

	get_task_struct(k);
	ca->alloc_thread = k;

	bch2_dev_group_add(tier, ca);
	bch2_dev_group_add(&c->all_devs, ca);

	mutex_lock(&c->sb_lock);
	journal_buckets = bch2_sb_get_journal(ca->disk_sb.sb);
	has_journal = bch2_nr_journal_buckets(journal_buckets) >=
		BCH_JOURNAL_BUCKETS_MIN;
	mutex_unlock(&c->sb_lock);

	if (has_journal)
		bch2_dev_group_add(&c->journal.devs, ca);

	bch2_recalc_capacity(c);

	/*
	 * Don't wake up allocator thread until after adding device to
	 * allocator groups - otherwise, alloc thread could get a spurious
	 * -EROFS due to prio_write() -> journal_meta() not finding any devices:
	 */
	wake_up_process(k);
	return 0;
}

void bch2_fs_allocator_init(struct bch_fs *c)
{
	unsigned i;

	INIT_LIST_HEAD(&c->open_buckets_open);
	INIT_LIST_HEAD(&c->open_buckets_free);
	spin_lock_init(&c->open_buckets_lock);
	bch2_prio_timer_init(c, READ);
	bch2_prio_timer_init(c, WRITE);

	/* open bucket 0 is a sentinal NULL: */
	mutex_init(&c->open_buckets[0].lock);
	INIT_LIST_HEAD(&c->open_buckets[0].list);

	for (i = 1; i < ARRAY_SIZE(c->open_buckets); i++) {
		mutex_init(&c->open_buckets[i].lock);
		c->open_buckets_nr_free++;
		list_add(&c->open_buckets[i].list, &c->open_buckets_free);
	}

	spin_lock_init(&c->all_devs.lock);

	for (i = 0; i < ARRAY_SIZE(c->tiers); i++)
		spin_lock_init(&c->tiers[i].devs.lock);

	for (i = 0; i < ARRAY_SIZE(c->write_points); i++)
		c->write_points[i].throttle = true;

	c->pd_controllers_update_seconds = 5;
	INIT_DELAYED_WORK(&c->pd_controllers_update, pd_controllers_update);

	spin_lock_init(&c->foreground_write_pd_lock);
	bch2_pd_controller_init(&c->foreground_write_pd);
	/*
	 * We do not want the write rate to have an effect on the computed
	 * rate, for two reasons:
	 *
	 * We do not call bch2_ratelimit_delay() at all if the write rate
	 * exceeds 1GB/s. In this case, the PD controller will think we are
	 * not "keeping up" and not change the rate.
	 */
	c->foreground_write_pd.backpressure = 0;
	init_timer(&c->foreground_write_wakeup);

	c->foreground_write_wakeup.data = (unsigned long) c;
	c->foreground_write_wakeup.function = bch2_wake_delayed_writes;
}
