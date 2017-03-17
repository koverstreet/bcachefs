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
#include <linux/sched/task.h>
#include <linux/sort.h>
#include <trace/events/bcachefs.h>

static void bch2_recalc_min_prio(struct bch_dev *, int);

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

		for_each_member_device_rcu(ca, c, iter, &c->tiers[i].devs) {
			struct bch_dev_usage stats = bch2_dev_usage_read(ca);
			unsigned bucket_bits = ca->bucket_bits + 9;

			u64 size = (ca->mi.nbuckets -
				    ca->mi.first_bucket) << bucket_bits;
			u64 dirty = stats.buckets[S_DIRTY] << bucket_bits;
			u64 free = __dev_buckets_free(ca, stats) << bucket_bits;
			/*
			 * Bytes of internal fragmentation, which can be
			 * reclaimed by copy GC
			 */
			s64 fragmented = ((stats.buckets[S_DIRTY] +
					   stats.buckets_cached) <<
					  bucket_bits) -
				((stats.sectors[S_DIRTY] +
				  stats.sectors_cached) << 9);

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

static unsigned bch_alloc_val_u64s(const struct bch_alloc *a)
{
	unsigned bytes = offsetof(struct bch_alloc, data);

	if (a->fields & (1 << BCH_ALLOC_FIELD_READ_TIME))
		bytes += 2;
	if (a->fields & (1 << BCH_ALLOC_FIELD_WRITE_TIME))
		bytes += 2;

	return DIV_ROUND_UP(bytes, sizeof(u64));
}

static const char *bch2_alloc_invalid(const struct bch_fs *c,
				      struct bkey_s_c k)
{
	if (k.k->p.inode >= c->sb.nr_devices ||
	    !c->devs[k.k->p.inode])
		return "invalid device";

	switch (k.k->type) {
	case BCH_ALLOC: {
		struct bkey_s_c_alloc a = bkey_s_c_to_alloc(k);

		if (bch_alloc_val_u64s(a.v) != bkey_val_u64s(a.k))
			return "incorrect value size";
		break;
	}
	default:
		return "invalid type";
	}

	return NULL;
}

static void bch2_alloc_to_text(struct bch_fs *c, char *buf,
			       size_t size, struct bkey_s_c k)
{
	buf[0] = '\0';

	switch (k.k->type) {
	case BCH_ALLOC:
		break;
	}
}

const struct bkey_ops bch2_bkey_alloc_ops = {
	.key_invalid	= bch2_alloc_invalid,
	.val_to_text	= bch2_alloc_to_text,
};

static inline unsigned get_alloc_field(const u8 **p, unsigned bytes)
{
	unsigned v;

	switch (bytes) {
	case 1:
		v = **p;
		break;
	case 2:
		v = le16_to_cpup((void *) *p);
		break;
	case 4:
		v = le32_to_cpup((void *) *p);
		break;
	default:
		BUG();
	}

	*p += bytes;
	return v;
}

static inline void put_alloc_field(u8 **p, unsigned bytes, unsigned v)
{
	switch (bytes) {
	case 1:
		**p = v;
		break;
	case 2:
		*((__le16 *) *p) = cpu_to_le16(v);
		break;
	case 4:
		*((__le32 *) *p) = cpu_to_le32(v);
		break;
	default:
		BUG();
	}

	*p += bytes;
}

static void bch2_alloc_read_key(struct bch_fs *c, struct bkey_s_c k)
{
	struct bch_dev *ca;
	struct bkey_s_c_alloc a;
	struct bucket_mark new;
	struct bucket *g;
	const u8 *d;

	if (k.k->type != BCH_ALLOC)
		return;

	a = bkey_s_c_to_alloc(k);
	ca = c->devs[a.k->p.inode];

	if (a.k->p.offset >= ca->mi.nbuckets)
		return;

	g = ca->buckets + a.k->p.offset;
	bucket_cmpxchg(g, new, ({
		new.gen = a.v->gen;
		new.gen_valid = 1;
	}));

	d = a.v->data;
	if (a.v->fields & (1 << BCH_ALLOC_FIELD_READ_TIME))
		g->prio[READ] = get_alloc_field(&d, 2);
	if (a.v->fields & (1 << BCH_ALLOC_FIELD_WRITE_TIME))
		g->prio[WRITE] = get_alloc_field(&d, 2);
}

int bch2_alloc_read(struct bch_fs *c, struct list_head *journal_replay_list)
{
	struct journal_replay *r;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	if (!c->btree_roots[BTREE_ID_ALLOC].b)
		return 0;

	for_each_btree_key(&iter, c, BTREE_ID_ALLOC, POS_MIN, 0, k) {
		bch2_alloc_read_key(c, k);
		bch2_btree_iter_cond_resched(&iter);
	}

	ret = bch2_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	list_for_each_entry(r, journal_replay_list, list) {
		struct bkey_i *k, *n;
		struct jset_entry *entry;

		for_each_jset_key(k, n, entry, &r->j)
			if (entry->btree_id == BTREE_ID_ALLOC)
				bch2_alloc_read_key(c, bkey_i_to_s_c(k));
	}

	return 0;
}

static int __bch2_alloc_write_key(struct bch_fs *c, struct bch_dev *ca,
				  struct bucket *g, struct btree_iter *iter,
				  u64 *journal_seq)
{
	struct bucket_mark m;
	__BKEY_PADDED(k, DIV_ROUND_UP(sizeof(struct bch_alloc), 8)) alloc_key;
	struct bkey_i_alloc *a;
	u8 *d;
	int ret;

	bch2_btree_iter_set_pos(iter, POS(ca->dev_idx, g - ca->buckets));

	do {
		ret = bch2_btree_iter_traverse(iter);
		if (ret)
			break;

		/* read mark under btree node lock: */
		m = READ_ONCE(g->mark);
		a = bkey_alloc_init(&alloc_key.k);
		a->k.p		= iter->pos;
		a->v.fields	= 0;
		a->v.gen	= m.gen;
		set_bkey_val_u64s(&a->k, bch_alloc_val_u64s(&a->v));

		d = a->v.data;
		if (a->v.fields & (1 << BCH_ALLOC_FIELD_READ_TIME))
			put_alloc_field(&d, 2, g->prio[READ]);
		if (a->v.fields & (1 << BCH_ALLOC_FIELD_WRITE_TIME))
			put_alloc_field(&d, 2, g->prio[WRITE]);

		bch2_btree_iter_set_pos(iter, a->k.p);
		ret = bch2_btree_insert_at(c, NULL, NULL, journal_seq,
					   BTREE_INSERT_ATOMIC|
					   BTREE_INSERT_NOFAIL|
					   BTREE_INSERT_USE_RESERVE|
					   BTREE_INSERT_USE_ALLOC_RESERVE|
					   BTREE_INSERT_NOWAIT,
					   BTREE_INSERT_ENTRY(iter, &a->k_i));
		bch2_btree_iter_cond_resched(iter);
	} while (ret == -EINTR);

	return ret;
}

int bch2_alloc_replay_key(struct bch_fs *c, struct bpos pos)
{
	struct bch_dev *ca;
	struct bucket *g;
	struct btree_iter iter;
	int ret;

	if (pos.inode >= c->sb.nr_devices || !c->devs[pos.inode])
		return 0;

	ca = c->devs[pos.inode];

	if (pos.offset >= ca->mi.nbuckets)
		return 0;

	g = ca->buckets + pos.offset;

	bch2_btree_iter_init(&iter, c, BTREE_ID_ALLOC, POS_MIN,
			     BTREE_ITER_INTENT);

	ret = __bch2_alloc_write_key(c, ca, g, &iter, NULL);
	bch2_btree_iter_unlock(&iter);
	return ret;
}

static int bch2_alloc_write(struct bch_fs *c, struct bch_dev *ca, u64 *journal_seq)
{
	struct btree_iter iter;
	unsigned long bucket;
	int ret = 0;

	bch2_btree_iter_init(&iter, c, BTREE_ID_ALLOC, POS_MIN,
			     BTREE_ITER_INTENT);

	for_each_set_bit(bucket, ca->bucket_dirty, ca->mi.nbuckets) {
		ret = __bch2_alloc_write_key(c, ca, ca->buckets + bucket,
					     &iter, journal_seq);
		if (ret)
			break;

		clear_bit(bucket, ca->bucket_dirty);
	}

	bch2_btree_iter_unlock(&iter);
	return ret;
}

#define BUCKET_GC_GEN_MAX	96U

/**
 * wait_buckets_available - wait on reclaimable buckets
 *
 * If there aren't enough available buckets to fill up free_inc, wait until
 * there are.
 */
static int wait_buckets_available(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned long gc_count = c->gc_count;
	int ret = 0;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			ret = -1;
			break;
		}

		if (gc_count != c->gc_count)
			ca->inc_gen_really_needs_gc = 0;

		if ((ssize_t) (dev_buckets_available(ca) -
			       ca->inc_gen_really_needs_gc) >=
		    (ssize_t) fifo_free(&ca->free_inc))
			break;

		up_read(&c->gc_lock);
		schedule();
		try_to_freeze();
		down_read(&c->gc_lock);
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

static bool bch2_can_invalidate_bucket(struct bch_dev *ca, struct bucket *g,
				       struct bucket_mark mark)
{
	if (!is_available_bucket(mark))
		return false;

	if (bucket_gc_gen(ca, g) >= BUCKET_GC_GEN_MAX / 2)
		ca->inc_gen_needs_gc++;

	if (bucket_gc_gen(ca, g) >= BUCKET_GC_GEN_MAX)
		ca->inc_gen_really_needs_gc++;

	return can_inc_bucket_gen(ca, g);
}

static void bch2_invalidate_one_bucket(struct bch_dev *ca, struct bucket *g)
{
	struct bch_fs *c = ca->fs;
	struct bucket_mark m;

	spin_lock(&ca->freelist_lock);
	if (!bch2_invalidate_bucket(ca, g, &m)) {
		spin_unlock(&ca->freelist_lock);
		return;
	}

	verify_not_on_freelist(ca, g - ca->buckets);
	BUG_ON(!fifo_push(&ca->free_inc, g - ca->buckets));
	spin_unlock(&ca->freelist_lock);

	g->prio[READ] = c->prio_clock[READ].hand;
	g->prio[WRITE] = c->prio_clock[WRITE].hand;

	if (m.cached_sectors) {
		ca->allocator_invalidating_data = true;
	} else if (m.journal_seq_valid) {
		u64 journal_seq = atomic64_read(&c->journal.seq);
		u64 bucket_seq	= journal_seq;

		bucket_seq &= ~((u64) U16_MAX);
		bucket_seq |= m.journal_seq;

		if (bucket_seq > journal_seq)
			bucket_seq -= 1 << 16;

		ca->allocator_journal_seq_flush =
			max(ca->allocator_journal_seq_flush, bucket_seq);
	}
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
 * - If hotness * sectors used compares equal, we pick the bucket with the
 *   smallest bucket_gc_gen() - since incrementing the same bucket's generation
 *   number repeatedly forces us to run mark and sweep gc to avoid generation
 *   number wraparound.
 */

static unsigned long bucket_sort_key(struct bch_dev *ca,
				     struct bucket *g,
				     struct bucket_mark m)
{
	/*
	 * Time since last read, scaled to [0, 8) where larger value indicates
	 * more recently read data:
	 */
	unsigned long hotness =
		(g->prio[READ]			- ca->min_prio[READ]) * 7 /
		(ca->fs->prio_clock[READ].hand	- ca->min_prio[READ]);

	/* How much we want to keep the data in this bucket: */
	unsigned long data_wantness =
		(hotness + 1) * bucket_sectors_used(m);

	unsigned long needs_journal_commit =
		    bucket_needs_journal_commit(m, ca->fs->journal.last_seq_ondisk);

	return  (data_wantness << 9) |
		(needs_journal_commit << 8) |
		bucket_gc_gen(ca, g);
}

static inline int bucket_alloc_cmp(alloc_heap *h,
				   struct alloc_heap_entry l,
				   struct alloc_heap_entry r)
{
	return (l.key > r.key) - (l.key < r.key);
}

static void invalidate_buckets_lru(struct bch_dev *ca)
{
	struct alloc_heap_entry e;
	struct bucket *g;

	ca->alloc_heap.used = 0;

	mutex_lock(&ca->fs->bucket_lock);
	bch2_recalc_min_prio(ca, READ);
	bch2_recalc_min_prio(ca, WRITE);

	/*
	 * Find buckets with lowest read priority, by building a maxheap sorted
	 * by read priority and repeatedly replacing the maximum element until
	 * all buckets have been visited.
	 */
	for_each_bucket(g, ca) {
		struct bucket_mark m = READ_ONCE(g->mark);

		if (!bch2_can_invalidate_bucket(ca, g, m))
			continue;

		e = (struct alloc_heap_entry) {
			.bucket = g - ca->buckets,
			.key	= bucket_sort_key(ca, g, m)
		};

		heap_add_or_replace(&ca->alloc_heap, e, -bucket_alloc_cmp);
	}

	heap_resort(&ca->alloc_heap, bucket_alloc_cmp);

	/*
	 * If we run out of buckets to invalidate, bch2_allocator_thread() will
	 * kick stuff and retry us
	 */
	while (!fifo_full(&ca->free_inc) &&
	       heap_pop(&ca->alloc_heap, e, bucket_alloc_cmp))
		bch2_invalidate_one_bucket(ca, &ca->buckets[e.bucket]);

	mutex_unlock(&ca->fs->bucket_lock);
}

static void invalidate_buckets_fifo(struct bch_dev *ca)
{
	struct bucket_mark m;
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->mi.first_bucket ||
		    ca->fifo_last_bucket >= ca->mi.nbuckets)
			ca->fifo_last_bucket = ca->mi.first_bucket;

		g = ca->buckets + ca->fifo_last_bucket++;
		m = READ_ONCE(g->mark);

		if (bch2_can_invalidate_bucket(ca, g, m))
			bch2_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets)
			return;
	}
}

static void invalidate_buckets_random(struct bch_dev *ca)
{
	struct bucket_mark m;
	struct bucket *g;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n = bch2_rand_range(ca->mi.nbuckets -
					  ca->mi.first_bucket) +
			ca->mi.first_bucket;

		g = ca->buckets + n;
		m = READ_ONCE(g->mark);

		if (bch2_can_invalidate_bucket(ca, g, m))
			bch2_invalidate_one_bucket(ca, g);

		if (++checked >= ca->mi.nbuckets / 2)
			return;
	}
}

static void invalidate_buckets(struct bch_dev *ca)
{
	ca->inc_gen_needs_gc			= 0;
	ca->inc_gen_really_needs_gc		= 0;

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

static int size_t_cmp(const void *_l, const void *_r)
{
	const size_t *l = _l, *r = _r;

	return (*l > *r) - (*l < *r);
}

static int bch2_invalidate_free_inc(struct bch_fs *c, struct bch_dev *ca,
				    u64 *journal_seq)
{
	struct btree_iter iter;
	unsigned nr_invalidated = 0;
	size_t b, i;
	int ret = 0;

	bch2_btree_iter_init(&iter, c, BTREE_ID_ALLOC, POS(ca->dev_idx, 0),
			     BTREE_ITER_INTENT);

	fifo_for_each_entry(b, &ca->free_inc, i) {
		ret = __bch2_alloc_write_key(c, ca, ca->buckets + b,
					     &iter, journal_seq);
		if (ret)
			break;

		nr_invalidated++;
	}

	bch2_btree_iter_unlock(&iter);
	return nr_invalidated ?: ret;
}

/*
 * Given an invalidated, ready to use bucket: issue a discard to it if enabled,
 * then add it to the freelist, waiting until there's room if necessary:
 */
static void discard_invalidated_bucket(struct bch_dev *ca, long bucket)
{
	if (ca->mi.discard &&
	    blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev)))
		blkdev_issue_discard(ca->disk_sb.bdev,
				     bucket_to_sector(ca, bucket),
				     ca->mi.bucket_size, GFP_NOIO, 0);

	while (1) {
		bool pushed = false;
		unsigned i;

		set_current_state(TASK_INTERRUPTIBLE);

		/*
		 * Don't remove from free_inc until after it's added to
		 * freelist, so gc can find it:
		 */
		spin_lock(&ca->freelist_lock);
		for (i = 0; i < RESERVE_NR; i++)
			if (fifo_push(&ca->free[i], bucket)) {
				fifo_pop(&ca->free_inc, bucket);
				closure_wake_up(&ca->fs->freelist_wait);
				pushed = true;
				break;
			}
		spin_unlock(&ca->freelist_lock);

		if (pushed)
			break;

		if (kthread_should_stop())
			break;

		schedule();
		try_to_freeze();
	}

	__set_current_state(TASK_RUNNING);
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
	u64 journal_seq;
	size_t bucket;
	int ret;

	set_freezable();

	while (1) {
		while (1) {
			while (ca->nr_invalidated) {
				BUG_ON(fifo_empty(&ca->free_inc));

				bucket = fifo_peek(&ca->free_inc);
				discard_invalidated_bucket(ca, bucket);
				if (kthread_should_stop())
					return 0;
				--ca->nr_invalidated;
			}

			if (fifo_empty(&ca->free_inc))
				break;

			journal_seq = 0;
			ret = bch2_invalidate_free_inc(c, ca, &journal_seq);
			if (ret < 0)
				return 0;

			ca->nr_invalidated = ret;

			if (ca->nr_invalidated == fifo_used(&ca->free_inc)) {
				ca->alloc_thread_started = true;
				bch2_alloc_write(c, ca, &journal_seq);
			}

			if (ca->allocator_invalidating_data)
				bch2_journal_flush_seq(&c->journal, journal_seq);
			else if (ca->allocator_journal_seq_flush)
				bch2_journal_flush_seq(&c->journal,
						       ca->allocator_journal_seq_flush);
		}

		/* Reset front/back so we can easily sort fifo entries later: */
		ca->free_inc.front = ca->free_inc.back	= 0;
		ca->allocator_journal_seq_flush		= 0;
		ca->allocator_invalidating_data		= false;

		down_read(&c->gc_lock);
		if (test_bit(BCH_FS_GC_FAILURE, &c->flags)) {
			up_read(&c->gc_lock);
			return 0;
		}

		while (1) {
			/*
			 * Find some buckets that we can invalidate, either
			 * they're completely unused, or only contain clean data
			 * that's been written back to the backing device or
			 * another cache tier
			 */

			invalidate_buckets(ca);
			trace_alloc_batch(ca, fifo_used(&ca->free_inc),
					  ca->free_inc.size);

			if ((ca->inc_gen_needs_gc >= ca->free_inc.size ||
			     (!fifo_full(&ca->free_inc) &&
			      ca->inc_gen_really_needs_gc >=
			      fifo_free(&ca->free_inc))) &&
			    c->gc_thread) {
				atomic_inc(&c->kick_gc);
				wake_up_process(c->gc_thread);
			}

			if (fifo_full(&ca->free_inc))
				break;

			if (wait_buckets_available(c, ca)) {
				up_read(&c->gc_lock);
				return 0;
			}
		}
		up_read(&c->gc_lock);

		BUG_ON(ca->free_inc.front);

		spin_lock(&ca->freelist_lock);
		sort(ca->free_inc.data,
		     ca->free_inc.back,
		     sizeof(ca->free_inc.data[0]),
		     size_t_cmp, NULL);
		spin_unlock(&ca->freelist_lock);

		/*
		 * free_inc is now full of newly-invalidated buckets: next,
		 * write out the new bucket gens:
		 */
	}
}

/* Allocation */

/*
 * XXX: allocation on startup is still sketchy. There is insufficient
 * synchronization for bch2_bucket_alloc_startup() to work correctly after
 * bch2_alloc_write() has been called, and we aren't currently doing anything
 * to guarantee that this won't happen.
 *
 * Even aside from that, it's really difficult to avoid situations where on
 * startup we write out a pointer to a freshly allocated bucket before the
 * corresponding gen - when we're still digging ourself out of the "i need to
 * allocate to write bucket gens, but i need to write bucket gens to allocate"
 * hole.
 *
 * Fortunately, bch2_btree_mark_key_initial() will detect and repair this
 * easily enough...
 */
static long bch2_bucket_alloc_startup(struct bch_fs *c, struct bch_dev *ca)
{
	struct bucket *g;
	long r = -1;

	if (!down_read_trylock(&c->gc_lock))
		return r;

	if (test_bit(BCH_FS_GC_FAILURE, &c->flags))
		goto out;

	for_each_bucket(g, ca)
		if (!g->mark.touched_this_mount &&
		    is_available_bucket(g->mark) &&
		    bch2_mark_alloc_bucket_startup(ca, g)) {
			r = g - ca->buckets;
			set_bit(r, ca->bucket_dirty);
			break;
		}
out:
	up_read(&c->gc_lock);
	return r;
}

/**
 * bch_bucket_alloc - allocate a single bucket from a specific device
 *
 * Returns index of bucket on success, 0 on failure
 * */
long bch2_bucket_alloc(struct bch_fs *c, struct bch_dev *ca,
		       enum alloc_reserve reserve)
{
	size_t r;

	spin_lock(&ca->freelist_lock);
	if (likely(fifo_pop(&ca->free[RESERVE_NONE], r)))
		goto out;

	switch (reserve) {
	case RESERVE_ALLOC:
		if (fifo_pop(&ca->free[RESERVE_BTREE], r))
			goto out;
		break;
	case RESERVE_BTREE:
		if (fifo_used(&ca->free[RESERVE_BTREE]) * 2 >=
		    ca->free[RESERVE_BTREE].size &&
		    fifo_pop(&ca->free[RESERVE_BTREE], r))
			goto out;
		break;
	case RESERVE_MOVINGGC:
		if (fifo_pop(&ca->free[RESERVE_MOVINGGC], r))
			goto out;
		break;
	default:
		break;
	}

	spin_unlock(&ca->freelist_lock);

	if (unlikely(!ca->alloc_thread_started) &&
	    (reserve == RESERVE_ALLOC) &&
	    (r = bch2_bucket_alloc_startup(c, ca)) >= 0) {
		verify_not_on_freelist(ca, r);
		goto out2;
	}

	trace_bucket_alloc_fail(ca, reserve);
	return -1;
out:
	verify_not_on_freelist(ca, r);
	spin_unlock(&ca->freelist_lock);

	bch2_wake_allocator(ca);
out2:
	ca->buckets[r].prio[READ]	= c->prio_clock[READ].hand;
	ca->buckets[r].prio[WRITE]	= c->prio_clock[WRITE].hand;

	trace_bucket_alloc(ca, reserve);
	return r;
}

enum bucket_alloc_ret {
	ALLOC_SUCCESS,
	NO_DEVICES,		/* -EROFS */
	FREELIST_EMPTY,		/* Allocator thread not keeping up */
};

struct dev_alloc_list bch2_wp_alloc_list(struct bch_fs *c,
					 struct write_point *wp,
					 struct bch_devs_mask *devs)
{
	struct dev_alloc_list ret = { .nr = 0 };
	struct bch_dev *ca, *ca2;
	unsigned i, j;

	for_each_member_device_rcu(ca, c, i, devs) {
		for (j = 0; j < ret.nr; j++) {
			unsigned idx = ret.devs[j];

			ca2 = rcu_dereference(c->devs[idx]);
			if (!ca2)
				break;

			if (ca->mi.tier < ca2->mi.tier)
				break;

			if (ca->mi.tier == ca2->mi.tier &&
			    wp->next_alloc[i] < wp->next_alloc[idx])
				break;
		}

		memmove(&ret.devs[j + 1],
			&ret.devs[j],
			sizeof(ret.devs[0]) * (ret.nr - j));
		ret.nr++;
		ret.devs[j] = i;
	}

	return ret;
}

void bch2_wp_rescale(struct bch_fs *c, struct bch_dev *ca,
		     struct write_point *wp)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(wp->next_alloc); i++)
		wp->next_alloc[i] >>= 1;
}

static enum bucket_alloc_ret __bch2_bucket_alloc_set(struct bch_fs *c,
					struct write_point *wp,
					struct open_bucket *ob,
					unsigned nr_replicas,
					enum alloc_reserve reserve,
					struct bch_devs_mask *devs)
{
	enum bucket_alloc_ret ret = NO_DEVICES;
	struct dev_alloc_list devs_sorted;
	unsigned i;

	BUG_ON(nr_replicas > ARRAY_SIZE(ob->ptrs));

	if (ob->nr_ptrs >= nr_replicas)
		return ALLOC_SUCCESS;

	rcu_read_lock();
	devs_sorted = bch2_wp_alloc_list(c, wp, devs);

	for (i = 0; i < devs_sorted.nr; i++) {
		struct bch_dev *ca =
			rcu_dereference(c->devs[devs_sorted.devs[i]]);
		long bucket;

		if (!ca)
			continue;

		bucket = bch2_bucket_alloc(c, ca, reserve);
		if (bucket < 0) {
			ret = FREELIST_EMPTY;
			continue;
		}

		wp->next_alloc[ca->dev_idx] +=
			div64_u64(U64_MAX, dev_buckets_free(ca) *
				  ca->mi.bucket_size);
		bch2_wp_rescale(c, ca, wp);

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

		if (ob->nr_ptrs == nr_replicas) {
			ret = ALLOC_SUCCESS;
			break;
		}
	}

	EBUG_ON(ret != ALLOC_SUCCESS && reserve == RESERVE_MOVINGGC);
	rcu_read_unlock();
	return ret;
}

static int bch2_bucket_alloc_set(struct bch_fs *c, struct write_point *wp,
				struct open_bucket *ob, unsigned nr_replicas,
				enum alloc_reserve reserve,
				struct bch_devs_mask *devs,
				struct closure *cl)
{
	bool waiting = false;

	while (1) {
		switch (__bch2_bucket_alloc_set(c, wp, ob, nr_replicas,
						reserve, devs)) {
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

	while ((ob = READ_ONCE(wp->b))) {
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
	struct bch_devs_mask devs = c->rw_devs[wp->type];
	unsigned i;
	int ret;

	if (ob->nr_ptrs >= nr_replicas)
		return 0;

	/* Don't allocate from devices we already have pointers to: */
	for (i = 0; i < ob->nr_ptrs; i++)
		__clear_bit(ob->ptrs[i].dev, devs.d);

	if (wp->group)
		bitmap_and(devs.d, devs.d, wp->group->d, BCH_SB_MEMBERS_MAX);

	ret = bch2_bucket_alloc_set(c, wp, ob, nr_replicas,
				    reserve, &devs, cl);

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

	lockdep_assert_held(&c->state_lock);

	for_each_online_member(ca, c, i) {
		struct backing_dev_info *bdi = ca->disk_sb.bdev->bd_bdi;

		ra_pages += bdi->ra_pages;
	}

	if (c->vfs_sb)
		c->vfs_sb->s_bdi->ra_pages = ra_pages;

	/* Find fastest, slowest tiers with devices: */

	for (tier = c->tiers;
	     tier < c->tiers + ARRAY_SIZE(c->tiers); tier++) {
		if (!dev_mask_nr(&tier->devs))
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
	for_each_member_device_rcu(ca, c, i, &slowest_tier->devs) {
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
set_capacity:
	total_capacity = capacity;

	capacity *= (100 - c->opts.gc_reserve_percent);
	capacity = div64_u64(capacity, 100);

	BUG_ON(reserved_sectors > total_capacity);

	capacity = min(capacity, total_capacity - reserved_sectors);

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

static void bch2_stop_write_point(struct bch_fs *c, struct bch_dev *ca,
				  struct write_point *wp)
{
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

static bool bch2_dev_has_open_write_point(struct bch_fs *c, struct bch_dev *ca)
{
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
void bch2_dev_allocator_remove(struct bch_fs *c, struct bch_dev *ca)
{
	struct closure cl;
	unsigned i;

	BUG_ON(ca->alloc_thread);

	closure_init_stack(&cl);

	/* First, remove device from allocation groups: */

	clear_bit(ca->dev_idx, c->tiers[ca->mi.tier].devs.d);
	for (i = 0; i < ARRAY_SIZE(c->rw_devs); i++)
		clear_bit(ca->dev_idx, c->rw_devs[i].d);

	/*
	 * Capacity is calculated based off of devices in allocation groups:
	 */
	bch2_recalc_capacity(c);

	/* Next, close write points that point to this device... */
	for (i = 0; i < ARRAY_SIZE(c->write_points); i++)
		bch2_stop_write_point(c, ca, &c->write_points[i]);

	bch2_stop_write_point(c, ca, &ca->copygc_write_point);
	bch2_stop_write_point(c, ca, &c->promote_write_point);
	bch2_stop_write_point(c, ca, &c->tiers[ca->mi.tier].wp);
	bch2_stop_write_point(c, ca, &c->migration_write_point);
	bch2_stop_write_point(c, ca, &c->btree_write_point);

	mutex_lock(&c->btree_reserve_cache_lock);
	while (c->btree_reserve_cache_nr) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		bch2_open_bucket_put(c, a->ob);
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

	/*
	 * Wake up threads that were blocked on allocation, so they can notice
	 * the device can no longer be removed and the capacity has changed:
	 */
	closure_wake_up(&c->freelist_wait);

	/*
	 * journal_res_get() can block waiting for free space in the journal -
	 * it needs to notice there may not be devices to allocate from anymore:
	 */
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	while (1) {
		closure_wait(&c->open_buckets_wait, &cl);

		if (!bch2_dev_has_open_write_point(c, ca)) {
			closure_wake_up(&c->open_buckets_wait);
			break;
		}

		closure_sync(&cl);
	}
}

/* device goes rw: */
void bch2_dev_allocator_add(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->rw_devs); i++)
		if (ca->mi.data_allowed & (1 << i))
			set_bit(ca->dev_idx, c->rw_devs[i].d);
	set_bit(ca->dev_idx, c->tiers[ca->mi.tier].devs.d);
}

/* stop allocator thread: */
void bch2_dev_allocator_stop(struct bch_dev *ca)
{
	struct task_struct *p = ca->alloc_thread;

	ca->alloc_thread = NULL;

	/*
	 * We need an rcu barrier between setting ca->alloc_thread = NULL and
	 * the thread shutting down to avoid bch2_wake_allocator() racing:
	 *
	 * XXX: it would be better to have the rcu barrier be asynchronous
	 * instead of blocking us here
	 */
	synchronize_rcu();

	if (p) {
		kthread_stop(p);
		put_task_struct(p);
	}
}

/* start allocator thread: */
int bch2_dev_allocator_start(struct bch_dev *ca)
{
	struct task_struct *p;

	/*
	 * allocator thread already started?
	 */
	if (ca->alloc_thread)
		return 0;

	p = kthread_create(bch2_allocator_thread, ca, "bcache_allocator");
	if (IS_ERR(p))
		return PTR_ERR(p);

	get_task_struct(p);
	ca->alloc_thread = p;
	wake_up_process(p);
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

	c->journal.wp.type		= BCH_DATA_JOURNAL;
	c->btree_write_point.type	= BCH_DATA_BTREE;

	for (i = 0; i < ARRAY_SIZE(c->tiers); i++)
		c->tiers[i].wp.type	= BCH_DATA_USER;

	for (i = 0; i < ARRAY_SIZE(c->write_points); i++)
		c->write_points[i].type = BCH_DATA_USER;

	c->promote_write_point.type	= BCH_DATA_USER;
	c->migration_write_point.type	= BCH_DATA_USER;

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
	timer_setup(&c->foreground_write_wakeup, bch2_wake_delayed_writes, 0);
}
