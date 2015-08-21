/*
 * Code for manipulating bucket marks for garbage collection.
 *
 * Copyright 2014 Datera, Inc.
 *
 * Bucket states:
 * - free bucket: mark == 0
 *   The bucket contains no data and will not be read
 *
 * - allocator bucket: owned_by_allocator == 1
 *   The bucket is on a free list, or it is an open bucket
 *
 * - cached bucket: owned_by_allocator == 0 &&
 *                  dirty_sectors == 0 &&
 *                  cached_sectors > 0
 *   The bucket contains data but may be safely discarded as the
 *   we have another replica of the data on a cache device, or it
 *   has been written back to the backing device
 *
 * - dirty bucket: owned_by_allocator == 0 &&
 *                 dirty_sectors > 0
 *   The bucket contains data that we only have one copy of
 *
 * - metadata bucket: owned_by_allocator == 0 && is_metadata == 1
 *   This is a btree node, journal or prio bucket
 *
 * Lifecycle:
 *
 * bucket invalidated => bucket on freelist => open bucket =>
 *     dirty bucket => clean bucket => bucket invalidated => ...
 *
 * Transitions:
 *
 * - free => allocator: bucket was invalidated
 * - cached => allocator: bucket was invalidated
 *
 * - allocator => dirty: open bucket was filled up
 * - allocator => cached: open bucket was filled up
 * - allocator => metadata: metadata was allocated
 *
 * - dirty => cached: dirty sectors were overwritten
 * - dirty => free: dirty sectors were overwritten
 * - cached => free: cached sectors were overwritten
 *
 * - metadata => free: metadata was freed
 *
 * Oddities:
 * - cached => dirty: a device was removed so formerly replicated data
 *                    is no longer sufficiently replicated
 * - free => cached: cannot happen
 * - free => dirty: cannot happen
 * - free => metadata: cannot happen
 */

#include "bcache.h"
#include "btree.h"
#include "buckets.h"

#include <trace/events/bcachefs.h>

static inline int is_meta_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && m.is_metadata;
}

static inline int is_dirty_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && !!m.dirty_sectors;
}

static inline int is_cached_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && !m.dirty_sectors && !!m.cached_sectors;
}

static void bucket_stats_update(struct cache *ca,
				struct bucket_mark old,
				struct bucket_mark new)
{
	struct bucket_stats *stats;

	preempt_disable();
	stats = this_cpu_ptr(ca->bucket_stats_percpu);

	stats->sectors_cached +=
		(int) new.cached_sectors - (int) old.cached_sectors;

	stats->sectors_dirty +=
		(int) new.dirty_sectors - (int) old.dirty_sectors;

	stats->buckets_alloc +=
		(int) new.owned_by_allocator - (int) old.owned_by_allocator;

	stats->buckets_meta += is_meta_bucket(new) - is_meta_bucket(old);
	stats->buckets_cached += is_cached_bucket(new) - is_cached_bucket(old);
	stats->buckets_dirty += is_dirty_bucket(new) - is_dirty_bucket(old);

	preempt_enable();

	if (!is_available_bucket(old) &&
	    is_available_bucket(new))
		wake_up_process(ca->alloc_thread);
}

static struct bucket_mark bch_bucket_mark_set(struct cache *ca,
					      struct bucket *g,
					      struct bucket_mark new)
{
	struct bucket_mark old = xchg(&g->mark, new);

	bucket_stats_update(ca, old, new);
	return old;
}

#define bucket_cmpxchg(g, old, new, expr)			\
do {								\
	u32 _v = READ_ONCE((g)->mark.counter);			\
								\
	do {							\
		new.counter = old.counter = _v;			\
		expr;						\
	} while ((_v = cmpxchg(&(g)->mark.counter,		\
			       old.counter,			\
			       new.counter)) != old.counter);	\
	bucket_stats_update(ca, old, new);			\
} while (0)

void bch_mark_free_bucket(struct cache *ca, struct bucket *g)
{
	bch_bucket_mark_set(ca, g, (struct bucket_mark) { .counter = 0 });
}

void bch_mark_alloc_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old = bch_bucket_mark_set(ca, g,
			(struct bucket_mark) { .owned_by_allocator = 1 });

	BUG_ON(old.dirty_sectors);

	if (!old.owned_by_allocator && old.cached_sectors)
		trace_bcache_invalidate(ca, g - ca->buckets,
					old.cached_sectors);
}

void bch_mark_metadata_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old = bch_bucket_mark_set(ca, g,
			(struct bucket_mark) { .is_metadata = 1 });

	BUG_ON(old.cached_sectors);
	BUG_ON(old.dirty_sectors);
}

#define saturated_add(ca, dst, src, max)			\
do {								\
	BUG_ON((int) (dst) + (src) < 0);			\
	if ((dst) == (max))					\
		;						\
	else if ((dst) + (src) <= (max))			\
		dst += (src);					\
	else {							\
		dst = (max);					\
		trace_bcache_sectors_saturated(ca);		\
	}							\
} while (0)

u8 bch_mark_data_bucket(struct cache_set *c, struct cache *ca, struct bkey *k,
			unsigned i, int sectors, bool dirty, bool gc)
{
	struct bucket_mark old, new;
	unsigned long bucket_nr = PTR_BUCKET_NR(c, k, i);
	unsigned gen = PTR_GEN(k, i);
	unsigned saturated;
	u8 stale;

	bucket_cmpxchg(&ca->buckets[bucket_nr], old, new, ({
		saturated = 0;
		/*
		 * cmpxchg() only implies a full barrier on success, not
		 * failure, so we need a read barrier on all iterations -
		 * between reading the mark and checking pointer validity/gc
		 * status
		 */
		smp_rmb();

		/*
		 * Check this after reading bucket mark to guard against
		 * the allocator invalidating a bucket after we've already
		 * checked the gen
		 */
		stale = gen_after(ca->bucket_gens[bucket_nr], gen);
		if (stale)
			return stale;

		/*
		 * Check this after reading bucket mark to guard against
		 * GC starting between when we check gc_cur_key and when
		 * the GC zeroes out marks
		 */
		if (!gc && gc_will_visit_key(c, k))
			return 0;

		BUG_ON(old.is_metadata);
		if (dirty &&
		    new.dirty_sectors == GC_MAX_SECTORS_USED &&
		    sectors < 0)
			saturated = -sectors;

		if (dirty)
			saturated_add(ca, new.dirty_sectors, sectors,
				      GC_MAX_SECTORS_USED);
		else
			saturated_add(ca, new.cached_sectors, sectors,
				      GC_MAX_SECTORS_USED);
	}));

	if (saturated &&
	    atomic_long_add_return(saturated,
				   &ca->saturated_count) >=
	    ca->free_inc.size << c->bucket_bits)
		wake_up_process(ca->alloc_thread);


	return 0;
}

void bch_unmark_open_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.is_metadata);
		new.owned_by_allocator = 0;
	}));
}
