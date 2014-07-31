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
#include "buckets.h"

#include <trace/events/bcachefs.h>

#define bucket_cmpxchg(g, old, new, expr)			\
do {								\
	old = (g)->mark;					\
	while (1) {						\
		u32 _v;						\
								\
		new.counter = old.counter;			\
		expr;						\
		_v = cmpxchg(&(g)->mark.counter,		\
			     old.counter,			\
			     new.counter);			\
		if (old.counter == _v)				\
			break;					\
		old.counter = _v;				\
	}							\
} while (0)

void bch_mark_free_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;
	struct bucket_stats *stats = &ca->bucket_stats[0];

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.dirty_sectors);
		BUG_ON(old.cached_sectors);
		new.counter = 0;
	}));

	if (old.owned_by_allocator)
		atomic_dec_bug(&stats->buckets_alloc);
	else if (old.is_metadata)
		atomic_dec_bug(&stats->buckets_meta);
}

void bch_mark_alloc_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;
	struct bucket_stats *stats = &ca->bucket_stats[0];

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.dirty_sectors);
		new.counter = 0;
		new.owned_by_allocator = 1;
	}));

	if (!old.owned_by_allocator) {
		if (old.cached_sectors) {
			atomic64_sub_bug(old.cached_sectors,
					 &stats->sectors_cached);
			atomic_dec_bug(&stats->buckets_cached);
			trace_bcache_invalidate(ca, g - ca->buckets,
						old.cached_sectors);
		} else if (old.is_metadata)
			atomic_dec_bug(&stats->buckets_meta);

		atomic_inc(&stats->buckets_alloc);
	}
}

void bch_mark_metadata_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;
	struct bucket_stats *stats = &ca->bucket_stats[0];

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.cached_sectors);
		BUG_ON(old.dirty_sectors);
		new.is_metadata = 1;
		new.owned_by_allocator = 0;
	}));

	if (old.owned_by_allocator) {
		atomic_inc(&stats->buckets_meta);
		atomic_dec_bug(&stats->buckets_alloc);
	} else if (!old.is_metadata)
		atomic_inc(&stats->buckets_meta);
}

#define saturated_add(ca, dst, src, max)			\
do {								\
	if ((dst) == (max))					\
		;						\
	else if ((dst) + (src) <= (max))			\
		dst += (src);					\
	else {							\
		dst = (max);					\
		trace_bcache_sectors_saturated(ca);		\
	}							\
} while (0)

void bch_mark_data_bucket(struct cache *ca, struct bucket *g,
			  int sectors, bool dirty)
{
	struct bucket_mark old, new;
	struct bucket_stats *stats = &ca->bucket_stats[0];

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.is_metadata);
		if (dirty)
			saturated_add(ca, new.dirty_sectors, sectors,
				      GC_MAX_SECTORS_USED);
		else
			saturated_add(ca, new.cached_sectors, sectors,
				      GC_MAX_SECTORS_USED);
	}));

	if (!old.owned_by_allocator) {
		if (dirty) {
			atomic64_add_bug(sectors, &stats->sectors_dirty);

			if (!old.dirty_sectors && new.dirty_sectors) {
				if (old.cached_sectors)
					atomic_dec_bug(&stats->buckets_cached);
				atomic_inc(&stats->buckets_dirty);
			} else if (old.dirty_sectors && !new.dirty_sectors) {
				if (old.cached_sectors)
					atomic_inc(&stats->buckets_cached);
				atomic_dec(&stats->buckets_dirty);
			}
		} else {
			atomic64_add_bug(sectors, &stats->sectors_cached);

			if (old.dirty_sectors)
				/* don't count buckets twice */;
			else if (!old.cached_sectors && new.cached_sectors)
				atomic_inc(&stats->buckets_cached);
			else if (old.cached_sectors && !new.cached_sectors)
				atomic_dec_bug(&stats->buckets_cached);
		}
	}
}
