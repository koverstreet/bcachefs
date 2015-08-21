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

static void bucket_stats_update(struct cache *ca,
				struct bucket_mark old,
				struct bucket_mark new)
{
	struct bucket_stats *stats = &ca->bucket_stats[0];
	int v;

	if ((v = ((int) new.owned_by_allocator - (int) old.owned_by_allocator)))
		atomic_add_bug(v, &stats->buckets_alloc);

	if ((v = ((int) new.is_metadata - (int) old.is_metadata)))
		atomic_add_bug(v, &stats->buckets_meta);

	if ((v = ((int) new.cached_sectors - (int) old.cached_sectors)))
		atomic64_add_bug(v, &stats->sectors_cached);

	if ((v = ((int) !!new.cached_sectors - (int) !!old.cached_sectors)))
		atomic_add_bug(v, &stats->buckets_cached);

	if ((v = ((int) new.dirty_sectors - (int) old.dirty_sectors)))
		atomic64_add_bug(v, &stats->sectors_dirty);

	if ((v = ((int) !!new.dirty_sectors - (int) !!old.dirty_sectors)))
		atomic_add_bug(v, &stats->buckets_dirty);
}

struct bucket_mark bch_bucket_mark_set(struct cache *ca, struct bucket *g,
				       struct bucket_mark new)
{
	struct bucket_mark old = xchg(&g->mark, new);

	bucket_stats_update(ca, old, new);
	return old;
}

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
		if (old.counter == _v) {			\
			bucket_stats_update(ca, old, new);	\
			break;					\
		}						\
		old.counter = _v;				\
	}							\
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

void bch_mark_data_bucket(struct cache *ca, struct bucket *g,
			  int sectors, bool dirty)
{
	struct bucket_mark old, new;

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.is_metadata);
		if (dirty)
			saturated_add(ca, new.dirty_sectors, sectors,
				      GC_MAX_SECTORS_USED);
		else
			saturated_add(ca, new.cached_sectors, sectors,
				      GC_MAX_SECTORS_USED);
	}));
}

void bch_unmark_open_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;

	bucket_cmpxchg(g, old, new, ({
		BUG_ON(old.is_metadata);
		new.owned_by_allocator = 0;
	}));
}
