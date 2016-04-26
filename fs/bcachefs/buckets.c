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
 *   The bucket contains data but may be safely discarded as there are
 *   enough replicas of the data on other cache devices, or it has been
 *   written back to the backing device
 *
 * - dirty bucket: owned_by_allocator == 0 &&
 *                 dirty_sectors > 0
 *   The bucket contains data that we must not discard (either only copy,
 *   or one of the 'main copies' for data requiring multiple replicas)
 *
 * - metadata bucket: owned_by_allocator == 0 && is_metadata == 1
 *   This is a btree node, journal or gen/prio bucket
 *
 * Lifecycle:
 *
 * bucket invalidated => bucket on freelist => open bucket =>
 *     [dirty bucket =>] cached bucket => bucket invalidated => ...
 *
 * Note that cache promotion can skip the dirty bucket step, as data
 * is copied from a deeper tier to a shallower tier, onto a cached
 * bucket.
 * Note also that a cached bucket can spontaneously become dirty --
 * see below.
 *
 * Only a traversal of the key space can determine whether a bucket is
 * truly dirty or cached.
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
 * - dirty => cached: dirty sectors were copied to a deeper tier
 * - dirty => free: dirty sectors were overwritten or moved (copy gc)
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
#include "alloc.h"
#include "btree_gc.h"
#include "buckets.h"

#include <trace/events/bcachefs.h>

#define bucket_stats_add(_acc, _stats)					\
do {									\
	typeof(_acc) _a = (_acc), _s = (_stats);			\
	unsigned i;							\
									\
	for (i = 0; i < sizeof(*_a) / sizeof(u64); i++)			\
		((u64 *) (_a))[i] += ((u64 *) (_s))[i];			\
} while (0)

#define bucket_stats_read_raw(_stats)					\
({									\
	typeof(*this_cpu_ptr(_stats)) _acc = { 0 };			\
	int cpu;							\
									\
	for_each_possible_cpu(cpu)					\
		bucket_stats_add(&_acc, per_cpu_ptr((_stats), cpu));	\
									\
	_acc;								\
})

#define bucket_stats_read_cached(_c, _cached, _uncached)		\
({									\
	typeof(_cached) _ret;						\
	unsigned _seq;							\
									\
	do {								\
		_seq = read_seqcount_begin(&(_c)->gc_pos_lock);		\
		_ret = (_c)->gc_pos.phase == GC_PHASE_DONE		\
			? bucket_stats_read_raw(_uncached)		\
			: (_cached);					\
	} while (read_seqcount_retry(&(_c)->gc_pos_lock, _seq));	\
									\
	_ret;								\
})

struct bucket_stats_cache __bch_bucket_stats_read_cache(struct cache *ca)
{
	return bucket_stats_read_raw(ca->bucket_stats_percpu);
}

struct bucket_stats_cache bch_bucket_stats_read_cache(struct cache *ca)
{
	return bucket_stats_read_cached(ca->set,
				ca->bucket_stats_cached,
				ca->bucket_stats_percpu);
}

struct bucket_stats_cache_set
__bch_bucket_stats_read_cache_set(struct cache_set *c)
{
	return bucket_stats_read_raw(c->bucket_stats_percpu);
}

struct bucket_stats_cache_set
bch_bucket_stats_read_cache_set(struct cache_set *c)
{
	return bucket_stats_read_cached(c,
				c->bucket_stats_cached,
				c->bucket_stats_percpu);
}

static inline int is_meta_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && m.is_metadata;
}

static inline int is_dirty_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && !m.is_metadata && !!m.dirty_sectors;
}

static inline int is_cached_bucket(struct bucket_mark m)
{
	return !m.owned_by_allocator && !m.dirty_sectors && !!m.cached_sectors;
}

void bch_cache_set_stats_apply(struct cache_set *c,
			       struct bucket_stats_cache_set *stats,
			       struct disk_reservation *disk_res,
			       struct gc_pos gc_pos)
{
	s64 added = stats->sectors_dirty +
		stats->sectors_meta +
		stats->sectors_persistent_reserved +
		stats->sectors_online_reserved;

	/*
	 * Not allowed to reduce sectors_available except by getting a
	 * reservation:
	 */
	BUG_ON(added > (disk_res ? disk_res->sectors : 0));

	if (added > 0) {
		disk_res->sectors		-= added;
		stats->sectors_online_reserved	-= added;
	}

	lg_local_lock(&c->bucket_stats_lock);
	if (!gc_will_visit(c, gc_pos))
		bucket_stats_add(this_cpu_ptr(c->bucket_stats_percpu), stats);
	lg_local_unlock(&c->bucket_stats_lock);

	memset(stats, 0, sizeof(*stats));
}

static void bucket_stats_update(struct cache *ca,
			struct bucket_mark old, struct bucket_mark new,
			bool may_make_unavailable,
			struct bucket_stats_cache_set *cache_set_stats)
{
	struct cache_set *c = ca->set;
	struct bucket_stats_cache *cache_stats;

	BUG_ON(!may_make_unavailable &&
	       is_available_bucket(old) &&
	       !is_available_bucket(new) &&
	       c->gc_pos.phase == GC_PHASE_DONE);

	if (cache_set_stats) {
		cache_set_stats->sectors_cached +=
			(int) new.cached_sectors - (int) old.cached_sectors;

		if (old.is_metadata)
			cache_set_stats->sectors_meta -= old.dirty_sectors;
		else
			cache_set_stats->sectors_dirty -= old.dirty_sectors;

		if (new.is_metadata)
			cache_set_stats->sectors_meta += new.dirty_sectors;
		else
			cache_set_stats->sectors_dirty += new.dirty_sectors;
	}

	preempt_disable();
	cache_stats = this_cpu_ptr(ca->bucket_stats_percpu);

	cache_stats->sectors_cached +=
		(int) new.cached_sectors - (int) old.cached_sectors;

	if (old.is_metadata)
		cache_stats->sectors_meta -= old.dirty_sectors;
	else
		cache_stats->sectors_dirty -= old.dirty_sectors;

	if (new.is_metadata)
		cache_stats->sectors_meta += new.dirty_sectors;
	else
		cache_stats->sectors_dirty += new.dirty_sectors;

	cache_stats->buckets_alloc +=
		(int) new.owned_by_allocator - (int) old.owned_by_allocator;

	cache_stats->buckets_meta += is_meta_bucket(new) - is_meta_bucket(old);
	cache_stats->buckets_cached += is_cached_bucket(new) - is_cached_bucket(old);
	cache_stats->buckets_dirty += is_dirty_bucket(new) - is_dirty_bucket(old);
	preempt_enable();

	if (!is_available_bucket(old) && is_available_bucket(new))
		bch_wake_allocator(ca);
}

static struct bucket_mark bch_bucket_mark_set(struct cache *ca,
				struct bucket *g, struct bucket_mark new,
				bool may_make_unavailable)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old;

	old.counter = xchg(&g->mark.counter, new.counter);

	bucket_stats_update(ca, old, new, may_make_unavailable, &stats);

	/*
	 * Ick:
	 *
	 * Only stats.sectors_cached should be nonzero: this is important
	 * because in this path we modify cache_set_stats based on how the
	 * bucket_mark was modified, and the sector counts in bucket_mark are
	 * subject to (saturating) overflow - and if they did overflow, the
	 * cache set stats will now be off. We can tolerate this for
	 * sectors_cached, but not anything else:
	 * */
	stats.sectors_cached = 0;
	BUG_ON(!bch_is_zero((void *) &stats, sizeof(stats)));

	return old;
}

#define bucket_cmpxchg(g, old, new,				\
		       may_make_unavailable,			\
		       cache_set_stats, expr)			\
do {								\
	u32 _v = READ_ONCE((g)->mark.counter);			\
								\
	do {							\
		new.counter = old.counter = _v;			\
		expr;						\
	} while ((_v = cmpxchg(&(g)->mark.counter,		\
			       old.counter,			\
			       new.counter)) != old.counter);	\
	bucket_stats_update(ca, old, new,			\
			    may_make_unavailable,		\
			    cache_set_stats);			\
} while (0)

void bch_mark_free_bucket(struct cache *ca, struct bucket *g)
{
	bch_bucket_mark_set(ca, g,
			    (struct bucket_mark) { .counter = 0 },
			    false);
}

void bch_mark_alloc_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old = bch_bucket_mark_set(ca, g,
			(struct bucket_mark) { .owned_by_allocator = 1 },
			true);

	BUG_ON(old.dirty_sectors);

	if (!old.owned_by_allocator && old.cached_sectors)
		trace_bcache_invalidate(ca, g - ca->buckets,
					old.cached_sectors);
}

void bch_mark_metadata_bucket(struct cache *ca, struct bucket *g,
			      bool may_make_unavailable)
{
	struct bucket_mark old = bch_bucket_mark_set(ca, g,
			(struct bucket_mark) { .is_metadata = 1 },
			may_make_unavailable);

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

/*
 * Checking against gc's position has to be done here, inside the cmpxchg()
 * loop, to avoid racing with the start of gc clearing all the marks - GC does
 * that with the gc pos seqlock held.
 */
static void bch_mark_pointer(struct cache_set *c, struct cache *ca,
			     const struct bch_extent_ptr *ptr, int sectors,
			     bool dirty, bool metadata,
			     bool may_make_unavailable,
			     struct bucket_stats_cache_set *stats,
			     bool is_gc, struct gc_pos gc_pos)
{
	struct bucket_mark old, new;
	unsigned long bucket_nr = PTR_BUCKET_NR(ca, ptr);
	unsigned saturated;

	bucket_cmpxchg(&ca->buckets[bucket_nr], old, new,
		       may_make_unavailable, NULL, ({
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
		if (ptr_stale(ca, ptr)) {
			BUG_ON(metadata);
			return;
		}

		/*
		 * Check this after reading bucket mark to guard against
		 * GC starting between when we check gc_cur_key and when
		 * the GC zeroes out marks
		 */
		if (!is_gc && gc_will_visit(c, gc_pos))
			goto out;

		/*
		 * Disallowed state transition - this means a bkey_cmpxchg()
		 * operation is racing; just treat it like the pointer was
		 * already stale
		 */
		if (!may_make_unavailable &&
		    (metadata || dirty) &&
		    is_available_bucket(old)) {
			BUG_ON(metadata);
			return;
		}

		BUG_ON((old.dirty_sectors ||
			old.cached_sectors) &&
		       old.is_metadata != metadata);

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

		if (!new.dirty_sectors &&
		    !new.cached_sectors)
			new.is_metadata = false;
		else
			new.is_metadata = metadata;

	}));

	if (saturated &&
	    atomic_long_add_return(saturated,
				   &ca->saturated_count) >=
	    ca->free_inc.size << ca->bucket_bits) {
		if (c->gc_thread) {
			trace_bcache_gc_sectors_saturated(c);
			wake_up_process(c->gc_thread);
		}
	}
out:
	if (metadata)
		stats->sectors_meta += sectors;
	else if (dirty)
		stats->sectors_dirty += sectors;
	else
		stats->sectors_cached += sectors;
}

static void bch_mark_extent(struct cache_set *c, struct bkey_s_c_extent e,
			    int sectors, bool metadata,
			    bool may_make_unavailable,
			    struct bucket_stats_cache_set *stats,
			    bool is_gc, struct gc_pos gc_pos)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	BUG_ON(metadata && bkey_extent_is_cached(e.k));
	BUG_ON(!sectors);

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca) {
		bool dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		trace_bcache_mark_bucket(ca, e.k, ptr, sectors, dirty);

		bch_mark_pointer(c, ca, ptr, sectors, dirty, metadata,
				 may_make_unavailable, stats, is_gc, gc_pos);
	}
	rcu_read_unlock();
}

static void __bch_mark_key(struct cache_set *c, struct bkey_s_c k,
			   int sectors, bool metadata,
			   bool may_make_unavailable,
			   struct bucket_stats_cache_set *stats,
			   bool is_gc, struct gc_pos gc_pos)
{
	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		bch_mark_extent(c, bkey_s_c_to_extent(k), sectors, metadata,
				may_make_unavailable, stats, is_gc, gc_pos);
		break;
	case BCH_RESERVATION:
		stats->sectors_persistent_reserved += sectors;
		break;
	}
}

void __bch_gc_mark_key(struct cache_set *c, struct bkey_s_c k,
		       int sectors, bool metadata,
		       struct bucket_stats_cache_set *stats)
{
	__bch_mark_key(c, k, sectors, metadata, true, stats, true, GC_POS_MIN);
}

void bch_gc_mark_key(struct cache_set *c, struct bkey_s_c k,
		     int sectors, bool metadata)
{
	struct bucket_stats_cache_set stats = { 0 };

	__bch_gc_mark_key(c, k, sectors, metadata, &stats);

	preempt_disable();
	bucket_stats_add(this_cpu_ptr(c->bucket_stats_percpu), &stats);
	preempt_enable();
}

void bch_mark_key(struct cache_set *c, struct bkey_s_c k,
		  int sectors, bool metadata, struct gc_pos gc_pos,
		  struct bucket_stats_cache_set *stats)
{
	lg_local_lock(&c->bucket_stats_lock);
	__bch_mark_key(c, k, sectors, metadata, false, stats, false, gc_pos);
	lg_local_unlock(&c->bucket_stats_lock);
}

void bch_unmark_open_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old, new;

	bucket_cmpxchg(g, old, new, false, NULL, ({
		new.owned_by_allocator = 0;
	}));

	/* owned_by_allocator buckets aren't tracked in cache_set_stats: */
	BUG_ON(!bch_is_zero((void *) &stats, sizeof(stats)));
}

static u64 __recalc_sectors_available(struct cache_set *c)
{
	return c->capacity - cache_set_sectors_used(c);
}

/* Used by gc when it's starting: */
void bch_recalc_sectors_available(struct cache_set *c)
{
	int cpu;

	lg_global_lock(&c->bucket_stats_lock);

	for_each_possible_cpu(cpu)
		this_cpu_ptr(c->bucket_stats_percpu)->sectors_available_cache = 0;

	atomic64_set(&c->sectors_available,
		     __recalc_sectors_available(c));

	lg_global_unlock(&c->bucket_stats_lock);
}

void bch_disk_reservation_put(struct cache_set *c,
			      struct disk_reservation *res)
{
	this_cpu_sub(c->bucket_stats_percpu->sectors_online_reserved,
		     res->sectors);
	res->sectors = 0;
}

#define SECTORS_CACHE	1024

int __bch_disk_reservation_get(struct cache_set *c,
			       struct disk_reservation *res,
			       unsigned sectors,
			       bool check_enospc, bool gc_lock_held)
{
	struct bucket_stats_cache_set *stats;
	u64 old, new, v;
	s64 sectors_available;
	int ret;

	res->sectors = sectors;
	res->gen = c->capacity_gen;

	lg_local_lock(&c->bucket_stats_lock);
	stats = this_cpu_ptr(c->bucket_stats_percpu);

	if (sectors >= stats->sectors_available_cache)
		goto out;

	v = atomic64_read(&c->sectors_available);
	do {
		old = v;
		if (old < sectors) {
			lg_local_unlock(&c->bucket_stats_lock);
			goto recalculate;
		}

		new = max_t(s64, 0, old - sectors - SECTORS_CACHE);
	} while ((v = atomic64_cmpxchg(&c->sectors_available,
				       old, new)) != old);

	stats->sectors_available_cache	+= old - new;
out:
	stats->sectors_available_cache	-= sectors;
	stats->sectors_online_reserved	+= sectors;
	lg_local_unlock(&c->bucket_stats_lock);
	return 0;

recalculate:
	/*
	 * GC recalculates sectors_available when it starts, so that hopefully
	 * we don't normally end up blocking here:
	 */
	if (!gc_lock_held)
		down_read(&c->gc_lock);
	lg_global_lock(&c->bucket_stats_lock);

	sectors_available = __recalc_sectors_available(c);

	if (!check_enospc || sectors <= sectors_available) {
		atomic64_set(&c->sectors_available,
			     max_t(s64, 0, sectors_available - sectors));
		stats->sectors_online_reserved += sectors;
		ret = 0;
	} else {
		atomic64_set(&c->sectors_available, sectors_available);
		res->sectors = 0;
		ret = -ENOSPC;
	}

	lg_global_unlock(&c->bucket_stats_lock);
	if (!gc_lock_held)
		up_read(&c->gc_lock);

	return ret;
}

int bch_disk_reservation_get(struct cache_set *c,
			     struct disk_reservation *res,
			     unsigned sectors)
{
	return __bch_disk_reservation_get(c, res, sectors, true, false);
}
