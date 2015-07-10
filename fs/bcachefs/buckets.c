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

struct bucket_stats bch_bucket_stats_read(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket_stats ret;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&c->gc_cur_lock);
		ret = c->gc_cur_phase == GC_PHASE_DONE
			? __bucket_stats_read(ca)
			: ca->bucket_stats_cached;
	} while (read_seqcount_retry(&c->gc_cur_lock, seq));

	return ret;
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

static void bucket_stats_update(struct cache *ca,
				struct bucket_mark old,
				struct bucket_mark new,
				bool may_make_unavailable)
{
	struct bucket_stats *stats;

	BUG_ON(!may_make_unavailable &&
	       is_available_bucket(old) &&
	       !is_available_bucket(new) &&
	       ca->set->gc_cur_phase == GC_PHASE_DONE);

	preempt_disable();
	stats = this_cpu_ptr(ca->bucket_stats_percpu);

	stats->sectors_cached +=
		(int) new.cached_sectors - (int) old.cached_sectors;

	if (old.is_metadata)
		stats->sectors_meta -= old.dirty_sectors;
	else
		stats->sectors_dirty -= old.dirty_sectors;

	if (new.is_metadata)
		stats->sectors_meta += new.dirty_sectors;
	else
		stats->sectors_dirty += new.dirty_sectors;

	stats->buckets_alloc +=
		(int) new.owned_by_allocator - (int) old.owned_by_allocator;

	stats->buckets_meta += is_meta_bucket(new) - is_meta_bucket(old);
	stats->buckets_cached += is_cached_bucket(new) - is_cached_bucket(old);
	stats->buckets_dirty += is_dirty_bucket(new) - is_dirty_bucket(old);

	preempt_enable();

	if (!is_available_bucket(old) && is_available_bucket(new))
		bch_wake_allocator(ca);
}

static struct bucket_mark bch_bucket_mark_set(struct cache *ca,
					      struct bucket *g,
					      struct bucket_mark new,
					      bool may_make_unavailable)
{
	struct bucket_mark old = xchg(&g->mark, new);

	bucket_stats_update(ca, old, new, may_make_unavailable);
	return old;
}

#define bucket_cmpxchg(g, old, new, may_make_unavailable, expr)	\
do {								\
	u32 _v = READ_ONCE((g)->mark.counter);			\
								\
	do {							\
		new.counter = old.counter = _v;			\
		expr;						\
	} while ((_v = cmpxchg(&(g)->mark.counter,		\
			       old.counter,			\
			       new.counter)) != old.counter);	\
	bucket_stats_update(ca, old, new, may_make_unavailable);\
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

static u8 bch_mark_bucket(struct cache_set *c, struct cache *ca,
			  struct btree *b, const struct bch_extent_ptr *ptr,
			  int sectors, bool dirty, bool metadata, bool is_gc)
{
	struct bucket_mark old, new;
	unsigned long bucket_nr = PTR_BUCKET_NR(ca, ptr);
	unsigned saturated;
	u8 stale;

	bucket_cmpxchg(&ca->buckets[bucket_nr], old, new, is_gc, ({
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
		stale = gen_after(ca->bucket_gens[bucket_nr], ptr->gen);
		if (stale)
			return stale;

		if (!is_gc) {
			/*
			 * Check this after reading bucket mark to guard against
			 * GC starting between when we check gc_cur_key and when
			 * the GC zeroes out marks
			 */
			if (b
			    ? gc_will_visit_node(c, b)
			    : gc_will_visit_root(c, BTREE_ID_EXTENTS))
				return 0;

			/*
			 * Disallowed state transition - this means a bkey_cmpxchg()
			 * operation is racing; just treat it like the pointer was
			 * already stale
			 */
			if (dirty && is_available_bucket(old))
				return 1;
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

	return 0;
}

/*
 * Returns 0 on success, -1 on failure (pointer was stale)
 */
int bch_mark_pointers(struct cache_set *c, struct btree *b,
		      struct bkey_s_c_extent e, int sectors,
		      bool fail_if_stale, bool metadata, bool is_gc)
{
	const struct bch_extent_ptr *ptr, *ptr2;
	struct cache *ca;

	BUG_ON(metadata && bkey_extent_is_cached(e.k));
	BUG_ON(!sectors);

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca) {
		bool stale, dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		trace_bcache_mark_bucket(ca, e.k, ptr, sectors, dirty);

		/*
		 * Two ways a dirty pointer could be stale here:
		 *
		 * - A bkey_cmpxchg() operation could be trying to replace a key
		 *   that no longer exists. The new key, which can have some of
		 *   the same pointers as the old key, gets added here before
		 *   checking if the cmpxchg operation succeeds or not to avoid
		 *   another race.
		 *
		 *   If that's the case, we just bail out of the cmpxchg
		 *   operation early - a dirty pointer can only be stale if the
		 *   actual dirty pointer in the btree was overwritten.
		 *
		 *   And in that case we _have_ to bail out here instead of
		 *   letting bkey_cmpxchg() fail and undoing the accounting we
		 *   did here with subtract_sectors() (like we do otherwise),
		 *   because buckets going stale out from under us changes which
		 *   pointers we count as dirty.
		 *
		 * - Journal replay
		 *
		 *   A dirty pointer could be stale in journal replay if we
		 *   haven't finished journal replay - if it's going to get
		 *   overwritten again later in replay.
		 *
		 *   In that case, we don't want to fail the insert (just for
		 *   mental health) - but, since extent_normalize() drops stale
		 *   pointers, we need to count replicas in a way that's
		 *   invariant under normalize.
		 *
		 *   Fuck me, I hate my life.
		 */
		stale = bch_mark_bucket(c, ca, b, ptr, sectors,
					dirty, metadata, is_gc);
		if (stale && dirty && fail_if_stale)
			goto stale;
	}
	rcu_read_unlock();

	return 0;
stale:
	extent_for_each_online_device(c, e, ptr2, ca) {
		if (ptr2 == ptr)
			break;

		bch_mark_bucket(c, ca, b, ptr, -sectors,
				bch_extent_ptr_is_dirty(c, e, ptr),
				metadata, is_gc);
	}
	rcu_read_unlock();

	return -1;
}

void bch_unmark_open_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_mark old, new;

	bucket_cmpxchg(g, old, new, false, ({
		new.owned_by_allocator = 0;
	}));
}
