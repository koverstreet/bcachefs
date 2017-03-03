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

#include <linux/preempt.h>
#include <trace/events/bcachefs.h>

#ifdef DEBUG_BUCKETS

#define lg_local_lock	lg_global_lock
#define lg_local_unlock	lg_global_unlock

static void bch_fs_stats_verify(struct cache_set *c)
{
	struct bucket_stats_cache_set stats =
		__bch_bucket_stats_read_cache_set(c);

	if ((s64) stats.sectors_dirty < 0)
		panic("sectors_dirty underflow: %lli\n", stats.sectors_dirty);

	if ((s64) stats.sectors_cached < 0)
		panic("sectors_cached underflow: %lli\n", stats.sectors_cached);

	if ((s64) stats.sectors_meta < 0)
		panic("sectors_meta underflow: %lli\n", stats.sectors_meta);

	if ((s64) stats.sectors_persistent_reserved < 0)
		panic("sectors_persistent_reserved underflow: %lli\n", stats.sectors_persistent_reserved);

	if ((s64) stats.sectors_online_reserved < 0)
		panic("sectors_online_reserved underflow: %lli\n", stats.sectors_online_reserved);
}

#else

static void bch_fs_stats_verify(struct cache_set *c) {}

#endif

void bch_bucket_seq_cleanup(struct cache_set *c)
{
	u16 last_seq_ondisk = c->journal.last_seq_ondisk;
	struct cache *ca;
	struct bucket *g;
	struct bucket_mark m;
	unsigned i;

	for_each_cache(ca, c, i)
		for_each_bucket(g, ca) {
			bucket_cmpxchg(g, m, ({
				if (!m.wait_on_journal ||
				    ((s16) last_seq_ondisk -
				     (s16) m.journal_seq < 0))
					break;

				m.wait_on_journal = 0;
			}));
		}
}

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

void bch_fs_stats_apply(struct cache_set *c,
			struct bucket_stats_cache_set *stats,
			struct disk_reservation *disk_res,
			struct gc_pos gc_pos)
{
	s64 added =
		stats->s[S_COMPRESSED][S_META] +
		stats->s[S_COMPRESSED][S_DIRTY] +
		stats->persistent_reserved +
		stats->online_reserved;

	/*
	 * Not allowed to reduce sectors_available except by getting a
	 * reservation:
	 */
	BUG_ON(added > (s64) (disk_res ? disk_res->sectors : 0));

	if (added > 0) {
		disk_res->sectors	-= added;
		stats->online_reserved	-= added;
	}

	lg_local_lock(&c->bucket_stats_lock);
	/* online_reserved not subject to gc: */
	this_cpu_ptr(c->bucket_stats_percpu)->online_reserved +=
		stats->online_reserved;
	stats->online_reserved = 0;

	if (!gc_will_visit(c, gc_pos))
		bucket_stats_add(this_cpu_ptr(c->bucket_stats_percpu), stats);

	bch_fs_stats_verify(c);
	lg_local_unlock(&c->bucket_stats_lock);

	memset(stats, 0, sizeof(*stats));
}

static void bucket_stats_update(struct cache *ca,
			struct bucket_mark old, struct bucket_mark new,
			bool may_make_unavailable,
			struct bucket_stats_cache_set *bch_alloc_stats)
{
	struct cache_set *c = ca->set;
	struct bucket_stats_cache *cache_stats;

	BUG_ON(!may_make_unavailable &&
	       is_available_bucket(old) &&
	       !is_available_bucket(new) &&
	       c->gc_pos.phase == GC_PHASE_DONE);

	if (bch_alloc_stats) {
		bch_alloc_stats->s[S_COMPRESSED][S_CACHED] +=
			(int) new.cached_sectors - (int) old.cached_sectors;

		bch_alloc_stats->s[S_COMPRESSED]
			[old.is_metadata ? S_META : S_DIRTY] -=
			old.dirty_sectors;

		bch_alloc_stats->s[S_COMPRESSED]
			[new.is_metadata ? S_META : S_DIRTY] +=
			new.dirty_sectors;
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

void bch_invalidate_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old, new;

	old = bucket_cmpxchg(g, new, ({
		new.owned_by_allocator	= 1;
		new.is_metadata		= 0;
		new.cached_sectors	= 0;
		new.dirty_sectors	= 0;
		new.copygc		= 0;
		new.gen++;
	}));

	BUG_ON(old.dirty_sectors);

	bucket_stats_update(ca, old, new, true, &stats);

	/*
	 * Ick:
	 *
	 * Only stats.sectors_cached should be nonzero: this is important
	 * because in this path we modify bch_alloc_stats based on how the
	 * bucket_mark was modified, and the sector counts in bucket_mark are
	 * subject to (saturating) overflow - and if they did overflow, the
	 * cache set stats will now be off. We can tolerate this for
	 * sectors_cached, but not anything else:
	 */
	stats.s[S_COMPRESSED][S_CACHED] = 0;
	stats.s[S_UNCOMPRESSED][S_CACHED] = 0;
	BUG_ON(!bch_is_zero(&stats, sizeof(stats)));

	if (!old.owned_by_allocator && old.cached_sectors)
		trace_bcache_invalidate(ca, g - ca->buckets,
					old.cached_sectors);
}

void bch_mark_free_bucket(struct cache *ca, struct bucket *g)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old, new;

	old = bucket_cmpxchg(g, new, ({
		new.owned_by_allocator	= 0;
		new.is_metadata		= 0;
		new.cached_sectors	= 0;
		new.dirty_sectors	= 0;
	}));

	bucket_stats_update(ca, old, new, false, &stats);
}

void bch_mark_alloc_bucket(struct cache *ca, struct bucket *g,
			   bool owned_by_allocator)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old, new;

	old = bucket_cmpxchg(g, new, new.owned_by_allocator = owned_by_allocator);

	bucket_stats_update(ca, old, new, true, &stats);
}

void bch_mark_metadata_bucket(struct cache *ca, struct bucket *g,
			      bool may_make_unavailable)
{
	struct bucket_stats_cache_set stats = { 0 };
	struct bucket_mark old, new;

	old = bucket_cmpxchg(g, new, ({
		new.is_metadata = 1;
		new.had_metadata = 1;
	}));

	BUG_ON(old.cached_sectors);
	BUG_ON(old.dirty_sectors);

	bucket_stats_update(ca, old, new, may_make_unavailable, &stats);
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

#if 0
/* Reverting this until the copygc + compression issue is fixed: */

static unsigned __disk_sectors(const union bch_extent_crc *crc, unsigned sectors)
{
	return crc_compression_type(crc)
		? sectors * crc_compressed_size(crc) / crc_uncompressed_size(crc)
		: sectors;
}

static unsigned __compressed_sectors(const union bch_extent_crc *crc, unsigned sectors)
{
	return crc_compression_type(crc)
		? min_t(unsigned, crc_compressed_size(crc), sectors)
		: sectors;
}
#else
static unsigned __disk_sectors(const union bch_extent_crc *crc, unsigned sectors)
{
	return sectors;
}

static unsigned __compressed_sectors(const union bch_extent_crc *crc, unsigned sectors)
{
	return sectors;
}
#endif

/*
 * Checking against gc's position has to be done here, inside the cmpxchg()
 * loop, to avoid racing with the start of gc clearing all the marks - GC does
 * that with the gc pos seqlock held.
 */
static void bch_mark_pointer(struct cache_set *c,
			     struct bkey_s_c_extent e,
			     struct cache *ca,
			     const union bch_extent_crc *crc,
			     const struct bch_extent_ptr *ptr,
			     s64 sectors, enum s_alloc type,
			     bool may_make_unavailable,
			     struct bucket_stats_cache_set *stats,
			     bool gc_will_visit, u64 journal_seq)
{
	struct bucket_mark old, new;
	unsigned saturated;
	struct bucket *g = ca->buckets + PTR_BUCKET_NR(ca, ptr);
	u64 v = READ_ONCE(g->_mark.counter);
	unsigned old_sectors, new_sectors;
	int disk_sectors, compressed_sectors;

	if (sectors > 0) {
		old_sectors = 0;
		new_sectors = sectors;
	} else {
		old_sectors = e.k->size;
		new_sectors = e.k->size + sectors;
	}

	disk_sectors = -__disk_sectors(crc, old_sectors)
		+ __disk_sectors(crc, new_sectors);
	compressed_sectors = -__compressed_sectors(crc, old_sectors)
		+ __compressed_sectors(crc, new_sectors);

	if (gc_will_visit) {
		if (journal_seq)
			bucket_cmpxchg(g, new, new.journal_seq = journal_seq);

		goto out;
	}

	do {
		new.counter = old.counter = v;
		saturated = 0;

		/*
		 * Check this after reading bucket mark to guard against
		 * the allocator invalidating a bucket after we've already
		 * checked the gen
		 */
		if (gen_after(old.gen, ptr->gen)) {
			EBUG_ON(type != S_CACHED &&
				test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags));
			return;
		}

		EBUG_ON(type != S_CACHED &&
			!may_make_unavailable &&
			is_available_bucket(old) &&
			test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags));

		if (type != S_CACHED &&
		    new.dirty_sectors == GC_MAX_SECTORS_USED &&
		    disk_sectors < 0)
			saturated = -disk_sectors;

		if (type == S_CACHED)
			saturated_add(ca, new.cached_sectors, disk_sectors,
				      GC_MAX_SECTORS_USED);
		else
			saturated_add(ca, new.dirty_sectors, disk_sectors,
				      GC_MAX_SECTORS_USED);

		if (!new.dirty_sectors &&
		    !new.cached_sectors) {
			new.is_metadata = false;

			if (journal_seq) {
				new.wait_on_journal = true;
				new.journal_seq = journal_seq;
			}
		} else {
			new.is_metadata = (type == S_META);
		}

		new.had_metadata |= new.is_metadata;
	} while ((v = cmpxchg(&g->_mark.counter,
			      old.counter,
			      new.counter)) != old.counter);

	bucket_stats_update(ca, old, new, may_make_unavailable, NULL);

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
	stats->s[S_COMPRESSED][type]	+= compressed_sectors;
	stats->s[S_UNCOMPRESSED][type]	+= sectors;
}

static void bch_mark_extent(struct cache_set *c, struct bkey_s_c_extent e,
			    s64 sectors, bool metadata,
			    bool may_make_unavailable,
			    struct bucket_stats_cache_set *stats,
			    bool gc_will_visit, u64 journal_seq)
{
	const struct bch_extent_ptr *ptr;
	const union bch_extent_crc *crc;
	struct cache *ca;
	enum s_alloc type = metadata ? S_META : S_DIRTY;

	BUG_ON(metadata && bkey_extent_is_cached(e.k));
	BUG_ON(!sectors);

	rcu_read_lock();
	extent_for_each_online_device_crc(c, e, crc, ptr, ca) {
		trace_bcache_mark_bucket(ca, e.k, ptr, sectors, !ptr->cached);

		bch_mark_pointer(c, e, ca, crc, ptr, sectors,
				 ptr->cached ? S_CACHED : type,
				 may_make_unavailable,
				 stats, gc_will_visit, journal_seq);
	}
	rcu_read_unlock();
}

static void __bch_mark_key(struct cache_set *c, struct bkey_s_c k,
			   s64 sectors, bool metadata,
			   bool may_make_unavailable,
			   struct bucket_stats_cache_set *stats,
			   bool gc_will_visit, u64 journal_seq)
{
	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		bch_mark_extent(c, bkey_s_c_to_extent(k), sectors, metadata,
				may_make_unavailable, stats,
				gc_will_visit, journal_seq);
		break;
	case BCH_RESERVATION: {
		struct bkey_s_c_reservation r = bkey_s_c_to_reservation(k);

		stats->persistent_reserved += r.v->nr_replicas * sectors;
		break;
	}
	}
}

void __bch_gc_mark_key(struct cache_set *c, struct bkey_s_c k,
		       s64 sectors, bool metadata,
		       struct bucket_stats_cache_set *stats)
{
	__bch_mark_key(c, k, sectors, metadata, true, stats, false, 0);
}

void bch_gc_mark_key(struct cache_set *c, struct bkey_s_c k,
		     s64 sectors, bool metadata)
{
	struct bucket_stats_cache_set stats = { 0 };

	__bch_gc_mark_key(c, k, sectors, metadata, &stats);

	preempt_disable();
	bucket_stats_add(this_cpu_ptr(c->bucket_stats_percpu), &stats);
	preempt_enable();
}

void bch_mark_key(struct cache_set *c, struct bkey_s_c k,
		  s64 sectors, bool metadata, struct gc_pos gc_pos,
		  struct bucket_stats_cache_set *stats, u64 journal_seq)
{
	/*
	 * synchronization w.r.t. GC:
	 *
	 * Normally, bucket sector counts/marks are updated on the fly, as
	 * references are added/removed from the btree, the lists of buckets the
	 * allocator owns, other metadata buckets, etc.
	 *
	 * When GC is in progress and going to mark this reference, we do _not_
	 * mark this reference here, to avoid double counting - GC will count it
	 * when it gets to it.
	 *
	 * To know whether we should mark a given reference (GC either isn't
	 * running, or has already marked references at this position) we
	 * construct a total order for everything GC walks. Then, we can simply
	 * compare the position of the reference we're marking - @gc_pos - with
	 * GC's current position. If GC is going to mark this reference, GC's
	 * current position will be less than @gc_pos; if GC's current position
	 * is greater than @gc_pos GC has either already walked this position,
	 * or isn't running.
	 *
	 * To avoid racing with GC's position changing, we have to deal with
	 *  - GC's position being set to GC_POS_MIN when GC starts:
	 *    bucket_stats_lock guards against this
	 *  - GC's position overtaking @gc_pos: we guard against this with
	 *    whatever lock protects the data structure the reference lives in
	 *    (e.g. the btree node lock, or the relevant allocator lock).
	 */
	lg_local_lock(&c->bucket_stats_lock);
	__bch_mark_key(c, k, sectors, metadata, false, stats,
		       gc_will_visit(c, gc_pos), journal_seq);

	bch_fs_stats_verify(c);
	lg_local_unlock(&c->bucket_stats_lock);
}

static u64 __recalc_sectors_available(struct cache_set *c)
{
	return c->capacity - bch_fs_sectors_used(c);
}

/* Used by gc when it's starting: */
void bch_recalc_sectors_available(struct cache_set *c)
{
	int cpu;

	lg_global_lock(&c->bucket_stats_lock);

	for_each_possible_cpu(cpu)
		per_cpu_ptr(c->bucket_stats_percpu, cpu)->available_cache = 0;

	atomic64_set(&c->sectors_available,
		     __recalc_sectors_available(c));

	lg_global_unlock(&c->bucket_stats_lock);
}

void bch_disk_reservation_put(struct cache_set *c,
			      struct disk_reservation *res)
{
	if (res->sectors) {
		lg_local_lock(&c->bucket_stats_lock);
		this_cpu_sub(c->bucket_stats_percpu->online_reserved,
			     res->sectors);

		bch_fs_stats_verify(c);
		lg_local_unlock(&c->bucket_stats_lock);

		res->sectors = 0;
	}
}

#define SECTORS_CACHE	1024

int bch_disk_reservation_add(struct cache_set *c,
			     struct disk_reservation *res,
			     unsigned sectors, int flags)
{
	struct bucket_stats_cache_set *stats;
	u64 old, new, v;
	s64 sectors_available;
	int ret;

	sectors *= res->nr_replicas;

	lg_local_lock(&c->bucket_stats_lock);
	stats = this_cpu_ptr(c->bucket_stats_percpu);

	if (sectors >= stats->available_cache)
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

	stats->available_cache	+= old - new;
out:
	stats->available_cache	-= sectors;
	stats->online_reserved	+= sectors;
	res->sectors		+= sectors;

	bch_fs_stats_verify(c);
	lg_local_unlock(&c->bucket_stats_lock);
	return 0;

recalculate:
	/*
	 * GC recalculates sectors_available when it starts, so that hopefully
	 * we don't normally end up blocking here:
	 */

	/*
	 * Piss fuck, we can be called from extent_insert_fixup() with btree
	 * locks held:
	 */

	if (!(flags & BCH_DISK_RESERVATION_GC_LOCK_HELD)) {
		if (!(flags & BCH_DISK_RESERVATION_BTREE_LOCKS_HELD))
			down_read(&c->gc_lock);
		else if (!down_read_trylock(&c->gc_lock))
			return -EINTR;
	}
	lg_global_lock(&c->bucket_stats_lock);

	sectors_available = __recalc_sectors_available(c);

	if (sectors <= sectors_available ||
	    (flags & BCH_DISK_RESERVATION_NOFAIL)) {
		atomic64_set(&c->sectors_available,
			     max_t(s64, 0, sectors_available - sectors));
		stats->online_reserved	+= sectors;
		res->sectors		+= sectors;
		ret = 0;
	} else {
		atomic64_set(&c->sectors_available, sectors_available);
		ret = -ENOSPC;
	}

	bch_fs_stats_verify(c);
	lg_global_unlock(&c->bucket_stats_lock);
	if (!(flags & BCH_DISK_RESERVATION_GC_LOCK_HELD))
		up_read(&c->gc_lock);

	return ret;
}

int bch_disk_reservation_get(struct cache_set *c,
			     struct disk_reservation *res,
			     unsigned sectors, int flags)
{
	res->sectors = 0;
	res->gen = c->capacity_gen;
	res->nr_replicas = (flags & BCH_DISK_RESERVATION_METADATA)
		? c->opts.metadata_replicas
		: c->opts.data_replicas;

	return bch_disk_reservation_add(c, res, sectors, flags);
}
