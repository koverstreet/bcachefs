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

#include "bcachefs.h"
#include "alloc.h"
#include "btree_gc.h"
#include "buckets.h"
#include "error.h"

#include <linux/preempt.h>
#include <trace/events/bcachefs.h>

#ifdef DEBUG_BUCKETS

#define lg_local_lock	lg_global_lock
#define lg_local_unlock	lg_global_unlock

static void bch2_fs_stats_verify(struct bch_fs *c)
{
	struct bch_fs_usage stats =
		__bch2_fs_usage_read(c);
	unsigned i;

	for (i = 0; i < BCH_REPLICAS_MAX; i++) {
		if ((s64) stats.s[i].data[S_META] < 0)
			panic("replicas %u meta underflow: %lli\n",
			      i + 1, stats.s[i].data[S_META]);

		if ((s64) stats.s[i].data[S_DIRTY] < 0)
			panic("replicas %u dirty underflow: %lli\n",
			      i + 1, stats.s[i].data[S_DIRTY]);

		if ((s64) stats.s[i].persistent_reserved < 0)
			panic("replicas %u reserved underflow: %lli\n",
			      i + 1, stats.s[i].persistent_reserved);
	}

	if ((s64) stats.online_reserved < 0)
		panic("sectors_online_reserved underflow: %lli\n",
		      stats.online_reserved);
}

static void bch2_disk_reservations_verify(struct bch_fs *c, int flags)
{
	if (!(flags & BCH_DISK_RESERVATION_NOFAIL)) {
		u64 used = __bch2_fs_sectors_used(c);
		u64 cached = 0;
		u64 avail = atomic64_read(&c->sectors_available);
		int cpu;

		for_each_possible_cpu(cpu)
			cached += per_cpu_ptr(c->usage_percpu, cpu)->available_cache;

		if (used + avail + cached > c->capacity)
			panic("used %llu avail %llu cached %llu capacity %llu\n",
			      used, avail, cached, c->capacity);
	}
}

#else

static void bch2_fs_stats_verify(struct bch_fs *c) {}
static void bch2_disk_reservations_verify(struct bch_fs *c, int flags) {}

#endif

/*
 * Clear journal_seq_valid for buckets for which it's not needed, to prevent
 * wraparound:
 */
void bch2_bucket_seq_cleanup(struct bch_fs *c)
{
	u16 last_seq_ondisk = c->journal.last_seq_ondisk;
	struct bch_dev *ca;
	struct bucket *g;
	struct bucket_mark m;
	unsigned i;

	for_each_member_device(ca, c, i)
		for_each_bucket(g, ca) {
			bucket_cmpxchg(g, m, ({
				if (!m.journal_seq_valid ||
				    bucket_needs_journal_commit(m, last_seq_ondisk))
					break;

				m.journal_seq_valid = 0;
			}));
		}
}

#define bch2_usage_add(_acc, _stats)					\
do {									\
	typeof(_acc) _a = (_acc), _s = (_stats);			\
	unsigned i;							\
									\
	for (i = 0; i < sizeof(*_a) / sizeof(u64); i++)			\
		((u64 *) (_a))[i] += ((u64 *) (_s))[i];			\
} while (0)

#define bch2_usage_read_raw(_stats)					\
({									\
	typeof(*this_cpu_ptr(_stats)) _acc = { 0 };			\
	int cpu;							\
									\
	for_each_possible_cpu(cpu)					\
		bch2_usage_add(&_acc, per_cpu_ptr((_stats), cpu));	\
									\
	_acc;								\
})

#define bch2_usage_read_cached(_c, _cached, _uncached)			\
({									\
	typeof(_cached) _ret;						\
	unsigned _seq;							\
									\
	do {								\
		_seq = read_seqcount_begin(&(_c)->gc_pos_lock);		\
		_ret = (_c)->gc_pos.phase == GC_PHASE_DONE		\
			? bch2_usage_read_raw(_uncached)			\
			: (_cached);					\
	} while (read_seqcount_retry(&(_c)->gc_pos_lock, _seq));	\
									\
	_ret;								\
})

struct bch_dev_usage __bch2_dev_usage_read(struct bch_dev *ca)
{
	return bch2_usage_read_raw(ca->usage_percpu);
}

struct bch_dev_usage bch2_dev_usage_read(struct bch_dev *ca)
{
	return bch2_usage_read_cached(ca->fs,
				ca->usage_cached,
				ca->usage_percpu);
}

struct bch_fs_usage
__bch2_fs_usage_read(struct bch_fs *c)
{
	return bch2_usage_read_raw(c->usage_percpu);
}

struct bch_fs_usage
bch2_fs_usage_read(struct bch_fs *c)
{
	return bch2_usage_read_cached(c,
				     c->usage_cached,
				     c->usage_percpu);
}

static inline int is_meta_bucket(struct bucket_mark m)
{
	return m.data_type != BUCKET_DATA;
}

static inline int is_dirty_bucket(struct bucket_mark m)
{
	return m.data_type == BUCKET_DATA && !!m.dirty_sectors;
}

static inline int is_cached_bucket(struct bucket_mark m)
{
	return m.data_type == BUCKET_DATA &&
		!m.dirty_sectors && !!m.cached_sectors;
}

static inline enum s_alloc bucket_type(struct bucket_mark m)
{
	return is_meta_bucket(m) ? S_META : S_DIRTY;
}

static bool bucket_became_unavailable(struct bch_fs *c,
				      struct bucket_mark old,
				      struct bucket_mark new)
{
	return is_available_bucket(old) &&
	       !is_available_bucket(new) &&
	       c && c->gc_pos.phase == GC_PHASE_DONE;
}

void bch2_fs_usage_apply(struct bch_fs *c,
			struct bch_fs_usage *stats,
			struct disk_reservation *disk_res,
			struct gc_pos gc_pos)
{
	struct fs_usage_sum sum = __fs_usage_sum(*stats);
	s64 added = sum.data + sum.reserved;

	/*
	 * Not allowed to reduce sectors_available except by getting a
	 * reservation:
	 */
	BUG_ON(added > (s64) (disk_res ? disk_res->sectors : 0));

	if (added > 0) {
		disk_res->sectors	-= added;
		stats->online_reserved	-= added;
	}

	lg_local_lock(&c->usage_lock);
	/* online_reserved not subject to gc: */
	this_cpu_ptr(c->usage_percpu)->online_reserved +=
		stats->online_reserved;
	stats->online_reserved = 0;

	if (!gc_will_visit(c, gc_pos))
		bch2_usage_add(this_cpu_ptr(c->usage_percpu), stats);

	bch2_fs_stats_verify(c);
	lg_local_unlock(&c->usage_lock);

	memset(stats, 0, sizeof(*stats));
}

static void bch2_dev_usage_update(struct bch_dev *ca,
				  struct bucket_mark old, struct bucket_mark new)
{
	struct bch_fs *c = ca->fs;
	struct bch_dev_usage *dev_usage;

	bch2_fs_inconsistent_on(old.data_type && new.data_type &&
			old.data_type != new.data_type, c,
			"different types of metadata in same bucket: %u, %u",
			old.data_type, new.data_type);

	preempt_disable();
	dev_usage = this_cpu_ptr(ca->usage_percpu);

	dev_usage->sectors_cached +=
		(int) new.cached_sectors - (int) old.cached_sectors;

	dev_usage->sectors[bucket_type(old)] -= old.dirty_sectors;
	dev_usage->sectors[bucket_type(new)] += new.dirty_sectors;

	dev_usage->buckets_alloc +=
		(int) new.owned_by_allocator - (int) old.owned_by_allocator;

	dev_usage->buckets[S_META] += is_meta_bucket(new) - is_meta_bucket(old);
	dev_usage->buckets[S_DIRTY] += is_dirty_bucket(new) - is_dirty_bucket(old);
	dev_usage->buckets_cached += is_cached_bucket(new) - is_cached_bucket(old);
	preempt_enable();

	if (!is_available_bucket(old) && is_available_bucket(new))
		bch2_wake_allocator(ca);
}

#define bucket_data_cmpxchg(ca, g, new, expr)			\
({								\
	struct bucket_mark _old = bucket_cmpxchg(g, new, expr);	\
								\
	bch2_dev_usage_update(ca, _old, new);			\
	_old;							\
})

bool bch2_invalidate_bucket(struct bch_dev *ca, struct bucket *g,
			    struct bucket_mark *old)
{
	struct bucket_mark new;

	*old = bucket_data_cmpxchg(ca, g, new, ({
		if (!is_available_bucket(new))
			return false;

		new.owned_by_allocator	= 1;
		new.touched_this_mount	= 1;
		new.data_type		= 0;
		new.cached_sectors	= 0;
		new.dirty_sectors	= 0;
		new.gen++;
	}));

	if (!old->owned_by_allocator && old->cached_sectors)
		trace_invalidate(ca, bucket_to_sector(ca, g - ca->buckets),
				 old->cached_sectors);
	return true;
}

bool bch2_mark_alloc_bucket_startup(struct bch_dev *ca, struct bucket *g)
{
	struct bucket_mark new, old;

	old = bucket_data_cmpxchg(ca, g, new, ({
		if (new.touched_this_mount ||
		    !is_available_bucket(new))
			return false;

		new.owned_by_allocator	= 1;
		new.touched_this_mount	= 1;
	}));

	return true;
}

void bch2_mark_free_bucket(struct bch_dev *ca, struct bucket *g)
{
	struct bucket_mark old, new;

	old = bucket_data_cmpxchg(ca, g, new, ({
		new.touched_this_mount	= 1;
		new.owned_by_allocator	= 0;
		new.data_type		= 0;
		new.cached_sectors	= 0;
		new.dirty_sectors	= 0;
	}));

	BUG_ON(bucket_became_unavailable(ca->fs, old, new));
}

void bch2_mark_alloc_bucket(struct bch_dev *ca, struct bucket *g,
			   bool owned_by_allocator)
{
	struct bucket_mark old, new;

	old = bucket_data_cmpxchg(ca, g, new, ({
		new.touched_this_mount	= 1;
		new.owned_by_allocator	= owned_by_allocator;
	}));

	BUG_ON(!owned_by_allocator && !old.owned_by_allocator &&
	       ca->fs->gc_pos.phase == GC_PHASE_DONE);
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
		trace_sectors_saturated(ca);		\
	}							\
} while (0)

void bch2_mark_metadata_bucket(struct bch_dev *ca, struct bucket *g,
			       enum bucket_data_type type,
			       bool may_make_unavailable)
{
	struct bucket_mark old, new;

	BUG_ON(!type);

	old = bucket_data_cmpxchg(ca, g, new, ({
		saturated_add(ca, new.dirty_sectors, ca->mi.bucket_size,
			      GC_MAX_SECTORS_USED);
		new.data_type		= type;
		new.touched_this_mount	= 1;
	}));

	if (old.data_type != type &&
	    (old.data_type ||
	     old.cached_sectors ||
	     old.dirty_sectors))
		bch_err(ca->fs, "bucket %zu has multiple types of data (%u, %u)",
			g - ca->buckets, old.data_type, new.data_type);

	BUG_ON(!may_make_unavailable &&
	       bucket_became_unavailable(ca->fs, old, new));
}

/* Reverting this until the copygc + compression issue is fixed: */

static int __disk_sectors(struct bch_extent_crc_unpacked crc, unsigned sectors)
{
	if (!sectors)
		return 0;

	return max(1U, DIV_ROUND_UP(sectors * crc.compressed_size,
				    crc.uncompressed_size));
}

/*
 * Checking against gc's position has to be done here, inside the cmpxchg()
 * loop, to avoid racing with the start of gc clearing all the marks - GC does
 * that with the gc pos seqlock held.
 */
static void bch2_mark_pointer(struct bch_fs *c,
			     struct bkey_s_c_extent e,
			     const struct bch_extent_ptr *ptr,
			     struct bch_extent_crc_unpacked crc,
			     s64 sectors, enum s_alloc type,
			     struct bch_fs_usage *stats,
			     u64 journal_seq, unsigned flags)
{
	struct bucket_mark old, new;
	unsigned saturated;
	struct bch_dev *ca = c->devs[ptr->dev];
	struct bucket *g = ca->buckets + PTR_BUCKET_NR(ca, ptr);
	unsigned data_type = type == S_META
		? BUCKET_BTREE : BUCKET_DATA;
	u64 v;

	if (crc.compression_type) {
		unsigned old_sectors, new_sectors;

		if (sectors > 0) {
			old_sectors = 0;
			new_sectors = sectors;
		} else {
			old_sectors = e.k->size;
			new_sectors = e.k->size + sectors;
		}

		sectors = -__disk_sectors(crc, old_sectors)
			  +__disk_sectors(crc, new_sectors);
	}

	if (flags & BCH_BUCKET_MARK_GC_WILL_VISIT) {
		if (journal_seq)
			bucket_cmpxchg(g, new, ({
				new.touched_this_mount	= 1;
				new.journal_seq_valid	= 1;
				new.journal_seq		= journal_seq;
			}));

		return;
	}

	v = READ_ONCE(g->_mark.counter);
	do {
		new.counter = old.counter = v;
		saturated = 0;

		/*
		 * Check this after reading bucket mark to guard against
		 * the allocator invalidating a bucket after we've already
		 * checked the gen
		 */
		if (gen_after(new.gen, ptr->gen)) {
			BUG_ON(!test_bit(BCH_FS_ALLOC_READ_DONE, &c->flags));
			EBUG_ON(!ptr->cached &&
				test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags));
			return;
		}

		if (!ptr->cached &&
		    new.dirty_sectors == GC_MAX_SECTORS_USED &&
		    sectors < 0)
			saturated = -sectors;

		if (ptr->cached)
			saturated_add(ca, new.cached_sectors, sectors,
				      GC_MAX_SECTORS_USED);
		else
			saturated_add(ca, new.dirty_sectors, sectors,
				      GC_MAX_SECTORS_USED);

		if (!new.dirty_sectors &&
		    !new.cached_sectors) {
			new.data_type	= 0;

			if (journal_seq) {
				new.journal_seq_valid = 1;
				new.journal_seq = journal_seq;
			}
		} else {
			new.data_type = data_type;
		}

		new.touched_this_mount	= 1;

		if (flags & BCH_BUCKET_MARK_NOATOMIC) {
			g->_mark = new;
			break;
		}
	} while ((v = cmpxchg(&g->_mark.counter,
			      old.counter,
			      new.counter)) != old.counter);

	bch2_dev_usage_update(ca, old, new);

	if (old.data_type != data_type &&
	    (old.data_type ||
	     old.cached_sectors ||
	     old.dirty_sectors))
		bch_err(c, "bucket %zu has multiple types of data (%u, %u)",
			g - ca->buckets, old.data_type, new.data_type);

	BUG_ON(!(flags & BCH_BUCKET_MARK_MAY_MAKE_UNAVAILABLE) &&
	       bucket_became_unavailable(c, old, new));

	if (saturated &&
	    atomic_long_add_return(saturated,
				   &ca->saturated_count) >=
	    bucket_to_sector(ca, ca->free_inc.size)) {
		if (c->gc_thread) {
			trace_gc_sectors_saturated(c);
			wake_up_process(c->gc_thread);
		}
	}
}

static void bch2_mark_extent(struct bch_fs *c, struct bkey_s_c_extent e,
			    s64 sectors, bool metadata,
			    struct bch_fs_usage *stats,
			    u64 journal_seq, unsigned flags)
{
	const struct bch_extent_ptr *ptr;
	struct bch_extent_crc_unpacked crc;
	enum s_alloc type = metadata ? S_META : S_DIRTY;
	unsigned replicas = 0;

	BUG_ON(metadata && bkey_extent_is_cached(e.k));
	BUG_ON(!sectors);

	extent_for_each_ptr_crc(e, ptr, crc) {
		bch2_mark_pointer(c, e, ptr, crc, sectors, type,
				  stats, journal_seq, flags);
		replicas += !ptr->cached;
	}

	BUG_ON(replicas >= BCH_REPLICAS_MAX);

	if (replicas)
		stats->s[replicas - 1].data[type] += sectors;
}

void __bch2_mark_key(struct bch_fs *c, struct bkey_s_c k,
		     s64 sectors, bool metadata,
		     struct bch_fs_usage *stats,
		     u64 journal_seq, unsigned flags)
{
	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		bch2_mark_extent(c, bkey_s_c_to_extent(k), sectors, metadata,
				stats, journal_seq, flags);
		break;
	case BCH_RESERVATION: {
		struct bkey_s_c_reservation r = bkey_s_c_to_reservation(k);

		if (r.v->nr_replicas)
			stats->s[r.v->nr_replicas - 1].persistent_reserved += sectors;
		break;
	}
	}
}

void bch2_gc_mark_key(struct bch_fs *c, struct bkey_s_c k,
		     s64 sectors, bool metadata, unsigned flags)
{
	struct bch_fs_usage stats = { 0 };

	__bch2_mark_key(c, k, sectors, metadata, &stats, 0,
			flags|BCH_BUCKET_MARK_MAY_MAKE_UNAVAILABLE);

	preempt_disable();
	bch2_usage_add(this_cpu_ptr(c->usage_percpu), &stats);
	preempt_enable();
}

void bch2_mark_key(struct bch_fs *c, struct bkey_s_c k,
		  s64 sectors, bool metadata, struct gc_pos gc_pos,
		  struct bch_fs_usage *stats, u64 journal_seq)
{
	unsigned flags = gc_will_visit(c, gc_pos)
		? BCH_BUCKET_MARK_GC_WILL_VISIT : 0;
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
	 *    usage_lock guards against this
	 *  - GC's position overtaking @gc_pos: we guard against this with
	 *    whatever lock protects the data structure the reference lives in
	 *    (e.g. the btree node lock, or the relevant allocator lock).
	 */
	lg_local_lock(&c->usage_lock);
	__bch2_mark_key(c, k, sectors, metadata, stats, journal_seq, flags);
	bch2_fs_stats_verify(c);
	lg_local_unlock(&c->usage_lock);
}

static u64 __recalc_sectors_available(struct bch_fs *c)
{
	u64 avail;
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu_ptr(c->usage_percpu, cpu)->available_cache = 0;

	avail = c->capacity - bch2_fs_sectors_used(c);

	avail <<= RESERVE_FACTOR;
	avail /= (1 << RESERVE_FACTOR) + 1;
	return avail;
}

/* Used by gc when it's starting: */
void bch2_recalc_sectors_available(struct bch_fs *c)
{
	lg_global_lock(&c->usage_lock);
	atomic64_set(&c->sectors_available, __recalc_sectors_available(c));
	lg_global_unlock(&c->usage_lock);
}

void __bch2_disk_reservation_put(struct bch_fs *c, struct disk_reservation *res)
{
	lg_local_lock(&c->usage_lock);
	this_cpu_sub(c->usage_percpu->online_reserved,
		     res->sectors);

	bch2_fs_stats_verify(c);
	lg_local_unlock(&c->usage_lock);

	res->sectors = 0;
}

#define SECTORS_CACHE	1024

int bch2_disk_reservation_add(struct bch_fs *c, struct disk_reservation *res,
			      unsigned sectors, int flags)
{
	struct bch_fs_usage *stats;
	u64 old, v, get;
	s64 sectors_available;
	int ret;

	sectors *= res->nr_replicas;

	lg_local_lock(&c->usage_lock);
	stats = this_cpu_ptr(c->usage_percpu);

	if (sectors <= stats->available_cache)
		goto out;

	v = atomic64_read(&c->sectors_available);
	do {
		old = v;
		get = min((u64) sectors + SECTORS_CACHE, old);

		if (get < sectors) {
			lg_local_unlock(&c->usage_lock);
			goto recalculate;
		}
	} while ((v = atomic64_cmpxchg(&c->sectors_available,
				       old, old - get)) != old);

	stats->available_cache	+= get;

out:
	stats->available_cache	-= sectors;
	stats->online_reserved	+= sectors;
	res->sectors		+= sectors;

	bch2_disk_reservations_verify(c, flags);
	bch2_fs_stats_verify(c);
	lg_local_unlock(&c->usage_lock);
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
	lg_global_lock(&c->usage_lock);

	sectors_available = __recalc_sectors_available(c);

	if (sectors <= sectors_available ||
	    (flags & BCH_DISK_RESERVATION_NOFAIL)) {
		atomic64_set(&c->sectors_available,
			     max_t(s64, 0, sectors_available - sectors));
		stats->online_reserved	+= sectors;
		res->sectors		+= sectors;
		ret = 0;

		bch2_disk_reservations_verify(c, flags);
	} else {
		atomic64_set(&c->sectors_available, sectors_available);
		ret = -ENOSPC;
	}

	bch2_fs_stats_verify(c);
	lg_global_unlock(&c->usage_lock);
	if (!(flags & BCH_DISK_RESERVATION_GC_LOCK_HELD))
		up_read(&c->gc_lock);

	return ret;
}

int bch2_disk_reservation_get(struct bch_fs *c,
			     struct disk_reservation *res,
			     unsigned sectors, int flags)
{
	res->sectors = 0;
	res->gen = c->capacity_gen;
	res->nr_replicas = (flags & BCH_DISK_RESERVATION_METADATA)
		? c->opts.metadata_replicas
		: c->opts.data_replicas;

	return bch2_disk_reservation_add(c, res, sectors, flags);
}
