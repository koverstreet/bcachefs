/*
 * Code for manipulating bucket marks for garbage collection.
 *
 * Copyright 2014 Datera, Inc.
 */

#ifndef _BUCKETS_H
#define _BUCKETS_H

#include "buckets_types.h"
#include "super.h"

#define for_each_bucket(b, ca)						\
	for (b = (ca)->buckets + (ca)->mi.first_bucket;			\
	     b < (ca)->buckets + (ca)->mi.nbuckets; b++)

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree.
 */

static inline u8 bucket_gc_gen(struct cache *ca, struct bucket *g)
{
	unsigned long r = g - ca->buckets;
	return ca->bucket_gens[r] - ca->buckets[r].oldest_gen;
}

static inline struct cache *PTR_CACHE(const struct cache_set *c,
				      const struct bch_extent_ptr *ptr)
{
	EBUG_ON(ptr->dev > rcu_dereference(c->members)->nr_in_set);

	return rcu_dereference(c->cache[ptr->dev]);
}

static inline size_t PTR_BUCKET_NR(const struct cache *ca,
				   const struct bch_extent_ptr *ptr)
{
	return sector_to_bucket(ca, ptr->offset);
}

/*
 * Returns 0 if no pointers or device offline - only for tracepoints!
 */
static inline size_t PTR_BUCKET_NR_TRACE(const struct cache_set *c,
					 const struct bkey_i *k,
					 unsigned ptr)
{
	size_t bucket = 0;
#if 0
	if (bkey_extent_is_data(&k->k)) {
		const struct bch_extent_ptr *ptr;
		const struct cache *ca;

		rcu_read_lock();
		extent_for_each_online_device(c, bkey_i_to_s_c_extent(k), ptr, ca) {
			bucket = PTR_BUCKET_NR(ca, ptr);
			break;
		}
		rcu_read_unlock();
	}
#endif
	return bucket;
}

static inline u8 PTR_BUCKET_GEN(const struct cache *ca,
				const struct bch_extent_ptr *ptr)
{
	return ca->bucket_gens[PTR_BUCKET_NR(ca, ptr)];
}

static inline struct bucket *PTR_BUCKET(struct cache *ca,
					const struct bch_extent_ptr *ptr)
{
	return ca->buckets + PTR_BUCKET_NR(ca, ptr);
}

static inline u8 __gen_after(u8 a, u8 b)
{
	u8 r = a - b;

	return r > 128U ? 0 : r;
}

static inline u8 gen_after(u8 a, u8 b)
{
	u8 r = a - b;

	BUG_ON(r > 128U);

	return r;
}

/**
 * ptr_stale() - check if a pointer points into a bucket that has been
 * invalidated.
 *
 * Warning: PTR_CACHE(c, k, ptr) must equal ca.
 */
static inline u8 ptr_stale(const struct cache *ca,
			   const struct bch_extent_ptr *ptr)
{
	return gen_after(PTR_BUCKET_GEN(ca, ptr), ptr->gen);
}

/* bucket heaps */

static inline bool bucket_min_cmp(struct bucket_heap_entry l,
				  struct bucket_heap_entry r)
{
	return l.val < r.val;
}

static inline bool bucket_max_cmp(struct bucket_heap_entry l,
				  struct bucket_heap_entry r)
{
	return l.val > r.val;
}

static inline void bucket_heap_push(struct cache *ca, struct bucket *g,
				    unsigned long val)
{
	struct bucket_heap_entry new = { g, val };

	if (!heap_full(&ca->heap))
		heap_add(&ca->heap, new, bucket_min_cmp);
	else if (bucket_min_cmp(new, heap_peek(&ca->heap))) {
		ca->heap.data[0] = new;
		heap_sift(&ca->heap, 0, bucket_min_cmp);
	}
}

/* bucket gc marks */

/* The dirty and cached sector counts saturate. If this occurs,
 * reference counting alone will not free the bucket, and a btree
 * GC must be performed. */
#define GC_MAX_SECTORS_USED ((1U << 15) - 1)

static inline bool bucket_unused(struct bucket *g)
{
	return !g->mark.counter;
}

static inline unsigned bucket_sectors_used(struct bucket *g)
{
	return g->mark.dirty_sectors + g->mark.cached_sectors;
}

/* Per device stats: */

struct bucket_stats_cache __bch_bucket_stats_read_cache(struct cache *);
struct bucket_stats_cache bch_bucket_stats_read_cache(struct cache *);

static inline u64 __buckets_available_cache(struct cache *ca,
					    struct bucket_stats_cache stats)
{
	return max_t(s64, 0,
		     ca->mi.nbuckets - ca->mi.first_bucket -
		     stats.buckets_dirty -
		     stats.buckets_alloc -
		     stats.buckets_meta);
}

/*
 * Number of reclaimable buckets - only for use by the allocator thread:
 */
static inline u64 buckets_available_cache(struct cache *ca)
{
	return __buckets_available_cache(ca, bch_bucket_stats_read_cache(ca));
}

static inline u64 __buckets_free_cache(struct cache *ca,
				       struct bucket_stats_cache stats)
{
	return __buckets_available_cache(ca, stats) +
		fifo_used(&ca->free[RESERVE_NONE]) +
		fifo_used(&ca->free_inc);
}

static inline u64 buckets_free_cache(struct cache *ca)
{
	return __buckets_free_cache(ca, bch_bucket_stats_read_cache(ca));
}

/* Cache set stats: */

struct bucket_stats_cache_set __bch_bucket_stats_read_cache_set(struct cache_set *);
struct bucket_stats_cache_set bch_bucket_stats_read_cache_set(struct cache_set *);
void bch_cache_set_stats_apply(struct cache_set *,
			       struct bucket_stats_cache_set *,
			       struct disk_reservation *,
			       struct gc_pos);

static inline u64 __cache_set_sectors_used(struct cache_set *c)
{
	struct bucket_stats_cache_set stats = __bch_bucket_stats_read_cache_set(c);
	u64 reserved = stats.persistent_reserved +
		stats.online_reserved;

	return stats.s[S_COMPRESSED][S_META] +
		stats.s[S_COMPRESSED][S_DIRTY] +
		reserved +
		(reserved >> 7);
}

static inline u64 cache_set_sectors_used(struct cache_set *c)
{
	return min(c->capacity, __cache_set_sectors_used(c));
}

/* XXX: kill? */
static inline u64 sectors_available(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	u64 ret = 0;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		ret += buckets_available_cache(ca) << ca->bucket_bits;
	rcu_read_unlock();

	return ret;
}

static inline bool is_available_bucket(struct bucket_mark mark)
{
	return (!mark.owned_by_allocator &&
		!mark.is_metadata &&
		!mark.dirty_sectors);
}

void bch_mark_free_bucket(struct cache *, struct bucket *);
void bch_mark_alloc_bucket(struct cache *, struct bucket *);
void bch_mark_metadata_bucket(struct cache *, struct bucket *, bool);
void bch_unmark_open_bucket(struct cache *, struct bucket *);

void __bch_gc_mark_key(struct cache_set *, struct bkey_s_c, int, bool,
		       struct bucket_stats_cache_set *);
void bch_gc_mark_key(struct cache_set *, struct bkey_s_c, int, bool);
void bch_mark_key(struct cache_set *, struct bkey_s_c, int, bool,
		  struct gc_pos, struct bucket_stats_cache_set *);

void bch_recalc_sectors_available(struct cache_set *);

void bch_disk_reservation_put(struct cache_set *,
			      struct disk_reservation *);

#define BCH_DISK_RESERVATION_NOFAIL		(1 << 0)
#define BCH_DISK_RESERVATION_METADATA		(1 << 1)
#define BCH_DISK_RESERVATION_GC_LOCK_HELD	(1 << 2)
#define BCH_DISK_RESERVATION_BTREE_LOCKS_HELD	(1 << 3)

int bch_disk_reservation_add(struct cache_set *,
			     struct disk_reservation *,
			     unsigned, int);
int bch_disk_reservation_get(struct cache_set *,
			     struct disk_reservation *,
			     unsigned, int);

#endif /* _BUCKETS_H */
