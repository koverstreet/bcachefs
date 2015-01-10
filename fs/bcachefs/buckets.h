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
	for (b = (ca)->buckets + (ca)->sb.first_bucket;			\
	     b < (ca)->buckets + (ca)->sb.nbuckets; b++)

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree.
 */

static inline u8 bucket_gc_gen(struct cache *ca, size_t r)
{
	return ca->bucket_gens[r] - ca->buckets[r].oldest_gen;
}

static inline struct cache *PTR_CACHE(const struct cache_set *c,
				      const struct bkey *k,
				      unsigned ptr)
{
	unsigned dev = PTR_DEV(k, ptr);

	/* The range test covers PTR_LOST_DEV and PTR_CHECK_DEV  */

	return dev < MAX_CACHES_PER_SET
		? rcu_dereference(c->cache[dev])
		: NULL;
}

static inline size_t PTR_BUCKET_NR(const struct cache *ca,
				   const struct bkey *k,
				   unsigned ptr)
{
	return sector_to_bucket(ca, PTR_OFFSET(k, ptr));
}

/*
 * Returns 0 if no pointers or device offline - only for tracepoints!
 */
static inline size_t PTR_BUCKET_NR_TRACE(const struct cache_set *c,
					 const struct bkey *k,
					 unsigned ptr)
{
	const struct cache *ca;
	size_t bucket;

	rcu_read_lock();
	bucket = (bch_extent_ptrs(k) && (ca = PTR_CACHE(c, k, ptr)))
		? PTR_BUCKET_NR(ca, k, ptr) : 0;
	rcu_read_unlock();

	return bucket;
}

static inline u8 PTR_BUCKET_GEN(const struct cache *ca,
				const struct bkey *k,
				unsigned ptr)
{
	return ca->bucket_gens[PTR_BUCKET_NR(ca, k, ptr)];
}

static inline struct bucket *PTR_BUCKET(struct cache *ca,
					const struct bkey *k,
					unsigned ptr)
{
	return ca->buckets + PTR_BUCKET_NR(ca, k, ptr);
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
			   const struct bkey *k, unsigned ptr)
{
	return gen_after(PTR_BUCKET_GEN(ca, k, ptr), PTR_GEN(k, ptr));
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

static inline void __bucket_stats_add(struct bucket_stats *acc,
				      struct bucket_stats *s)
{
	unsigned i;

	for (i = 0; i < sizeof(*s) / sizeof(u64); i++)
		((u64 *) acc)[i] += ((u64 *) s)[i];
}

static inline struct bucket_stats __bucket_stats_read(struct cache *ca)
{
	struct bucket_stats ret;
	int cpu;

	memset(&ret, 0, sizeof(ret));

	for_each_possible_cpu(cpu)
		__bucket_stats_add(&ret,
				   per_cpu_ptr(ca->bucket_stats_percpu, cpu));


	return ret;
}

static inline struct bucket_stats bucket_stats_read(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket_stats ret;
	unsigned seq;

	do {
		seq = read_seqbegin(&c->gc_cur_lock);
		ret = c->gc_cur_btree > BTREE_ID_NR
			? __bucket_stats_read(ca)
			: ca->bucket_stats_cached;
	} while (read_seqretry(&c->gc_cur_lock, seq));

	return ret;
}

static inline bool bucket_unused(struct bucket *g)
{
	return !g->mark.counter;
}

static inline unsigned bucket_sectors_used(struct bucket *g)
{
	return g->mark.dirty_sectors + g->mark.cached_sectors;
}

static inline size_t __buckets_available_cache(struct cache *ca,
					       struct bucket_stats stats)
{
	return max_t(s64, 0,
		     ca->sb.nbuckets - ca->sb.first_bucket -
		     stats.buckets_dirty -
		     stats.buckets_alloc -
		     stats.buckets_meta);
}

static inline size_t buckets_available_cache(struct cache *ca)
{
	return __buckets_available_cache(ca, bucket_stats_read(ca));
}

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

static inline size_t __buckets_free_cache(struct cache *ca,
					  struct bucket_stats stats,
					  enum alloc_reserve reserve)
{
	size_t free =  __buckets_available_cache(ca, stats) +
		fifo_used(&ca->free[reserve]) +
		fifo_used(&ca->free_inc);

	if (reserve == RESERVE_NONE)
		free = max_t(ssize_t, 0, free -
				ca->reserve_buckets_count);

	return free;
}

static inline size_t buckets_free_cache(struct cache *ca,
					enum alloc_reserve reserve)
{
	return __buckets_free_cache(ca, bucket_stats_read(ca), reserve);
}

static inline u64 cache_sectors_used(struct cache *ca)
{
	struct bucket_stats stats = bucket_stats_read(ca);

	return ((stats.buckets_alloc +
		 stats.buckets_meta) << ca->bucket_bits) +
		stats.sectors_dirty;
}

static inline bool cache_set_full(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	u64 used = 0;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		used += cache_sectors_used(ca);
	rcu_read_unlock();

	return used >= c->capacity;
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
u8 bch_mark_data_bucket(struct cache_set *, struct cache *, struct btree *,
			const struct bkey *, unsigned, int, bool);
void bch_unmark_open_bucket(struct cache *, struct bucket *);

#endif /* _BUCKETS_H */
