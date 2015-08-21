/*
 * Code for manipulating bucket marks for garbage collection.
 *
 * Copyright 2014 Datera, Inc.
 */

#ifndef _BUCKETS_H
#define _BUCKETS_H

#include "bcache.h"

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

static inline size_t buckets_available_cache(struct cache *ca)
{
	struct bucket_stats stats = bucket_stats_read(ca);

	return max_t(s64, 0,
		     ca->sb.nbuckets - ca->sb.first_bucket -
		     stats.buckets_dirty -
		     stats.buckets_alloc -
		     stats.buckets_meta);
}

static inline u64 sectors_available(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	u64 ret = 0;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		ret += buckets_available_cache(ca);
	rcu_read_unlock();

	return ret << c->bucket_bits;
}

static inline size_t buckets_free_cache(struct cache *ca,
					enum alloc_reserve reserve)
{
	size_t free = buckets_available_cache(ca) +
		fifo_used(&ca->free[reserve]) +
		fifo_used(&ca->free_inc);

	if (reserve == RESERVE_NONE)
		free = max_t(ssize_t, 0, free -
			     ca->reserve_buckets_count);

	return free;
}

static inline u64 cache_sectors_used(struct cache *ca)
{
	struct bucket_stats stats = bucket_stats_read(ca);

	return (((u64) (ca->sb.first_bucket +
			stats.buckets_alloc +
			stats.buckets_meta)) << ca->set->bucket_bits) +
		stats.sectors_dirty;
}

static inline bool cache_set_can_write(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	u64 used = 0;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		used += cache_sectors_used(ca);
	rcu_read_unlock();

	return used < c->capacity;
}

static inline bool is_available_bucket(struct bucket_mark mark)
{
	return (!mark.owned_by_allocator &&
		!mark.is_metadata &&
		!mark.dirty_sectors);
}

void bch_mark_free_bucket(struct cache *, struct bucket *);
void bch_mark_alloc_bucket(struct cache *, struct bucket *);
void bch_mark_metadata_bucket(struct cache *, struct bucket *);
u8 bch_mark_data_bucket(struct cache_set *, struct cache *, struct bkey *,
			unsigned, int, bool, bool);
void bch_unmark_open_bucket(struct cache *, struct bucket *);

#endif
