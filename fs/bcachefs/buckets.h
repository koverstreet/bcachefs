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

static inline struct bucket_stats bucket_stats_read(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket_stats ret;
	unsigned seq;

	do {
		seq = read_seqbegin(&c->gc_cur_lock);
		ret = ca->bucket_stats[c->gc_mark_valid ? 0 : 1];
	} while (read_seqretry(&c->gc_cur_lock, seq));

	return ret;
}

static inline bool bucket_unused(struct bucket *b)
{
	return !b->mark.counter;
}

static inline unsigned bucket_sectors_used(struct bucket *b)
{
	return b->mark.dirty_sectors + b->mark.cached_sectors;
}

static inline size_t buckets_available_cache(struct cache *ca)
{
	size_t buckets = ca->sb.nbuckets - ca->sb.first_bucket;
	struct bucket_stats stats = bucket_stats_read(ca);

	/* XXX: awkward? */
	return buckets -
		atomic_read(&stats.buckets_dirty) -
		atomic_read(&stats.buckets_alloc) -
		atomic_read(&stats.buckets_meta);
}

static inline size_t buckets_available(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	size_t ret = 0;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		ret += buckets_available_cache(ca);
	rcu_read_unlock();

	return ret;
}

static inline size_t buckets_free_cache(struct cache *ca,
					enum alloc_reserve reserve)
{
	return buckets_available_cache(ca) +
		fifo_used(&ca->free[reserve]) +
		fifo_used(&ca->free_inc);
}

void bch_mark_free_bucket(struct cache *, struct bucket *);
void bch_mark_alloc_bucket(struct cache *, struct bucket *);
void bch_mark_metadata_bucket(struct cache *, struct bucket *);
void bch_mark_data_bucket(struct cache_set *, struct cache *,
			  struct bkey *, unsigned, int,
			  bool, bool);
void bch_unmark_open_bucket(struct cache *, struct bucket *);

#endif
