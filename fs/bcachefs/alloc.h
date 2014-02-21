#ifndef _BCACHE_ALLOC_H
#define _BCACHE_ALLOC_H

#include "bcache.h"

struct bkey;
struct bucket;
struct cache;
struct cache_set;

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree (last_gc).
 */

static inline u8 bucket_gc_gen(struct bucket *b)
{
	return b->gen - b->last_gc;
}

#define BUCKET_GC_GEN_MAX	96U

static inline void wake_up_allocators(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	for_each_cache(ca, c, i)
		wake_up_process(ca->alloc_thread);
}

static inline size_t buckets_available(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	size_t ret = 0;

	for_each_cache(ca, c, i)
		ret += ca->buckets_free;

	return ret;
}

static inline size_t buckets_free_cache(struct cache *ca, unsigned reserve)
{
	return ca->buckets_free +
		fifo_used(&ca->free[reserve]) +
		fifo_used(&ca->free_inc);
}

void bch_rescale_priorities(struct cache_set *, int);

bool bch_can_invalidate_bucket(struct cache *, struct bucket *);
void __bch_invalidate_one_bucket(struct cache *, struct bucket *);

void __bch_bucket_free(struct cache *, struct bucket *);
void bch_bucket_free(struct cache_set *, struct bkey *);

long bch_bucket_alloc(struct cache *, unsigned, bool);
int bch_bucket_alloc_set(struct cache_set *, unsigned, struct bkey *,
			 int, unsigned, bool);

void bch_open_bucket_put(struct cache_set *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors(struct cache_set *, struct bkey *,
				      unsigned, unsigned, bool,
				      unsigned long *);
struct open_bucket *bch_gc_alloc_sectors(struct cache_set *, struct bkey *,
					 unsigned long *);

void bch_mark_open_buckets(struct cache_set *);

void bch_open_buckets_init(struct cache_set *);
int bch_cache_allocator_start(struct cache *);

#endif /* _BCACHE_ALLOC_H */
