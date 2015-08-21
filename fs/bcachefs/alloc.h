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

static inline size_t buckets_available(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	size_t ret = 0;

	for_each_cache(ca, c, i)
		ret += ca->buckets_free;

	return ret;
}

static inline size_t buckets_free_cache(struct cache *ca,
					enum alloc_reserve reserve)
{
	return ca->buckets_free +
		fifo_used(&ca->free[reserve]) +
		fifo_used(&ca->free_inc);
}

void bch_recalc_min_prio(struct cache *, int);
void bch_increment_clock_slowpath(struct cache_set *, int);

static inline void bch_increment_clock(struct cache_set *c,
				       unsigned sectors, int rw)
{
	struct prio_clock *clock = &c->prio_clock[rw];

	/* Buffer up one megabyte worth of IO in the percpu counter */
	preempt_disable();
	if (this_cpu_add_return(*clock->rescale_percpu, sectors) < 2048) {
		preempt_enable();
		return;
	}

	sectors = this_cpu_xchg(*clock->rescale_percpu, 0);
	preempt_enable();

	/*
	 * we only increment when 0.1% of the cache_set has been read
	 * or written too, this determines if it's time
	 */
	if (atomic_long_sub_return(sectors, &clock->rescale) < 0)
		bch_increment_clock_slowpath(c, rw);
}

void bch_prio_init(struct cache_set *);

void __bch_bucket_free(struct cache *, struct bucket *);
void bch_bucket_free(struct cache_set *, struct bkey *);

int bch_bucket_wait(struct cache_set *, enum alloc_reserve,
		    struct closure *);

long bch_bucket_alloc(struct cache *, unsigned, struct closure *);
int bch_bucket_alloc_set(struct cache_set *, unsigned, struct bkey *,
			 int, unsigned, struct closure *);

void bch_open_bucket_put(struct cache_set *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors(struct cache_set *, struct bkey *,
				      unsigned, unsigned,
				      unsigned long *, struct closure *);
struct open_bucket *bch_gc_alloc_sectors(struct cache_set *, struct bkey *,
					 unsigned long *, struct closure *);

void bch_mark_open_buckets(struct cache_set *);

void bch_open_buckets_init(struct cache_set *);
int bch_cache_allocator_start(struct cache *);

#endif /* _BCACHE_ALLOC_H */
