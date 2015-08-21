#ifndef _BCACHE_ALLOC_H
#define _BCACHE_ALLOC_H

#include "alloc_types.h"

struct bkey;
struct bucket;
struct cache;
struct cache_set;
struct cache_group;

void bch_cache_group_remove_cache(struct cache_group *, struct cache *);
void bch_cache_group_add_cache(struct cache_group *, struct cache *);

int bch_prio_read(struct cache *);

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

void __bch_bucket_free(struct cache *, struct bucket *);
void bch_bucket_free(struct cache_set *, struct bkey *);

int bch_bucket_alloc_set(struct cache_set *, enum alloc_reserve, struct bkey *,
			 int, struct cache_group *, struct closure *);

void bch_open_bucket_put(struct cache_set *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors(struct cache_set *, struct write_point *,
				      struct bkey *, struct closure *, bool);

static inline void bch_wake_allocator(struct cache *ca)
{
	struct task_struct *p;

	rcu_read_lock();
	if ((p = ACCESS_ONCE(ca->alloc_thread)))
		wake_up_process(p);
	rcu_read_unlock();

	closure_wake_up(&ca->set->buckets_available_wait);
}

void bch_open_buckets_init(struct cache_set *);
const char *bch_cache_allocator_start(struct cache *);

void bch_stop_new_data_writes(struct cache *);
void bch_await_scheduled_data_writes(struct cache *);

#endif /* _BCACHE_ALLOC_H */
