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
void bch_prio_timer_start(struct cache_set *, int);

void bch_open_bucket_put(struct cache_set *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors(struct cache_set *, struct write_point *,
				      struct bkey_i *, bool, struct closure *);

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
