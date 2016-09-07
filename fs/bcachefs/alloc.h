#ifndef _BCACHE_ALLOC_H
#define _BCACHE_ALLOC_H

#include "alloc_types.h"

struct bkey;
struct bucket;
struct cache;
struct cache_set;
struct cache_group;

int bch_prio_read(struct cache *);

void bch_recalc_min_prio(struct cache *, int);

void bch_open_bucket_put(struct cache_set *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors_start(struct cache_set *,
					    struct write_point *,
					    struct bkey_i_extent *,
					    unsigned, struct closure *);
void bch_alloc_sectors_done(struct cache_set *, struct write_point *,
			    struct bkey_i_extent *, unsigned,
			    struct open_bucket *, unsigned);

struct open_bucket *bch_alloc_sectors(struct cache_set *, struct write_point *,
				      struct bkey_i_extent *, unsigned,
				      struct closure *);

static inline void bch_wake_allocator(struct cache *ca)
{
	struct task_struct *p;

	rcu_read_lock();
	if ((p = ACCESS_ONCE(ca->alloc_thread)))
		wake_up_process(p);
	rcu_read_unlock();

	/*
	 * XXX: this is only needed because of ca->reserve_buckets_count, but is
	 * reserve_buckets_count needed anymore? It predates modern
	 * reservations.
	 */
	closure_wake_up(&ca->set->freelist_wait);
}

#define __open_bucket_next_online_device(_c, _ob, _ptr, _ca)            \
({									\
	(_ca) = NULL;							\
									\
	while ((_ptr) < (_ob)->ptrs + (_ob)->nr_ptrs &&			\
	       !((_ca) = PTR_CACHE(_c, _ptr)))				\
		(_ptr)++;						\
	(_ca);								\
})

#define open_bucket_for_each_online_device(_c, _ob, _ptr, _ca)		\
	for ((_ptr) = (_ob)->ptrs;					\
	     ((_ca) = __open_bucket_next_online_device(_c, _ob,	_ptr, _ca));\
	     (_ptr)++)

void bch_cache_allocator_stop(struct cache *);
int bch_cache_allocator_start(struct cache *);
const char *bch_cache_allocator_start_once(struct cache *);
void bch_open_buckets_init(struct cache_set *);

#endif /* _BCACHE_ALLOC_H */
