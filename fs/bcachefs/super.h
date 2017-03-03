#ifndef _BCACHE_SUPER_H
#define _BCACHE_SUPER_H

#include "extents.h"

static inline size_t sector_to_bucket(const struct cache *ca, sector_t s)
{
	return s >> ca->bucket_bits;
}

static inline sector_t bucket_to_sector(const struct cache *ca, size_t b)
{
	return ((sector_t) b) << ca->bucket_bits;
}

static inline sector_t bucket_remainder(const struct cache *ca, sector_t s)
{
	return s & (ca->mi.bucket_size - 1);
}

static inline struct cache *bch_next_cache_rcu(struct cache_set *c,
					       unsigned *iter)
{
	struct cache *ret = NULL;

	while (*iter < c->sb.nr_devices &&
	       !(ret = rcu_dereference(c->cache[*iter])))
		(*iter)++;

	return ret;
}

#define for_each_cache_rcu(ca, c, iter)					\
	for ((iter) = 0; ((ca) = bch_next_cache_rcu((c), &(iter))); (iter)++)

static inline struct cache *bch_get_next_cache(struct cache_set *c,
					       unsigned *iter)
{
	struct cache *ret;

	rcu_read_lock();
	if ((ret = bch_next_cache_rcu(c, iter)))
		percpu_ref_get(&ret->ref);
	rcu_read_unlock();

	return ret;
}

/*
 * If you break early, you must drop your ref on the current cache
 */
#define for_each_cache(ca, c, iter)					\
	for ((iter) = 0;						\
	     (ca = bch_get_next_cache(c, &(iter)));			\
	     percpu_ref_put(&ca->ref), (iter)++)

static inline bool bch_cache_may_remove(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_group *tier = &c->cache_tiers[ca->mi.tier];

	/*
	 * Right now, we can't remove the last device from a tier,
	 * - For tier 0, because all metadata lives in tier 0 and because
	 *   there is no way to have foreground writes go directly to tier 1.
	 * - For tier 1, because the code doesn't completely support an
	 *   empty tier 1.
	 */

	/*
	 * Turning a device read-only removes it from the cache group,
	 * so there may only be one read-write device in a tier, and yet
	 * the device we are removing is in the same tier, so we have
	 * to check for identity.
	 * Removing the last RW device from a tier requires turning the
	 * whole cache set RO.
	 */

	return tier->nr_devices != 1 ||
		rcu_access_pointer(tier->d[0].dev) != ca;
}

void bch_cache_set_release(struct kobject *);
void bch_cache_release(struct kobject *);

void bch_cache_set_unregister(struct cache_set *);
void bch_cache_set_stop(struct cache_set *);

const char *bch_register_one(const char *path);
const char *bch_register_cache_set(char * const *, unsigned,
				   struct bch_opts,
				   struct cache_set **);

bool bch_cache_set_read_only(struct cache_set *);
bool bch_cache_set_emergency_read_only(struct cache_set *);
void bch_cache_set_read_only_sync(struct cache_set *);
const char *bch_cache_set_read_write(struct cache_set *);

bool bch_cache_read_only(struct cache *);
const char *bch_cache_read_write(struct cache *);
bool bch_cache_remove(struct cache *, bool force);
int bch_cache_set_add_cache(struct cache_set *, const char *);

extern struct mutex bch_register_lock;
extern struct list_head bch_cache_sets;
extern struct idr bch_cache_set_minor;
extern struct workqueue_struct *bcache_io_wq;
extern struct crypto_shash *bch_sha256;

extern struct kobj_type bch_cache_set_ktype;
extern struct kobj_type bch_cache_set_internal_ktype;
extern struct kobj_type bch_cache_set_time_stats_ktype;
extern struct kobj_type bch_cache_set_opts_dir_ktype;
extern struct kobj_type bch_cache_ktype;

#endif /* _BCACHE_SUPER_H */
