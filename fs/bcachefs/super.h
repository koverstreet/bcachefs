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

static inline bool bch_dev_may_remove(struct cache *ca)
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

void bch_dev_release(struct kobject *);

bool bch_dev_read_only(struct cache *);
const char *bch_dev_read_write(struct cache *);
bool bch_dev_remove(struct cache *, bool force);
int bch_dev_add(struct cache_set *, const char *);

void bch_fs_detach(struct cache_set *);

bool bch_fs_read_only(struct cache_set *);
bool bch_fs_emergency_read_only(struct cache_set *);
void bch_fs_read_only_sync(struct cache_set *);
const char *bch_fs_read_write(struct cache_set *);

void bch_fs_release(struct kobject *);
void bch_fs_stop(struct cache_set *);
void bch_fs_stop_sync(struct cache_set *);

const char *bch_fs_start(struct cache_set *);
const char *bch_fs_open(char * const *, unsigned, struct bch_opts,
			struct cache_set **);
const char *bch_fs_open_incremental(const char *path);

extern struct mutex bch_register_lock;
extern struct list_head bch_fs_list;
extern struct workqueue_struct *bcache_io_wq;
extern struct crypto_shash *bch_sha256;

extern struct kobj_type bch_fs_ktype;
extern struct kobj_type bch_fs_internal_ktype;
extern struct kobj_type bch_fs_time_stats_ktype;
extern struct kobj_type bch_fs_opts_dir_ktype;
extern struct kobj_type bch_dev_ktype;

#endif /* _BCACHE_SUPER_H */
