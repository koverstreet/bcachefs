#ifndef _BCACHE_SUPER_H
#define _BCACHE_SUPER_H

#include "extents.h"

#include "bcachefs_ioctl.h"

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

void bch_dev_release(struct kobject *);

bool bch_dev_state_allowed(struct cache_set *, struct cache *,
			   enum bch_member_state, int);
int __bch_dev_set_state(struct cache_set *, struct cache *,
			enum bch_member_state, int);
int bch_dev_set_state(struct cache_set *, struct cache *,
		      enum bch_member_state, int);

int bch_dev_fail(struct cache *, int);
int bch_dev_remove(struct cache_set *, struct cache *, int);
int bch_dev_add(struct cache_set *, const char *);

void bch_fs_detach(struct cache_set *);

bool bch_fs_emergency_read_only(struct cache_set *);
void bch_fs_read_only(struct cache_set *);
const char *bch_fs_read_write(struct cache_set *);

void bch_fs_release(struct kobject *);
void bch_fs_stop_async(struct cache_set *);
void bch_fs_stop(struct cache_set *);

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
