#ifndef _BCACHE_SUPER_H
#define _BCACHE_SUPER_H

#include "extents.h"

#include "bcachefs_ioctl.h"

static inline size_t sector_to_bucket(const struct bch_dev *ca, sector_t s)
{
	return s >> ca->bucket_bits;
}

static inline sector_t bucket_to_sector(const struct bch_dev *ca, size_t b)
{
	return ((sector_t) b) << ca->bucket_bits;
}

static inline sector_t bucket_remainder(const struct bch_dev *ca, sector_t s)
{
	return s & (ca->mi.bucket_size - 1);
}

static inline struct bch_dev *bch_next_cache_rcu(struct bch_fs *c,
					       unsigned *iter)
{
	struct bch_dev *ret = NULL;

	while (*iter < c->sb.nr_devices &&
	       !(ret = rcu_dereference(c->devs[*iter])))
		(*iter)++;

	return ret;
}

#define for_each_member_device_rcu(ca, c, iter)				\
	for ((iter) = 0; ((ca) = bch_next_cache_rcu((c), &(iter))); (iter)++)

static inline struct bch_dev *bch_get_next_cache(struct bch_fs *c,
					       unsigned *iter)
{
	struct bch_dev *ret;

	rcu_read_lock();
	if ((ret = bch_next_cache_rcu(c, iter)))
		percpu_ref_get(&ret->ref);
	rcu_read_unlock();

	return ret;
}

/*
 * If you break early, you must drop your ref on the current device
 */
#define for_each_member_device(ca, c, iter)					\
	for ((iter) = 0;						\
	     (ca = bch_get_next_cache(c, &(iter)));			\
	     percpu_ref_put(&ca->ref), (iter)++)

void bch_dev_release(struct kobject *);

bool bch_dev_state_allowed(struct bch_fs *, struct bch_dev *,
			   enum bch_member_state, int);
int __bch_dev_set_state(struct bch_fs *, struct bch_dev *,
			enum bch_member_state, int);
int bch_dev_set_state(struct bch_fs *, struct bch_dev *,
		      enum bch_member_state, int);

int bch_dev_fail(struct bch_dev *, int);
int bch_dev_remove(struct bch_fs *, struct bch_dev *, int);
int bch_dev_add(struct bch_fs *, const char *);

void bch_fs_detach(struct bch_fs *);

bool bch_fs_emergency_read_only(struct bch_fs *);
void bch_fs_read_only(struct bch_fs *);
const char *bch_fs_read_write(struct bch_fs *);

void bch_fs_release(struct kobject *);
void bch_fs_stop_async(struct bch_fs *);
void bch_fs_stop(struct bch_fs *);

const char *bch_fs_start(struct bch_fs *);
const char *bch_fs_open(char * const *, unsigned, struct bch_opts,
			struct bch_fs **);
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
