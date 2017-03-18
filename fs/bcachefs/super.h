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

static inline struct bch_dev *__bch_next_dev(struct bch_fs *c, unsigned *iter)
{
	struct bch_dev *ca = NULL;

	while (*iter < c->sb.nr_devices &&
	       !(ca = rcu_dereference_check(c->devs[*iter],
					    lockdep_is_held(&c->state_lock))))
		(*iter)++;

	return ca;
}

#define __for_each_member_device(ca, c, iter)				\
	for ((iter) = 0; ((ca) = __bch_next_dev((c), &(iter))); (iter)++)

#define for_each_member_device_rcu(ca, c, iter)				\
	__for_each_member_device(ca, c, iter)

static inline struct bch_dev *bch_get_next_dev(struct bch_fs *c, unsigned *iter)
{
	struct bch_dev *ca;

	rcu_read_lock();
	if ((ca = __bch_next_dev(c, iter)))
		percpu_ref_get(&ca->ref);
	rcu_read_unlock();

	return ca;
}

/*
 * If you break early, you must drop your ref on the current device
 */
#define for_each_member_device(ca, c, iter)				\
	for ((iter) = 0;						\
	     (ca = bch_get_next_dev(c, &(iter)));			\
	     percpu_ref_put(&ca->ref), (iter)++)

static inline struct bch_dev *bch_get_next_online_dev(struct bch_fs *c,
						      unsigned *iter,
						      int state_mask)
{
	struct bch_dev *ca;

	rcu_read_lock();
	while ((ca = __bch_next_dev(c, iter)) &&
	       (!((1 << ca->mi.state) & state_mask) ||
		!percpu_ref_tryget(&ca->io_ref)))
		(*iter)++;
	rcu_read_unlock();

	return ca;
}

#define __for_each_online_member(ca, c, iter, state_mask)		\
	for ((iter) = 0;						\
	     (ca = bch_get_next_online_dev(c, &(iter), state_mask));	\
	     percpu_ref_put(&ca->io_ref), (iter)++)

#define for_each_online_member(ca, c, iter)				\
	__for_each_online_member(ca, c, iter, ~0)

#define for_each_rw_member(ca, c, iter)					\
	__for_each_online_member(ca, c, iter, 1 << BCH_MEMBER_STATE_RW)

#define for_each_readable_member(ca, c, iter)				\
	__for_each_online_member(ca, c, iter,				\
		(1 << BCH_MEMBER_STATE_RW)|(1 << BCH_MEMBER_STATE_RO))

struct bch_fs *bch_bdev_to_fs(struct block_device *);
struct bch_fs *bch_uuid_to_fs(uuid_le);
int bch_congested(struct bch_fs *, int);

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
int bch_dev_online(struct bch_fs *, const char *);
int bch_dev_offline(struct bch_fs *, struct bch_dev *, int);
int bch_dev_evacuate(struct bch_fs *, struct bch_dev *);

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

extern struct workqueue_struct *bcache_io_wq;

extern struct kobj_type bch_fs_ktype;
extern struct kobj_type bch_fs_internal_ktype;
extern struct kobj_type bch_fs_time_stats_ktype;
extern struct kobj_type bch_fs_opts_dir_ktype;
extern struct kobj_type bch_dev_ktype;

#endif /* _BCACHE_SUPER_H */
