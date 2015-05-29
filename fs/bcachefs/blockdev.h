#ifndef _BCACHE_BLOCKDEV_H
#define _BCACHE_BLOCKDEV_H

#include "blockdev_types.h"
#include "btree.h"
#include "io.h"

void bch_write_bdev_super(struct cached_dev *, struct closure *);

void bch_cached_dev_release(struct kobject *);
void bch_flash_dev_release(struct kobject *);

int bch_cached_dev_attach(struct cached_dev *, struct cache_set *);
void bch_cached_dev_detach(struct cached_dev *);
void bch_cached_dev_run(struct cached_dev *);
void bcache_device_stop(struct bcache_device *);

bool bch_is_open_backing(struct block_device *);
const char *bch_register_bdev(struct bcache_superblock *);
int flash_devs_run(struct cache_set *);
int bch_flash_dev_create(struct cache_set *, u64);

void bch_blockdev_exit(void);
int bch_blockdev_init(void);

extern struct list_head uncached_devices;

static inline void cached_dev_put(struct cached_dev *dc)
{
	if (atomic_dec_and_test(&dc->count))
		schedule_work(&dc->detach);
}

static inline bool cached_dev_get(struct cached_dev *dc)
{
	if (!atomic_inc_not_zero(&dc->count))
		return false;

	/* Paired with the mb in cached_dev_attach */
	smp_mb__after_atomic();
	return true;
}

static inline u64 bcache_dev_inum(struct bcache_device *d)
{
	return d->inode.k.p.inode;
}

static inline struct bcache_device *bch_dev_find(struct cache_set *c, u64 inode)
{
	return radix_tree_lookup(&c->devices, inode);
}

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct bch_write_bio	bio;
	/* Not modified */
	struct bio		*orig_bio;
	struct bcache_device	*d;

	unsigned		inode;
	unsigned		write:1;

	/* Flags only used for reads */
	unsigned		recoverable:1;
	unsigned		read_dirty_data:1;
	unsigned		cache_miss:1;

	/*
	 * For reads:  bypass read from cache and insertion into cache
	 * For writes: discard key range from cache, sending the write to
	 *             the backing device (if there is a backing device)
	 */
	unsigned		bypass:1;

	unsigned long		start_time;

	/*
	 * Mostly only used for writes. For reads, we still make use of
	 * some trivial fields:
	 * - c
	 * - error
	 */
	struct bch_write_op	iop;
};

extern struct kmem_cache *bch_search_cache;

extern struct kobj_type bch_cached_dev_ktype;
extern struct kobj_type bch_flash_dev_ktype;

#endif /* _BCACHE_BLOCKDEV_H */
