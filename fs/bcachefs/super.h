#ifndef _BCACHE_SUPER_H
#define _BCACHE_SUPER_H

#include "extents.h"

static inline size_t sector_to_bucket(struct cache_set *c, sector_t s)
{
	return s >> c->bucket_bits;
}

static inline sector_t bucket_to_sector(struct cache_set *c, size_t b)
{
	return ((sector_t) b) << c->bucket_bits;
}

static inline sector_t bucket_remainder(struct cache_set *c, sector_t s)
{
	return s & (c->sb.bucket_size - 1);
}

static inline struct cache_member *cache_member_info(struct cache *ca)
{
	return ca->set->members + ca->sb.nr_this_dev;
}

static inline struct cache *bch_next_cache_rcu(struct cache_set *c,
					       unsigned *iter)
{
	struct cache *ret = NULL;

	while (*iter < c->sb.nr_in_set &&
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
	return KEY_INODE(&d->inode.i_inode.i_key);
}

static inline struct bcache_device *bch_dev_find(struct cache_set *c,
						 u64 inode)
{
	return radix_tree_lookup(&c->devices, inode);
}

__printf(2, 3)
bool bch_cache_set_error(struct cache_set *, const char *, ...);

u64 bch_checksum_update(unsigned, u64, const void *, size_t);
u64 bch_checksum(unsigned, const void *, size_t);

/*
 * This is used for various on disk data structures - cache_sb, prio_set, bset,
 * jset: The checksum is _always_ the first 8 bytes of these structs
 */
#define csum_set(i, type)						\
({									\
	void *start = ((void *) (i)) + sizeof(u64);			\
	void *end = bset_bkey_last(i);					\
									\
	bch_checksum(type, start, end - start);				\
})

void bch_prio_write(struct cache *);

void bch_check_mark_super_slowpath(struct cache_set *, struct bkey *, bool);

static inline bool bch_check_super_marked(struct cache_set *c,
					  struct bkey *k, bool meta)
{
	unsigned ptr;
	struct cache_member *mi;

	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++) {
		mi = c->members + PTR_DEV(k, ptr);

		if (!(meta ? CACHE_HAS_METADATA : CACHE_HAS_DATA)(mi))
			return false;
	}

	return true;
}

static inline void bch_check_mark_super(struct cache_set *c,
					struct bkey *k, bool meta)
{
	if (bch_check_super_marked(c, k, meta))
		return;

	bch_check_mark_super_slowpath(c, k, meta);
}

int bch_super_realloc(struct cache *, unsigned);
void bcache_write_super(struct cache_set *);

void bch_write_bdev_super(struct cached_dev *, struct closure *);

void bch_cached_dev_release(struct kobject *);
void bch_flash_dev_release(struct kobject *);
void bch_cache_set_release(struct kobject *);
void bch_cache_release(struct kobject *);

void bch_cache_set_unregister(struct cache_set *);
void bch_cache_set_stop(struct cache_set *);

const char *register_bcache_devices(char **, int, struct cache_set **);
const char *bch_run_cache_set(struct cache_set *);

int bch_flash_dev_create(struct cache_set *, u64);

int bch_cached_dev_attach(struct cached_dev *, struct cache_set *);
void bch_cached_dev_detach(struct cached_dev *);
void bch_cached_dev_run(struct cached_dev *);
void bcache_device_stop(struct bcache_device *);

void bch_cache_read_only(struct cache *);
const char *bch_cache_read_write(struct cache *);
void bch_cache_remove(struct cache *);
int bch_cache_add(struct cache_set *, const char *);

extern struct mutex bch_register_lock;
extern struct list_head bch_cache_sets;
extern struct idr bch_cache_set_minor;

extern struct kobj_type bch_cached_dev_ktype;
extern struct kobj_type bch_flash_dev_ktype;
extern struct kobj_type bch_cache_set_ktype;
extern struct kobj_type bch_cache_set_internal_ktype;
extern struct kobj_type bch_cache_ktype;

#endif /* _BCACHE_SUPER_H */
