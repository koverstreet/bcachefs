/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_SUPER_H
#define _BCACHE_SUPER_H

struct cached_dev;
struct cache;
struct cache_set;

void bch_write_bdev_super(struct cached_dev *dc, struct closure *parent);
void bcache_write_super(struct cache_set *c);
int bch_uuid_write(struct cache_set *c);
int bch_prio_write(struct cache *ca, bool wait);

void bcache_device_stop(struct bcache_device *d);
int bch_cached_dev_run(struct cached_dev *dc);
void bch_cached_dev_detach(struct cached_dev *dc);
int bch_cached_dev_attach(struct cached_dev *dc, struct cache_set *c,
			  uint8_t *set_uuid);

bool bch_cached_dev_error(struct cached_dev *dc);

int bch_flash_dev_create(struct cache_set *c, uint64_t size);

void bch_cached_dev_release(struct kobject *kobj);
void bch_flash_dev_release(struct kobject *kobj);
void bch_cache_set_release(struct kobject *kobj);
void bch_cache_release(struct kobject *kobj);

void bch_cache_set_unregister(struct cache_set *c);
void bch_cache_set_stop(struct cache_set *c);

struct cache_set *bch_cache_set_alloc(struct cache_sb *sb);

#endif /* _BCACHE_SUPER_H */
