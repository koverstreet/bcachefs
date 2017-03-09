#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

#include "stats.h"

struct bch_fs;
struct cached_dev;
struct bcache_device;
struct kmem_cache;

unsigned bch_get_congested(struct bch_fs *);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_blockdev_volume_request_init(struct bcache_device *d);

#endif /* _BCACHE_REQUEST_H_ */
