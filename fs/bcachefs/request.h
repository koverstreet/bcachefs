#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

#include "stats.h"

struct cache_set;
struct cached_dev;
struct bcache_device;
struct kmem_cache;

unsigned bch_get_congested(struct cache_set *);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

extern struct kmem_cache *bch_search_cache;

#endif /* _BCACHE_REQUEST_H_ */
