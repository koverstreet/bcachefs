#ifndef _BCACHE_TIER_H
#define _BCACHE_TIER_H

void bch_tiering_init_cache_set(struct cache_set *);
int bch_tiering_init_cache(struct cache *);
int bch_tiering_read_start(struct cache_set *);
void bch_tiering_write_destroy(struct cache *);
void bch_tiering_read_stop(struct cache_set *);

#endif
