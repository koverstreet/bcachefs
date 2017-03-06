#ifndef _BCACHE_TIER_H
#define _BCACHE_TIER_H

void bch_tiering_stop(struct cache_set *);
int bch_tiering_start(struct cache_set *);
void bch_fs_tiering_init(struct cache_set *);

#endif
