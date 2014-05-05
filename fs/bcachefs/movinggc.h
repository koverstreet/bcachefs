#ifndef _BCACHE_MOVINGGC_H
#define _BCACHE_MOVINGGC_H

void bch_moving_init_cache(struct cache *);
int bch_moving_gc_thread_start(struct cache *ca);

#endif
