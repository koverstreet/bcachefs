#ifndef _BCACHE_STATS_H_
#define _BCACHE_STATS_H_

#include "stats_types.h"

struct cache_set;
struct cached_dev;
struct bcache_device;

void bch_cache_accounting_init(struct cache_accounting *, struct closure *);
int bch_cache_accounting_add_kobjs(struct cache_accounting *, struct kobject *);
void bch_cache_accounting_clear(struct cache_accounting *);
void bch_cache_accounting_destroy(struct cache_accounting *);

static inline void mark_cache_stats(struct cache_stat_collector *stats,
				    bool hit, bool bypass)
{
	atomic_inc(&stats->cache_hit_array[!bypass][!hit]);
}

static inline void bch_mark_cache_accounting(struct cache_set *c,
					     struct cached_dev *dc,
					     bool hit, bool bypass)
{
	mark_cache_stats(&dc->accounting.collector, hit, bypass);
	mark_cache_stats(&c->accounting.collector, hit, bypass);
}

static inline void bch_mark_sectors_bypassed(struct cache_set *c,
					     struct cached_dev *dc,
					     unsigned sectors)
{
	atomic_add(sectors, &dc->accounting.collector.sectors_bypassed);
	atomic_add(sectors, &c->accounting.collector.sectors_bypassed);
}

static inline void bch_mark_gc_write(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.gc_write_sectors);
}

static inline void bch_mark_foreground_write(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.foreground_write_sectors);
}

static inline void bch_mark_discard(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.discard_sectors);
}

#endif /* _BCACHE_STATS_H_ */
