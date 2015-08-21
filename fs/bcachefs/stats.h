#ifndef _BCACHE_STATS_H_
#define _BCACHE_STATS_H_

struct cache_stat_collector {
	union {
	struct {
		atomic_t	cache_hits;
		atomic_t	cache_misses;
		atomic_t	cache_bypass_hits;
		atomic_t	cache_bypass_misses;
	};

	/* cache_hit_array[!bypass][!hit]: */
	atomic_t		cache_hit_array[2][2];
	};


	atomic_t		cache_readaheads;
	atomic_t		cache_miss_collisions;
	atomic_t		sectors_bypassed;
	atomic_t		foreground_write_sectors;
	atomic_t		gc_write_sectors;
	atomic_t		discard_sectors;
};

struct cache_stats {
	struct kobject		kobj;

	unsigned long		cache_hits;
	unsigned long		cache_misses;
	unsigned long		cache_bypass_hits;
	unsigned long		cache_bypass_misses;
	unsigned long		cache_readaheads;
	unsigned long		cache_miss_collisions;
	unsigned long		sectors_bypassed;
	unsigned long		foreground_write_sectors;
	unsigned long		gc_write_sectors;
	unsigned long		discard_sectors;

	unsigned		rescale;
};

struct cache_accounting {
	struct closure		cl;
	struct timer_list	timer;
	atomic_t		closing;

	struct cache_stat_collector collector;

	struct cache_stats	total;
	struct cache_stats	five_minute;
	struct cache_stats	hour;
	struct cache_stats	day;
};

struct cache_set;
struct cached_dev;
struct bcache_device;

void bch_cache_accounting_init(struct cache_accounting *, struct closure *);
int bch_cache_accounting_add_kobjs(struct cache_accounting *, struct kobject *);
void bch_cache_accounting_clear(struct cache_accounting *);
void bch_cache_accounting_destroy(struct cache_accounting *);

#endif /* _BCACHE_STATS_H_ */
