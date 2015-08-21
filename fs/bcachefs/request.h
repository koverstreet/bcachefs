#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

#include "stats.h"

struct cache_set;
struct cached_dev;
struct bcache_device;
struct kmem_cache;

struct data_insert_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct	*io_wq;
	struct bio		*bio;

	/* Used internally, do not touch */
	struct btree_op		op;

	short			error;

	union {
		u8		flags;

	struct {
		/* Wait for data bucket allocation or just
		 * fail when out of space? */
		unsigned	wait:1;
		/* Discard key range? */
		unsigned	discard:1;
		/* Wait for journal commit? */
		unsigned	flush:1;
		/* Perform a compare-exchange with replace_key? */
		unsigned	replace:1;

		/* Set on completion, if cmpxchg index update failed */
		unsigned	replace_collision:1;
		/* Internal */
		unsigned	insert_data_done:1;
	};
	};

	u8			btree_alloc_reserve;

	struct write_point	*wp;
	struct open_bucket	*open_buckets[2];

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

void bch_data_insert_op_init(struct data_insert_op *, struct cache_set *,
			     struct bio *, struct write_point *, bool,
			     bool, bool, struct bkey *, struct bkey *);

unsigned bch_get_congested(struct cache_set *);
int bch_read(struct cache_set *, struct bio *, u64);
void bch_data_insert(struct closure *cl);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

void bch_read_race_work(struct work_struct *work);

extern struct kmem_cache *bch_search_cache;

#endif /* _BCACHE_REQUEST_H_ */
