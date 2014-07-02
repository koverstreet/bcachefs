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
	struct bio		*bio;

	/* Used internally, do not touch */
	struct btree_op		op;

	uint16_t		write_point;
	short			error;

	union {
		uint16_t	flags;

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
		/* Tier to write to */
		unsigned	tier:2;
		/* Use moving GC reserves for buckets, btree nodes and
		 * open buckets? */
		unsigned	moving_gc:1;
		/* Use tiering reserves for btree nodes? */
		unsigned	tiering:1;
		/* Set on completion */
		unsigned	replace_collision:1;
		/* Internal */
		unsigned	insert_data_done:1;
	};
	};

	struct open_bucket	*open_buckets[1];

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

static inline void bch_data_insert_op_init(struct data_insert_op *op,
					   struct cache_set *c,
					   struct bio *bio,
					   unsigned write_point,
					   bool wait, bool discard, bool flush,
					   struct bkey *insert_key,
					   struct bkey *replace_key)
{
	op->c		= c;
	op->bio		= bio;
	op->write_point	= write_point;
	op->error	= 0;
	op->flags	= 0;
	op->wait	= wait;
	op->discard	= discard;
	op->flush	= flush;

	bch_keylist_init(&op->insert_keys);
	bkey_copy(&op->insert_key, insert_key);

	if (replace_key) {
		op->replace = true;
		bkey_copy(&op->replace_key, replace_key);
	}
}

unsigned bch_get_congested(struct cache_set *);
int bch_read(struct cache_set *, struct bio *, u64);
void bch_data_insert(struct closure *cl);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

void bch_read_race_work(struct work_struct *work);

extern struct kmem_cache *bch_search_cache;

#endif /* _BCACHE_REQUEST_H_ */
