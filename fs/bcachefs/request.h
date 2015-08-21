#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

struct data_insert_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct *wq;
	struct bio		*bio;

	uint16_t		write_point;
	uint16_t		write_prio;
	short			error;

	union {
		uint16_t	flags;

	struct {
		unsigned	bypass:1;
		unsigned	flush:1;
		unsigned	replace:1;

		unsigned	replace_collision:1;
		unsigned	insert_data_done:1;
	};
	};

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

static inline void bch_data_insert_op_init(struct data_insert_op *op,
					   struct cache_set *c,
					   struct workqueue_struct *wq,
					   struct bio *bio,
					   unsigned write_point,
					   bool bypass, bool flush,
					   struct bkey *insert_key,
					   struct bkey *replace_key)
{
	op->c		= c;
	op->wq		= wq;
	op->bio		= bio;
	op->write_point	= write_point;
	op->error	= 0;
	op->flags	= 0;
	op->bypass	= bypass;
	op->flush	= flush;

	bch_keylist_init(&op->insert_keys);
	bkey_copy(&op->insert_key, insert_key);

	if (replace_key) {
		op->replace = true;
		bkey_copy(&op->replace_key, replace_key);
	}
}

unsigned bch_get_congested(struct cache_set *);
void bch_data_insert(struct closure *cl);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

extern struct kmem_cache *bch_search_cache, *bch_passthrough_cache;

#endif /* _BCACHE_REQUEST_H_ */
