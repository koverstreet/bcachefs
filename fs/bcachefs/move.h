#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "request.h"

struct moving_io_stats {
	u64			keys_moved;
	u64			sectors_moved;
};

struct moving_io {
	struct closure		cl;
	struct bch_write_op	op;
	/* Stats to update from submission context */
	struct moving_io_stats	*stats;
	struct semaphore	*in_flight;
	bool			support_moving_error;
	BKEY_PADDED(key);
	/* Must be last since it is variable size */
	struct bbio		bio;
};

static inline struct moving_io *moving_io_alloc(struct bkey *k)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
		     * DIV_ROUND_UP(KEY_SIZE(k), PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return NULL;

	bkey_copy(&io->key, k);

	return io;
}

void bch_data_move(struct closure *);
int bch_move_data_off_device(struct cache *);

#endif /* _BCACHE_MOVE_H */
