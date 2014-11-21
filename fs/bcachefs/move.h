#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "request.h"

struct moving_io_stats {
	u64			keys_moved;
	u64			sectors_moved;
};

struct moving_io {
	struct closure		cl;
	struct keybuf_key	*w;
	struct keybuf		*keybuf;
	struct bch_write_op	op;
	/* Stats to update from submission context */
	struct moving_io_stats	*stats;
	bool			support_moving_error;
	/* Must be last because it is variable size */
	struct bbio		bio;
};

static inline struct moving_io *moving_io_alloc(struct keybuf_key *w)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
		     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return NULL;

	io->w = w;

	return io;
}

void bch_data_move(struct closure *);
int bch_move_data_off_device(struct cache *);

#endif /* _BCACHE_MOVE_H */
