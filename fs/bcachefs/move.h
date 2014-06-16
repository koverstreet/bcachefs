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
	struct data_insert_op	op;
	/* Stats to update from submission context */
	struct moving_io_stats	*stats;
	/* Must be last */
	struct bbio		bio;
};

void bch_data_move(struct closure *);

#endif /* _BCACHE_MOVE_H */
