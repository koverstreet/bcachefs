#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "request.h"

struct moving_io {
	struct closure		cl;
	struct keybuf_key	*w;
	struct keybuf		*keybuf;
	struct data_insert_op	op;
	struct bbio		bio; /* must be last */
};

void bch_data_move(struct closure *);

#endif /* _BCACHE_MOVE_H */
