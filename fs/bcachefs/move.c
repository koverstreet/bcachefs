
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "io.h"
#include "keybuf.h"
#include "move.h"

#include <trace/events/bcachefs.h>

static void moving_init(struct moving_io *io)
{
	struct bio *bio = &io->bio.bio;

	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= KEY_SIZE(&io->w->key) << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(KEY_SIZE(&io->w->key),
					       PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);

	if (io->stats) {
		io->stats->keys_moved++;
		io->stats->sectors_moved += KEY_SIZE(&io->w->key);
	}
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	bio_free_pages(&io->bio.bio);

	if (io->op.replace_collision)
		trace_bcache_copy_collision(&io->w->key);

	bch_keybuf_put(io->keybuf, io->w);
	kfree(io);
}

static void write_moving(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct data_insert_op *op = &io->op;

	if (!op->error)	{
		moving_init(io);

		op->bio->bi_iter.bi_sector = KEY_START(&io->w->key);

		closure_call(&op->cl, bch_data_insert, NULL, cl);
	}

	closure_return_with_destructor(cl, moving_io_destructor);
}

static void read_moving_endio(struct bio *bio)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct moving_io *io = container_of(bio->bi_private,
					    struct moving_io, cl);
	if (bio->bi_error)
		io->op.error = bio->bi_error;
	else if (ptr_stale(b->ca->set, b->ca, &b->key, 0))
		io->op.error = -EINTR;

	bch_bbio_endio(b, bio->bi_error, "reading data to move");
}

void bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct cache *ca;
	int ptr;

	/* bail out if all pointers are stale */
	ca = bch_extent_pick_ptr(io->op.c, &io->w->key, &ptr);
	if (!ca)
		closure_return_with_destructor(cl, moving_io_destructor);

	moving_init(io);

	if (bio_alloc_pages(&io->bio.bio, GFP_KERNEL)) {
		percpu_ref_put(&ca->ref);
		closure_return_with_destructor(cl, moving_io_destructor);
	}

	bio_set_op_attrs(&io->bio.bio, REQ_OP_READ, 0);
	io->bio.bio.bi_end_io	= read_moving_endio;

	bch_submit_bbio(&io->bio, ca, &io->w->key, ptr, false);

	continue_at(cl, write_moving, io->op.io_wq);
}
