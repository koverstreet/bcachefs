
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "move.h"
#include "super.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

enum moving_flag_bitnos {
	MOVING_FLAG_BITNO_ALLOC = 0,
	MOVING_FLAG_BITNO_READ,
	MOVING_FLAG_BITNO_WRITE,
};

#define MOVING_FLAG_ALLOC	(1U << MOVING_FLAG_BITNO_ALLOC)
#define MOVING_FLAG_READ	(1U << MOVING_FLAG_BITNO_READ)
#define MOVING_FLAG_WRITE	(1U << MOVING_FLAG_BITNO_WRITE)

struct moving_ctxt {
	struct closure cl;
	atomic_t error_count;
	atomic_t error_flags;
};

static void moving_error(struct closure *cl, unsigned flag)
{
	struct closure *parent = cl->parent;
	struct moving_ctxt *ctxt = container_of(parent, struct moving_ctxt, cl);

	atomic_inc(&ctxt->error_count);
	atomic_or(flag, &ctxt->error_flags);
}

static void moving_init(struct moving_io *io)
{
	struct bio *bio = &io->bio.bio;

	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= KEY_SIZE(&io->key) << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(KEY_SIZE(&io->key),
					       PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);

	if (io->stats) {
		io->stats->keys_moved++;
		io->stats->sectors_moved += KEY_SIZE(&io->key);
	}
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->bio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);

	if (io->op.replace_collision)
		trace_bcache_copy_collision(&io->key);

	up(io->in_flight);
	kfree(io);
}

static void moving_io_after_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if ((io->op.error != 0) && (io->support_moving_error))
		moving_error(cl, MOVING_FLAG_WRITE);

	moving_io_destructor(cl);
}

static void write_moving(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct bch_write_op *op = &io->op;

	if (op->error)
		closure_return_with_destructor(cl, moving_io_destructor);
	else {
		moving_init(io);

		op->bio->bi_iter.bi_sector = KEY_START(&io->key);

		closure_call(&op->cl, bch_write, NULL, cl);
		closure_return_with_destructor(cl, moving_io_after_write);
	}
}

static void read_moving_endio(struct bio *bio)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct moving_io *io = container_of(bio->bi_private,
					    struct moving_io, cl);
	if (bio->bi_error) {
		io->op.error = bio->bi_error;
		if (io->support_moving_error)
			moving_error(&io->cl, MOVING_FLAG_READ);
	}
	else if (ptr_stale(b->ca->set, b->ca, &b->key, 0))
		io->op.error = -EINTR;

	bch_bbio_endio(b, bio->bi_error, "reading data to move");
}

void bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct cache *ca;
	int ptr;

	down(io->in_flight);

	/* bail out if all pointers are stale */
	ca = bch_extent_pick_ptr(io->op.c, &io->key, &ptr);
	if (!ca)
		closure_return_with_destructor(cl, moving_io_destructor);

	moving_init(io);

	if (bio_alloc_pages(&io->bio.bio, GFP_KERNEL)) {
		if (io->support_moving_error)
			moving_error(cl, MOVING_FLAG_ALLOC);
		percpu_ref_put(&ca->ref);
		closure_return_with_destructor(cl, moving_io_destructor);
	}

	bio_set_op_attrs(&io->bio.bio, REQ_OP_READ, 0);
	io->bio.bio.bi_end_io	= read_moving_endio;

	bch_submit_bbio(&io->bio, ca, &io->key, ptr, false);

	continue_at(cl, write_moving, io->op.io_wq);
}

struct move_data_off_device_op {
	unsigned		dev;
	struct semaphore	in_flight;
	struct scan_keylist	keys;
};

static bool migrate_data_pred(struct scan_keylist *kl, struct bkey *k)
{
	struct move_data_off_device_op *op =
		container_of(kl, struct move_data_off_device_op, keys);
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_DEV(k, i) == op->dev)
			return true;

	return false;
}

#define MAX_DATA_OFF_ITER	10
#define MAX_MOVE_IN_FLIGHT	200
#define DFLT_MOVE_KEYS_MAX_SIZE	DFLT_SCAN_KEYLIST_MAX_SIZE

int bch_move_data_off_device(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct moving_io *io;
	struct moving_io_stats stats;
	struct moving_ctxt ctxt;
	struct move_data_off_device_op *op;
	u64 seen_key_count;
	struct bkey *k;
	unsigned i;
	int ret;
	unsigned pass;
	unsigned last_error_count;
	unsigned last_error_flags;

	op = kmalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;

	op->dev = ca->sb.nr_this_dev;
	sema_init(&op->in_flight, MAX_MOVE_IN_FLIGHT);
	bch_scan_keylist_init(&op->keys, DFLT_MOVE_KEYS_MAX_SIZE);
	memset(&stats, 0, sizeof(stats));
	memset(&ctxt, 0, sizeof(ctxt));

	closure_init_stack(&ctxt.cl);

	/*
	 * Only one pass should be necessary as we've quiesced all writes
	 * before calling this.
	 *
	 * The only reason we may iterate is if one of the moves fails
	 * due to an error, which we can find out from the moving_ctxt.
	 *
	 * Currently it can also fail to move some extent because it's key
	 * changes in between so that bkey_cmpxchg fails. The reason for
	 * this is that the extent is cached or un-cached, changing the
	 * device pointers.  This will be remedied soon by improving
	 * bkey_cmpxchg to recognize this case.
	 */

	seen_key_count = 1;
	last_error_count = 1;
	last_error_flags = 0;

	for (pass = 0;
	     (seen_key_count != 0 && (pass < MAX_DATA_OFF_ITER));
	     pass++) {
		ret = 0;
		seen_key_count = 0;
		atomic_set(&ctxt.error_count, 0);
		atomic_set(&ctxt.error_flags, 0);
		op->keys.last_scanned = ZERO_KEY;

		while ((k = bch_scan_keylist_next_rescan(c, &op->keys, &MAX_KEY,
							 migrate_data_pred))) {
			bool found;
			struct cache_member *mi = &ca->mi;

			seen_key_count += 1;

			if (CACHE_STATE(mi) != CACHE_RO &&
			    CACHE_STATE(mi) != CACHE_ACTIVE) {
				ret = -EACCES;
				goto out;
			}

			io = moving_io_alloc(k);
			if (!io) {
				ret = -ENOMEM;
				goto out;
			}

			io->stats = &stats;
			io->in_flight = &op->in_flight;
			io->support_moving_error = true;

			/* This also copies k into the write op */

			bch_write_op_init(&io->op, c, &io->bio.bio,
					  &c->migration_write_point,
					  true, false, true,
					  k, k);
			io->op.io_wq	= c->tiering_write; /* XXX */

			bch_scan_keylist_advance(&op->keys);

			k = &io->op.insert_key;

			found = false;
			for (i = 0; i < bch_extent_ptrs(k); i++)
				if (PTR_DEV(k, i) == op->dev) {
					bch_extent_drop_ptr(k, i--);
					found = true;
				}

			BUG_ON(!found);
			closure_call(&io->cl, bch_data_move, NULL, &ctxt.cl);
		}

		if ((pass != 0)
		    && (seen_key_count != 0)
		    && (last_error_count == 0)) {
			pr_notice("found %llu keys on pass %u.",
				  seen_key_count, pass);
		}

		closure_sync(&ctxt.cl);
		last_error_count = atomic_read(&ctxt.error_count);
		last_error_flags = atomic_read(&ctxt.error_flags);

		if (last_error_count != 0) {
			pr_notice("error count = %u, error flags = 0x%x",
				  last_error_count, last_error_flags);
		}
	}

	bch_scan_keylist_destroy(&op->keys);
	kfree(op);

	if ((seen_key_count != 0) || (atomic_read(&ctxt.error_count) != 0)) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -EDEADLK;
	}

	return ret;

out:
	closure_sync(&ctxt.cl);
	bch_scan_keylist_destroy(&op->keys);
	kfree(op);
	return ret;
}
