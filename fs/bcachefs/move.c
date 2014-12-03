
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "move.h"
#include "super.h"
#include "journal.h"
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
	if (IS_ERR_OR_NULL(ca))
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

static bool migrate_data_pred(struct scan_keylist *kl, struct bkey *k)
{
	struct cache *ca = container_of(kl, struct cache, moving_gc_keys);
	unsigned dev = ca->sb.nr_this_dev;
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_DEV(k, i) == dev)
			return true;

	return false;
}

#define MAX_DATA_OFF_ITER	10
#define MAX_MOVE_IN_FLIGHT	200

/*
 * This moves only the data off, leaving the meta-data (if any) in place.
 * It walks the key space, and for any key with a valid pointer to the
 * relevant device, it copies it elsewhere, updating the key to point to
 * the copy.
 * The meta-data is moved off by bch_move_meta_data_off_device.
 *
 * Note: If the number of data replicas desired is > 1, ideally, any
 * new copies would not be made in the same device that already have a
 * copy (if there are enough devices).
 * This is _not_ currently implemented.  The multiple replicas can
 * land in the same device even if there are others available.
 */

int bch_move_data_off_device(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct moving_io *io;
	struct moving_io_stats stats;
	struct moving_ctxt ctxt;
	struct semaphore in_flight;
	u64 seen_key_count;
	struct bkey *k;
	unsigned i, dev;
	int ret;
	unsigned pass;
	unsigned last_error_count;
	unsigned last_error_flags;

	/*
	 * This re-uses the moving gc scan key list because moving gc
	 * must already be stopped when this is called and btree gc
	 * already knows to scan it.
	 */

	BUG_ON(ca->moving_gc_read != NULL);
	bch_scan_keylist_reset(&ca->moving_gc_keys);
	dev = ca->sb.nr_this_dev;

	sema_init(&in_flight, MAX_MOVE_IN_FLIGHT);
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
		ca->moving_gc_keys.last_scanned = ZERO_KEY;

		while ((k = bch_scan_keylist_next_rescan(c,
							 &ca->moving_gc_keys,
							 &MAX_KEY,
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
			io->in_flight = &in_flight;
			io->support_moving_error = true;

			/* This also copies k into the write op */

			bch_write_op_init(&io->op, c, &io->bio.bio,
					  &c->migration_write_point,
					  true, false, true,
					  k, k);
			io->op.io_wq	= c->tiering_write; /* XXX */

			bch_scan_keylist_dequeue(&ca->moving_gc_keys);

			k = &io->op.insert_key;

			found = false;
			for (i = 0; i < bch_extent_ptrs(k); i++)
				if (PTR_DEV(k, i) == dev) {
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

	if ((seen_key_count != 0) || (atomic_read(&ctxt.error_count) != 0)) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -EDEADLK;
	}

	return ret;

out:
	closure_sync(&ctxt.cl);
	return ret;
}

struct btree_move {
	struct btree_op	op;	/* Tree traversal info */
	unsigned	dev;	/* Device to move btree from */
	unsigned	err;	/* Something went awry */
	unsigned	seen;	/* How many were examined */
	unsigned	found;	/* How many were found. */
	unsigned	moved;	/* How many were moved. */
	struct bkey	start;	/* Where to re-start walk */
};

#define MOVE_DEBUG	0

/*
 * Note: btree_map_nodes implements a post-order traversal,
 * i.e. the children of this node have already been processed.
 */

static int move_btree_off_fn(struct btree_op *op, struct btree *b)
{
	unsigned i;
	struct bkey *k = &b->key;
	struct btree_move *mov = container_of(op, struct btree_move, op);

	mov->seen += 1;

	if (MOVE_DEBUG) {
		char buf[256];

		(void) bch_bkey_to_text(buf, sizeof(buf), k);
		pr_notice("Examining bkey %s (%u pointers)",
			  buf, bch_extent_ptrs(k));
		for (i = 0; i < bch_extent_ptrs(k); i++)
			pr_notice("device %u", ((unsigned) PTR_DEV(k, i)));
	}

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_DEV(k, i) == mov->dev)
			goto found;

	/* Not found */
	return MAP_CONTINUE;

found:
	mov->found += 1;

	if (btree_move_node(b, op)) {
		mov->moved += 1;
		return MAP_CONTINUE;
	}

	/*
	 * Assume failure due to inability to allocate space.
	 * Remember where to start again, and punt.
	 * btree_move_node has already made op.cl wait in the bucket
	 * freelist.
	 */
	mov->start = START_KEY(k);
	return MAP_DONE;
}

/*
 * This walks the btree without walking the leaves, and for any
 * pointer to a node in the relevant device, it moves the interior
 * node elsewhere.
 *
 * Note: If the number of meta-data replicas desired is > 1, ideally,
 * any new copies would not be made in the same device that already
 * have a copy (if there are enough devices).
 *
 * This is _not_ currently implemented.  The multiple replicas can
 * land in the same device even if there are others available.
 */

/*
 * Note: Since this intent-locks the whole btree (including the root),
 * perhaps we want to do something similar to btree gc, and
 * periodically give up, to prevent foreground writes from being
 * stalled for a long time.
 */

static int bch_move_btree_off(struct cache *ca,
			      enum btree_id id,
			      const char *name)
{
	int val, ret;
	unsigned pass;
	struct bkey start;
	struct btree_move mov;

	if (MOVE_DEBUG) {
		/* Debugging */
		pr_notice("Moving %s btree off device %u",
			  name, ca->sb.nr_this_dev);
	}

	for (pass = 0; (pass < MAX_DATA_OFF_ITER); pass++) {
		bch_btree_op_init(&mov.op, id, S8_MAX);
		mov.dev = ca->sb.nr_this_dev;
		mov.err = mov.seen = mov.found = mov.moved = 0;
		mov.start = ZERO_KEY;

		while (1) {
			start = mov.start;
			mov.start = MAX_KEY;
			val = bch_btree_map_nodes(&mov.op,
						  ca->set,
						  &start,
						  move_btree_off_fn,
						  (MAP_ASYNC
						   |MAP_ALL_NODES));

			/*
			 * Actually wait on the bucket freelist.
			 * The call to closure_wait is all the way in
			 * __btree_check_reserve called (eventually)
			 * by btree_move_node when there aren't enough
			 * buckets available.
			 * That way, we wait after unlocking the tree,
			 * rather than in the guts, with the tree
			 * write-locked.
			 * Note that if we didn't fail to allocate, we
			 * won't wait at all, since we won't be in the
			 * waitlist.
			 */
			closure_sync(&mov.op.cl);

			if (val < 0) {
				ret = 1; /* Failure */
				break;
			} else if (bkey_cmp(&mov.start, &MAX_KEY) == 0) {
				ret = 0; /* Success */
				break;
			}
		}

		if (MOVE_DEBUG) {
			/* Debugging */
			pr_notice("%s pass %u: seen %u, found %u, moved %u.",
				  name, pass, mov.seen, mov.found, mov.moved);

			if (mov.moved != 0)
				pr_notice("moved %u %s nodes in pass %u.",
					  mov.moved, name, pass);
		}

		if (ret != 0)
			pr_err("pass %u: Unable to move %s meta-data in %pU.",
			       pass, name, ca->set->sb.set_uuid.b);
		else if (mov.found == 0)
			break;
	}

	if (mov.found != 0)
		ret = -1;	/* We don't know if we succeeded */

	return ret;
}

/*
 * This moves only the meta-data off, leaving the data (if any) in place.
 * The data is moved off by bch_move_data_off_device, if desired, and
 * called first.
 *
 * Before calling this, allocation of buckets to the device must have
 * been disabled, as else we'll continue to write meta-data to the device
 * when new buckets are picked for meta-data writes.
 * In addition, the copying gc and allocator threads for the device
 * must have been stopped.  The allocator thread is the only thread
 * that writes prio/gen information.
 *
 * Meta-data consists of:
 * - Btree nodes
 * - Prio/gen information
 * - Journal entries
 * - Superblock
 *
 * This has to move the btree nodes and the journal only:
 * - prio/gen information is not written once the allocator thread is stopped.
 *   also, as the prio/gen information is per-device it is not moved.
 * - the superblock will be written by the caller once after everything
 *   is stopped.
 *
 * Note that currently there is no way to stop btree node and journal
 * meta-data writes to a device without moving the meta-data because
 * once a bucket is open for a btree node, unless a replacement btree
 * node is allocated (and the tree updated), the bucket will continue
 * to be written with updates.  Similarly for the journal (it gets
 * written until filled).
 *
 * This routine leaves the data (if any) in place.  Whether the data
 * should be moved off is a decision independent of whether the meta
 * data should be moved off and stopped:
 *
 * - For device removal, both data and meta-data are moved off, in
 *   that order.
 *
 * - However, for turning a device read-only without removing it, only
 *   meta-data is moved off since that's the only way to prevent it
 *   from being written.  Data is left in the device, but no new data
 *   is written.
 */

#define DEF_BTREE_ID(kwd, val, name) name,

static const char *btree_id_names[BTREE_ID_NR] = {
	DEFINE_BCH_BTREE_IDS()
};

#undef DEF_BTREE_ID

int bch_move_meta_data_off_device(struct cache *ca)
{
	unsigned i;
	int ret = 0;		/* Success */

	/* 1st, Move the btree nodes off the device */

	for (i = 0; i < BTREE_ID_NR; i++)
		if (bch_move_btree_off(ca, i, btree_id_names[i]) != 0)
			return 1;

	/* There are no prios/gens to move -- they are already in the device. */

	/* 2nd. Move the journal off the device */

	if (bch_journal_move(ca) != 0) {
		pr_err("Unable to move the journal off in %pU.",
		       ca->set->sb.set_uuid.b);
		ret = 1;	/* Failure */
	}

	return ret;
}
