
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

static void moving_error(struct moving_context *ctxt, unsigned flag)
{
	atomic_inc(&ctxt->error_count);
	atomic_or(flag, &ctxt->error_flags);
}

void bch_moving_context_init(struct moving_context *ctxt)
{
	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->task = current;
	closure_init_stack(&ctxt->cl);
}

void bch_moving_wait(struct moving_context *ctxt)
{
	do {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (atomic_read(&ctxt->pending))
			set_current_state(TASK_RUNNING);
		schedule();
	} while (atomic_xchg(&ctxt->pending, 0) == 0);
}

static void bch_moving_notify(struct moving_context *ctxt)
{
	atomic_set(&ctxt->pending, 1);
	wake_up_process(ctxt->task);
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
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_queue *q = io->q;
	struct moving_context *ctxt = io->context;
	unsigned long flags;
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->bio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);

	if (io->op.replace_collision)
		trace_bcache_copy_collision(q, &io->key);

	spin_lock_irqsave(&q->lock, flags);

	BUG_ON(!q->count);
	q->count--;

	if (!io->read_completed) {
		BUG_ON(!q->read_count);
		q->read_count--;
	}

	if (io->write_issued) {
		BUG_ON(!q->write_count);
		q->write_count--;
		trace_bcache_move_write_done(q, &io->key);
	} else
		list_del(&io->list);

	spin_unlock_irqrestore(&q->lock, flags);
	queue_work(q->wq, &q->work);

	kfree(io);

	bch_moving_notify(ctxt);
}

static void moving_io_after_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (io->op.error)
		moving_error(io->context, MOVING_FLAG_WRITE);

	moving_io_destructor(cl);
}
static void write_moving(struct moving_io *io)
{
	struct bch_write_op *op = &io->op;

	if (op->error)
		closure_return_with_destructor(&io->cl, moving_io_destructor);
	else {
		moving_init(io);

		op->bio->bi_iter.bi_sector = KEY_START(&io->key);

		closure_call(&op->cl, bch_write, NULL, &io->cl);
		closure_return_with_destructor(&io->cl, moving_io_after_write);
	}
}

static void bch_queue_write_work(struct work_struct *work)
{
	struct moving_queue *q = container_of(work, struct moving_queue, work);
	struct moving_io *io;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	while (q->write_count < q->max_write_count) {
		io = list_first_entry_or_null(&q->pending,
					struct moving_io, list);
		if (!io)
			break;
		if (!io->read_completed)
			break;

		q->write_count++;
		BUG_ON(io->write_issued);
		io->write_issued = 1;
		list_del(&io->list);
		trace_bcache_move_write(q, &io->key);
		spin_unlock_irqrestore(&q->lock, flags);
		write_moving(io);
		spin_lock_irqsave(&q->lock, flags);
	}
	spin_unlock_irqrestore(&q->lock, flags);
}

void bch_queue_init(struct moving_queue *q,
		    unsigned max_size,
		    unsigned max_count,
		    unsigned max_read_count,
		    unsigned max_write_count)
{
	memset(q, 0, sizeof(*q));

	INIT_WORK(&q->work, bch_queue_write_work);
	bch_scan_keylist_init(&q->keys, max_size);

	q->max_count = max_count;
	q->max_read_count = max_read_count;
	q->max_write_count = max_write_count;

	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->pending);
}

int bch_queue_start(struct moving_queue *q,
		    const char *name)
{
	q->wq = alloc_workqueue(name, WQ_UNBOUND|WQ_MEM_RECLAIM, 1);
	if (!q->wq)
		return -ENOMEM;

	return 0;
}

void bch_queue_destroy(struct moving_queue *q)
{
	if (q->wq) {
		destroy_workqueue(q->wq);
		q->wq = NULL;
	}

	bch_scan_keylist_destroy(&q->keys);
}

static void read_moving_endio(struct bio *bio)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct moving_io *io = container_of(bio->bi_private,
					    struct moving_io, cl);
	struct moving_queue *q = io->q;
	struct moving_context *ctxt = io->context;
	unsigned long flags;

	if (bio->bi_error) {
		io->op.error = bio->bi_error;
		moving_error(io->context, MOVING_FLAG_READ);
	} else if (ptr_stale(b->ca->set, b->ca, &b->key, 0))
		io->op.error = -EINTR;

	bch_bbio_endio(b, bio->bi_error, "reading data to move");

	spin_lock_irqsave(&q->lock, flags);

	trace_bcache_move_read_done(q, &io->key);

	BUG_ON(io->read_completed);
	io->read_completed = 1;
	BUG_ON(!q->read_count);
	q->read_count--;
	spin_unlock_irqrestore(&q->lock, flags);
	queue_work(q->wq, &q->work);

	bch_moving_notify(ctxt);
}

static void __bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct cache *ca;
	int ptr;

	ca = bch_extent_pick_ptr(io->op.c, &io->key, &ptr);
	if (IS_ERR_OR_NULL(ca))
		closure_return_with_destructor(cl, moving_io_destructor);

	io->context->keys_moved++;
	io->context->sectors_moved += KEY_SIZE(&io->key);

	moving_init(io);

	if (bio_alloc_pages(&io->bio.bio, GFP_KERNEL)) {
		moving_error(io->context, MOVING_FLAG_ALLOC);
		percpu_ref_put(&ca->ref);
		closure_return_with_destructor(&io->cl, moving_io_destructor);
	}

	bio_set_op_attrs(&io->bio.bio, REQ_OP_READ, 0);
	io->bio.bio.bi_end_io	= read_moving_endio;

	bch_submit_bbio(&io->bio, ca, &io->key, ptr, false);
}

bool bch_queue_full(struct moving_queue *q)
{
	unsigned long flags;
	bool full;

	spin_lock_irqsave(&q->lock, flags);
	BUG_ON(q->count > q->max_count);
	BUG_ON(q->read_count > q->max_read_count);
	full = (q->count == q->max_count ||
		q->read_count == q->max_read_count);
	spin_unlock_irqrestore(&q->lock, flags);

	return full;
}

void bch_data_move(struct moving_queue *q,
		   struct moving_context *ctxt,
		   struct moving_io *io)
{
	unsigned long flags;

	io->q = q;
	io->context = ctxt;

	spin_lock_irqsave(&q->lock, flags);
	q->count++;
	q->read_count++;
	list_add_tail(&io->list, &q->pending);
	trace_bcache_move_read(q, &io->key);

	spin_unlock_irqrestore(&q->lock, flags);

	closure_call(&io->cl, __bch_data_move, NULL, &ctxt->cl);
}

struct migrate_data_op {
	struct cache_set	*c;
	struct moving_queue	queue;
	struct moving_context	context;
	unsigned		dev;
};

static bool migrate_data_pred(struct scan_keylist *kl, struct bkey *k)
{
	struct migrate_data_op *op =
		container_of(kl, struct migrate_data_op, queue.keys);
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_DEV(k, i) == op->dev)
			return true;

	return false;
}

static int issue_migration_move(struct moving_queue *q,
				struct moving_context *ctxt,
				struct bkey *k)
{
	struct migrate_data_op *op = container_of(q, struct migrate_data_op,
						  queue);
	struct moving_io *io;
	unsigned i;
	bool found;

	io = moving_io_alloc(k);
	if (io == NULL)
		return -ENOMEM;

	/* This also copies k into the write op */

	bch_write_op_init(&io->op, op->c, &io->bio.bio,
			  &op->c->migration_write_point,
			  true, false, true,
			  k, k);
	io->op.io_wq = q->wq;

	bch_scan_keylist_dequeue(&q->keys);

	k = &io->op.insert_key;

	found = false;
	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (PTR_DEV(k, i) == op->dev) {
			bch_extent_drop_ptr(k, i--);
			found = true;
		}

	BUG_ON(!found);

	bch_data_move(q, ctxt, io);
	return 0;
}

#define MIGRATION_KEYS_MAX_SIZE DFLT_SCAN_KEYLIST_MAX_SIZE
#define MIGRATION_NR 32
#define MIGRATION_READ_NR 16
#define MIGRATION_WRITE_NR 16

#define MAX_DATA_OFF_ITER	10

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
	struct bkey *k;
	int ret;
	unsigned pass;
	struct migrate_data_op *op;
	u64 seen_key_count;
	unsigned last_error_count;
	unsigned last_error_flags;

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;

	op->c = ca->set;
	op->dev = ca->sb.nr_this_dev;

	bch_queue_init(&op->queue,
		       MIGRATION_KEYS_MAX_SIZE,
		       MIGRATION_NR,
		       MIGRATION_READ_NR,
		       MIGRATION_WRITE_NR);

	ret = bch_queue_start(&op->queue, "bch_migration");
	if (ret)
		goto out_free;

	bch_moving_context_init(&op->context);

	/*
	 * Only one pass should be necessary as we've quiesced all writes
	 * before calling this.
	 *
	 * The only reason we may iterate is if one of the moves fails
	 * due to an error, which we can find out from the moving_context.
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
		atomic_set(&op->context.error_count, 0);
		atomic_set(&op->context.error_flags, 0);
		op->context.last_scanned = ZERO_KEY;

		while (1) {
			if (CACHE_STATE(&ca->mi) != CACHE_RO &&
			    CACHE_STATE(&ca->mi) != CACHE_ACTIVE) {
				ret = -EACCES;
				goto out;
			}

			if (bch_queue_full(&op->queue)) {
				bch_moving_wait(&op->context);
				continue;
			}

			k = bch_scan_keylist_next_rescan(op->c,
						&op->queue.keys,
						&op->context.last_scanned,
						&MAX_KEY,
						migrate_data_pred);
			if (k == NULL)
				break;

			ret = issue_migration_move(&op->queue, &op->context, k);
			if (!ret)
				seen_key_count += 1;
		}

		if ((pass != 0)
		    && (seen_key_count != 0)
		    && (last_error_count == 0)) {
			pr_notice("found %llu keys on pass %u.",
				  seen_key_count, pass);
		}

		closure_sync(&op->context.cl);
		last_error_count = atomic_read(&op->context.error_count);
		last_error_flags = atomic_read(&op->context.error_flags);

		if (last_error_count != 0) {
			pr_notice("error count = %u, error flags = 0x%x",
				  last_error_count, last_error_flags);
		}
	}

	if (seen_key_count != 0 || atomic_read(&op->context.error_count) != 0) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -EDEADLK;
	}

out:
	closure_sync(&op->context.cl);
out_free:
	bch_queue_destroy(&op->queue);
	kfree(op);

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
