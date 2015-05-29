
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "gc.h"
#include "io.h"
#include "move.h"
#include "super.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

static void moving_error(struct moving_context *ctxt, unsigned flag)
{
	atomic_inc(&ctxt->error_count);
	atomic_or(flag, &ctxt->error_flags);
}

void bch_moving_context_init(struct moving_context *ctxt,
			     struct bch_ratelimit *rate,
			     enum moving_purpose purpose)
{
	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->task = current;
	ctxt->rate = rate;
	ctxt->purpose = purpose;
	closure_init_stack(&ctxt->cl);
}

/*
 * bch_moving_wait() -- wait for a bch_moving_notify() call
 *
 * To deal with lost wakeups, we make this return immediately if notify
 * was already called.
 */
void bch_moving_wait(struct moving_context *ctxt)
{
	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (atomic_xchg(&ctxt->pending, 0))
			break;
		schedule();
	}
	set_current_state(TASK_RUNNING);
}

static void bch_moving_notify(struct moving_context *ctxt)
{
	atomic_set(&ctxt->pending, 1);
	wake_up_process(ctxt->task);
}

static bool __bch_queue_reads_pending(struct moving_queue *q)
{
	return (q->read_count > 0 || !RB_EMPTY_ROOT(&q->tree));
}

static bool bch_queue_reads_pending(struct moving_queue *q)
{
	unsigned long flags;
	bool pending;

	spin_lock_irqsave(&q->lock, flags);
	pending = __bch_queue_reads_pending(q);
	spin_unlock_irqrestore(&q->lock, flags);

	return pending;
}

static void bch_queue_write(struct moving_queue *q)
{
	BUG_ON(q->wq == NULL);
	queue_work(q->wq, &q->work);
}

static void moving_init(struct moving_io *io)
{
	struct bio *bio = &io->bio.bio.bio;

	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= io->key.k.size << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(io->key.k.size,
					       PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

struct moving_io *moving_io_alloc(struct bkey_s_c k)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
		     * DIV_ROUND_UP(k.k->size, PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return NULL;

	bkey_reassemble(&io->key, k);

	moving_init(io);

	if (bio_alloc_pages(&io->bio.bio.bio, GFP_KERNEL)) {
		kfree(io);
		return NULL;
	}

	return io;
}

void moving_io_free(struct moving_io *io)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->bio.bio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);

	kfree(io);
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_queue *q = io->q;
	struct moving_context *ctxt = io->context;
	unsigned long flags;
	bool kick_writes = true;

	if (io->op.replace_collision)
		trace_bcache_copy_collision(q, &io->key.k);

	spin_lock_irqsave(&q->lock, flags);

	BUG_ON(!q->count);
	q->count--;

	if (io->read_issued) {
		BUG_ON(!q->read_count);
		q->read_count--;
	}

	if (io->write_issued) {
		BUG_ON(!q->write_count);
		q->write_count--;
		trace_bcache_move_write_done(q, &io->key.k);
	}

	list_del_init(&io->list);

	if ((q->count == 0) && (q->stop_waitcl != NULL)) {
		closure_put(q->stop_waitcl);
		q->stop_waitcl = NULL;
	}

	if (q->rotational && __bch_queue_reads_pending(q))
		kick_writes = false;

	if (list_empty(&q->pending))
		kick_writes = false;

	spin_unlock_irqrestore(&q->lock, flags);

	moving_io_free(io);

	if (kick_writes)
		bch_queue_write(q);

	bch_moving_notify(ctxt);
}

static void moving_io_after_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->context;

	if (io->op.error)
		moving_error(ctxt, MOVING_FLAG_WRITE);

	moving_io_destructor(cl);
}

static void write_moving(struct moving_io *io)
{
	bool stopped;
	unsigned long flags;
	struct bch_write_op *op = &io->op;

	spin_lock_irqsave(&io->q->lock, flags);
	BUG_ON(io->q->count == 0);
	stopped = io->q->stopped;
	spin_unlock_irqrestore(&io->q->lock, flags);

	/*
	 * If the queue has been stopped, prevent the write from occurring.
	 * This stops all writes on a device going read-only as quickly
	 * as possible.
	 */

	if (op->error || stopped)
		closure_return_with_destructor(&io->cl, moving_io_destructor);
	else {
		moving_init(io);

		op->bio->bio.bio.bi_iter.bi_sector = bkey_start_offset(&io->key.k);

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

	if (q->rotational && __bch_queue_reads_pending(q)) {
		/* All reads should have finished before writes start */
		spin_unlock_irqrestore(&q->lock, flags);
		return;
	}

	while (!q->stopped && q->write_count < q->max_write_count) {
		io = list_first_entry_or_null(&q->pending,
					struct moving_io, list);
		/*
		 * We only issue the writes in insertion order to preserve
		 * any linearity in the original key list/tree, so if we
		 * find an io whose read hasn't completed, we don't
		 * scan beyond it.  Eventually that read will complete,
		 * at which point we may issue multiple writes (for it
		 * and any following entries whose reads had already
		 * completed and we had not examined here).
		 */
		if (!io || !io->read_completed)
			break;

		BUG_ON(io->write_issued);
		q->write_count++;
		io->write_issued = 1;
		list_del(&io->list);
		list_add_tail(&io->list, &q->write_pending);
		trace_bcache_move_write(q, &io->key.k);
		spin_unlock_irqrestore(&q->lock, flags);
		write_moving(io);
		spin_lock_irqsave(&q->lock, flags);
	}

	spin_unlock_irqrestore(&q->lock, flags);
}

/*
 * IMPORTANT: The caller of queue_init must have zero-filled it when it
 * allocates it.
 */

void bch_queue_init(struct moving_queue *q,
		    struct cache_set *c,
		    unsigned max_size,
		    unsigned max_count,
		    unsigned max_read_count,
		    unsigned max_write_count,
		    bool rotational)
{
	if (test_and_set_bit(MOVING_QUEUE_INITIALIZED, &q->flags))
		return;

	INIT_WORK(&q->work, bch_queue_write_work);
	bch_scan_keylist_init(&q->keys, c, max_size);

	q->keys.owner = q;
	q->max_count = max_count;
	q->max_read_count = max_read_count;
	q->max_write_count = max_write_count;
	q->rotational = rotational;

	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->pending);
	INIT_LIST_HEAD(&q->write_pending);
	q->tree = RB_ROOT;
}

int bch_queue_start(struct moving_queue *q,
		    const char *name)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	q->stopped = false;
	spin_unlock_irqrestore(&q->lock, flags);

	bch_scan_keylist_reset(&q->keys);

	/* Re-use workqueue if already started */
	if (!q->wq)
		q->wq = alloc_workqueue(name, WQ_UNBOUND|WQ_MEM_RECLAIM, 1);

	if (!q->wq)
		return -ENOMEM;

	return 0;
}

void queue_io_resize(struct moving_queue *q,
		     unsigned max_io,
		     unsigned max_read,
		     unsigned max_write)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	q->max_count = max_io;
	q->max_read_count = max_read;
	q->max_write_count = max_write;
	spin_unlock_irqrestore(&q->lock, flags);
}

void bch_queue_destroy(struct moving_queue *q)
{
	if (!test_and_clear_bit(MOVING_QUEUE_INITIALIZED, &q->flags))
		return;

	if (q->wq) {
		destroy_workqueue(q->wq);
		q->wq = NULL;
	}

	bch_scan_keylist_destroy(&q->keys);
}

static void bch_queue_cancel_writes(struct moving_queue *q)
{
	struct moving_io *io;
	unsigned long flags;
	bool read_issued, read_completed;

	spin_lock_irqsave(&q->lock, flags);

	while (1) {
		io = list_first_entry_or_null(&q->pending,
					      struct moving_io,
					      list);
		if (!io)
			break;

		BUG_ON(io->write_issued);
		list_del_init(&io->list);
		read_issued = io->read_issued;
		read_completed = io->read_completed;
		if (!read_issued && !read_completed && q->rotational)
			rb_erase(&io->node, &q->tree);
		spin_unlock_irqrestore(&q->lock, flags);
		if (read_completed)
			closure_return_with_destructor_noreturn(&io->cl,
					moving_io_destructor);
		else if (!read_issued)
			moving_io_destructor(&io->cl);
		spin_lock_irqsave(&q->lock, flags);
	}

	spin_unlock_irqrestore(&q->lock, flags);
}

void bch_queue_stop(struct moving_queue *q)
{
	unsigned long flags;
	struct closure waitcl;

	closure_init_stack(&waitcl);

	spin_lock_irqsave(&q->lock, flags);
	if (q->stopped)
		BUG_ON(q->stop_waitcl != NULL);
	else {
		q->stopped = true;
		if (q->count != 0) {
			q->stop_waitcl = &waitcl;
			closure_get(&waitcl);
		}
	}
	spin_unlock_irqrestore(&q->lock, flags);

	bch_queue_cancel_writes(q);

	closure_sync(&waitcl);

	/*
	 * Make sure that it is empty so that gc marking doesn't keep
	 * marking stale entries from when last used.
	 */
	bch_scan_keylist_reset(&q->keys);
}

static void pending_recalc_oldest_gens(struct cache_set *c, struct list_head *l)
{
	struct moving_io *io;

	list_for_each_entry(io, l, list) {
		/*
		 * This only marks the (replacement) key and not the
		 * insertion key in the bch_write_op, as the insertion
		 * key should be a subset of the replacement key except
		 * for any new pointers added by the write, and those
		 * don't need to be marked because they are pointing
		 * to open buckets until the write completes
		 */
		bch_btree_key_recalc_oldest_gen(c, bkey_i_to_s_c(&io->key));
	}
}

void bch_queue_recalc_oldest_gens(struct cache_set *c, struct moving_queue *q)
{
	unsigned long flags;

	/* 1st, mark the keylist keys */
	bch_keylist_recalc_oldest_gens(c, &q->keys);

	/* 2nd, mark the keys in the I/Os */
	spin_lock_irqsave(&q->lock, flags);

	pending_recalc_oldest_gens(c, &q->pending);
	pending_recalc_oldest_gens(c, &q->write_pending);

	spin_unlock_irqrestore(&q->lock, flags);
}

static void read_moving_endio(struct bio *bio)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct moving_io *io = container_of(bio->bi_private,
					    struct moving_io, cl);
	struct moving_queue *q = io->q;
	struct moving_context *ctxt = io->context;
	bool stopped;

	unsigned long flags;

	if (bio->bi_error) {
		io->op.error = bio->bi_error;
		moving_error(io->context, MOVING_FLAG_READ);
	} else if (ptr_stale(b->ca, &bkey_i_to_extent_c(&b->key)->v.ptr[0])) {
		io->op.error = -EINTR;
	}

	bch_bbio_endio(b, bio->bi_error, "reading data to move");

	spin_lock_irqsave(&q->lock, flags);

	trace_bcache_move_read_done(q, &io->key.k);

	BUG_ON(!io->read_issued);
	BUG_ON(io->read_completed);
	io->read_issued = 0;
	io->read_completed = 1;
	BUG_ON(!q->read_count);
	q->read_count--;
	stopped = q->stopped;
	if (stopped)
		list_del_init(&io->list);
	spin_unlock_irqrestore(&q->lock, flags);

	if (stopped)
		closure_return_with_destructor(&io->cl,
			moving_io_destructor);
	else if (!q->rotational)
		bch_queue_write(q);

	bch_moving_notify(ctxt);
}

static void __bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct extent_pick_ptr pick;
	u64 size = io->key.k.size;

	pick = bch_extent_pick_ptr_avoiding(io->op.c, bkey_i_to_s_c(&io->key),
					    io->context->avoid);
	if (IS_ERR_OR_NULL(pick.ca))
		closure_return_with_destructor(cl, moving_io_destructor);

	io->context->keys_moved++;
	io->context->sectors_moved += size;
	if (io->context->rate)
		bch_ratelimit_increment(io->context->rate, size);

	bio_set_op_attrs(&io->bio.bio.bio, REQ_OP_READ, 0);
	io->bio.bio.bio.bi_end_io	= read_moving_endio;

	bch_submit_bbio(&io->bio.bio, pick.ca, &io->key, &pick.ptr, false);
}

/*
 * bch_queue_full() - return if more reads can be queued with bch_data_move().
 *
 * In rotational mode, always returns false if no reads are in flight (see
 * how max_count is initialized in bch_queue_init()).
 */
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

static int moving_io_cmp(struct moving_io *io1, struct moving_io *io2)
{
	if (io1->sort_key < io2->sort_key)
		return -1;
	else if (io1->sort_key > io2->sort_key)
		return 1;
	else {
		/* We don't want duplicate keys. Eventually, we will have
		 * support for GC with duplicate pointers -- for now,
		 * just sort them randomly instead */
		if (io1 < io2)
			return -1;
		else if (io1 > io2)
			return 1;
		BUG();
	}
}

void bch_data_move(struct moving_queue *q,
		   struct moving_context *ctxt,
		   struct moving_io *io)
{
	unsigned long flags;
	bool stopped = false;

	BUG_ON(q->wq == NULL);
	io->q = q;
	io->context = ctxt;

	spin_lock_irqsave(&q->lock, flags);
	if (q->stopped) {
		stopped = true;
		goto out;
	}

	q->count++;
	list_add_tail(&io->list, &q->pending);
	trace_bcache_move_read(q, &io->key.k);

	if (q->rotational)
		BUG_ON(RB_INSERT(&q->tree, io, node, moving_io_cmp));
	else {
		BUG_ON(io->read_issued);
		io->read_issued = 1;
		q->read_count++;
	}

out:
	spin_unlock_irqrestore(&q->lock, flags);

	if (stopped)
		moving_io_free(io);
	else if (!q->rotational)
		closure_call(&io->cl, __bch_data_move, NULL, &ctxt->cl);
}

/* Rotational device queues */

static bool bch_queue_read(struct moving_queue *q,
			   struct moving_context *ctxt)
{
	unsigned long flags;
	struct rb_node *node;
	struct moving_io *io;
	bool stopped;

	BUG_ON(!q->rotational);

	spin_lock_irqsave(&q->lock, flags);
	node = rb_first(&q->tree);
	if (!node) {
		spin_unlock_irqrestore(&q->lock, flags);
		return false;
	}

	io = rb_entry(node, struct moving_io, node);
	rb_erase(node, &q->tree);
	io->read_issued = 1;
	q->read_count++;
	stopped = q->stopped;
	spin_unlock_irqrestore(&q->lock, flags);

	if (stopped) {
		moving_io_destructor(&io->cl);
		return false;
	} else {
		closure_call(&io->cl, __bch_data_move, NULL, &ctxt->cl);
		return true;
	}
}

void bch_queue_run(struct moving_queue *q, struct moving_context *ctxt)
{
	unsigned long flags;
	bool full;

	if (!q->rotational)
		goto sync;

	while (!bch_moving_context_wait(ctxt)) {
		spin_lock_irqsave(&q->lock, flags);
		full = (q->read_count == q->max_read_count);
		spin_unlock_irqrestore(&q->lock, flags);

		if (full) {
			bch_moving_wait(ctxt);
			continue;
		}

		if (!bch_queue_read(q, ctxt))
			break;
	}

	while (bch_queue_reads_pending(q))
		bch_moving_wait(ctxt);

	bch_queue_write(q);

sync:
	closure_sync(&ctxt->cl);
}
