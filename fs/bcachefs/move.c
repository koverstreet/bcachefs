
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "gc.h"
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
	struct bio *bio = &io->bio.bio;

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

	if (bio_alloc_pages(&io->bio.bio, GFP_KERNEL)) {
		kfree(io);
		return NULL;
	}

	return io;
}

static void moving_io_free(struct moving_io *io)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->bio.bio, i)
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

		op->bio->bi_iter.bi_sector = bkey_start_offset(&io->key.k);

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

static void queue_io_resize(struct moving_queue *q,
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
		rcu_read_lock();
		bch_btree_key_recalc_oldest_gen(c,
					bkey_i_to_s_c_extent(&io->key));
		rcu_read_unlock();
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
	struct cache *ca;
	const struct bch_extent_ptr *ptr;
	u64 size = io->key.k.size;

	ca = bch_extent_pick_ptr_avoiding(io->op.c, bkey_i_to_s_c(&io->key),
					  &ptr, io->context->avoid);
	if (IS_ERR_OR_NULL(ca))
		closure_return_with_destructor(cl, moving_io_destructor);

	io->context->keys_moved++;
	io->context->sectors_moved += size;
	if (io->context->rate)
		bch_ratelimit_increment(io->context->rate, size);

	bio_set_op_attrs(&io->bio.bio, REQ_OP_READ, 0);
	io->bio.bio.bi_end_io	= read_moving_endio;

	bch_submit_bbio(&io->bio, ca, &io->key, ptr, false);
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

static bool migrate_data_pred(struct scan_keylist *kl, struct bkey_s_c k)
{
	struct cache *ca = container_of(kl, struct cache,
					moving_gc_queue.keys);

	switch (k.k->type) {
	case BCH_EXTENT:
		return bch_extent_has_device(bkey_s_c_to_extent(k),
					     ca->sb.nr_this_dev);
	default:
		return false;
	}
}

#if (0)

/*
 * This code is ifdef'd out because it does not work when replicas_want > 1,
 * and when replicas_want is 1, it merely removes all the extent pointers
 * from the key, which can be dome more simply and works for replicas_want > 1
 * at the expense of copying more data around.
 * At some point this should be 'resurrected' and fixed to cause less copying.
 * But for now, it is disabled.
 */

static atomic64_t bch_dropped_pointer = ATOMIC64_INIT(0);

static void migrate_compact_key(struct cache_set *c,
				struct bkey *k,
				struct cache *ca)
{
	struct bkey_i_extent *e = bkey_to_extent(k);
	bool dropped;
	unsigned tierno;
	unsigned i, tier[CACHE_TIERS], tier_count[CACHE_TIERS];
	unsigned replicas_want = CACHE_SET_DATA_REPLICAS_WANT(&c->sb);

	tierno = CACHE_TIER(&ca->mi);

	bch_extent_drop_stale(c, k);

	/*
	 * Ensure that we are not inserting too many
	 * copies in either tier.
	 * We can do this better by not actually copying
	 * in these cases, and supporting MIGRATE_REWRITE_KEY,
	 * but that could make some buckets become unavailable
	 * (from clean to dirty), which is not supported yet.
	 */
	for (i = 0; i < CACHE_TIERS; i++) {
		tier[i] = ((unsigned) -1);
		tier_count[i] = 0;
	}

	rcu_read_lock();

	/*
	 * This relies on pointers being sorted by tier _and_
	 * the rest of the code considering dirty any pointers
	 * closer to the end of the list.
	 */

	for (i = bch_extent_ptrs(e); i != 0; ) {
		unsigned tierno;
		struct cache *ca2;

		i -= 1;
		ca2 = PTR_CACHE(c, &e->v, i);
		BUG_ON(ca2 == NULL);
		tierno = CACHE_TIER(&ca2->mi);
		tier_count[tierno] += 1;
		if ((tier[i] == ((unsigned) -1))
		    || bch_ptr_is_cache_ptr(c, k, i))
			tier[tierno] = i;
	}
	rcu_read_unlock();

	dropped = false;
	/* This relies on pointers being sorted by tier. */
	for (i = CACHE_TIERS; i != 0; ) {
		i -= 1;
		BUG_ON(tier_count[i] > replicas_want);
		if (tier_count[i] == replicas_want) {
			BUG_ON(i == tierno);
			BUG_ON(tier[i] == ((unsigned) -1));
			bch_extent_drop_ptr(k, tier[i]);
			dropped = true;
		}
	}

	if (dropped)
		atomic64_inc(&bch_dropped_pointer);
}

#endif

/*
 * It's OK to leave keys whose pointers are all stale as they'll be
 * removed by tree gc which won't allow a device slot to be re-used
 * until it has found no pointers to that slot -- presumably such keys
 * have been overwritten by something else and we were just racing.
 */

enum migrate_option {
	MIGRATE_IGNORE,		/* All pointers stale, don't do anything */
	MIGRATE_COPY,
	MIGRATE_REWRITE_KEY,	/* Unused for now */
};

static enum migrate_option migrate_cleanup_key(struct cache_set *c,
					       struct bkey_i *k,
					       struct cache *ca)
{
	struct bkey_s_extent e = bkey_i_to_s_extent(k);
	struct bch_extent_ptr *ptr;
	bool found;

	found = false;
	extent_for_each_ptr_backwards(e, ptr)
		if (PTR_DEV(ptr) == ca->sb.nr_this_dev) {
			bch_extent_drop_ptr(e, ptr - e.v->ptr);
			found = true;
		}

	if (!found) {
		/* The pointer to this device was stale. */
		return MIGRATE_IGNORE;
	}

	/*
	 * Remove all pointers, to avoid too many in a tier.
	 * migrate_compact_key above does the same when n_replicas is
	 * 1, and doesn't actually work if n_replicas > 1, so do
	 * something simple instead.
	 * Effectively, every migration copy is a fresh 'foreground' write.
	 */
	bch_set_extent_ptrs(e, 0);
	return MIGRATE_COPY;
}

static int issue_migration_move(struct cache *ca,
				struct moving_context *ctxt,
				struct bkey_s_c k,
				u64 *seen_key_count)
{
	enum migrate_option option;
	struct moving_queue *q = &ca->moving_gc_queue;
	struct cache_set *c = ca->set;
	struct moving_io *io;
	struct write_point *wp = &c->migration_write_point;

	io = moving_io_alloc(k);
	if (io == NULL)
		return -ENOMEM;

	/*
	 * This is a gross hack. It relies on migrate_cleanup_key
	 * removing all extent pointers from the key to be inserted.
	 */
	if (CACHE_SET_DATA_REPLICAS_WANT(&c->sb) > 1)
		wp = NULL;

	/* This also copies k into the write op's replace_key and insert_key */

	bch_write_op_init(&io->op, c, &io->bio.bio,
			  wp, k, k, 0);

#if (0)
	/* For testing only */
	io->op.replace_info.replace_exact = true;
#endif

	BUG_ON(q->wq == NULL);
	io->op.io_wq = q->wq;

	option = migrate_cleanup_key(c, &io->op.insert_key, ca);

	switch (option) {
	default:
	case MIGRATE_REWRITE_KEY:
		/* For now */
		BUG();

	case MIGRATE_COPY:
		bch_data_move(q, ctxt, io);
		(*seen_key_count)++;
		break;

	case MIGRATE_IGNORE:
		/* The pointer to this device was stale. */
		moving_io_free(io);
		break;
	}

	/*
	 * IMPORTANT: We must call bch_data_move before we dequeue so
	 * that the key can always be found in either the pending list
	 * in the moving queue or in the scan keylist list in the
	 * moving queue.
	 * If we reorder, there is a window where a key is not found
	 * by btree gc marking.
	 */
	bch_scan_keylist_dequeue(&q->keys);
	return 0;
}

#define MIGRATION_DEBUG		0

#define MAX_DATA_OFF_ITER	10
#define MAX_FLAG_DATA_BAD_ITER	(MIGRATION_DEBUG ? 2 : 1)
#define PASS_LOW_LIMIT		(MIGRATION_DEBUG ? 0 : 2)
#define MIGRATE_NR		64
#define MIGRATE_READ_NR		32
#define MIGRATE_WRITE_NR	32

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
	int ret;
	struct bkey_i *k;
	unsigned pass;
	u64 seen_key_count;
	unsigned last_error_count;
	unsigned last_error_flags;
	struct moving_context context;
	struct cache_set *c = ca->set;
	struct moving_queue *queue = &ca->moving_gc_queue;

	/*
	 * This reuses the moving gc queue as it is no longer in use
	 * by moving gc, which must have been stopped to call this.
	 */

	BUG_ON(ca->moving_gc_read != NULL);

	/*
	 * This may actually need to start the work queue because the
	 * device may have always been read-only and never have had it
	 * started (moving gc usually starts it but not for RO
	 * devices).
	 */

	ret = bch_queue_start(queue, "bch_move_data_off_device");
	if (ret)
		return ret;

	queue_io_resize(queue, MIGRATE_NR, MIGRATE_READ_NR, MIGRATE_WRITE_NR);

	BUG_ON(queue->wq == NULL);
	bch_moving_context_init(&context, NULL, MOVING_PURPOSE_MIGRATION);
	context.avoid = ca;

	/*
	 * In theory, only one pass should be necessary as we've
	 * quiesced all writes before calling this.
	 *
	 * However, in practice, more than one pass may be necessary:
	 * - Some move fails due to an error. We can can find this out
	 *   from the moving_context.
	 * - Some key swap failed because some of the pointers in the
	 *   key in the tree changed due to caching behavior, btree gc
	 *   pruning stale pointers, or tiering (if the device being
	 *   removed is in tier 0).  A smarter bkey_cmpxchg would
	 *   handle these cases.
	 *
	 * Thus this scans the tree one more time than strictly necessary,
	 * but that can be viewed as a verification pass.
	 */

	seen_key_count = 1;
	last_error_count = 0;
	last_error_flags = 0;

	for (pass = 0;
	     (seen_key_count != 0 && (pass < MAX_DATA_OFF_ITER));
	     pass++) {
		bool again;

		seen_key_count = 0;
		atomic_set(&context.error_count, 0);
		atomic_set(&context.error_flags, 0);
		context.last_scanned = POS_MIN;

again:
		again = false;

		while (1) {
			if (CACHE_STATE(&ca->mi) != CACHE_RO &&
			    CACHE_STATE(&ca->mi) != CACHE_ACTIVE) {
				ret = -EACCES;
				goto out;
			}

			if (bch_queue_full(queue)) {
				if (queue->rotational) {
					again = true;
					break;
				} else {
					bch_moving_wait(&context);
					continue;
				}
			}

			k = bch_scan_keylist_next_rescan(c,
							 &queue->keys,
							 &context.last_scanned,
							 POS_MAX,
							 migrate_data_pred);
			if (k == NULL)
				break;

			if (issue_migration_move(ca, &context, bkey_i_to_s_c(k),
						 &seen_key_count)) {
				/*
				 * Memory allocation failed; we will wait for
				 * all queued moves to finish and continue
				 * scanning starting from the same key
				 */
				again = true;
				break;
			}
		}

		bch_queue_run(queue, &context);
		if (again)
			goto again;

		if ((pass >= PASS_LOW_LIMIT)
		    && (seen_key_count != (MIGRATION_DEBUG ? ~0ULL : 0))) {
			pr_notice("found %llu keys on pass %u.",
				  seen_key_count, pass);
		}

		last_error_count = atomic_read(&context.error_count);
		last_error_flags = atomic_read(&context.error_flags);

		if (last_error_count != 0) {
			pr_notice("pass %u: error count = %u, error flags = 0x%x",
				  pass, last_error_count, last_error_flags);
		}
	}

	if (seen_key_count != 0 || last_error_count != 0) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -EDEADLK;
	} else if (MIGRATION_DEBUG)
		pr_notice("Migrated all data in %d iterations", pass);

out:
	bch_queue_run(queue, &context);
	return ret;
}

/*
 * This walks the btree, and for any node on the relevant device it moves the
 * node elsewhere.
 */
static int bch_move_btree_off(struct cache *ca,
			      enum btree_id id,
			      const char *name)
{
	unsigned pass;

	pr_debug("Moving %s btree off device %u",
		 name, ca->sb.nr_this_dev);

	for (pass = 0; (pass < MAX_DATA_OFF_ITER); pass++) {
		struct btree_iter iter;
		struct btree *b;
		unsigned moved = 0, seen = 0;
		int ret;

		for_each_btree_node(&iter, ca->set, id, POS_MIN, b) {
			struct bkey_s_c_extent e =
				bkey_i_to_s_c_extent(&b->key);
			seen++;
retry:
			if (!bch_extent_has_device(e, ca->sb.nr_this_dev))
				continue;

			if (bch_btree_node_rewrite(b, &iter, true)) {
				/*
				 * Drop locks to upgrade locks or wait on
				 * reserve: after retaking, recheck in case we
				 * raced.
				 */
				bch_btree_iter_unlock(&iter);
				b = bch_btree_iter_peek_node(&iter);
				goto retry;
			}

			moved++;
			iter.locks_want = -1;
		}
		ret = bch_btree_iter_unlock(&iter);
		if (ret)
			return ret; /* btree IO error */

		if (!moved)
			return 0;

		pr_debug("%s pass %u: seen %u, moved %u.",
			 name, pass, seen, moved);
	}

	/* Failed: */
	return -1;
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

int bch_move_meta_data_off_device(struct cache *ca)
{
	unsigned i;
	int ret = 0;		/* Success */

	/* 1st, Move the btree nodes off the device */

	for (i = 0; i < BTREE_ID_NR; i++)
		if (bch_move_btree_off(ca, i, bch_btree_id_names[i]) != 0)
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

/*
 * Flagging data bad when forcibly removing a device after failing to
 * migrate the data off the device.
 */

static int bch_flag_key_bad(struct btree_iter *iter,
			    struct cache *ca,
			    struct bkey_s_c_extent orig)
{
	BKEY_PADDED(key) tmp;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache_set *c = ca->set;
	bool found = false;

	/* Iterate backwards because we might drop pointers */

	bkey_reassemble(&tmp.key, to_bkey_s_c(orig));
	e = bkey_i_to_s_extent(&tmp.key);

	extent_for_each_ptr_backwards(e, ptr)
		if (PTR_DEV(ptr) == ca->sb.nr_this_dev) {
			found = true;

			/*
			 * If it was dirty, replace it with a ptr to
			 * PTR_LOST_DEV, so counting dirty replicas still works
			 * (and so we know we lost data)
			 *
			 * If the pointer was considered cached, just drop it -
			 * we can't replace it with a ptr to PTR_LOST_DEV
			 * because bch_extent_normalize() will sort it
			 * incorrectly but fortunately we don't need to.
			 */
			if (bch_extent_ptr_is_dirty(c, extent_s_to_s_c(e), ptr))
				*ptr = PTR(0, 0, PTR_LOST_DEV);
			else
				bch_extent_drop_ptr(e, ptr - e.v->ptr);
		}

	if (!found)
		return 0;

	/*
	 * bch_extent_normalize() needs to know how to turn a key with only
	 * pointers to PTR_LOST_DEV into a KEY_BAD() key anyways - because we
	 * might have a cached pointer that will go stale later - so just call
	 * it here.
	 *
	 * If the key was cached, we may have dropped all pointers above --
	 * in this case, bch_extent_normalize() will change the key type to
	 * DISCARD.
	 */
	bch_extent_normalize(c, bkey_i_to_s(&tmp.key));

	return bch_btree_insert_at(iter,
				   &keylist_single(&tmp.key),
				   NULL, /* replace_info */
				   NULL, /* closure */
				   BTREE_INSERT_ATOMIC);
}

/*
 * This doesn't actually move any data -- it marks the keys as bad
 * if they contain a pointer to a device that is forcibly removed
 * and don't have other valid pointers.  If there are valid pointers,
 * the necessary pointers to the removed device are replaced with
 * bad pointers instead.
 * This is only called if bch_move_data_off_device above failed, meaning
 * that we've already tried to move the data MAX_DATA_OFF_ITER times and
 * are not likely to succeed if we try again.
 */

int bch_flag_data_bad(struct cache *ca)
{
	int ret = 0, ret2;
	struct bkey_s_c k;
	struct btree_iter iter;

	if (MIGRATION_DEBUG)
		pr_notice("Flagging bad data.");

	bch_btree_iter_init(&iter, ca->set, BTREE_ID_EXTENTS, POS_MIN);

	while ((k = bch_btree_iter_peek(&iter)).k) {
		if (k.k->type == BCH_EXTENT) {
			ret = bch_flag_key_bad(&iter, ca,
					       bkey_s_c_to_extent(k));
			if (ret == -EINTR || ret == -EAGAIN)
				continue;

			if (ret)
				break;
		}

		bch_btree_iter_advance_pos(&iter);
	}

	ret2 = bch_btree_iter_unlock(&iter);

#ifdef CONFIG_BCACHEFS_DEBUG
	if (!ret && !ret2)
		for_each_btree_key(&iter, ca->set, BTREE_ID_EXTENTS, POS_MIN, k)
			BUG_ON(k.k->type == BCH_EXTENT &&
			       bch_extent_has_device(bkey_s_c_to_extent(k),
						     ca->sb.nr_this_dev));

	bch_btree_iter_unlock(&iter);
#endif

	return ret ?: ret2;
}
