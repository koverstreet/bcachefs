
#include "bcache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
#include "io.h"
#include "move.h"
#include "super.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

static struct bch_extent_ptr *bkey_find_ptr(struct cache_set *c,
					    struct bkey_s_extent e,
					    struct bch_extent_ptr ptr)
{
	struct bch_extent_ptr *ptr2;
	struct cache_member_rcu *mi;
	unsigned bucket_bits;

	mi = cache_member_info_get(c);
	bucket_bits = ilog2(mi->m[ptr.dev].bucket_size);
	cache_member_info_put();

	extent_for_each_ptr(e, ptr2)
		if (ptr2->dev == ptr.dev &&
		    ptr2->gen == ptr.gen &&
		    (ptr2->offset >> bucket_bits) ==
		    (ptr.offset >> bucket_bits))
			return ptr2;

	return NULL;
}

static struct bch_extent_ptr *bch_migrate_matching_ptr(struct migrate_write *m,
						       struct bkey_s_extent e)
{
	const struct bch_extent_ptr *ptr;
	struct bch_extent_ptr *ret;

	if (m->move)
		ret = bkey_find_ptr(m->op.c, e, m->move_ptr);
	else
		extent_for_each_ptr(bkey_i_to_s_c_extent(&m->key), ptr)
			if ((ret = bkey_find_ptr(m->op.c, e, *ptr)))
				break;

	return ret;
}

static int bch_migrate_index_update(struct bch_write_op *op)
{
	struct cache_set *c = op->c;
	struct migrate_write *m =
		container_of(op, struct migrate_write, op);
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret = 0;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS,
		bkey_start_pos(&bch_keylist_front(keys)->k));

	while (1) {
		struct bkey_i *insert = bch_keylist_front(keys);
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);
		struct bch_extent_ptr *ptr;
		struct bkey_s_extent e;
		BKEY_PADDED(k) new;

		if (!k.k) {
			ret = bch_btree_iter_unlock(&iter);
			break;
		}

		if (!bkey_extent_is_data(k.k))
			goto nomatch;

		bkey_reassemble(&new.k, k);
		bch_cut_front(iter.pos, &new.k);
		bch_cut_back(insert->k.p, &new.k.k);
		e = bkey_i_to_s_extent(&new.k);

		/* hack - promotes can race: */
		if (m->promote)
			extent_for_each_ptr(bkey_i_to_s_extent(insert), ptr)
				if (bch_extent_has_device(e.c, ptr->dev))
					goto nomatch;

		ptr = bch_migrate_matching_ptr(m, e);
		if (ptr) {
			if (m->move)
				__bch_extent_drop_ptr(e, ptr);

			memcpy(extent_entry_last(e),
			       &insert->v,
			       bkey_val_bytes(&insert->k));
			e.k->u64s += bkey_val_u64s(&insert->k);

			bch_extent_narrow_crcs(e);
			bch_extent_drop_redundant_crcs(e);
			bch_extent_normalize(c, e.s);

			ret = bch_btree_insert_at(c, &op->res,
					NULL, op_journal_seq(op),
					BTREE_INSERT_NOFAIL|BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&iter, &new.k));
			if (ret && ret != -EINTR)
				break;
		} else {
nomatch:
			bch_btree_iter_advance_pos(&iter);
		}

		while (bkey_cmp(iter.pos, bch_keylist_front(keys)->k.p) >= 0) {
			bch_keylist_pop_front(keys);
			if (bch_keylist_empty(keys))
				goto out;
		}

		bch_cut_front(iter.pos, bch_keylist_front(keys));
	}
out:
	bch_btree_iter_unlock(&iter);
	return ret;
}

void bch_migrate_write_init(struct cache_set *c,
			    struct migrate_write *m,
			    struct write_point *wp,
			    struct bkey_s_c k,
			    const struct bch_extent_ptr *move_ptr,
			    unsigned flags)
{
	bkey_reassemble(&m->key, k);

	m->promote = false;
	m->move = move_ptr != NULL;
	if (move_ptr)
		m->move_ptr = *move_ptr;

	if (bkey_extent_is_cached(k.k))
		flags |= BCH_WRITE_CACHED;

	bch_write_op_init(&m->op, c, &m->wbio,
			  (struct disk_reservation) { 0 },
			  wp,
			  bkey_start_pos(k.k),
			  NULL, flags);

	m->op.nr_replicas	= 1;
	m->op.index_update_fn	= bch_migrate_index_update;
}

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
	ctxt->rate = rate;
	ctxt->purpose = purpose;
	closure_init_stack(&ctxt->cl);
}

static bool bch_queue_reads_pending(struct moving_queue *q)
{
	return atomic_read(&q->read_count) || !RB_EMPTY_ROOT(&q->tree);
}

static void bch_queue_write(struct moving_queue *q)
{
	BUG_ON(q->wq == NULL);
	queue_work(q->wq, &q->work);
}

static void migrate_bio_init(struct moving_io *io, struct bio *bio,
			     unsigned sectors)
{
	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= sectors << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(sectors, PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= io->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

struct moving_io *moving_io_alloc(struct cache_set *c,
				  struct moving_queue *q,
				  struct write_point *wp,
				  struct bkey_s_c k,
				  const struct bch_extent_ptr *move_ptr)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
		     * DIV_ROUND_UP(k.k->size, PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return NULL;

	migrate_bio_init(io, &io->rbio.bio, k.k->size);

	if (bio_alloc_pages(&io->rbio.bio, GFP_KERNEL)) {
		kfree(io);
		return NULL;
	}

	migrate_bio_init(io, &io->write.wbio.bio.bio, k.k->size);
	io->write.wbio.bio.bio.bi_iter.bi_sector = bkey_start_offset(k.k);

	bch_migrate_write_init(c, &io->write, wp, k, move_ptr, 0);

	if (move_ptr)
		io->sort_key = move_ptr->offset;

	return io;
}

void moving_io_free(struct moving_io *io)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->write.wbio.bio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);

	kfree(io);
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_queue *q = io->q;
	unsigned long flags;
	bool kick_writes = true;

	//if (io->replace.failures)
	//	trace_bcache_copy_collision(q, &io->key.k);

	spin_lock_irqsave(&q->lock, flags);

	if (io->read_issued) {
		BUG_ON(!atomic_read(&q->read_count));
		atomic_dec(&q->read_count);
	}

	if (io->write_issued) {
		BUG_ON(!atomic_read(&q->write_count));
		atomic_dec(&q->write_count);
		trace_bcache_move_write_done(q, &io->write.key.k);
	}

	BUG_ON(!atomic_read(&q->count));
	atomic_dec(&q->count);
	wake_up(&q->wait);

	list_del_init(&io->list);

	if (!atomic_read(&q->count) && q->stop_waitcl) {
		closure_put(q->stop_waitcl);
		q->stop_waitcl = NULL;
	}

	if (q->rotational && bch_queue_reads_pending(q))
		kick_writes = false;

	if (list_empty(&q->pending))
		kick_writes = false;

	spin_unlock_irqrestore(&q->lock, flags);

	moving_io_free(io);

	if (kick_writes)
		bch_queue_write(q);
}

static void moving_io_after_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->context;

	if (io->write.op.error)
		moving_error(ctxt, MOVING_FLAG_WRITE);

	moving_io_destructor(cl);
}

static void write_moving(struct moving_io *io)
{
	bool stopped;
	struct bch_write_op *op = &io->write.op;

	spin_lock_irq(&io->q->lock);
	BUG_ON(!atomic_read(&io->q->count));
	stopped = io->q->stopped;
	spin_unlock_irq(&io->q->lock);

	/*
	 * If the queue has been stopped, prevent the write from occurring.
	 * This stops all writes on a device going read-only as quickly
	 * as possible.
	 */

	if (op->error || stopped)
		closure_return_with_destructor(&io->cl, moving_io_destructor);
	else {
		closure_call(&op->cl, bch_write, NULL, &io->cl);
		closure_return_with_destructor(&io->cl, moving_io_after_write);
	}
}

static void bch_queue_write_work(struct work_struct *work)
{
	struct moving_queue *q = container_of(work, struct moving_queue, work);
	struct moving_io *io;

	spin_lock_irq(&q->lock);

	if (q->rotational && bch_queue_reads_pending(q)) {
		/* All reads should have finished before writes start */
		spin_unlock_irq(&q->lock);
		return;
	}

	while (!q->stopped &&
	       atomic_read(&q->write_count) < q->max_write_count) {
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
		atomic_inc(&q->write_count);
		io->write_issued = 1;
		list_del(&io->list);
		list_add_tail(&io->list, &q->write_pending);
		trace_bcache_move_write(q, &io->write.key.k);
		spin_unlock_irq(&q->lock);
		write_moving(io);
		spin_lock_irq(&q->lock);
	}

	spin_unlock_irq(&q->lock);
}

/*
 * IMPORTANT: The caller of queue_init must have zero-filled it when it
 * allocates it.
 */

int bch_queue_init(struct moving_queue *q,
		   struct cache_set *c,
		   unsigned max_count,
		   unsigned max_read_count,
		   unsigned max_write_count,
		   bool rotational,
		   const char *name)
{
	INIT_WORK(&q->work, bch_queue_write_work);

	q->max_count = max_count;
	q->max_read_count = max_read_count;
	q->max_write_count = max_write_count;
	q->rotational = rotational;

	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->pending);
	INIT_LIST_HEAD(&q->write_pending);
	q->tree = RB_ROOT;
	init_waitqueue_head(&q->wait);

	q->wq = alloc_workqueue(name,
				WQ_UNBOUND|WQ_FREEZABLE|WQ_MEM_RECLAIM, 1);
	if (!q->wq)
		return -ENOMEM;

	return 0;
}

void bch_queue_start(struct moving_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	q->stopped = false;
	spin_unlock_irqrestore(&q->lock, flags);
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
	if (q->wq)
		destroy_workqueue(q->wq);
	q->wq = NULL;
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
		if (!read_issued && !read_completed && q->rotational) {
			rb_erase(&io->node, &q->tree);
			wake_up(&q->wait);
		}

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
	struct closure waitcl;

	closure_init_stack(&waitcl);

	spin_lock_irq(&q->lock);
	if (q->stopped)
		BUG_ON(q->stop_waitcl != NULL);
	else {
		q->stopped = true;
		if (atomic_read(&q->count)) {
			q->stop_waitcl = &waitcl;
			closure_get(&waitcl);
		}
	}
	spin_unlock_irq(&q->lock);

	bch_queue_cancel_writes(q);

	closure_sync(&waitcl);
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
		bch_btree_key_recalc_oldest_gen(c,
					bkey_i_to_s_c(&io->write.key));
	}
}

void bch_queue_recalc_oldest_gens(struct cache_set *c, struct moving_queue *q)
{
	unsigned long flags;

	/* 2nd, mark the keys in the I/Os */
	spin_lock_irqsave(&q->lock, flags);

	pending_recalc_oldest_gens(c, &q->pending);
	pending_recalc_oldest_gens(c, &q->write_pending);

	spin_unlock_irqrestore(&q->lock, flags);
}

static void read_moving_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_queue *q = io->q;
	bool stopped;

	unsigned long flags;

	if (bio->bi_error) {
		io->write.op.error = bio->bi_error;
		moving_error(io->context, MOVING_FLAG_READ);
	}

	bio_put(bio);

	spin_lock_irqsave(&q->lock, flags);

	trace_bcache_move_read_done(q, &io->write.key.k);

	BUG_ON(!io->read_issued);
	BUG_ON(io->read_completed);
	io->read_issued = 0;
	io->read_completed = 1;

	BUG_ON(!atomic_read(&q->read_count));
	atomic_dec(&q->read_count);
	wake_up(&q->wait);

	stopped = q->stopped;
	if (stopped)
		list_del_init(&io->list);
	spin_unlock_irqrestore(&q->lock, flags);

	if (stopped)
		closure_return_with_destructor(&io->cl,
			moving_io_destructor);
	else if (!q->rotational)
		bch_queue_write(q);
}

static void __bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct cache_set *c = io->write.op.c;
	struct extent_pick_ptr pick;
	u64 size = io->write.key.k.size;

	bch_extent_pick_ptr_avoiding(c, bkey_i_to_s_c(&io->write.key),
				     io->context->avoid, &pick);
	if (IS_ERR_OR_NULL(pick.ca))
		closure_return_with_destructor(cl, moving_io_destructor);

	io->context->keys_moved++;
	io->context->sectors_moved += size;
	if (io->context->rate)
		bch_ratelimit_increment(io->context->rate, size);

	bio_set_op_attrs(&io->rbio.bio, REQ_OP_READ, 0);
	io->rbio.bio.bi_iter.bi_sector = bkey_start_offset(&io->write.key.k);
	io->rbio.bio.bi_end_io	= read_moving_endio;

	bch_read_extent(c, &io->rbio,
			bkey_i_to_s_c(&io->write.key),
			&pick, BCH_READ_IS_LAST);
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
	bool stopped = false;

	BUG_ON(q->wq == NULL);
	io->q = q;
	io->context = ctxt;

	spin_lock_irq(&q->lock);
	if (q->stopped) {
		stopped = true;
		goto out;
	}

	atomic_inc(&q->count);
	list_add_tail(&io->list, &q->pending);
	trace_bcache_move_read(q, &io->write.key.k);

	if (q->rotational)
		BUG_ON(RB_INSERT(&q->tree, io, node, moving_io_cmp));
	else {
		BUG_ON(io->read_issued);
		io->read_issued = 1;
		atomic_inc(&q->read_count);
	}

out:
	spin_unlock_irq(&q->lock);

	if (stopped)
		moving_io_free(io);
	else if (!q->rotational)
		closure_call(&io->cl, __bch_data_move, NULL, &ctxt->cl);
}

/* Rotational device queues */

static bool bch_queue_read(struct moving_queue *q,
			   struct moving_context *ctxt)
{
	struct rb_node *node;
	struct moving_io *io;
	bool stopped;

	BUG_ON(!q->rotational);

	spin_lock_irq(&q->lock);
	node = rb_first(&q->tree);
	if (!node) {
		spin_unlock_irq(&q->lock);
		return false;
	}

	io = rb_entry(node, struct moving_io, node);
	rb_erase(node, &q->tree);
	wake_up(&q->wait);

	io->read_issued = 1;
	atomic_inc(&q->read_count);
	stopped = q->stopped;
	spin_unlock_irq(&q->lock);

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
	if (!q->rotational)
		goto sync;

	while (!bch_moving_context_wait(ctxt)) {
		wait_event(q->wait,
			   atomic_read(&q->read_count) < q->max_read_count);

		if (!bch_queue_read(q, ctxt))
			break;
	}

	wait_event(q->wait, !bch_queue_reads_pending(q));
	bch_queue_write(q);
sync:
	closure_sync(&ctxt->cl);
}
