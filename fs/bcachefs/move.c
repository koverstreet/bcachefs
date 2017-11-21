
#include "bcachefs.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
#include "io.h"
#include "move.h"
#include "super-io.h"
#include "keylist.h"

#include <linux/ioprio.h>

#include <trace/events/bcachefs.h>

static struct bch_extent_ptr *bkey_find_ptr(struct bch_fs *c,
					    struct bkey_s_extent e,
					    struct bch_extent_ptr ptr)
{
	struct bch_extent_ptr *ptr2;
	struct bch_dev *ca = c->devs[ptr.dev];

	extent_for_each_ptr(e, ptr2)
		if (ptr2->dev == ptr.dev &&
		    ptr2->gen == ptr.gen &&
		    PTR_BUCKET_NR(ca, ptr2) ==
		    PTR_BUCKET_NR(ca, &ptr))
			return ptr2;

	return NULL;
}

static struct bch_extent_ptr *bch2_migrate_matching_ptr(struct migrate_write *m,
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

static int bch2_migrate_index_update(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct migrate_write *m =
		container_of(op, struct migrate_write, op);
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret = 0;

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS,
			     bkey_start_pos(&bch2_keylist_front(keys)->k),
			     BTREE_ITER_INTENT);

	while (1) {
		struct bkey_s_extent insert =
			bkey_i_to_s_extent(bch2_keylist_front(keys));
		struct bkey_s_c k = bch2_btree_iter_peek_with_holes(&iter);
		struct bch_extent_ptr *ptr;
		struct bkey_s_extent e;
		BKEY_PADDED(k) new;

		if (!k.k) {
			ret = bch2_btree_iter_unlock(&iter);
			break;
		}

		if (!bkey_extent_is_data(k.k))
			goto nomatch;

		bkey_reassemble(&new.k, k);
		bch2_cut_front(iter.pos, &new.k);
		bch2_cut_back(insert.k->p, &new.k.k);
		e = bkey_i_to_s_extent(&new.k);

		/* hack - promotes can race: */
		if (m->promote)
			extent_for_each_ptr(insert, ptr)
				if (bch2_extent_has_device(e.c, ptr->dev))
					goto nomatch;

		ptr = bch2_migrate_matching_ptr(m, e);
		if (ptr) {
			int nr_new_dirty = bch2_extent_nr_dirty_ptrs(insert.s_c);
			unsigned insert_flags =
				BTREE_INSERT_ATOMIC|
				BTREE_INSERT_NOFAIL;

			/* copygc uses btree node reserve: */
			if (m->move)
				insert_flags |= BTREE_INSERT_USE_RESERVE;

			if (m->move) {
				nr_new_dirty -= !ptr->cached;
				__bch2_extent_drop_ptr(e, ptr);
			}

			BUG_ON(nr_new_dirty < 0);

			memcpy_u64s(extent_entry_last(e),
				    insert.v,
				    bkey_val_u64s(insert.k));
			e.k->u64s += bkey_val_u64s(insert.k);

			bch2_extent_narrow_crcs(e);
			bch2_extent_drop_redundant_crcs(e);
			bch2_extent_normalize(c, e.s);
			bch2_extent_mark_replicas_cached(c, e, nr_new_dirty);

			ret = bch2_btree_insert_at(c, &op->res,
					NULL, op_journal_seq(op),
					insert_flags,
					BTREE_INSERT_ENTRY(&iter, &new.k));
			if (ret && ret != -EINTR)
				break;
		} else {
nomatch:
			bch2_btree_iter_advance_pos(&iter);
		}

		while (bkey_cmp(iter.pos, bch2_keylist_front(keys)->k.p) >= 0) {
			bch2_keylist_pop_front(keys);
			if (bch2_keylist_empty(keys))
				goto out;
		}

		bch2_cut_front(iter.pos, bch2_keylist_front(keys));
	}
out:
	bch2_btree_iter_unlock(&iter);
	return ret;
}

void bch2_migrate_write_init(struct bch_fs *c,
			     struct migrate_write *m,
			     struct bch_devs_mask *devs,
			     struct bkey_s_c k,
			     const struct bch_extent_ptr *move_ptr,
			     unsigned flags)
{
	bkey_reassemble(&m->key, k);

	m->promote = false;
	m->move = move_ptr != NULL;
	if (move_ptr)
		m->move_ptr = *move_ptr;

	if (bkey_extent_is_cached(k.k) ||
	    (move_ptr && move_ptr->cached))
		flags |= BCH_WRITE_CACHED;

	bch2_write_op_init(&m->op, c, (struct disk_reservation) { 0 },
			   devs, (unsigned long) current,
			   bkey_start_pos(k.k), NULL,
			   flags|BCH_WRITE_ONLY_SPECIFIED_DEVS);

	if (m->move)
		m->op.alloc_reserve = RESERVE_MOVINGGC;

	m->op.nonce		= extent_current_nonce(bkey_s_c_to_extent(k));
	m->op.nr_replicas	= 1;
	m->op.index_update_fn	= bch2_migrate_index_update;
}

static void migrate_bio_init(struct moving_io *io, struct bio *bio,
			     unsigned sectors)
{
	bio_init(bio, io->bi_inline_vecs,
		 DIV_ROUND_UP(sectors, PAGE_SECTORS));
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= sectors << 9;
	bio->bi_private		= &io->cl;
	bch2_bio_map(bio, NULL);
}

static void moving_io_free(struct moving_io *io)
{
	struct moving_context *ctxt = io->ctxt;
	struct bio_vec *bv;
	int i;

	atomic_sub(io->write.key.k.size, &ctxt->sectors_in_flight);
	wake_up(&ctxt->wait);

	bio_for_each_segment_all(bv, &io->write.op.wbio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);
	kfree(io);
}

static void moving_error(struct moving_context *ctxt, unsigned flag)
{
	atomic_inc(&ctxt->error_count);
	//atomic_or(flag, &ctxt->error_flags);
}

static void moving_write_done(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (io->write.op.error)
		moving_error(io->ctxt, MOVING_FLAG_WRITE);

	//if (io->replace.failures)
	//	trace_copy_collision(q, &io->key.k);

	moving_io_free(io);
}

static void write_moving(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct bch_write_op *op = &io->write.op;

	closure_call(&op->cl, bch2_write, NULL, &io->cl);
	closure_return_with_destructor(&io->cl, moving_write_done);
}

static inline struct moving_io *next_pending_write(struct moving_context *ctxt)
{
	struct moving_io *io =
		list_first_entry_or_null(&ctxt->reads, struct moving_io, list);

	return io && io->read_completed ? io : NULL;
}

static void read_moving_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->ctxt;

	trace_move_read_done(&io->write.key.k);

	if (bio->bi_status)
		moving_error(io->ctxt, MOVING_FLAG_READ);

	io->read_completed = true;
	if (next_pending_write(ctxt))
		wake_up(&ctxt->wait);

	closure_put(&ctxt->cl);
}

int bch2_data_move(struct bch_fs *c,
		   struct moving_context *ctxt,
		   struct bch_devs_mask *devs,
		   struct bkey_s_c k,
		   const struct bch_extent_ptr *move_ptr)
{
	struct extent_pick_ptr pick;
	struct moving_io *io;

	bch2_extent_pick_ptr(c, k, &ctxt->avoid, &pick);
	if (IS_ERR_OR_NULL(pick.ca))
		return pick.ca ? PTR_ERR(pick.ca) : 0;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec) *
		     DIV_ROUND_UP(k.k->size, PAGE_SECTORS), GFP_KERNEL);
	if (!io)
		return -ENOMEM;

	io->ctxt = ctxt;

	migrate_bio_init(io, &io->rbio.bio, k.k->size);

	bio_set_op_attrs(&io->rbio.bio, REQ_OP_READ, 0);
	io->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(k.k);
	io->rbio.bio.bi_end_io		= read_moving_endio;

	if (bch2_bio_alloc_pages(&io->rbio.bio, GFP_KERNEL)) {
		kfree(io);
		return -ENOMEM;
	}

	migrate_bio_init(io, &io->write.op.wbio.bio, k.k->size);

	bch2_migrate_write_init(c, &io->write, devs, k, move_ptr, 0);

	trace_move_read(&io->write.key.k);

	ctxt->keys_moved++;
	ctxt->sectors_moved += k.k->size;
	if (ctxt->rate)
		bch2_ratelimit_increment(ctxt->rate, k.k->size);

	atomic_add(k.k->size, &ctxt->sectors_in_flight);
	list_add_tail(&io->list, &ctxt->reads);

	/*
	 * dropped by read_moving_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&io->ctxt->cl);
	bch2_read_extent(c, &io->rbio, k, &pick, 0);
	return 0;
}

static void do_pending_writes(struct moving_context *ctxt)
{
	struct moving_io *io;

	while ((io = next_pending_write(ctxt))) {
		list_del(&io->list);

		if (io->rbio.bio.bi_status) {
			moving_io_free(io);
			continue;
		}

		trace_move_write(&io->write.key.k);
		closure_call(&io->cl, write_moving, NULL, &ctxt->cl);
	}
}

#define move_ctxt_wait_event(_ctxt, _cond)			\
do {								\
	do_pending_writes(_ctxt);				\
								\
	if (_cond)						\
		break;						\
	__wait_event((_ctxt)->wait,				\
		     next_pending_write(_ctxt) || (_cond));	\
} while (1)

int bch2_move_ctxt_wait(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt,
			     atomic_read(&ctxt->sectors_in_flight) <
			     ctxt->max_sectors_in_flight);

	return ctxt->rate
		? bch2_ratelimit_wait_freezable_stoppable(ctxt->rate)
		: 0;
}

void bch2_move_ctxt_wait_for_io(struct moving_context *ctxt)
{
	unsigned sectors_pending = atomic_read(&ctxt->sectors_in_flight);

	move_ctxt_wait_event(ctxt,
		!atomic_read(&ctxt->sectors_in_flight) ||
		atomic_read(&ctxt->sectors_in_flight) != sectors_pending);
}

void bch2_move_ctxt_exit(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt, !atomic_read(&ctxt->sectors_in_flight));
	closure_sync(&ctxt->cl);

	EBUG_ON(!list_empty(&ctxt->reads));
	EBUG_ON(atomic_read(&ctxt->sectors_in_flight));
}

void bch2_move_ctxt_init(struct moving_context *ctxt,
			struct bch_ratelimit *rate,
			unsigned max_sectors_in_flight)
{
	memset(ctxt, 0, sizeof(*ctxt));
	closure_init_stack(&ctxt->cl);

	ctxt->rate = rate;
	ctxt->max_sectors_in_flight = max_sectors_in_flight;

	INIT_LIST_HEAD(&ctxt->reads);
	init_waitqueue_head(&ctxt->wait);
}
