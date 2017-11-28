
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
		struct bch_extent_ptr *ptr, *existing_ptr;
		struct bkey_s_extent e;
		struct bkey_i_extent *e_i;
		BKEY_PADDED(k) new;

		if (btree_iter_err(k)) {
			ret = bch2_btree_iter_unlock(&iter);
			break;
		}

		if (!bkey_extent_is_data(k.k))
			goto nomatch;

		bkey_reassemble(&new.k, k);
		bch2_cut_front(iter.pos, &new.k);
		bch2_cut_back(insert.k->p, &new.k.k);
		e = bkey_i_to_s_extent(&new.k);
		e_i = bkey_i_to_extent(&new.k);

		if (bch2_extent_matches_ptr(c, bkey_s_c_to_extent(k),
					    m->ptr, m->offset)) {
			unsigned insert_flags =
				BTREE_INSERT_ATOMIC|
				BTREE_INSERT_NOFAIL;

			/* copygc uses btree node reserve: */
			if (m->move)
				insert_flags |= BTREE_INSERT_USE_RESERVE;

			extent_for_each_ptr(insert, ptr) {
				existing_ptr = (struct bch_extent_ptr *)
					bch2_extent_has_device(e.c, ptr->dev);

				BUG_ON(existing_ptr && !m->move && !m->promote);

				if (!existing_ptr != !m->move)
					goto nomatch;

				if (existing_ptr)
					bch2_extent_drop_ptr(e, existing_ptr);
			}

			memcpy_u64s(extent_entry_last(e),
				    insert.v,
				    bkey_val_u64s(insert.k));
			e.k->u64s += bkey_val_u64s(insert.k);

			bch2_extent_narrow_crcs(e_i,
					(struct bch_extent_crc_unpacked) { 0 });
			bch2_extent_normalize(c, e.s);
			bch2_extent_mark_replicas_cached(c, e);

			ret = bch2_btree_insert_at(c, &op->res,
					NULL, op_journal_seq(op),
					insert_flags,
					BTREE_INSERT_ENTRY(&iter, &new.k));
			if (!ret)
				atomic_long_inc(&c->extent_migrate_done);
			if (ret == -EINTR)
				ret = 0;
			if (ret)
				break;
		} else {
nomatch:
			atomic_long_inc(&c->extent_migrate_raced);
			trace_move_collision(k.k->p, k.k->p.offset - iter.pos.offset);

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

void bch2_migrate_write_init(struct migrate_write *m,
			     struct bch_read_bio *rbio)
{
	/* write bio must own pages: */
	BUG_ON(!m->op.wbio.bio.bi_vcnt);

	m->ptr		= rbio->pick.ptr;
	m->offset	= rbio->pos.offset - rbio->pick.crc.offset;

	m->op.pos	= rbio->pos;
	m->op.version	= rbio->version;
	m->op.crc	= rbio->pick.crc;

	if (bch2_csum_type_is_encryption(m->op.crc.csum_type)) {
		m->op.nonce	= m->op.crc.nonce + m->op.crc.offset;
		m->op.csum_type = m->op.crc.csum_type;
	}

	if (m->move)
		m->op.alloc_reserve = RESERVE_MOVINGGC;

	m->op.flags |= BCH_WRITE_ONLY_SPECIFIED_DEVS|
		BCH_WRITE_PAGES_STABLE|
		BCH_WRITE_PAGES_OWNED|
		BCH_WRITE_DATA_ENCODED;

	m->op.wbio.bio.bi_iter.bi_size = m->op.crc.compressed_size << 9;
	m->op.nr_replicas	= 1;
	m->op.index_update_fn	= bch2_migrate_index_update;
}

static void move_free(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->ctxt;
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->write.op.wbio.bio, i)
		if (bv->bv_page)
			__free_page(bv->bv_page);

	atomic_sub(io->sectors, &ctxt->sectors_in_flight);
	wake_up(&ctxt->wait);

	kfree(io);
}

static void move_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (likely(!io->rbio.bio.bi_status)) {
		trace_move_write(io->rbio.pos, io->sectors);

		bch2_migrate_write_init(&io->write, &io->rbio);
		closure_call(&io->write.op.cl, bch2_write, NULL, cl);
	}

	closure_return_with_destructor(cl, move_free);
}

static inline struct moving_io *next_pending_write(struct moving_context *ctxt)
{
	struct moving_io *io =
		list_first_entry_or_null(&ctxt->reads, struct moving_io, list);

	return io && io->read_completed ? io : NULL;
}

static void move_read_endio(struct bio *bio)
{
	struct moving_io *io = container_of(bio, struct moving_io, rbio.bio);
	struct moving_context *ctxt = io->ctxt;

	trace_move_read_done(io->rbio.pos, io->sectors);

	io->read_completed = true;
	if (next_pending_write(ctxt))
		wake_up(&ctxt->wait);

	closure_put(&ctxt->cl);
}

int bch2_data_move(struct bch_fs *c,
		   struct moving_context *ctxt,
		   struct bch_devs_mask *devs,
		   struct write_point_specifier wp,
		   struct bkey_s_c k, bool move)
{
	struct extent_pick_ptr pick;
	struct moving_io *io;
	const struct bch_extent_ptr *ptr;
	struct bch_extent_crc_unpacked crc;
	unsigned sectors = k.k->size, pages;

	bch2_extent_pick_ptr(c, k, &ctxt->avoid, &pick);
	if (IS_ERR_OR_NULL(pick.ca))
		return pick.ca ? PTR_ERR(pick.ca) : 0;

	/* write path might have to decompress data: */
	extent_for_each_ptr_crc(bkey_s_c_to_extent(k), ptr, crc)
		sectors = max_t(unsigned, sectors, crc.uncompressed_size);

	pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);
	io = kzalloc(sizeof(struct moving_io) +
		     sizeof(struct bio_vec) * pages, GFP_KERNEL);
	if (!io)
		return -ENOMEM;

	io->ctxt	= ctxt;
	io->sectors	= k.k->size;

	bio_init(&io->write.op.wbio.bio, io->bi_inline_vecs, pages);
	bio_set_prio(&io->write.op.wbio.bio,
		     IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
	io->write.op.wbio.bio.bi_iter.bi_size = sectors << 9;

	bch2_bio_map(&io->write.op.wbio.bio, NULL);
	if (bch2_bio_alloc_pages(&io->write.op.wbio.bio, GFP_KERNEL)) {
		kfree(io);
		return -ENOMEM;
	}

	bio_init(&io->rbio.bio, io->bi_inline_vecs, pages);
	bio_set_prio(&io->rbio.bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
	io->rbio.bio.bi_iter.bi_size = sectors << 9;

	bio_set_op_attrs(&io->rbio.bio, REQ_OP_READ, 0);
	io->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(k.k);
	io->rbio.bio.bi_end_io		= move_read_endio;

	__bch2_write_op_init(&io->write.op, c);
	io->write.move		= move;
	io->write.op.devs	= devs;
	io->write.op.write_point = wp;

	ctxt->keys_moved++;
	ctxt->sectors_moved += k.k->size;
	if (ctxt->rate)
		bch2_ratelimit_increment(ctxt->rate, io->sectors);
	trace_move_read(k.k->p, k.k->size);

	atomic_add(io->sectors, &ctxt->sectors_in_flight);
	list_add_tail(&io->list, &ctxt->reads);

	/*
	 * dropped by move_read_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&io->ctxt->cl);
	bch2_read_extent(c, &io->rbio, k, &pick, BCH_READ_NODECODE);
	return 0;
}

static void do_pending_writes(struct moving_context *ctxt)
{
	struct moving_io *io;

	while ((io = next_pending_write(ctxt))) {
		list_del(&io->list);
		closure_call(&io->cl, move_write, NULL, &ctxt->cl);
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
