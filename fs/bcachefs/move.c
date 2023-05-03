// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "bkey_on_stack.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "disk_groups.h"
#include "inode.h"
#include "io.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "move.h"
#include "replicas.h"
#include "super-io.h"
#include "trace.h"

#include <linux/ioprio.h>
#include <linux/kthread.h>

#define SECTORS_IN_FLIGHT_PER_DEVICE	2048

struct moving_io {
	struct list_head	list;
	struct closure		cl;
	bool			read_completed;

	unsigned		read_sectors;
	unsigned		write_sectors;

	struct bch_read_bio	rbio;

	struct migrate_write	write;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

struct moving_context {
	/* Closure for waiting on all reads and writes to complete */
	struct closure		cl;

	struct bch_move_stats	*stats;

	struct list_head	reads;

	/* in flight sectors: */
	atomic_t		read_sectors;
	atomic_t		write_sectors;

	wait_queue_head_t	wait;
};

static int bch2_migrate_index_update(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct btree_trans trans;
	struct btree_iter *iter;
	struct migrate_write *m =
		container_of(op, struct migrate_write, op);
	struct keylist *keys = &op->insert_keys;
	int ret = 0;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	iter = bch2_trans_get_iter(&trans, m->btree_id,
				   bkey_start_pos(&bch2_keylist_front(keys)->k),
				   BTREE_ITER_SLOTS|BTREE_ITER_INTENT);

	while (1) {
		struct bkey_s_c k;
		struct bkey_i *insert;
		struct bkey_i_extent *new;
		BKEY_PADDED(k) _new, _insert;
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		bool did_work = false;
		int nr;

		bch2_trans_reset(&trans, 0);

		k = bch2_btree_iter_peek_slot(iter);
		ret = bkey_err(k);
		if (ret) {
			if (ret == -EINTR)
				continue;
			break;
		}

		new = bkey_i_to_extent(bch2_keylist_front(keys));

		if (bversion_cmp(k.k->version, new->k.version) ||
		    !bch2_bkey_matches_ptr(c, k, m->ptr, m->offset))
			goto nomatch;

		if (m->data_cmd == DATA_REWRITE &&
		    !bch2_bkey_has_device(k, m->data_opts.rewrite_dev))
			goto nomatch;

		bkey_reassemble(&_insert.k, k);
		insert = &_insert.k;

		bkey_copy(&_new.k, bch2_keylist_front(keys));
		new = bkey_i_to_extent(&_new.k);
		bch2_cut_front(iter->pos, &new->k_i);

		bch2_cut_front(iter->pos,	insert);
		bch2_cut_back(new->k.p,		insert);
		bch2_cut_back(insert->k.p,	&new->k_i);

		if (m->data_cmd == DATA_REWRITE)
			bch2_bkey_drop_device(bkey_i_to_s(insert),
					      m->data_opts.rewrite_dev);

		extent_for_each_ptr_decode(extent_i_to_s(new), p, entry) {
			if (bch2_bkey_has_device(bkey_i_to_s_c(insert), p.ptr.dev)) {
				/*
				 * raced with another move op? extent already
				 * has a pointer to the device we just wrote
				 * data to
				 */
				continue;
			}

			bch2_extent_ptr_decoded_append(insert, &p);
			did_work = true;
		}

		if (!did_work)
			goto nomatch;

		bch2_bkey_narrow_crcs(insert,
				(struct bch_extent_crc_unpacked) { 0 });
		bch2_extent_normalize(c, bkey_i_to_s(insert));
		bch2_bkey_mark_replicas_cached(c, bkey_i_to_s(insert),
					       op->opts.background_target,
					       op->opts.data_replicas);

		/*
		 * If we're not fully overwriting @k, and it's compressed, we
		 * need a reservation for all the pointers in @insert
		 */
		nr = bch2_bkey_nr_ptrs_allocated(bkey_i_to_s_c(insert)) -
			 m->nr_ptrs_reserved;

		if (insert->k.size < k.k->size &&
		    bch2_bkey_sectors_compressed(k) &&
		    nr > 0) {
			ret = bch2_disk_reservation_add(c, &op->res,
					keylist_sectors(keys) * nr, 0);
			if (ret)
				goto out;

			m->nr_ptrs_reserved += nr;
			goto next;
		}

		bch2_trans_update(&trans, iter, insert, 0);

		ret = bch2_trans_commit(&trans, &op->res,
				op_journal_seq(op),
				BTREE_INSERT_NOFAIL|
				BTREE_INSERT_USE_RESERVE|
				m->data_opts.btree_insert_flags);
		if (!ret)
			atomic_long_inc(&c->extent_migrate_done);
		if (ret == -EINTR)
			ret = 0;
		if (ret)
			break;
next:
		while (bkey_cmp(iter->pos, bch2_keylist_front(keys)->k.p) >= 0) {
			bch2_keylist_pop_front(keys);
			if (bch2_keylist_empty(keys))
				goto out;
		}
		continue;
nomatch:
		if (m->ctxt) {
			BUG_ON(k.k->p.offset <= iter->pos.offset);
			atomic64_inc(&m->ctxt->stats->keys_raced);
			atomic64_add(k.k->p.offset - iter->pos.offset,
				     &m->ctxt->stats->sectors_raced);
		}
		atomic_long_inc(&c->extent_migrate_raced);
		trace_move_race(&new->k);
		bch2_btree_iter_next_slot(iter);
		goto next;
	}
out:
	bch2_trans_exit(&trans);
	BUG_ON(ret == -EINTR);
	return ret;
}

void bch2_migrate_read_done(struct migrate_write *m, struct bch_read_bio *rbio)
{
	/* write bio must own pages: */
	BUG_ON(!m->op.wbio.bio.bi_vcnt);

	m->ptr		= rbio->pick.ptr;
	m->offset	= rbio->pos.offset - rbio->pick.crc.offset;
	m->op.devs_have	= rbio->devs_have;
	m->op.pos	= rbio->pos;
	m->op.version	= rbio->version;
	m->op.crc	= rbio->pick.crc;
	m->op.wbio.bio.bi_iter.bi_size = m->op.crc.compressed_size << 9;

	if (bch2_csum_type_is_encryption(m->op.crc.csum_type)) {
		m->op.nonce	= m->op.crc.nonce + m->op.crc.offset;
		m->op.csum_type = m->op.crc.csum_type;
	}

	if (m->data_cmd == DATA_REWRITE)
		bch2_dev_list_drop_dev(&m->op.devs_have, m->data_opts.rewrite_dev);
}

int bch2_migrate_write_init(struct bch_fs *c, struct migrate_write *m,
			    struct write_point_specifier wp,
			    struct bch_io_opts io_opts,
			    enum data_cmd data_cmd,
			    struct data_opts data_opts,
			    enum btree_id btree_id,
			    struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	int ret;

	m->btree_id	= btree_id;
	m->data_cmd	= data_cmd;
	m->data_opts	= data_opts;
	m->nr_ptrs_reserved = 0;

	bch2_write_op_init(&m->op, c, io_opts);

	if (!bch2_bkey_is_incompressible(k))
		m->op.compression_type =
			bch2_compression_opt_to_type[io_opts.background_compression ?:
						     io_opts.compression];
	else
		m->op.incompressible = true;

	m->op.target	= data_opts.target,
	m->op.write_point = wp;

	if (m->data_opts.btree_insert_flags & BTREE_INSERT_USE_RESERVE)
		m->op.alloc_reserve = RESERVE_MOVINGGC;

	m->op.flags |= BCH_WRITE_ONLY_SPECIFIED_DEVS|
		BCH_WRITE_PAGES_STABLE|
		BCH_WRITE_PAGES_OWNED|
		BCH_WRITE_DATA_ENCODED|
		BCH_WRITE_FROM_INTERNAL;

	m->op.nr_replicas	= 1;
	m->op.nr_replicas_required = 1;
	m->op.index_update_fn	= bch2_migrate_index_update;

	switch (data_cmd) {
	case DATA_ADD_REPLICAS: {
		/*
		 * DATA_ADD_REPLICAS is used for moving data to a different
		 * device in the background, and due to compression the new copy
		 * might take up more space than the old copy:
		 */
#if 0
		int nr = (int) io_opts.data_replicas -
			bch2_bkey_nr_ptrs_allocated(k);
#endif
		int nr = (int) io_opts.data_replicas;

		if (nr > 0) {
			m->op.nr_replicas = m->nr_ptrs_reserved = nr;

			ret = bch2_disk_reservation_get(c, &m->op.res,
					k.k->size, m->op.nr_replicas, 0);
			if (ret)
				return ret;
		}
		break;
	}
	case DATA_REWRITE: {
		unsigned compressed_sectors = 0;

		bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
			if (!p.ptr.cached &&
			    crc_is_compressed(p.crc) &&
			    bch2_dev_in_target(c, p.ptr.dev, data_opts.target))
				compressed_sectors += p.crc.compressed_size;

		if (compressed_sectors) {
			ret = bch2_disk_reservation_add(c, &m->op.res,
					compressed_sectors,
					BCH_DISK_RESERVATION_NOFAIL);
			if (ret)
				return ret;
		}
		break;
	}
	case DATA_PROMOTE:
		m->op.flags	|= BCH_WRITE_ALLOC_NOWAIT;
		m->op.flags	|= BCH_WRITE_CACHED;
		break;
	default:
		BUG();
	}

	return 0;
}

static void move_free(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->write.ctxt;
	struct bvec_iter_all iter;
	struct bio_vec bv;

	bch2_disk_reservation_put(io->write.op.c, &io->write.op.res);

	bio_for_each_segment_all(bv, &io->write.op.wbio.bio, iter)
		if (bv.bv_page)
			__free_page(bv.bv_page);

	wake_up(&ctxt->wait);

	kfree(io);
}

static void move_write_done(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	atomic_sub(io->write_sectors, &io->write.ctxt->write_sectors);
	closure_return_with_destructor(cl, move_free);
}

static void move_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (unlikely(io->rbio.bio.bi_status || io->rbio.hole)) {
		closure_return_with_destructor(cl, move_free);
		return;
	}

	bch2_migrate_read_done(&io->write, &io->rbio);

	atomic_add(io->write_sectors, &io->write.ctxt->write_sectors);
	closure_call(&io->write.op.cl, bch2_write, NULL, cl);
	continue_at(cl, move_write_done, NULL);
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
	struct moving_context *ctxt = io->write.ctxt;

	atomic_sub(io->read_sectors, &ctxt->read_sectors);
	io->read_completed = true;

	if (next_pending_write(ctxt))
		wake_up(&ctxt->wait);

	closure_put(&ctxt->cl);
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

static void bch2_move_ctxt_wait_for_io(struct moving_context *ctxt)
{
	unsigned sectors_pending = atomic_read(&ctxt->write_sectors);

	move_ctxt_wait_event(ctxt,
		!atomic_read(&ctxt->write_sectors) ||
		atomic_read(&ctxt->write_sectors) != sectors_pending);
}

static int bch2_move_extent(struct bch_fs *c,
			    struct moving_context *ctxt,
			    struct write_point_specifier wp,
			    struct bch_io_opts io_opts,
			    enum btree_id btree_id,
			    struct bkey_s_c k,
			    enum data_cmd data_cmd,
			    struct data_opts data_opts)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct moving_io *io;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned sectors = k.k->size, pages;
	int ret = -ENOMEM;

	move_ctxt_wait_event(ctxt,
		atomic_read(&ctxt->write_sectors) <
		SECTORS_IN_FLIGHT_PER_DEVICE);

	move_ctxt_wait_event(ctxt,
		atomic_read(&ctxt->read_sectors) <
		SECTORS_IN_FLIGHT_PER_DEVICE);

	/* write path might have to decompress data: */
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
		sectors = max_t(unsigned, sectors, p.crc.uncompressed_size);

	pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);
	io = kzalloc(sizeof(struct moving_io) +
		     sizeof(struct bio_vec) * pages, GFP_KERNEL);
	if (!io)
		goto err;

	io->write.ctxt		= ctxt;
	io->read_sectors	= k.k->size;
	io->write_sectors	= k.k->size;

	bio_init(&io->write.op.wbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	bio_set_prio(&io->write.op.wbio.bio,
		     IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	if (bch2_bio_alloc_pages(&io->write.op.wbio.bio, sectors << 9,
				 GFP_KERNEL))
		goto err_free;

	io->rbio.c		= c;
	io->rbio.opts		= io_opts;
	bio_init(&io->rbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	io->rbio.bio.bi_vcnt = pages;
	bio_set_prio(&io->rbio.bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
	io->rbio.bio.bi_iter.bi_size = sectors << 9;

	io->rbio.bio.bi_opf		= REQ_OP_READ;
	io->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(k.k);
	io->rbio.bio.bi_end_io		= move_read_endio;

	ret = bch2_migrate_write_init(c, &io->write, wp, io_opts,
				      data_cmd, data_opts, btree_id, k);
	if (ret)
		goto err_free_pages;

	atomic64_inc(&ctxt->stats->keys_moved);
	atomic64_add(k.k->size, &ctxt->stats->sectors_moved);

	trace_move_extent(k.k);

	atomic_add(io->read_sectors, &ctxt->read_sectors);
	list_add_tail(&io->list, &ctxt->reads);

	/*
	 * dropped by move_read_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&ctxt->cl);
	bch2_read_extent(c, &io->rbio, k, 0,
			 BCH_READ_NODECODE|
			 BCH_READ_LAST_FRAGMENT);
	return 0;
err_free_pages:
	bio_free_pages(&io->write.op.wbio.bio);
err_free:
	kfree(io);
err:
	trace_move_alloc_fail(k.k);
	return ret;
}

static int __bch2_move_data(struct bch_fs *c,
		struct moving_context *ctxt,
		struct bch_ratelimit *rate,
		struct write_point_specifier wp,
		struct bpos start,
		struct bpos end,
		move_pred_fn pred, void *arg,
		struct bch_move_stats *stats,
		enum btree_id btree_id)
{
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	struct bkey_on_stack sk;
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct data_opts data_opts;
	enum data_cmd data_cmd;
	u64 delay, cur_inum = U64_MAX;
	int ret = 0, ret2;

	bkey_on_stack_init(&sk);
	bch2_trans_init(&trans, c, 0, 0);

	stats->data_type = BCH_DATA_user;
	stats->btree_id	= btree_id;
	stats->pos	= POS_MIN;

	iter = bch2_trans_get_iter(&trans, btree_id, start,
				   BTREE_ITER_PREFETCH);

	if (rate)
		bch2_ratelimit_reset(rate);

	while (1) {
		do {
			delay = rate ? bch2_ratelimit_delay(rate) : 0;

			if (delay) {
				bch2_trans_unlock(&trans);
				set_current_state(TASK_INTERRUPTIBLE);
			}

			if (kthread && (ret = kthread_should_stop())) {
				__set_current_state(TASK_RUNNING);
				goto out;
			}

			if (delay)
				schedule_timeout(delay);

			if (unlikely(freezing(current))) {
				bch2_trans_unlock(&trans);
				move_ctxt_wait_event(ctxt, list_empty(&ctxt->reads));
				try_to_freeze();
			}
		} while (delay);
peek:
		k = bch2_btree_iter_peek(iter);

		stats->pos = iter->pos;

		if (!k.k)
			break;
		ret = bkey_err(k);
		if (ret)
			break;
		if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
			break;

		if (!bkey_extent_is_direct_data(k.k))
			goto next_nondata;

		if (btree_id == BTREE_ID_EXTENTS &&
		    cur_inum != k.k->p.inode) {
			struct bch_inode_unpacked inode;

			/* don't hold btree locks while looking up inode: */
			bch2_trans_unlock(&trans);

			io_opts = bch2_opts_to_inode_opts(c->opts);
			if (!bch2_inode_find_by_inum(c, k.k->p.inode, &inode))
				bch2_io_opts_apply(&io_opts, bch2_inode_opts_get(&inode));
			cur_inum = k.k->p.inode;
			goto peek;
		}

		switch ((data_cmd = pred(c, arg, k, &io_opts, &data_opts))) {
		case DATA_SKIP:
			goto next;
		case DATA_SCRUB:
			BUG();
		case DATA_ADD_REPLICAS:
		case DATA_REWRITE:
		case DATA_PROMOTE:
			break;
		default:
			BUG();
		}

		/* unlock before doing IO: */
		bkey_on_stack_reassemble(&sk, c, k);
		k = bkey_i_to_s_c(sk.k);
		bch2_trans_unlock(&trans);

		ret2 = bch2_move_extent(c, ctxt, wp, io_opts, btree_id, k,
					data_cmd, data_opts);
		if (ret2) {
			if (ret2 == -ENOMEM) {
				/* memory allocation failure, wait for some IO to finish */
				bch2_move_ctxt_wait_for_io(ctxt);
				continue;
			}

			/* XXX signal failure */
			goto next;
		}

		if (rate)
			bch2_ratelimit_increment(rate, k.k->size);
next:
		atomic64_add(k.k->size * bch2_bkey_nr_ptrs_allocated(k),
			     &stats->sectors_seen);
next_nondata:
		bch2_btree_iter_next(iter);
		bch2_trans_cond_resched(&trans);
	}
out:
	ret = bch2_trans_exit(&trans) ?: ret;
	bkey_on_stack_exit(&sk, c);

	return ret;
}

int bch2_move_data(struct bch_fs *c,
		   struct bch_ratelimit *rate,
		   struct write_point_specifier wp,
		   struct bpos start,
		   struct bpos end,
		   move_pred_fn pred, void *arg,
		   struct bch_move_stats *stats)
{
	struct moving_context ctxt = { .stats = stats };
	int ret;

	closure_init_stack(&ctxt.cl);
	INIT_LIST_HEAD(&ctxt.reads);
	init_waitqueue_head(&ctxt.wait);

	stats->data_type = BCH_DATA_user;

	ret =   __bch2_move_data(c, &ctxt, rate, wp, start, end,
				 pred, arg, stats, BTREE_ID_EXTENTS) ?:
		__bch2_move_data(c, &ctxt, rate, wp, start, end,
				 pred, arg, stats, BTREE_ID_REFLINK);

	move_ctxt_wait_event(&ctxt, list_empty(&ctxt.reads));
	closure_sync(&ctxt.cl);

	EBUG_ON(atomic_read(&ctxt.write_sectors));

	trace_move_data(c,
			atomic64_read(&stats->sectors_moved),
			atomic64_read(&stats->keys_moved));

	return ret;
}

static int bch2_move_btree(struct bch_fs *c,
			   move_pred_fn pred,
			   void *arg,
			   struct bch_move_stats *stats)
{
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	struct btree_trans trans;
	struct btree_iter *iter;
	struct btree *b;
	unsigned id;
	struct data_opts data_opts;
	enum data_cmd cmd;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);

	stats->data_type = BCH_DATA_btree;

	for (id = 0; id < BTREE_ID_NR; id++) {
		stats->btree_id = id;

		for_each_btree_node(&trans, iter, id, POS_MIN,
				    BTREE_ITER_PREFETCH, b) {
			stats->pos = iter->pos;

			switch ((cmd = pred(c, arg,
					    bkey_i_to_s_c(&b->key),
					    &io_opts, &data_opts))) {
			case DATA_SKIP:
				goto next;
			case DATA_SCRUB:
				BUG();
			case DATA_ADD_REPLICAS:
			case DATA_REWRITE:
				break;
			default:
				BUG();
			}

			ret = bch2_btree_node_rewrite(c, iter,
					b->data->keys.seq, 0) ?: ret;
next:
			bch2_trans_cond_resched(&trans);
		}

		ret = bch2_trans_iter_free(&trans, iter) ?: ret;
	}

	bch2_trans_exit(&trans);

	return ret;
}

#if 0
static enum data_cmd scrub_pred(struct bch_fs *c, void *arg,
				struct bkey_s_c k,
				struct bch_io_opts *io_opts,
				struct data_opts *data_opts)
{
	return DATA_SCRUB;
}
#endif

static enum data_cmd rereplicate_pred(struct bch_fs *c, void *arg,
				      struct bkey_s_c k,
				      struct bch_io_opts *io_opts,
				      struct data_opts *data_opts)
{
	unsigned nr_good = bch2_bkey_durability(c, k);
	unsigned replicas = 0;

	switch (k.k->type) {
	case KEY_TYPE_btree_ptr:
		replicas = c->opts.metadata_replicas;
		break;
	case KEY_TYPE_extent:
		replicas = io_opts->data_replicas;
		break;
	}

	if (!nr_good || nr_good >= replicas)
		return DATA_SKIP;

	data_opts->target		= 0;
	data_opts->btree_insert_flags	= 0;
	return DATA_ADD_REPLICAS;
}

static enum data_cmd migrate_pred(struct bch_fs *c, void *arg,
				  struct bkey_s_c k,
				  struct bch_io_opts *io_opts,
				  struct data_opts *data_opts)
{
	struct bch_ioctl_data *op = arg;

	if (!bch2_bkey_has_device(k, op->migrate.dev))
		return DATA_SKIP;

	data_opts->target		= 0;
	data_opts->btree_insert_flags	= 0;
	data_opts->rewrite_dev		= op->migrate.dev;
	return DATA_REWRITE;
}

int bch2_data_job(struct bch_fs *c,
		  struct bch_move_stats *stats,
		  struct bch_ioctl_data op)
{
	int ret = 0;

	switch (op.op) {
	case BCH_DATA_OP_REREPLICATE:
		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, -1);

		ret = bch2_move_btree(c, rereplicate_pred, c, stats) ?: ret;

		closure_wait_event(&c->btree_interior_update_wait,
				   !bch2_btree_interior_updates_nr_pending(c));

		ret = bch2_replicas_gc2(c) ?: ret;

		ret = bch2_move_data(c, NULL,
				     writepoint_hashed((unsigned long) current),
				     op.start,
				     op.end,
				     rereplicate_pred, c, stats) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;
		break;
	case BCH_DATA_OP_MIGRATE:
		if (op.migrate.dev >= c->sb.nr_devices)
			return -EINVAL;

		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, op.migrate.dev);

		ret = bch2_move_btree(c, migrate_pred, &op, stats) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;

		ret = bch2_move_data(c, NULL,
				     writepoint_hashed((unsigned long) current),
				     op.start,
				     op.end,
				     migrate_pred, &op, stats) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
