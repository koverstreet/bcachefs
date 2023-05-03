// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
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
	struct migrate_write *m =
		container_of(op, struct migrate_write, op);
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret = 0;

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS,
			     bkey_start_pos(&bch2_keylist_front(keys)->k),
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);

	while (1) {
		struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
		struct bkey_i_extent *insert, *new =
			bkey_i_to_extent(bch2_keylist_front(keys));
		BKEY_PADDED(k) _new, _insert;
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		bool did_work = false;
		int nr;

		if (btree_iter_err(k)) {
			ret = bch2_btree_iter_unlock(&iter);
			break;
		}

		if (bversion_cmp(k.k->version, new->k.version) ||
		    !bkey_extent_is_data(k.k) ||
		    !bch2_extent_matches_ptr(c, bkey_s_c_to_extent(k),
					     m->ptr, m->offset))
			goto nomatch;

		if (m->data_cmd == DATA_REWRITE &&
		    !bch2_extent_has_device(bkey_s_c_to_extent(k),
					    m->data_opts.rewrite_dev))
			goto nomatch;

		bkey_reassemble(&_insert.k, k);
		insert = bkey_i_to_extent(&_insert.k);

		bkey_copy(&_new.k, bch2_keylist_front(keys));
		new = bkey_i_to_extent(&_new.k);

		bch2_cut_front(iter.pos, &insert->k_i);
		bch2_cut_back(new->k.p, &insert->k);
		bch2_cut_back(insert->k.p, &new->k);

		if (m->data_cmd == DATA_REWRITE)
			bch2_extent_drop_device(extent_i_to_s(insert),
						m->data_opts.rewrite_dev);

		extent_for_each_ptr_decode(extent_i_to_s(new), p, entry) {
			if (bch2_extent_has_device(extent_i_to_s_c(insert), p.ptr.dev)) {
				/*
				 * raced with another move op? extent already
				 * has a pointer to the device we just wrote
				 * data to
				 */
				continue;
			}

			bch2_extent_crc_append(insert, p.crc);
			extent_ptr_append(insert, p.ptr);
			did_work = true;
		}

		if (!did_work)
			goto nomatch;

		bch2_extent_narrow_crcs(insert,
				(struct bch_extent_crc_unpacked) { 0 });
		bch2_extent_normalize(c, extent_i_to_s(insert).s);
		bch2_extent_mark_replicas_cached(c, extent_i_to_s(insert),
						 op->opts.background_target,
						 op->opts.data_replicas);

		/*
		 * It's possible we race, and for whatever reason the extent now
		 * has fewer replicas than when we last looked at it - meaning
		 * we need to get a disk reservation here:
		 */
		nr = bch2_extent_nr_dirty_ptrs(bkey_i_to_s_c(&insert->k_i)) -
			(bch2_extent_nr_dirty_ptrs(k) + m->nr_ptrs_reserved);
		if (nr > 0) {
			/*
			 * can't call bch2_disk_reservation_add() with btree
			 * locks held, at least not without a song and dance
			 */
			bch2_btree_iter_unlock(&iter);

			ret = bch2_disk_reservation_add(c, &op->res,
					keylist_sectors(keys) * nr, 0);
			if (ret)
				goto out;

			m->nr_ptrs_reserved += nr;
			goto next;
		}

		ret = bch2_mark_bkey_replicas(c, BCH_DATA_USER,
					      extent_i_to_s_c(insert).s_c);
		if (ret)
			break;

		ret = bch2_btree_insert_at(c, &op->res,
				op_journal_seq(op),
				BTREE_INSERT_ATOMIC|
				BTREE_INSERT_NOFAIL|
				BTREE_INSERT_USE_RESERVE|
				m->data_opts.btree_insert_flags,
				BTREE_INSERT_ENTRY(&iter, &insert->k_i));
		if (!ret)
			atomic_long_inc(&c->extent_migrate_done);
		if (ret == -EINTR)
			ret = 0;
		if (ret)
			break;
next:
		while (bkey_cmp(iter.pos, bch2_keylist_front(keys)->k.p) >= 0) {
			bch2_keylist_pop_front(keys);
			if (bch2_keylist_empty(keys))
				goto out;
		}

		bch2_cut_front(iter.pos, bch2_keylist_front(keys));
		continue;
nomatch:
		if (m->ctxt)
			atomic64_add(k.k->p.offset - iter.pos.offset,
				     &m->ctxt->stats->sectors_raced);
		atomic_long_inc(&c->extent_migrate_raced);
		trace_move_race(&new->k);
		bch2_btree_iter_next_slot(&iter);
		goto next;
	}
out:
	bch2_btree_iter_unlock(&iter);
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
			    struct bkey_s_c k)
{
	int ret;

	m->data_cmd	= data_cmd;
	m->data_opts	= data_opts;
	m->nr_ptrs_reserved = 0;

	bch2_write_op_init(&m->op, c, io_opts);
	m->op.compression_type =
		bch2_compression_opt_to_type[io_opts.background_compression ?:
					     io_opts.compression];
	m->op.target	= data_opts.target,
	m->op.write_point = wp;

	if (m->data_opts.btree_insert_flags & BTREE_INSERT_USE_RESERVE)
		m->op.alloc_reserve = RESERVE_MOVINGGC;

	m->op.flags |= BCH_WRITE_ONLY_SPECIFIED_DEVS|
		BCH_WRITE_PAGES_STABLE|
		BCH_WRITE_PAGES_OWNED|
		BCH_WRITE_DATA_ENCODED|
		BCH_WRITE_NOMARK_REPLICAS;

	m->op.nr_replicas	= 1;
	m->op.nr_replicas_required = 1;
	m->op.index_update_fn	= bch2_migrate_index_update;

	switch (data_cmd) {
	case DATA_ADD_REPLICAS: {
		int nr = (int) io_opts.data_replicas -
			bch2_extent_nr_dirty_ptrs(k);

		if (nr > 0) {
			m->op.nr_replicas = m->nr_ptrs_reserved = nr;

			ret = bch2_disk_reservation_get(c, &m->op.res,
					k.k->size, m->op.nr_replicas, 0);
			if (ret)
				return ret;
		}
		break;
	}
	case DATA_REWRITE:
		break;
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
			    struct bkey_s_c_extent e,
			    enum data_cmd data_cmd,
			    struct data_opts data_opts)
{
	struct moving_io *io;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned sectors = e.k->size, pages;
	int ret = -ENOMEM;

	move_ctxt_wait_event(ctxt,
		atomic_read(&ctxt->write_sectors) <
		SECTORS_IN_FLIGHT_PER_DEVICE);

	move_ctxt_wait_event(ctxt,
		atomic_read(&ctxt->read_sectors) <
		SECTORS_IN_FLIGHT_PER_DEVICE);

	/* write path might have to decompress data: */
	extent_for_each_ptr_decode(e, p, entry)
		sectors = max_t(unsigned, sectors, p.crc.uncompressed_size);

	pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);
	io = kzalloc(sizeof(struct moving_io) +
		     sizeof(struct bio_vec) * pages, GFP_KERNEL);
	if (!io)
		goto err;

	io->write.ctxt		= ctxt;
	io->read_sectors	= e.k->size;
	io->write_sectors	= e.k->size;

	bio_init(&io->write.op.wbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	bio_set_prio(&io->write.op.wbio.bio,
		     IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	if (bch2_bio_alloc_pages(&io->write.op.wbio.bio, sectors << 9,
				 GFP_KERNEL))
		goto err_free;

	io->rbio.opts = io_opts;
	bio_init(&io->rbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	io->rbio.bio.bi_vcnt = pages;
	bio_set_prio(&io->rbio.bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
	io->rbio.bio.bi_iter.bi_size = sectors << 9;

	io->rbio.bio.bi_opf		= REQ_OP_READ;
	io->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(e.k);
	io->rbio.bio.bi_end_io		= move_read_endio;

	ret = bch2_migrate_write_init(c, &io->write, wp, io_opts,
				      data_cmd, data_opts, e.s_c);
	if (ret)
		goto err_free_pages;

	atomic64_inc(&ctxt->stats->keys_moved);
	atomic64_add(e.k->size, &ctxt->stats->sectors_moved);

	trace_move_extent(e.k);

	atomic_add(io->read_sectors, &ctxt->read_sectors);
	list_add_tail(&io->list, &ctxt->reads);

	/*
	 * dropped by move_read_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&ctxt->cl);
	bch2_read_extent(c, &io->rbio, e.s_c,
			 BCH_READ_NODECODE|
			 BCH_READ_LAST_FRAGMENT);
	return 0;
err_free_pages:
	bio_free_pages(&io->write.op.wbio.bio);
err_free:
	kfree(io);
err:
	trace_move_alloc_fail(e.k);
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
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	struct moving_context ctxt = { .stats = stats };
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	BKEY_PADDED(k) tmp;
	struct bkey_s_c k;
	struct bkey_s_c_extent e;
	struct data_opts data_opts;
	enum data_cmd data_cmd;
	u64 delay, cur_inum = U64_MAX;
	int ret = 0, ret2;

	closure_init_stack(&ctxt.cl);
	INIT_LIST_HEAD(&ctxt.reads);
	init_waitqueue_head(&ctxt.wait);

	stats->data_type = BCH_DATA_USER;
	bch2_btree_iter_init(&stats->iter, c, BTREE_ID_EXTENTS, start,
			     BTREE_ITER_PREFETCH);

	if (rate)
		bch2_ratelimit_reset(rate);

	while (1) {
		do {
			delay = rate ? bch2_ratelimit_delay(rate) : 0;

			if (delay) {
				bch2_btree_iter_unlock(&stats->iter);
				set_current_state(TASK_INTERRUPTIBLE);
			}

			if (kthread && (ret = kthread_should_stop())) {
				__set_current_state(TASK_RUNNING);
				goto out;
			}

			if (delay)
				schedule_timeout(delay);

			if (unlikely(freezing(current))) {
				bch2_btree_iter_unlock(&stats->iter);
				move_ctxt_wait_event(&ctxt, list_empty(&ctxt.reads));
				try_to_freeze();
			}
		} while (delay);
peek:
		k = bch2_btree_iter_peek(&stats->iter);
		if (!k.k)
			break;
		ret = btree_iter_err(k);
		if (ret)
			break;
		if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
			break;

		if (!bkey_extent_is_data(k.k))
			goto next_nondata;

		e = bkey_s_c_to_extent(k);

		if (cur_inum != k.k->p.inode) {
			struct bch_inode_unpacked inode;

			/* don't hold btree locks while looking up inode: */
			bch2_btree_iter_unlock(&stats->iter);

			io_opts = bch2_opts_to_inode_opts(c->opts);
			if (!bch2_inode_find_by_inum(c, k.k->p.inode, &inode))
				bch2_io_opts_apply(&io_opts, bch2_inode_opts_get(&inode));
			cur_inum = k.k->p.inode;
			goto peek;
		}

		switch ((data_cmd = pred(c, arg, BKEY_TYPE_EXTENTS, e,
					 &io_opts, &data_opts))) {
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
		bkey_reassemble(&tmp.k, k);
		k = bkey_i_to_s_c(&tmp.k);
		bch2_btree_iter_unlock(&stats->iter);

		ret2 = bch2_move_extent(c, &ctxt, wp, io_opts,
					bkey_s_c_to_extent(k),
					data_cmd, data_opts);
		if (ret2) {
			if (ret2 == -ENOMEM) {
				/* memory allocation failure, wait for some IO to finish */
				bch2_move_ctxt_wait_for_io(&ctxt);
				continue;
			}

			/* XXX signal failure */
			goto next;
		}

		if (rate)
			bch2_ratelimit_increment(rate, k.k->size);
next:
		atomic64_add(k.k->size * bch2_extent_nr_dirty_ptrs(k),
			     &stats->sectors_seen);
next_nondata:
		bch2_btree_iter_next(&stats->iter);
		bch2_btree_iter_cond_resched(&stats->iter);
	}
out:
	bch2_btree_iter_unlock(&stats->iter);

	move_ctxt_wait_event(&ctxt, list_empty(&ctxt.reads));
	closure_sync(&ctxt.cl);

	EBUG_ON(atomic_read(&ctxt.write_sectors));

	trace_move_data(c,
			atomic64_read(&stats->sectors_moved),
			atomic64_read(&stats->keys_moved));

	return ret;
}

static int bch2_gc_data_replicas(struct bch_fs *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, (1 << BCH_DATA_USER)|(1 << BCH_DATA_CACHED));

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			   BTREE_ITER_PREFETCH, k) {
		ret = bch2_mark_bkey_replicas(c, BCH_DATA_USER, k);
		if (ret)
			break;
	}
	ret = bch2_btree_iter_unlock(&iter) ?: ret;

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);

	return ret;
}

static int bch2_gc_btree_replicas(struct bch_fs *c)
{
	struct btree_iter iter;
	struct btree *b;
	unsigned id;
	int ret = 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_BTREE);

	for (id = 0; id < BTREE_ID_NR; id++) {
		for_each_btree_node(&iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
			ret = bch2_mark_bkey_replicas(c, BCH_DATA_BTREE,
						      bkey_i_to_s_c(&b->key));

			bch2_btree_iter_cond_resched(&iter);
		}

		ret = bch2_btree_iter_unlock(&iter) ?: ret;
	}

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);

	return ret;
}

static int bch2_move_btree(struct bch_fs *c,
			   move_pred_fn pred,
			   void *arg,
			   struct bch_move_stats *stats)
{
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	struct btree *b;
	unsigned id;
	struct data_opts data_opts;
	enum data_cmd cmd;
	int ret = 0;

	stats->data_type = BCH_DATA_BTREE;

	for (id = 0; id < BTREE_ID_NR; id++) {
		for_each_btree_node(&stats->iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
			switch ((cmd = pred(c, arg, BKEY_TYPE_BTREE,
					    bkey_i_to_s_c_extent(&b->key),
					    &io_opts,
					    &data_opts))) {
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

			ret = bch2_btree_node_rewrite(c, &stats->iter,
					b->data->keys.seq, 0) ?: ret;
next:
			bch2_btree_iter_cond_resched(&stats->iter);
		}

		ret = bch2_btree_iter_unlock(&stats->iter) ?: ret;
	}

	return ret;
}

#if 0
static enum data_cmd scrub_pred(struct bch_fs *c, void *arg,
				enum bkey_type type,
				struct bkey_s_c_extent e,
				struct bch_io_opts *io_opts,
				struct data_opts *data_opts)
{
	return DATA_SCRUB;
}
#endif

static enum data_cmd rereplicate_pred(struct bch_fs *c, void *arg,
				      enum bkey_type type,
				      struct bkey_s_c_extent e,
				      struct bch_io_opts *io_opts,
				      struct data_opts *data_opts)
{
	unsigned nr_good = bch2_extent_durability(c, e);
	unsigned replicas = type == BKEY_TYPE_BTREE
		? c->opts.metadata_replicas
		: io_opts->data_replicas;

	if (!nr_good || nr_good >= replicas)
		return DATA_SKIP;

	data_opts->target		= 0;
	data_opts->btree_insert_flags = 0;
	return DATA_ADD_REPLICAS;
}

static enum data_cmd migrate_pred(struct bch_fs *c, void *arg,
				  enum bkey_type type,
				  struct bkey_s_c_extent e,
				  struct bch_io_opts *io_opts,
				  struct data_opts *data_opts)
{
	struct bch_ioctl_data *op = arg;

	if (!bch2_extent_has_device(e, op->migrate.dev))
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
		stats->data_type = BCH_DATA_JOURNAL;
		ret = bch2_journal_flush_device_pins(&c->journal, -1);

		ret = bch2_move_btree(c, rereplicate_pred, c, stats) ?: ret;
		ret = bch2_gc_btree_replicas(c) ?: ret;

		ret = bch2_move_data(c, NULL,
				     writepoint_hashed((unsigned long) current),
				     op.start,
				     op.end,
				     rereplicate_pred, c, stats) ?: ret;
		ret = bch2_gc_data_replicas(c) ?: ret;
		break;
	case BCH_DATA_OP_MIGRATE:
		if (op.migrate.dev >= c->sb.nr_devices)
			return -EINVAL;

		stats->data_type = BCH_DATA_JOURNAL;
		ret = bch2_journal_flush_device_pins(&c->journal, op.migrate.dev);

		ret = bch2_move_btree(c, migrate_pred, &op, stats) ?: ret;
		ret = bch2_gc_btree_replicas(c) ?: ret;

		ret = bch2_move_data(c, NULL,
				     writepoint_hashed((unsigned long) current),
				     op.start,
				     op.end,
				     migrate_pred, &op, stats) ?: ret;
		ret = bch2_gc_data_replicas(c) ?: ret;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
