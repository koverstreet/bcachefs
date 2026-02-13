// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/backpointers.h"
#include "alloc/replicas.h"

#include "btree/bkey_buf.h"
#include "btree/check.h"
#include "btree/interior.h"
#include "btree/read.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/compress.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/read.h"
#include "data/reconcile/trigger.h"
#include "data/reflink.h"
#include "data/write.h"

#include "fs/inode.h"

#include "init/error.h"

#include "journal/reclaim.h"

#include "sb/counters.h"
#include "sb/io.h"

#include "snapshots/snapshot.h"

#include <linux/ioprio.h>
#include <linux/kthread.h>

const char * const bch2_data_ops_strs[] = {
#define x(t, n, ...) [n] = #t,
	BCH_DATA_OPS()
#undef x
	NULL
};

struct evacuate_bucket_arg {
	struct bpos		bucket;
	int			gen;
	struct data_update_opts	data_opts;
};

static int evacuate_bucket_pred(struct btree_trans *, void *,
				enum btree_id, struct bkey_s_c,
				struct bch_inode_opts *,
				struct data_update_opts *);

static void move_write_done(struct bch_write_op *op)
{
	struct data_update *u = container_of(op, struct data_update, op);
	struct moving_context *ctxt = u->ctxt;

	atomic_sub(u->k.k->k.size, &ctxt->write_sectors);
	atomic_dec(&ctxt->write_ios);

	bch2_data_update_exit(u, op->error);
	kfree_rcu(u, rcu);
	closure_put(&ctxt->cl);
}

static void move_write(struct data_update *u)
{
	struct moving_context *ctxt = u->ctxt;
	struct bch_read_bio *rbio = &u->rbio;

	if (ctxt->stats) {
		if (rbio->ret)
			atomic64_add(u->rbio.bvec_iter.bi_size >> 9,
				     &ctxt->stats->sectors_error_uncorrected);
		else if (rbio->saw_error)
			atomic64_add(u->rbio.bvec_iter.bi_size >> 9,
				     &ctxt->stats->sectors_error_corrected);
	}

	closure_get(&ctxt->cl);
	atomic_add(u->k.k->k.size, &ctxt->write_sectors);
	atomic_inc(&ctxt->write_ios);

	bch2_data_update_read_done(u);
}

struct data_update *bch2_moving_ctxt_next_pending_write(struct moving_context *ctxt)
{
	struct data_update *u =
		list_first_entry_or_null(&ctxt->reads, struct data_update, read_list);

	return u && u->read_done ? u : NULL;
}

static void move_read_endio(struct bio *bio)
{
	struct data_update *u = container_of(bio, struct data_update, rbio.bio);
	struct moving_context *ctxt = u->ctxt;

	atomic_sub(u->k.k->k.size, &ctxt->read_sectors);
	atomic_dec(&ctxt->read_ios);
	u->read_done = true;

	wake_up(&ctxt->wait);
	closure_put(&ctxt->cl);
}

void bch2_moving_ctxt_do_pending_writes(struct moving_context *ctxt)
{
	struct data_update *u;

	while ((u = bch2_moving_ctxt_next_pending_write(ctxt))) {
		bch2_trans_unlock_long(ctxt->trans);
		list_del(&u->read_list);
		move_write(u);
	}
}

void bch2_move_ctxt_wait_for_io(struct moving_context *ctxt)
{
	unsigned sectors_pending = atomic_read(&ctxt->write_sectors);

	move_ctxt_wait_event(ctxt,
		!atomic_read(&ctxt->write_sectors) ||
		atomic_read(&ctxt->write_sectors) != sectors_pending);
}

void bch2_moving_ctxt_flush_all(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt, list_empty(&ctxt->reads));
	bch2_trans_unlock_long(ctxt->trans);
	closure_sync(&ctxt->cl);
}

void bch2_moving_ctxt_exit(struct moving_context *ctxt)
{
	struct bch_fs *c = ctxt->trans->c;

	bch2_moving_ctxt_flush_all(ctxt);

	EBUG_ON(atomic_read(&ctxt->write_sectors));
	EBUG_ON(atomic_read(&ctxt->write_ios));
	EBUG_ON(atomic_read(&ctxt->read_sectors));
	EBUG_ON(atomic_read(&ctxt->read_ios));

	scoped_guard(mutex, &c->moving_context_lock)
		list_del(&ctxt->list);

	/*
	 * Generally, releasing a transaction within a transaction restart means
	 * an unhandled transaction restart: but this can happen legitimately
	 * within the move code, e.g. when bch2_move_ratelimit() tells us to
	 * exit before we've retried
	 */
	bch2_trans_begin(ctxt->trans);
	bch2_trans_put(ctxt->trans);
	memset(ctxt, 0, sizeof(*ctxt));
}

void bch2_moving_ctxt_init(struct moving_context *ctxt,
			   struct bch_fs *c,
			   struct bch_ratelimit *rate,
			   struct bch_move_stats *stats,
			   struct write_point_specifier wp,
			   bool wait_on_copygc)
{
	memset(ctxt, 0, sizeof(*ctxt));

	ctxt->trans	= bch2_trans_get(c);
	ctxt->fn	= (void *) _RET_IP_;
	ctxt->rate	= rate;
	ctxt->stats	= stats;
	ctxt->wp	= wp;
	ctxt->wait_on_copygc = wait_on_copygc;

	closure_init_stack(&ctxt->cl);

	mutex_init(&ctxt->lock);
	INIT_LIST_HEAD(&ctxt->reads);
	INIT_LIST_HEAD(&ctxt->ios);
	init_waitqueue_head(&ctxt->wait);

	scoped_guard(mutex, &c->moving_context_lock)
		list_add(&ctxt->list, &c->moving_context_list);
}

void bch2_move_stats_exit(struct bch_move_stats *stats, struct bch_fs *c)
{
}

void bch2_move_stats_init(struct bch_move_stats *stats, const char *name)
{
	memset(stats, 0, sizeof(*stats));
	stats->data_type = BCH_DATA_user;
	scnprintf(stats->name, sizeof(stats->name), "%s", name);
}

DEFINE_FREE(data_update_free, struct data_update *, if (_T) kfree_rcu(_T, rcu))

static int __bch2_move_extent(struct moving_context *ctxt,
		     struct move_bucket *bucket_in_flight,
		     struct btree_iter *iter,
		     struct bkey_s_c k,
		     struct bch_inode_opts *io_opts,
		     struct data_update_opts *data_opts)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (ctxt->stats)
		ctxt->stats->pos = BBPOS(iter->btree_id, iter->pos);

	struct data_update *u __free(data_update_free) =
		allocate_dropping_locks(trans, ret, kzalloc(sizeof(struct data_update), _gfp));
	if (!u && !ret)
		ret = bch_err_throw(c, ENOMEM_move_extent);
	if (ret)
		return ret;

	ret = bch2_data_update_init(trans, iter, ctxt, u, ctxt->wp,
				    io_opts, *data_opts, iter->btree_id, k);
	if (ret)
		return bch2_err_matches(ret, BCH_ERR_data_update_done) ? 0 : ret;

	k = bkey_i_to_s_c(u->k.k);

	u->op.end_io		= move_write_done;
	u->rbio.bio.bi_end_io	= move_read_endio;
	u->rbio.bio.bi_ioprio	= IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);

	if (ctxt->rate)
		bch2_ratelimit_increment(ctxt->rate, k.k->size);

	if (ctxt->stats) {
		atomic64_inc(&ctxt->stats->keys_moved);
		atomic64_add(u->k.k->k.size, &ctxt->stats->sectors_moved);
	}

	if (bucket_in_flight) {
		u->b = bucket_in_flight;
		atomic_inc(&u->b->count);
	}

	scoped_guard(mutex, &ctxt->lock) {
		atomic_add(u->k.k->k.size, &ctxt->read_sectors);
		atomic_inc(&ctxt->read_ios);

		list_add_tail(&u->read_list, &ctxt->reads);
		list_add_tail(&u->io_list, &ctxt->ios);

		u->io_seq = ctxt->io_seq++;
	}

	/*
	 * dropped by move_read_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&ctxt->cl);
	__bch2_read_extent(trans, &u->rbio,
			   u->rbio.bio.bi_iter,
			   bkey_start_pos(k.k),
			   iter->btree_id, k, 0,
			   NULL,
			   data_opts->read_flags|BCH_READ_last_fragment,
			   data_opts->read_dev);
	u = NULL;
	return 0;
}

int bch2_move_extent(struct moving_context *ctxt,
		     struct move_bucket *bucket_in_flight,
		     struct bch_inode_opts *opts,
		     struct data_update_opts *data_opts,
		     struct btree_iter *iter, unsigned level, struct bkey_s_c k)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (data_opts->type == BCH_DATA_UPDATE_scrub &&
	    !bch2_dev_idx_is_online(c, data_opts->read_dev))
		return bch_err_throw(c, device_offline);

	if (!bkey_is_btree_ptr(k.k))
		ret = __bch2_move_extent(ctxt, bucket_in_flight, iter, k, opts, data_opts);
	else if (data_opts->type != BCH_DATA_UPDATE_scrub) {
		if (data_opts->type != BCH_DATA_UPDATE_copygc)
			try(bch2_can_do_data_update(trans, opts, data_opts, k, NULL));

		enum bch_trans_commit_flags commit_flags = data_opts->commit_flags;
		if ((commit_flags & BCH_WATERMARK_MASK) == BCH_WATERMARK_copygc)
			commit_flags = btree_update_set_watermark_hipri(commit_flags);

		ret = bch2_btree_node_rewrite_pos(trans, iter->btree_id, level, k.k->p,
						  data_opts->target,
						  data_opts->commit_flags,
						  data_opts->write_flags);
	} else
		ret = bch2_btree_node_scrub(trans, iter->btree_id, level, k, data_opts->read_dev);

	if (bch2_err_matches(ret, ENOMEM)) {
		/* memory allocation failure, wait for some IO to finish */
		bch2_move_ctxt_wait_for_io(ctxt);
		ret = bch_err_throw(c, transaction_restart_nested);
	}

	if (!bch2_err_matches(ret, BCH_ERR_transaction_restart) && ctxt->stats &&
	    !ctxt->stats->phys)
		atomic64_add(!bkey_is_btree_ptr(k.k)
			     ? k.k->size
			     : c->opts.btree_node_size >> 9, &ctxt->stats->sectors_seen);

	return ret;
}

static int bch2_move_extent_pred(struct moving_context *ctxt,
				 struct move_bucket *bucket_in_flight,
				 struct per_snapshot_io_opts *snapshot_io_opts,
				 move_pred_fn pred, void *arg,
				 struct btree_iter *iter, unsigned level, struct bkey_s_c k)
{
	if (!bkey_extent_is_direct_data(k.k))
		return 0;

	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts));
	try(bch2_update_reconcile_opts(trans, snapshot_io_opts, &opts, iter, level, k,
				       SET_NEEDS_RECONCILE_other));

	CLASS(disk_reservation, res)(c);
	try(bch2_trans_commit_lazy(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc));

	struct data_update_opts data_opts = { .read_dev = -1 };
	int ret = pred(trans, arg, iter->btree_id, k, &opts, &data_opts);

	event_add_trace(c, data_update_pred, k.k->size, buf, ({
		prt_printf(&buf, "%ps: %i", pred, ret);

		if (pred == evacuate_bucket_pred) {
			struct evacuate_bucket_arg *e = arg;
			prt_printf(&buf, " gen=%u", e->gen);
		}

		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);
		bch2_data_update_opts_to_text(&buf, c, &opts, &data_opts);
	}));

	if (ret <= 0)
		return ret;

	return bch2_move_extent(ctxt, bucket_in_flight, &opts, &data_opts, iter, level, k);
}

int bch2_move_ratelimit(struct moving_context *ctxt)
{
	struct bch_fs *c = ctxt->trans->c;
	bool is_kthread = current->flags & PF_KTHREAD;
	u64 delay;

	if (ctxt->wait_on_copygc && c->copygc.running) {
		bch2_moving_ctxt_flush_all(ctxt);
		wait_event_freezable(c->copygc.running_wq,
				    !c->copygc.running ||
				    (is_kthread && kthread_should_stop()));
	}

	do {
		delay = ctxt->rate ? bch2_ratelimit_delay(ctxt->rate) : 0;

		if (is_kthread && kthread_should_stop())
			return 1;

		if (delay)
			move_ctxt_wait_event_timeout(ctxt,
					freezing(current) ||
					(is_kthread && kthread_should_stop()),
					delay);

		if (unlikely(freezing(current))) {
			bch2_moving_ctxt_flush_all(ctxt);
			try_to_freeze();
		}
	} while (delay);

	/*
	 * XXX: these limits really ought to be per device, SSDs and hard drives
	 * will want different limits
	 */
	move_ctxt_wait_event(ctxt,
		atomic_read(&ctxt->write_sectors) < c->opts.move_bytes_in_flight >> 9 &&
		atomic_read(&ctxt->read_sectors) < c->opts.move_bytes_in_flight >> 9 &&
		atomic_read(&ctxt->write_ios) < c->opts.move_ios_in_flight &&
		atomic_read(&ctxt->read_ios) < c->opts.move_ios_in_flight);

	return 0;
}

int bch2_move_data_btree(struct moving_context *ctxt,
			 struct bpos start,
			 struct bpos end,
			 move_pred_fn pred, void *arg,
			 enum btree_id btree_id, unsigned level)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

	if (ctxt->stats) {
		ctxt->stats->data_type	= BCH_DATA_user;
		ctxt->stats->pos	= BBPOS(btree_id, start);
	}

	try(for_btree_root_key_at_level(trans, iter, btree_id, level, k, ({
		int ret = bch2_move_extent_pred(ctxt, NULL, &snapshot_io_opts, pred, arg, &iter, level, k);
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		WARN_ONCE(ret &&
			  !bch2_err_matches(ret, BCH_ERR_transaction_restart) &&
			  !bch2_err_matches(ret, EAGAIN) &&
			  !bch2_err_matches(ret, EROFS) &&
			  !bch2_err_matches(ret, EIO),
			  "unhandled error from move_extent: %s", bch2_err_str(ret));
		ret;
	})));

	bch2_trans_begin(trans);
	CLASS(btree_node_iter, iter)(trans, btree_id, start, 0, level,
				     BTREE_ITER_prefetch|
				     BTREE_ITER_not_extents|
				     BTREE_ITER_all_snapshots);

	if (ctxt->rate)
		bch2_ratelimit_reset(ctxt->rate);

	int ret = 0;
	while (!(ret = bch2_move_ratelimit(ctxt))) {
		bch2_trans_begin(trans);

		struct bkey_s_c k = bch2_btree_iter_peek(&iter);
		if (!k.k)
			break;

		ret = bkey_err(k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;

		if (bkey_gt(bkey_start_pos(k.k), end))
			break;

		if (ctxt->stats)
			ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

		if (!bkey_extent_is_direct_data(k.k))
			goto next_nondata;

		ret = bch2_move_extent_pred(ctxt, NULL, &snapshot_io_opts, pred, arg, &iter, level, k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		if (bch2_err_matches(ret, EROFS) ||
		    bch2_err_matches(ret, EIO)) /* topology error, btree node read error */
			break;
		WARN_ONCE(ret && !bch2_err_matches(ret, EAGAIN),
			  "unhandled error from move_extent: %s", bch2_err_str(ret));
next_nondata:
		if (!bch2_btree_iter_advance(&iter))
			break;
	}

	/* ratelimit told us to stop (kthread_should_stop), not an error */
	if (ret > 0)
		ret = 0;
	return ret;
}

static int __bch2_move_data_phys(struct moving_context *ctxt,
			struct move_bucket *bucket_in_flight,
			unsigned dev,
			u64 sector_start,
			u64 sector_end,
			unsigned data_types,
			bool copygc,
			move_pred_fn pred, void *arg)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret = 0;

	/* Userspace might have supplied @dev: */
	CLASS(bch2_dev_tryget_noerror, ca)(c, dev);
	if (!ca)
		return 0;

	sector_end = min(sector_end, bucket_to_sector(ca, ca->mi.nbuckets));

	u64 check_mismatch_done = sector_to_bucket(ca, sector_start);

	struct bpos bp_start	= POS(dev, sector_start	<< c->sb.extent_bp_shift);
	struct bpos bp_end	= POS(dev, sector_end	<< c->sb.extent_bp_shift);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	/*
	 * We're not run in a context that handles transaction restarts:
	 */
	bch2_trans_begin(trans);

	CLASS(btree_iter, bp_iter)(trans, BTREE_ID_backpointers, bp_start, 0);

	ret = bch2_btree_write_buffer_tryflush(trans);
	if (!bch2_err_matches(ret, EROFS))
		bch_err_msg(c, ret, "flushing btree write buffer");
	if (ret)
		return ret;

	while (!(ret = bch2_move_ratelimit(ctxt))) {
		bch2_trans_begin(trans);

		k = bch2_btree_iter_peek(&bp_iter);
		ret = bkey_err(k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;

		if (!k.k || bkey_gt(k.k->p, bp_end))
			break;

		if (check_mismatch_done < bp_pos_to_bucket(ca, k.k->p).offset) {
			while (check_mismatch_done < bp_pos_to_bucket(ca, k.k->p).offset)
				bch2_check_bucket_backpointer_mismatch(trans, ca, check_mismatch_done++,
								       copygc, &last_flushed);
			continue;
		}

		if (k.k->type != KEY_TYPE_backpointer) {
			bch2_btree_iter_advance(&bp_iter);
			continue;
		}

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);

		if (ctxt->stats)
			ctxt->stats->offset = bp.k->p.offset >> c->sb.extent_bp_shift;

		if (!(data_types & BIT(bp.v->data_type)) ||
		    (!bp.v->level && bp.v->btree_id == BTREE_ID_stripes)) {
			bch2_btree_iter_advance(&bp_iter);
			continue;
		}

		CLASS(btree_iter_uninit, iter)(trans);
		k = bch2_backpointer_get_key(trans, bp, &iter, 0, &last_flushed);
		ret = bkey_err(k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;
		if (!k.k) {
			bch2_btree_iter_advance(&bp_iter);
			continue;
		}

		ret = bch2_move_extent_pred(ctxt, bucket_in_flight, NULL, pred, arg, &iter, bp.v->level, k);

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ctxt->stats)
			atomic64_add(bp.v->bucket_len, &ctxt->stats->sectors_seen);
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		if (bch2_err_matches(ret, EAGAIN) ||
		    bch2_err_matches(ret, EROFS) ||
		    bch2_err_matches(ret, EIO) ||
		    bch2_err_matches(ret, BCH_ERR_device_offline))
			break;
		WARN_ONCE(ret, "unhandled error from move_extent: %s", bch2_err_str(ret));
		bch2_btree_iter_advance(&bp_iter);
	}

	/* ratelimit told us to stop (kthread_should_stop), not an error */
	if (ret > 0)
		ret = 0;

	while (check_mismatch_done < sector_to_bucket(ca, sector_end))
		bch2_check_bucket_backpointer_mismatch(trans, ca, check_mismatch_done++,
						       copygc, &last_flushed);

	bch_err_fn(c, ret);
	return ret;
}

int bch2_move_data_phys(struct bch_fs *c,
			unsigned dev,
			u64 start,
			u64 end,
			unsigned data_types,
			struct bch_ratelimit *rate,
			struct bch_move_stats *stats,
			struct write_point_specifier wp,
			bool wait_on_copygc,
			move_pred_fn pred, void *arg)
{
	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, rate, stats, wp, wait_on_copygc);

	if (ctxt.stats) {
		ctxt.stats->phys = true;
		ctxt.stats->data_type = (int) DATA_PROGRESS_DATA_TYPE_phys;
	}

	bch2_btree_write_buffer_flush_sync(ctxt.trans);

	return __bch2_move_data_phys(&ctxt, NULL, dev, start, end, data_types, false, pred, arg);
}

struct evacuate_arg {
	unsigned		dev;
};

static int evacuate_pred(struct btree_trans *trans, void *_arg,
			 enum btree_id btree, struct bkey_s_c k,
			 struct bch_inode_opts *io_opts,
			 struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	struct evacuate_arg *arg = _arg;

	data_opts->read_dev = -1;

	unsigned ptr_bit = 1;
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		if (ptr->dev == arg->dev)
			data_opts->ptrs_kill |= ptr_bit;
		ptr_bit <<= 1;
	}

	return data_opts->ptrs_kill != 0;
}

int bch2_evacuate_data(struct moving_context *ctxt,
		       unsigned dev, u64 start, u64 end)
{
	struct evacuate_arg arg = { .dev = dev };

	return __bch2_move_data_phys(ctxt, NULL,
				     dev, start, end,
				     ~0,
				     false,
				     evacuate_pred, &arg);
}

static int evacuate_bucket_pred(struct btree_trans *trans, void *_arg,
				enum btree_id btree, struct bkey_s_c k,
				struct bch_inode_opts *io_opts,
				struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	struct evacuate_bucket_arg *arg = _arg;

	*data_opts = arg->data_opts;
	data_opts->read_dev = -1;

	unsigned i = 0;
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		if (ptr->dev == arg->bucket.inode &&
		    (arg->gen < 0 || arg->gen == ptr->gen) &&
		    !ptr->cached)
			data_opts->ptrs_kill |= BIT(i);
		i++;
	}

	return data_opts->ptrs_kill != 0;
}

int bch2_evacuate_bucket(struct moving_context *ctxt,
			 struct move_bucket *bucket_in_flight,
			 struct bpos bucket, int gen,
			 struct data_update_opts data_opts)
{
	struct bch_fs *c = ctxt->trans->c;
	struct evacuate_bucket_arg arg = { bucket, gen, data_opts, };

	/* Userspace might have supplied @dev: */
	CLASS(bch2_dev_tryget_noerror, ca)(c, bucket.inode);
	if (!ca)
		return 0;

	int ret = __bch2_move_data_phys(ctxt, bucket_in_flight,
					bucket.inode,
					bucket_to_sector(ca, bucket.offset),
					bucket_to_sector(ca, bucket.offset + 1),
					~0,
					true,
					evacuate_bucket_pred, &arg);

	event_inc_trace(c, evacuate_bucket, buf, ({
		prt_printf(&buf, "bucket: ");
		bch2_bpos_to_text(&buf, bucket);
		prt_printf(&buf, " gen: %i ret %s\n", gen, bch2_err_str(ret));
	}));

	return ret;
}

static int scrub_pred(struct btree_trans *trans, void *_arg,
		      enum btree_id btree, struct bkey_s_c k,
		      struct bch_inode_opts *io_opts,
		      struct data_update_opts *data_opts)
{
	struct bch_ioctl_data *arg = _arg;

	if (k.k->type != KEY_TYPE_btree_ptr_v2) {
		struct bch_fs *c = trans->c;
		struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
			if (p.ptr.dev == arg->migrate.dev) {
				if (!p.crc.csum_type)
					return false;
				break;
			}
	}

	data_opts->type		= BCH_DATA_UPDATE_scrub;
	data_opts->read_dev	= arg->migrate.dev;
	data_opts->read_flags	= BCH_READ_hard_require_read_device;
	return true;
}

int bch2_data_job(struct bch_fs *c,
		  struct bch_move_stats *stats,
		  struct bch_ioctl_data *op)
{
	int ret = 0;

	if (op->op >= BCH_DATA_OP_NR)
		return -EINVAL;

	bch2_move_stats_init(stats, bch2_data_ops_strs[op->op]);

	switch (op->op) {
	case BCH_DATA_OP_scrub:
		/*
		 * prevent tests from spuriously failing, make sure we see all
		 * btree nodes that need to be repaired
		 */
		bch2_btree_interior_updates_flush(c);

		ret = bch2_move_data_phys(c, op->scrub.dev, 0, U64_MAX,
					  op->scrub.data_types,
					  NULL,
					  stats,
					  writepoint_hashed((unsigned long) current),
					  false,
					  scrub_pred, op) ?: ret;
		break;

	default:
		ret = -EINVAL;
	}

	bch2_move_stats_exit(stats, c);
	return ret;
}

void bch2_move_stats_to_text(struct printbuf *out, struct bch_move_stats *stats)
{
	prt_printf(out, "%s: data type==", stats->name);
	bch2_prt_data_type(out, stats->data_type);
	prt_str(out, " pos=");
	bch2_bbpos_to_text(out, stats->pos);
	prt_newline(out);
	guard(printbuf_indent)(out);

	prt_printf(out, "keys moved:\t%llu\n",	atomic64_read(&stats->keys_moved));
	prt_printf(out, "keys raced:\t%llu\n",	atomic64_read(&stats->keys_raced));
	prt_printf(out, "bytes seen:\t");
	prt_human_readable_u64(out, atomic64_read(&stats->sectors_seen) << 9);
	prt_newline(out);

	prt_printf(out, "bytes moved:\t");
	prt_human_readable_u64(out, atomic64_read(&stats->sectors_moved) << 9);
	prt_newline(out);

	prt_printf(out, "bytes raced:\t");
	prt_human_readable_u64(out, atomic64_read(&stats->sectors_raced) << 9);
	prt_newline(out);
}

static void bch2_moving_ctxt_to_text(struct printbuf *out, struct bch_fs *c, struct moving_context *ctxt)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 32);

	bch2_move_stats_to_text(out, ctxt->stats);
	guard(printbuf_indent)(out);

	prt_printf(out, "reads: ios %u/%u sectors %u/%u\n",
		   atomic_read(&ctxt->read_ios),
		   c->opts.move_ios_in_flight,
		   atomic_read(&ctxt->read_sectors),
		   c->opts.move_bytes_in_flight >> 9);

	prt_printf(out, "writes: ios %u/%u sectors %u/%u\n",
		   atomic_read(&ctxt->write_ios),
		   c->opts.move_ios_in_flight,
		   atomic_read(&ctxt->write_sectors),
		   c->opts.move_bytes_in_flight >> 9);

	guard(printbuf_indent)(out);

	scoped_guard(mutex, &ctxt->lock) {
		struct data_update *u;
		list_for_each_entry(u, &ctxt->ios, io_list)
			bch2_data_update_inflight_to_text(out, u);
	}
}

void bch2_fs_moving_ctxts_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct moving_context *ctxt;

	scoped_guard(mutex, &c->moving_context_lock)
		list_for_each_entry(ctxt, &c->moving_context_list, list)
			bch2_moving_ctxt_to_text(out, c, ctxt);
}

void bch2_fs_move_init(struct bch_fs *c)
{
	INIT_LIST_HEAD(&c->moving_context_list);
	mutex_init(&c->moving_context_lock);
}
