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
#include "data/ec.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/read.h"
#include "data/rebalance.h"
#include "data/reflink.h"
#include "data/write.h"

#include "fs/inode.h"

#include "init/error.h"

#include "journal/reclaim.h"

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

static noinline void
trace_io_move_pred2(struct bch_fs *c, struct bkey_s_c k,
		    struct bch_inode_opts *io_opts,
		    struct data_update_opts *data_opts,
		    move_pred_fn pred, void *_arg, int ret)
{
	CLASS(printbuf, buf)();

	prt_printf(&buf, "%ps: %i", pred, ret);

	if (pred == evacuate_bucket_pred) {
		struct evacuate_bucket_arg *arg = _arg;
		prt_printf(&buf, " gen=%u", arg->gen);
	}

	prt_newline(&buf);
	bch2_bkey_val_to_text(&buf, c, k);
	prt_newline(&buf);
	bch2_data_update_opts_to_text(&buf, c, io_opts, data_opts);
	trace_io_move_pred(c, buf.buf);
}

static noinline void
trace_io_move_evacuate_bucket2(struct bch_fs *c, struct bpos bucket, int gen)
{
	struct printbuf buf = PRINTBUF;

	prt_printf(&buf, "bucket: ");
	bch2_bpos_to_text(&buf, bucket);
	prt_printf(&buf, " gen: %i\n", gen);

	trace_io_move_evacuate_bucket(c, buf.buf);
	printbuf_exit(&buf);
}

static void move_write_done(struct bch_write_op *op)
{
	struct data_update *u = container_of(op, struct data_update, op);
	struct moving_context *ctxt = u->ctxt;

	atomic_sub(u->k.k->k.size, &ctxt->write_sectors);
	atomic_dec(&ctxt->write_ios);

	bch2_data_update_exit(u, op->error);
	kfree(u);
	closure_put(&ctxt->cl);
}

static void move_write(struct data_update *u)
{
	struct moving_context *ctxt = u->ctxt;
	struct bch_read_bio *rbio = &u->rbio;

	if (ctxt->stats) {
		if (rbio->bio.bi_status)
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
	trace_move_data(c, stats);
}

void bch2_move_stats_init(struct bch_move_stats *stats, const char *name)
{
	memset(stats, 0, sizeof(*stats));
	stats->data_type = BCH_DATA_user;
	scnprintf(stats->name, sizeof(stats->name), "%s", name);
}

static int __bch2_move_extent(struct moving_context *ctxt,
		     struct move_bucket *bucket_in_flight,
		     struct btree_iter *iter,
		     struct bkey_s_c k,
		     struct bch_inode_opts io_opts,
		     struct data_update_opts data_opts)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (ctxt->stats)
		ctxt->stats->pos = BBPOS(iter->btree_id, iter->pos);

	struct data_update *u = allocate_dropping_locks(trans, ret,
				kzalloc(sizeof(struct data_update), _gfp));
	if (!u && !ret)
		ret = bch_err_throw(c, ENOMEM_move_extent);
	if (ret)
		goto err;

	ret = bch2_data_update_init(trans, iter, ctxt, u, ctxt->wp,
				    &io_opts, data_opts, iter->btree_id, k);
	if (ret)
		goto err;

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
			   BCH_READ_last_fragment,
			   data_opts.type == BCH_DATA_UPDATE_scrub ? data_opts.read_dev : -1);
	return 0;
err:
	kfree(u);

	return bch2_err_matches(ret, BCH_ERR_data_update_done)
		? 0
		: ret;
}

int bch2_move_extent(struct moving_context *ctxt,
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
	try(bch2_update_rebalance_opts(trans, snapshot_io_opts, &opts, iter, level, k,
				       SET_NEEDS_REBALANCE_other));

	CLASS(disk_reservation, res)(c);
	try(bch2_trans_commit_lazy(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc));

	struct data_update_opts data_opts = {};
	int ret = pred(trans, arg, iter->btree_id, k, &opts, &data_opts);

	if (trace_io_move_pred_enabled())
		trace_io_move_pred2(c, k, &opts, &data_opts, pred, arg, ret);

	if (ret <= 0)
		return ret;

	if (data_opts.type == BCH_DATA_UPDATE_scrub &&
	    !bch2_dev_idx_is_online(c, data_opts.read_dev))
		return bch_err_throw(c, device_offline);

	if (!bkey_is_btree_ptr(k.k))
		ret = __bch2_move_extent(ctxt, bucket_in_flight, iter, k, opts, data_opts);
	else if (data_opts.type != BCH_DATA_UPDATE_scrub)
		ret = bch2_btree_node_rewrite_pos(trans, iter->btree_id, level, k.k->p, data_opts.target, 0);
	else
		ret = bch2_btree_node_scrub(trans, iter->btree_id, level, k, data_opts.read_dev);

	if (bch2_err_matches(ret, ENOMEM)) {
		/* memory allocation failure, wait for some IO to finish */
		bch2_move_ctxt_wait_for_io(ctxt);
		ret = bch_err_throw(c, transaction_restart_nested);
	}

	if (!bch2_err_matches(ret, BCH_ERR_transaction_restart) && ctxt->stats)
		atomic64_add(!bkey_is_btree_ptr(k.k)
			     ? k.k->size
			     : c->opts.btree_node_size >> 9, &ctxt->stats->sectors_seen);

	return ret;
}

int bch2_move_ratelimit(struct moving_context *ctxt)
{
	struct bch_fs *c = ctxt->trans->c;
	bool is_kthread = current->flags & PF_KTHREAD;
	u64 delay;

	if (ctxt->wait_on_copygc && c->copygc_running) {
		bch2_moving_ctxt_flush_all(ctxt);
		wait_event_freezable(c->copygc_running_wq,
				    !c->copygc_running ||
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
	struct bkey_s_c k;
	int ret = 0;

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);
	CLASS(btree_iter_uninit, iter)(trans);

	if (ctxt->stats) {
		ctxt->stats->data_type	= BCH_DATA_user;
		ctxt->stats->pos	= BBPOS(btree_id, start);
	}

retry_root:
	bch2_trans_begin(trans);

	if (level == bch2_btree_id_root(c, btree_id)->level + 1) {
		bch2_trans_node_iter_init(trans, &iter, btree_id, start, 0, level - 1,
					  BTREE_ITER_prefetch|
					  BTREE_ITER_not_extents|
					  BTREE_ITER_all_snapshots);
		struct btree *b = bch2_btree_iter_peek_node(&iter);
		ret = PTR_ERR_OR_ZERO(b);
		if (ret)
			goto root_err;

		if (b != btree_node_root(c, b))
			goto retry_root;

		if (btree_node_fake(b))
			return 0;

		k = bkey_i_to_s_c(&b->key);
		ret = bch2_move_extent(ctxt, NULL, &snapshot_io_opts, pred, arg, &iter, level, k);
root_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto retry_root;
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		WARN_ONCE(ret && !bch2_err_matches(ret, EROFS),
			  "unhandled error from move_extent: %s", bch2_err_str(ret));
		return ret;
	}

	bch2_trans_node_iter_init(trans, &iter, btree_id, start, 0, level,
				  BTREE_ITER_prefetch|
				  BTREE_ITER_not_extents|
				  BTREE_ITER_all_snapshots);

	if (ctxt->rate)
		bch2_ratelimit_reset(ctxt->rate);

	while (!(ret = bch2_move_ratelimit(ctxt))) {
		bch2_trans_begin(trans);

		k = bch2_btree_iter_peek(&iter);
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

		ret = bch2_move_extent(ctxt, NULL, &snapshot_io_opts, pred, arg, &iter, level, k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		if (bch2_err_matches(ret, EROFS))
			break;
		WARN_ONCE(ret, "unhandled error from move_extent: %s", bch2_err_str(ret));
next_nondata:
		if (!bch2_btree_iter_advance(&iter))
			break;
	}

	return ret;
}

static int bch2_move_data(struct bch_fs *c,
			  struct bbpos start,
			  struct bbpos end,
			  unsigned min_depth,
			  struct bch_ratelimit *rate,
			  struct bch_move_stats *stats,
			  struct write_point_specifier wp,
			  bool wait_on_copygc,
			  move_pred_fn pred, void *arg)
{
	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, rate, stats, wp, wait_on_copygc);

	for (enum btree_id id = start.btree;
	     id <= min_t(unsigned, end.btree, btree_id_nr_alive(c) - 1);
	     id++) {
		ctxt.stats->pos = BBPOS(id, POS_MIN);

		if (!bch2_btree_id_root(c, id)->b)
			continue;

		unsigned min_depth_this_btree = min_depth;

		/* Stripe keys have pointers, but are handled separately */
		if (!btree_type_has_data_ptrs(id) ||
		    id == BTREE_ID_stripes)
			min_depth_this_btree = max(min_depth_this_btree, 1);

		for (unsigned level = min_depth_this_btree;
		     level < BTREE_MAX_DEPTH;
		     level++) {
			try(bch2_move_data_btree(&ctxt,
						 id == start.btree ? start.pos : POS_MIN,
						 id == end.btree   ? end.pos   : POS_MAX,
						 pred, arg, id, level));
		}
	}

	return 0;
}

static int __bch2_move_data_phys(struct moving_context *ctxt,
			struct move_bucket *bucket_in_flight,
			unsigned dev,
			u64 bucket_start,
			u64 bucket_end,
			unsigned data_types,
			bool copygc,
			move_pred_fn pred, void *arg)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	bool is_kthread = current->flags & PF_KTHREAD;
	struct bkey_s_c k;
	u64 check_mismatch_done = bucket_start;
	int ret = 0;

	/* Userspace might have supplied @dev: */
	CLASS(bch2_dev_tryget_noerror, ca)(c, dev);
	if (!ca)
		return 0;

	bucket_end = min(bucket_end, ca->mi.nbuckets);

	struct bpos bp_start	= bucket_pos_to_bp_start(ca, POS(dev, bucket_start));
	struct bpos bp_end	= bucket_pos_to_bp_end(ca, POS(dev, bucket_end));

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
		if (is_kthread && kthread_should_stop())
			break;

		bch2_trans_begin(trans);

		k = bch2_btree_iter_peek(&bp_iter);
		ret = bkey_err(k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			return ret;

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
			ctxt->stats->offset = bp.k->p.offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT;

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
			return ret;
		if (!k.k) {
			bch2_btree_iter_advance(&bp_iter);
			continue;
		}

		ret = bch2_move_extent(ctxt, bucket_in_flight, NULL, pred, arg, &iter, bp.v->level, k);

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		if (bch2_err_matches(ret, EROFS) ||
		    bch2_err_matches(ret, BCH_ERR_device_offline))
			return ret;
		WARN_ONCE(ret, "unhandled error from move_extent: %s", bch2_err_str(ret));
		bch2_btree_iter_advance(&bp_iter);
	}

	while (check_mismatch_done < bucket_end)
		bch2_check_bucket_backpointer_mismatch(trans, ca, check_mismatch_done++,
						       copygc, &last_flushed);

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

static int evacuate_bucket_pred(struct btree_trans *trans, void *_arg,
				enum btree_id btree, struct bkey_s_c k,
				struct bch_inode_opts *io_opts,
				struct data_update_opts *data_opts)
{
	struct evacuate_bucket_arg *arg = _arg;

	*data_opts = arg->data_opts;

	unsigned i = 0;
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		if (ptr->dev == arg->bucket.inode &&
		    (arg->gen < 0 || arg->gen == ptr->gen) &&
		    !ptr->cached)
			data_opts->ptrs_rewrite |= BIT(i);
		i++;
	}

	return data_opts->ptrs_rewrite != 0;
}

int bch2_evacuate_bucket(struct moving_context *ctxt,
			 struct move_bucket *bucket_in_flight,
			 struct bpos bucket, int gen,
			 struct data_update_opts data_opts)
{
	struct bch_fs *c = ctxt->trans->c;
	struct evacuate_bucket_arg arg = { bucket, gen, data_opts, };

	count_event(c, io_move_evacuate_bucket);
	if (trace_io_move_evacuate_bucket_enabled())
		trace_io_move_evacuate_bucket2(c, bucket, gen);

	return __bch2_move_data_phys(ctxt, bucket_in_flight,
				   bucket.inode,
				   bucket.offset,
				   bucket.offset + 1,
				   ~0,
				   true,
				   evacuate_bucket_pred, &arg);
}

typedef bool (*move_btree_pred)(struct bch_fs *, void *,
				struct btree *, struct bch_inode_opts *,
				struct data_update_opts *);

static int bch2_move_btree(struct bch_fs *c,
			   struct bbpos start,
			   struct bbpos end,
			   move_btree_pred pred, void *arg,
			   struct bch_move_stats *stats)
{
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	struct btree *b;
	enum btree_id btree;
	int ret = 0;

	struct bch_inode_opts io_opts;
	bch2_inode_opts_get(c, &io_opts, true);

	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, NULL, stats, writepoint_ptr(&c->btree_write_point), true);
	struct btree_trans *trans = ctxt.trans;

	CLASS(btree_iter_uninit, iter)(trans);

	stats->data_type = BCH_DATA_btree;

	for (btree = start.btree;
	     btree <= min_t(unsigned, end.btree, btree_id_nr_alive(c) - 1);
	     btree ++) {
		stats->pos = BBPOS(btree, POS_MIN);

		if (!bch2_btree_id_root(c, btree)->b)
			continue;

		bch2_trans_node_iter_init(trans, &iter, btree, POS_MIN, 0, 0,
					  BTREE_ITER_prefetch);
retry:
		ret = 0;
		while (bch2_trans_begin(trans),
		       (b = bch2_btree_iter_peek_node(&iter)) &&
		       !(ret = PTR_ERR_OR_ZERO(b))) {
			if (kthread && kthread_should_stop())
				break;

			if ((cmp_int(btree, end.btree) ?:
			     bpos_cmp(b->key.k.p, end.pos)) > 0)
				break;

			stats->pos = BBPOS(iter.btree_id, iter.pos);

			if (btree_node_fake(b))
				goto next;

			struct data_update_opts data_opts = {};
			if (!pred(c, arg, b, &io_opts, &data_opts))
				goto next;

			ret = bch2_btree_node_rewrite(trans, &iter, b, 0, 0) ?: ret;
			if (ret)
				break;
next:
			bch2_btree_iter_next_node(&iter);
		}
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto retry;

		if (kthread && kthread_should_stop())
			break;
	}

	bch2_trans_unlock(trans);
	bch2_btree_interior_updates_flush(c);
	bch_err_fn(c, ret);

	return ret;
}

static int rereplicate_pred(struct btree_trans *trans, void *arg,
			    enum btree_id btree, struct bkey_s_c k,
			    struct bch_inode_opts *io_opts,
			    struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	unsigned nr_good = bch2_bkey_durability(c, k);
	unsigned replicas = bkey_is_btree_ptr(k.k)
		? c->opts.metadata_replicas
		: io_opts->data_replicas;

	guard(rcu)();
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned i = 0;
	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch2_dev_rcu(c, ptr->dev);
		if (!ptr->cached &&
		    (!ca || !ca->mi.durability))
			data_opts->ptrs_kill |= BIT(i);
		i++;
	}

	if (!data_opts->ptrs_kill &&
	    (!nr_good || nr_good >= replicas))
		return false;

	data_opts->extra_replicas = replicas - nr_good;
	return true;
}

static int migrate_pred(struct btree_trans *trans, void *arg,
			enum btree_id btree, struct bkey_s_c k,
			struct bch_inode_opts *io_opts,
			struct data_update_opts *data_opts)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct bch_ioctl_data *op = arg;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == op->migrate.dev)
			data_opts->ptrs_rewrite |= ptr_bit;
		ptr_bit <<= 1;
	}

	return data_opts->ptrs_rewrite != 0;
}

/*
 * Ancient versions of bcachefs produced packed formats which could represent
 * keys that the in memory format cannot represent; this checks for those
 * formats so we can get rid of them.
 */
static bool bformat_needs_redo(struct bkey_format *f)
{
	for (unsigned i = 0; i < f->nr_fields; i++)
		if (bch2_bkey_format_field_overflows(f, i))
			return true;

	return false;
}

static bool rewrite_old_nodes_pred(struct bch_fs *c, void *arg,
				   struct btree *b,
				   struct bch_inode_opts *io_opts,
				   struct data_update_opts *data_opts)
{
	if (b->version_ondisk != c->sb.version ||
	    btree_node_need_rewrite(b) ||
	    bformat_needs_redo(&b->format))
		return true;

	return false;
}

int bch2_scan_old_btree_nodes(struct bch_fs *c, struct bch_move_stats *stats)
{
	int ret;

	ret = bch2_move_btree(c,
			      BBPOS_MIN,
			      BBPOS_MAX,
			      rewrite_old_nodes_pred, c, stats);
	if (!ret) {
		guard(mutex)(&c->sb_lock);
		c->disk_sb.sb->compat[0] |= cpu_to_le64(1ULL << BCH_COMPAT_extents_above_btree_updates_done);
		c->disk_sb.sb->compat[0] |= cpu_to_le64(1ULL << BCH_COMPAT_bformat_overflow_done);
		c->disk_sb.sb->version_min = c->disk_sb.sb->version;
		bch2_write_super(c);
	}

	bch_err_fn(c, ret);
	return ret;
}

static int drop_extra_replicas_pred(struct btree_trans *trans, void *arg,
				    enum btree_id btree, struct bkey_s_c k,
				    struct bch_inode_opts *io_opts,
				    struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	unsigned durability = bch2_bkey_durability(c, k);
	unsigned replicas = bkey_is_btree_ptr(k.k)
		? c->opts.metadata_replicas
		: io_opts->data_replicas;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned i = 0;

	guard(rcu)();
	bkey_for_each_ptr_decode(k.k, bch2_bkey_ptrs_c(k), p, entry) {
		unsigned d = bch2_extent_ptr_durability(c, &p);

		if (d && durability - d >= replicas) {
			data_opts->ptrs_kill |= BIT(i);
			durability -= d;
		}

		i++;
	}

	i = 0;
	bkey_for_each_ptr_decode(k.k, bch2_bkey_ptrs_c(k), p, entry) {
		if (p.has_ec && durability - p.ec.redundancy >= replicas) {
			data_opts->ptrs_kill_ec |= BIT(i);
			durability -= p.ec.redundancy;
		}

		i++;
	}

	return (data_opts->ptrs_kill|data_opts->ptrs_kill_ec) != 0;
}

static int scrub_pred(struct btree_trans *trans, void *_arg,
		      enum btree_id btree, struct bkey_s_c k,
		      struct bch_inode_opts *io_opts,
		      struct data_update_opts *data_opts)
{
	struct bch_ioctl_data *arg = _arg;

	if (k.k->type != KEY_TYPE_btree_ptr_v2) {
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
	return true;
}

int bch2_data_job(struct bch_fs *c,
		  struct bch_move_stats *stats,
		  struct bch_ioctl_data *op)
{
	struct bbpos start	= BBPOS(op->start_btree, op->start_pos);
	struct bbpos end	= BBPOS(op->end_btree, op->end_pos);
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

	case BCH_DATA_OP_rereplicate:
		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, -1);
		ret = bch2_move_data(c, start, end, 0, NULL, stats,
				     writepoint_hashed((unsigned long) current),
				     true,
				     rereplicate_pred, c) ?: ret;
		bch2_btree_interior_updates_flush(c);
		break;
	case BCH_DATA_OP_migrate:
		if (op->migrate.dev >= c->sb.nr_devices)
			return -EINVAL;

		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, op->migrate.dev);
		ret = bch2_move_data_phys(c, op->migrate.dev, 0, U64_MAX,
					  ~0,
					  NULL,
					  stats,
					  writepoint_hashed((unsigned long) current),
					  true,
					  migrate_pred, op) ?: ret;
		bch2_btree_interior_updates_flush(c);
		break;
	case BCH_DATA_OP_rewrite_old_nodes:
		ret = bch2_scan_old_btree_nodes(c, stats);
		break;
	case BCH_DATA_OP_drop_extra_replicas:
		ret = bch2_move_data(c, start, end, 0, NULL, stats,
				     writepoint_hashed((unsigned long) current),
				     true,
				     drop_extra_replicas_pred, c) ?: ret;
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
