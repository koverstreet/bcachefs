// SPDX-License-Identifier: GPL-2.0
/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "async_objs.h"
#include "btree_update.h"
#include "buckets.h"
#include "checksum.h"
#include "clock.h"
#include "compress.h"
#include "data_update.h"
#include "disk_groups.h"
#include "ec.h"
#include "enumerated_ref.h"
#include "error.h"
#include "io_read.h"
#include "io_misc.h"
#include "io_write.h"
#include "reflink.h"
#include "subvolume.h"
#include "trace.h"

#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/sched/mm.h>

#ifdef CONFIG_BCACHEFS_DEBUG
static unsigned bch2_read_corrupt_ratio;
module_param_named(read_corrupt_ratio, bch2_read_corrupt_ratio, uint, 0644);
MODULE_PARM_DESC(read_corrupt_ratio, "");
#endif

#ifndef CONFIG_BCACHEFS_NO_LATENCY_ACCT

static inline u32 bch2_dev_congested_read(struct bch_dev *ca, u64 now)
{
	s64 congested = atomic_read(&ca->congested);
	u64 last = READ_ONCE(ca->congested_last);
	if (time_after64(now, last))
		congested -= (now - last) >> 12;

	return clamp(congested, 0LL, CONGESTED_MAX);
}

static bool bch2_target_congested(struct bch_fs *c, u16 target)
{
	const struct bch_devs_mask *devs;
	unsigned d, nr = 0, total = 0;
	u64 now = local_clock();

	guard(rcu)();
	devs = bch2_target_to_mask(c, target) ?:
		&c->rw_devs[BCH_DATA_user];

	for_each_set_bit(d, devs->d, BCH_SB_MEMBERS_MAX) {
		struct bch_dev *ca = rcu_dereference(c->devs[d]);
		if (!ca)
			continue;

		total += bch2_dev_congested_read(ca, now);
		nr++;
	}

	return get_random_u32_below(nr * CONGESTED_MAX) < total;
}

void bch2_dev_congested_to_text(struct printbuf *out, struct bch_dev *ca)
{
	printbuf_tabstop_push(out, 32);

	prt_printf(out, "current:\t%u%%\n",
		   bch2_dev_congested_read(ca, local_clock()) *
		   100 / CONGESTED_MAX);

	prt_printf(out, "raw:\t%i/%u\n", atomic_read(&ca->congested), CONGESTED_MAX);

	prt_printf(out, "last io over threshold:\t");
	bch2_pr_time_units(out, local_clock() - ca->congested_last);
	prt_newline(out);

	prt_printf(out, "read latency threshold:\t");
	bch2_pr_time_units(out,
			   ca->io_latency[READ].quantiles.entries[QUANTILE_IDX(1)].m << 2);
	prt_newline(out);

	prt_printf(out, "median read latency:\t");
	bch2_pr_time_units(out,
			   ca->io_latency[READ].quantiles.entries[QUANTILE_IDX(7)].m);
	prt_newline(out);

	prt_printf(out, "write latency threshold:\t");
	bch2_pr_time_units(out,
			   ca->io_latency[WRITE].quantiles.entries[QUANTILE_IDX(1)].m << 3);
	prt_newline(out);

	prt_printf(out, "median write latency:\t");
	bch2_pr_time_units(out,
			   ca->io_latency[WRITE].quantiles.entries[QUANTILE_IDX(7)].m);
	prt_newline(out);
}

#else

static bool bch2_target_congested(struct bch_fs *c, u16 target)
{
	return false;
}

#endif

/* Cache promotion on read */

static const struct rhashtable_params bch_promote_params = {
	.head_offset		= offsetof(struct promote_op, hash),
	.key_offset		= offsetof(struct promote_op, pos),
	.key_len		= sizeof(struct bpos),
	.automatic_shrinking	= true,
};

static inline bool have_io_error(struct bch_io_failures *failed)
{
	return failed && failed->nr;
}

static inline struct data_update *rbio_data_update(struct bch_read_bio *rbio)
{
	EBUG_ON(rbio->split);

	return rbio->data_update
		? container_of(rbio, struct data_update, rbio)
		: NULL;
}

static bool ptr_being_rewritten(struct bch_read_bio *orig, unsigned dev)
{
	struct data_update *u = rbio_data_update(orig);
	if (!u)
		return false;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(bkey_i_to_s_c(u->k.k));
	unsigned i = 0;
	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == dev &&
		    u->data_opts.rewrite_ptrs & BIT(i))
			return true;
		i++;
	}

	return false;
}

static inline int should_promote(struct bch_fs *c, struct bkey_s_c k,
				  struct bpos pos,
				  struct bch_io_opts opts,
				  unsigned flags,
				  struct bch_io_failures *failed)
{
	if (!have_io_error(failed)) {
		BUG_ON(!opts.promote_target);

		if (!(flags & BCH_READ_may_promote)) {
			count_event(c, io_read_nopromote_may_not);
			return bch_err_throw(c, nopromote_may_not);
		}

		if (bch2_bkey_has_target(c, k, opts.promote_target)) {
			count_event(c, io_read_nopromote_already_promoted);
			return bch_err_throw(c, nopromote_already_promoted);
		}

		if (bkey_extent_is_unwritten(k)) {
			count_event(c, io_read_nopromote_unwritten);
			return bch_err_throw(c, nopromote_unwritten);
		}

		if (bch2_target_congested(c, opts.promote_target)) {
			count_event(c, io_read_nopromote_congested);
			return bch_err_throw(c, nopromote_congested);
		}
	}

	if (rhashtable_lookup_fast(&c->promote_table, &pos,
				   bch_promote_params)) {
		count_event(c, io_read_nopromote_in_flight);
		return bch_err_throw(c, nopromote_in_flight);
	}

	return 0;
}

static noinline void promote_free(struct bch_read_bio *rbio)
{
	struct promote_op *op = container_of(rbio, struct promote_op, write.rbio);
	struct bch_fs *c = rbio->c;

	int ret = rhashtable_remove_fast(&c->promote_table, &op->hash,
					 bch_promote_params);
	BUG_ON(ret);

	async_object_list_del(c, promote, op->list_idx);
	async_object_list_del(c, rbio, rbio->list_idx);

	bch2_data_update_exit(&op->write);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_promote);
	kfree_rcu(op, rcu);
}

static void promote_done(struct bch_write_op *wop)
{
	struct promote_op *op = container_of(wop, struct promote_op, write.op);
	struct bch_fs *c = op->write.rbio.c;

	bch2_time_stats_update(&c->times[BCH_TIME_data_promote], op->start_time);
	promote_free(&op->write.rbio);
}

static void promote_start_work(struct work_struct *work)
{
	struct promote_op *op = container_of(work, struct promote_op, work);

	bch2_data_update_read_done(&op->write);
}

static noinline void promote_start(struct bch_read_bio *rbio)
{
	struct promote_op *op = container_of(rbio, struct promote_op, write.rbio);

	trace_and_count(op->write.op.c, io_read_promote, &rbio->bio);

	INIT_WORK(&op->work, promote_start_work);
	queue_work(rbio->c->write_ref_wq, &op->work);
}

static struct bch_read_bio *__promote_alloc(struct btree_trans *trans,
					    enum btree_id btree_id,
					    struct bkey_s_c k,
					    struct bpos pos,
					    struct extent_ptr_decoded *pick,
					    unsigned sectors,
					    struct bch_read_bio *orig,
					    struct bch_io_failures *failed)
{
	struct bch_fs *c = trans->c;
	int ret;

	struct data_update_opts update_opts = { .write_flags = BCH_WRITE_alloc_nowait };

	if (!have_io_error(failed)) {
		update_opts.target = orig->opts.promote_target;
		update_opts.extra_replicas = 1;
		update_opts.write_flags |= BCH_WRITE_cached;
		update_opts.write_flags |= BCH_WRITE_only_specified_devs;
	} else {
		update_opts.target = orig->opts.foreground_target;

		struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
		unsigned ptr_bit = 1;
		bkey_for_each_ptr(ptrs, ptr) {
			if (bch2_dev_io_failures(failed, ptr->dev) &&
			    !ptr_being_rewritten(orig, ptr->dev))
				update_opts.rewrite_ptrs |= ptr_bit;
			ptr_bit <<= 1;
		}

		if (!update_opts.rewrite_ptrs)
			return NULL;
	}

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_promote))
		return ERR_PTR(-BCH_ERR_nopromote_no_writes);

	struct promote_op *op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op) {
		ret = bch_err_throw(c, nopromote_enomem);
		goto err_put;
	}

	op->start_time = local_clock();
	op->pos = pos;

	if (rhashtable_lookup_insert_fast(&c->promote_table, &op->hash,
					  bch_promote_params)) {
		ret = bch_err_throw(c, nopromote_in_flight);
		goto err;
	}

	ret = async_object_list_add(c, promote, op, &op->list_idx);
	if (ret < 0)
		goto err_remove_hash;

	ret = bch2_data_update_init(trans, NULL, NULL, &op->write,
			writepoint_hashed((unsigned long) current),
			&orig->opts,
			update_opts,
			btree_id, k);
	op->write.type = BCH_DATA_UPDATE_promote;
	/*
	 * possible errors: -BCH_ERR_nocow_lock_blocked,
	 * -BCH_ERR_ENOSPC_disk_reservation:
	 */
	if (ret)
		goto err_remove_list;

	rbio_init_fragment(&op->write.rbio.bio, orig);
	op->write.rbio.bounce	= true;
	op->write.rbio.promote	= true;
	op->write.op.end_io = promote_done;

	return &op->write.rbio;
err_remove_list:
	async_object_list_del(c, promote, op->list_idx);
err_remove_hash:
	BUG_ON(rhashtable_remove_fast(&c->promote_table, &op->hash,
				      bch_promote_params));
err:
	bio_free_pages(&op->write.op.wbio.bio);
	/* We may have added to the rhashtable and thus need rcu freeing: */
	kfree_rcu(op, rcu);
err_put:
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_promote);
	return ERR_PTR(ret);
}

noinline
static struct bch_read_bio *promote_alloc(struct btree_trans *trans,
					struct bvec_iter iter,
					struct bkey_s_c k,
					struct extent_ptr_decoded *pick,
					unsigned flags,
					struct bch_read_bio *orig,
					bool *bounce,
					bool *read_full,
					struct bch_io_failures *failed)
{
	/*
	 * We're in the retry path, but we don't know what to repair yet, and we
	 * don't want to do a promote here:
	 */
	if (failed && !failed->nr)
		return NULL;

	struct bch_fs *c = trans->c;
	/*
	 * if failed != NULL we're not actually doing a promote, we're
	 * recovering from an io/checksum error
	 */
	bool promote_full = (have_io_error(failed) ||
			     *read_full ||
			     READ_ONCE(c->opts.promote_whole_extents));
	/* data might have to be decompressed in the write path: */
	unsigned sectors = promote_full
		? max(pick->crc.compressed_size, pick->crc.live_size)
		: bvec_iter_sectors(iter);
	struct bpos pos = promote_full
		? bkey_start_pos(k.k)
		: POS(k.k->p.inode, iter.bi_sector);
	int ret;

	ret = should_promote(c, k, pos, orig->opts, flags, failed);
	if (ret)
		goto nopromote;

	struct bch_read_bio *promote =
		__promote_alloc(trans,
				k.k->type == KEY_TYPE_reflink_v
				? BTREE_ID_reflink
				: BTREE_ID_extents,
				k, pos, pick, sectors, orig, failed);
	if (!promote)
		return NULL;

	ret = PTR_ERR_OR_ZERO(promote);
	if (ret)
		goto nopromote;

	*bounce		= true;
	*read_full	= promote_full;

	if (have_io_error(failed))
		orig->self_healing = true;

	return promote;
nopromote:
	if (trace_io_read_nopromote_enabled()) {
		CLASS(printbuf, buf)();
		printbuf_indent_add_nextline(&buf, 2);
		prt_printf(&buf, "%s\n", bch2_err_str(ret));
		bch2_bkey_val_to_text(&buf, c, k);

		trace_io_read_nopromote(c, buf.buf);
	}
	count_event(c, io_read_nopromote);

	return NULL;
}

void bch2_promote_op_to_text(struct printbuf *out,
			     struct bch_fs *c,
			     struct promote_op *op)
{
	if (!op->write.read_done) {
		prt_printf(out, "parent read: %px\n", op->write.rbio.parent);
		printbuf_indent_add(out, 2);
		bch2_read_bio_to_text(out, c, op->write.rbio.parent);
		printbuf_indent_sub(out, 2);
	}

	bch2_data_update_to_text(out, &op->write);
}

/* Read */

static int bch2_read_err_msg_trans(struct btree_trans *trans, struct printbuf *out,
				   struct bch_read_bio *rbio, struct bpos read_pos)
{
	int ret = lockrestart_do(trans,
		bch2_inum_offset_err_msg_trans(trans, out,
				(subvol_inum) { rbio->subvol, read_pos.inode },
				read_pos.offset << 9));
	if (ret)
		return ret;

	if (rbio->data_update)
		prt_str(out, "(internal move) ");

	return 0;
}

static void bch2_read_err_msg(struct bch_fs *c, struct printbuf *out,
			      struct bch_read_bio *rbio, struct bpos read_pos)
{
	CLASS(btree_trans, trans)(c);
	bch2_read_err_msg_trans(trans, out, rbio, read_pos);
}

enum rbio_context {
	RBIO_CONTEXT_NULL,
	RBIO_CONTEXT_HIGHPRI,
	RBIO_CONTEXT_UNBOUND,
};

static inline struct bch_read_bio *
bch2_rbio_parent(struct bch_read_bio *rbio)
{
	return rbio->split ? rbio->parent : rbio;
}

__always_inline
static void bch2_rbio_punt(struct bch_read_bio *rbio, work_func_t fn,
			   enum rbio_context context,
			   struct workqueue_struct *wq)
{
	if (context <= rbio->context) {
		fn(&rbio->work);
	} else {
		rbio->work.func		= fn;
		rbio->context		= context;
		queue_work(wq, &rbio->work);
	}
}

static inline struct bch_read_bio *bch2_rbio_free(struct bch_read_bio *rbio)
{
	BUG_ON(rbio->bounce && !rbio->split);

	if (rbio->have_ioref) {
		struct bch_dev *ca = bch2_dev_have_ref(rbio->c, rbio->pick.ptr.dev);
		enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_io_read);
	}

	if (rbio->split) {
		struct bch_read_bio *parent = rbio->parent;

		if (unlikely(rbio->promote)) {
			if (!rbio->bio.bi_status)
				promote_start(rbio);
			else
				promote_free(rbio);
		} else {
			async_object_list_del(rbio->c, rbio, rbio->list_idx);

			if (rbio->bounce)
				bch2_bio_free_pages_pool(rbio->c, &rbio->bio);

			bio_put(&rbio->bio);
		}

		rbio = parent;
	}

	return rbio;
}

/*
 * Only called on a top level bch_read_bio to complete an entire read request,
 * not a split:
 */
static void bch2_rbio_done(struct bch_read_bio *rbio)
{
	if (rbio->start_time)
		bch2_time_stats_update(&rbio->c->times[BCH_TIME_data_read],
				       rbio->start_time);
#ifdef CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
	if (rbio->list_idx)
		async_object_list_del(rbio->c, rbio, rbio->list_idx);
#endif
	bio_endio(&rbio->bio);
}

static void get_rbio_extent(struct btree_trans *trans,
			    struct bch_read_bio *rbio,
			    struct bkey_buf *sk)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = lockrestart_do(trans,
			bkey_err(k = bch2_bkey_get_iter(trans, &iter,
						rbio->data_btree, rbio->data_pos, 0)));
	if (ret)
		return;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr(ptrs, ptr)
		if (bch2_extent_ptr_eq(*ptr, rbio->pick.ptr)) {
			bch2_bkey_buf_reassemble(sk, trans->c, k);
			break;
		}

	bch2_trans_iter_exit(&iter);
}

static noinline int maybe_poison_extent(struct btree_trans *trans, struct bch_read_bio *rbio,
					enum btree_id btree, struct bkey_s_c read_k)
{
	struct bch_fs *c = trans->c;

	struct data_update *u = rbio_data_update(rbio);
	if (u)
		read_k = bkey_i_to_s_c(u->k.k);

	u64 flags = bch2_bkey_extent_flags(read_k);
	if (flags & BIT_ULL(BCH_EXTENT_FLAG_poisoned))
		return 0;

	CLASS(btree_iter, iter)(trans, btree, bkey_start_pos(read_k.k), BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (ret)
		return ret;

	if (!bkey_and_val_eq(k, read_k))
		return 0;

	struct bkey_i *new = bch2_trans_kmalloc(trans,
					bkey_bytes(k.k) + sizeof(struct bch_extent_flags));
	ret =   PTR_ERR_OR_ZERO(new) ?:
		(bkey_reassemble(new, k), 0) ?:
		bch2_bkey_extent_flags_set(c, new, flags|BIT_ULL(BCH_EXTENT_FLAG_poisoned)) ?:
		bch2_trans_update(trans, &iter, new, BTREE_UPDATE_internal_snapshot_node) ?:
		bch2_trans_commit(trans, NULL, NULL, 0);
	if (ret)
		return ret;

	/*
	 * Propagate key change back to data update path, in particular so it
	 * knows the extent has been poisoned and it's safe to change the
	 * checksum
	 */
	if (u)
		bch2_bkey_buf_copy(&u->k, c, new);
	return 0;
}

static noinline int bch2_read_retry_nodecode(struct btree_trans *trans,
					struct bch_read_bio *rbio,
					struct bvec_iter bvec_iter,
					struct bch_io_failures *failed,
					unsigned flags)
{
	struct data_update *u = container_of(rbio, struct data_update, rbio);
retry:
	bch2_trans_begin(trans);

	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = lockrestart_do(trans,
		bkey_err(k = bch2_bkey_get_iter(trans, &iter,
				u->btree_id, bkey_start_pos(&u->k.k->k),
				0)));
	if (ret)
		goto err;

	if (!bkey_and_val_eq(k, bkey_i_to_s_c(u->k.k))) {
		/* extent we wanted to read no longer exists: */
		rbio->ret = bch_err_throw(trans->c, data_read_key_overwritten);
		goto err;
	}

	ret = __bch2_read_extent(trans, rbio, bvec_iter,
				 bkey_start_pos(&u->k.k->k),
				 u->btree_id,
				 bkey_i_to_s_c(u->k.k),
				 0, failed, flags, -1);
err:
	bch2_trans_iter_exit(&iter);

	if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
	    bch2_err_matches(ret, BCH_ERR_data_read_retry))
		goto retry;

	if (ret) {
		rbio->bio.bi_status	= BLK_STS_IOERR;
		rbio->ret		= ret;
	}

	BUG_ON(atomic_read(&rbio->bio.__bi_remaining) != 1);
	return ret;
}

static void bch2_rbio_retry(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c	= rbio->c;
	struct bvec_iter iter	= rbio->bvec_iter;
	unsigned flags		= rbio->flags;
	subvol_inum inum = {
		.subvol = rbio->subvol,
		.inum	= rbio->read_pos.inode,
	};
	struct bch_io_failures failed = { .nr = 0 };

	CLASS(btree_trans, trans)(c);

	struct bkey_buf sk;
	bch2_bkey_buf_init(&sk);
	bkey_init(&sk.k->k);

	trace_io_read_retry(&rbio->bio);
	this_cpu_add(c->counters[BCH_COUNTER_io_read_retry],
		     bvec_iter_sectors(rbio->bvec_iter));

	get_rbio_extent(trans, rbio, &sk);

	if (!bkey_deleted(&sk.k->k) &&
	    bch2_err_matches(rbio->ret, BCH_ERR_data_read_retry_avoid))
		bch2_mark_io_failure(&failed, &rbio->pick,
				     rbio->ret == -BCH_ERR_data_read_retry_csum_err);

	if (!rbio->split) {
		rbio->bio.bi_status	= 0;
		rbio->ret		= 0;
	}

	unsigned subvol		= rbio->subvol;
	struct bpos read_pos	= rbio->read_pos;

	rbio = bch2_rbio_free(rbio);

	flags |= BCH_READ_in_retry;
	flags &= ~BCH_READ_may_promote;
	flags &= ~BCH_READ_last_fragment;
	flags |= BCH_READ_must_clone;

	int ret = rbio->data_update
		? bch2_read_retry_nodecode(trans, rbio, iter, &failed, flags)
		: __bch2_read(trans, rbio, iter, inum, &failed, &sk, flags);

	if (ret) {
		rbio->ret = ret;
		rbio->bio.bi_status = BLK_STS_IOERR;
	}

	if (failed.nr || ret) {
		CLASS(printbuf, buf)();
		bch2_log_msg_start(c, &buf);

		lockrestart_do(trans,
			bch2_inum_offset_err_msg_trans(trans, &buf,
					(subvol_inum) { subvol, read_pos.inode },
					read_pos.offset << 9));
		if (rbio->data_update)
			prt_str(&buf, "(internal move) ");

		prt_str(&buf, "data read error, ");
		if (!ret) {
			prt_str(&buf, "successful retry");
			if (rbio->self_healing)
				prt_str(&buf, ", self healing");
		} else
			prt_str(&buf, bch2_err_str(ret));
		prt_newline(&buf);


		if (!bkey_deleted(&sk.k->k)) {
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(sk.k));
			prt_newline(&buf);
		}

		bch2_io_failures_to_text(&buf, c, &failed);

		bch2_print_str_ratelimited(c, KERN_ERR, buf.buf);
	}

	bch2_rbio_done(rbio);
	bch2_bkey_buf_exit(&sk, c);
}

static void bch2_rbio_error(struct bch_read_bio *rbio,
			    int ret, blk_status_t blk_error)
{
	BUG_ON(ret >= 0);

	rbio->ret		= ret;
	rbio->bio.bi_status	= blk_error;

	bch2_rbio_parent(rbio)->saw_error = true;

	if (rbio->flags & BCH_READ_in_retry)
		return;

	if (bch2_err_matches(ret, BCH_ERR_data_read_retry)) {
		bch2_rbio_punt(rbio, bch2_rbio_retry,
			       RBIO_CONTEXT_UNBOUND, system_unbound_wq);
	} else {
		rbio = bch2_rbio_free(rbio);

		rbio->ret		= ret;
		rbio->bio.bi_status	= blk_error;

		bch2_rbio_done(rbio);
	}
}

static int __bch2_rbio_narrow_crcs(struct btree_trans *trans,
				   struct bch_read_bio *rbio)
{
	struct bch_fs *c = rbio->c;
	u64 data_offset = rbio->data_pos.offset - rbio->pick.crc.offset;
	int ret = 0;

	if (crc_is_compressed(rbio->pick.crc))
		return 0;

	CLASS(btree_iter, iter)(trans, rbio->data_btree, rbio->data_pos, BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	if ((ret = bkey_err(k)))
		return ret;

	if (bversion_cmp(k.k->bversion, rbio->version) ||
	    !bch2_bkey_matches_ptr(c, k, rbio->pick.ptr, data_offset))
		return 0;

	/* Extent was merged? */
	if (bkey_start_offset(k.k) < data_offset ||
	    k.k->p.offset > data_offset + rbio->pick.crc.uncompressed_size)
		return 0;

	struct bch_extent_crc_unpacked new_crc;
	if (bch2_rechecksum_bio(c, &rbio->bio, rbio->version,
			rbio->pick.crc, NULL, &new_crc,
			bkey_start_offset(k.k) - data_offset, k.k->size,
			rbio->pick.crc.csum_type)) {
		bch_err(c, "error verifying existing checksum while narrowing checksum (memory corruption?)");
		return 0;
	}

	/*
	 * going to be temporarily appending another checksum entry:
	 */
	struct bkey_i *new = bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
						sizeof(struct bch_extent_crc128));
	if ((ret = PTR_ERR_OR_ZERO(new)))
		return ret;

	bkey_reassemble(new, k);

	if (!bch2_bkey_narrow_crcs(new, new_crc))
		return 0;

	return bch2_trans_update(trans, &iter, new, BTREE_UPDATE_internal_snapshot_node);
}

static noinline void bch2_rbio_narrow_crcs(struct bch_read_bio *rbio)
{
	CLASS(btree_trans, trans)(rbio->c);
	commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		  __bch2_rbio_narrow_crcs(trans, rbio));
}

static void bch2_read_decompress_err(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c	= rbio->c;
	CLASS(printbuf, buf)();

	bch2_read_err_msg(c, &buf, rbio, rbio->read_pos);
	prt_str(&buf, "decompression error");

	struct bch_dev *ca = rbio->have_ioref ? bch2_dev_have_ref(c, rbio->pick.ptr.dev) : NULL;
	if (ca)
		bch_err_ratelimited(ca, "%s", buf.buf);
	else
		bch_err_ratelimited(c, "%s", buf.buf);

	bch2_rbio_error(rbio, -BCH_ERR_data_read_decompress_err, BLK_STS_IOERR);
}

static void bch2_read_decrypt_err(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c	= rbio->c;
	CLASS(printbuf, buf)();

	bch2_read_err_msg(c, &buf, rbio, rbio->read_pos);
	prt_str(&buf, "decrypt error");

	struct bch_dev *ca = rbio->have_ioref ? bch2_dev_have_ref(c, rbio->pick.ptr.dev) : NULL;
	if (ca)
		bch_err_ratelimited(ca, "%s", buf.buf);
	else
		bch_err_ratelimited(c, "%s", buf.buf);

	bch2_rbio_error(rbio, -BCH_ERR_data_read_decrypt_err, BLK_STS_IOERR);
}

/* Inner part that may run in process context */
static void __bch2_read_endio(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c	= rbio->c;
	struct bch_dev *ca = rbio->have_ioref ? bch2_dev_have_ref(c, rbio->pick.ptr.dev) : NULL;
	struct bch_read_bio *parent	= bch2_rbio_parent(rbio);
	struct bio *src			= &rbio->bio;
	struct bio *dst			= &parent->bio;
	struct bvec_iter dst_iter	= rbio->bvec_iter;
	struct bch_extent_crc_unpacked crc = rbio->pick.crc;
	struct nonce nonce = extent_nonce(rbio->version, crc);
	unsigned nofs_flags;
	struct bch_csum csum;
	int ret;

	nofs_flags = memalloc_nofs_save();

	/* Reset iterator for checksumming and copying bounced data: */
	if (rbio->bounce) {
		src->bi_iter.bi_size		= crc.compressed_size << 9;
		src->bi_iter.bi_idx		= 0;
		src->bi_iter.bi_bvec_done	= 0;
	} else {
		src->bi_iter			= rbio->bvec_iter;
	}

	bch2_maybe_corrupt_bio(src, bch2_read_corrupt_ratio);

	csum = bch2_checksum_bio(c, crc.csum_type, nonce, src);
	bool csum_good = !bch2_crc_cmp(csum, rbio->pick.crc.csum) || c->opts.no_data_io;

	/*
	 * Checksum error: if the bio wasn't bounced, we may have been
	 * reading into buffers owned by userspace (that userspace can
	 * scribble over) - retry the read, bouncing it this time:
	 */
	if (!csum_good && !rbio->bounce && (rbio->flags & BCH_READ_user_mapped)) {
		rbio->flags |= BCH_READ_must_bounce;
		bch2_rbio_error(rbio, -BCH_ERR_data_read_retry_csum_err_maybe_userspace,
				BLK_STS_IOERR);
		goto out;
	}

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_checksum, 0, csum_good);

	if (!csum_good)
		goto csum_err;

	/*
	 * XXX
	 * We need to rework the narrow_crcs path to deliver the read completion
	 * first, and then punt to a different workqueue, otherwise we're
	 * holding up reads while doing btree updates which is bad for memory
	 * reclaim.
	 */
	if (unlikely(rbio->narrow_crcs))
		bch2_rbio_narrow_crcs(rbio);

	if (likely(!parent->data_update)) {
		/* Adjust crc to point to subset of data we want: */
		crc.offset     += rbio->offset_into_extent;
		crc.live_size	= bvec_iter_sectors(rbio->bvec_iter);

		if (crc_is_compressed(crc)) {
			ret = bch2_encrypt_bio(c, crc.csum_type, nonce, src);
			if (ret)
				goto decrypt_err;

			if (bch2_bio_uncompress(c, src, dst, dst_iter, crc) &&
			    !c->opts.no_data_io)
				goto decompression_err;
		} else {
			/* don't need to decrypt the entire bio: */
			nonce = nonce_add(nonce, crc.offset << 9);
			bio_advance(src, crc.offset << 9);

			BUG_ON(src->bi_iter.bi_size < dst_iter.bi_size);
			src->bi_iter.bi_size = dst_iter.bi_size;

			ret = bch2_encrypt_bio(c, crc.csum_type, nonce, src);
			if (ret)
				goto decrypt_err;

			if (rbio->bounce) {
				struct bvec_iter src_iter = src->bi_iter;

				bio_copy_data_iter(dst, &dst_iter, src, &src_iter);
			}
		}
	} else {
		if (rbio->split)
			rbio->parent->pick = rbio->pick;

		if (rbio->bounce) {
			struct bvec_iter src_iter = src->bi_iter;

			bio_copy_data_iter(dst, &dst_iter, src, &src_iter);
		}
	}

	if (rbio->promote) {
		/*
		 * Re encrypt data we decrypted, so it's consistent with
		 * rbio->crc:
		 */
		ret = bch2_encrypt_bio(c, crc.csum_type, nonce, src);
		if (ret)
			goto decrypt_err;
	}

	if (likely(!(rbio->flags & BCH_READ_in_retry))) {
		rbio = bch2_rbio_free(rbio);
		bch2_rbio_done(rbio);
	}
out:
	memalloc_nofs_restore(nofs_flags);
	return;
csum_err:
	bch2_rbio_error(rbio, -BCH_ERR_data_read_retry_csum_err, BLK_STS_IOERR);
	goto out;
decompression_err:
	bch2_rbio_punt(rbio, bch2_read_decompress_err, RBIO_CONTEXT_UNBOUND, system_unbound_wq);
	goto out;
decrypt_err:
	bch2_rbio_punt(rbio, bch2_read_decrypt_err, RBIO_CONTEXT_UNBOUND, system_unbound_wq);
	goto out;
}

static void bch2_read_endio(struct bio *bio)
{
	struct bch_read_bio *rbio =
		container_of(bio, struct bch_read_bio, bio);
	struct bch_fs *c	= rbio->c;
	struct bch_dev *ca = rbio->have_ioref ? bch2_dev_have_ref(c, rbio->pick.ptr.dev) : NULL;
	struct workqueue_struct *wq = NULL;
	enum rbio_context context = RBIO_CONTEXT_NULL;

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read,
				   rbio->submit_time, !bio->bi_status);

	if (!rbio->split)
		rbio->bio.bi_end_io = rbio->end_io;

	if (unlikely(bio->bi_status)) {
		bch2_rbio_error(rbio, -BCH_ERR_data_read_retry_io_err, bio->bi_status);
		return;
	}

	if (((rbio->flags & BCH_READ_retry_if_stale) && race_fault()) ||
	    (ca && dev_ptr_stale(ca, &rbio->pick.ptr))) {
		trace_and_count(c, io_read_reuse_race, &rbio->bio);

		if (rbio->flags & BCH_READ_retry_if_stale)
			bch2_rbio_error(rbio, -BCH_ERR_data_read_ptr_stale_retry, BLK_STS_AGAIN);
		else
			bch2_rbio_error(rbio, -BCH_ERR_data_read_ptr_stale_race, BLK_STS_AGAIN);
		return;
	}

	if (rbio->narrow_crcs ||
	    rbio->promote ||
	    crc_is_compressed(rbio->pick.crc) ||
	    bch2_csum_type_is_encryption(rbio->pick.crc.csum_type))
		context = RBIO_CONTEXT_UNBOUND,	wq = system_unbound_wq;
	else if (rbio->pick.crc.csum_type)
		context = RBIO_CONTEXT_HIGHPRI,	wq = system_highpri_wq;

	bch2_rbio_punt(rbio, __bch2_read_endio, context, wq);
}

static noinline void read_from_stale_dirty_pointer(struct btree_trans *trans,
						   struct bch_dev *ca,
						   struct bkey_s_c k,
						   struct bch_extent_ptr ptr)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc,
				PTR_BUCKET_POS(ca, &ptr),
				BTREE_ITER_cached);

	int gen = bucket_gen_get(ca, iter.pos.offset);
	if (gen >= 0) {
		prt_printf(&buf, "Attempting to read from stale dirty pointer:\n");
		printbuf_indent_add(&buf, 2);

		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);

		prt_printf(&buf, "memory gen: %u", gen);

		int ret = lockrestart_do(trans, bkey_err(k = bch2_btree_iter_peek_slot(&iter)));
		if (!ret) {
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, k);
		}
	} else {
		prt_printf(&buf, "Attempting to read from invalid bucket %llu:%llu:\n",
			   iter.pos.inode, iter.pos.offset);
		printbuf_indent_add(&buf, 2);

		prt_printf(&buf, "first bucket %u nbuckets %llu\n",
			   ca->mi.first_bucket, ca->mi.nbuckets);

		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);
	}

	bch2_fs_inconsistent(c, "%s", buf.buf);
}

int __bch2_read_extent(struct btree_trans *trans, struct bch_read_bio *orig,
		       struct bvec_iter iter, struct bpos read_pos,
		       enum btree_id data_btree, struct bkey_s_c k,
		       unsigned offset_into_extent,
		       struct bch_io_failures *failed, unsigned flags, int dev)
{
	struct bch_fs *c = trans->c;
	struct extent_ptr_decoded pick;
	struct bch_read_bio *rbio = NULL;
	bool bounce = false, read_full = false, narrow_crcs = false;
	struct bpos data_pos = bkey_start_pos(k.k);
	struct data_update *u = rbio_data_update(orig);
	int ret = 0;

	if (bkey_extent_is_inline_data(k.k)) {
		unsigned bytes = min_t(unsigned, iter.bi_size,
				       bkey_inline_data_bytes(k.k));

		swap(iter.bi_size, bytes);
		memcpy_to_bio(&orig->bio, iter, bkey_inline_data_p(k));
		swap(iter.bi_size, bytes);
		bio_advance_iter(&orig->bio, &iter, bytes);
		zero_fill_bio_iter(&orig->bio, iter);
		this_cpu_add(c->counters[BCH_COUNTER_io_read_inline],
			     bvec_iter_sectors(iter));
		goto out_read_done;
	}

	if ((bch2_bkey_extent_flags(k) & BIT_ULL(BCH_EXTENT_FLAG_poisoned)) &&
	    !orig->data_update)
		return bch_err_throw(c, extent_poisoned);
retry_pick:
	ret = bch2_bkey_pick_read_device(c, k, failed, &pick, dev);

	/* hole or reservation - just zero fill: */
	if (!ret)
		goto hole;

	if (unlikely(ret < 0)) {
		if (ret == -BCH_ERR_data_read_csum_err) {
			int ret2 = maybe_poison_extent(trans, orig, data_btree, k);
			if (ret2) {
				ret = ret2;
				goto err;
			}

			trace_and_count(c, io_read_fail_and_poison, &orig->bio);
		}

		CLASS(printbuf, buf)();
		bch2_read_err_msg_trans(trans, &buf, orig, read_pos);
		prt_printf(&buf, "%s\n  ", bch2_err_str(ret));
		bch2_bkey_val_to_text(&buf, c, k);
		bch_err_ratelimited(c, "%s", buf.buf);
		goto err;
	}

	if (unlikely(bch2_csum_type_is_encryption(pick.crc.csum_type)) &&
	    !c->chacha20_key_set) {
		CLASS(printbuf, buf)();
		bch2_read_err_msg_trans(trans, &buf, orig, read_pos);
		prt_printf(&buf, "attempting to read encrypted data without encryption key\n  ");
		bch2_bkey_val_to_text(&buf, c, k);

		bch_err_ratelimited(c, "%s", buf.buf);
		ret = bch_err_throw(c, data_read_no_encryption_key);
		goto err;
	}

	struct bch_dev *ca = bch2_dev_get_ioref(c, pick.ptr.dev, READ,
					BCH_DEV_READ_REF_io_read);

	/*
	 * Stale dirty pointers are treated as IO errors, but @failed isn't
	 * allocated unless we're in the retry path - so if we're not in the
	 * retry path, don't check here, it'll be caught in bch2_read_endio()
	 * and we'll end up in the retry path:
	 */
	if ((flags & BCH_READ_in_retry) &&
	    !pick.ptr.cached &&
	    ca &&
	    unlikely(dev_ptr_stale(ca, &pick.ptr))) {
		read_from_stale_dirty_pointer(trans, ca, k, pick.ptr);
		bch2_mark_io_failure(failed, &pick, false);
		enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_io_read);
		goto retry_pick;
	}

	if (likely(!u)) {
		if (!(flags & BCH_READ_last_fragment) ||
		    bio_flagged(&orig->bio, BIO_CHAIN))
			flags |= BCH_READ_must_clone;

		narrow_crcs = !(flags & BCH_READ_in_retry) &&
			bch2_can_narrow_extent_crcs(k, pick.crc);

		if (narrow_crcs && (flags & BCH_READ_user_mapped))
			flags |= BCH_READ_must_bounce;

		EBUG_ON(offset_into_extent + bvec_iter_sectors(iter) > k.k->size);

		if (crc_is_compressed(pick.crc) ||
		    (pick.crc.csum_type != BCH_CSUM_none &&
		     (bvec_iter_sectors(iter) != pick.crc.uncompressed_size ||
		      (bch2_csum_type_is_encryption(pick.crc.csum_type) &&
		       (flags & BCH_READ_user_mapped)) ||
		      (flags & BCH_READ_must_bounce)))) {
			read_full = true;
			bounce = true;
		}
	} else {
		/*
		 * can happen if we retry, and the extent we were going to read
		 * has been merged in the meantime:
		 */
		if (pick.crc.compressed_size > u->op.wbio.bio.bi_iter.bi_size) {
			if (ca)
				enumerated_ref_put(&ca->io_ref[READ],
					BCH_DEV_READ_REF_io_read);
			rbio->ret = bch_err_throw(c, data_read_buffer_too_small);
			goto out_read_done;
		}

		iter.bi_size	= pick.crc.compressed_size << 9;
		read_full = true;
	}

	if (orig->opts.promote_target || have_io_error(failed))
		rbio = promote_alloc(trans, iter, k, &pick, flags, orig,
				     &bounce, &read_full, failed);

	if (!read_full) {
		EBUG_ON(crc_is_compressed(pick.crc));
		EBUG_ON(pick.crc.csum_type &&
			(bvec_iter_sectors(iter) != pick.crc.uncompressed_size ||
			 bvec_iter_sectors(iter) != pick.crc.live_size ||
			 pick.crc.offset ||
			 offset_into_extent));

		data_pos.offset += offset_into_extent;
		pick.ptr.offset += pick.crc.offset +
			offset_into_extent;
		offset_into_extent		= 0;
		pick.crc.compressed_size	= bvec_iter_sectors(iter);
		pick.crc.uncompressed_size	= bvec_iter_sectors(iter);
		pick.crc.offset			= 0;
		pick.crc.live_size		= bvec_iter_sectors(iter);
	}

	if (rbio) {
		/*
		 * promote already allocated bounce rbio:
		 * promote needs to allocate a bio big enough for uncompressing
		 * data in the write path, but we're not going to use it all
		 * here:
		 */
		EBUG_ON(rbio->bio.bi_iter.bi_size <
		       pick.crc.compressed_size << 9);
		rbio->bio.bi_iter.bi_size =
			pick.crc.compressed_size << 9;
	} else if (bounce) {
		unsigned sectors = pick.crc.compressed_size;

		rbio = rbio_init_fragment(bio_alloc_bioset(NULL,
						  DIV_ROUND_UP(sectors, PAGE_SECTORS),
						  0,
						  GFP_NOFS,
						  &c->bio_read_split),
				 orig);

		bch2_bio_alloc_pages_pool(c, &rbio->bio, sectors << 9);
		rbio->bounce	= true;
	} else if (flags & BCH_READ_must_clone) {
		/*
		 * Have to clone if there were any splits, due to error
		 * reporting issues (if a split errored, and retrying didn't
		 * work, when it reports the error to its parent (us) we don't
		 * know if the error was from our bio, and we should retry, or
		 * from the whole bio, in which case we don't want to retry and
		 * lose the error)
		 */
		rbio = rbio_init_fragment(bio_alloc_clone(NULL, &orig->bio, GFP_NOFS,
						 &c->bio_read_split),
				 orig);
		rbio->bio.bi_iter = iter;
	} else {
		rbio = orig;
		rbio->bio.bi_iter = iter;
		EBUG_ON(bio_flagged(&rbio->bio, BIO_CHAIN));
	}

	EBUG_ON(bio_sectors(&rbio->bio) != pick.crc.compressed_size);

	rbio->submit_time	= local_clock();
	if (!rbio->split)
		rbio->end_io	= orig->bio.bi_end_io;
	rbio->bvec_iter		= iter;
	rbio->offset_into_extent= offset_into_extent;
	rbio->flags		= flags;
	rbio->have_ioref	= ca != NULL;
	rbio->narrow_crcs	= narrow_crcs;
	rbio->ret		= 0;
	rbio->context		= 0;
	rbio->pick		= pick;
	rbio->subvol		= orig->subvol;
	rbio->read_pos		= read_pos;
	rbio->data_btree	= data_btree;
	rbio->data_pos		= data_pos;
	rbio->version		= k.k->bversion;
	INIT_WORK(&rbio->work, NULL);

	rbio->bio.bi_opf	= orig->bio.bi_opf;
	rbio->bio.bi_iter.bi_sector = pick.ptr.offset;
	rbio->bio.bi_end_io	= bch2_read_endio;

	async_object_list_add(c, rbio, rbio, &rbio->list_idx);

	/* XXX: also nvme read recovery level */
	if (unlikely(failed && bch2_dev_io_failures(failed, pick.ptr.dev)))
		rbio->bio.bi_opf |= REQ_FUA;

	if (rbio->bounce)
		trace_and_count(c, io_read_bounce, &rbio->bio);

	if (!u)
		this_cpu_add(c->counters[BCH_COUNTER_io_read], bio_sectors(&rbio->bio));
	else
		this_cpu_add(c->counters[BCH_COUNTER_io_move_read], bio_sectors(&rbio->bio));
	bch2_increment_clock(c, bio_sectors(&rbio->bio), READ);

	/*
	 * If it's being moved internally, we don't want to flag it as a cache
	 * hit:
	 */
	if (ca && pick.ptr.cached && !u)
		bch2_bucket_io_time_reset(trans, pick.ptr.dev,
			PTR_BUCKET_NR(ca, &pick.ptr), READ);

	if (!(flags & (BCH_READ_in_retry|BCH_READ_last_fragment))) {
		bio_inc_remaining(&orig->bio);
		trace_and_count(c, io_read_split, &orig->bio);
	}

	/*
	 * Unlock the iterator while the btree node's lock is still in
	 * cache, before doing the IO:
	 */
	if (!(flags & BCH_READ_in_retry))
		bch2_trans_unlock(trans);
	else
		bch2_trans_unlock_long(trans);

	if (likely(!rbio->pick.do_ec_reconstruct)) {
		if (unlikely(!rbio->have_ioref)) {
			bch2_rbio_error(rbio,
					-BCH_ERR_data_read_retry_device_offline,
					BLK_STS_IOERR);
			goto out;
		}

		this_cpu_add(ca->io_done->sectors[READ][BCH_DATA_user],
			     bio_sectors(&rbio->bio));
		bio_set_dev(&rbio->bio, ca->disk_sb.bdev);

		if (unlikely(c->opts.no_data_io)) {
			if (likely(!(flags & BCH_READ_in_retry)))
				bio_endio(&rbio->bio);
		} else {
			if (likely(!(flags & BCH_READ_in_retry)))
				submit_bio(&rbio->bio);
			else
				submit_bio_wait(&rbio->bio);
		}

		/*
		 * We just submitted IO which may block, we expect relock fail
		 * events and shouldn't count them:
		 */
		trans->notrace_relock_fail = true;
	} else {
		/* Attempting reconstruct read: */
		if (bch2_ec_read_extent(trans, rbio, k)) {
			bch2_rbio_error(rbio, -BCH_ERR_data_read_retry_ec_reconstruct_err,
					BLK_STS_IOERR);
			goto out;
		}

		if (likely(!(flags & BCH_READ_in_retry)))
			bio_endio(&rbio->bio);
	}
out:
	if (likely(!(flags & BCH_READ_in_retry))) {
		return 0;
	} else {
		bch2_trans_unlock(trans);

		int ret;

		rbio->context = RBIO_CONTEXT_UNBOUND;
		bch2_read_endio(&rbio->bio);

		ret = rbio->ret;
		rbio = bch2_rbio_free(rbio);

		if (bch2_err_matches(ret, BCH_ERR_data_read_retry_avoid))
			bch2_mark_io_failure(failed, &pick,
					ret == -BCH_ERR_data_read_retry_csum_err);

		return ret;
	}

err:
	if (flags & BCH_READ_in_retry)
		return ret;

	orig->bio.bi_status	= BLK_STS_IOERR;
	orig->ret		= ret;
	goto out_read_done;

hole:
	this_cpu_add(c->counters[BCH_COUNTER_io_read_hole],
		     bvec_iter_sectors(iter));
	/*
	 * won't normally happen in the data update (bch2_move_extent()) path,
	 * but if we retry and the extent we wanted to read no longer exists we
	 * have to signal that:
	 */
	if (u)
		orig->ret = bch_err_throw(c, data_read_key_overwritten);

	zero_fill_bio_iter(&orig->bio, iter);
out_read_done:
	if ((flags & BCH_READ_last_fragment) &&
	    !(flags & BCH_READ_in_retry))
		bch2_rbio_done(orig);
	return 0;
}

int __bch2_read(struct btree_trans *trans, struct bch_read_bio *rbio,
		struct bvec_iter bvec_iter, subvol_inum inum,
		struct bch_io_failures *failed,
		struct bkey_buf *prev_read,
		unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct bkey_buf sk;
	struct bkey_s_c k;
	enum btree_id data_btree;
	int ret;

	EBUG_ON(rbio->data_update);

	bch2_bkey_buf_init(&sk);
	CLASS(btree_iter, iter)(trans, BTREE_ID_extents,
				POS(inum.inum, bvec_iter.bi_sector),
				BTREE_ITER_slots);

	while (1) {
		data_btree = BTREE_ID_extents;

		bch2_trans_begin(trans);

		u32 snapshot;
		ret = bch2_subvolume_get_snapshot(trans, inum.subvol, &snapshot);
		if (ret)
			goto err;

		bch2_btree_iter_set_snapshot(&iter, snapshot);

		bch2_btree_iter_set_pos(&iter,
				POS(inum.inum, bvec_iter.bi_sector));

		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		s64 offset_into_extent = iter.pos.offset -
			bkey_start_offset(k.k);
		unsigned sectors = k.k->size - offset_into_extent;

		bch2_bkey_buf_reassemble(&sk, c, k);

		ret = bch2_read_indirect_extent(trans, &data_btree,
					&offset_into_extent, &sk);
		if (ret)
			goto err;

		k = bkey_i_to_s_c(sk.k);

		if (unlikely(flags & BCH_READ_in_retry)) {
			if (!bkey_and_val_eq(k, bkey_i_to_s_c(prev_read->k)))
				failed->nr = 0;
			bch2_bkey_buf_copy(prev_read, c, sk.k);
		}

		/*
		 * With indirect extents, the amount of data to read is the min
		 * of the original extent and the indirect extent:
		 */
		sectors = min_t(unsigned, sectors, k.k->size - offset_into_extent);

		unsigned bytes = min(sectors, bvec_iter_sectors(bvec_iter)) << 9;
		swap(bvec_iter.bi_size, bytes);

		if (bvec_iter.bi_size == bytes)
			flags |= BCH_READ_last_fragment;

		ret = __bch2_read_extent(trans, rbio, bvec_iter, iter.pos,
					 data_btree, k,
					 offset_into_extent, failed, flags, -1);
		swap(bvec_iter.bi_size, bytes);

		if (ret)
			goto err;

		if (flags & BCH_READ_last_fragment)
			break;

		bio_advance_iter(&rbio->bio, &bvec_iter, bytes);
err:
		if (ret == -BCH_ERR_data_read_retry_csum_err_maybe_userspace)
			flags |= BCH_READ_must_bounce;

		if (ret &&
		    !bch2_err_matches(ret, BCH_ERR_transaction_restart) &&
		    !bch2_err_matches(ret, BCH_ERR_data_read_retry))
			break;
	}

	if (unlikely(ret)) {
		if (ret != -BCH_ERR_extent_poisoned) {
			CLASS(printbuf, buf)();
			lockrestart_do(trans,
				       bch2_inum_offset_err_msg_trans(trans, &buf, inum,
								      bvec_iter.bi_sector << 9));
			prt_printf(&buf, "data read error: %s", bch2_err_str(ret));
			bch_err_ratelimited(c, "%s", buf.buf);
		}

		rbio->bio.bi_status	= BLK_STS_IOERR;
		rbio->ret		= ret;

		if (!(flags & BCH_READ_in_retry))
			bch2_rbio_done(rbio);
	}

	bch2_bkey_buf_exit(&sk, c);
	return ret;
}

static const char * const bch2_read_bio_flags[] = {
#define x(n)	#n,
	BCH_READ_FLAGS()
#undef x
	NULL
};

void bch2_read_bio_to_text(struct printbuf *out,
			   struct bch_fs *c,
			   struct bch_read_bio *rbio)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 20);

	bch2_read_err_msg(c, out, rbio, rbio->read_pos);
	prt_newline(out);

	/* Are we in a retry? */

	printbuf_indent_add(out, 2);

	u64 now = local_clock();
	prt_printf(out, "start_time:\t");
	bch2_pr_time_units(out, max_t(s64, 0, now - rbio->start_time));
	prt_newline(out);

	prt_printf(out, "submit_time:\t");
	bch2_pr_time_units(out, max_t(s64, 0, now - rbio->submit_time));
	prt_newline(out);

	if (!rbio->split)
		prt_printf(out, "end_io:\t%ps\n", rbio->end_io);
	else
		prt_printf(out, "parent:\t%px\n", rbio->parent);

	prt_printf(out, "promote:\t%u\n",	rbio->promote);
	prt_printf(out, "bounce:\t%u\n",	rbio->bounce);
	prt_printf(out, "split:\t%u\n",		rbio->split);
	prt_printf(out, "have_ioref:\t%u\n",	rbio->have_ioref);
	prt_printf(out, "narrow_crcs:\t%u\n",	rbio->narrow_crcs);
	prt_printf(out, "context:\t%u\n",	rbio->context);

	int ret = READ_ONCE(rbio->ret);
	if (ret < 0)
		prt_printf(out, "ret:\t%s\n",		bch2_err_str(ret));
	else
		prt_printf(out, "ret:\t%i\n",		ret);

	prt_printf(out, "flags:\t");
	bch2_prt_bitflags(out, bch2_read_bio_flags, rbio->flags);
	prt_newline(out);

	bch2_bio_to_text(out, &rbio->bio);
	printbuf_indent_sub(out, 2);
}

void bch2_fs_io_read_exit(struct bch_fs *c)
{
	if (c->promote_table.tbl)
		rhashtable_destroy(&c->promote_table);
	bioset_exit(&c->bio_read_split);
	bioset_exit(&c->bio_read);
	mempool_exit(&c->bio_bounce_pages);
}

int bch2_fs_io_read_init(struct bch_fs *c)
{
	if (mempool_init_page_pool(&c->bio_bounce_pages,
				   max_t(unsigned,
					 c->opts.btree_node_size,
					 c->opts.encoded_extent_max) /
				   PAGE_SIZE, 0))
		return bch_err_throw(c, ENOMEM_bio_bounce_pages_init);

	if (bioset_init(&c->bio_read, 1, offsetof(struct bch_read_bio, bio),
			BIOSET_NEED_BVECS))
		return bch_err_throw(c, ENOMEM_bio_read_init);

	if (bioset_init(&c->bio_read_split, 1, offsetof(struct bch_read_bio, bio),
			BIOSET_NEED_BVECS))
		return bch_err_throw(c, ENOMEM_bio_read_split_init);

	if (rhashtable_init(&c->promote_table, &bch_promote_params))
		return bch_err_throw(c, ENOMEM_promote_table_init);

	return 0;
}
