// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/interior.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/compress.h"
#include "data/copygc.h"
#include "data/ec/trigger.h"
#include "data/move.h"
#include "data/reconcile/work.h"
#include "data/write.h"

#include "init/error.h"
#include "init/progress.h"

#include "fs/inode.h"
#include "fs/namei.h"

#include "sb/counters.h"
#include "snapshots/subvolume.h"

#include "util/clock.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/sched/cputime.h>

#define RECONCILE_PHASE_TYPES()		\
	x(scan)				\
	x(btree)			\
	x(phys)				\
	x(normal)			\

enum reconcile_phase_type {
#define x(n)	RECONCILE_PHASE_##n,
	RECONCILE_PHASE_TYPES()
#undef x
};

#define x(n) #n,

const char * const bch2_reconcile_opts[] = {
	BCH_RECONCILE_OPTS()
	NULL
};

static const char * const bch2_reconcile_work_ids[] = {
	RECONCILE_WORK_IDS()
	NULL
};

static const char * const bch2_rebalance_scan_strs[] = {
	RECONCILE_SCAN_TYPES()
};

static const char * const bch2_reconcile_phase_types[] = {
	RECONCILE_PHASE_TYPES()
};

#undef x

static bool btree_is_reconcile_phys(enum btree_id btree)
{
	return btree == BTREE_ID_reconcile_hipri_phys ||
		btree == BTREE_ID_reconcile_work_phys;
}

static u64 reconcile_scan_encode(struct reconcile_scan s)
{
	switch (s.type) {
	case RECONCILE_SCAN_fs:
		return RECONCILE_SCAN_COOKIE_fs;
	case RECONCILE_SCAN_metadata:
		return RECONCILE_SCAN_COOKIE_metadata;
	case RECONCILE_SCAN_pending:
		return RECONCILE_SCAN_COOKIE_pending;
	case RECONCILE_SCAN_device:
		return RECONCILE_SCAN_COOKIE_device + s.dev;
	case RECONCILE_SCAN_inum:
		return s.inum;
	default:
		BUG();
	}
}

static struct reconcile_scan reconcile_scan_decode(struct bch_fs *c, u64 v)
{
	if (v >= BCACHEFS_ROOT_INO)
		return (struct reconcile_scan) { .type = RECONCILE_SCAN_inum, .inum = v, };
	if (v >= RECONCILE_SCAN_COOKIE_device)
		return (struct reconcile_scan) {
			.type = RECONCILE_SCAN_device,
			.dev =  v - RECONCILE_SCAN_COOKIE_device,
		};
	if (v == RECONCILE_SCAN_COOKIE_pending)
		return (struct reconcile_scan) { .type = RECONCILE_SCAN_pending };
	if (v == RECONCILE_SCAN_COOKIE_metadata)
		return (struct reconcile_scan) { .type = RECONCILE_SCAN_metadata };
	if (v == RECONCILE_SCAN_COOKIE_fs)
		return (struct reconcile_scan) { .type = RECONCILE_SCAN_fs};

	bch_err(c, "unknown realance scan cookie %llu", v);
	return (struct reconcile_scan) { .type = RECONCILE_SCAN_fs};
}

static void reconcile_scan_to_text(struct printbuf *out,
				   struct bch_fs *c, struct reconcile_scan s)
{
	prt_str(out, bch2_rebalance_scan_strs[s.type]);
	switch (s.type) {
	case RECONCILE_SCAN_device:
		prt_str(out, ": ");
		bch2_prt_member_name(out, c, s.dev);
		break;
	case RECONCILE_SCAN_inum:
		prt_str(out, ": ");
		bch2_trans_do(c, bch2_inum_snapshot_to_path(trans, s.inum, 0, NULL, out));
		break;
	default:
		break;
	}
}

int bch2_set_reconcile_needs_scan_trans(struct btree_trans *trans, struct reconcile_scan s)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan,
				POS(0, reconcile_scan_encode(s)),
				BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	u64 v = k.k->type == KEY_TYPE_cookie
		? le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie)
		: 0;

	struct bkey_i_cookie *cookie = errptr_try(bch2_trans_kmalloc(trans, sizeof(*cookie)));

	bkey_cookie_init(&cookie->k_i);
	cookie->k.p = iter.pos;
	cookie->v.cookie = cpu_to_le64(v + 1);

	return bch2_trans_update(trans, &iter, &cookie->k_i, 0);
}

int bch2_set_reconcile_needs_scan(struct bch_fs *c, struct reconcile_scan s, bool wakeup)
{
	CLASS(btree_trans, trans)(c);
	try(commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		      bch2_set_reconcile_needs_scan_trans(trans, s)));
	if (wakeup)
		bch2_reconcile_wakeup(c);
	return 0;
}

int bch2_set_fs_needs_reconcile(struct bch_fs *c)
{
	return bch2_set_reconcile_needs_scan(c,
				(struct reconcile_scan) { .type = RECONCILE_SCAN_fs },
				true);
}

static int bch2_clear_reconcile_needs_scan(struct btree_trans *trans, struct bpos pos, u64 cookie)
{
	struct bch_fs *c = trans->c;
	u64 v;

	try(commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, pos, BTREE_ITER_intent);
		struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

		v = k.k->type == KEY_TYPE_cookie
			? le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie)
			: 0;
		v == cookie
			? bch2_btree_delete_at(trans, &iter, 0)
			: 0;
	})));

	event_inc_trace(c, reconcile_clear_scan, buf, ({
		reconcile_scan_to_text(&buf, c, reconcile_scan_decode(c, pos.offset));
		prt_newline(&buf);
		prt_printf(&buf, "scan started with cookie %llu now have %llu", cookie, v);
		prt_printf(&buf, "%sdeleting scan cookie\n", v == cookie ? "" : "not ");
	}));
	return 0;
}

#define RECONCILE_WORK_BUF_NR		1024
DEFINE_DARRAY_NAMED(darray_reconcile_work, struct bkey_i);

static struct bkey_s_c next_reconcile_entry(struct btree_trans *trans,
					    darray_reconcile_work *buf,
					    struct bbpos *work_pos,
					    struct bpos end)
{
	enum btree_iter_update_trigger_flags flags = BTREE_ITER_prefetch;

	if (btree_type_has_snapshots(work_pos->btree))
		flags |= BTREE_ITER_all_snapshots;

	if (work_pos->btree == BTREE_ID_reconcile_scan) {
		buf->nr = 0;

		int ret = for_each_btree_key_max(trans, iter, work_pos->btree, work_pos->pos, end,
				   flags, k, ({
			bkey_reassemble(&darray_top(*buf), k);
			return bkey_i_to_s_c(&darray_top(*buf));
			0;
		}));

		return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
	}

	if (unlikely(!buf->nr)) {
		/* Avoid contention with write buffer flush: buffer up work entries in a darray */

		BUG_ON(!buf->size);;

		int ret = for_each_btree_key_max(trans, iter, work_pos->btree, work_pos->pos, end,
				   flags, k, ({
			bch2_progress_update_iter(trans, &trans->c->reconcile.progress, &iter);

			/* There might be leftover scan cookies from rebalance, pre reconcile upgrade: */
			if (k.k->type != KEY_TYPE_set)
				continue;

			BUG_ON(bkey_bytes(k.k) > sizeof(buf->data[0]));

			/* we previously used darray_make_room */
			bkey_reassemble(&darray_top(*buf), k);
			buf->nr++;

			work_pos->pos = bpos_successor(iter.pos);
			if (buf->nr == buf->size)
				break;
			0;
		}));
		if (ret)
			return bkey_s_c_err(ret);

		if (!buf->nr)
			return bkey_s_c_null;

		unsigned l = 0, r = buf->nr - 1;
		while (l < r) {
			swap(buf->data[l], buf->data[r]);
			l++;
			--r;
		}
	}

	return bkey_i_to_s_c(&darray_pop(buf));
}

static int extent_ec_pending(struct btree_trans *trans, struct bkey_ptrs_c ptrs)
{
	struct bch_fs *c = trans->c;

	guard(rcu)();
	bkey_for_each_ptr(ptrs, ptr) {
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, ptr->dev);
		if (!ca)
			continue;

		struct bpos bucket = PTR_BUCKET_POS(ca, ptr);
		if (bch2_bucket_has_new_stripe(c, bucket_to_u64(bucket)))
			return true;
	}
	return false;
}

static int bch2_extent_reconcile_pending_mod(struct btree_trans *, struct btree_iter *,
					     unsigned, struct bkey_s_c, bool);

static int reconcile_set_data_opts(struct btree_trans *trans,
				   struct btree_iter *iter,
				   unsigned level,
				   struct bkey_s_c k,
				   struct bch_inode_opts *opts,
				   struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	const struct bch_extent_reconcile *r = bch2_bkey_reconcile_opts(c, k);
	if (!r || !r->need_rb) /* Write buffer race? */
		return 0;

	data_opts->type			= BCH_DATA_UPDATE_reconcile;
	data_opts->target		= r->background_target;

	/*
	 * we can't add/drop replicas from btree nodes incrementally, we always
	 * need to be able to spill over to the whole fs
	 */
	if (!r->hipri && !bkey_is_btree_ptr(k.k))
		data_opts->write_flags |= BCH_WRITE_only_specified_devs;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;

	unsigned csum_type = bch2_data_checksum_type_rb(c, *r);
	unsigned compression_type = bch2_compression_opt_to_type(r->background_compression);

	if (r->need_rb & BIT(BCH_RECONCILE_data_replicas)) {
		struct bkey_durability durability;
		try(bch2_bkey_durability(trans, k, &durability));

		unsigned ptr_bit = 1;

		if (durability.total <= r->data_replicas) {
			guard(rcu)();

			bkey_for_each_ptr(ptrs, ptr) {
				if (bch2_dev_bad_or_evacuating(c, ptr->dev))
					data_opts->ptrs_kill |= ptr_bit;
				ptr_bit <<= 1;
			}
		} else {
			if (durability.total != durability.online) {
				/* Try dropping offline devices first */
				bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
					if (p.ptr.dev == BCH_SB_MEMBER_INVALID ||
					    !test_bit(p.ptr.dev, c->devs_online.d)) {
						int d = bch2_extent_ptr_durability(trans, &p);
						if (d < 0)
							return d;

						if (bch2_dev_bad_or_evacuating(c, p.ptr.dev) ||
						    (!p.ptr.cached &&
						     d && durability.total - d >= r->data_replicas)) {
							data_opts->ptrs_kill |= ptr_bit;
							durability.total -= d;
						}
					}

					ptr_bit <<= 1;
				}

				/* Stripe ec? */
				ptr_bit = 1;
				bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
					if (p.ptr.dev == BCH_SB_MEMBER_INVALID ||
					    !test_bit(p.ptr.dev, c->devs_online.d)) {
						if (p.has_ec && durability.total - p.ec.redundancy >= r->data_replicas) {
							data_opts->ptrs_kill_ec |= ptr_bit;
							durability.total -= p.ec.redundancy;
						}
					}

					ptr_bit <<= 1;
				}
			}

			/* Don't let online durability go below data_replicas */

			/* Drop entire pointers? */
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				int d = bch2_extent_ptr_durability(trans, &p);
				if (d < 0)
					return d;

				if (bch2_dev_bad_or_evacuating(c, p.ptr.dev) ||
				    (!p.ptr.cached &&
				     d && durability.online - d >= r->data_replicas)) {
					data_opts->ptrs_kill |= ptr_bit;
					durability.online -= d;
				}

				ptr_bit <<= 1;
			}

			/* Stripe ec? */
			ptr_bit = 1;
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				if (p.has_ec && durability.online - p.ec.redundancy >= r->data_replicas) {
					data_opts->ptrs_kill_ec |= ptr_bit;
					durability.online -= p.ec.redundancy;
				}

				ptr_bit <<= 1;
			}
		}
	}

	if (r->need_rb & BIT(BCH_RECONCILE_erasure_code)) {
		if (r->erasure_code) {
			/* XXX: we'll need ratelimiting */
			if (extent_ec_pending(trans, ptrs))
				return false;

			data_opts->extra_replicas = 1;
			data_opts->no_devs_have = true;

			if (r->need_rb == BIT(BCH_RECONCILE_erasure_code))
				data_opts->write_flags |= BCH_WRITE_must_ec;
		} else {
			unsigned ptr_bit = 1;
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				if (p.has_ec)
					data_opts->ptrs_kill_ec |= ptr_bit;

				ptr_bit <<= 1;
			}
		}
	}

	scoped_guard(rcu) {
		unsigned ptr_bit = 1;
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if ((r->need_rb & BIT(BCH_RECONCILE_data_checksum)) &&
			    p.crc.csum_type != csum_type)
				data_opts->ptrs_kill |= ptr_bit;

			if ((r->need_rb & BIT(BCH_RECONCILE_background_compression)) &&
			    p.crc.compression_type != compression_type)
				data_opts->ptrs_kill |= ptr_bit;

			if ((r->need_rb & BIT(BCH_RECONCILE_background_target)) &&
			    !p.ptr.cached &&
			    !bch2_dev_in_target_rcu(c, p.ptr.dev, r->background_target))
				data_opts->ptrs_kill |= ptr_bit;

			ptr_bit <<= 1;
		}
	}

	bool ret = (data_opts->ptrs_kill ||
		    data_opts->ptrs_kill_ec ||
		    data_opts->extra_replicas);
	if (!ret) {
		if (r->need_rb == BIT(BCH_RECONCILE_data_replicas)) {
			/*
			 * We can end up here because you have all devices set
			 * to durability=2 and replicas set to 1, 3 - we can't
			 * exactly match the replicas setting - or because we
			 * want to drop replicas and we can't without reducing
			 * online durability
			 */
			return bch2_extent_reconcile_pending_mod(trans, iter, level, k, true);
		} else {
			CLASS(bch_log_msg_ratelimited, msg)(c);
			prt_printf(&msg.m, "got extent to reconcile but nothing to do, confused\n  ");
			bch2_bkey_val_to_text(&msg.m, c, k);
		}
	}

	return ret;
}

static void bkey_reconcile_pending_mod(struct bch_fs *c, struct bkey_i *k, bool set)
{
	struct bch_extent_reconcile *r = (struct bch_extent_reconcile *)
		bch2_bkey_reconcile_opts(c, bkey_i_to_s_c(k));
	BUG_ON(!r);

	r->pending = set;
}

static int bch2_extent_reconcile_pending_mod(struct btree_trans *trans, struct btree_iter *iter,
					     unsigned level, struct bkey_s_c k, bool set)
{
	struct bch_fs *c = trans->c;

	if ((rb_work_id(bch2_bkey_reconcile_opts(c, k)) == RECONCILE_WORK_pending) == set)
		return 0;

	try(bch2_trans_relock(trans));

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k)));
	bkey_reassemble(n, k);

	if (!level) {
		bkey_reconcile_pending_mod(c, n, set);

		return  bch2_trans_update(trans, iter, n, 0) ?:
			bch2_trans_commit(trans, NULL, NULL,
					  BCH_TRANS_COMMIT_no_enospc);
	} else {
		CLASS(btree_node_iter, iter2)(trans, iter->btree_id, k.k->p, 0, level - 1, 0);
		struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter2));

		if (!btree_bkey_and_val_eq(bkey_i_to_s_c(&b->key), bkey_i_to_s_c(n))) {
			CLASS(printbuf, buf)();
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, k);
			panic("\n%s\n", buf.buf);
		}

		bkey_reconcile_pending_mod(c, n, set);

		return bch2_btree_node_update_key(trans, &iter2, b, n, BCH_TRANS_COMMIT_no_enospc, false);
	}
}

static int check_reconcile_pending_err(struct btree_trans *trans,
				       struct bch_inode_opts *opts,
				       struct data_update_opts *data_opts,
				       struct bkey_s_c k, int err)
{
	struct bch_fs *c = trans->c;

	 if (!bch2_err_matches(err, BCH_ERR_data_update_fail_no_rw_devs) &&
	     !bch2_err_matches(err, BCH_ERR_insufficient_devices) &&
	     !bch2_err_matches(err, ENOSPC))
		 return err;

	event_add_trace(c, reconcile_set_pending, k.k->size, buf, ({
		prt_printf(&buf, "%s\n", bch2_err_str(err));
		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);
		bch2_data_update_opts_to_text(&buf, c, opts, data_opts);
		prt_newline(&buf);
		int ret = bch2_can_do_data_update(trans, opts, data_opts, k, &buf);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ret;
	}));
	return 1;
}

static int __do_reconcile_extent(struct moving_context *ctxt,
				 struct per_snapshot_io_opts *snapshot_io_opts,
				 struct bch_inode_opts *opts,
				 struct data_update_opts *data_opts,
				 struct bbpos work,
				 struct btree_iter *iter,
				 unsigned level,
				 struct bkey_s_c k)
{
	if (!bkey_extent_is_direct_data(k.k))
		return 0;

	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	u32 restart_count = trans->restart_count;

	ctxt->stats = &c->reconcile.work_stats;

	try(bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, opts));
	try(bch2_update_reconcile_opts(trans, snapshot_io_opts, opts, iter, level, k,
				       SET_NEEDS_RECONCILE_other));

	CLASS(disk_reservation, res)(c);
	try(bch2_trans_commit_lazy(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc));

	int ret = reconcile_set_data_opts(trans, iter, level, k, opts, data_opts);
	if (ret <= 0)
		return ret;

	if (work.btree == BTREE_ID_reconcile_pending) {
		int ret = bch2_can_do_data_update(trans, opts, data_opts, k, NULL);
		ret = check_reconcile_pending_err(trans, opts, data_opts, k, ret);
		if (ret > 0)
			return 0;
		if (ret)
			return ret;

		if (extent_has_rotational(c, k)) {
			/*
			 * The pending list is in logical inode:offset order,
			 * but if the extent is on spinning rust we want do it
			 * in device LBA order.
			 *
			 * Just take it off the pending list for now, and we'll
			 * pick it up when we scan reconcile_work_phys:
			 */
			return bch2_extent_reconcile_pending_mod(trans, iter, level, k, false);
		}
	}

	ret = bch2_move_extent(ctxt, NULL, opts, data_opts, iter, level, k);
	BUG_ON(ret > 0);
	ret = check_reconcile_pending_err(trans, opts, data_opts, k, ret);
	if (ret > 0)
		return bch2_extent_reconcile_pending_mod(trans, iter, level, k, true);
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
	    bch2_err_matches(ret, BCH_ERR_data_update_fail_need_copygc))
		return ret;
	if (ret) {
		WARN_ONCE(!bch2_err_matches(ret, EROFS) &&
			  ret != -BCH_ERR_data_update_fail_no_snapshot &&
			  ret != -BCH_ERR_data_update_fail_in_flight,
			  "unhandled error from move_extent: %s", bch2_err_str(ret));
		/* skip it and continue */
	}

	/*
	 * Suppress trans_was_restarted() check: read_extent -> ec retry will
	 * handle transaction restarts, and we don't care:
	 */
	trans->restart_count = restart_count;
	return 0;
}

static int do_reconcile_extent(struct moving_context *ctxt,
			       struct per_snapshot_io_opts *snapshot_io_opts,
			       struct bbpos work)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bbpos data_pos = rb_work_to_data_pos(work.pos);

	CLASS(btree_iter, iter)(trans, data_pos.btree, data_pos.pos, BTREE_ITER_all_snapshots);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));
	if (!k.k)
		return 0;

	struct bkey_buf stack_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&stack_k);
	bch2_bkey_buf_reassemble(&stack_k, k);

	struct bch_inode_opts opts;
	struct data_update_opts data_opts = {};
	try(__do_reconcile_extent(ctxt, snapshot_io_opts, &opts, &data_opts, work, &iter, 0, k));

	event_add_trace(c, reconcile_data, stack_k.k->k.size, buf, ({
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(stack_k.k));
		prt_newline(&buf);
		bch2_data_update_opts_to_text(&buf, c, &opts, &data_opts);
	}));
	return 0;
}

static int do_reconcile_extent_phys(struct moving_context *ctxt,
				    struct per_snapshot_io_opts *snapshot_io_opts,
				    struct bbpos work,
				    struct wb_maybe_flush *last_flushed)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	CLASS(btree_iter, bp_iter)(trans, BTREE_ID_backpointers, work.pos, 0);
	struct bkey_s_c bp_k = bkey_try(bch2_btree_iter_peek_slot(&bp_iter));
	if (!bp_k.k || bp_k.k->type != KEY_TYPE_backpointer) /* write buffer race */
		return 0;

	struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(bp_k);

	struct bbpos pos = BBPOS(bp.v->btree_id, bp.v->pos);
	if (bch2_data_update_in_flight(c, &pos))
		return 0;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_backpointer_get_key(trans, bp, &iter, 0, last_flushed));
	if (!k.k)
		return 0;

	struct bkey_buf stack_bp __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&stack_bp);
	bch2_bkey_buf_reassemble(&stack_bp, bp_k);

	struct bkey_buf stack_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&stack_k);
	bch2_bkey_buf_reassemble(&stack_k, k);

	struct bch_inode_opts opts;
	struct data_update_opts data_opts = {
		.read_dev	= work.pos.inode,
		.read_flags	= BCH_READ_soft_require_read_device,
	};
	try(__do_reconcile_extent(ctxt, snapshot_io_opts, &opts, &data_opts, work, &iter, bp.v->level, k));

	event_add_trace(c, reconcile_phys, k.k->size, buf, ({
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(stack_bp.k));
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(stack_k.k));
		prt_newline(&buf);
		bch2_data_update_opts_to_text(&buf, c, &opts, &data_opts);
	}));

	return 0;
}

noinline_for_stack
static int do_reconcile_btree(struct moving_context *ctxt,
			      struct per_snapshot_io_opts *snapshot_io_opts,
			      struct bbpos work,
			      struct bkey_s_c_backpointer bp)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(reconcile_bp_get_key(trans, &iter, bp));
	if (!k.k)
		return 0;

	struct bkey_buf stack_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&stack_k);
	bch2_bkey_buf_reassemble(&stack_k, k);

	struct bch_inode_opts opts;
	struct data_update_opts data_opts = {};
	try(__do_reconcile_extent(ctxt, snapshot_io_opts, &opts, &data_opts, work, &iter, bp.v->level, k));

	event_add_trace(c, reconcile_btree, btree_sectors(c), buf, ({
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(stack_k.k));
		prt_newline(&buf);
		bch2_data_update_opts_to_text(&buf, c, &opts, &data_opts);
	}));

	return 0;
}

static int update_reconcile_opts_scan(struct btree_trans *trans,
				      struct per_snapshot_io_opts *snapshot_io_opts,
				      struct bch_inode_opts *opts,
				      struct btree_iter *iter,
				      unsigned level,
				      struct bkey_s_c k,
				      struct reconcile_scan s)
{
	switch (s.type) {
#define x(n) case RECONCILE_SCAN_##n:						\
		event_add_trace(trans->c, reconcile_scan_##n, k.k->size,	\
				buf, bch2_bkey_val_to_text(&buf, trans->c, k));	\
		break;
		RECONCILE_SCAN_TYPES()
#undef x
	}

	return bch2_update_reconcile_opts(trans, snapshot_io_opts, opts, iter, level, k,
					  SET_NEEDS_RECONCILE_opt_change);
}

static bool bch2_reconcile_enabled(struct bch_fs *c)
{
	return !c->opts.read_only &&
		c->opts.reconcile_enabled &&
		!(c->opts.reconcile_on_ac_only &&
		  c->reconcile.on_battery);
}

static int do_reconcile_scan_bp(struct btree_trans *trans,
				struct reconcile_scan s,
				struct bkey_s_c_backpointer bp,
				struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_backpointer_get_key(trans, bp, &iter, BTREE_ITER_intent,
							      last_flushed));
	if (!k.k)
		return 0;

	atomic64_add(!bp.v->level ? k.k->size : c->opts.btree_node_size >> 9,
		     &r->scan_stats.sectors_seen);

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));

	return update_reconcile_opts_scan(trans, NULL, &opts, &iter, bp.v->level, k, s);
}

static int do_reconcile_scan_bps(struct moving_context *ctxt,
				 struct reconcile_scan s,
				 struct wb_maybe_flush *last_flushed)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;

	r->scan_start	= BBPOS(BTREE_ID_backpointers, POS(s.dev, 0));
	r->scan_end	= BBPOS(BTREE_ID_backpointers, POS(s.dev, U64_MAX));

	bch2_btree_write_buffer_flush_sync(trans);

	return backpointer_scan_for_each(trans, iter, POS(s.dev, 0), POS(s.dev, U64_MAX),
				  last_flushed, NULL, bp, ({
		ctxt->stats->pos = BBPOS(BTREE_ID_backpointers, iter.pos);

		if (kthread_should_stop() || !bch2_reconcile_enabled(c))
			break;

		CLASS(disk_reservation, res)(c);
		do_reconcile_scan_bp(trans, s, bp, last_flushed) ?:
		bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc);
	}));
}

static int do_reconcile_scan_indirect(struct moving_context *ctxt,
				      struct reconcile_scan s,
				      struct disk_reservation *res,
				      struct bkey_s_c_reflink_p p,
				      struct per_snapshot_io_opts *snapshot_io_opts,
				      struct bch_inode_opts *opts)
{
	struct btree_trans *trans = ctxt->trans;

	u64 idx = REFLINK_P_IDX(p.v) - le32_to_cpu(p.v->front_pad);
	u64 end = REFLINK_P_IDX(p.v) + p.k->size + le32_to_cpu(p.v->back_pad);
	u32 restart_count = trans->restart_count;

	try(for_each_btree_key_commit(trans, iter, BTREE_ID_reflink,
				      POS(0, idx),
				      BTREE_ITER_intent|
				      BTREE_ITER_not_extents, k,
				      res, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		if (bpos_ge(bkey_start_pos(k.k), POS(0, end)))
			break;

		bch2_disk_reservation_put(trans->c, res);
		update_reconcile_opts_scan(trans, snapshot_io_opts, opts, &iter, 0, k, s);
	})));

	/* suppress trans_was_restarted() check */
	trans->restart_count = restart_count;
	return 0;
}

static int do_reconcile_scan_btree(struct moving_context *ctxt,
				   struct reconcile_scan s,
				   struct per_snapshot_io_opts *snapshot_io_opts,
				   enum btree_id btree, unsigned level,
				   struct bpos start, struct bpos end)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;

	try(for_btree_root_key_at_level(trans, iter, btree, level, k, ({
		struct bch_inode_opts opts;
		bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts) ?:
		update_reconcile_opts_scan(trans, snapshot_io_opts, &opts, &iter, level, k, s);
	})));

	bch2_trans_begin(trans);
	CLASS(btree_node_iter, iter)(trans, btree, start, 0, level,
				     BTREE_ITER_prefetch|
				     BTREE_ITER_not_extents|
				     BTREE_ITER_all_snapshots);
	CLASS(disk_reservation, res)(c);

	return for_each_btree_key_max_continue(trans, iter, end, 0, k, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);
		bch2_progress_update_iter(trans, &r->progress, &iter);

		if (kthread_should_stop() || !bch2_reconcile_enabled(c))
			return 0;

		atomic64_add(!level ? k.k->size : c->opts.btree_node_size >> 9,
			     &r->scan_stats.sectors_seen);

		bch2_disk_reservation_put(c, &res.r);

		struct bch_inode_opts opts;
		bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts) ?:
		update_reconcile_opts_scan(trans, snapshot_io_opts, &opts, &iter, level, k, s) ?:
		(start.inode &&
		 k.k->type == KEY_TYPE_reflink_p &&
		 REFLINK_P_MAY_UPDATE_OPTIONS(bkey_s_c_to_reflink_p(k).v)
		 ? do_reconcile_scan_indirect(ctxt, s, &res.r, bkey_s_c_to_reflink_p(k),
					      snapshot_io_opts, &opts)
		 : 0) ?:
		bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc);
	}));
}

static int do_reconcile_scan_fs(struct moving_context *ctxt, struct reconcile_scan s,
				struct per_snapshot_io_opts *snapshot_io_opts,
				bool metadata)
{
	struct bch_fs *c = ctxt->trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;

	bch2_progress_init(&r->progress, NULL, c, metadata ? 0 : ~0ULL, ~0ULL);

	r->scan_start	= BBPOS_MIN;
	r->scan_end	= BBPOS_MAX;

	for (enum btree_id btree = 0; btree < btree_id_nr_alive(c); btree++) {
		if (!bch2_btree_id_root(c, btree)->b)
			continue;

		bool scan_leaves = !metadata &&
			(btree == BTREE_ID_extents ||
			 btree == BTREE_ID_reflink);

		for (unsigned level = !scan_leaves; level < BTREE_MAX_DEPTH; level++)
			try(do_reconcile_scan_btree(ctxt, s, snapshot_io_opts,
						    btree, level, POS_MIN, SPOS_MAX));
	}

	return 0;
}

noinline_for_stack
static int do_reconcile_scan(struct moving_context *ctxt,
			     struct per_snapshot_io_opts *snapshot_io_opts,
			     struct bpos cookie_pos, u64 cookie, u64 *sectors_scanned,
			     struct wb_maybe_flush *last_flushed)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;

	bch2_move_stats_init(&r->scan_stats, "reconcile_scan");
	ctxt->stats = &r->scan_stats;

	struct reconcile_scan s = reconcile_scan_decode(c, cookie_pos.offset);
	if (s.type == RECONCILE_SCAN_fs) {
		try(do_reconcile_scan_fs(ctxt, s, snapshot_io_opts, false));
	} else if (s.type == RECONCILE_SCAN_metadata) {
		try(do_reconcile_scan_fs(ctxt, s, snapshot_io_opts, true));
	} else if (s.type == RECONCILE_SCAN_device) {
		try(do_reconcile_scan_bps(ctxt, s, last_flushed));
	} else if (s.type == RECONCILE_SCAN_inum) {
		r->scan_start	= BBPOS(BTREE_ID_extents, POS(s.inum, 0));
		r->scan_end	= BBPOS(BTREE_ID_extents, POS(s.inum, U64_MAX));

		try(do_reconcile_scan_btree(ctxt, s, snapshot_io_opts, BTREE_ID_extents, 0,
					    r->scan_start.pos, r->scan_end.pos));
	}

	try(bch2_clear_reconcile_needs_scan(trans, cookie_pos, cookie));

	*sectors_scanned += atomic64_read(&r->scan_stats.sectors_seen);
	/*
	 * Ensure that the entries we created are seen by the next iteration of
	 * do_reconcile(), so we don't end up stuck in reconcile_wait():
	 */
	*sectors_scanned += 1;
	bch2_move_stats_exit(&r->scan_stats, c);

	bch2_btree_write_buffer_flush_sync(trans);
	return 0;
}

static void reconcile_wait(struct bch_fs *c)
{
	struct bch_fs_reconcile *r = &c->reconcile;
	struct io_clock *clock = &c->io_clock[WRITE];
	u64 now = atomic64_read(&clock->now);
	u64 min_member_capacity = bch2_min_rw_member_capacity(c);

	if (min_member_capacity == U64_MAX)
		min_member_capacity = 128 * 2048;

	r->wait_iotime_end		= now + (min_member_capacity >> 6);

	if (r->running) {
		r->wait_iotime_start	= now;
		r->wait_wallclock_start	= ktime_get_real_ns();
		r->running		= false;
	}

	bch2_kthread_io_clock_wait_once(clock, r->wait_iotime_end, MAX_SCHEDULE_TIMEOUT);
}

struct reconcile_phase {
	enum reconcile_phase_type	type;
	enum reconcile_work_id		priority;
	enum btree_id			btree;
	struct bpos			start, end;
};

static const struct reconcile_phase reconcile_phases[] = {
	/* Scan cookies: */
	{ RECONCILE_PHASE_scan,		RECONCILE_WORK_hipri,
		BTREE_ID_reconcile_scan, POS_MIN, POS(0, U64_MAX), },

	/* Hipri work first - evacuate/rereplicate */

	/*
	 * Btree nodes first - they're indexed separately from the normal work
	 * btrees because they require backpointers:
	 */
	{ RECONCILE_PHASE_btree,	RECONCILE_WORK_hipri,
		BTREE_ID_reconcile_scan, POS(RECONCILE_WORK_hipri, 0), POS(RECONCILE_WORK_hipri, U64_MAX) },

	/*
	 * User data:
	 * Phys btrees first: pending work there will also be present in the normal work btrees
	 * Then the logical btrees, this will be data on SSDS:
	 * */
	{ RECONCILE_PHASE_phys,		RECONCILE_WORK_hipri,
		BTREE_ID_reconcile_hipri_phys,	POS_MIN, SPOS_MAX },
	{ RECONCILE_PHASE_normal,	RECONCILE_WORK_hipri,
		BTREE_ID_reconcile_hipri,		POS_MIN, SPOS_MAX },

	/* Normal priority work: */
	{ RECONCILE_PHASE_btree,	RECONCILE_WORK_normal,
		BTREE_ID_reconcile_scan, POS(RECONCILE_WORK_normal, 0), POS(RECONCILE_WORK_normal, U64_MAX) },
	{ RECONCILE_PHASE_phys,		RECONCILE_WORK_normal,
		BTREE_ID_reconcile_work_phys,		POS_MIN, SPOS_MAX },
	{ RECONCILE_PHASE_normal,	RECONCILE_WORK_normal,
		BTREE_ID_reconcile_work,		POS_MIN, SPOS_MAX },

	/*
	 * Lastly, work that we marked as unable to complete until system
	 * configuration changes: this won't be process unless kicked by
	 * something else
	 */
	{ RECONCILE_PHASE_btree,	RECONCILE_WORK_pending,
		BTREE_ID_reconcile_scan, POS(RECONCILE_WORK_pending, 0), POS(RECONCILE_WORK_pending, U64_MAX) },
	{ RECONCILE_PHASE_normal,	RECONCILE_WORK_pending,
		BTREE_ID_reconcile_pending,		POS_MIN, SPOS_MAX },
};

typedef struct {
	struct bch_fs		*c;
	unsigned		dev;
	unsigned		reconcile_phase;
	struct closure		cl;

	struct bch_move_stats	stats;
} reconcile_phys_thr;

DEFINE_DARRAY(reconcile_phys_thr);

static CLOSURE_CALLBACK(do_reconcile_phys_thread)
{
	closure_type(thr, reconcile_phys_thr, cl);
	struct bch_fs *c = thr->c;

	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, NULL, &thr->stats,
			      writepoint_ptr(&c->allocator.reconcile_write_point),
			      true);

	struct btree_trans *trans = ctxt.trans;

	CLASS(darray_reconcile_work, work)();
	darray_make_room(&work, RECONCILE_WORK_BUF_NR);
	if (!work.size) {
		bch_err(c, "%s: unable to allocate memory", __func__);
		closure_return(cl);
		return;
	}

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct bbpos work_pos = BBPOS(reconcile_phases[thr->reconcile_phase].btree,
				      POS(thr->dev, 0));

	while (!bch2_move_ratelimit(&ctxt)) {
		if (!bch2_reconcile_enabled(c) ||
		    test_bit(BCH_FS_going_ro, &c->flags))
			break;

		bch2_trans_begin(trans);

		struct bkey_s_c k = next_reconcile_entry(trans, &work, &work_pos, POS(thr->dev, U64_MAX));
		if (bkey_err(k) ||
		    !k.k ||
		    k.k->p.inode != thr->dev)
			break;

		int ret = lockrestart_do(trans,
			do_reconcile_extent_phys(&ctxt, &snapshot_io_opts,
						 BBPOS(work_pos.btree, k.k->p), &last_flushed));
		if (ret)
			break;
	}

	closure_return(cl);
}

static int do_reconcile_phys(struct bch_fs *c, unsigned reconcile_phase)
{
	CLASS(darray_reconcile_phys_thr, thrs)();
	CLASS(closure_stack, cl)();

	for_each_member_device(c, ca)
		if (ca->mi.rotational &&
		    bch2_dev_is_online(ca))
			try(darray_push(&thrs, ((reconcile_phys_thr) {
						.c			= c,
						.dev			= ca->dev_idx,
						.reconcile_phase	= reconcile_phase,
						})));

	darray_for_each(thrs, i)
		closure_call(&i->cl, do_reconcile_phys_thread, system_unbound_wq, &cl);

	closure_sync_unbounded(&cl);
	return 0;
}

static void reconcile_phase_start(struct bch_fs *c)
{
	struct bch_fs_reconcile *r = &c->reconcile;
	struct reconcile_phase p = reconcile_phases[r->phase];
	r->work_pos = BBPOS(p.btree, p.start);

	switch (p.type) {
	case RECONCILE_PHASE_normal:
		bch2_progress_init(&r->progress, NULL, c,
				   BIT_ULL(reconcile_work_btree[p.priority]), 0);
		break;
	case RECONCILE_PHASE_phys:
		bch2_progress_init(&r->progress, NULL, c,
				   BIT_ULL(reconcile_work_phys_btree[p.priority]), 0);
		break;
	default:
		break;
	}
}

static bool reconcile_phase_is_pending(unsigned i)
{
	struct reconcile_phase p = reconcile_phases[i];
	return (p.btree == BTREE_ID_reconcile_scan &&
		p.start.inode == RECONCILE_WORK_pending) ||
		p.btree == BTREE_ID_reconcile_pending;
}

static int do_reconcile(struct moving_context *ctxt)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;
	u64 sectors_scanned = 0;
	u32 kick = r->kick;
	u32 copygc_run_count = c->copygc.run_count;
	int ret = 0;

	CLASS(darray_reconcile_work, work)();
	try(darray_make_room(&work, RECONCILE_WORK_BUF_NR));

	bch2_move_stats_init(&r->work_stats, "reconcile_work");

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

	r->phase = 0;
	reconcile_phase_start(c);

	struct bkey_i_cookie pending_cookie;
	bkey_init(&pending_cookie.k);

	bch2_moving_ctxt_flush_all(ctxt);
	bch2_btree_write_buffer_flush_sync(trans);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	while (!bch2_move_ratelimit(ctxt) &&
	       !test_bit(BCH_FS_going_ro, &c->flags)) {
		if (!bch2_reconcile_enabled(c)) {
			bch2_moving_ctxt_flush_all(ctxt);
			kthread_wait_freezable(bch2_reconcile_enabled(c) ||
					       kthread_should_stop());
			if (kthread_should_stop())
				break;
		}

		if (kick != r->kick) {
			kick		= r->kick;
			work.nr		= 0;
			r->phase	= 0;
			reconcile_phase_start(c);
		}

		bch2_trans_begin(trans);

		struct bkey_s_c k = next_reconcile_entry(trans, &work,
							 &r->work_pos,
							 reconcile_phases[r->phase].end);
		ret = bkey_err(k);
		if (ret)
			break;

		if (!k.k) {
			if (++r->phase == ARRAY_SIZE(reconcile_phases))
				break;

			reconcile_phase_start(c);

			if (reconcile_phase_is_pending(r->phase) &&
			    bkey_deleted(&pending_cookie.k))
				break;

			/* Avoid conflicts when switching between phys/normal */
			bch2_moving_ctxt_flush_all(ctxt);
			bch2_btree_write_buffer_flush_sync(trans);
			continue;
		}

		r->running = true;
		r->work_pos.pos = k.k->p;

		if (k.k->type == KEY_TYPE_cookie &&
		    reconcile_scan_decode(c, k.k->p.offset).type == RECONCILE_SCAN_pending)
			bkey_reassemble(&pending_cookie.k_i, k);

		if (k.k->type == KEY_TYPE_cookie) {
			ret = do_reconcile_scan(ctxt, &snapshot_io_opts,
						k.k->p,
						le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie),
						&sectors_scanned, &last_flushed);

			if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
#ifdef CONFIG_BCACHEFS_DEBUG
				CLASS(printbuf, buf)();
				bch2_prt_backtrace(&buf, &trans->last_restarted_trace);
				panic("in transaction restart: %s, last restarted by\n%s",
				      bch2_err_str(trans->restarted),
				      buf.buf);
#else
				panic("in transaction restart: %s, last restarted by %pS\n",
				      bch2_err_str(trans->restarted),
				      (void *) trans->last_restarted_ip);
#endif
			}
		} else if (k.k->type == KEY_TYPE_backpointer) {
			ret = do_reconcile_btree(ctxt, &snapshot_io_opts,
						 r->work_pos, bkey_s_c_to_backpointer(k));
		} else if (btree_is_reconcile_phys(r->work_pos.btree)) {
			bch2_trans_unlock_long(trans);
			ret = do_reconcile_phys(c, r->phase);
			BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart));
			reconcile_phase_start(c);
		} else {
			ret = lockrestart_do(trans,
				do_reconcile_extent(ctxt, &snapshot_io_opts, r->work_pos));
		}

		if (bch2_err_matches(ret, BCH_ERR_data_update_fail_need_copygc)) {
			bch2_trans_unlock_long(trans);
			bch2_copygc_wakeup(c);
			wait_event(c->copygc.running_wq,
				   c->copygc.run_count != copygc_run_count ||
				   kthread_should_stop());
			copygc_run_count = c->copygc.run_count;
			ret = 0;
			continue;
		}

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			ret = 0;
			continue;
		}

		if (ret)
			break;

		r->work_pos.pos = btree_type_has_snapshot_field(r->work_pos.btree)
			? bpos_successor(r->work_pos.pos)
			: bpos_nosnap_successor(r->work_pos.pos);
	}

	if (!ret && !bkey_deleted(&pending_cookie.k))
		try(bch2_clear_reconcile_needs_scan(trans,
				pending_cookie.k.p, pending_cookie.v.cookie));

	bch2_move_stats_exit(&r->work_stats, c);

	if (!ret &&
	    !kthread_should_stop() &&
	    !atomic64_read(&r->work_stats.sectors_seen) &&
	    !sectors_scanned &&
	    kick == r->kick) {
		bch2_moving_ctxt_flush_all(ctxt);
		bch2_trans_unlock_long(trans);
		reconcile_wait(c);
	}

	if (!bch2_err_matches(ret, EROFS))
		bch_err_fn(c, ret);
	return ret;
}

static int bch2_reconcile_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct bch_fs_reconcile *r = &c->reconcile;

	set_freezable();

	/*
	 * Data move operations can't run until after check_snapshots has
	 * completed, and bch2_snapshot_is_ancestor() is available.
	 */
	kthread_wait_freezable(c->recovery.pass_done > BCH_RECOVERY_PASS_check_snapshots ||
			       kthread_should_stop());
	if (kthread_should_stop())
		return 0;

	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, NULL, &r->work_stats,
			      writepoint_ptr(&c->allocator.reconcile_write_point),
			      true);

	while (!kthread_should_stop() && !do_reconcile(&ctxt))
		;

	return 0;
}

void bch2_reconcile_status_to_text(struct printbuf *out, struct bch_fs *c)
{
	printbuf_tabstop_push(out, 24);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 12);

	struct bch_fs_reconcile *r = &c->reconcile;

	if (!r->running) {
		prt_printf(out, "waiting:\n");
		u64 now = atomic64_read(&c->io_clock[WRITE].now);

		prt_printf(out, "io wait duration:\t");
		bch2_prt_human_readable_s64(out, (r->wait_iotime_end - r->wait_iotime_start) << 9);
		prt_newline(out);

		prt_printf(out, "io wait remaining:\t");
		bch2_prt_human_readable_s64(out, (r->wait_iotime_end - now) << 9);
		prt_newline(out);

		prt_printf(out, "duration waited:\t");
		bch2_pr_time_units(out, ktime_get_real_ns() - r->wait_wallclock_start);
		prt_newline(out);
	} else {
		struct reconcile_phase phase = reconcile_phases[r->phase];
		struct bpos work_pos = r->work_pos.pos;
		barrier();

		if (phase.type == RECONCILE_PHASE_scan) {
			prt_printf(out, "scanning: ");
			struct reconcile_scan s = reconcile_scan_decode(c, work_pos.offset);
			reconcile_scan_to_text(out, c, s);

			if (s.type == RECONCILE_SCAN_fs ||
			    s.type == RECONCILE_SCAN_metadata) {
				prt_char(out, ' ');
				bch2_progress_to_text(out, &r->progress);
			}
			prt_newline(out);
		} else {
			prt_printf(out, "processing %s %s: ",
				   bch2_reconcile_work_ids[phase.priority],
				   bch2_reconcile_phase_types[phase.type]);

			if (phase.type == RECONCILE_PHASE_normal) {
				bch2_progress_to_text(out, &r->progress);
			} else {
				bch2_bpos_to_text(out, work_pos);
			}

			prt_newline(out);
		}
	}

	struct task_struct *t;
	scoped_guard(rcu) {
		t = rcu_dereference(c->reconcile.thread);
		if (t)
			get_task_struct(t);
	}

	prt_newline(out);

	if (t) {
		prt_str(out, "Reconcile thread backtrace:\n");
		guard(printbuf_indent)(out);
		bch2_prt_task_backtrace(out, t, 0, GFP_KERNEL);
		put_task_struct(t);
	} else {
		prt_str(out, "Reconcile thread not running\n");
	}
}

void bch2_reconcile_scan_pending_to_text(struct printbuf *out, struct bch_fs *c)
{
	/*
	 * No multithreaded btree access until BCH_FS_may_go_rw and we're no
	 * longer modifying the journal keys gap buffer:
	 */
	if (!test_bit(BCH_FS_may_go_rw, &c->flags))
		return;

	CLASS(btree_trans, trans)(c);
	CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, POS_MIN, 0);

	struct bkey_s_c k;
	lockrestart_do(trans, bkey_err(k = bch2_btree_iter_peek(&iter)));

	prt_printf(out, "%u\n", iter.pos.inode == 0);
}

void bch2_reconcile_stop(struct bch_fs *c)
{
	struct task_struct *p;

	p = rcu_dereference_protected(c->reconcile.thread, 1);
	c->reconcile.thread = NULL;

	if (p) {
		/* for sychronizing with bch2_reconcile_wakeup() */
		synchronize_rcu();

		kthread_stop(p);
		put_task_struct(p);
	}
}

int bch2_reconcile_start(struct bch_fs *c)
{
	if (c->reconcile.thread)
		return 0;

	if (c->opts.nochanges)
		return 0;

	struct task_struct *p =
		kthread_create(bch2_reconcile_thread, c, "bch-reconcile/%s", c->name);
	int ret = PTR_ERR_OR_ZERO(p);
	bch_err_msg(c, ret, "creating reconcile thread");
	if (ret)
		return ret;

	get_task_struct(p);
	rcu_assign_pointer(c->reconcile.thread, p);
	wake_up_process(p);
	return 0;
}

#ifdef CONFIG_POWER_SUPPLY
#include <linux/power_supply.h>

static int bch2_reconcile_power_notifier(struct notifier_block *nb,
					 unsigned long event, void *data)
{
	struct bch_fs *c = container_of(nb, struct bch_fs, reconcile.power_notifier);

	c->reconcile.on_battery = !power_supply_is_system_supplied();
	bch2_reconcile_wakeup(c);
	return NOTIFY_OK;
}
#endif

void bch2_fs_reconcile_exit(struct bch_fs *c)
{
#ifdef CONFIG_POWER_SUPPLY
	power_supply_unreg_notifier(&c->reconcile.power_notifier);
#endif
}

int bch2_fs_reconcile_init(struct bch_fs *c)
{
#ifdef CONFIG_POWER_SUPPLY
	struct bch_fs_reconcile *r = &c->reconcile;

	r->power_notifier.notifier_call = bch2_reconcile_power_notifier;
	try(power_supply_reg_notifier(&r->power_notifier));

	r->on_battery = !power_supply_is_system_supplied();
#endif
	return 0;
}
