// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "btree_iter.h"
#include "btree_update.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "clock.h"
#include "compress.h"
#include "disk_groups.h"
#include "errcode.h"
#include "error.h"
#include "inode.h"
#include "io_write.h"
#include "move.h"
#include "progress.h"
#include "rebalance.h"
#include "subvolume.h"
#include "super-io.h"
#include "trace.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/sched/cputime.h>

/* bch_extent_rebalance: */

static const struct bch_extent_rebalance *bch2_bkey_ptrs_rebalance_opts(struct bkey_ptrs_c ptrs)
{
	const union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (__extent_entry_type(entry) == BCH_EXTENT_ENTRY_rebalance)
			return &entry->rebalance;

	return NULL;
}

static const struct bch_extent_rebalance *bch2_bkey_rebalance_opts(struct bkey_s_c k)
{
	return bch2_bkey_ptrs_rebalance_opts(bch2_bkey_ptrs_c(k));
}

void bch2_extent_rebalance_to_text(struct printbuf *out, struct bch_fs *c,
				   const struct bch_extent_rebalance *r)
{
	prt_printf(out, "replicas=%u", r->data_replicas);
	if (r->data_replicas_from_inode)
		prt_str(out, " (inode)");

	prt_str(out, " checksum=");
	bch2_prt_csum_opt(out, r->data_checksum);
	if (r->data_checksum_from_inode)
		prt_str(out, " (inode)");

	if (r->background_compression || r->background_compression_from_inode) {
		prt_str(out, " background_compression=");
		bch2_compression_opt_to_text(out, r->background_compression);

		if (r->background_compression_from_inode)
			prt_str(out, " (inode)");
	}

	if (r->background_target || r->background_target_from_inode) {
		prt_str(out, " background_target=");
		if (c)
			bch2_target_to_text(out, c, r->background_target);
		else
			prt_printf(out, "%u", r->background_target);

		if (r->background_target_from_inode)
			prt_str(out, " (inode)");
	}

	if (r->promote_target || r->promote_target_from_inode) {
		prt_str(out, " promote_target=");
		if (c)
			bch2_target_to_text(out, c, r->promote_target);
		else
			prt_printf(out, "%u", r->promote_target);

		if (r->promote_target_from_inode)
			prt_str(out, " (inode)");
	}

	if (r->erasure_code || r->erasure_code_from_inode) {
		prt_printf(out, " ec=%u", r->erasure_code);
		if (r->erasure_code_from_inode)
			prt_str(out, " (inode)");
	}
}

int bch2_trigger_extent_rebalance(struct btree_trans *trans,
				  struct bkey_s_c old, struct bkey_s_c new,
				  enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	int need_rebalance_delta = 0;
	s64 need_rebalance_sectors_delta[1] = { 0 };

	s64 s = bch2_bkey_sectors_need_rebalance(c, old);
	need_rebalance_delta -= s != 0;
	need_rebalance_sectors_delta[0] -= s;

	s = bch2_bkey_sectors_need_rebalance(c, new);
	need_rebalance_delta += s != 0;
	need_rebalance_sectors_delta[0] += s;

	if ((flags & BTREE_TRIGGER_transactional) && need_rebalance_delta) {
		int ret = bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work,
						      new.k->p, need_rebalance_delta > 0);
		if (ret)
			return ret;
	}

	if (need_rebalance_sectors_delta[0]) {
		int ret = bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc,
						    need_rebalance_sectors_delta, rebalance_work);
		if (ret)
			return ret;
	}

	return 0;
}

static void bch2_bkey_needs_rebalance(struct bch_fs *c, struct bkey_s_c k,
				      struct bch_inode_opts *io_opts,
				      unsigned *move_ptrs,
				      unsigned *compress_ptrs,
				      u64 *sectors)
{
	*move_ptrs	= 0;
	*compress_ptrs	= 0;
	*sectors	= 0;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	const struct bch_extent_rebalance *rb_opts = bch2_bkey_ptrs_rebalance_opts(ptrs);
	if (!io_opts && !rb_opts)
		return;

	if (bch2_bkey_extent_ptrs_flags(ptrs) & BIT_ULL(BCH_EXTENT_FLAG_poisoned))
		return;

	unsigned compression_type =
		bch2_compression_opt_to_type(io_opts
					     ? io_opts->background_compression
					     : rb_opts->background_compression);
	unsigned target = io_opts
		? io_opts->background_target
		: rb_opts->background_target;
	if (target && !bch2_target_accepts_data(c, BCH_DATA_user, target))
		target = 0;

	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	bool incompressible = false, unwritten = false;

	unsigned ptr_idx = 1;

	guard(rcu)();
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		incompressible	|= p.crc.compression_type == BCH_COMPRESSION_TYPE_incompressible;
		unwritten	|= p.ptr.unwritten;

		if (!p.ptr.cached) {
			if (p.crc.compression_type != compression_type)
				*compress_ptrs |= ptr_idx;

			if (target && !bch2_dev_in_target(c, p.ptr.dev, target))
				*move_ptrs |= ptr_idx;
		}

		ptr_idx <<= 1;
	}

	if (unwritten)
		*compress_ptrs = 0;
	if (incompressible)
		*compress_ptrs = 0;

	unsigned rb_ptrs = *move_ptrs | *compress_ptrs;

	if (!rb_ptrs)
		return;

	ptr_idx = 1;
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (rb_ptrs & ptr_idx)
			*sectors += p.crc.compressed_size;
		ptr_idx <<= 1;
	}
}

u64 bch2_bkey_sectors_need_rebalance(struct bch_fs *c, struct bkey_s_c k)
{
	unsigned move_ptrs	= 0;
	unsigned compress_ptrs	= 0;
	u64 sectors		= 0;

	bch2_bkey_needs_rebalance(c, k, NULL, &move_ptrs, &compress_ptrs, &sectors);
	return sectors;
}

static unsigned bch2_bkey_ptrs_need_rebalance(struct bch_fs *c,
					      struct bch_inode_opts *opts,
					      struct bkey_s_c k)
{
	unsigned move_ptrs	= 0;
	unsigned compress_ptrs	= 0;
	u64 sectors		= 0;

	bch2_bkey_needs_rebalance(c, k, opts, &move_ptrs, &compress_ptrs, &sectors);
	return move_ptrs|compress_ptrs;
}

static inline bool bkey_should_have_rb_opts(struct bch_fs *c,
					    struct bch_inode_opts *opts,
					    struct bkey_s_c k)
{
	if (k.k->type == KEY_TYPE_reflink_v) {
#define x(n)	if (opts->n##_from_inode) return true;
		BCH_REBALANCE_OPTS()
#undef x
	}
	return bch2_bkey_ptrs_need_rebalance(c, opts, k);
}

int bch2_bkey_set_needs_rebalance(struct bch_fs *c, struct bch_inode_opts *opts,
				  struct bkey_i *_k,
				  enum set_needs_rebalance_ctx ctx,
				  u32 change_cookie)
{
	if (!bkey_extent_is_direct_data(&_k->k))
		return 0;

	struct bkey_s k = bkey_i_to_s(_k);
	struct bch_extent_rebalance *old =
		(struct bch_extent_rebalance *) bch2_bkey_rebalance_opts(k.s_c);

	if (bkey_should_have_rb_opts(c, opts, k.s_c)) {
		if (!old) {
			old = bkey_val_end(k);
			k.k->u64s += sizeof(*old) / sizeof(u64);
		}

		*old = io_opts_to_rebalance_opts(c, opts);
	} else {
		if (old)
			extent_entry_drop(k, (union bch_extent_entry *) old);
	}

	return 0;
}

static int bch2_get_update_rebalance_opts(struct btree_trans *trans,
					  struct bch_inode_opts *io_opts,
					  struct btree_iter *iter,
					  struct bkey_s_c k,
					  enum set_needs_rebalance_ctx ctx)
{
	struct bch_fs *c = trans->c;

	BUG_ON(iter->flags & BTREE_ITER_is_extents);
	BUG_ON(iter->flags & BTREE_ITER_filter_snapshots);

	if (!bkey_extent_is_direct_data(k.k))
		return 0;

	bool may_update_indirect = ctx == SET_NEEDS_REBALANCE_opt_change_indirect;

	/*
	 * If it's an indirect extent, and we walked to it directly, we won't
	 * have the options from the inode that were directly applied: options
	 * from the extent take precedence - unless the io_opts option came from
	 * the inode and may_update_indirect is true (walked from a
	 * REFLINK_P_MAY_UPDATE_OPTIONS pointer).
	 */
	const struct bch_extent_rebalance *old = bch2_bkey_rebalance_opts(k);
	if (old && k.k->type == KEY_TYPE_reflink_v) {
#define x(_name)								\
		if (old->_name##_from_inode &&					\
		    !(may_update_indirect && io_opts->_name##_from_inode)) {	\
			io_opts->_name = old->_name;				\
			io_opts->_name##_from_inode = true;			\
		}
		BCH_REBALANCE_OPTS()
#undef x
	}

	struct bch_extent_rebalance new = io_opts_to_rebalance_opts(c, io_opts);

	if (bkey_should_have_rb_opts(c, io_opts, k)
	    ? old && !memcmp(old, &new, sizeof(new))
	    : !old)
		return 0;

	struct bkey_i *n = bch2_trans_kmalloc(trans, bkey_bytes(k.k) + 8);
	int ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		return ret;

	bkey_reassemble(n, k);

	/* On successfull transaction commit, @k was invalidated: */

	return bch2_bkey_set_needs_rebalance(c, io_opts, n, ctx, 0) ?:
		bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node) ?:
		bch2_trans_commit(trans, NULL, NULL, 0) ?:
		bch_err_throw(c, transaction_restart_commit);
}

static struct bch_inode_opts *bch2_extent_get_io_opts(struct btree_trans *trans,
			  struct per_snapshot_io_opts *io_opts,
			  struct bpos extent_pos, /* extent_iter, extent_k may be in reflink btree */
			  struct btree_iter *extent_iter,
			  struct bkey_s_c extent_k)
{
	struct bch_fs *c = trans->c;
	u32 restart_count = trans->restart_count;
	int ret = 0;

	if (btree_iter_path(trans, extent_iter)->level)
		return &io_opts->fs_io_opts;

	if (extent_k.k->type == KEY_TYPE_reflink_v)
		return &io_opts->fs_io_opts;

	if (io_opts->cur_inum != extent_pos.inode) {
		io_opts->d.nr = 0;

		ret = for_each_btree_key(trans, iter, BTREE_ID_inodes, POS(0, extent_pos.inode),
					 BTREE_ITER_all_snapshots, k, ({
			if (k.k->p.offset != extent_pos.inode)
				break;

			if (!bkey_is_inode(k.k))
				continue;

			struct bch_inode_unpacked inode;
			_ret3 = bch2_inode_unpack(k, &inode);
			if (_ret3)
				break;

			struct snapshot_io_opts_entry e = { .snapshot = k.k->p.snapshot };
			bch2_inode_opts_get_inode(c, &inode, &e.io_opts);

			darray_push(&io_opts->d, e);
		}));
		io_opts->cur_inum = extent_pos.inode;
	}

	ret = ret ?: trans_was_restarted(trans, restart_count);
	if (ret)
		return ERR_PTR(ret);

	if (extent_k.k->p.snapshot)
		darray_for_each(io_opts->d, i)
			if (bch2_snapshot_is_ancestor(c, extent_k.k->p.snapshot, i->snapshot))
				return &i->io_opts;

	return &io_opts->fs_io_opts;
}

struct bch_inode_opts *bch2_extent_get_apply_io_opts(struct btree_trans *trans,
			  struct per_snapshot_io_opts *snapshot_io_opts,
			  struct bpos extent_pos, /* extent_iter, extent_k may be in reflink btree */
			  struct btree_iter *extent_iter,
			  struct bkey_s_c extent_k,
			  enum set_needs_rebalance_ctx ctx)
{
	struct bch_inode_opts *opts =
		bch2_extent_get_io_opts(trans, snapshot_io_opts, extent_pos, extent_iter, extent_k);
	if (IS_ERR(opts) || btree_iter_path(trans, extent_iter)->level)
		return opts;

	int ret = bch2_get_update_rebalance_opts(trans, opts, extent_iter, extent_k, ctx);
	return ret ? ERR_PTR(ret) : opts;
}

int bch2_extent_get_io_opts_one(struct btree_trans *trans,
				struct bch_inode_opts *io_opts,
				struct btree_iter *extent_iter,
				struct bkey_s_c extent_k,
				enum set_needs_rebalance_ctx ctx)
{
	struct bch_fs *c = trans->c;

	bch2_inode_opts_get(c, io_opts);

	/* reflink btree? */
	if (extent_k.k->p.inode) {
		CLASS(btree_iter, inode_iter)(trans, BTREE_ID_inodes,
				       SPOS(0, extent_k.k->p.inode, extent_k.k->p.snapshot),
				       BTREE_ITER_cached);
		struct bkey_s_c inode_k = bch2_btree_iter_peek_slot(&inode_iter);
		int ret = bkey_err(inode_k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ret;

		if (!ret && bkey_is_inode(inode_k.k)) {
			struct bch_inode_unpacked inode;
			bch2_inode_unpack(inode_k, &inode);
			bch2_inode_opts_get_inode(c, &inode, io_opts);
		}
	}

	return 0;
}

int bch2_extent_get_apply_io_opts_one(struct btree_trans *trans,
				      struct bch_inode_opts *io_opts,
				      struct btree_iter *extent_iter,
				      struct bkey_s_c extent_k,
				      enum set_needs_rebalance_ctx ctx)
{
	int ret = bch2_extent_get_io_opts_one(trans, io_opts, extent_iter, extent_k, ctx);
	if (ret || btree_iter_path(trans, extent_iter)->level)
		return ret;

	return bch2_get_update_rebalance_opts(trans, io_opts, extent_iter, extent_k, ctx);
}

#define REBALANCE_WORK_SCAN_OFFSET	(U64_MAX - 1)

static const char * const bch2_rebalance_state_strs[] = {
#define x(t) #t,
	BCH_REBALANCE_STATES()
	NULL
#undef x
};

int bch2_set_rebalance_needs_scan_trans(struct btree_trans *trans, u64 inum)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_rebalance_work,
				SPOS(inum, REBALANCE_WORK_SCAN_OFFSET, U32_MAX),
				BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (ret)
		return ret;

	u64 v = k.k->type == KEY_TYPE_cookie
		? le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie)
		: 0;

	struct bkey_i_cookie *cookie = bch2_trans_kmalloc(trans, sizeof(*cookie));
	ret = PTR_ERR_OR_ZERO(cookie);
	if (ret)
		return ret;

	bkey_cookie_init(&cookie->k_i);
	cookie->k.p = iter.pos;
	cookie->v.cookie = cpu_to_le64(v + 1);

	return bch2_trans_update(trans, &iter, &cookie->k_i, 0);
}

int bch2_set_rebalance_needs_scan(struct bch_fs *c, u64 inum)
{
	CLASS(btree_trans, trans)(c);
	int ret = commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			    bch2_set_rebalance_needs_scan_trans(trans, inum));
	bch2_rebalance_wakeup(c);
	return ret;
}

int bch2_set_fs_needs_rebalance(struct bch_fs *c)
{
	return bch2_set_rebalance_needs_scan(c, 0);
}

static int bch2_clear_rebalance_needs_scan(struct btree_trans *trans, u64 inum, u64 cookie)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_rebalance_work,
				SPOS(inum, REBALANCE_WORK_SCAN_OFFSET, U32_MAX),
				BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (ret)
		return ret;

	u64 v = k.k->type == KEY_TYPE_cookie
		? le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie)
		: 0;

	return v == cookie
		? bch2_btree_delete_at(trans, &iter, 0)
		: 0;
}

#define REBALANCE_WORK_BUF_NR		1024
DEFINE_DARRAY_NAMED(darray_rebalance_work, struct bkey_i_cookie);

static struct bkey_i *next_rebalance_entry(struct btree_trans *trans,
					 darray_rebalance_work *buf, struct bpos *work_pos)
{
	if (unlikely(!buf->nr)) {
		/*
		 * Avoid contention with write buffer flush: buffer up rebalance
		 * work entries in a darray
		 */

		BUG_ON(!buf->size);;

		bch2_trans_begin(trans);

		for_each_btree_key(trans, iter, BTREE_ID_rebalance_work, *work_pos,
				   BTREE_ITER_all_snapshots|BTREE_ITER_prefetch, k, ({
			/* we previously used darray_make_room */
			BUG_ON(bkey_bytes(k.k) > sizeof(buf->data[0]));

			bkey_reassemble(&darray_top(*buf).k_i, k);
			buf->nr++;

			*work_pos = bpos_successor(iter.pos);
			if (buf->nr == buf->size)
				break;
			0;
		}));

		if (!buf->nr)
			return NULL;

		unsigned l = 0, r = buf->nr - 1;
		while (l < r) {
			swap(buf->data[l], buf->data[r]);
			l++;
			--r;
		}
	}

	return &(&darray_pop(buf))->k_i;
}

static int bch2_bkey_clear_needs_rebalance(struct btree_trans *trans,
					   struct btree_iter *iter,
					   struct bkey_s_c k)
{
	if (k.k->type == KEY_TYPE_reflink_v || !bch2_bkey_rebalance_opts(k))
		return 0;

	struct bkey_i *n = bch2_bkey_make_mut(trans, iter, &k, 0);
	int ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		return ret;

	extent_entry_drop(bkey_i_to_s(n),
			  (void *) bch2_bkey_rebalance_opts(bkey_i_to_s_c(n)));
	return bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

static struct bkey_s_c next_rebalance_extent(struct btree_trans *trans,
			struct per_snapshot_io_opts *snapshot_io_opts,
			struct bpos work_pos,
			struct btree_iter *extent_iter,
			struct bch_inode_opts **opts_ret,
			struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;

	bch2_trans_iter_exit(extent_iter);
	bch2_trans_iter_init(trans, extent_iter,
			     work_pos.inode ? BTREE_ID_extents : BTREE_ID_reflink,
			     work_pos,
			     BTREE_ITER_all_snapshots);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(extent_iter);
	if (bkey_err(k))
		return k;

	struct bch_inode_opts *opts =
		bch2_extent_get_apply_io_opts(trans, snapshot_io_opts,
					      extent_iter->pos, extent_iter, k,
					      SET_NEEDS_REBALANCE_other);
	int ret = PTR_ERR_OR_ZERO(opts);
	if (ret)
		return bkey_s_c_err(ret);

	*opts_ret = opts;

	memset(data_opts, 0, sizeof(*data_opts));
	data_opts->rewrite_ptrs		= bch2_bkey_ptrs_need_rebalance(c, opts, k);
	data_opts->target		= opts->background_target;
	data_opts->write_flags		|= BCH_WRITE_only_specified_devs;

	if (!data_opts->rewrite_ptrs) {
		/*
		 * device we would want to write to offline? devices in target
		 * changed?
		 *
		 * We'll now need a full scan before this extent is picked up
		 * again:
		 */
		int ret = bch2_bkey_clear_needs_rebalance(trans, extent_iter, k);
		if (ret)
			return bkey_s_c_err(ret);
		return bkey_s_c_null;
	}

	if (trace_rebalance_extent_enabled()) {
		CLASS(printbuf, buf)();

		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);

		unsigned move_ptrs	= 0;
		unsigned compress_ptrs	= 0;
		u64 sectors		= 0;

		bch2_bkey_needs_rebalance(c, k, opts, &move_ptrs, &compress_ptrs, &sectors);

		if (move_ptrs) {
			prt_str(&buf, "move=");
			bch2_target_to_text(&buf, c, opts->background_target);
			prt_str(&buf, " ");
			bch2_prt_u64_base2(&buf, move_ptrs);
			prt_newline(&buf);
		}

		if (compress_ptrs) {
			prt_str(&buf, "compression=");
			bch2_compression_opt_to_text(&buf, opts->background_compression);
			prt_str(&buf, " ");
			bch2_prt_u64_base2(&buf, compress_ptrs);
			prt_newline(&buf);
		}

		trace_rebalance_extent(c, buf.buf);
	}
	count_event(c, rebalance_extent);

	return k;
}

noinline_for_stack
static int do_rebalance_extent(struct moving_context *ctxt,
			       struct per_snapshot_io_opts *snapshot_io_opts,
			       struct bpos work_pos,
			       struct btree_iter *extent_iter)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_rebalance *r = &trans->c->rebalance;
	struct data_update_opts data_opts;
	struct bch_inode_opts *io_opts;
	struct bkey_s_c k;
	struct bkey_buf sk;
	int ret;

	ctxt->stats = &r->work_stats;
	r->state = BCH_REBALANCE_working;

	bch2_bkey_buf_init(&sk);

	ret = lockrestart_do(trans,
		bkey_err(k = next_rebalance_extent(trans, snapshot_io_opts,
				work_pos, extent_iter, &io_opts, &data_opts)));
	if (ret || !k.k)
		goto out;

	atomic64_add(k.k->size, &ctxt->stats->sectors_seen);

	/*
	 * The iterator gets unlocked by __bch2_read_extent - need to
	 * save a copy of @k elsewhere:
	 */
	bch2_bkey_buf_reassemble(&sk, c, k);
	k = bkey_i_to_s_c(sk.k);

	ret = bch2_move_extent(ctxt, NULL, extent_iter, k, *io_opts, data_opts);
	if (ret) {
		if (bch2_err_matches(ret, ENOMEM)) {
			/* memory allocation failure, wait for some IO to finish */
			bch2_move_ctxt_wait_for_io(ctxt);
			ret = bch_err_throw(c, transaction_restart_nested);
		}

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto out;

		/* skip it and continue, XXX signal failure */
		ret = 0;
	}
out:
	bch2_bkey_buf_exit(&sk, c);
	return ret;
}

static int do_rebalance_scan_indirect(struct btree_trans *trans,
				      struct bkey_s_c_reflink_p p,
				      struct bch_inode_opts *opts)
{
	u64 idx = REFLINK_P_IDX(p.v) - le32_to_cpu(p.v->front_pad);
	u64 end = REFLINK_P_IDX(p.v) + p.k->size + le32_to_cpu(p.v->back_pad);
	u32 restart_count = trans->restart_count;

	int ret = for_each_btree_key(trans, iter, BTREE_ID_reflink,
				     POS(0, idx), BTREE_ITER_not_extents, k, ({
		if (bpos_ge(bkey_start_pos(k.k), POS(0, end)))
			break;
		bch2_get_update_rebalance_opts(trans, opts, &iter, k,
					       SET_NEEDS_REBALANCE_opt_change_indirect);
	}));
	if (ret)
		return ret;

	/* suppress trans_was_restarted() check */
	trans->restart_count = restart_count;
	return 0;
}

static int do_rebalance_scan(struct moving_context *ctxt,
			     struct per_snapshot_io_opts *snapshot_io_opts,
			     u64 inum, u64 cookie, u64 *sectors_scanned)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_rebalance *r = &c->rebalance;

	bch2_move_stats_init(&r->scan_stats, "rebalance_scan");
	ctxt->stats = &r->scan_stats;

	if (!inum) {
		r->scan_start	= BBPOS_MIN;
		r->scan_end	= BBPOS_MAX;
	} else {
		r->scan_start	= BBPOS(BTREE_ID_extents, POS(inum, 0));
		r->scan_end	= BBPOS(BTREE_ID_extents, POS(inum, U64_MAX));
	}

	r->state = BCH_REBALANCE_scanning;

	int ret = for_each_btree_key_max(trans, iter, BTREE_ID_extents,
					 r->scan_start.pos, r->scan_end.pos,
					 BTREE_ITER_all_snapshots|
					 BTREE_ITER_prefetch, k, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

		atomic64_add(k.k->size, &r->scan_stats.sectors_seen);

		struct bch_inode_opts *opts = bch2_extent_get_apply_io_opts(trans,
					snapshot_io_opts, iter.pos, &iter, k,
					SET_NEEDS_REBALANCE_opt_change);
		PTR_ERR_OR_ZERO(opts) ?:
		(inum &&
		 k.k->type == KEY_TYPE_reflink_p &&
		 REFLINK_P_MAY_UPDATE_OPTIONS(bkey_s_c_to_reflink_p(k).v)
		 ? do_rebalance_scan_indirect(trans, bkey_s_c_to_reflink_p(k), opts)
		 : 0);
	}));
	if (ret)
		goto out;

	if (!inum) {
		ret = for_each_btree_key_max(trans, iter, BTREE_ID_reflink,
					     POS_MIN, POS_MAX,
					     BTREE_ITER_all_snapshots|
					     BTREE_ITER_prefetch, k, ({
			ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

			atomic64_add(k.k->size, &r->scan_stats.sectors_seen);

			struct bch_inode_opts *opts = bch2_extent_get_apply_io_opts(trans,
						snapshot_io_opts, iter.pos, &iter, k,
						SET_NEEDS_REBALANCE_opt_change);
			PTR_ERR_OR_ZERO(opts);
		}));
		if (ret)
			goto out;
	}

	ret = commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_clear_rebalance_needs_scan(trans, inum, cookie));
out:
	*sectors_scanned += atomic64_read(&r->scan_stats.sectors_seen);
	/*
	 * Ensure that the rebalance_work entries we created are seen by the
	 * next iteration of do_rebalance(), so we don't end up stuck in
	 * rebalance_wait():
	 */
	*sectors_scanned += 1;
	bch2_move_stats_exit(&r->scan_stats, c);

	bch2_btree_write_buffer_flush_sync(trans);

	return ret;
}

static void rebalance_wait(struct bch_fs *c)
{
	struct bch_fs_rebalance *r = &c->rebalance;
	struct io_clock *clock = &c->io_clock[WRITE];
	u64 now = atomic64_read(&clock->now);
	u64 min_member_capacity = bch2_min_rw_member_capacity(c);

	if (min_member_capacity == U64_MAX)
		min_member_capacity = 128 * 2048;

	r->wait_iotime_end		= now + (min_member_capacity >> 6);

	if (r->state != BCH_REBALANCE_waiting) {
		r->wait_iotime_start	= now;
		r->wait_wallclock_start	= ktime_get_real_ns();
		r->state		= BCH_REBALANCE_waiting;
	}

	bch2_kthread_io_clock_wait_once(clock, r->wait_iotime_end, MAX_SCHEDULE_TIMEOUT);
}

static bool bch2_rebalance_enabled(struct bch_fs *c)
{
	return c->opts.rebalance_enabled &&
		!(c->opts.rebalance_on_ac_only &&
		  c->rebalance.on_battery);
}

static int do_rebalance(struct moving_context *ctxt)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_rebalance *r = &c->rebalance;
	struct btree_iter extent_iter = {};
	u64 sectors_scanned = 0;
	u32 kick = r->kick;

	struct bpos work_pos = POS_MIN;
	CLASS(darray_rebalance_work, work)();
	int ret = darray_make_room(&work, REBALANCE_WORK_BUF_NR);
	if (ret)
		return ret;

	bch2_move_stats_init(&r->work_stats, "rebalance_work");

	struct per_snapshot_io_opts snapshot_io_opts;
	per_snapshot_io_opts_init(&snapshot_io_opts, c);

	while (!bch2_move_ratelimit(ctxt)) {
		if (!bch2_rebalance_enabled(c)) {
			bch2_moving_ctxt_flush_all(ctxt);
			kthread_wait_freezable(bch2_rebalance_enabled(c) ||
					       kthread_should_stop());
			if (kthread_should_stop())
				break;
		}

		struct bkey_i *k = next_rebalance_entry(trans, &work, &work_pos);
		if (!k)
			break;

		ret = k->k.type == KEY_TYPE_cookie
			? do_rebalance_scan(ctxt, &snapshot_io_opts,
					    k->k.p.inode,
					    le64_to_cpu(bkey_i_to_cookie(k)->v.cookie),
					    &sectors_scanned)
			: do_rebalance_extent(ctxt, &snapshot_io_opts,
					      k->k.p, &extent_iter);
		if (ret)
			break;
	}

	bch2_trans_iter_exit(&extent_iter);
	per_snapshot_io_opts_exit(&snapshot_io_opts);
	bch2_move_stats_exit(&r->work_stats, c);

	if (!ret &&
	    !kthread_should_stop() &&
	    !atomic64_read(&r->work_stats.sectors_seen) &&
	    !sectors_scanned &&
	    kick == r->kick) {
		bch2_moving_ctxt_flush_all(ctxt);
		bch2_trans_unlock_long(trans);
		rebalance_wait(c);
	}

	if (!bch2_err_matches(ret, EROFS))
		bch_err_fn(c, ret);
	return ret;
}

static int bch2_rebalance_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct bch_fs_rebalance *r = &c->rebalance;
	struct moving_context ctxt;

	set_freezable();

	/*
	 * Data move operations can't run until after check_snapshots has
	 * completed, and bch2_snapshot_is_ancestor() is available.
	 */
	kthread_wait_freezable(c->recovery.pass_done > BCH_RECOVERY_PASS_check_snapshots ||
			       kthread_should_stop());

	bch2_moving_ctxt_init(&ctxt, c, NULL, &r->work_stats,
			      writepoint_ptr(&c->rebalance_write_point),
			      true);

	while (!kthread_should_stop() && !do_rebalance(&ctxt))
		;

	bch2_moving_ctxt_exit(&ctxt);

	return 0;
}

void bch2_rebalance_status_to_text(struct printbuf *out, struct bch_fs *c)
{
	printbuf_tabstop_push(out, 32);

	struct bch_fs_rebalance *r = &c->rebalance;

	/* print pending work */
	struct disk_accounting_pos acc;
	disk_accounting_key_init(acc, rebalance_work);
	u64 v;
	bch2_accounting_mem_read(c, disk_accounting_pos_to_bpos(&acc), &v, 1);

	prt_printf(out, "pending work:\t");
	prt_human_readable_u64(out, v << 9);
	prt_printf(out, "\n\n");

	prt_str(out, bch2_rebalance_state_strs[r->state]);
	prt_newline(out);
	guard(printbuf_indent)(out);

	switch (r->state) {
	case BCH_REBALANCE_waiting: {
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
		break;
	}
	case BCH_REBALANCE_working:
		bch2_move_stats_to_text(out, &r->work_stats);
		break;
	case BCH_REBALANCE_scanning:
		bch2_move_stats_to_text(out, &r->scan_stats);
		break;
	}
	prt_newline(out);

	struct task_struct *t;
	scoped_guard(rcu) {
		t = rcu_dereference(c->rebalance.thread);
		if (t)
			get_task_struct(t);
	}

	if (t) {
		bch2_prt_task_backtrace(out, t, 0, GFP_KERNEL);
		put_task_struct(t);
	}
}

void bch2_rebalance_stop(struct bch_fs *c)
{
	struct task_struct *p;

	c->rebalance.pd.rate.rate = UINT_MAX;
	bch2_ratelimit_reset(&c->rebalance.pd.rate);

	p = rcu_dereference_protected(c->rebalance.thread, 1);
	c->rebalance.thread = NULL;

	if (p) {
		/* for sychronizing with bch2_rebalance_wakeup() */
		synchronize_rcu();

		kthread_stop(p);
		put_task_struct(p);
	}
}

int bch2_rebalance_start(struct bch_fs *c)
{
	if (c->rebalance.thread)
		return 0;

	if (c->opts.nochanges)
		return 0;

	struct task_struct *p =
		kthread_create(bch2_rebalance_thread, c, "bch-rebalance/%s", c->name);
	int ret = PTR_ERR_OR_ZERO(p);
	bch_err_msg(c, ret, "creating rebalance thread");
	if (ret)
		return ret;

	get_task_struct(p);
	rcu_assign_pointer(c->rebalance.thread, p);
	wake_up_process(p);
	return 0;
}

#ifdef CONFIG_POWER_SUPPLY
#include <linux/power_supply.h>

static int bch2_rebalance_power_notifier(struct notifier_block *nb,
					 unsigned long event, void *data)
{
	struct bch_fs *c = container_of(nb, struct bch_fs, rebalance.power_notifier);

	c->rebalance.on_battery = !power_supply_is_system_supplied();
	bch2_rebalance_wakeup(c);
	return NOTIFY_OK;
}
#endif

void bch2_fs_rebalance_exit(struct bch_fs *c)
{
#ifdef CONFIG_POWER_SUPPLY
	power_supply_unreg_notifier(&c->rebalance.power_notifier);
#endif
}

int bch2_fs_rebalance_init(struct bch_fs *c)
{
	struct bch_fs_rebalance *r = &c->rebalance;

	bch2_pd_controller_init(&r->pd);

#ifdef CONFIG_POWER_SUPPLY
	r->power_notifier.notifier_call = bch2_rebalance_power_notifier;
	int ret = power_supply_reg_notifier(&r->power_notifier);
	if (ret)
		return ret;

	r->on_battery = !power_supply_is_system_supplied();
#endif
	return 0;
}

static int check_rebalance_work_one(struct btree_trans *trans,
				    struct btree_iter *extent_iter,
				    struct btree_iter *rebalance_iter,
				    struct bkey_buf *last_flushed)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c extent_k, rebalance_k;
	CLASS(printbuf, buf)();

	int ret = bkey_err(extent_k	= bch2_btree_iter_peek(extent_iter)) ?:
		  bkey_err(rebalance_k	= bch2_btree_iter_peek(rebalance_iter));
	if (ret)
		return ret;

	if (!extent_k.k &&
	    extent_iter->btree_id == BTREE_ID_reflink &&
	    (!rebalance_k.k ||
	     rebalance_k.k->p.inode >= BCACHEFS_ROOT_INO)) {
		bch2_trans_iter_exit(extent_iter);
		bch2_trans_iter_init(trans, extent_iter,
				     BTREE_ID_extents, POS_MIN,
				     BTREE_ITER_prefetch|
				     BTREE_ITER_all_snapshots);
		return bch_err_throw(c, transaction_restart_nested);
	}

	if (!extent_k.k && !rebalance_k.k)
		return 1;

	int cmp = bpos_cmp(extent_k.k	 ? extent_k.k->p    : SPOS_MAX,
			   rebalance_k.k ? rebalance_k.k->p : SPOS_MAX);

	struct bkey deleted;
	bkey_init(&deleted);

	if (cmp < 0) {
		deleted.p = extent_k.k->p;
		rebalance_k.k = &deleted;
	} else if (cmp > 0) {
		deleted.p = rebalance_k.k->p;
		extent_k.k = &deleted;
	}

	bool should_have_rebalance =
		bch2_bkey_sectors_need_rebalance(c, extent_k) != 0;
	bool have_rebalance = rebalance_k.k->type == KEY_TYPE_set;

	if (should_have_rebalance != have_rebalance) {
		ret = bch2_btree_write_buffer_maybe_flush(trans, extent_k, last_flushed);
		if (ret)
			return ret;

		bch2_bkey_val_to_text(&buf, c, extent_k);
	}

	if (fsck_err_on(!should_have_rebalance && have_rebalance,
			trans, rebalance_work_incorrectly_set,
			"rebalance work incorrectly set\n%s", buf.buf)) {
		ret = bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work,
						  extent_k.k->p, false);
		if (ret)
			return ret;
	}

	if (fsck_err_on(should_have_rebalance && !have_rebalance,
			trans, rebalance_work_incorrectly_unset,
			"rebalance work incorrectly unset\n%s", buf.buf)) {
		ret = bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work,
						  extent_k.k->p, true);
		if (ret)
			return ret;
	}

	if (cmp <= 0)
		bch2_btree_iter_advance(extent_iter);
	if (cmp >= 0)
		bch2_btree_iter_advance(rebalance_iter);
fsck_err:
	return ret;
}

int bch2_check_rebalance_work(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(btree_iter, extent_iter)(trans, BTREE_ID_reflink, POS_MIN,
				       BTREE_ITER_prefetch);
	CLASS(btree_iter, rebalance_iter)(trans, BTREE_ID_rebalance_work, POS_MIN,
					  BTREE_ITER_prefetch);

	struct bkey_buf last_flushed;
	bch2_bkey_buf_init(&last_flushed);
	bkey_init(&last_flushed.k->k);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_rebalance_work));

	int ret = 0;
	while (!ret) {
		progress_update_iter(trans, &progress, &rebalance_iter);

		bch2_trans_begin(trans);

		ret = check_rebalance_work_one(trans, &extent_iter, &rebalance_iter, &last_flushed);

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			ret = 0;
	}

	bch2_bkey_buf_exit(&last_flushed, c);
	return ret < 0 ? ret : 0;
}
