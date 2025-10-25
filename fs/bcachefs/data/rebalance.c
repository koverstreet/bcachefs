// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/iter.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/compress.h"
#include "data/move.h"
#include "data/rebalance.h"
#include "data/write.h"

#include "init/error.h"
#include "init/progress.h"

#include "fs/inode.h"

#include "snapshots/subvolume.h"

#include "util/clock.h"

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

	if ((flags & BTREE_TRIGGER_transactional) && need_rebalance_delta)
		try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work,
						new.k->p, need_rebalance_delta > 0));

	if (need_rebalance_sectors_delta[0])
		try(bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc,
					      need_rebalance_sectors_delta, rebalance_work));

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

int bch2_update_rebalance_opts(struct btree_trans *trans,
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

	if (bkey_is_btree_ptr(k.k))
		return 0;

	const struct bch_extent_rebalance *old = bch2_bkey_rebalance_opts(k);
	struct bch_extent_rebalance new = io_opts_to_rebalance_opts(c, io_opts);

	if (bkey_should_have_rb_opts(c, io_opts, k)
	    ? old && !memcmp(old, &new, sizeof(new))
	    : !old)
		return 0;

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
							 sizeof(struct bch_extent_rebalance)));
	bkey_reassemble(n, k);

	return  bch2_bkey_set_needs_rebalance(c, io_opts, n, ctx, 0) ?:
		bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node);
}

int bch2_bkey_get_io_opts(struct btree_trans *trans,
			  struct per_snapshot_io_opts *snapshot_opts, struct bkey_s_c k,
			  struct bch_inode_opts *opts)
{
	struct bch_fs *c = trans->c;
	bool metadata = bkey_is_btree_ptr(k.k);

	if (!snapshot_opts) {
		bch2_inode_opts_get(c, opts, metadata);

		if (k.k->p.snapshot) {
			struct bch_inode_unpacked inode;
			int ret = bch2_inode_find_by_inum_snapshot(trans, k.k->p.inode, k.k->p.snapshot,
								   &inode, BTREE_ITER_cached);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
				return ret;
			if (!ret)
				bch2_inode_opts_get_inode(c, &inode, opts);
		}
	} else {
		if (snapshot_opts->fs_io_opts.change_cookie != atomic_read(&c->opt_change_cookie)) {
			bch2_inode_opts_get(c, &snapshot_opts->fs_io_opts, metadata);

			snapshot_opts->cur_inum = 0;
			snapshot_opts->d.nr = 0;
		}

		if (k.k->p.snapshot) {
			if (snapshot_opts->cur_inum != k.k->p.inode) {
				snapshot_opts->d.nr = 0;

				int ret = for_each_btree_key(trans, iter, BTREE_ID_inodes, POS(0, k.k->p.inode),
							     BTREE_ITER_all_snapshots, k, ({
					if (k.k->p.offset != k.k->p.inode)
						break;

					if (!bkey_is_inode(k.k))
						continue;

					struct bch_inode_unpacked inode;
					_ret3 = bch2_inode_unpack(k, &inode);
					if (_ret3)
						break;

					struct snapshot_io_opts_entry e = { .snapshot = k.k->p.snapshot };
					bch2_inode_opts_get_inode(c, &inode, &e.io_opts);

					darray_push(&snapshot_opts->d, e);
				}));

				snapshot_opts->cur_inum = k.k->p.inode;

				return ret ?: bch_err_throw(c, transaction_restart_nested);
			}

			darray_for_each(snapshot_opts->d, i)
				if (bch2_snapshot_is_ancestor(c, k.k->p.snapshot, i->snapshot)) {
					*opts = i->io_opts;
					return 0;
				}
		}

		*opts = snapshot_opts->fs_io_opts;
	}

	const struct bch_extent_rebalance *old;
	if (k.k->type == KEY_TYPE_reflink_v &&
	    (old = bch2_bkey_rebalance_opts(k))) {
#define x(_name)								\
		if (old->_name##_from_inode)					\
			opts->_name		= old->_name;			\
		opts->_name##_from_inode	= old->_name##_from_inode;
		BCH_REBALANCE_OPTS()
#undef x
	}

	return 0;
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

int bch2_set_rebalance_needs_scan(struct bch_fs *c, u64 inum)
{
	CLASS(btree_trans, trans)(c);
	return commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			    bch2_set_rebalance_needs_scan_trans(trans, inum));
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
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

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

	struct bkey_i *n = errptr_try(bch2_bkey_make_mut(trans, iter, &k, 0));

	extent_entry_drop(bkey_i_to_s(n),
			  (void *) bch2_bkey_rebalance_opts(bkey_i_to_s_c(n)));
	return bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

static int rebalance_set_data_opts(struct btree_trans *trans,
				   void *arg,
				   enum btree_id btree,
				   struct bkey_s_c k,
				   struct bch_inode_opts *opts,
				   struct data_update_opts *data_opts)
{
	struct btree_iter *extent_iter = arg;
	struct bch_fs *c = trans->c;

	memset(data_opts, 0, sizeof(*data_opts));
	data_opts->type			= BCH_DATA_UPDATE_rebalance;
	data_opts->ptrs_rewrite		= bch2_bkey_ptrs_need_rebalance(c, opts, k);
	data_opts->target		= opts->background_target;
	data_opts->write_flags		|= BCH_WRITE_only_specified_devs;

	if (!data_opts->ptrs_rewrite) {
		/*
		 * device we would want to write to offline? devices in target
		 * changed?
		 *
		 * We'll now need a full scan before this extent is picked up
		 * again:
		 */
		try(bch2_bkey_clear_needs_rebalance(trans, extent_iter, k));
		return 0;
	}

	count_event(c, rebalance_extent);
	return 1;
}

static int do_rebalance_extent(struct moving_context *ctxt,
			       struct per_snapshot_io_opts *snapshot_io_opts,
			       struct bpos work_pos)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	u32 restart_count = trans->restart_count;

	ctxt->stats = &c->rebalance.work_stats;
	c->rebalance.state = BCH_REBALANCE_working;

	CLASS(btree_iter, iter)(trans, work_pos.inode ? BTREE_ID_extents : BTREE_ID_reflink,
				work_pos, BTREE_ITER_all_snapshots);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	int ret = bch2_move_extent(ctxt, NULL, snapshot_io_opts,
				   rebalance_set_data_opts, NULL,
				   &iter, 0, k);
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
		return ret;
	if (bch2_err_matches(ret, EROFS))
		return ret;
	if (ret) {
		WARN_ONCE(ret != -BCH_ERR_data_update_fail_no_snapshot &&
			  ret != -BCH_ERR_data_update_fail_no_rw_devs,
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

static int do_rebalance_scan_indirect(struct btree_trans *trans,
				      struct bkey_s_c_reflink_p p,
				      struct bch_inode_opts *opts)
{
	u64 idx = REFLINK_P_IDX(p.v) - le32_to_cpu(p.v->front_pad);
	u64 end = REFLINK_P_IDX(p.v) + p.k->size + le32_to_cpu(p.v->back_pad);
	u32 restart_count = trans->restart_count;

	try(for_each_btree_key_commit(trans, iter, BTREE_ID_reflink,
				      POS(0, idx),
				      BTREE_ITER_intent|
				      BTREE_ITER_not_extents, k,
				      NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		if (bpos_ge(bkey_start_pos(k.k), POS(0, end)))
			break;
		bch2_update_rebalance_opts(trans, opts, &iter, k,
					   SET_NEEDS_REBALANCE_opt_change_indirect);
	})));

	/* suppress trans_was_restarted() check */
	trans->restart_count = restart_count;
	return 0;
}

static int do_rebalance_scan_btree(struct moving_context *ctxt,
				   struct per_snapshot_io_opts *snapshot_io_opts,
				   enum btree_id btree, unsigned level,
				   struct bpos start, struct bpos end)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_rebalance *r = &c->rebalance;

	/*
	 * peek(), peek_slot() don't know how to fetch btree root keys - we
	 * really should fix this
	 */
	while (level == bch2_btree_id_root(c, btree)->level + 1) {
		bch2_trans_begin(trans);

		CLASS(btree_node_iter, iter)(trans, btree, start, 0, level - 1,
					     BTREE_ITER_prefetch|
					     BTREE_ITER_not_extents|
					     BTREE_ITER_all_snapshots);
		struct btree *b = bch2_btree_iter_peek_node(&iter);
		int ret = PTR_ERR_OR_ZERO(b);
		if (ret)
			goto root_err;

		if (b != btree_node_root(c, b))
			continue;

		if (btree_node_fake(b))
			return 0;

		struct bkey_s_c k = bkey_i_to_s_c(&b->key);

		struct bch_inode_opts opts;
		ret =   bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts) ?:
			bch2_update_rebalance_opts(trans, &opts, &iter, k, SET_NEEDS_REBALANCE_opt_change);
root_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (bch2_err_matches(ret, BCH_ERR_data_update_fail))
			ret = 0; /* failure for this extent, keep going */
		WARN_ONCE(ret && !bch2_err_matches(ret, EROFS),
			  "unhandled error from move_extent: %s", bch2_err_str(ret));
		return ret;
	}

	bch2_trans_begin(trans);
	CLASS(btree_node_iter, iter)(trans, btree, start, 0, level,
				     BTREE_ITER_prefetch|
				     BTREE_ITER_not_extents|
				     BTREE_ITER_all_snapshots);

	return for_each_btree_key_max_continue(trans, iter, end, 0, k, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

		atomic64_add(!level ? k.k->size : c->opts.btree_node_size >> 9,
			     &r->scan_stats.sectors_seen);

		struct bch_inode_opts opts;

		bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts) ?:
		bch2_update_rebalance_opts(trans, &opts, &iter, k, SET_NEEDS_REBALANCE_opt_change) ?:
		(start.inode &&
		 k.k->type == KEY_TYPE_reflink_p &&
		 REFLINK_P_MAY_UPDATE_OPTIONS(bkey_s_c_to_reflink_p(k).v)
		 ? do_rebalance_scan_indirect(trans, bkey_s_c_to_reflink_p(k), &opts)
		 : 0) ?:
		bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
	}));
}

noinline_for_stack
static int do_rebalance_scan(struct moving_context *ctxt,
			     struct per_snapshot_io_opts *snapshot_io_opts,
			     u64 inum, u64 cookie, u64 *sectors_scanned)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_rebalance *r = &c->rebalance;

	bch2_move_stats_init(&r->scan_stats, "rebalance_scan");
	ctxt->stats = &r->scan_stats;

	r->state = BCH_REBALANCE_scanning;

	if (!inum) {
		r->scan_start	= BBPOS_MIN;
		r->scan_end	= BBPOS_MAX;

		for (enum btree_id btree = 0; btree < btree_id_nr_alive(c); btree++) {
			if (btree != BTREE_ID_extents &&
			    btree != BTREE_ID_reflink)
				continue;

			try(do_rebalance_scan_btree(ctxt, snapshot_io_opts, btree, 0,
						    POS_MIN, SPOS_MAX));
		}
	} else {
		r->scan_start	= BBPOS(BTREE_ID_extents, POS(inum, 0));
		r->scan_end	= BBPOS(BTREE_ID_extents, POS(inum, U64_MAX));

		try(do_rebalance_scan_btree(ctxt, snapshot_io_opts, BTREE_ID_extents, 0,
					    r->scan_start.pos, r->scan_end.pos));
	}

	try(commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_clear_rebalance_needs_scan(trans, inum, cookie)));

	*sectors_scanned += atomic64_read(&r->scan_stats.sectors_seen);
	/*
	 * Ensure that the rebalance_work entries we created are seen by the
	 * next iteration of do_rebalance(), so we don't end up stuck in
	 * rebalance_wait():
	 */
	*sectors_scanned += 1;
	bch2_move_stats_exit(&r->scan_stats, c);

	bch2_btree_write_buffer_flush_sync(trans);
	return 0;
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
	u64 sectors_scanned = 0;
	u32 kick = r->kick;
	int ret = 0;

	struct bpos work_pos = POS_MIN;
	CLASS(darray_rebalance_work, work)();
	try(darray_make_room(&work, REBALANCE_WORK_BUF_NR));

	bch2_move_stats_init(&r->work_stats, "rebalance_work");

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

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
			: lockrestart_do(trans,
				do_rebalance_extent(ctxt, &snapshot_io_opts, k->k.p));
		if (ret)
			break;
	}

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

	set_freezable();

	/*
	 * Data move operations can't run until after check_snapshots has
	 * completed, and bch2_snapshot_is_ancestor() is available.
	 */
	kthread_wait_freezable(c->recovery.pass_done > BCH_RECOVERY_PASS_check_snapshots ||
			       kthread_should_stop());

	struct moving_context ctxt __cleanup(bch2_moving_ctxt_exit);
	bch2_moving_ctxt_init(&ctxt, c, NULL, &r->work_stats,
			      writepoint_ptr(&c->rebalance_write_point),
			      true);

	while (!kthread_should_stop() && !do_rebalance(&ctxt))
		;

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
	try(power_supply_reg_notifier(&r->power_notifier));

	r->on_battery = !power_supply_is_system_supplied();
#endif
	return 0;
}

static int check_rebalance_work_one(struct btree_trans *trans,
				    struct btree_iter *extent_iter,
				    struct btree_iter *rebalance_iter,
				    struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = 0;

	struct bkey_s_c extent_k	= bkey_try(bch2_btree_iter_peek(extent_iter));
	struct bkey_s_c rebalance_k	= bkey_try(bch2_btree_iter_peek(rebalance_iter));

	if (!extent_k.k &&
	    extent_iter->btree_id == BTREE_ID_reflink &&
	    (!rebalance_k.k ||
	     rebalance_k.k->p.inode >= BCACHEFS_ROOT_INO)) {
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
		try(bch2_btree_write_buffer_maybe_flush(trans, extent_k, last_flushed));

		bch2_bkey_val_to_text(&buf, c, extent_k);
	}

	if (fsck_err_on(!should_have_rebalance && have_rebalance,
			trans, rebalance_work_incorrectly_set,
			"rebalance work incorrectly set\n%s", buf.buf))
		try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work, extent_k.k->p, false));

	if (fsck_err_on(should_have_rebalance && !have_rebalance,
			trans, rebalance_work_incorrectly_unset,
			"rebalance work incorrectly unset\n%s", buf.buf))
		try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work, extent_k.k->p, true));

	try(bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

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

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_rebalance_work));

	int ret = 0;
	while (!(ret = lockrestart_do(trans,
			progress_update_iter(trans, &progress, &rebalance_iter) ?:
			wb_maybe_flush_inc(&last_flushed) ?:
			check_rebalance_work_one(trans, &extent_iter, &rebalance_iter, &last_flushed))))
	       ;

	return min(ret, 0);
}
