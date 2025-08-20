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

#define REBALANCE_WORK_SCAN_OFFSET	(U64_MAX - 1)

/* bch_extent_rebalance: */

static const struct bch_extent_rebalance *bch2_bkey_ptrs_rebalance_opts(struct bkey_ptrs_c ptrs)
{
	const union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (__extent_entry_type(entry) == BCH_EXTENT_ENTRY_rebalance)
			return &entry->rebalance;

	return NULL;
}

const struct bch_extent_rebalance *bch2_bkey_rebalance_opts(struct bkey_s_c k)
{
	return bch2_bkey_ptrs_rebalance_opts(bch2_bkey_ptrs_c(k));
}

static const char * const rebalance_opts[] = {
#define x(n) #n,
	BCH_REBALANCE_OPTS()
#undef x
	NULL
};

void bch2_extent_rebalance_to_text(struct printbuf *out, struct bch_fs *c,
				   const struct bch_extent_rebalance *r)
{
	prt_str(out, "need_rb=");
	prt_bitflags(out, rebalance_opts, r->need_rb);

	if (r->hipri)
		prt_str(out, " hipri");
	if (r->pending)
		prt_str(out, " pending");

	prt_printf(out, " replicas=%u", r->data_replicas);
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

/*
 * XXX: check in bkey_validate that if r->hipri or r->pending are set,
 * r->data_replicas are also set
 */

static inline unsigned rb_accounting_counters(const struct bch_extent_rebalance *r)
{
	if (!r)
		return 0;
	unsigned ret = r->need_rb;

	if (r->hipri)
		ret |= BIT(BCH_REBALANCE_ACCOUNTING_high_priority);
	if (r->pending) {
		ret |= BIT(BCH_REBALANCE_ACCOUNTING_pending);
		ret &= ~BIT(BCH_REBALANCE_ACCOUNTING_background_target);
	}
	return ret;
}

int __bch2_trigger_extent_rebalance(struct btree_trans *trans,
				    struct bkey_s_c old, struct bkey_s_c new,
				    unsigned old_r, unsigned new_r,
				    enum btree_iter_update_trigger_flags flags)
{
	int delta = (int) !!new_r - (int) !!old_r;
	if ((flags & BTREE_TRIGGER_transactional) && delta)
		try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_rebalance_work, new.k->p, delta > 0));

	delta = old.k->size == new.k->size
		? old_r ^ new_r
		: old_r | new_r;
	while (delta) {
		unsigned c = __ffs(delta);
		delta ^= BIT(c);

		s64 v[1] = { 0 };
		if (old_r & BIT(c))
			v[0] -= (s64) old.k->size;
		if (new_r & BIT(c))
			v[0] += (s64) new.k->size;

		try(bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc, v, rebalance_work_v2, c));
	}

	return 0;
}

static struct bch_extent_rebalance
bch2_bkey_needs_rebalance(struct bch_fs *c, struct bkey_s_c k,
			  struct bch_inode_opts *opts,
			  unsigned *move_ptrs,
			  unsigned *compress_ptrs,
			  bool may_update_indirect)
{
	*move_ptrs	= 0;
	*compress_ptrs	= 0;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct bch_extent_rebalance r = { .type = BIT(BCH_EXTENT_ENTRY_rebalance) };

	bool poisoned = bch2_bkey_extent_ptrs_flags(ptrs) & BIT_ULL(BCH_EXTENT_FLAG_poisoned);

	const struct bch_extent_rebalance *old_r = bch2_bkey_ptrs_rebalance_opts(ptrs);
	if (old_r) {
		r = *old_r;
		r.need_rb = 0;
	}

#define x(_name)							\
	if (k.k->type != KEY_TYPE_reflink_v ||				\
	    may_update_indirect ||					\
	    (!opts->_name##_from_inode && !r._name##_from_inode)) {	\
		r._name			= opts->_name;			\
		r._name##_from_inode	= opts->_name##_from_inode;	\
	}
	BCH_REBALANCE_OPTS()
#undef x

	unsigned compression_type = bch2_compression_opt_to_type(r.background_compression);

	bool incompressible = false, unwritten = false, ec = false;
	unsigned durability = 0, min_durability = INT_MAX;

	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned ptr_idx = 1;

	guard(rcu)();
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		incompressible	|= p.crc.compression_type == BCH_COMPRESSION_TYPE_incompressible;
		unwritten	|= p.ptr.unwritten;

		struct bch_dev *ca = bch2_dev_rcu_noerror(c, p.ptr.dev);
		if (ca && !p.ptr.cached) {
			if (!poisoned) {
				if (p.crc.compression_type != compression_type) {
					*compress_ptrs |= ptr_idx;
					r.need_rb |= BIT(BCH_REBALANCE_background_compression);
				}

				if (r.background_target &&
				    !bch2_dev_in_target(c, p.ptr.dev, r.background_target)) {
					*move_ptrs |= ptr_idx;
					r.need_rb |= BIT(BCH_REBALANCE_background_target);
				}
			}

			unsigned d = bch2_extent_ptr_durability(c, &p);
			durability += d;
			min_durability = min(min_durability, d);

			ec |= p.has_ec;
		}

		ptr_idx <<= 1;
	}

	if (unwritten || incompressible) {
		*compress_ptrs = 0;
		r.need_rb &= ~BIT(BCH_REBALANCE_background_compression);
	}
	return r;
}

static int check_rebalance_scan_cookie(struct btree_trans *trans, u64 inum, bool *v)
{
	if (v && *v)
		return 1;

	/*
	 * If opts need to be propagated to the extent, a scan cookie should be
	 * present:
	 */
	CLASS(btree_iter, iter)(trans, BTREE_ID_rebalance_work,
				SPOS(inum, REBALANCE_WORK_SCAN_OFFSET, U32_MAX),
				0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	int ret = k.k->type == KEY_TYPE_cookie;
	if (v)
		*v = ret;
	return ret;
}

static int new_needs_rb_allowed(struct btree_trans *trans,
				struct per_snapshot_io_opts *s,
				struct bkey_s_c k,
				enum set_needs_rebalance_ctx ctx,
				unsigned opt_change_cookie,
				const struct bch_extent_rebalance *old,
				const struct bch_extent_rebalance *new,
				unsigned new_need_rb)
{
	struct bch_fs *c = trans->c;
	/*
	 * New need_rb - pointers that don't match the current io path options -
	 * are only allowed in certain situations:
	 *
	 * Propagating new options: from bch2_set_rebalance_needs_scan
	 *
	 * Foreground writes: background_compression and background_target are
	 * allowed
	 *
	 * Foreground writes: we may have raced with an option change:
	 * opt_change_cookie checks for this
	 *
	 * XXX: foreground writes should still match compression,
	 * foreground_target - figure out how to check for this
	 */
	if (ctx == SET_NEEDS_REBALANCE_opt_change ||
	    ctx == SET_NEEDS_REBALANCE_opt_change_indirect)
		return 0;

	if (ctx == SET_NEEDS_REBALANCE_foreground) {
		new_need_rb &= ~(BIT(BCH_REBALANCE_background_compression)|
				 BIT(BCH_REBALANCE_background_target));
		if (!new_need_rb)
			return 0;

		if (opt_change_cookie != atomic_read(&c->opt_change_cookie))
			return 0;
	}

	/*
	 * Either the extent data or the extent io options (from
	 * bch_extent_rebalance) should match the io_opts from the
	 * inode/filesystem, unless
	 *
	 * - There's a scan pending to propagate new options
	 * - It's an indirect extent: it may be referenced by inodes
	 *   with inconsistent options
	 *
	 * For efficiency (so that we can cache checking for scan
	 * cookies), only check option consistency when we're called
	 * with snapshot_io_opts - don't bother when we're called from
	 * move_data_phys() -> get_io_opts_one()
	 *
	 * Note that we can cache the existence of a cookie, but not the
	 * non-existence, to avoid spurious false positives.
	 */
	int ret = check_rebalance_scan_cookie(trans, 0,			s ? &s->fs_scan_cookie : NULL) ?:
		  check_rebalance_scan_cookie(trans, k.k->p.inode,	s ? &s->inum_scan_cookie : NULL);
	if (ret)
		return min(ret, 0);

	CLASS(printbuf, buf)();

	prt_printf(&buf, "extent with incorrect/missing rebalance opts:\n");
	bch2_bkey_val_to_text(&buf, c, k);
	prt_printf(&buf, "\nnew rebalance: ");
	bch2_extent_rebalance_to_text(&buf, c, new);

	const struct bch_extent_rebalance _old = {};
	if (!old)
		old = &_old;

#define x(_name)								\
	if (new_need_rb & BIT(BCH_REBALANCE_##_name))				\
		prt_printf(&buf, "\n" #_name " %u != %u", old->_name, new->_name);
	BCH_REBALANCE_OPTS()
#undef x

	fsck_err(trans, extent_io_opts_not_set, "%s", buf.buf);
fsck_err:
	return ret;
}

static inline bool bkey_should_have_rb_opts(struct bkey_s_c k,
					    struct bch_extent_rebalance new)
{
	if (k.k->type == KEY_TYPE_reflink_v) {
#define x(n)	if (new.n##_from_inode) return true;
		BCH_REBALANCE_OPTS()
#undef x
	}
	return new.need_rb;
}

int bch2_bkey_set_needs_rebalance(struct btree_trans *trans,
				  struct per_snapshot_io_opts *snapshot_io_opts,
				  struct bch_inode_opts *opts,
				  struct bkey_i *_k,
				  enum set_needs_rebalance_ctx ctx,
				  u32 opt_change_cookie)
{
	if (!bkey_extent_is_direct_data(&_k->k))
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_s k = bkey_i_to_s(_k);
	struct bch_extent_rebalance *old =
		(struct bch_extent_rebalance *) bch2_bkey_rebalance_opts(k.s_c);

	unsigned move_ptrs	= 0;
	unsigned compress_ptrs	= 0;
	struct bch_extent_rebalance new =
		bch2_bkey_needs_rebalance(c, k.s_c, opts, &move_ptrs, &compress_ptrs,
					  ctx == SET_NEEDS_REBALANCE_opt_change_indirect);

	bool should_have_rb = bkey_should_have_rb_opts(k.s_c, new);

	if (should_have_rb == !!old &&
	    (should_have_rb ? !memcmp(old, &new, sizeof(new)) : !old))
		return 0;

	unsigned new_need_rb = new.need_rb & ~(old ? old->need_rb : 0);

	if (unlikely(new_need_rb))
		try(new_needs_rb_allowed(trans, snapshot_io_opts, k.s_c, ctx, opt_change_cookie,
					 old, &new, new_need_rb));

	if (should_have_rb) {
		if (!old) {
			old = bkey_val_end(k);
			k.k->u64s += sizeof(*old) / sizeof(u64);
		}

		*old = new;
	} else if (old)
		extent_entry_drop(k, (union bch_extent_entry *) old);

	return 0;
}

int bch2_update_rebalance_opts(struct btree_trans *trans,
			       struct per_snapshot_io_opts *snapshot_io_opts,
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

	struct bch_extent_rebalance *old =
		(struct bch_extent_rebalance *) bch2_bkey_rebalance_opts(k);

	unsigned move_ptrs	= 0;
	unsigned compress_ptrs	= 0;
	struct bch_extent_rebalance new =
		bch2_bkey_needs_rebalance(c, k, io_opts, &move_ptrs, &compress_ptrs,
					  ctx == SET_NEEDS_REBALANCE_opt_change_indirect);

	bool should_have_rb = bkey_should_have_rb_opts(k, new);

	if (should_have_rb == !!old &&
	    (should_have_rb ? !memcmp(old, &new, sizeof(new)) : !old))
		return 0;

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
							 sizeof(struct bch_extent_rebalance)));
	bkey_reassemble(n, k);

	return  bch2_bkey_set_needs_rebalance(trans, snapshot_io_opts, io_opts, n, ctx, 0) ?:
		bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node);
}

struct bch_inode_opts *bch2_extent_get_io_opts(struct btree_trans *trans,
				  struct per_snapshot_io_opts *io_opts, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	if (io_opts->fs_io_opts.change_cookie != atomic_read(&c->opt_change_cookie)) {
		bch2_inode_opts_get(c, &io_opts->fs_io_opts, bkey_is_btree_ptr(k.k));

		io_opts->cur_inum = 0;
		io_opts->d.nr = 0;
	}

	if (bkey_is_btree_ptr(k.k))
		return &io_opts->fs_io_opts;

	if (k.k->type == KEY_TYPE_reflink_v)
		return &io_opts->fs_io_opts;

	if (io_opts->cur_inum != k.k->p.inode) {
		io_opts->d.nr = 0;

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

			darray_push(&io_opts->d, e);
		}));

		io_opts->cur_inum		= k.k->p.inode;
		io_opts->inum_scan_cookie	= false;

		return ERR_PTR(ret ?: bch_err_throw(c, transaction_restart_nested));
	}

	if (k.k->p.snapshot)
		darray_for_each(io_opts->d, i)
			if (bch2_snapshot_is_ancestor(c, k.k->p.snapshot, i->snapshot))
				return &i->io_opts;

	return &io_opts->fs_io_opts;
}

int bch2_extent_get_io_opts_one(struct btree_trans *trans,
				struct bch_inode_opts *opts,
				struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	bch2_inode_opts_get(c, opts, bkey_is_btree_ptr(k.k));

	if (!bkey_is_btree_ptr(k.k) && k.k->type != KEY_TYPE_reflink_v) {
		CLASS(btree_iter, inode_iter)(trans, BTREE_ID_inodes,
				       SPOS(0, k.k->p.inode, k.k->p.snapshot),
				       BTREE_ITER_cached);
		struct bkey_s_c inode_k = bch2_btree_iter_peek_slot(&inode_iter);
		int ret = bkey_err(inode_k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ret;

		if (!ret && bkey_is_inode(inode_k.k)) {
			struct bch_inode_unpacked inode;
			bch2_inode_unpack(inode_k, &inode);
			bch2_inode_opts_get_inode(c, &inode, opts);
		}
	}

	return 0;
}

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

static int rebalance_set_data_opts(struct btree_trans *trans,
				   struct bkey_s_c k,
				   struct bch_inode_opts *opts,
				   struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;
	unsigned move_ptrs	= 0;
	unsigned compress_ptrs	= 0;
	bch2_bkey_needs_rebalance(c, k, opts, &move_ptrs, &compress_ptrs, false);

	memset(data_opts, 0, sizeof(*data_opts));
	data_opts->rewrite_ptrs		= move_ptrs|compress_ptrs;
	data_opts->target		= opts->background_target;
	data_opts->write_flags		|= BCH_WRITE_only_specified_devs;

	if (!data_opts->rewrite_ptrs &&
	    !data_opts->kill_ptrs &&
	    !data_opts->kill_ec_ptrs &&
	    !data_opts->extra_replicas) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "got extent to rebalance but nothing to do, confused\n  ");
		bch2_bkey_val_to_text(&buf, c, k);
		bch_err(c, "%s", buf.buf);
		return 1;
	}

	if (trace_rebalance_extent_enabled()) {
		CLASS(printbuf, buf)();

		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);

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
	return 0;
}

noinline_for_stack
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

	struct bch_inode_opts *opts =
		errptr_try(bch2_extent_get_io_opts(trans, snapshot_io_opts, k));

	try(bch2_update_rebalance_opts(trans, snapshot_io_opts, opts,
				       &iter, k, SET_NEEDS_REBALANCE_other));
	try(bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

	const struct bch_extent_rebalance *r = bch2_bkey_rebalance_opts(k);
	if (!r || !r->need_rb) /* Write buffer race? */
		return 0;

	struct data_update_opts data_opts;
	int ret = rebalance_set_data_opts(trans, k, opts, &data_opts);
	if (ret)
		return ret < 0 ? ret : 0;

	/*
	 * The iterator gets unlocked by __bch2_read_extent - need to
	 * save a copy of @k elsewhere:
	 */

	struct bkey_buf sk __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&sk);
	bch2_bkey_buf_reassemble(&sk, k);
	k = bkey_i_to_s_c(sk.k);

	ret = bch2_move_extent(ctxt, NULL, &iter, k, *opts, data_opts);
	if (ret) {
		if (bch2_err_matches(ret, ENOMEM)) {
			/* memory allocation failure, wait for some IO to finish */
			bch2_move_ctxt_wait_for_io(ctxt);
			return bch_err_throw(c, transaction_restart_nested);
		}

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ret;

		/* skip it and continue, XXX signal failure */
	}

	atomic64_add(k.k->size, &ctxt->stats->sectors_seen);

	/*
	 * Suppress trans_was_restarted() check: read_extent -> ec retry will
	 * handle transaction restarts, and we don't care:
	 */
	trans->restart_count = restart_count;
	return 0;
}

static int do_rebalance_scan_indirect(struct btree_trans *trans,
				      struct bkey_s_c_reflink_p p,
				      struct per_snapshot_io_opts *snapshot_io_opts,
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
		bch2_update_rebalance_opts(trans, snapshot_io_opts, opts, &iter, k,
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

	CLASS(btree_node_iter, iter)(trans, btree, start, 0, level,
				     BTREE_ITER_prefetch|
				     BTREE_ITER_not_extents|
				     BTREE_ITER_all_snapshots);

	return for_each_btree_key_max_continue(trans, iter, end, 0, k, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

		atomic64_add(!level ? k.k->size : c->opts.btree_node_size >> 9,
			     &r->scan_stats.sectors_seen);

		struct bch_inode_opts *opts = bch2_extent_get_io_opts(trans, snapshot_io_opts, k);

		PTR_ERR_OR_ZERO(opts) ?:
		bch2_update_rebalance_opts(trans, snapshot_io_opts, opts, &iter, k,
					   SET_NEEDS_REBALANCE_opt_change) ?:
		(start.inode &&
		 k.k->type == KEY_TYPE_reflink_p &&
		 REFLINK_P_MAY_UPDATE_OPTIONS(bkey_s_c_to_reflink_p(k).v)
		 ? do_rebalance_scan_indirect(trans, bkey_s_c_to_reflink_p(k),
					      snapshot_io_opts, opts)
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
			: lockrestart_do(trans,
				do_rebalance_extent(ctxt, &snapshot_io_opts, k->k.p));
		if (ret)
			break;
	}

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
	try(power_supply_reg_notifier(&r->power_notifier));

	r->on_battery = !power_supply_is_system_supplied();
#endif
	return 0;
}

static int check_rebalance_work_one(struct btree_trans *trans,
				    struct btree_iter *extent_iter,
				    struct btree_iter *rebalance_iter,
				    struct per_snapshot_io_opts *snapshot_io_opts,
				    struct bkey_buf *last_flushed)
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

	bool should_have_rebalance = bch2_bkey_needs_rb(extent_k);
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

	struct bch_inode_opts *opts =
		errptr_try(bch2_extent_get_io_opts(trans, snapshot_io_opts, extent_k));

	try(bch2_update_rebalance_opts(trans, snapshot_io_opts, opts, extent_iter, extent_k,
				       SET_NEEDS_REBALANCE_other));
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
				       BTREE_ITER_not_extents|
				       BTREE_ITER_prefetch);
	CLASS(btree_iter, rebalance_iter)(trans, BTREE_ID_rebalance_work, POS_MIN,
					  BTREE_ITER_prefetch);

	struct per_snapshot_io_opts snapshot_io_opts;
	per_snapshot_io_opts_init(&snapshot_io_opts, c);

	struct bkey_buf last_flushed __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&last_flushed);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_rebalance_work));

	int ret = 0;
	while (!ret) {
		progress_update_iter(trans, &progress, &rebalance_iter);

		ret = lockrestart_do(trans,
			check_rebalance_work_one(trans, &extent_iter, &rebalance_iter,
						 &snapshot_io_opts, &last_flushed));
	}

	per_snapshot_io_opts_exit(&snapshot_io_opts);
	return ret < 0 ? ret : 0;
}
