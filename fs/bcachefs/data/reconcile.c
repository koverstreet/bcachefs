// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/interior.h"
#include "btree/iter.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/compress.h"
#include "data/ec.h"
#include "data/move.h"
#include "data/reconcile.h"
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

#define x(n) #n,

static const char * const reconcile_opts[] = {
	BCH_REBALANCE_OPTS()
	NULL
};

static const char * const reconcile_work_ids[] = {
	RECONCILE_WORK_IDS()
	NULL
};

static const char * const rebalance_scan_strs[] = {
	RECONCILE_SCAN_TYPES()
};

#undef x

#define RECONCILE_SCAN_COOKIE_device	32
#define RECONCILE_SCAN_COOKIE_pending	2
#define RECONCILE_SCAN_COOKIE_metadata	1
#define RECONCILE_SCAN_COOKIE_fs	0

static bool btree_is_reconcile_phys(enum btree_id btree)
{
	return btree == BTREE_ID_reconcile_hipri_phys ||
		btree == BTREE_ID_reconcile_work_phys;
}

static enum reconcile_work_id btree_to_reconcile_work_id(enum btree_id btree)
{
	switch (btree) {
	case BTREE_ID_reconcile_hipri:
		return RECONCILE_WORK_hipri;
	case BTREE_ID_reconcile_work:
		return RECONCILE_WORK_normal;
	case BTREE_ID_reconcile_pending:
		return RECONCILE_WORK_pending;
	default:
		BUG();
	}
}

/* bch_extent_reconcile: */

int bch2_extent_reconcile_validate(struct bch_fs *c,
				   struct bkey_s_c k,
				   struct bkey_validate_context from,
				   const struct bch_extent_reconcile *r)
{
	int ret = 0;

	bkey_fsck_err_on(r->pending && !r->need_rb,
			 c, extent_reconcile_bad_pending,
			 "pending incorrectly set");

	bkey_fsck_err_on(r->hipri && !(r->need_rb & BIT(BCH_REBALANCE_data_replicas)),
			 c, extent_reconcile_bad_hipri,
			 "hipri incorrectly set");

	bkey_fsck_err_on(!r->data_replicas,
			 c, extent_reconcile_bad_replicas,
			 "bad replicas");

fsck_err:
	return ret;
}

static const struct bch_extent_reconcile *bch2_bkey_ptrs_reconcile_opts(const struct bch_fs *c,
									struct bkey_ptrs_c ptrs)
{
	const union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile)
			return &entry->reconcile;

	return NULL;
}

const struct bch_extent_reconcile *bch2_bkey_reconcile_opts(const struct bch_fs *c,
							    struct bkey_s_c k)
{
	return bch2_bkey_ptrs_reconcile_opts(c, bch2_bkey_ptrs_c(k));
}

void bch2_extent_rebalance_v1_to_text(struct printbuf *out, struct bch_fs *c,
				      const struct bch_extent_rebalance_v1 *r)
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

void bch2_extent_reconcile_to_text(struct printbuf *out, struct bch_fs *c,
				      const struct bch_extent_reconcile *r)
{
	prt_str(out, "need_rb=");
	prt_bitflags(out, reconcile_opts, r->need_rb);

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

static inline unsigned rb_accounting_counters(const struct bch_extent_reconcile *r)
{
	if (!r)
		return 0;

	unsigned ret = r->need_rb;
	if (r->pending) {
		ret |=  BIT(BCH_REBALANCE_ACCOUNTING_pending);
		ret &= ~BIT(BCH_REBALANCE_ACCOUNTING_target);
		ret &= ~BIT(BCH_REBALANCE_ACCOUNTING_replicas);
	} else if (r->hipri) {
		ret |=  BIT(BCH_REBALANCE_ACCOUNTING_high_priority);
	}
	return ret;
}

static u64 bch2_bkey_get_reconcile_bp(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile_bp)
			return entry->reconcile_bp.idx;
	return 0;
}

static struct bpos bch2_bkey_get_reconcile_bp_pos(const struct bch_fs *c, struct bkey_s_c k)
{
	return POS(rb_work_id(bch2_bkey_reconcile_opts(c, k)),
		   bch2_bkey_get_reconcile_bp(c, k));
}

static void bch2_bkey_set_reconcile_bp(const struct bch_fs *c, struct bkey_s k, u64 idx)
{
	struct bkey_ptrs ptrs = bch2_bkey_ptrs(k);
	union bch_extent_entry *entry;
	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_reconcile_bp) {
			if (idx)
				entry->reconcile_bp.idx = idx;
			else
				bch2_bkey_extent_entry_drop_s(c, k, entry);
			return;
		}

	if (!idx)
		return;

	struct bch_extent_reconcile_bp r = {
		.type	= BIT(BCH_EXTENT_ENTRY_reconcile_bp),
		.idx	= idx,
	};
	union bch_extent_entry *end = bkey_val_end(k);
	memcpy_u64s(end, &r, sizeof(r) / sizeof(u64));
	k.k->u64s += sizeof(r) / sizeof(u64);
}

static inline struct bch_backpointer rb_bp(enum btree_id btree, unsigned level, struct bkey_s_c k)
{
	return (struct bch_backpointer) {
		.btree_id	= btree,
		.level		= level,
		.pos		= k.k->p,
	};
}

static int reconcile_bp_del(struct btree_trans *trans, enum btree_id btree, unsigned level,
			    struct bkey_s_c k, struct bpos bp_pos)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, bp_pos,
				BTREE_ITER_intent|
				BTREE_ITER_with_updates);
	struct bkey_s_c bp_k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	struct bch_backpointer bp = rb_bp(btree, level, k);

	if (bp_k.k->type != KEY_TYPE_backpointer || memcmp(bp_k.v, &bp, sizeof(bp))) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "btree ptr points to bad/missing reconcile bp\n");
		bch2_bkey_val_to_text(&buf, trans->c, k);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, trans->c, bp_k);

		ret_fsck_err(trans, btree_ptr_to_bad_reconcile_bp, "%s", buf.buf);
		return 0;
	}

	return bch2_btree_delete_at(trans, &iter, 0);
}

static int reconcile_bp_add(struct btree_trans *trans, enum btree_id btree, unsigned level,
			    struct bkey_s k, struct bpos *bp_pos)
{
	CLASS(btree_iter_uninit, iter)(trans);
	try(bch2_bkey_get_empty_slot(trans, &iter, BTREE_ID_reconcile_scan,
				     POS(bp_pos->inode, 1), POS(bp_pos->inode, U64_MAX)));

	*bp_pos = iter.pos;

	struct bkey_i_backpointer *bp = errptr_try(bch2_bkey_alloc(trans, &iter, 0, backpointer));
	bp->v = rb_bp(btree, level, k.s_c);
	return 0;
}

static struct bkey_s_c reconcile_bp_get_key(struct btree_trans *trans,
					    struct btree_iter *iter,
					    struct bkey_s_c_backpointer bp)
{
	struct bch_fs *c = trans->c;
	int ret = 0;
	CLASS(printbuf, buf)();

	/*
	 * we're still using fsck_err() here, which does a goto, which has
	 * problems with CLASS()
	 */
	CLASS(btree_iter_uninit, iter2)(trans);

	/* don't allow bps to non btree nodes: */
	if (fsck_err_on(!bp.v->level,
			trans, reconcile_bp_to_leaf_node_key,
			"reconcile bp to leaf node key\n%s",
			(bch2_bkey_val_to_text(&buf, c, bp.s_c), buf.buf))) {
		ret =   bch2_btree_delete(trans, BTREE_ID_reconcile_scan, bp.k->p, 0) ?:
			bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
		return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
	}

	bch2_trans_node_iter_init(trans, iter, bp.v->btree_id, bp.v->pos, 0, bp.v->level, 0);

	/* walk down a level - we need to have the node pointed to locked, not
	 * the parent node, for synchronization with btree_node_update_key when
	 * the node isn't yet written */

	bch2_trans_node_iter_init(trans, &iter2, bp.v->btree_id, bp.v->pos, 0, bp.v->level - 1, 0);
	struct btree *b = bch2_btree_iter_peek_node(&iter2);
	if (IS_ERR(b))
		return bkey_s_c_err(PTR_ERR(b));

	struct bkey_s_c k = bkey_s_c_null;
	if (b) {
		if (btree_node_will_make_reachable(b))
			return bkey_s_c_null;

		k = bkey_i_to_s_c(&b->key);
		if (bpos_eq(bp.k->p, bch2_bkey_get_reconcile_bp_pos(c, k)))
			return k;
	}

	prt_printf(&buf, "reconcile backpointer to missing/incorrect btree ptr\n");
	bch2_bkey_val_to_text(&buf, c, bp.s_c);
	prt_newline(&buf);
	if (k.k)
		bch2_bkey_val_to_text(&buf, c, k);
	else
		prt_str(&buf, "(no key)");

	if (b) {
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));
	}

	if (fsck_err(trans, reconcile_bp_to_missing_btree_ptr, "%s", buf.buf))
		ret =   bch2_btree_delete(trans, BTREE_ID_reconcile_scan, bp.k->p, 0) ?:
			bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
fsck_err:
	return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
}

static int trigger_dev_counters(struct btree_trans *trans,
				bool metadata,
				struct bkey_s_c k,
				const struct bch_extent_reconcile *r,
				enum btree_iter_update_trigger_flags flags)
{
	if (!r || !r->ptrs_moving || r->pending)
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (r->ptrs_moving & ptr_bit) {
			u64 v[1] = { !metadata ? p.crc.compressed_size : btree_sectors(c) };
			if (flags & BTREE_TRIGGER_overwrite)
				v[0] = -v[0];

			try(bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc, v, dev_leaving, p.ptr.dev));
		}

		ptr_bit <<= 1;
	}

	return 0;
}

static inline struct bpos data_to_rb_work_pos(enum btree_id btree, struct bpos pos)
{
	if (btree == BTREE_ID_reflink ||
	    btree == BTREE_ID_stripes)
		pos = bpos_min(pos, POS(0, U64_MAX));

	if (btree == BTREE_ID_extents)
		pos = bpos_max(pos, POS(BCACHEFS_ROOT_INO, 0));

	if (btree == BTREE_ID_reflink)
		pos.inode++;
	return pos;
}

static inline struct bbpos rb_work_to_data_pos(struct bpos pos)
{
	if (!pos.inode)
		return BBPOS(BTREE_ID_stripes, pos);
	if (pos.inode < BCACHEFS_ROOT_INO) {
		--pos.inode;
		return BBPOS(BTREE_ID_reflink, pos);
	}
	return BBPOS(BTREE_ID_extents, pos);
}

static inline bool extent_has_rotational(struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(ptrs, ptr)
		if (bch2_dev_rotational(c, ptr->dev))
			return true;
	return false;
}

static int reconcile_work_mod(struct btree_trans *trans, struct bkey_s_c k,
			      enum reconcile_work_id w, struct bpos pos, bool set)
{
	return w ? bch2_btree_bit_mod_buffered(trans, reconcile_work_btree[w], pos, set) : 0;
}

int __bch2_trigger_extent_reconcile(struct btree_trans *trans,
				    enum btree_id btree, unsigned level,
				    struct bkey_s_c old, struct bkey_s new,
				    const struct bch_extent_reconcile *old_r,
				    const struct bch_extent_reconcile *new_r,
				    enum btree_iter_update_trigger_flags flags)
{
	if (flags & BTREE_TRIGGER_transactional) {
		enum reconcile_work_id old_work = rb_work_id(old_r);
		enum reconcile_work_id new_work = rb_work_id(new_r);

		if (!level) {
			if (old_work != new_work) {
				/* adjust reflink pos */
				struct bpos pos = data_to_rb_work_pos(btree, new.k->p);

				try(reconcile_work_mod(trans, old,	old_work, pos, false));
				try(reconcile_work_mod(trans, new.s_c,	new_work, pos, true));
			}
		} else {
			struct bch_fs *c = trans->c;
			struct bpos bp = POS(old_work, bch2_bkey_get_reconcile_bp(c, old));

			if (bp.inode != new_work && bp.offset) {
				try(reconcile_bp_del(trans, btree, level, old, bp));
				bp.offset = 0;
			}

			bp.inode = new_work;

			if (bp.inode && !bp.offset)
				try(reconcile_bp_add(trans, btree, level, new, &bp));

			bch2_bkey_set_reconcile_bp(c, new, bp.offset);
		}
	}

	if (flags & (BTREE_TRIGGER_transactional|BTREE_TRIGGER_gc)) {
		bool metadata = level != 0;
		s64 old_size = !metadata ? old.k->size : btree_sectors(trans->c);
		s64 new_size = !metadata ? new.k->size : btree_sectors(trans->c);

		unsigned old_a = rb_accounting_counters(old_r);
		unsigned new_a = rb_accounting_counters(new_r);

		unsigned delta = old_size == new_size
			? old_a ^ new_a
			: old_a | new_a;

		while (delta) {
			unsigned c = __ffs(delta);
			delta ^= BIT(c);

			s64 v[2] = { 0, 0 };
			if (old_a & BIT(c))
				v[metadata] -= old_size;
			if (new_a & BIT(c))
				v[metadata] += new_size;

			try(bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc, v, reconcile_work, c));
		}

		try(trigger_dev_counters(trans, metadata, old,     old_r, flags & ~BTREE_TRIGGER_insert));
		try(trigger_dev_counters(trans, metadata, new.s_c, new_r, flags & ~BTREE_TRIGGER_overwrite));
	}

	return 0;
}

static inline bool bkey_should_have_rb_opts(struct bkey_s_c k,
					    struct bch_extent_reconcile new)
{
	if (k.k->type == KEY_TYPE_reflink_v) {
#define x(n)	if (new.n##_from_inode) return true;
		BCH_REBALANCE_OPTS()
#undef x
	}
	return new.need_rb;
}

static bool bch2_bkey_needs_reconcile(struct bch_fs *c, struct bkey_s_c k,
				      struct bch_inode_opts *opts,
				      int *need_update_invalid_devs,
				      struct bch_extent_reconcile *ret)
{
	bool btree = bkey_is_btree_ptr(k.k);

	if (btree &&
	    bch2_request_incompat_feature(c, bcachefs_metadata_version_reconcile))
		return false;

	struct bch_extent_reconcile r = {
		.type = BIT(BCH_EXTENT_ENTRY_reconcile),
#define x(_name)							\
		._name			= opts->_name,			\
		._name##_from_inode	= opts->_name##_from_inode,
	BCH_REBALANCE_OPTS()
#undef x
	};

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bool poisoned = bch2_bkey_extent_ptrs_flags(ptrs) & BIT_ULL(BCH_EXTENT_FLAG_poisoned);
	unsigned compression_type = bch2_compression_opt_to_type(r.background_compression);
	unsigned csum_type	= bch2_data_checksum_type_rb(c, r);

	bool incompressible = false, unwritten = false, ec = false;
	unsigned durability = 0, durability_acct = 0, invalid = 0, min_durability = INT_MAX;

	scoped_guard(rcu) {
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		unsigned ptr_bit = 1;

		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			incompressible	|= p.crc.compression_type == BCH_COMPRESSION_TYPE_incompressible;
			unwritten	|= p.ptr.unwritten;

			struct bch_dev *ca = bch2_dev_rcu_noerror(c, p.ptr.dev);
			if (ca && !p.ptr.cached) {
				if (!poisoned &&
				    !btree &&
				    p.crc.csum_type != csum_type)
					r.need_rb |= BIT(BCH_REBALANCE_data_checksum);

				if (!poisoned &&
				    p.crc.compression_type != compression_type)
					r.need_rb |= BIT(BCH_REBALANCE_background_compression);

				if (!poisoned &&
				    r.background_target &&
				    !bch2_dev_in_target(c, p.ptr.dev, r.background_target)) {
					r.need_rb |= BIT(BCH_REBALANCE_background_target);
					r.ptrs_moving |= ptr_bit;
				}

				if (ca->mi.state == BCH_MEMBER_STATE_evacuating) {
					r.need_rb |= BIT(BCH_REBALANCE_data_replicas);
					r.hipri = 1;
					r.ptrs_moving |= ptr_bit;
				}

				unsigned d = __extent_ptr_durability(ca, &p);

				durability_acct += d;

				if (ca->mi.state == BCH_MEMBER_STATE_evacuating)
					d = 0;

				durability += d;
				min_durability = min(min_durability, d);

				ec |= p.has_ec;
			}

			invalid += p.ptr.dev == BCH_SB_MEMBER_INVALID;

			ptr_bit <<= 1;
		}
	}

	if (unwritten || incompressible)
		r.need_rb &= ~BIT(BCH_REBALANCE_background_compression);

	if (unwritten)
		r.need_rb &= ~BIT(BCH_REBALANCE_data_checksum);

	if (durability < r.data_replicas) {
		r.need_rb |= BIT(BCH_REBALANCE_data_replicas);
		r.hipri = 1;
	}

	if (durability >= r.data_replicas + min_durability)
		r.need_rb |= BIT(BCH_REBALANCE_data_replicas);

	if (!unwritten && r.erasure_code != ec)
		r.need_rb |= BIT(BCH_REBALANCE_erasure_code);

	*need_update_invalid_devs =
		min_t(int, durability_acct + invalid - r.data_replicas, invalid);

	/* Multiple pointers to BCH_SB_MEMBER_INVALID is an incompat feature: */
	if (*need_update_invalid_devs < 0 &&
	    bch2_request_incompat_feature(c, bcachefs_metadata_version_reconcile))
		*need_update_invalid_devs = 0;

	const struct bch_extent_reconcile *old = bch2_bkey_ptrs_reconcile_opts(c, ptrs);
	if (old && !(old->need_rb & ~r.need_rb)) {
		r.pending = old->pending;
		if (r.hipri && !old->hipri)
			r.pending = 0;
	}

	bool should_have_rb = bkey_should_have_rb_opts(k, r);

	*ret = r;

	return (*need_update_invalid_devs ||
		should_have_rb != !!old ||
		(should_have_rb ? memcmp(old, &r, sizeof(r)) : old != NULL)) &&
		!bch2_request_incompat_feature(c, bcachefs_metadata_version_sb_field_extent_type_u64s);
}

static int check_reconcile_scan_cookie(struct btree_trans *trans, u64 inum, bool *v)
{
	if (v && *v)
		return 1;

	/*
	 * If opts need to be propagated to the extent, a scan cookie should be
	 * present:
	 */
	CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, POS(0, inum), 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	int ret = k.k->type == KEY_TYPE_cookie;
	if (v)
		*v = ret;
	return ret;
}

static int check_dev_reconcile_scan_cookie(struct btree_trans *trans, struct bkey_s_c k,
					   struct bch_devs_mask *v)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == BCH_SB_MEMBER_INVALID)
			continue;

		if (v && test_bit(ptr->dev, v->d))
			return 1;
	}

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == BCH_SB_MEMBER_INVALID)
			continue;

		int ret = check_reconcile_scan_cookie(trans,
				RECONCILE_SCAN_COOKIE_device + ptr->dev, NULL);
		if (ret < 0)
			return ret;
		if (ret) {
			if (v)
				__set_bit(ptr->dev, v->d);
			return ret;
		}
	}

	return 0;
}

static bool bkey_has_ec(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_stripe_ptr)
			return true;
	return false;
}

static int new_needs_rb_allowed(struct btree_trans *trans,
				struct per_snapshot_io_opts *s,
				struct bkey_s_c k,
				enum set_needs_reconcile_ctx ctx,
				unsigned opt_change_cookie,
				const struct bch_extent_reconcile *old,
				const struct bch_extent_reconcile *new,
				unsigned new_need_rb)
{
	struct bch_fs *c = trans->c;
	/*
	 * New need_rb - pointers that don't match the current io path options -
	 * are only allowed in certain situations:
	 *
	 * Propagating new options: from bch2_set_reconcile_needs_scan
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

	if ((new_need_rb & BIT(BCH_REBALANCE_erasure_code)) &&
	    !bkey_has_ec(c, k)) {
		/* Foreground writes are not initially erasure coded - and we
		 * may crash before a stripe is created
		 */
		new_need_rb &= ~BIT(BCH_REBALANCE_erasure_code);
	}

	if (ctx == SET_NEEDS_REBALANCE_foreground) {
		new_need_rb &= ~(BIT(BCH_REBALANCE_background_compression)|
				 BIT(BCH_REBALANCE_background_target));

		/*
		 * Foreground writes might end up degraded when a device is
		 * getting yanked:
		 *
		 * XXX: this is something we need to fix, but adding retries to
		 * the write path is something we have to do carefully.
		 */
		new_need_rb &= ~BIT(BCH_REBALANCE_data_replicas);
		if (!new_need_rb)
			return 0;

		if (opt_change_cookie != atomic_read(&c->opt_change_cookie))
			return 0;
	}

	/*
	 * Either the extent data or the extent io options (from
	 * bch_extent_reconcile) should match the io_opts from the
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
	int ret = check_reconcile_scan_cookie(trans, 0,			s ? &s->fs_scan_cookie : NULL) ?:
		  check_reconcile_scan_cookie(trans, k.k->p.inode,	s ? &s->inum_scan_cookie : NULL);
	if (ret)
		return min(ret, 0);

	if (new_need_rb == BIT(BCH_REBALANCE_data_replicas)) {
		ret = check_dev_reconcile_scan_cookie(trans, k, s ? &s->dev_cookie : NULL);
		if (ret)
			return min(ret, 0);
	}

	CLASS(printbuf, buf)();

	prt_printf(&buf, "extent with incorrect/missing reconcile opts:\n");
	bch2_bkey_val_to_text(&buf, c, k);
	prt_printf(&buf, "\nnew reconcile : ");
	bch2_extent_reconcile_to_text(&buf, c, new);

	const struct bch_extent_reconcile _old = {};
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

int bch2_bkey_set_needs_reconcile(struct btree_trans *trans,
				  struct per_snapshot_io_opts *snapshot_io_opts,
				  struct bch_inode_opts *opts,
				  struct bkey_i *_k,
				  enum set_needs_reconcile_ctx ctx,
				  u32 opt_change_cookie)
{
	if (!bkey_extent_is_direct_data(&_k->k))
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_s k = bkey_i_to_s(_k);

	int need_update_invalid_devs;
	struct bch_extent_reconcile new;

	if (!bch2_bkey_needs_reconcile(c, k.s_c, opts, &need_update_invalid_devs, &new))
		return 0;

	struct bch_extent_reconcile *old =
		(struct bch_extent_reconcile *) bch2_bkey_reconcile_opts(c, k.s_c);
	unsigned new_need_rb = new.need_rb & ~(old ? old->need_rb : 0);

	if (unlikely(new_need_rb))
		try(new_needs_rb_allowed(trans, snapshot_io_opts, k.s_c, ctx, opt_change_cookie,
					 old, &new, new_need_rb));

	if (bkey_should_have_rb_opts(k.s_c, new)) {
		if (!old) {
			old = bkey_val_end(k);
			k.k->u64s += sizeof(*old) / sizeof(u64);
		}

		*old = new;
	} else if (old)
		extent_entry_drop(c, k, (union bch_extent_entry *) old);

	if (unlikely(need_update_invalid_devs)) {
		if (need_update_invalid_devs > 0) {
			bch2_bkey_drop_ptrs(k, p, entry,
				(p.ptr.dev == BCH_SB_MEMBER_INVALID &&
				 need_update_invalid_devs &&
				 need_update_invalid_devs--));
		} else {
			need_update_invalid_devs = -need_update_invalid_devs;

			trans->extra_disk_res += (u64) need_update_invalid_devs *
				(bkey_is_btree_ptr(k.k) ? btree_sectors(c) : k.k->size);

			while (need_update_invalid_devs--) {
				union bch_extent_entry *end = bkey_val_end(k);

				end->ptr = (struct bch_extent_ptr) {
					.type	= BIT(BCH_EXTENT_ENTRY_ptr),
					.dev	= BCH_SB_MEMBER_INVALID,
				};

				_k->k.u64s++;
			}
		}
	}

	return 0;
}

int bch2_update_reconcile_opts(struct btree_trans *trans,
			       struct per_snapshot_io_opts *snapshot_io_opts,
			       struct bch_inode_opts *opts,
			       struct btree_iter *iter,
			       unsigned level,
			       struct bkey_s_c k,
			       enum set_needs_reconcile_ctx ctx)
{
	BUG_ON(iter->flags & BTREE_ITER_is_extents);
	BUG_ON(iter->flags & BTREE_ITER_filter_snapshots);

	if (!bkey_extent_is_direct_data(k.k))
		return 0;

	struct bch_fs *c = trans->c;
	int need_update_invalid_devs;
	struct bch_extent_reconcile new;

	if (!bch2_bkey_needs_reconcile(c, k, opts, &need_update_invalid_devs, &new))
		return 0;

	if (!level) {
		struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
							sizeof(struct bch_extent_reconcile) +
							sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX));
		bkey_reassemble(n, k);

		return  bch2_bkey_set_needs_reconcile(trans, snapshot_io_opts, opts, n, ctx, 0) ?:
			bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node);
	} else {
		CLASS(btree_node_iter, iter2)(trans, iter->btree_id, iter->pos, 0, level - 1, 0);
		struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter2));

		struct bkey_i *n =
			errptr_try(bch2_trans_kmalloc(trans, BKEY_BTREE_PTR_U64s_MAX * sizeof(u64)));
		bkey_copy(n, &b->key);

		return  bch2_bkey_set_needs_reconcile(trans, snapshot_io_opts, opts, n, ctx, 0) ?:
			bch2_btree_node_update_key(trans, &iter2, b, n, BCH_TRANS_COMMIT_no_enospc, false) ?:
			bch_err_throw(c, transaction_restart_commit);
	}
}

int bch2_bkey_get_io_opts(struct btree_trans *trans,
			  struct per_snapshot_io_opts *snapshot_opts, struct bkey_s_c k,
			  struct bch_inode_opts *opts)
{
	struct bch_fs *c = trans->c;
	enum io_opts_mode {
		IO_OPTS_metadata,
		IO_OPTS_reflink,
		IO_OPTS_user,
	} mode;

	if (bkey_is_btree_ptr(k.k))
		mode = IO_OPTS_metadata;
	else if (bkey_is_indirect(k.k))
		mode = IO_OPTS_reflink;
	else if (bkey_is_user_data(k.k)) {
		mode = IO_OPTS_user;

		if (unlikely(!k.k->p.snapshot)) {
			CLASS(printbuf, buf)();
			bch2_bkey_val_to_text(&buf, trans->c, k);
			WARN(1, "user data key with snapshot == 0\n%s", buf.buf);
			bch2_inode_opts_get(c, opts, false);
			return 0;
		}
	} else {
		/* KEY_TYPE_error? */
		bch2_inode_opts_get(c, opts, false);
		return 0;
	}

	if (!snapshot_opts) {
		bch2_inode_opts_get(c, opts, mode == IO_OPTS_metadata);

		if (mode == IO_OPTS_user) {
			struct bch_inode_unpacked inode;
			int ret = bch2_inode_find_by_inum_snapshot(trans, k.k->p.inode, k.k->p.snapshot,
								   &inode, BTREE_ITER_cached);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
				return ret;
			if (!ret)
				bch2_inode_opts_get_inode(c, &inode, opts);
		}
	} else {
		/*
		 * If we have a per_snapshot_io_opts, we're doing a scan in
		 * natural key order: we can cache options for the inode number
		 * we're currently on, but we have to cache options from every
		 * different snapshot version of that inode
		 */

		bool metadata = mode == IO_OPTS_metadata;
		if (snapshot_opts->fs_io_opts.change_cookie	!= atomic_read(&c->opt_change_cookie) ||
		    snapshot_opts->metadata			!= metadata) {
			bch2_inode_opts_get(c, &snapshot_opts->fs_io_opts, metadata);

			snapshot_opts->metadata = metadata;
			snapshot_opts->cur_inum = 0;
			snapshot_opts->d.nr	= 0;
		}

		if (mode == IO_OPTS_user) {
			if (snapshot_opts->cur_inum != k.k->p.inode) {
				snapshot_opts->d.nr = 0;

				try(for_each_btree_key_max(trans, iter, BTREE_ID_inodes,
							   SPOS(0, k.k->p.inode, 0),
							   SPOS(0, k.k->p.inode, U32_MAX),
							   BTREE_ITER_all_snapshots, inode_k, ({
					struct bch_inode_unpacked inode;
					if (!bkey_is_inode(inode_k.k) ||
					    bch2_inode_unpack(inode_k, &inode))
						continue;

					struct snapshot_io_opts_entry e = { .snapshot = inode_k.k->p.snapshot };
					bch2_inode_opts_get_inode(c, &inode, &e.io_opts);

					darray_push(&snapshot_opts->d, e);
				})));

				snapshot_opts->cur_inum	= k.k->p.inode;
				snapshot_opts->inum_scan_cookie	= false;

				return bch_err_throw(c, transaction_restart_nested);
			}

			struct snapshot_io_opts_entry *i =
				darray_find_p(snapshot_opts->d, i,
					      bch2_snapshot_is_ancestor(c, k.k->p.snapshot, i->snapshot));
			if (i) {
				*opts = i->io_opts;
				return 0;
			}
		}

		*opts = snapshot_opts->fs_io_opts;
	}

	const struct bch_extent_reconcile *old;
	if (mode == IO_OPTS_reflink &&
	    (old = bch2_bkey_reconcile_opts(c, k))) {
#define x(_name)								\
		if (old->_name##_from_inode)					\
			opts->_name		= old->_name;			\
		opts->_name##_from_inode	= old->_name##_from_inode;
		BCH_REBALANCE_OPTS()
#undef x
	}

	return 0;
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
	prt_str(out, rebalance_scan_strs[s.type]);
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
	return commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, pos, BTREE_ITER_intent);
		struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

		u64 v = k.k->type == KEY_TYPE_cookie
			? le64_to_cpu(bkey_s_c_to_cookie(k).v->cookie)
			: 0;
		v == cookie
			? bch2_btree_delete_at(trans, &iter, 0)
			: 0;
	}));
}

#define REBALANCE_WORK_BUF_NR		1024
DEFINE_DARRAY_NAMED(darray_reconcile_work, struct bkey_i);

static struct bkey_s_c next_reconcile_entry(struct btree_trans *trans,
					    darray_reconcile_work *buf,
					    enum btree_id btree,
					    struct bpos *work_pos)
{
	if (btree == BTREE_ID_reconcile_scan) {
		buf->nr = 0;

		int ret = for_each_btree_key(trans, iter, btree, *work_pos,
				   BTREE_ITER_all_snapshots|BTREE_ITER_prefetch, k, ({
			bkey_reassemble(&darray_top(*buf), k);
			return bkey_i_to_s_c(&darray_top(*buf));
			0;
		}));

		return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
	}

	if (unlikely(!buf->nr)) {
		/* Avoid contention with write buffer flush: buffer up work entries in a darray */

		BUG_ON(!buf->size);;

		int ret = for_each_btree_key(trans, iter, btree, *work_pos,
				   BTREE_ITER_all_snapshots|BTREE_ITER_prefetch, k, ({
			/* There might be leftover scan cookies from rebalance, pre reconcile upgrade: */
			if (k.k->type != KEY_TYPE_set)
				continue;

			BUG_ON(bkey_bytes(k.k) > sizeof(buf->data[0]));

			/* we previously used darray_make_room */
			bkey_reassemble(&darray_top(*buf), k);
			buf->nr++;

			*work_pos = bpos_successor(iter.pos);
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

static int reconcile_set_data_opts(struct btree_trans *trans,
				   void *arg,
				   enum btree_id btree,
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

	if (r->need_rb & BIT(BCH_REBALANCE_data_replicas)) {
		unsigned durability = bch2_bkey_durability(c, k);
		unsigned ptr_bit = 1;

		guard(rcu)();
		if (durability <= r->data_replicas) {
			bkey_for_each_ptr(ptrs, ptr) {
				struct bch_dev *ca = bch2_dev_rcu_noerror(c, ptr->dev);
				if (ca && !ptr->cached && !ca->mi.durability)
					data_opts->ptrs_kill |= ptr_bit;
				ptr_bit <<= 1;
			}

			data_opts->extra_replicas = r->data_replicas - durability;
		} else {
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				unsigned d = bch2_extent_ptr_durability(c, &p);

				if (d && durability - d >= r->data_replicas) {
					data_opts->ptrs_kill |= ptr_bit;
					durability -= d;
				}

				ptr_bit <<= 1;
			}

			ptr_bit = 1;
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				if (p.has_ec && durability - p.ec.redundancy >= r->data_replicas) {
					data_opts->ptrs_kill_ec |= ptr_bit;
					durability -= p.ec.redundancy;
				}

				ptr_bit <<= 1;
			}
		}
	}

	if (r->need_rb & BIT(BCH_REBALANCE_erasure_code)) {
		if (r->erasure_code) {
			/* XXX: we'll need ratelimiting */
			if (extent_ec_pending(trans, ptrs))
				return false;

			data_opts->extra_replicas = r->data_replicas;
		} else {
			unsigned ptr_bit = 1;
			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				if (p.has_ec) {
					data_opts->ptrs_kill_ec |= ptr_bit;
					data_opts->extra_replicas += p.ec.redundancy;
				}

				ptr_bit <<= 1;
			}
		}
	}

	scoped_guard(rcu) {
		unsigned ptr_bit = 1;
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if ((r->need_rb & BIT(BCH_REBALANCE_data_checksum)) &&
			    p.crc.csum_type != csum_type)
				data_opts->ptrs_rewrite |= ptr_bit;

			if ((r->need_rb & BIT(BCH_REBALANCE_background_compression)) &&
			    p.crc.compression_type != compression_type)
				data_opts->ptrs_rewrite |= ptr_bit;

			if ((r->need_rb & BIT(BCH_REBALANCE_background_target)) &&
			    !bch2_dev_in_target(c, p.ptr.dev, r->background_target))
				data_opts->ptrs_rewrite |= ptr_bit;

			ptr_bit <<= 1;
		}
	}

	bool ret = (data_opts->ptrs_rewrite ||
		    data_opts->ptrs_kill ||
		    data_opts->ptrs_kill_ec ||
		    data_opts->extra_replicas);
	if (!ret) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "got extent to reconcile but nothing to do, confused\n  ");
		bch2_bkey_val_to_text(&buf, c, k);
		bch_err(c, "%s", buf.buf);
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
					     struct bkey_s_c k, bool set)
{
	struct bch_fs *c = trans->c;

	if ((rb_work_id(bch2_bkey_reconcile_opts(c, k)) == RECONCILE_WORK_pending) == set)
		return 0;

	try(bch2_trans_relock(trans));

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k)));
	bkey_reassemble(n, k);

	if (!iter->min_depth) {
		bkey_reconcile_pending_mod(c, n, set);

		return  bch2_trans_update(trans, iter, n, 0) ?:
			bch2_trans_commit(trans, NULL, NULL,
					  BCH_TRANS_COMMIT_no_enospc);
	} else {
		CLASS(btree_node_iter, iter2)(trans, iter->btree_id, k.k->p, 0, iter->min_depth - 1, 0);
		struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter2));

		if (!bkey_and_val_eq(bkey_i_to_s_c(&b->key), bkey_i_to_s_c(n))) {
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

static bool is_reconcile_pending_err(struct bch_fs *c, struct bkey_s_c k, int err)
{
	 bool ret = (bch2_err_matches(err, BCH_ERR_data_update_fail_no_rw_devs) ||
		     bch2_err_matches(err, BCH_ERR_insufficient_devices) ||
		     bch2_err_matches(err, ENOSPC));
	 if (ret)
		event_add_trace(c, reconcile_set_pending, k.k->size, buf, ({
			prt_printf(&buf, "%s\n", bch2_err_str(err));
			bch2_bkey_val_to_text(&buf, c, k);
		}));
	 return ret;
}

static int __do_reconcile_extent(struct moving_context *ctxt,
				 struct per_snapshot_io_opts *snapshot_io_opts,
				 struct btree_iter *iter, struct bkey_s_c k)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	u32 restart_count = trans->restart_count;

	ctxt->stats = &c->reconcile.work_stats;

	int ret = bch2_move_extent(ctxt, NULL, snapshot_io_opts,
				   reconcile_set_data_opts, NULL,
				   iter, iter->min_depth, k);
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
	    bch2_err_matches(ret, EROFS))
		return ret;
	if (is_reconcile_pending_err(c, k, ret))
		return bch2_extent_reconcile_pending_mod(trans, iter, k, true);
	if (ret) {
		WARN_ONCE(ret != -BCH_ERR_data_update_fail_no_snapshot,
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

	if (work.btree == BTREE_ID_reconcile_pending) {
		struct bch_inode_opts opts;
		try(bch2_bkey_get_io_opts(trans, snapshot_io_opts, k, &opts));

		struct data_update_opts data_opts = { .read_dev = -1 };
		reconcile_set_data_opts(trans, NULL, data_pos.btree, k, &opts, &data_opts);

		struct bch_devs_list devs_have = bch2_data_update_devs_keeping(c, &data_opts, k);
		int ret = bch2_can_do_write(c, &opts, &data_opts, k, &devs_have);
		if (ret) {
			if (is_reconcile_pending_err(c, k, ret))
				return 0;
			return ret;
		}

		if (extent_has_rotational(c, k))
			return bch2_extent_reconcile_pending_mod(trans, &iter, k, false);
	}

	event_add_trace(c, reconcile_data, k.k->size, buf,
			bch2_bkey_val_to_text(&buf, c, k));

	return __do_reconcile_extent(ctxt, snapshot_io_opts, &iter, k);
}

static int do_reconcile_phys(struct moving_context *ctxt,
			     struct per_snapshot_io_opts *snapshot_io_opts,
			     struct bpos bp_pos, struct wb_maybe_flush *last_flushed)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	CLASS(btree_iter, bp_iter)(trans, BTREE_ID_backpointers, bp_pos, 0);
	struct bkey_s_c bp_k = bkey_try(bch2_btree_iter_peek_slot(&bp_iter));
	if (!bp_k.k || bp_k.k->type != KEY_TYPE_backpointer) /* write buffer race */
		return 0;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_backpointer_get_key(trans, bkey_s_c_to_backpointer(bp_k),
							      &iter, 0, last_flushed));
	if (!k.k)
		return 0;

	event_add_trace(c, reconcile_phys, k.k->size, buf, ({
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bp_k);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, k);
	}));

	return __do_reconcile_extent(ctxt, snapshot_io_opts, &iter, k);
}

noinline_for_stack
static int do_reconcile_btree(struct moving_context *ctxt,
			      struct per_snapshot_io_opts *snapshot_io_opts,
			      struct bkey_s_c_backpointer bp)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(reconcile_bp_get_key(trans, &iter, bp));
	if (!k.k)
		return 0;

	event_add_trace(c, reconcile_btree, btree_sectors(c), buf,
			bch2_bkey_val_to_text(&buf, c, k));

	return __do_reconcile_extent(ctxt, snapshot_io_opts, &iter, k);
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
					  SET_NEEDS_REBALANCE_opt_change);
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

	CLASS(disk_reservation, res)(c);

	return for_each_btree_key_max_commit(trans, iter, BTREE_ID_backpointers,
					  POS(s.dev, 0), POS(s.dev, U64_MAX),
					  BTREE_ITER_prefetch, k,
					  &res.r, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

		if (k.k->type != KEY_TYPE_backpointer)
			continue;

		bch2_disk_reservation_put(c, &res.r);
		do_reconcile_scan_bp(trans, s, bkey_s_c_to_backpointer(k), last_flushed);
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
			update_reconcile_opts_scan(trans, snapshot_io_opts, &opts, &iter, level, k, s);
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
	CLASS(disk_reservation, res)(c);

	return for_each_btree_key_max_continue(trans, iter, end, 0, k, ({
		ctxt->stats->pos = BBPOS(iter.btree_id, iter.pos);

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

static bool bch2_reconcile_enabled(struct bch_fs *c)
{
	return c->opts.reconcile_enabled &&
		!(c->opts.reconcile_on_ac_only &&
		  c->reconcile.on_battery);
}

static int do_reconcile(struct moving_context *ctxt)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct bch_fs_reconcile *r = &c->reconcile;
	u64 sectors_scanned = 0;
	u32 kick = r->kick;
	int ret = 0;

	CLASS(darray_reconcile_work, work)();
	try(darray_make_room(&work, REBALANCE_WORK_BUF_NR));

	bch2_move_stats_init(&r->work_stats, "reconcile_work");

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

	static enum btree_id scan_btrees[] = {
		BTREE_ID_reconcile_scan,
		BTREE_ID_reconcile_hipri_phys,
		BTREE_ID_reconcile_hipri,
		BTREE_ID_reconcile_work_phys,
		BTREE_ID_reconcile_work,
		BTREE_ID_reconcile_pending,
	};
	unsigned i = 0;

	r->work_pos = BBPOS(scan_btrees[i], POS_MIN);

	struct bkey_i_cookie pending_cookie;
	bkey_init(&pending_cookie.k);

	bch2_moving_ctxt_flush_all(ctxt);
	bch2_btree_write_buffer_flush_sync(trans);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	while (!bch2_move_ratelimit(ctxt)) {
		if (!bch2_reconcile_enabled(c)) {
			bch2_moving_ctxt_flush_all(ctxt);
			kthread_wait_freezable(bch2_reconcile_enabled(c) ||
					       kthread_should_stop());
			if (kthread_should_stop())
				break;
		}

		if (kick != r->kick) {
			kick		= r->kick;
			i		= 0;
			r->work_pos	= BBPOS(scan_btrees[i], POS_MIN);
			work.nr		= 0;
		}

		bch2_trans_begin(trans);

		struct bkey_s_c k = next_reconcile_entry(trans, &work, r->work_pos.btree, &r->work_pos.pos);
		ret = bkey_err(k);
		if (ret)
			break;

		if (!k.k) {
			if (++i == ARRAY_SIZE(scan_btrees))
				break;

			r->work_pos = BBPOS(scan_btrees[i], POS_MIN);

			if (r->work_pos.btree == BTREE_ID_reconcile_pending &&
			    bkey_deleted(&pending_cookie.k))
				break;

			/* Avoid conflicts when switching between phys/normal */
			bch2_moving_ctxt_flush_all(ctxt);
			bch2_btree_write_buffer_flush_sync(trans);
			continue;
		}

		if ((r->work_pos.btree == BTREE_ID_reconcile_hipri_phys ||
		     r->work_pos.btree == BTREE_ID_reconcile_work_phys) &&
		    k.k->p.inode != r->work_pos.pos.inode) {
			/*
			 * We don't yet do multiple devices in parallel - that
			 * will require extra synchronization to avoid kicking
			 * off the same reconciles simultaneously via multiple
			 * backpointers.
			 *
			 * For now, flush when switching devices to avoid
			 * conflicts:
			 */
			bch2_moving_ctxt_flush_all(ctxt);
			bch2_btree_write_buffer_flush_sync(trans);
			work.nr = 0;
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
		} else if (k.k->type == KEY_TYPE_backpointer) {
			if (k.k->p.inode == RECONCILE_WORK_pending &&
			    bkey_deleted(&pending_cookie.k)) {
				r->work_pos = BBPOS(scan_btrees[++i], POS_MIN);
				continue;
			}

			ret = do_reconcile_btree(ctxt, &snapshot_io_opts,
						 bkey_s_c_to_backpointer(k));
		} else if (btree_is_reconcile_phys(r->work_pos.btree)) {
			ret = lockrestart_do(trans,
				do_reconcile_phys(ctxt, &snapshot_io_opts, k.k->p, &last_flushed));
		} else {
			ret = lockrestart_do(trans,
				do_reconcile_extent(ctxt, &snapshot_io_opts, r->work_pos));
		}

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			ret = 0;
			continue;
		}

		if (ret)
			break;

		r->work_pos.pos = btree_type_has_snapshots(r->work_pos.btree)
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

	prt_printf(out, "pending work:\tdata\rmetadata\r\n");
	for (unsigned i = 0; i < BCH_REBALANCE_ACCOUNTING_NR; i++) {
		struct disk_accounting_pos acc;
		disk_accounting_key_init(acc, reconcile_work, i);
		u64 v[2];
		bch2_accounting_mem_read(c, disk_accounting_pos_to_bpos(&acc), v, ARRAY_SIZE(v));

		bch2_prt_reconcile_accounting_type(out, i);
		prt_printf(out, ":\t");
		prt_human_readable_u64(out, v[0] << 9);
		prt_tab_rjust(out);
		prt_human_readable_u64(out, v[1] << 9);
		prt_tab_rjust(out);
		prt_newline(out);
	}

	prt_newline(out);
	guard(printbuf_indent_nextline)(out);

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
		struct bbpos work_pos = r->work_pos;
		barrier();

		if (work_pos.btree	== BTREE_ID_reconcile_scan &&
		    work_pos.pos.inode	== 0) {
			prt_printf(out, "scanning:\n");
			reconcile_scan_to_text(out, c,
				reconcile_scan_decode(c, work_pos.pos.offset));
		} else if (work_pos.btree == BTREE_ID_reconcile_scan) {
			prt_printf(out, "processing metadata: %s %llu\n",
				   reconcile_work_ids[work_pos.pos.inode - 1],
				   work_pos.pos.offset);

		} else {
			prt_printf(out, "processing data: ");

			if (btree_is_reconcile_phys(work_pos.btree)) {
				bch2_bbpos_to_text(out, work_pos);
			} else {
				prt_printf(out, " %s ",
					   reconcile_work_ids[btree_to_reconcile_work_id(work_pos.btree)]);

				bch2_bbpos_to_text(out, rb_work_to_data_pos(work_pos.pos));
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

	if (t) {
		bch2_prt_task_backtrace(out, t, 0, GFP_KERNEL);
		put_task_struct(t);
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

/* need better helpers for iterating in parallel */

static int fix_reconcile_work_btree(struct btree_trans *trans,
				    enum btree_id want_set_in_btree,
				    struct bpos pos,
				    struct btree_iter *rb_iter)
{
	bool should_have_reconcile = rb_iter->btree_id == want_set_in_btree;
	bool have_reconcile = rb_iter->k.type == KEY_TYPE_set;

	return should_have_reconcile != have_reconcile
		? bch2_btree_bit_mod_buffered(trans, rb_iter->btree_id, pos, should_have_reconcile)
		: 0;
}

static int check_reconcile_work_one(struct btree_trans *trans,
				    struct btree_iter *data_iter,
				    struct btree_iter *rb_w,
				    struct btree_iter *rb_h,
				    struct btree_iter *rb_p,
				    struct per_snapshot_io_opts *snapshot_io_opts,
				    struct wb_maybe_flush *last_flushed,
				    struct bpos *cur_pos)
{
	struct bch_fs *c = trans->c;

	struct bbpos data_pos = rb_work_to_data_pos(*cur_pos);
	bch2_btree_iter_set_pos(data_iter,	data_pos.pos);
	bch2_btree_iter_set_pos(rb_w,		*cur_pos);
	bch2_btree_iter_set_pos(rb_h,		*cur_pos);
	bch2_btree_iter_set_pos(rb_p,		*cur_pos);

	struct bkey_s_c data_k	= bkey_try(bch2_btree_iter_peek(data_iter));
	struct bkey_s_c w_k	= bkey_try(bch2_btree_iter_peek(rb_w));
	bkey_try(bch2_btree_iter_peek(rb_h));
	bkey_try(bch2_btree_iter_peek(rb_p));

	if (w_k.k && w_k.k->type == KEY_TYPE_cookie) {
		try(bch2_btree_delete_at(trans, rb_w, 0));
		try(bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));
	}

	struct bpos rb_work_pos = bpos_min(bpos_min(rb_w->pos, rb_h->pos), rb_p->pos);

	struct bpos pos = bpos_min(rb_work_pos,
				   data_to_rb_work_pos(data_iter->btree_id, data_iter->pos));

	struct bkey d_deleted;
	bkey_init(&d_deleted);
	d_deleted.p = data_pos.pos;

	struct bkey r_deleted;
	bkey_init(&r_deleted);
	r_deleted.p = pos;

	if (bpos_lt(pos, data_iter->pos)) {
		data_k.k	= &d_deleted;
		data_iter->k	= d_deleted;
	}
	if (bpos_lt(pos, rb_w->pos))
		rb_w->k		= r_deleted;
	if (bpos_lt(pos, rb_h->pos))
		rb_h->k		= r_deleted;
	if (bpos_lt(pos, rb_p->pos))
		rb_p->k		= r_deleted;

	*cur_pos = pos;
	if (bpos_ge(*cur_pos, data_to_rb_work_pos(data_iter->btree_id, SPOS_MAX)))
		return 0;

	enum btree_id btree_want_set = reconcile_work_btree[rb_work_id(bch2_bkey_reconcile_opts(c, data_k))];

	u64 btrees_set =
		(rb_w->k.type	? BIT_ULL(rb_w->btree_id) : 0)|
		(rb_h->k.type	? BIT_ULL(rb_h->btree_id) : 0)|
		(rb_p->k.type	? BIT_ULL(rb_p->btree_id) : 0);

	u64 btree_want_set_mask = btree_want_set ? BIT_ULL(btree_want_set) : 0;
	if (btrees_set != btree_want_set_mask) {
		try(bch2_btree_write_buffer_maybe_flush(trans, data_k, last_flushed));

		CLASS(printbuf, buf)();
		prt_str(&buf, "extent should be set in ");
		if (btree_want_set)
			bch2_btree_id_str(btree_want_set);
		else
			prt_str(&buf, "(none)");
		prt_printf(&buf, "\nbut set in: ");
		bch2_prt_bitflags(&buf, __bch2_btree_ids, btrees_set);
		prt_newline(&buf);

		bch2_btree_id_to_text(&buf, data_iter->btree_id);
		prt_str(&buf, ": ");
		bch2_bkey_val_to_text(&buf, trans->c, data_k);

		if (ret_fsck_err(trans, reconcile_work_incorrectly_set, "%s", buf.buf)) {
			try(fix_reconcile_work_btree(trans, btree_want_set, *cur_pos, rb_w));
			try(fix_reconcile_work_btree(trans, btree_want_set, *cur_pos, rb_h));
			try(fix_reconcile_work_btree(trans, btree_want_set, *cur_pos, rb_p));
		}
	}

	struct bch_inode_opts opts;

	try(bch2_bkey_get_io_opts(trans, snapshot_io_opts, data_k, &opts));
	try(bch2_update_reconcile_opts(trans, snapshot_io_opts, &opts, data_iter, 0, data_k,
				       SET_NEEDS_REBALANCE_other));
	return 0;
}

noinline_for_stack
static int check_reconcile_work_data_btree(struct btree_trans *trans,
				      enum btree_id btree,
				      struct btree_iter *rb_w,
				      struct btree_iter *rb_h,
				      struct btree_iter *rb_p,
				      struct per_snapshot_io_opts *snapshot_io_opts,
				      struct progress_indicator *progress,
				      struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	CLASS(disk_reservation, res)(c);
	CLASS(btree_iter, data_iter)(trans, btree, POS_MIN,
				     BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);
	struct bpos cur_pos = data_to_rb_work_pos(btree, POS_MIN);

	while (true) {
		bch2_disk_reservation_put(c, &res.r);

		try(bch2_progress_update_iter(trans, progress, &data_iter));
		try(commit_do(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc,
			      check_reconcile_work_one(trans, &data_iter, rb_w, rb_h, rb_p,
						       snapshot_io_opts, last_flushed, &cur_pos)));
		if (bpos_ge(cur_pos, data_to_rb_work_pos(btree, SPOS_MAX)))
			return 0;

		cur_pos = btree_type_has_snapshots(btree)
			? bpos_successor(cur_pos)
			: bpos_nosnap_successor(cur_pos);
		wb_maybe_flush_inc(last_flushed);
	}
}

static int check_reconcile_work_phys_one(struct btree_trans *trans,
					 struct btree_iter *bp_iter,
					 struct btree_iter *r_w,
					 struct btree_iter *r_h,
					 struct wb_maybe_flush *last_flushed,
					 struct bpos *cur_pos)
{
	bch2_btree_iter_set_pos(bp_iter,	*cur_pos);
	bch2_btree_iter_set_pos(r_w,		*cur_pos);
	bch2_btree_iter_set_pos(r_h,		*cur_pos);

	struct bkey_s_c bp = bkey_try(bch2_btree_iter_peek(bp_iter));
	bkey_try(bch2_btree_iter_peek(r_w));
	bkey_try(bch2_btree_iter_peek(r_h));

	*cur_pos = bpos_min(bpos_min(r_w->pos, r_h->pos), bp_iter->pos);

	struct bkey deleted;
	bkey_init(&deleted);
	deleted.p = *cur_pos;

	if (bpos_lt(*cur_pos, bp_iter->pos)) {
		bp.k		= &deleted;
		bp_iter->k	= deleted;
	}
	if (bpos_lt(*cur_pos, r_w->pos))
		r_w->k		= deleted;
	if (bpos_lt(*cur_pos, r_h->pos))
		r_h->k		= deleted;

	enum reconcile_work_id w = bp.k && bp.k->type == KEY_TYPE_backpointer
		? BACKPOINTER_RECONCILE_PHYS(bkey_s_c_to_backpointer(bp).v)
		: 0;

	enum btree_id btree_want_set = w < ARRAY_SIZE(reconcile_work_phys_btree)
		? reconcile_work_phys_btree[w]
		: 0;

	u64 btrees_set =
		(r_w->k.type	? BIT_ULL(r_w->btree_id) : 0)|
		(r_h->k.type	? BIT_ULL(r_h->btree_id) : 0);

	u64 btree_want_set_mask = btree_want_set ? BIT_ULL(btree_want_set) : 0;
	if (btrees_set != btree_want_set_mask) {
		try(bch2_btree_write_buffer_maybe_flush(trans, bp, last_flushed));

		CLASS(printbuf, buf)();
		prt_str(&buf, "backpointer should be set in ");
		if (btree_want_set)
			bch2_btree_id_str(btree_want_set);
		else
			prt_str(&buf, "(none)");
		prt_printf(&buf, "\nbut set in: ");
		bch2_prt_bitflags(&buf, __bch2_btree_ids, btrees_set);
		prt_newline(&buf);

		bch2_bkey_val_to_text(&buf, trans->c, bp);

		if (ret_fsck_err(trans, reconcile_work_phys_incorrectly_set, "%s", buf.buf)) {
			try(fix_reconcile_work_btree(trans, btree_want_set, *cur_pos, r_w));
			try(fix_reconcile_work_btree(trans, btree_want_set, *cur_pos, r_h));
		}
	}

	return 0;
}

noinline_for_stack
static int check_reconcile_work_phys(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_backpointers), 0);
	struct bpos cur_pos = POS_MIN;

	CLASS(btree_iter, bp)(trans, BTREE_ID_backpointers, POS_MIN, BTREE_ITER_prefetch);
	CLASS(btree_iter, r_w)(trans, BTREE_ID_reconcile_work_phys, POS_MIN, BTREE_ITER_prefetch);
	CLASS(btree_iter, r_h)(trans, BTREE_ID_reconcile_hipri_phys, POS_MIN, BTREE_ITER_prefetch);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	while (true) {
		try(bch2_progress_update_iter(trans, &progress, &bp));

		try(commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			      check_reconcile_work_phys_one(trans, &bp, &r_w, &r_h,
							    &last_flushed, &cur_pos)));
		if (bpos_eq(cur_pos, POS_MAX))
			return 0;

		cur_pos = bpos_nosnap_successor(cur_pos);
		wb_maybe_flush_inc(&last_flushed);
	}
}

static int check_reconcile_work_btree_key(struct btree_trans *trans,
					  struct btree_iter *iter, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));
	try(bch2_update_reconcile_opts(trans, NULL, &opts, iter, iter->min_depth, k,
				       SET_NEEDS_REBALANCE_other));

	struct bpos bp_pos = bch2_bkey_get_reconcile_bp_pos(c, k);

	CLASS(printbuf, buf)();

	if (ret_fsck_err_on(bp_pos.inode && !bp_pos.offset,
			trans, btree_ptr_with_no_reconcile_bp,
			"btree ptr with no reconcile \n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) + sizeof(struct bch_extent_reconcile_bp)));

		bkey_reassemble(n, k);

		try(reconcile_bp_add(trans, iter->btree_id, iter->min_depth,
				     bkey_i_to_s(n), &bp_pos));
		bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), bp_pos.offset);
		return 0;
	}

	if (ret_fsck_err_on(!bp_pos.inode && bp_pos.offset,
			trans, btree_ptr_with_bad_reconcile_bp,
			"btree ptr with bad reconcile \n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) + sizeof(struct bch_extent_reconcile_bp)));

		bkey_reassemble(n, k);
		bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), 0);

		try(bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node));
		return 0;
	}

	if (!bpos_eq(bp_pos, POS_MIN)) {
		CLASS(btree_iter, rb_iter)(trans, BTREE_ID_reconcile_scan, bp_pos, BTREE_ITER_intent);
		struct bkey_s_c bp_k = bkey_try(bch2_btree_iter_peek_slot(&rb_iter));

		struct bch_backpointer bp = rb_bp(iter->btree_id, iter->min_depth, k);

		if (bp_k.k->type != KEY_TYPE_backpointer || memcmp(bp_k.v, &bp, sizeof(bp))) {
			CLASS(printbuf, buf)();
			prt_printf(&buf, "btree ptr points to bad/missing reconcile bp\n");
			bch2_bkey_val_to_text(&buf, trans->c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, trans->c, bp_k);

			ret_fsck_err(trans, btree_ptr_to_bad_reconcile_bp, "%s", buf.buf);

			if (bp_k.k->type != KEY_TYPE_backpointer) {
				struct bkey_i_backpointer *new_bp = errptr_try(bch2_bkey_alloc(trans, &rb_iter, 0, backpointer));
				new_bp->v = bp;
			} else {
				try(bch2_bkey_get_empty_slot(trans, &rb_iter, BTREE_ID_reconcile_scan,
							     POS(1, 1), POS(1, U64_MAX)));

				struct bkey_i_backpointer *new_bp = errptr_try(bch2_bkey_alloc(trans, &rb_iter, 0, backpointer));
				new_bp->v = bp;

				struct bkey_i *n = errptr_try(bch2_bkey_make_mut(trans, iter, &k, 0));
				bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), rb_iter.pos.offset);
			}
		}
	}

	return 0;
}

noinline_for_stack
static int check_reconcile_work_btrees(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;

	CLASS(disk_reservation, res)(c);
	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, 0, ~0ULL);

	for (enum btree_id btree = 0; btree < btree_id_nr_alive(c); btree++) {
		if (!bch2_btree_id_root(c, btree)->b)
			continue;

		for (unsigned level = 1; level < BTREE_MAX_DEPTH; level++) {
			CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0, level,
						     BTREE_ITER_prefetch|
						     BTREE_ITER_not_extents|
						     BTREE_ITER_all_snapshots);

			try(for_each_btree_key_continue(trans, iter, 0, k, ({
				bch2_disk_reservation_put(c, &res.r);
				bch2_progress_update_iter(trans, &progress, &iter) ?:
				check_reconcile_work_btree_key(trans, &iter, k) ?:
				bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc);
			})));
		}
	}

	return 0;
}

static int check_reconcile_btree_bp(struct btree_trans *trans, struct bkey_s_c k)
{
	if (k.k->type != KEY_TYPE_backpointer)
		return 0;

	CLASS(btree_iter_uninit, iter)(trans);
	bkey_try(reconcile_bp_get_key(trans, &iter, bkey_s_c_to_backpointer(k)));
	return 0;
}

noinline_for_stack
static int check_reconcile_btree_bps(struct btree_trans *trans)
{
	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, trans->c, BIT_ULL(BTREE_ID_reconcile_scan), 0);

	return for_each_btree_key_max(trans, iter, BTREE_ID_reconcile_scan,
				      POS(1, 0), POS(1, U64_MAX),
				      BTREE_ITER_prefetch, k, ({
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_reconcile_btree_bp(trans, k);
	}));
}

int bch2_check_reconcile_work(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(btree_iter_uninit, extent_iter)(trans);
	CLASS(btree_iter, rb_w)(trans, BTREE_ID_reconcile_work, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);
	CLASS(btree_iter, rb_h)(trans, BTREE_ID_reconcile_hipri, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);
	CLASS(btree_iter, rb_p)(trans, BTREE_ID_reconcile_pending, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);

	CLASS(per_snapshot_io_opts, snapshot_io_opts)(c);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c,
			   BIT_ULL(BTREE_ID_extents)|
			   BIT_ULL(BTREE_ID_reflink),
			   0);

	static const enum btree_id data_btrees[] = {
		BTREE_ID_stripes,
		BTREE_ID_reflink,
		BTREE_ID_extents,
	};
	for (unsigned i = 0; i < ARRAY_SIZE(data_btrees); i++)
		try(check_reconcile_work_data_btree(trans, data_btrees[i],
						    &rb_w, &rb_h, &rb_p,
						    &snapshot_io_opts, &progress, &last_flushed));

	try(check_reconcile_work_phys(trans));
	try(check_reconcile_work_btrees(trans));
	try(check_reconcile_btree_bps(trans));

	return 0;
}
