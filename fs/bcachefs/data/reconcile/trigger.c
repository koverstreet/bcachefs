// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/disk_groups.h"

#include "btree/interior.h"
#include "btree/update.h"

#include "data/checksum.h"
#include "data/compress.h"
#include "data/extents.h"
#include "data/reconcile/trigger.h"
#include "data/reconcile/work.h"
#include "data/reflink.h"

#include "fs/inode.h"

#include "init/error.h"

int bch2_extent_reconcile_validate(struct bch_fs *c,
				   struct bkey_s_c k,
				   struct bkey_validate_context from,
				   const struct bch_extent_reconcile *r)
{
	int ret = 0;

	bkey_fsck_err_on(r->pending && !r->need_rb,
			 c, extent_reconcile_bad_pending,
			 "pending incorrectly set");

	bkey_fsck_err_on(r->hipri && !(r->need_rb & BIT(BCH_RECONCILE_data_replicas)),
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

enum reconcile_work_id bch2_bkey_reconcile_work_id(const struct bch_fs *c, struct bkey_s_c k)
{
	if (k.k->type == KEY_TYPE_stripe) {
		return bkey_s_c_to_stripe(k).v->needs_reconcile
			? RECONCILE_WORK_hipri
			: RECONCILE_WORK_none;
	} else {
		return rb_work_id(bch2_bkey_reconcile_opts(c, k));
	}
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
	prt_bitflags(out, bch2_reconcile_opts, r->need_rb);

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
		ret |=  BIT(BCH_RECONCILE_ACCOUNTING_pending);
		ret &= ~BIT(BCH_RECONCILE_ACCOUNTING_target);
		ret &= ~BIT(BCH_RECONCILE_ACCOUNTING_replicas);
	} else if (r->hipri) {
		ret |=  BIT(BCH_RECONCILE_ACCOUNTING_high_priority);
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

struct bpos bch2_bkey_get_reconcile_bp_pos(const struct bch_fs *c, struct bkey_s_c k)
{
	return POS(rb_work_id(bch2_bkey_reconcile_opts(c, k)),
		   bch2_bkey_get_reconcile_bp(c, k));
}

void bch2_bkey_set_reconcile_bp(const struct bch_fs *c, struct bkey_s k, u64 idx)
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

int reconcile_bp_del(struct btree_trans *trans, enum btree_id btree, unsigned level,
		     struct bkey_s_c k, struct bpos bp_pos)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_reconcile_scan, bp_pos, BTREE_ITER_intent);
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

int reconcile_bp_add(struct btree_trans *trans, enum btree_id btree, unsigned level,
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

struct bkey_s_c reconcile_bp_get_key(struct btree_trans *trans,
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
		BCH_RECONCILE_OPTS()
#undef x
	}
	return new.need_rb;
}

static int bch2_bkey_needs_reconcile(struct btree_trans *trans, struct bkey_s_c k,
				     struct bch_inode_opts *opts,
				     int *need_update_invalid_devs,
				     struct bch_extent_reconcile *ret)
{
	struct bch_fs *c = trans->c;
	bool btree = bkey_is_btree_ptr(k.k);

	if (btree &&
	    bch2_request_incompat_feature(c, bcachefs_metadata_version_reconcile))
		return false;

	struct bch_extent_reconcile r = {
		.type = BIT(BCH_EXTENT_ENTRY_reconcile),
#define x(_name)							\
		._name			= opts->_name,			\
		._name##_from_inode	= opts->_name##_from_inode,
	BCH_RECONCILE_OPTS()
#undef x
	};

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bool poisoned = bch2_bkey_extent_ptrs_flags(ptrs) & BIT_ULL(BCH_EXTENT_FLAG_poisoned);
	unsigned compression_type = bch2_compression_opt_to_type(r.background_compression);
	unsigned csum_type	= bch2_data_checksum_type_rb(c, r);

	bool incompressible = false, unwritten = false, ec = false;
	unsigned durability = 0, durability_acct = 0, invalid = 0, min_durability = INT_MAX;
	unsigned ec_redundancy = 0;

	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		incompressible	|= p.crc.compression_type == BCH_COMPRESSION_TYPE_incompressible;
		unwritten	|= p.ptr.unwritten;

		bool evacuating = bch2_ptr_bad_or_evacuating(c, &p.ptr) && !p.has_ec;

		if (!poisoned &&
		    !btree &&
		    !p.ptr.cached) {
			if (p.crc.csum_type != csum_type)
				r.need_rb |= BIT(BCH_RECONCILE_data_checksum);

			if (p.crc.compression_type != compression_type)
				r.need_rb |= BIT(BCH_RECONCILE_background_compression);
		}

		if (!poisoned &&
		    !evacuating &&
		    !p.ptr.cached &&
		    r.background_target &&
		    !bch2_dev_in_target(c, p.ptr.dev, r.background_target)) {
			r.need_rb |= BIT(BCH_RECONCILE_background_target);
			if (p.ptr.dev != BCH_SB_MEMBER_INVALID)
				r.ptrs_moving |= ptr_bit;
		}

		if (evacuating) {
			r.need_rb |= BIT(BCH_RECONCILE_data_replicas);
			r.hipri = 1;
			if (p.ptr.dev != BCH_SB_MEMBER_INVALID)
				r.ptrs_moving |= ptr_bit;
		}

		int d = bch2_extent_ptr_desired_durability(trans, &p);
		if (d < 0)
			return d;

		durability_acct += d;

		if (evacuating)
			d = 0;

		durability += d;
		if (!p.ptr.cached)
			min_durability = min(min_durability, d);

		if (p.has_ec && r.erasure_code)
			ec_redundancy = max_t(unsigned, ec_redundancy, p.ec.redundancy);
		ec |= p.has_ec;

		invalid += p.ptr.dev == BCH_SB_MEMBER_INVALID;

		ptr_bit <<= 1;
	}

	if (k.k->type == KEY_TYPE_stripe) {
		*ret = r;

		return (r.need_rb & BIT(BCH_RECONCILE_data_replicas)) &&
			!bkey_s_c_to_stripe(k).v->needs_reconcile;
	}

	if (unwritten || incompressible)
		r.need_rb &= ~BIT(BCH_RECONCILE_background_compression);

	if (unwritten)
		r.need_rb &= ~BIT(BCH_RECONCILE_data_checksum);

	if (max(durability, ec_redundancy) < r.data_replicas) {
		r.need_rb |= BIT(BCH_RECONCILE_data_replicas);
		r.hipri = 1;
	}

	if (durability >= r.data_replicas + min_durability)
		r.need_rb |= BIT(BCH_RECONCILE_data_replicas);

	if (!unwritten && r.erasure_code != ec)
		r.need_rb |= BIT(BCH_RECONCILE_erasure_code);

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
	if (ctx == SET_NEEDS_RECONCILE_opt_change ||
	    ctx == SET_NEEDS_RECONCILE_opt_change_indirect)
		return 0;

	if ((new_need_rb & BIT(BCH_RECONCILE_erasure_code)) &&
	    !bkey_has_ec(c, k)) {
		/* Foreground writes are not initially erasure coded - and we
		 * may crash before a stripe is created
		 */
		new_need_rb &= ~BIT(BCH_RECONCILE_erasure_code);
	}

	if (ctx == SET_NEEDS_RECONCILE_foreground) {
		new_need_rb &= ~(BIT(BCH_RECONCILE_background_compression)|
				 BIT(BCH_RECONCILE_background_target));

		/*
		 * Foreground writes might end up degraded when a device is
		 * getting yanked:
		 *
		 * XXX: this is something we need to fix, but adding retries to
		 * the write path is something we have to do carefully.
		 */
		new_need_rb &= ~BIT(BCH_RECONCILE_data_replicas);
		if (!new_need_rb)
			return 0;

		if (opt_change_cookie != c->opt_change_cookie)
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

	if (new_need_rb == BIT(BCH_RECONCILE_data_replicas)) {
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
	if (new_need_rb & BIT(BCH_RECONCILE_##_name))				\
		prt_printf(&buf, "\n" #_name " %u != %u", old->_name, new->_name);
	BCH_RECONCILE_OPTS()
#undef x

	fsck_err(trans, extent_io_opts_not_set, "%s", buf.buf);
fsck_err:
	return ret;
}

static int set_needs_reconcile_stripe(struct btree_trans *trans,
				      struct per_snapshot_io_opts *snapshot_io_opts,
				      struct bkey_i *k,
				      bool new_needs_reconcile)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_stripe *s = bkey_i_to_stripe(k);

	int delta = (int) new_needs_reconcile - (int) s->v.needs_reconcile;

	if (delta > 0) {
		int ret = check_dev_reconcile_scan_cookie(trans, bkey_i_to_s_c(k),
						snapshot_io_opts ? &snapshot_io_opts->dev_cookie : NULL);
		if (ret < 0)
			return ret;

		if (!ret) {
			CLASS(printbuf, buf)();
			prt_printf(&buf, "stripe with needs_reconcile incorrectly unset\n");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

			ret_fsck_err(trans, stripe_needs_reconcile_not_set, "%s", buf.buf);
		}
	}

	s->v.needs_reconcile = new_needs_reconcile;
	return 0;
}

int bch2_bkey_set_needs_reconcile(struct btree_trans *trans,
				  struct per_snapshot_io_opts *snapshot_io_opts,
				  struct bch_inode_opts *opts,
				  struct bkey_i *_k,
				  enum set_needs_reconcile_ctx ctx,
				  u32 opt_change_cookie)
{
	if (!bkey_extent_is_direct_data(&_k->k) &&
	    _k->k.type != KEY_TYPE_stripe)
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_s k = bkey_i_to_s(_k);

	int need_update_invalid_devs;
	struct bch_extent_reconcile new;

	int ret = bch2_bkey_needs_reconcile(trans, k.s_c, opts, &need_update_invalid_devs, &new);
	if (ret <= 0)
		return ret;

	if (_k->k.type == KEY_TYPE_stripe)
		return set_needs_reconcile_stripe(trans, snapshot_io_opts, _k,
						  new.need_rb & BIT(BCH_RECONCILE_data_replicas));

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
			bch2_bkey_drop_ptrs_noerror(k, p, entry,
				(p.ptr.dev == BCH_SB_MEMBER_INVALID &&
				 !p.has_ec &&
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

	if (!bkey_extent_is_direct_data(k.k) &&
	    k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bch_fs *c = trans->c;
	int need_update_invalid_devs;
	struct bch_extent_reconcile new;

	int ret = bch2_bkey_needs_reconcile(trans, k, opts, &need_update_invalid_devs, &new);
	if (ret <= 0)
		return ret;

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
		if (snapshot_opts->fs_io_opts.change_cookie	!= c->opt_change_cookie ||
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
					      bch2_snapshot_is_ancestor(trans, k.k->p.snapshot, i->snapshot));
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
		BCH_RECONCILE_OPTS()
#undef x
	}

	return 0;
}
