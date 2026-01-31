// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/interior.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/reconcile/check.h"
#include "data/reconcile/trigger.h"

#include "init/error.h"
#include "init/progress.h"

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

	enum btree_id btree_want_set = reconcile_work_btree[bch2_bkey_reconcile_work_id(c, data_k)];

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
				       SET_NEEDS_RECONCILE_other));
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

static int btree_node_update_key_get_node(struct btree_trans *trans, struct btree_iter *iter,
					  unsigned level, struct bkey_i *new_key)
{
	BUG_ON(!bkey_is_btree_ptr(&new_key->k));

	CLASS(btree_node_iter, iter2)(trans, iter->btree_id, iter->pos, 0, level - 1, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter2));

	return bch2_btree_node_update_key(trans, &iter2, b, new_key, BCH_TRANS_COMMIT_no_enospc, false);
}

static int check_reconcile_work_btree_key(struct btree_trans *trans,
					  struct btree_iter *iter,
					  unsigned level, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));
	try(bch2_update_reconcile_opts(trans, NULL, &opts, iter, level, k,
				       SET_NEEDS_RECONCILE_other));

	struct bpos bp_pos = bch2_bkey_get_reconcile_bp_pos(c, k);

	CLASS(printbuf, buf)();

	if (ret_fsck_err_on(bp_pos.inode && !bp_pos.offset,
			trans, btree_ptr_with_no_reconcile_bp,
			"btree ptr with no reconcile \n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) + sizeof(struct bch_extent_reconcile_bp)));

		bkey_reassemble(n, k);

		try(reconcile_bp_add(trans, iter->btree_id, level, bkey_i_to_s(n), &bp_pos));
		bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), bp_pos.offset);
		return btree_node_update_key_get_node(trans, iter, level, n);
	}

	if (ret_fsck_err_on(!bp_pos.inode && bp_pos.offset,
			trans, btree_ptr_with_bad_reconcile_bp,
			"btree ptr with bad reconcile \n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) + sizeof(struct bch_extent_reconcile_bp)));

		bkey_reassemble(n, k);
		bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), 0);

		return btree_node_update_key_get_node(trans, iter, level, n);
	}

	if (!bpos_eq(bp_pos, POS_MIN)) {
		CLASS(btree_iter, rb_iter)(trans, BTREE_ID_reconcile_scan, bp_pos, BTREE_ITER_intent);
		struct bkey_s_c bp_k = bkey_try(bch2_btree_iter_peek_slot(&rb_iter));

		struct bch_backpointer bp = rb_bp(iter->btree_id, level, k);

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

				struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k)));
				bkey_reassemble(n, k);

				bch2_bkey_set_reconcile_bp(c, bkey_i_to_s(n), rb_iter.pos.offset);

				return btree_node_update_key_get_node(trans, iter, level, n);
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
			try(for_btree_root_key_at_level(trans, iter, btree, level, k, ({
				BUG_ON(!bkey_is_btree_ptr(k.k));
				check_reconcile_work_btree_key(trans, &iter, level, k) ?:
				bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc);
			})));

			bch2_trans_begin(trans);
			CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0, level,
						     BTREE_ITER_prefetch|
						     BTREE_ITER_not_extents|
						     BTREE_ITER_all_snapshots);

			try(for_each_btree_key_continue(trans, iter, 0, k, ({
				bch2_disk_reservation_put(c, &res.r);
				bch2_progress_update_iter(trans, &progress, &iter) ?:
				check_reconcile_work_btree_key(trans, &iter, level, k) ?:
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
