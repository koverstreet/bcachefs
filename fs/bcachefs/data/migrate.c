// SPDX-License-Identifier: GPL-2.0
/*
 * Code for moving data off a device.
 */

#include "bcachefs.h"

#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/replicas.h"

#include "btree/bkey_buf.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/write_buffer.h"

#include "data/ec.h"
#include "data/extents.h"
#include "data/write.h"
#include "data/keylist.h"
#include "data/migrate.h"
#include "data/move.h"
#include "data/rebalance.h"

#include "journal/journal.h"

#include "sb/io.h"

#include "init/progress.h"

static int drop_dev_ptrs(struct bch_fs *c, struct bkey_s k, unsigned dev_idx,
			 unsigned flags, struct printbuf *err, bool metadata)
{
	unsigned replicas = metadata ? c->opts.metadata_replicas : c->opts.data_replicas;
	unsigned lost = metadata ? BCH_FORCE_IF_METADATA_LOST : BCH_FORCE_IF_DATA_LOST;
	unsigned degraded = metadata ? BCH_FORCE_IF_METADATA_DEGRADED : BCH_FORCE_IF_DATA_DEGRADED;
	unsigned nr_good;

	bch2_bkey_drop_device(k, dev_idx);

	nr_good = bch2_bkey_durability(c, k.s_c);
	if ((!nr_good && !(flags & lost)) ||
	    (nr_good < replicas && !(flags & degraded))) {
		prt_str(err, "cannot drop device without degrading/losing data\n  ");
		bch2_bkey_val_to_text(err, c, k.s_c);
		prt_newline(err);
		return bch_err_throw(c, remove_would_lose_data);
	}

	return 0;
}

static int drop_btree_ptrs(struct btree_trans *trans, struct btree_iter *iter,
			   struct btree *b, unsigned dev_idx,
			   unsigned flags, struct printbuf *err)
{
	struct bch_fs *c = trans->c;

	struct bkey_buf k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&k);
	bch2_bkey_buf_copy(&k, &b->key);

	return drop_dev_ptrs(c, bkey_i_to_s(k.k), dev_idx, flags, err, true) ?:
		bch2_btree_node_update_key(trans, iter, b, k.k, 0, false);
}

static int bch2_dev_usrdata_drop_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k,
				     unsigned dev_idx,
				     unsigned flags, struct printbuf *err)
{
	struct bch_fs *c = trans->c;

	if (!bch2_bkey_has_device_c(k, dev_idx))
		return 0;

	/* blah */
	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, BKEY_EXTENT_U64s_MAX * sizeof(u64)));
	bkey_reassemble(n, k);

	try(drop_dev_ptrs(c, bkey_i_to_s(n), dev_idx, flags, err, false));

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));
	try(bch2_bkey_set_needs_rebalance(trans, NULL, &opts, n, SET_NEEDS_REBALANCE_opt_change, 0));

	/*
	 * Since we're not inserting through an extent iterator
	 * (BTREE_ITER_all_snapshots iterators aren't extent iterators),
	 * we aren't using the extent overwrite path to delete, we're
	 * just using the normal key deletion path:
	 */
	if (bkey_deleted(&n->k))
		n->k.size = 0;
	return bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node);
}

static int bch2_dev_btree_drop_key(struct btree_trans *trans,
				   struct bkey_s_c_backpointer bp,
				   unsigned dev_idx,
				   struct wb_maybe_flush *last_flushed,
				   unsigned flags, struct printbuf *err)
{
	CLASS(btree_iter_uninit, iter)(trans);
	struct btree *b = bch2_backpointer_get_node(trans, bp, &iter, last_flushed);
	int ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		return ret == -BCH_ERR_backpointer_to_overwritten_btree_node ? 0 : ret;

	return drop_btree_ptrs(trans, &iter, b, dev_idx, flags, err);
}

static int bch2_dev_usrdata_drop(struct bch_fs *c,
				 struct progress_indicator_state *progress,
				 unsigned dev_idx,
				 unsigned flags, struct printbuf *err)
{
	CLASS(btree_trans, trans)(c);
	CLASS(disk_reservation, res)(c);

	/* FIXME: this does not handle unknown btrees with data pointers */
	for (unsigned id = 0; id < BTREE_ID_NR; id++) {
		if (!btree_type_has_data_ptrs(id))
			continue;

		/* Stripe keys have pointers, but are handled separately */
		if (id == BTREE_ID_stripes)
			continue;

		try(for_each_btree_key_commit(trans, iter, id, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				&res.r, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			bch2_disk_reservation_put(c, &res.r);
			bch2_progress_update_iter(trans, progress, &iter, "dropping user data") ?:
			bch2_dev_usrdata_drop_key(trans, &iter, k, dev_idx, flags, err);
		})));
	}

	return 0;
}

static int dev_metadata_drop_one(struct btree_trans *trans,
				 struct btree_iter *iter,
				 struct progress_indicator_state *progress,
				 unsigned dev_idx,
				 unsigned flags, struct printbuf *err)
{
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(iter));
	if (!b)
		return 1;

	try(bch2_progress_update_iter(trans, progress, iter, "dropping metadata"));

	if (bch2_bkey_has_device_c(bkey_i_to_s_c(&b->key), dev_idx))
		try(drop_btree_ptrs(trans, iter, b, dev_idx, flags, err));
	return 0;
}

static int bch2_dev_metadata_drop(struct bch_fs *c,
				  struct progress_indicator_state *progress,
				  unsigned dev_idx,
				  unsigned flags, struct printbuf *err)
{
	int ret = 0;

	/* don't handle this yet: */
	if (flags & BCH_FORCE_IF_METADATA_LOST)
		return bch_err_throw(c, remove_with_metadata_missing_unimplemented);

	CLASS(btree_trans, trans)(c);

	for (unsigned id = 0; id < btree_id_nr_alive(c) && !ret; id++) {
		CLASS(btree_node_iter, iter)(trans, id, POS_MIN, 0, 0, BTREE_ITER_prefetch);

		while (!(ret = lockrestart_do(trans,
					dev_metadata_drop_one(trans, &iter, progress, dev_idx, flags, err))))
			bch2_btree_iter_next_node(&iter);
	}

	bch2_trans_unlock(trans);
	bch2_btree_interior_updates_flush(c);

	BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart));

	return min(ret, 0);
}

static int data_drop_bp(struct btree_trans *trans, unsigned dev_idx,
			struct bkey_s_c_backpointer bp, struct wb_maybe_flush *last_flushed,
			unsigned flags, struct printbuf *err)
{
	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bch2_backpointer_get_key(trans, bp, &iter, BTREE_ITER_intent,
						     last_flushed);
	int ret = bkey_err(k);
	if (ret == -BCH_ERR_backpointer_to_overwritten_btree_node)
		return 0;
	if (ret)
		return ret;

	if (!k.k || !bch2_bkey_has_device_c(k, dev_idx))
		return 0;

	/*
	 * XXX: pass flags arg to invalidate_stripe_to_dev and handle it
	 * properly
	 */

	if (bkey_is_btree_ptr(k.k))
		return bch2_dev_btree_drop_key(trans, bp, dev_idx, last_flushed, flags, err);
	else if (k.k->type == KEY_TYPE_stripe)
		return bch2_invalidate_stripe_to_dev(trans, &iter, k, dev_idx, flags, err);
	else
		return bch2_dev_usrdata_drop_key(trans, &iter, k, dev_idx, flags, err);
}

int bch2_dev_data_drop_by_backpointers(struct bch_fs *c, unsigned dev_idx, unsigned flags,
				       struct printbuf *err)
{
	CLASS(btree_trans, trans)(c);
	CLASS(disk_reservation, res)(c);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	return bch2_btree_write_buffer_flush_sync(trans) ?:
		for_each_btree_key_max_commit(trans, iter, BTREE_ID_backpointers,
				POS(dev_idx, 0),
				POS(dev_idx, U64_MAX), 0, k,
				&res.r, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			if (k.k->type != KEY_TYPE_backpointer)
				continue;

			wb_maybe_flush_inc(&last_flushed);
			bch2_disk_reservation_put(c, &res.r);
			data_drop_bp(trans, dev_idx, bkey_s_c_to_backpointer(k),
				     &last_flushed, flags, err);

	}));
}

int bch2_dev_data_drop(struct bch_fs *c, unsigned dev_idx,
		       unsigned flags, struct printbuf *err)
{
	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, btree_has_data_ptrs_mask & ~BIT_ULL(BTREE_ID_stripes));

	try(bch2_dev_usrdata_drop(c, &progress, dev_idx, flags, err));

	bch2_progress_init_inner(&progress, c, 0, ~0ULL);

	return bch2_dev_metadata_drop(c, &progress, dev_idx, flags, err);
}
