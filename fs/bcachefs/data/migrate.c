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
#include "data/reconcile.h"

#include "journal/journal.h"

#include "sb/io.h"

#include "init/progress.h"

static struct bkey_i *drop_dev_ptrs(struct btree_trans *trans, struct bkey_s_c k, unsigned dev_idx,
				    unsigned flags, struct printbuf *err)
{
	struct bch_fs *c = trans->c;
	bool metadata = bkey_is_btree_ptr(k.k);
	unsigned replicas = metadata ? c->opts.metadata_replicas : c->opts.data_replicas;
	unsigned lost = metadata ? BCH_FORCE_IF_METADATA_LOST : BCH_FORCE_IF_DATA_LOST;
	unsigned degraded = metadata ? BCH_FORCE_IF_METADATA_DEGRADED : BCH_FORCE_IF_DATA_DEGRADED;

	if (!bch2_bkey_has_device_c(c, k, dev_idx))
		return NULL;

	struct bkey_i *n = bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
					      sizeof(struct bch_extent_reconcile) +
					      sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX);
	if (IS_ERR(n))
		return n;
	bkey_reassemble(n, k);

	bch2_bkey_drop_device(c, bkey_i_to_s(n), dev_idx);

	int nr_good = bch2_bkey_durability(trans, bkey_i_to_s_c(n));
	if (nr_good < 0)
		return ERR_PTR(nr_good);

	if ((!nr_good && !(flags & lost)) ||
	    (nr_good < replicas && !(flags & degraded))) {
		prt_str(err, "cannot drop device without degrading/losing data\n  ");
		bch2_bkey_val_to_text(err, c, k);
		prt_newline(err);
		return ERR_PTR(bch_err_throw(c, remove_would_lose_data));
	}

	if (bch2_bkey_can_read(c, bkey_i_to_s_c(n))) {
		struct bch_inode_opts opts;
		int ret = bch2_bkey_get_io_opts(trans, NULL, k, &opts) ?:
			  bch2_bkey_set_needs_reconcile(trans, NULL, &opts, n,
							SET_NEEDS_REBALANCE_opt_change, 0);
		if (ret)
			return ERR_PTR(ret);
	} else if (!metadata) {
		bch2_set_bkey_error(c, n, KEY_TYPE_ERROR_device_removed);
	}

	return n;
}

static int drop_btree_ptrs(struct btree_trans *trans, struct btree_iter *iter,
			   struct btree *b, unsigned dev_idx,
			   unsigned flags, struct printbuf *err)
{
	struct bkey_i *n = errptr_try(drop_dev_ptrs(trans, bkey_i_to_s_c(&b->key), dev_idx, flags, err));
	if (!n)
		return 0;

	return bch2_btree_node_update_key(trans, iter, b, n, 0, false);
}

static int bch2_dev_usrdata_drop_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k,
				     unsigned dev_idx,
				     unsigned flags, struct printbuf *err)
{
	struct bkey_i *n = errptr_try(drop_dev_ptrs(trans, k, dev_idx, flags, err));
	if (!n)
		return 0;

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
				 struct progress_indicator *progress,
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
			bch2_progress_update_iter(trans, progress, &iter) ?:
			bch2_dev_usrdata_drop_key(trans, &iter, k, dev_idx, flags, err);
		})));
	}

	return 0;
}

static int dev_metadata_drop_one(struct btree_trans *trans,
				 struct btree_iter *iter,
				 struct progress_indicator *progress,
				 unsigned dev_idx,
				 unsigned flags, struct printbuf *err)
{
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(iter));
	if (!b)
		return 1;

	try(bch2_progress_update_iter(trans, progress, iter));
	try(drop_btree_ptrs(trans, iter, b, dev_idx, flags, err));
	return 0;
}

static int bch2_dev_metadata_drop(struct bch_fs *c,
				  struct progress_indicator *progress,
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

	if (!k.k || !bch2_bkey_has_device_c(trans->c, k, dev_idx))
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

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct progress_indicator progress;
	bch2_progress_init(&progress, "dropping device data", c,
			   BIT(BTREE_ID_backpointers), 0);

	return bch2_btree_write_buffer_flush_sync(trans) ?:
		backpointer_scan_for_each(trans, iter, POS(dev_idx, 0), POS(dev_idx, U64_MAX),
					  &last_flushed, &progress, bp, ({
		wb_maybe_flush_inc(&last_flushed);
		CLASS(disk_reservation, res)(c);
		data_drop_bp(trans, dev_idx, bp, &last_flushed, flags, err) ?:
		bch2_trans_commit(trans, &res.r, NULL, BCH_TRANS_COMMIT_no_enospc);
	}));
}

int bch2_dev_data_drop(struct bch_fs *c, unsigned dev_idx,
		       unsigned flags, struct printbuf *err)
{
	struct progress_indicator progress;
	bch2_progress_init(&progress, "dropping user data", c,
			   btree_has_data_ptrs_mask & ~BIT_ULL(BTREE_ID_stripes), 0);

	try(bch2_dev_usrdata_drop(c, &progress, dev_idx, flags, err));

	bch2_progress_init(&progress, "dropping metadata", c, 0, ~0ULL);

	return bch2_dev_metadata_drop(c, &progress, dev_idx, flags, err);
}
