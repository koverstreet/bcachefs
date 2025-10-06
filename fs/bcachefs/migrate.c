// SPDX-License-Identifier: GPL-2.0
/*
 * Code for moving data off a device.
 */

#include "bcachefs.h"
#include "backpointers.h"
#include "bkey_buf.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "ec.h"
#include "errcode.h"
#include "extents.h"
#include "io_write.h"
#include "journal.h"
#include "keylist.h"
#include "migrate.h"
#include "move.h"
#include "progress.h"
#include "replicas.h"
#include "super-io.h"

static int drop_dev_ptrs(struct bch_fs *c, struct bkey_s k,
			 unsigned dev_idx, unsigned flags, bool metadata)
{
	unsigned replicas = metadata ? c->opts.metadata_replicas : c->opts.data_replicas;
	unsigned lost = metadata ? BCH_FORCE_IF_METADATA_LOST : BCH_FORCE_IF_DATA_LOST;
	unsigned degraded = metadata ? BCH_FORCE_IF_METADATA_DEGRADED : BCH_FORCE_IF_DATA_DEGRADED;
	unsigned nr_good;

	bch2_bkey_drop_device(k, dev_idx);

	nr_good = bch2_bkey_durability(c, k.s_c);
	if ((!nr_good && !(flags & lost)) ||
	    (nr_good < replicas && !(flags & degraded)))
		return bch_err_throw(c, remove_would_lose_data);

	return 0;
}

static int drop_btree_ptrs(struct btree_trans *trans, struct btree_iter *iter,
			   struct btree *b, unsigned dev_idx, unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct bkey_buf k;

	bch2_bkey_buf_init(&k);
	bch2_bkey_buf_copy(&k, c, &b->key);

	int ret = drop_dev_ptrs(c, bkey_i_to_s(k.k), dev_idx, flags, true) ?:
		bch2_btree_node_update_key(trans, iter, b, k.k, 0, false);

	bch_err_fn(c, ret);
	bch2_bkey_buf_exit(&k, c);
	return ret;
}

static int bch2_dev_usrdata_drop_key(struct btree_trans *trans,
				     struct btree_iter *iter,
				     struct bkey_s_c k,
				     unsigned dev_idx,
				     unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct bkey_i *n;
	int ret;

	if (!bch2_bkey_has_device_c(k, dev_idx))
		return 0;

	n = bch2_bkey_make_mut(trans, iter, &k, BTREE_UPDATE_internal_snapshot_node);
	ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		return ret;

	ret = drop_dev_ptrs(c, bkey_i_to_s(n), dev_idx, flags, false);
	if (ret)
		return ret;

	/*
	 * If the new extent no longer has any pointers, bch2_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_error key, or just a discard if it was a cached extent)
	 */
	bch2_extent_normalize(c, bkey_i_to_s(n));

	/*
	 * Since we're not inserting through an extent iterator
	 * (BTREE_ITER_all_snapshots iterators aren't extent iterators),
	 * we aren't using the extent overwrite path to delete, we're
	 * just using the normal key deletion path:
	 */
	if (bkey_deleted(&n->k))
		n->k.size = 0;
	return 0;
}

static int bch2_dev_btree_drop_key(struct btree_trans *trans,
				   struct bkey_s_c_backpointer bp,
				   unsigned dev_idx,
				   struct bkey_buf *last_flushed,
				   unsigned flags)
{
	struct btree_iter iter;
	struct btree *b = bch2_backpointer_get_node(trans, bp, &iter, last_flushed);
	int ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		return ret == -BCH_ERR_backpointer_to_overwritten_btree_node ? 0 : ret;

	ret = drop_btree_ptrs(trans, &iter, b, dev_idx, flags);

	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int bch2_dev_usrdata_drop(struct bch_fs *c,
				 struct progress_indicator_state *progress,
				 unsigned dev_idx, unsigned flags)
{
	CLASS(btree_trans, trans)(c);

	for (unsigned id = 0; id < BTREE_ID_NR; id++) {
		if (!btree_type_has_ptrs(id))
			continue;

		int ret = for_each_btree_key_commit(trans, iter, id, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			bch2_progress_update_iter(trans, progress, &iter, "dropping user data");
			bch2_dev_usrdata_drop_key(trans, &iter, k, dev_idx, flags);
		}));
		if (ret)
			return ret;
	}

	return 0;
}

static int bch2_dev_metadata_drop(struct bch_fs *c,
				  struct progress_indicator_state *progress,
				  unsigned dev_idx, unsigned flags)
{
	struct btree_iter iter;
	struct closure cl;
	struct btree *b;
	struct bkey_buf k;
	unsigned id;
	int ret;

	/* don't handle this yet: */
	if (flags & BCH_FORCE_IF_METADATA_LOST)
		return bch_err_throw(c, remove_with_metadata_missing_unimplemented);

	CLASS(btree_trans, trans)(c);
	bch2_bkey_buf_init(&k);
	closure_init_stack(&cl);

	for (id = 0; id < BTREE_ID_NR; id++) {
		bch2_trans_node_iter_init(trans, &iter, id, POS_MIN, 0, 0,
					  BTREE_ITER_prefetch);
retry:
		ret = 0;
		while (bch2_trans_begin(trans),
		       (b = bch2_btree_iter_peek_node(trans, &iter)) &&
		       !(ret = PTR_ERR_OR_ZERO(b))) {
			bch2_progress_update_iter(trans, progress, &iter, "dropping metadata");

			if (!bch2_bkey_has_device_c(bkey_i_to_s_c(&b->key), dev_idx))
				goto next;

			ret = drop_btree_ptrs(trans, &iter, b, dev_idx, flags);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
				ret = 0;
				continue;
			}

			if (ret)
				break;
next:
			bch2_btree_iter_next_node(trans, &iter);
		}
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto retry;

		bch2_trans_iter_exit(trans, &iter);

		if (ret)
			goto err;
	}

	bch2_btree_interior_updates_flush(c);
	ret = 0;
err:
	bch2_bkey_buf_exit(&k, c);

	BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart));

	return ret;
}

static int data_drop_bp(struct btree_trans *trans, unsigned dev_idx,
			struct bkey_s_c_backpointer bp, struct bkey_buf *last_flushed,
			unsigned flags)
{
	struct btree_iter iter;
	struct bkey_s_c k = bch2_backpointer_get_key(trans, bp, &iter, BTREE_ITER_intent,
						     last_flushed);
	int ret = bkey_err(k);
	if (ret == -BCH_ERR_backpointer_to_overwritten_btree_node)
		return 0;
	if (ret)
		return ret;

	if (!k.k || !bch2_bkey_has_device_c(k, dev_idx))
		goto out;

	/*
	 * XXX: pass flags arg to invalidate_stripe_to_dev and handle it
	 * properly
	 */

	if (bkey_is_btree_ptr(k.k))
		ret = bch2_dev_btree_drop_key(trans, bp, dev_idx, last_flushed, flags);
	else if (k.k->type == KEY_TYPE_stripe)
		ret = bch2_invalidate_stripe_to_dev(trans, &iter, k, dev_idx, flags);
	else
		ret = bch2_dev_usrdata_drop_key(trans, &iter, k, dev_idx, flags);
out:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_dev_data_drop_by_backpointers(struct bch_fs *c, unsigned dev_idx, unsigned flags)
{
	CLASS(btree_trans, trans)(c);

	struct bkey_buf last_flushed;
	bch2_bkey_buf_init(&last_flushed);
	bkey_init(&last_flushed.k->k);

	int ret = bch2_btree_write_buffer_flush_sync(trans) ?:
		for_each_btree_key_max_commit(trans, iter, BTREE_ID_backpointers,
				POS(dev_idx, 0),
				POS(dev_idx, U64_MAX), 0, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			if (k.k->type != KEY_TYPE_backpointer)
				continue;

			data_drop_bp(trans, dev_idx, bkey_s_c_to_backpointer(k),
				     &last_flushed, flags);

	}));

	bch2_bkey_buf_exit(&last_flushed, trans->c);
	bch_err_fn(c, ret);
	return ret;
}

int bch2_dev_data_drop(struct bch_fs *c, unsigned dev_idx, unsigned flags)
{
	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c,
			   BIT_ULL(BTREE_ID_extents)|
			   BIT_ULL(BTREE_ID_reflink));

	return bch2_dev_usrdata_drop(c, &progress, dev_idx, flags) ?:
		bch2_dev_metadata_drop(c, &progress, dev_idx, flags);
}
