/*
 * Code for moving data off a device.
 */

#include "bcachefs.h"
#include "btree_update.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "migrate.h"
#include "move.h"
#include "super-io.h"

static bool migrate_pred(void *arg, struct bkey_s_c_extent e)
{
	struct bch_dev *ca = arg;
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr)
		if (ptr->dev == ca->dev_idx)
			return true;

	return false;
}

#define MAX_DATA_OFF_ITER	10

static int bch2_dev_usrdata_migrate(struct bch_fs *c, struct bch_dev *ca,
				    int flags)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 keys_moved, sectors_moved;
	unsigned pass = 0;
	int ret = 0;

	if (!(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_USER)))
		return 0;

	/*
	 * In theory, only one pass should be necessary as we've
	 * quiesced all writes before calling this.
	 *
	 * However, in practice, more than one pass may be necessary:
	 * - Some move fails due to an error. We can can find this out
	 *   from the moving_context.
	 * - Some key swap failed because some of the pointers in the
	 *   key in the tree changed due to caching behavior, btree gc
	 *   pruning stale pointers, or tiering (if the device being
	 *   removed is in tier 0).  A smarter bkey_cmpxchg would
	 *   handle these cases.
	 *
	 * Thus this scans the tree one more time than strictly necessary,
	 * but that can be viewed as a verification pass.
	 */
	do {
		ret = bch2_move_data(c, NULL,
				     SECTORS_IN_FLIGHT_PER_DEVICE,
				     NULL,
				     writepoint_hashed((unsigned long) current),
				     0,
				     ca->dev_idx,
				     migrate_pred, ca,
				     &keys_moved,
				     &sectors_moved);
		if (ret) {
			bch_err(c, "error migrating data: %i", ret);
			return ret;
		}
	} while (keys_moved && pass++ < MAX_DATA_OFF_ITER);

	if (keys_moved) {
		bch_err(c, "unable to migrate all data in %d iterations",
			MAX_DATA_OFF_ITER);
		return -1;
	}

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_USER);

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS_MIN, BTREE_ITER_PREFETCH, k) {
		if (!bkey_extent_is_data(k.k))
			continue;

		ret = bch2_check_mark_super(c, bkey_s_c_to_extent(k),
					    BCH_DATA_USER);
		if (ret) {
			bch_err(c, "error migrating data %i from check_mark_super()", ret);
			break;
		}
	}

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);
	return ret;
}

static int bch2_move_btree_off(struct bch_fs *c, struct bch_dev *ca,
			       enum btree_id id)
{
	struct btree_iter iter;
	struct btree *b;
	int ret;

	for_each_btree_node(&iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
		struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);

		if (!bch2_extent_has_device(e, ca->dev_idx))
			continue;

		ret = bch2_btree_node_rewrite(c, &iter, b->data->keys.seq, 0);
		if (ret) {
			bch2_btree_iter_unlock(&iter);
			return ret;
		}

		bch2_btree_iter_set_locks_want(&iter, 0);
	}
	ret = bch2_btree_iter_unlock(&iter);
	if (ret)
		return ret; /* btree IO error */

	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG)) {
		for_each_btree_node(&iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
			struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);

			BUG_ON(bch2_extent_has_device(e, ca->dev_idx));
		}
		bch2_btree_iter_unlock(&iter);
	}

	return 0;
}

/*
 * This moves only the meta-data off, leaving the data (if any) in place.
 * The data is moved off by bch_move_data_off_device, if desired, and
 * called first.
 *
 * Before calling this, allocation of buckets to the device must have
 * been disabled, as else we'll continue to write meta-data to the device
 * when new buckets are picked for meta-data writes.
 * In addition, the copying gc and allocator threads for the device
 * must have been stopped.  The allocator thread is the only thread
 * that writes prio/gen information.
 *
 * Meta-data consists of:
 * - Btree nodes
 * - Prio/gen information
 * - Journal entries
 * - Superblock
 *
 * This has to move the btree nodes and the journal only:
 * - prio/gen information is not written once the allocator thread is stopped.
 *   also, as the prio/gen information is per-device it is not moved.
 * - the superblock will be written by the caller once after everything
 *   is stopped.
 *
 * Note that currently there is no way to stop btree node and journal
 * meta-data writes to a device without moving the meta-data because
 * once a bucket is open for a btree node, unless a replacement btree
 * node is allocated (and the tree updated), the bucket will continue
 * to be written with updates.  Similarly for the journal (it gets
 * written until filled).
 *
 * This routine leaves the data (if any) in place.  Whether the data
 * should be moved off is a decision independent of whether the meta
 * data should be moved off and stopped:
 *
 * - For device removal, both data and meta-data are moved off, in
 *   that order.
 *
 * - However, for turning a device read-only without removing it, only
 *   meta-data is moved off since that's the only way to prevent it
 *   from being written.  Data is left in the device, but no new data
 *   is written.
 */

static int bch2_dev_metadata_migrate(struct bch_fs *c, struct bch_dev *ca,
				     int flags)
{
	unsigned i;
	int ret = 0;

	if (!(bch2_dev_has_data(c, ca) &
	      ((1 << BCH_DATA_JOURNAL)|
	       (1 << BCH_DATA_BTREE))))
		return 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_BTREE);

	for (i = 0; i < BTREE_ID_NR; i++) {
		ret = bch2_move_btree_off(c, ca, i);
		if (ret)
			goto err;
	}
err:
	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);
	return ret;
}

int bch2_dev_data_migrate(struct bch_fs *c, struct bch_dev *ca, int flags)
{
	BUG_ON(ca->mi.state == BCH_MEMBER_STATE_RW &&
	       bch2_dev_is_online(ca));

	return bch2_dev_usrdata_migrate(c, ca, flags) ?:
		bch2_dev_metadata_migrate(c, ca, flags);
}

static int drop_dev_ptrs(struct bch_fs *c, struct bkey_s_extent e,
			 unsigned dev_idx, int flags, bool metadata)
{
	unsigned replicas = metadata ? c->opts.metadata_replicas : c->opts.data_replicas;
	unsigned lost = metadata ? BCH_FORCE_IF_METADATA_LOST : BCH_FORCE_IF_DATA_LOST;
	unsigned degraded = metadata ? BCH_FORCE_IF_METADATA_DEGRADED : BCH_FORCE_IF_DATA_DEGRADED;
	unsigned nr_good;

	bch2_extent_drop_device(e, dev_idx);

	nr_good = bch2_extent_nr_good_ptrs(c, e.c);
	if ((!nr_good && !(flags & lost)) ||
	    (nr_good < replicas && !(flags & degraded)))
		return -EINVAL;

	return 0;
}

/*
 * This doesn't actually move any data -- it marks the keys as bad
 * if they contain a pointer to a device that is forcibly removed
 * and don't have other valid pointers.  If there are valid pointers,
 * the necessary pointers to the removed device are replaced with
 * bad pointers instead.
 *
 * This is only called if bch_move_data_off_device above failed, meaning
 * that we've already tried to move the data MAX_DATA_OFF_ITER times and
 * are not likely to succeed if we try again.
 */
static int bch2_dev_usrdata_drop(struct bch_fs *c, unsigned dev_idx, int flags)
{
	struct bkey_s_c k;
	struct bkey_s_extent e;
	BKEY_PADDED(key) tmp;
	struct btree_iter iter;
	int ret = 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_USER);

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS,
			     POS_MIN, BTREE_ITER_PREFETCH);

	while ((k = bch2_btree_iter_peek(&iter)).k &&
	       !(ret = btree_iter_err(k))) {
		if (!bkey_extent_is_data(k.k))
			goto advance;

		if (!bch2_extent_has_device(bkey_s_c_to_extent(k), dev_idx))
			goto advance;

		bkey_reassemble(&tmp.key, k);
		e = bkey_i_to_s_extent(&tmp.key);

		ret = drop_dev_ptrs(c, e, dev_idx, flags, false);
		if (ret)
			break;

		/*
		 * If the new extent no longer has any pointers, bch2_extent_normalize()
		 * will do the appropriate thing with it (turning it into a
		 * KEY_TYPE_ERROR key, or just a discard if it was a cached extent)
		 */
		bch2_extent_normalize(c, e.s);

		if (bkey_extent_is_data(e.k) &&
		    (ret = bch2_check_mark_super(c, e.c, BCH_DATA_USER)))
			break;

		iter.pos = bkey_start_pos(&tmp.key.k);

		ret = bch2_btree_insert_at(c, NULL, NULL, NULL,
					   BTREE_INSERT_ATOMIC|
					   BTREE_INSERT_NOFAIL,
					   BTREE_INSERT_ENTRY(&iter, &tmp.key));

		/*
		 * don't want to leave ret == -EINTR, since if we raced and
		 * something else overwrote the key we could spuriously return
		 * -EINTR below:
		 */
		if (ret == -EINTR)
			ret = 0;
		if (ret)
			break;

		continue;
advance:
		if (bkey_extent_is_data(k.k)) {
			ret = bch2_check_mark_super(c, bkey_s_c_to_extent(k),
						    BCH_DATA_USER);
			if (ret)
				break;
		}
		bch2_btree_iter_advance_pos(&iter);
	}

	bch2_btree_iter_unlock(&iter);

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);

	return ret;
}

static int bch2_dev_metadata_drop(struct bch_fs *c, unsigned dev_idx, int flags)
{
	struct btree_iter iter;
	struct closure cl;
	struct btree *b;
	unsigned id;
	int ret;

	/* don't handle this yet: */
	if (flags & BCH_FORCE_IF_METADATA_LOST)
		return -EINVAL;

	closure_init_stack(&cl);

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_BTREE);

	for (id = 0; id < BTREE_ID_NR; id++) {
		for_each_btree_node(&iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
			__BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;
			struct bkey_i_extent *new_key;
retry:
			if (!bch2_extent_has_device(bkey_i_to_s_c_extent(&b->key),
						    dev_idx)) {
				bch2_btree_iter_set_locks_want(&iter, 0);

				ret = bch2_check_mark_super(c, bkey_i_to_s_c_extent(&b->key),
							    BCH_DATA_BTREE);
				if (ret)
					goto err;
			} else {
				bkey_copy(&tmp.k, &b->key);
				new_key = bkey_i_to_extent(&tmp.k);

				ret = drop_dev_ptrs(c, extent_i_to_s(new_key),
						    dev_idx, flags, true);
				if (ret)
					goto err;

				if (!bch2_btree_iter_set_locks_want(&iter, U8_MAX)) {
					b = bch2_btree_iter_peek_node(&iter);
					goto retry;
				}

				ret = bch2_btree_node_update_key(c, &iter, b, new_key);
				if (ret == -EINTR) {
					b = bch2_btree_iter_peek_node(&iter);
					goto retry;
				}
				if (ret)
					goto err;
			}
		}
		bch2_btree_iter_unlock(&iter);

		/* btree root */
		mutex_lock(&c->btree_root_lock);
		mutex_unlock(&c->btree_root_lock);
	}

	ret = 0;
out:
	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);

	return ret;
err:
	bch2_btree_iter_unlock(&iter);
	goto out;
}

int bch2_dev_data_drop(struct bch_fs *c, unsigned dev_idx, int flags)
{
	return bch2_dev_usrdata_drop(c, dev_idx, flags) ?:
		bch2_dev_metadata_drop(c, dev_idx, flags);
}
