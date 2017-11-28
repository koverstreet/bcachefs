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

static int issue_migration_move(struct bch_dev *ca,
				struct moving_context *ctxt,
				struct bch_devs_mask *devs,
				struct bkey_s_c k)
{
	struct bch_fs *c = ca->fs;
	struct disk_reservation res;
	const struct bch_extent_ptr *ptr;
	int ret;

	if (bch2_disk_reservation_get(c, &res, k.k->size, 0))
		return -ENOSPC;

	extent_for_each_ptr(bkey_s_c_to_extent(k), ptr)
		if (ptr->dev == ca->dev_idx)
			goto found;

	BUG();
found:
	/* XXX: we need to be doing something with the disk reservation */

	ret = bch2_data_move(c, ctxt, devs,
			     writepoint_hashed((unsigned long) current),
			     k, true);
	if (ret)
		bch2_disk_reservation_put(c, &res);
	return ret;
}

#define MAX_DATA_OFF_ITER	10

/*
 * This moves only the data off, leaving the meta-data (if any) in place.
 * It walks the key space, and for any key with a valid pointer to the
 * relevant device, it copies it elsewhere, updating the key to point to
 * the copy.
 * The meta-data is moved off by bch_move_meta_data_off_device.
 *
 * Note: If the number of data replicas desired is > 1, ideally, any
 * new copies would not be made in the same device that already have a
 * copy (if there are enough devices).
 * This is _not_ currently implemented.  The multiple replicas can
 * land in the same device even if there are others available.
 */

int bch2_move_data_off_device(struct bch_dev *ca)
{
	struct moving_context ctxt;
	struct bch_fs *c = ca->fs;
	unsigned pass = 0;
	u64 seen_key_count;
	int ret = 0;

	BUG_ON(ca->mi.state == BCH_MEMBER_STATE_RW);

	if (!(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_USER)))
		return 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_USER);

	bch2_move_ctxt_init(&ctxt, NULL, SECTORS_IN_FLIGHT_PER_DEVICE);
	__set_bit(ca->dev_idx, ctxt.avoid.d);

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
		struct btree_iter iter;
		struct bkey_s_c k;

		seen_key_count = 0;

		bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
				     BTREE_ITER_PREFETCH);

		while (!bch2_move_ctxt_wait(&ctxt) &&
		       (k = bch2_btree_iter_peek(&iter)).k &&
		       !(ret = btree_iter_err(k))) {
			if (!bkey_extent_is_data(k.k) ||
			    !bch2_extent_has_device(bkey_s_c_to_extent(k),
						   ca->dev_idx))
				goto next;

			ret = issue_migration_move(ca, &ctxt, NULL, k);
			if (ret == -ENOMEM) {
				bch2_btree_iter_unlock(&iter);

				/*
				 * memory allocation failure, wait for some IO
				 * to finish
				 */
				bch2_move_ctxt_wait_for_io(&ctxt);
				continue;
			}
			if (ret == -ENOSPC)
				break;
			BUG_ON(ret);

			seen_key_count++;
			continue;
next:
			if (bkey_extent_is_data(k.k)) {
				ret = bch2_check_mark_super(c, bkey_s_c_to_extent(k),
							    BCH_DATA_USER);
				if (ret)
					break;
			}
			bch2_btree_iter_advance_pos(&iter);
			bch2_btree_iter_cond_resched(&iter);

		}
		bch2_btree_iter_unlock(&iter);
		bch2_move_ctxt_exit(&ctxt);

		if (ret)
			goto err;
	} while (seen_key_count && pass++ < MAX_DATA_OFF_ITER);

	if (seen_key_count) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -1;
		goto err;
	}

err:
	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);
	return ret;
}

/*
 * This walks the btree, and for any node on the relevant device it moves the
 * node elsewhere.
 */
static int bch2_move_btree_off(struct bch_fs *c, struct bch_dev *ca,
			       enum btree_id id)
{
	struct btree_iter iter;
	struct closure cl;
	struct btree *b;
	int ret;

	BUG_ON(ca->mi.state == BCH_MEMBER_STATE_RW);

	closure_init_stack(&cl);

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

int bch2_move_metadata_off_device(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	unsigned i;
	int ret = 0;

	BUG_ON(ca->mi.state == BCH_MEMBER_STATE_RW);

	if (!(bch2_dev_has_data(c, ca) &
	      ((1 << BCH_DATA_JOURNAL)|
	       (1 << BCH_DATA_BTREE))))
		return 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c,
			       (1 << BCH_DATA_JOURNAL)|
			       (1 << BCH_DATA_BTREE));

	/* 1st, Move the btree nodes off the device */

	for (i = 0; i < BTREE_ID_NR; i++) {
		ret = bch2_move_btree_off(c, ca, i);
		if (ret)
			goto err;
	}

	/* There are no prios/gens to move -- they are already in the device. */

	/* 2nd. Move the journal off the device */

	ret = bch2_journal_move(ca);
	if (ret)
		goto err;

err:
	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);
	return ret;
}

/*
 * Flagging data bad when forcibly removing a device after failing to
 * migrate the data off the device.
 */

static int bch2_flag_key_bad(struct btree_iter *iter,
			    struct bch_dev *ca,
			    struct bkey_s_c_extent orig)
{
	BKEY_PADDED(key) tmp;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct bch_fs *c = ca->fs;

	bkey_reassemble(&tmp.key, orig.s_c);
	e = bkey_i_to_s_extent(&tmp.key);

	extent_for_each_ptr_backwards(e, ptr)
		if (ptr->dev == ca->dev_idx)
			bch2_extent_drop_ptr(e, ptr);

	/*
	 * If the new extent no longer has any pointers, bch2_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_ERROR key, or just a discard if it was a cached extent)
	 */
	bch2_extent_normalize(c, e.s);

	return bch2_btree_insert_at(c, NULL, NULL, NULL,
				   BTREE_INSERT_ATOMIC,
				   BTREE_INSERT_ENTRY(iter, &tmp.key));
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
int bch2_flag_data_bad(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bkey_s_c k;
	struct bkey_s_c_extent e;
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

		e = bkey_s_c_to_extent(k);
		if (!bch2_extent_has_device(e, ca->dev_idx))
			goto advance;

		ret = bch2_flag_key_bad(&iter, ca, e);

		/*
		 * don't want to leave ret == -EINTR, since if we raced and
		 * something else overwrote the key we could spuriously return
		 * -EINTR below:
		 */
		if (ret == -EINTR)
			ret = 0;
		if (ret)
			break;

		/*
		 * If the replica we're dropping was dirty and there is an
		 * additional cached replica, the cached replica will now be
		 * considered dirty - upon inserting the new version of the key,
		 * the bucket accounting will be updated to reflect the fact
		 * that the cached data is now dirty and everything works out as
		 * if by magic without us having to do anything.
		 *
		 * The one thing we need to be concerned with here is there's a
		 * race between when we drop any stale pointers from the key
		 * we're about to insert, and when the key actually gets
		 * inserted and the cached data is marked as dirty - we could
		 * end up trying to insert a key with a pointer that should be
		 * dirty, but points to stale data.
		 *
		 * If that happens the insert code just bails out and doesn't do
		 * the insert - however, it doesn't return an error. Hence we
		 * need to always recheck the current key before advancing to
		 * the next:
		 */
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
