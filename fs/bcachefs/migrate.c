/*
 * Code for moving data off a device.
 */

#include "bcache.h"
#include "btree_update.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "migrate.h"
#include "move.h"

static int issue_migration_move(struct cache *ca,
				struct moving_context *ctxt,
				struct bkey_s_c k)
{
	struct moving_queue *q = &ca->moving_gc_queue;
	struct cache_set *c = ca->set;
	struct moving_io *io;
	struct disk_reservation res;
	const struct bch_extent_ptr *ptr;

	if (bch_disk_reservation_get(c, &res, k.k->size, 0))
		return -ENOSPC;

	extent_for_each_ptr(bkey_s_c_to_extent(k), ptr)
		if (ptr->dev == ca->sb.nr_this_dev)
			goto found;

	BUG();
found:
	io = moving_io_alloc(c, q, &c->migration_write_point, k, ptr);
	if (!io) {
		bch_disk_reservation_put(c, &res);
		return -ENOMEM;
	}

	bch_data_move(q, ctxt, io);
	return 0;
}

#define MAX_DATA_OFF_ITER	10
#define MIGRATE_NR		64
#define MIGRATE_READ_NR		32
#define MIGRATE_WRITE_NR	32

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

int bch_move_data_off_device(struct cache *ca)
{
	struct moving_context ctxt;
	struct cache_set *c = ca->set;
	struct moving_queue *queue = &ca->moving_gc_queue;
	unsigned pass = 0;
	u64 seen_key_count;
	int ret = 0;

	BUG_ON(ca->mi.state == CACHE_ACTIVE);

	/*
	 * This reuses the moving gc queue as it is no longer in use
	 * by moving gc, which must have been stopped to call this.
	 */

	BUG_ON(ca->moving_gc_read != NULL);

	/*
	 * This may actually need to start the work queue because the
	 * device may have always been read-only and never have had it
	 * started (moving gc usually starts it but not for RO
	 * devices).
	 */

	bch_queue_start(queue);

	queue_io_resize(queue, MIGRATE_NR, MIGRATE_READ_NR, MIGRATE_WRITE_NR);

	BUG_ON(queue->wq == NULL);
	bch_moving_context_init(&ctxt, NULL, MOVING_PURPOSE_MIGRATION);
	ctxt.avoid = ca;

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
		atomic_set(&ctxt.error_count, 0);
		atomic_set(&ctxt.error_flags, 0);

		bch_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

		while ((k = bch_btree_iter_peek(&iter)).k) {
			if (!bkey_extent_is_data(k.k) ||
			    !bch_extent_has_device(bkey_s_c_to_extent(k),
						   ca->sb.nr_this_dev))
				goto next;

			if (bch_queue_full(queue)) {
				bch_btree_iter_unlock(&iter);

				if (queue->rotational)
					bch_queue_run(queue, &ctxt);
				else
					wait_event(queue->wait,
						   !bch_queue_full(queue));
				continue;
			}

			ret = issue_migration_move(ca, &ctxt, k);
			if (ret == -ENOMEM) {
				bch_btree_iter_unlock(&iter);

				/*
				 * memory allocation failure, wait for IOs to
				 * finish
				 */
				bch_queue_run(queue, &ctxt);
				continue;
			}
			if (ret == -ENOSPC) {
				bch_btree_iter_unlock(&iter);
				bch_queue_run(queue, &ctxt);
				return -ENOSPC;
			}
			BUG_ON(ret);

			seen_key_count++;
next:
			bch_btree_iter_advance_pos(&iter);
			bch_btree_iter_cond_resched(&iter);

		}
		ret = bch_btree_iter_unlock(&iter);
		bch_queue_run(queue, &ctxt);

		if (ret)
			return ret;
	} while (seen_key_count && pass++ < MAX_DATA_OFF_ITER);

	if (seen_key_count) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		return -1;
	}

	return 0;
}

/*
 * This walks the btree, and for any node on the relevant device it moves the
 * node elsewhere.
 */
static int bch_move_btree_off(struct cache *ca, enum btree_id id)
{
	struct cache_set *c = ca->set;
	struct btree_iter iter;
	struct closure cl;
	struct btree *b;
	int ret;

	BUG_ON(ca->mi.state == CACHE_ACTIVE);

	closure_init_stack(&cl);

	for_each_btree_node(&iter, c, id, POS_MIN, 0, b) {
		struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);
retry:
		if (!bch_extent_has_device(e, ca->sb.nr_this_dev))
			continue;

		ret = bch_btree_node_rewrite(&iter, b, &cl);
		if (ret == -EINTR || ret == -ENOSPC) {
			/*
			 * Drop locks to upgrade locks or wait on
			 * reserve: after retaking, recheck in case we
			 * raced.
			 */
			bch_btree_iter_unlock(&iter);
			closure_sync(&cl);
			b = bch_btree_iter_peek_node(&iter);
			goto retry;
		}
		if (ret) {
			bch_btree_iter_unlock(&iter);
			return ret;
		}

		iter.locks_want = 0;
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret; /* btree IO error */

	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG)) {
		for_each_btree_node(&iter, c, id, POS_MIN, 0, b) {
			struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);

			BUG_ON(bch_extent_has_device(e, ca->sb.nr_this_dev));
		}
		bch_btree_iter_unlock(&iter);
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

int bch_move_meta_data_off_device(struct cache *ca)
{
	unsigned i;
	int ret;

	/* 1st, Move the btree nodes off the device */

	for (i = 0; i < BTREE_ID_NR; i++) {
		ret = bch_move_btree_off(ca, i);
		if (ret)
			return ret;
	}

	/* There are no prios/gens to move -- they are already in the device. */

	/* 2nd. Move the journal off the device */

	ret = bch_journal_move(ca);
	if (ret)
		return ret;

	return 0;
}

/*
 * Flagging data bad when forcibly removing a device after failing to
 * migrate the data off the device.
 */

static int bch_flag_key_bad(struct btree_iter *iter,
			    struct cache *ca,
			    struct bkey_s_c_extent orig)
{
	BKEY_PADDED(key) tmp;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache_set *c = ca->set;

	bkey_reassemble(&tmp.key, orig.s_c);
	e = bkey_i_to_s_extent(&tmp.key);

	extent_for_each_ptr_backwards(e, ptr)
		if (ptr->dev == ca->sb.nr_this_dev)
			bch_extent_drop_ptr(e, ptr);

	/*
	 * If the new extent no longer has any pointers, bch_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_ERROR key, or just a discard if it was a cached extent)
	 */
	bch_extent_normalize(c, e.s);

	return bch_btree_insert_at(c, NULL, NULL, NULL,
				   BTREE_INSERT_ATOMIC,
				   BTREE_INSERT_ENTRY(iter, &tmp.key));
}

/*
 * This doesn't actually move any data -- it marks the keys as bad
 * if they contain a pointer to a device that is forcibly removed
 * and don't have other valid pointers.  If there are valid pointers,
 * the necessary pointers to the removed device are replaced with
 * bad pointers instead.
 * This is only called if bch_move_data_off_device above failed, meaning
 * that we've already tried to move the data MAX_DATA_OFF_ITER times and
 * are not likely to succeed if we try again.
 */

int bch_flag_data_bad(struct cache *ca)
{
	int ret = 0, ret2;
	struct bkey_s_c k;
	struct bkey_s_c_extent e;
	struct btree_iter iter;

	bch_btree_iter_init(&iter, ca->set, BTREE_ID_EXTENTS, POS_MIN);

	while ((k = bch_btree_iter_peek(&iter)).k) {
		if (!bkey_extent_is_data(k.k))
			goto advance;

		e = bkey_s_c_to_extent(k);
		if (!bch_extent_has_device(e, ca->sb.nr_this_dev))
			goto advance;

		ret = bch_flag_key_bad(&iter, ca, e);

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
		bch_btree_iter_advance_pos(&iter);
	}

	ret2 = bch_btree_iter_unlock(&iter);

	return ret ?: ret2;
}
