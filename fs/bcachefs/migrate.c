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

static bool migrate_data_pred(struct scan_keylist *kl, struct bkey_s_c k)
{
	struct cache *ca = container_of(kl, struct cache,
					moving_gc_queue.keys);

	return bkey_extent_is_data(k.k) &&
		bch_extent_has_device(bkey_s_c_to_extent(k),
				      ca->sb.nr_this_dev);
}

static void bch_extent_drop_dev_ptrs(struct bkey_s_extent e, unsigned dev)
{
	struct bch_extent_ptr *ptr;

	extent_for_each_ptr_backwards(e, ptr)
		if (ptr->dev == dev)
			bch_extent_drop_ptr(e, ptr);
}

static int issue_migration_move(struct cache *ca,
				struct moving_context *ctxt,
				struct bkey_s_c k,
				u64 *seen_key_count)
{
	struct moving_queue *q = &ca->moving_gc_queue;
	struct cache_set *c = ca->set;
	struct moving_io *io;
	struct disk_reservation res;

	if (bch_disk_reservation_get(c, &res, k.k->size))
		return -ENOSPC;

	io = moving_io_alloc(k);
	if (!io) {
		bch_disk_reservation_put(c, &res);
		return -ENOMEM;
	}

	/* This also copies k into the write op's replace_key and insert_key */

	bch_replace_init(&io->replace, k);

	bch_write_op_init(&io->op, c, &io->wbio, res,
			  &c->migration_write_point,
			  k, &io->replace.hook, NULL,
			  0);
	io->op.nr_replicas = 1;

	io->op.io_wq = q->wq;

	bch_extent_drop_dev_ptrs(bkey_i_to_s_extent(&io->op.insert_key),
				 ca->sb.nr_this_dev);

	bch_data_move(q, ctxt, io);
	(*seen_key_count)++;

	/*
	 * IMPORTANT: We must call bch_data_move before we dequeue so
	 * that the key can always be found in either the pending list
	 * in the moving queue or in the scan keylist list in the
	 * moving queue.
	 * If we reorder, there is a window where a key is not found
	 * by btree gc marking.
	 */
	bch_scan_keylist_dequeue(&q->keys);
	return 0;
}

#define MIGRATION_DEBUG		0

#define MAX_DATA_OFF_ITER	10
#define PASS_LOW_LIMIT		(MIGRATION_DEBUG ? 0 : 2)
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
	int ret;
	struct bkey_i *k;
	unsigned pass;
	u64 seen_key_count;
	unsigned last_error_count;
	unsigned last_error_flags;
	struct moving_context context;
	struct cache_set *c = ca->set;
	struct moving_queue *queue = &ca->moving_gc_queue;

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
	bch_moving_context_init(&context, NULL, MOVING_PURPOSE_MIGRATION);
	context.avoid = ca;

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

	seen_key_count = 1;
	last_error_count = 0;
	last_error_flags = 0;

	for (pass = 0;
	     (seen_key_count != 0 && (pass < MAX_DATA_OFF_ITER));
	     pass++) {
		bool again;

		seen_key_count = 0;
		atomic_set(&context.error_count, 0);
		atomic_set(&context.error_flags, 0);
		context.last_scanned = POS_MIN;

again:
		again = false;

		while (1) {
			if (bch_queue_full(queue)) {
				if (queue->rotational) {
					again = true;
					break;
				} else {
					bch_moving_wait(&context);
					continue;
				}
			}

			k = bch_scan_keylist_next_rescan(c,
							 &queue->keys,
							 &context.last_scanned,
							 POS_MAX,
							 migrate_data_pred);
			if (k == NULL)
				break;

			if (issue_migration_move(ca, &context, bkey_i_to_s_c(k),
						 &seen_key_count)) {
				/*
				 * Memory allocation failed; we will wait for
				 * all queued moves to finish and continue
				 * scanning starting from the same key
				 */
				again = true;
				break;
			}
		}

		bch_queue_run(queue, &context);
		if (again)
			goto again;

		if ((pass >= PASS_LOW_LIMIT)
		    && (seen_key_count != (MIGRATION_DEBUG ? ~0ULL : 0))) {
			pr_notice("found %llu keys on pass %u.",
				  seen_key_count, pass);
		}

		last_error_count = atomic_read(&context.error_count);
		last_error_flags = atomic_read(&context.error_flags);

		if (last_error_count != 0) {
			pr_notice("pass %u: error count = %u, error flags = 0x%x",
				  pass, last_error_count, last_error_flags);
		}
	}

	if (seen_key_count != 0 || last_error_count != 0) {
		pr_err("Unable to migrate all data in %d iterations.",
		       MAX_DATA_OFF_ITER);
		ret = -EDEADLK;
	} else if (MIGRATION_DEBUG)
		pr_notice("Migrated all data in %d iterations", pass);

	bch_queue_run(queue, &context);
	return ret;
}

/*
 * This walks the btree, and for any node on the relevant device it moves the
 * node elsewhere.
 */
static int bch_move_btree_off(struct cache *ca,
			      enum btree_id id,
			      const char *name)
{
	struct closure cl;
	unsigned pass;

	closure_init_stack(&cl);

	pr_debug("Moving %s btree off device %u",
		 name, ca->sb.nr_this_dev);

	for (pass = 0; (pass < MAX_DATA_OFF_ITER); pass++) {
		struct btree_iter iter;
		struct btree *b;
		unsigned moved = 0, seen = 0;
		int ret;

		for_each_btree_node(&iter, ca->set, id, POS_MIN, b) {
			struct bkey_s_c_extent e =
				bkey_i_to_s_c_extent(&b->key);
			seen++;
retry:
			if (!bch_extent_has_device(e, ca->sb.nr_this_dev))
				continue;

			if (bch_btree_node_rewrite(&iter, b, &cl)) {
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

			moved++;
			iter.locks_want = -1;
		}
		ret = bch_btree_iter_unlock(&iter);
		if (ret)
			return ret; /* btree IO error */

		if (!moved)
			return 0;

		pr_debug("%s pass %u: seen %u, moved %u.",
			 name, pass, seen, moved);
	}

	/* Failed: */
	return -1;
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
	int ret = 0;		/* Success */

	/* 1st, Move the btree nodes off the device */

	for (i = 0; i < BTREE_ID_NR; i++)
		if (bch_move_btree_off(ca, i, bch_btree_id_names[i]) != 0)
			return 1;

	/* There are no prios/gens to move -- they are already in the device. */

	/* 2nd. Move the journal off the device */

	if (bch_journal_move(ca) != 0) {
		pr_err("Unable to move the journal off in %pU.",
		       ca->set->disk_sb.user_uuid.b);
		ret = 1;	/* Failure */
	}

	return ret;
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
	struct cache_set *c = ca->set;

	bkey_reassemble(&tmp.key, orig.s_c);
	e = bkey_i_to_s_extent(&tmp.key);

	bch_extent_drop_dev_ptrs(e, ca->sb.nr_this_dev);

	/*
	 * If the new extent no longer has any pointers, bch_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_ERROR key, or just a discard if it was a cached extent)
	 */
	bch_extent_normalize(c, e.s);

	return bch_btree_insert_at(iter, &tmp.key, NULL, NULL,
				   NULL, BTREE_INSERT_ATOMIC);
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
