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

	return bch2_extent_has_device(e, ca->dev_idx);
}

#define MAX_DATA_OFF_ITER	10

static int bch2_dev_usrdata_migrate(struct bch_fs *c, struct bch_dev *ca,
				    int flags)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bch_move_stats stats;
	unsigned pass = 0;
	int ret = 0;

	if (!(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_USER)))
		return 0;

	/*
	 * XXX: we should be able to do this in one pass, but bch2_move_data()
	 * can spuriously fail to move an extent due to racing with other move
	 * operations
	 */
	do {
		ret = bch2_move_data(c, NULL,
				     SECTORS_IN_FLIGHT_PER_DEVICE,
				     NULL,
				     writepoint_hashed((unsigned long) current),
				     0,
				     ca->dev_idx,
				     migrate_pred, ca,
				     &stats);
		if (ret) {
			bch_err(c, "error migrating data: %i", ret);
			return ret;
		}
	} while (atomic64_read(&stats.keys_moved) && pass++ < MAX_DATA_OFF_ITER);

	if (atomic64_read(&stats.keys_moved)) {
		bch_err(c, "unable to migrate all data in %d iterations",
			MAX_DATA_OFF_ITER);
		return -1;
	}

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_USER);

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS_MIN, BTREE_ITER_PREFETCH, k) {
		ret = bch2_check_mark_super(c, BCH_DATA_USER, bch2_bkey_devs(k));
		if (ret) {
			bch_err(c, "error migrating data %i from check_mark_super()", ret);
			break;
		}
	}

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);
	return ret;
}

static int bch2_dev_metadata_migrate(struct bch_fs *c, struct bch_dev *ca,
				     int flags)
{
	struct btree_iter iter;
	struct btree *b;
	int ret = 0;
	unsigned id;

	if (!(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_BTREE)))
		return 0;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_BTREE);

	for (id = 0; id < BTREE_ID_NR; id++) {
		for_each_btree_node(&iter, c, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
			struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);

			if (!bch2_extent_has_device(e, ca->dev_idx))
				continue;

			ret = bch2_btree_node_rewrite(c, &iter, b->data->keys.seq, 0);
			if (ret) {
				bch2_btree_iter_unlock(&iter);
				goto err;
			}
		}
		ret = bch2_btree_iter_unlock(&iter);
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
		if (!bkey_extent_is_data(k.k) ||
		    !bch2_extent_has_device(bkey_s_c_to_extent(k), dev_idx)) {
			ret = bch2_check_mark_super(c, BCH_DATA_USER,
						    bch2_bkey_devs(k));
			if (ret)
				break;
			bch2_btree_iter_advance_pos(&iter);
			continue;
		}

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

		ret = bch2_check_mark_super(c, BCH_DATA_USER,
				bch2_bkey_devs(bkey_i_to_s_c(&tmp.key)));
		if (ret)
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

				ret = bch2_check_mark_super(c, BCH_DATA_BTREE,
						bch2_bkey_devs(bkey_i_to_s_c(&b->key)));
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
