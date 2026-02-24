// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets_waiting_for_journal.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

static int discard_in_flight_add(struct bch_dev *ca, u64 bucket, bool in_progress)
{
	struct bch_fs *c = ca->fs;

	guard(mutex)(&ca->discard_buckets_in_flight_lock);
	struct discard_in_flight *i =
		darray_find_p(ca->discard_buckets_in_flight, i, i->bucket == bucket);
	if (i)
		return bch_err_throw(c, EEXIST_discard_in_flight_add);

	return darray_push(&ca->discard_buckets_in_flight, ((struct discard_in_flight) {
			   .in_progress = in_progress,
			   .bucket	= bucket,
	}));
}

static void discard_in_flight_remove(struct bch_dev *ca, u64 bucket)
{
	guard(mutex)(&ca->discard_buckets_in_flight_lock);
	struct discard_in_flight *i =
		darray_find_p(ca->discard_buckets_in_flight, i, i->bucket == bucket);
	BUG_ON(!i || !i->in_progress);

	darray_remove_item(&ca->discard_buckets_in_flight, i);
}

struct discard_buckets_state {
	u64		seen;
	u64		open;
	u64		need_journal_commit;
	u64		commit_in_flight;
	u64		bad_data_type;
	u64		already_discarding;
	u64		discarded;
};

static void discard_buckets_state_to_text(struct printbuf *out, struct discard_buckets_state *s)
{
	printbuf_tabstop_push(out, 20);
	prt_printf(out, "seen:\t%llu\n",		s->seen);
	prt_printf(out, "open:\t%llu\n",		s->open);
	prt_printf(out, "need_journal_commit:\t%llu\n",	s->need_journal_commit);
	prt_printf(out, "commit_in_flight:\t%llu\n",	s->commit_in_flight);
	prt_printf(out, "bad_data_type:\t%llu\n",	s->bad_data_type);
	prt_printf(out, "already_discarding:\t%llu\n",	s->already_discarding);
	prt_printf(out, "discarded:\t%llu\n",		s->discarded);
}

static int bch2_discard_one_bucket(struct btree_trans *trans,
				   struct bch_dev *ca,
				   struct btree_iter *need_discard_iter,
				   struct bpos *discard_pos_done,
				   struct discard_buckets_state *s,
				   bool fastpath)
{
	struct bch_fs *c = trans->c;
	struct bpos pos = need_discard_iter->pos;
	bool discard_locked = false;
	int ret = 0;

	s->seen++;

	if (bch2_bucket_is_open_safe(c, pos.inode, pos.offset)) {
		s->open++;
		return 0;
	}

	u64 seq_ready = bch2_bucket_journal_seq_ready(&c->buckets_waiting_for_journal,
						      pos.inode, pos.offset);
	if (seq_ready > c->journal.flushed_seq_ondisk) {
		if (seq_ready > c->journal.flushing_seq)
			s->need_journal_commit++;
		else
			s->commit_in_flight++;
		return 0;
	}

	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, need_discard_iter->pos, BTREE_ITER_cached);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	struct bkey_buf orig_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&orig_k);
	bch2_bkey_buf_reassemble(&orig_k, k);

	struct bkey_i_alloc_v4 *a = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	if (a->v.data_type != BCH_DATA_need_discard) {
		s->bad_data_type++;

		if (need_discard_or_freespace_err(trans, k, true, true, true)) {
			try(bch2_btree_bit_mod_iter(trans, need_discard_iter, false));
			goto commit;
		}

		return 0;
	}

	if (!fastpath) {
		if (discard_in_flight_add(ca, iter.pos.offset, true)) {
			s->already_discarding++;
			goto out;
		}

		discard_locked = true;
	}

	if (!bkey_eq(*discard_pos_done, iter.pos)) {
		s->discarded++;
		*discard_pos_done = iter.pos;

		if (bch2_discard_opt_enabled(c, ca) && !c->opts.nochanges) {
			/*
			 * This works without any other locks because this is the only
			 * thread that removes items from the need_discard tree
			 */
			bch2_trans_unlock_long(trans);
			blkdev_issue_discard(ca->disk_sb.bdev,
					     k.k->p.offset * ca->mi.bucket_size,
					     ca->mi.bucket_size,
					     GFP_KERNEL);
			ret = bch2_trans_relock_notrace(trans);
			if (ret)
				goto out;
		}
	}

	SET_BCH_ALLOC_V4_NEED_DISCARD(&a->v, false);
	alloc_data_type_set(&a->v, a->v.data_type);

	ret = bch2_trans_update(trans, &iter, &a->k_i, 0);
	if (ret)
		goto out;
commit:
	ret = bch2_trans_commit(trans, NULL, NULL,
				BCH_WATERMARK_btree|
				BCH_TRANS_COMMIT_no_check_rw|
				BCH_TRANS_COMMIT_no_enospc);
	if (ret)
		goto out;

	if (!fastpath)
		event_inc_trace(c, bucket_discard, buf,
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(orig_k.k)));
	else
		event_inc_trace(c, bucket_discard_fast, buf,
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(orig_k.k)));
out:
fsck_err:
	if (discard_locked)
		discard_in_flight_remove(ca, iter.pos.offset);
	return ret;
}

static void __bch2_dev_do_discards(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct discard_buckets_state s = {};
	struct bpos discard_pos_done = POS_MAX;
	int ret;

	/*
	 * We're doing the commit in bch2_discard_one_bucket instead of using
	 * for_each_btree_key_commit() so that we can increment counters after
	 * successful commit:
	 */
	ret = bch2_trans_run(c,
		for_each_btree_key_max(trans, iter,
				   BTREE_ID_need_discard,
				   POS(ca->dev_idx, 0),
				   POS(ca->dev_idx, U64_MAX), 0, k,
			bch2_discard_one_bucket(trans, ca, &iter, &discard_pos_done, &s, false)));

	if (s.need_journal_commit > dev_buckets_available(ca, BCH_WATERMARK_normal))
		bch2_journal_flush_async(&c->journal, BCH_WATERMARK_reclaim, NULL);

	event_inc_trace(c, bucket_discard_worker, buf, ({
		prt_printf(&buf, "ret %s\ndev %s\n", bch2_err_str(ret), ca->name);
		discard_buckets_state_to_text(&buf, &s);
	}));

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_dev_do_discards);
}

void bch2_do_discards_going_ro(struct bch_fs *c)
{
	for_each_member_device(c, ca)
		if (bch2_dev_get_ioref(c, ca->dev_idx, WRITE, BCH_DEV_WRITE_REF_dev_do_discards))
			__bch2_dev_do_discards(ca);
}

void bch2_do_discards_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, discard_work);
	struct bch_fs *c = ca->fs;

	__bch2_dev_do_discards(ca);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_dev_do_discards(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_discard))
		return;

	if (!bch2_dev_get_ioref(c, ca->dev_idx, WRITE, BCH_DEV_WRITE_REF_dev_do_discards))
		goto put_write_ref;

	if (queue_work(c->write_ref_wq, &ca->discard_work))
		return;

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_dev_do_discards);
put_write_ref:
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_do_discards(struct bch_fs *c)
{
	for_each_member_device(c, ca)
		bch2_dev_do_discards(ca);
}

static int bch2_do_discards_fast_one(struct btree_trans *trans,
				     struct bch_dev *ca,
				     u64 bucket,
				     struct bpos *discard_pos_done,
				     struct discard_buckets_state *s)
{
	CLASS(btree_iter, need_discard_iter)(trans, BTREE_ID_need_discard, POS(ca->dev_idx, bucket), 0);
	struct bkey_s_c discard_k = bkey_try(bch2_btree_iter_peek_slot(&need_discard_iter));

	int ret = 0;
	if (log_fsck_err_on(discard_k.k->type != KEY_TYPE_set,
			    trans, discarding_bucket_not_in_need_discard_btree,
			    "attempting to discard bucket %u:%llu not in need_discard btree",
			    ca->dev_idx, bucket))
		return 0;

	return bch2_discard_one_bucket(trans, ca, &need_discard_iter, discard_pos_done, s, true);
fsck_err:
	return ret;
}

void bch2_do_discards_fast_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, discard_fast_work);
	struct bch_fs *c = ca->fs;
	struct discard_buckets_state s = {};
	struct bpos discard_pos_done = POS_MAX;
	struct btree_trans *trans = bch2_trans_get(c);
	int ret = 0;

	while (1) {
		bool got_bucket = false;
		u64 bucket;

		scoped_guard(mutex, &ca->discard_buckets_in_flight_lock)
			darray_for_each(ca->discard_buckets_in_flight, i) {
				if (i->in_progress)
					continue;

				got_bucket = true;
				bucket = i->bucket;
				i->in_progress = true;
				break;
			}

		if (!got_bucket)
			break;

		ret = lockrestart_do(trans,
			bch2_do_discards_fast_one(trans, ca, bucket, &discard_pos_done, &s));
		bch_err_fn(c, ret);

		discard_in_flight_remove(ca, bucket);

		if (ret)
			break;
	}

	event_inc_trace(c, bucket_discard_fast_worker, buf, ({
		prt_printf(&buf, "ret %s\ndev %s\n", bch2_err_str(ret), ca->name);
		discard_buckets_state_to_text(&buf, &s);
	}));

	bch2_trans_put(trans);
	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_one_bucket_fast);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard_fast);
}

void bch2_discard_one_bucket_fast(struct bch_dev *ca, u64 bucket)
{
	struct bch_fs *c = ca->fs;

	if (discard_in_flight_add(ca, bucket, false))
		return;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_discard_fast))
		return;

	if (!bch2_dev_get_ioref(c, ca->dev_idx, WRITE, BCH_DEV_WRITE_REF_discard_one_bucket_fast))
		goto put_ref;

	if (queue_work(c->write_ref_wq, &ca->discard_fast_work))
		return;

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_one_bucket_fast);
put_ref:
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard_fast);
}

static int invalidate_one_bp(struct btree_trans *trans,
			     struct bch_dev *ca,
			     struct bkey_s_c_backpointer bp,
			     struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_backpointer_get_key(trans, bp, &iter, 0, last_flushed));
	if (!k.k)
		return 0;

	struct bkey_i *n = errptr_try(bch2_bkey_make_mut(trans, &iter, &k,
						BTREE_UPDATE_internal_snapshot_node));

	bch2_bkey_drop_device_noerror(c, bkey_i_to_s(n), ca->dev_idx);

	if (!bch2_bkey_can_read(c, bkey_i_to_s_c(n)))
		bch2_set_bkey_error(c, n, KEY_TYPE_ERROR_device_removed);

	return 0;
}

static int invalidate_one_bucket_by_bps(struct btree_trans *trans,
					struct bch_dev *ca,
					struct bpos bucket,
					u8 gen,
					struct wb_maybe_flush *last_flushed)
{
	struct bpos bp_start	= bucket_pos_to_bp_start(ca,	bucket);
	struct bpos bp_end	= bucket_pos_to_bp_end(ca,	bucket);

	return for_each_btree_key_max_commit(trans, iter, BTREE_ID_backpointers,
				      bp_start, bp_end, 0, k,
				      NULL, NULL,
				      BCH_WATERMARK_btree|
				      BCH_TRANS_COMMIT_no_enospc, ({
		if (k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);

		if (bp.v->bucket_gen != gen)
			continue;

		/* filter out bps with gens that don't match */

		invalidate_one_bp(trans, ca, bp, last_flushed);
	}));
}

noinline_for_stack
static int invalidate_one_bucket(struct btree_trans *trans,
				 struct bch_dev *ca,
				 struct btree_iter *lru_iter,
				 struct bkey_s_c lru_k,
				 struct wb_maybe_flush *last_flushed,
				 s64 *nr_to_invalidate)
{
	struct bch_fs *c = trans->c;
	struct bpos bucket = u64_to_bucket(lru_k.k->p.offset);

	if (!bch2_dev_bucket_exists(c, bucket)) {
		if (ret_fsck_err(trans, lru_entry_to_invalid_bucket,
			     "lru key points to nonexistent device:bucket %llu:%llu",
			     bucket.inode, bucket.offset))
			return bch2_btree_bit_mod_buffered(trans, BTREE_ID_lru, lru_iter->pos, false);
		return 0;
	}

	if (bch2_bucket_is_open_safe(c, bucket.inode, bucket.offset))
		return 0;

	CLASS(btree_iter, alloc_iter)(trans, BTREE_ID_alloc, bucket, BTREE_ITER_cached);
	struct bkey_s_c alloc_k = bkey_try(bch2_btree_iter_peek_slot(&alloc_iter));

	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(alloc_k, &a_convert);

	/* We expect harmless races here due to the btree write buffer: */
	if (lru_pos_time(lru_iter->pos) != alloc_lru_idx_read(*a))
		return 0;

	/*
	 * Impossible since alloc_lru_idx_read() only returns nonzero if the
	 * bucket is supposed to be on the cached bucket LRU (i.e.
	 * BCH_DATA_cached)
	 *
	 * bch2_lru_validate() also disallows lru keys with lru_pos_time() == 0
	 */
	BUG_ON(a->data_type != BCH_DATA_cached);
	BUG_ON(a->dirty_sectors);

	if (!a->cached_sectors) {
		bch2_check_bucket_backpointer_mismatch(trans, ca, bucket.offset,
						       true, last_flushed);
		return 0;
	}

	u8 gen = a->gen;

	struct bkey_buf orig_alloc_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&orig_alloc_k);
	bch2_bkey_buf_reassemble(&orig_alloc_k, alloc_k);

	try(invalidate_one_bucket_by_bps(trans, ca, bucket, gen, last_flushed));

	event_inc_trace(c, bucket_invalidate, buf,
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(orig_alloc_k.k)));

	--*nr_to_invalidate;
	return 0;
}

static struct bkey_s_c next_lru_key(struct btree_trans *trans, struct btree_iter *iter,
				    struct bch_dev *ca, bool *wrapped)
{
	while (true) {
		struct bkey_s_c k = bch2_btree_iter_peek_max(iter, lru_pos(ca->dev_idx, U64_MAX, LRU_TIME_MAX));
		if (k.k || *wrapped)
			return k;

		bch2_btree_iter_set_pos(iter, lru_pos(ca->dev_idx, 0, 0));
		*wrapped = true;
	}
}

static void __bch2_do_invalidates(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	CLASS(btree_trans, trans)(c);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	bch2_btree_write_buffer_tryflush(trans);

	s64 nr_to_invalidate =
		should_invalidate_buckets(ca, bch2_dev_usage_read(ca));
	if (!nr_to_invalidate)
		return;

	bool wrapped = false;

	bch2_trans_begin(trans);
	CLASS(btree_iter, iter)(trans, BTREE_ID_lru,
				lru_pos(ca->dev_idx, 0,
					((bch2_current_io_time(c, READ) + U32_MAX) &
					 LRU_TIME_MAX)), 0);

	while (true) {
		bch2_trans_begin(trans);

		struct bkey_s_c k = next_lru_key(trans, &iter, ca, &wrapped);
		int ret = bkey_err(k);
		if (ret)
			goto restart_err;
		if (!k.k)
			break;

		ret = invalidate_one_bucket(trans, ca, &iter, k, &last_flushed, &nr_to_invalidate);
restart_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;

		if (!nr_to_invalidate) {
			nr_to_invalidate =
				should_invalidate_buckets(ca, bch2_dev_usage_read(ca));
			if (!nr_to_invalidate)
				break;
		}

		wb_maybe_flush_inc(&last_flushed);
		bch2_btree_iter_advance(&iter);
	}
}

void bch2_do_invalidates_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, invalidate_work);
	struct bch_fs *c = ca->fs;

	__bch2_do_invalidates(ca);

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_do_invalidates);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_invalidate);
}

void bch2_dev_do_invalidates(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_invalidate))
		return;

	if (!bch2_dev_get_ioref(c, ca->dev_idx, WRITE, BCH_DEV_WRITE_REF_do_invalidates))
		goto put_ref;

	if (queue_work(c->write_ref_wq, &ca->invalidate_work))
		return;

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_do_invalidates);
put_ref:
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_invalidate);
}

void bch2_do_invalidates(struct bch_fs *c)
{
	for_each_member_device(c, ca)
		bch2_dev_do_invalidates(ca);
}
