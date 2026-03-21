// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "init/fs.h"

#include "journal/journal.h"

struct discard_buckets_state {
	u64		seen;
	u64		open;
	u64		need_journal_commit;
	u64		bad_data_type;
	u64		discarded;
	u64		committed;
};

static void discard_buckets_state_to_text(struct printbuf *out,
					  struct discard_buckets_state *s)
{
	printbuf_tabstop_push(out, 20);
	prt_printf(out, "seen:\t%llu\n",		s->seen);
	prt_printf(out, "open:\t%llu\n",		s->open);
	prt_printf(out, "need_journal_commit:\t%llu\n",	s->need_journal_commit);
	prt_printf(out, "bad_data_type:\t%llu\n",	s->bad_data_type);
	prt_printf(out, "discarded:\t%llu\n",		s->discarded);
	prt_printf(out, "committed:\t%llu\n",		s->committed);
}

static int __bch2_discard_one_bucket(struct btree_trans *trans,
				     struct bch_dev *ca,
				     struct bpos pos,
				     struct bpos *discard_pos_done,
				     struct discard_buckets_state *s,
				     bool fastpath)
{
	struct bch_fs *c = trans->c;

	if (bch2_bucket_is_open_safe(c, pos.inode, pos.offset)) {
		s->open++;
		return 0;
	}

	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, pos, BTREE_ITER_cached);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	struct bkey_buf orig_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&orig_k);
	bch2_bkey_buf_reassemble(&orig_k, k);

	struct bkey_i_alloc_v4 *a = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	if (a->v.journal_seq_empty > c->journal.flushed_seq_ondisk) {
		s->need_journal_commit++;
		return 0;
	}

	if (a->v.data_type != BCH_DATA_need_discard) {
		/* expected race - btree write buffer */
		s->bad_data_type++;
		return 0;
	}

	if (!bkey_eq(*discard_pos_done, pos)) {
		s->discarded++;
		*discard_pos_done = pos;

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
			try(bch2_trans_relock_notrace(trans));
		}
	}

	SET_BCH_ALLOC_V4_NEED_DISCARD(&a->v, false);
	alloc_data_type_set(&a->v, a->v.data_type);

	try(bch2_trans_update(trans, &iter, &a->k_i, 0));

	try(bch2_trans_commit(trans, NULL, NULL,
			      BCH_WATERMARK_reclaim|
			      BCH_TRANS_COMMIT_no_check_rw|
			      BCH_TRANS_COMMIT_no_enospc));

	if (!fastpath)
		event_inc_trace(c, bucket_discard, buf,
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(orig_k.k)));
	else
		event_inc_trace(c, bucket_discard_fast, buf,
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(orig_k.k)));
	s->committed++;

	return 0;
}

static int bch2_discard_one_bucket(struct btree_trans *trans,
				   struct bpos bucket,
				   struct bpos *discard_pos_done,
				   struct discard_buckets_state *s,
				   bool fastpath)
{
	struct bch_dev *ca = bch2_dev_get_ioref(trans->c, bucket.inode, WRITE, BCH_DEV_WRITE_REF_discard_bucket);
	if (!ca)
		return 0;

	int ret = __bch2_discard_one_bucket(trans, ca, bucket, discard_pos_done, s, fastpath);

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_bucket);
	return ret;
}

struct discard_sectors_to_release {
	u64		buffer;
	u64		pending_need_flush;
	u64		pending_need_rewind_advance;
	u64		pending_total;
	u64		free;
	u64		reserve;
	u64		buffer_clamped;
	s64		release;
	bool		flush_journal;
};

static struct discard_sectors_to_release discard_sectors_to_release(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;

	struct discard_sectors_to_release s = {
		.buffer	= c->capacity.capacity *
			c->opts.journal_rewind_discard_buffer_percent / 100,
	};

	for_each_btree_key(trans, iter,
			BTREE_ID_need_discard, POS_MIN, 0, k, ({
		u64 journal_seq = k.k->p.inode;
		struct bpos bucket = u64_to_bucket(k.k->p.offset);

		guard(rcu)();
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, bucket.inode);
		if (ca) {
			u64 sectors = ca->mi.bucket_size;

			if (journal_seq >= c->journal.rewind_seq_ondisk ||
			    journal_seq > c->journal.flushed_seq_ondisk)
				s.pending_need_flush += sectors;
			if (journal_seq >= c->journal.rewind_seq)
				s.pending_need_rewind_advance += sectors;
			s.pending_total += sectors;
		}
		0;
	}));

	for_each_rw_member(c, ca, BCH_DEV_WRITE_REF_discard_sectors_to_release) {
		s.free += bch2_dev_usage_read(ca).buckets[BCH_DATA_free] * ca->mi.bucket_size;
		s.reserve += bch2_dev_buckets_reserved(ca, BCH_WATERMARK_stripe) * ca->mi.bucket_size;
	}

	s.buffer_clamped	= min(s.buffer, max(0, (s64) (s.free - s.reserve * 4)));
	s.release		= max(0, (s64) (s.pending_need_rewind_advance - s.buffer_clamped));
	s.flush_journal		= s.release && (s.pending_total - s.pending_need_flush) + s.free < s.buffer / 2;

	return s;
}

static void bch2_do_discards(struct bch_fs *c)
{
	int ret = 0;
	bool again;

	CLASS(btree_trans, trans)(c);

	do {
		again = false;

		struct discard_buckets_state s = {};
		struct bpos discard_pos_done = POS_MAX;

		/*
		 * Iterate need_discard btree (sorted by journal_seq).
		 * Stop when we hit a seq beyond rewind_seq_ondisk.
		 */
		ret = for_each_btree_key(trans, iter,
				BTREE_ID_need_discard, POS_MIN, 0, k, ({
			u64 journal_seq = k.k->p.inode;
			struct bpos bucket = u64_to_bucket(k.k->p.offset);
			int _ret = 0;

			if (journal_seq >= c->journal.rewind_seq_ondisk)
				break;

			_ret = bch2_discard_one_bucket(trans, bucket,
						       &discard_pos_done,
						       &s, false);

			s.seen += !_ret;
			_ret;
		}));

		/*
		 * Rewind buffer policy: advance rewind_seq when free space
		 * is tight, releasing more buckets for discard.
		 */
		struct discard_sectors_to_release r = discard_sectors_to_release(trans);

		if (!ret && r.release) {
			u64 new_rewind_seq = 0;
			s64 remaining = r.release;

			for_each_btree_key(trans, iter,
					BTREE_ID_need_discard, POS_MIN, 0, k, ({
				u64 journal_seq = k.k->p.inode;
				struct bpos bucket = u64_to_bucket(k.k->p.offset);

				if (remaining <= 0)
					break;

				if (journal_seq >= c->journal.rewind_seq) {
					CLASS(bch2_dev_tryget_noerror, ca)(c, bucket.inode);
					if (ca) {
						new_rewind_seq = max(new_rewind_seq, journal_seq + 1);
						remaining -= ca->mi.bucket_size;
					}
				}
				0;
			}));

			if (new_rewind_seq)
				bch2_journal_advance_rewind_seq(&c->journal, new_rewind_seq);
		}

		if (!ret && r.flush_journal) {
			bch2_trans_unlock_long(trans);
			u64 start_time = local_clock();
			ret = bch2_journal_flush(&c->journal);
			bch2_time_stats_update(&c->times[BCH_TIME_blocked_discard_journal_flush],
					       start_time);
			again = true;
		}

		/*
		 * If the FIFO is empty but we need free buckets, flush the
		 * write buffer — need_discard keys may be buffered from
		 * the alloc trigger's atomic section:
		 */
		if (!ret && !s.seen && r.release) {
			bch2_btree_write_buffer_flush_sync(trans);
			again = true;
		}

		event_inc_trace(c, bucket_discard_worker, buf, ({
			printbuf_tabstop_push(&buf, 24);
			prt_printf(&buf, "ret %s\n", bch2_err_str(ret));

			prt_printf(&buf, "Discard buckets state:\n");
			scoped_guard(printbuf_indent, &buf)
				discard_buckets_state_to_text(&buf, &s);

			prt_printf(&buf, "Discard buffer state\n");
			scoped_guard(printbuf_indent, &buf) {
				prt_printf(&buf, "release:\t%llu\n",		r.release);
				prt_printf(&buf, "flush_journal:\t%u\n",	r.flush_journal);
			}
		}));
	} while (!ret && again);
}

void bch2_do_discards_going_ro(struct bch_fs *c)
{
	bch2_do_discards(c);
}

void bch2_do_discards_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, allocator.discard_work);

	bch2_do_discards(c);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_do_discards_async(struct bch_fs *c)
{
	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_discard))
		return;

	if (queue_work(c->write_ref_wq, &c->allocator.discard_work))
		return;

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_do_discards_fast_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, discard_fast_work);
	struct bch_fs *c = ca->fs;
	struct discard_buckets_state s = {};
	struct bpos discard_pos_done = POS_MAX;
	int ret = 0;

	CLASS(btree_trans, trans)(c);

	while (1) {
		u64 bucket;

		scoped_guard(mutex, &c->allocator.discard_lock) {
			bucket = ca->discard_fast.nr
				? darray_pop(&ca->discard_fast)
				: 0;
		}

		if (!bucket)
			break;


		s.seen++;

		ret = lockrestart_do(trans,
			bch2_discard_one_bucket(trans, POS(ca->dev_idx, bucket),
						&discard_pos_done, &s, true));
		if (ret)
			break;
	}

	event_inc_trace(c, bucket_discard_fast_worker, buf, ({
		prt_printf(&buf, "ret %s\ndev %s\n", bch2_err_str(ret), ca->name);
		discard_buckets_state_to_text(&buf, &s);
	}));

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_one_bucket_fast);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard_fast);
}

void bch2_fast_discard_bucket_add(struct bch_dev *ca, u64 bucket)
{
	struct bch_fs *c = ca->fs;

	scoped_guard(mutex, &c->allocator.discard_lock)
		if (darray_push(&ca->discard_fast, bucket))
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

void bch2_fast_discards_to_text(struct printbuf *out, struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	guard(mutex)(&c->allocator.discard_lock);

	prt_printf(out, "fastpath: %zu\n", ca->discard_fast.nr);
}

/* Invalidates */

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

void bch2_dev_discards_exit(struct bch_dev *ca)
{
	darray_exit(&ca->discard_fast);
}

int bch2_dev_discards_init(struct bch_dev *ca)
{
	INIT_WORK(&ca->invalidate_work, bch2_do_invalidates_work);
	INIT_WORK(&ca->discard_fast_work, bch2_do_discards_fast_work);
	return 0;
}

void bch2_fs_discards_init_early(struct bch_fs *c)
{
	INIT_WORK(&c->allocator.discard_work, bch2_do_discards_work);
}
