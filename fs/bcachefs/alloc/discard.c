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

/* Discard FIFO - per-device, tracks buckets waiting for journal flush before discard */

static inline struct discard_fifo_entry *
discard_fifo_entry(struct bch_dev *ca, u64 journal_seq, bool create)
{
	size_t iter, insert_at = ca->discard_fifo.back;
	struct discard_fifo_entry *e;

	/*
	 * Scan from back: common case (trigger path under journal lock) is
	 * monotonic seqs, so the back entry matches or we append.
	 */
	fifo_for_each_entry_ptr_reverse(e, &ca->discard_fifo, iter) {
		if (e->seq == journal_seq)
			return e;
		if (e->seq < journal_seq)
			break;
		insert_at = iter - 1;
	}

	if (!create ||
	    (fifo_full(&ca->discard_fifo) &&
	     !fifo_grow(&ca->discard_fifo, GFP_KERNEL)))
		return NULL;

	/* Make room and shift entries after insert_at toward back */
	ca->discard_fifo.back++;
	for (size_t j = ca->discard_fifo.back - 1; j > insert_at; j--)
		ca->discard_fifo.data[j & ca->discard_fifo.mask] =
			ca->discard_fifo.data[(j - 1) & ca->discard_fifo.mask];

	e = &ca->discard_fifo.data[insert_at & ca->discard_fifo.mask];
	e->seq = journal_seq;
	darray_init(&e->buckets);
	return e;
}

/*
 * Entry may not exist if push failed due to OOM (degraded mode); the discard
 * worker will repopulate from the btree in that case.
 */
void bch2_discard_bucket_del(struct bch_dev *ca, u64 journal_seq, u64 bucket)
{
	guard(mutex)(&ca->discard_lock);

	if (journal_seq) {
		struct discard_fifo_entry *e = discard_fifo_entry(ca, journal_seq, false);
		u64 *p = e ? darray_find(e->buckets, bucket) : NULL;

		if (p) {
			darray_remove_item(&e->buckets, p);

			while (!fifo_empty(&ca->discard_fifo) &&
			       !(e = &fifo_peek_front(&ca->discard_fifo))->buckets.nr) {
				darray_exit(&e->buckets);
				ca->discard_fifo.front++;
			}
		}
	} else {
		u64 *i = darray_find(ca->discard_fast, bucket);
		if (i)
			darray_remove_item(&ca->discard_fast, i);
	}
}

void bch2_discard_bucket_add(struct bch_dev *ca, u64 journal_seq, u64 bucket)
{
	scoped_guard(mutex, &ca->discard_lock) {
		if (journal_seq) {
			struct discard_fifo_entry *e = discard_fifo_entry(ca, journal_seq, true);

			if (e && darray_find(e->buckets, bucket)) /* race with populate */
				return;

			if (e && !darray_push(&e->buckets, bucket)) {
				/* success */
			} else {
				bch_err(ca->fs, "discard_fifo_push degraded: dev %s bucket %llu seq %llu",
					ca->name, bucket, journal_seq);
				WRITE_ONCE(ca->discard_buckets_degraded, true);
			}
		} else {
			if (darray_find(ca->discard_fast, bucket)) /* race with populate */
				return;
			if (darray_push(&ca->discard_fast, bucket))
				WRITE_ONCE(ca->discard_buckets_degraded, true);
		}
	}

	if (journal_seq) {
		/* Non-fastpath discards are triggered from the journal path -
		 * journal commits make them elegible to be discarded */
	} else {
		struct bch_fs *c = ca->fs;

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
}

static int bch2_dev_discard_buckets_populate(struct btree_trans *trans, struct bch_dev *ca)
{
	return for_each_btree_key_max(trans, iter,
			BTREE_ID_need_discard,
			POS(ca->dev_idx, 0),
			POS(ca->dev_idx, U64_MAX), 0, k, ({
		CLASS(btree_iter, alloc_iter)(trans, BTREE_ID_alloc,
					     k.k->p, BTREE_ITER_cached);
		struct bkey_s_c alloc_k =
			bch2_btree_iter_peek_slot(&alloc_iter);
		int ret = bkey_err(alloc_k);
		if (!ret) {
			struct bch_alloc_v4 a_convert;
			const struct bch_alloc_v4 *a = bch2_alloc_to_v4(alloc_k, &a_convert);

			if (a->data_type == BCH_DATA_need_discard)
				bch2_discard_bucket_add(ca, a->journal_seq_empty, k.k->p.offset);
		}
		ret;
	}));
}

int bch2_discard_buckets_populate(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);

	for_each_member_device(c, ca)
		try(bch2_dev_discard_buckets_populate(trans, ca));

	return 0;
}

static u64 discard_fifo_get(struct bch_dev *ca, struct discard_fifo_cursor *cursor)
{
	u64 threshold = ca->fs->journal.flushed_seq_ondisk;

	guard(mutex)(&ca->discard_lock);

	if (cursor->fifo_idx < ca->discard_fifo.front)
		cursor->bucket_idx = 0;

	for (cursor->fifo_idx = max(cursor->fifo_idx, ca->discard_fifo.front);
	     cursor->fifo_idx < ca->discard_fifo.back;
	     cursor->fifo_idx++, cursor->bucket_idx = 0) {
		struct discard_fifo_entry *e =
			&ca->discard_fifo.data[cursor->fifo_idx & ca->discard_fifo.mask];

		if (e->seq > threshold)
			break;

		if (cursor->bucket_idx < e->buckets.nr)
			return e->buckets.data[cursor->bucket_idx++];
	}

	return 0;
}

static u64 discard_fifo_nr_pending(struct bch_dev *ca)
{
	guard(mutex)(&ca->discard_lock);

	u64 nr = 0;
	size_t iter;
	struct discard_fifo_entry *e;
	fifo_for_each_entry_ptr(e, &ca->discard_fifo, iter)
		nr += e->buckets.nr;
	return nr;
}

void bch2_discard_buckets_to_text(struct printbuf *out, struct bch_dev *ca)
{
	u64 threshold = ca->fs->journal.flushed_seq_ondisk;

	guard(mutex)(&ca->discard_lock);

	prt_printf(out, "discard fifo (threshold %llu):\n", threshold);

	prt_printf(out, "fastpath: %zu\n", ca->discard_fast.nr);

	size_t iter;
	struct discard_fifo_entry *e;
	fifo_for_each_entry_ptr(e, &ca->discard_fifo, iter)
		prt_printf(out, "  seq %llu:\t%zu buckets%s\n",
			   e->seq, e->buckets.nr,
			   e->seq <= threshold ? "" : " (waiting)");

	if (fifo_empty(&ca->discard_fifo))
		prt_printf(out, "  (empty)\n");

	if (READ_ONCE(ca->discard_buckets_degraded))
		prt_printf(out, "  DEGRADED\n");
}

struct discard_buckets_state {
	u64		seen;
	u64		open;
	u64		need_journal_commit;
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
	prt_printf(out, "bad_data_type:\t%llu\n",	s->bad_data_type);
	prt_printf(out, "already_discarding:\t%llu\n",	s->already_discarding);
	prt_printf(out, "discarded:\t%llu\n",		s->discarded);
}

static int bch2_discard_one_bucket(struct btree_trans *trans,
				   struct bch_dev *ca,
				   struct bpos pos,
				   struct bpos *discard_pos_done,
				   struct discard_buckets_state *s,
				   bool fastpath)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	s->seen++;

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
		goto out;
	}

	if (a->v.data_type != BCH_DATA_need_discard) {
		/* expected race */
		s->bad_data_type++;
		goto out;
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

	ret = bch2_trans_commit(trans, NULL, NULL,
				BCH_WATERMARK_reclaim|
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
	return ret;
}

static void __bch2_dev_do_discards(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct discard_buckets_state s = {};
	int ret = 0;

	CLASS(btree_trans, trans)(c);

	struct discard_fifo_cursor cursor = {};
	u64 bucket;
again:
	while ((bucket = discard_fifo_get(ca, &cursor))) {
		struct bpos discard_pos_done = POS_MAX;

		ret = lockrestart_do(trans,
			bch2_discard_one_bucket(trans, ca, POS(ca->dev_idx, bucket),
						&discard_pos_done, &s, false));
		if (ret)
			break;
	}

	/* FIFO lost entries due to OOM: repopulate from btree and drain again.
	 * Clear flag first so concurrent trigger failures re-set it. */
	if (!ret && READ_ONCE(ca->discard_buckets_degraded)) {
		WRITE_ONCE(ca->discard_buckets_degraded, false);
		bch2_dev_discard_buckets_populate(trans, ca);
		cursor = (struct discard_fifo_cursor){};
		goto again;
	}

	u64 nr_pending = discard_fifo_nr_pending(ca);
	if (nr_pending > dev_buckets_available(ca, BCH_WATERMARK_normal))
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

void bch2_do_discards_fast_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, discard_fast_work);
	struct bch_fs *c = ca->fs;
	struct discard_buckets_state s = {};
	int ret = 0;

	CLASS(btree_trans, trans)(c);

	size_t cursor = 0;
	while (1) {
		u64 bucket;

		scoped_guard(mutex, &ca->discard_lock) {
			if (cursor >= ca->discard_fast.nr)
				bucket = 0;
			else
				bucket = ca->discard_fast.data[cursor];
		}

		if (!bucket)
			break;

		struct bpos discard_pos_done = POS_MAX;

		ret = lockrestart_do(trans,
			bch2_discard_one_bucket(trans, ca, POS(ca->dev_idx, bucket),
						&discard_pos_done, &s, true));
		if (ret)
			break;

		/*
		 * If the discard succeeded, the alloc trigger removed
		 * this bucket from the darray — cursor now points to
		 * the next entry. If it was skipped (open, wrong
		 * data_type), it's still there — advance past it.
		 */
		scoped_guard(mutex, &ca->discard_lock) {
			if (cursor < ca->discard_fast.nr &&
			    ca->discard_fast.data[cursor] == bucket)
				cursor++;
		}
	}

	event_inc_trace(c, bucket_discard_fast_worker, buf, ({
		prt_printf(&buf, "ret %s\ndev %s\n", bch2_err_str(ret), ca->name);
		discard_buckets_state_to_text(&buf, &s);
	}));

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_one_bucket_fast);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard_fast);
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
	struct discard_fifo_entry entry;

	while (fifo_pop(&ca->discard_fifo, entry))
		darray_exit(&entry.buckets);
	free_fifo(&ca->discard_fifo);
	darray_exit(&ca->discard_fast);
}

int bch2_dev_discards_init(struct bch_dev *ca)
{
	INIT_WORK(&ca->invalidate_work, bch2_do_invalidates_work);
	INIT_WORK(&ca->discard_work, bch2_do_discards_work);
	INIT_WORK(&ca->discard_fast_work, bch2_do_discards_fast_work);
	mutex_init(&ca->discard_lock);

	if (!init_fifo(&ca->discard_fifo, 1024, GFP_KERNEL))
		return -ENOMEM;
	return 0;
}
