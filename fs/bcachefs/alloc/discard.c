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

static bool discard_opt_enabled_idx(struct bch_fs *c, unsigned dev)
{
	guard(rcu)();
	struct bch_dev *ca = bch2_dev_rcu_noerror(c, dev);
	BUG_ON(!ca);
	return ca && bch2_discard_opt_enabled(c, ca);
}

static u32 dev_bucket_size(struct bch_fs *c, unsigned dev)
{
	guard(rcu)();
	struct bch_dev *ca = bch2_dev_rcu_noerror(c, dev);
	return ca ? ca->mi.bucket_size : 0;
}

static bool dev_bucket_nouse(struct bch_fs *c, struct bpos bucket)
{
	guard(rcu)();
	struct bch_dev *ca = bch2_dev_rcu_noerror(c, bucket.inode);
	return ca ? bch2_bucket_nouse(ca, bucket.offset) : true;
}

#define DEV_IN_FLIGHT_MAX		4

static void __discard_state_to_text(struct printbuf *out, struct discard_state *s)
{
	printbuf_tabstop_push(out, 32);
	prt_printf(out, "seen:\t%llu\n",		s->seen);
	prt_printf(out, "not_rw:\t%llu\n",		s->not_rw);
	prt_printf(out, "eexist:\t%llu\n",		s->eexist);
	prt_printf(out, "eagain:\t%llu\n",		s->eagain);
	prt_printf(out, "open:\t%llu\n",		s->open);
	prt_printf(out, "need_journal_commit:\t%llu\n",	s->need_journal_commit);
	prt_printf(out, "need_rewind_advance:\t%llu\n",	s->need_rewind_advance);
	prt_printf(out, "bad_data_type:\t%llu\n",	s->bad_data_type);
	prt_printf(out, "discarded:\t%llu\n",		s->discarded);
	prt_printf(out, "committed:\t%llu\n",		s->committed);
}

void bch2_discards_to_text(struct printbuf *out, struct bch_fs *c, struct discard_state *s)
{
	__discard_state_to_text(out, s);

	prt_printf(out, "Discard release:\n");
	scoped_guard(printbuf_indent, out) {
		prt_printf(out, "buffer:\t%llu\n",		s->r.buffer);
		prt_printf(out, "pending_need_flush:\t%llu\n",	s->r.pending_need_flush);
		prt_printf(out, "pending_need_rewind_advance:\t%llu\n", s->r.pending_need_rewind_advance);
		prt_printf(out, "pending_total:\t%llu\n",	s->r.pending_total);
		prt_printf(out, "free:\t%llu\n",		s->r.free);
		prt_printf(out, "reserve:\t%llu\n",		s->r.reserve);
		prt_printf(out, "buffer_clamped:\t%llu\n",	s->r.buffer_clamped);
		prt_printf(out, "release:\t%lli\n",		s->r.release);
		prt_printf(out, "flush_journal:\t%u\n",		s->r.flush_journal);
		prt_printf(out, "flush_wb:\t%u\n",		s->r.flush_wb);
	}

	struct journal *j = &c->journal;
	prt_printf(out, "journal seq:\t%llu\n",			journal_cur_seq(j));
	prt_printf(out, "journal flushed seq:\t%llu -> %llu\n",	j->flushing_seq, j->flushed_seq_ondisk);
	prt_printf(out, "journal rewind seq:\t%llu -> %llu\n",	j->rewind_seq, j->rewind_seq_ondisk);
}

struct discard_bio {
	struct bch_dev			*ca;
	u64				dev_bucket;
	struct bio			bio;
};

static void discard_endio(struct bio *_bio)
{
	struct discard_bio *bio = container_of(_bio, struct discard_bio, bio);
	struct bch_dev *ca = bio->ca;
	struct bch_fs_discards *d = &ca->fs->discards;
	struct bpos bucket = u64_to_bucket(bio->dev_bucket);

	scoped_guard(spinlock_irqsave, &d->lock) {
		darray_find_p(d->in_flight, i,
			      i->dev_bucket == bio->dev_bucket)->complete = true;

		BUG_ON(!d->refs[bucket.inode]);
		BUG_ON(!d->ref);

		--d->refs[bucket.inode];
		if (!--d->ref)
			closure_wake_up(&d->wait);
	}

	bio_put(&bio->bio);
}

static int discard_in_flight_add(struct bch_fs *c, struct bpos bucket,
				 bool fastpath, bool check)
{
	u64 dev_bucket = bucket_to_u64(bucket);
	struct bch_fs_discards *d = &c->discards;
	guard(spinlock_irq)(&d->lock);

	if (darray_find_p(d->in_flight, i, i->dev_bucket == dev_bucket))
		return -EEXIST;

	if (d->refs[bucket.inode] >= DEV_IN_FLIGHT_MAX + fastpath)
		return bch_err_throw(c, max_discards_in_flight);

	if (!check) {
		try(darray_push_gfp(&d->in_flight,
				    ((discard_in_flight) { .dev_bucket = dev_bucket } ),
				    GFP_NOWAIT));

		d->refs[bucket.inode]++;
		d->ref++;
	}

	return 0;
}

static void discard_submit(struct bch_dev *ca, struct bpos bucket, bool fastpath)
{
	struct bch_fs *c = ca->fs;

	struct discard_bio *bio =
		container_of(bio_alloc_bioset(ca->disk_sb.bdev, 0, REQ_OP_DISCARD, GFP_NOIO,
					      &c->discards.bioset),
			     struct discard_bio, bio);

	bio->ca				= ca;
	bio->dev_bucket			= bucket_to_u64(bucket);
	bio->bio.bi_iter.bi_sector	= bucket_to_sector(ca, bucket.offset);
	bio->bio.bi_iter.bi_size	= ca->mi.bucket_size << 9;
	bio->bio.bi_end_io		= discard_endio;

	submit_bio(&bio->bio);
}

static int __discard_mark_free(struct btree_trans *trans,
			       struct discard_state *s,
			       bool fastpath,
			       struct btree_iter *iter,
			       struct bkey_i_alloc_v4 *a)
{
	struct bch_fs *c = trans->c;

	if (a->v.data_type != BCH_DATA_need_discard) {
		struct bch_fs *c = trans->c;
		CLASS(bch_log_msg, msg)(c);
		prt_printf(&msg.m, "Discarded bucket that is no longer BCH_DATA_need_discard!\n");
		bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&a->k_i));

		bch2_fs_emergency_read_only(c, &msg.m);
		return bch_err_throw(c, emergency_ro);
	}

	struct bkey_buf orig_k __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&orig_k);
	bch2_bkey_buf_copy(&orig_k, &a->k_i);

	SET_BCH_ALLOC_V4_NEED_DISCARD(&a->v, false);
	alloc_data_type_set(&a->v, a->v.data_type);

	try(bch2_trans_update(trans, iter, &a->k_i, BTREE_TRIGGER_is_discard));

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
	s->committed += dev_bucket_size(c, iter->k.p.inode);

	return 0;
}

static int discard_mark_free(struct btree_trans *trans,
			     struct bpos bucket,
			     struct discard_state *s,
			     bool fastpath)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, bucket, BTREE_ITER_cached|BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));
	struct bkey_i_alloc_v4 *a = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	return __discard_mark_free(trans, s, fastpath, &iter, a);
}

static u64 next_to_complete(struct bch_fs_discards *d, size_t *iter)
{
	guard(spinlock_irq)(&d->lock);
	darray_for_each_from(d->in_flight, i, d->in_flight.data + *iter)
		if (i->complete && !i->marking_free) {
			*iter = i - d->in_flight.data;
			i->marking_free = true;
			return i->dev_bucket;
		}

	return 0;
}

static bool discards_pending(struct bch_fs_discards *d, bool fastpath, bool all)
{
	guard(spinlock_irq)(&d->lock);
	if (all)
		return d->ref != 0;
	for (unsigned i = 0; i < ARRAY_SIZE(d->refs); i++)
		if (d->refs[i] >= DEV_IN_FLIGHT_MAX + fastpath)
			return true;
	return false;
}

static int bch2_discards_complete(struct btree_trans *trans,
				  struct discard_state *s,
				  bool fastpath, bool all)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_discards *d = &c->discards;
	int ret = 0;

	trans_wait_event(trans, &d->wait, !discards_pending(d, fastpath, all));

	u64 dev_bucket = 0;
	size_t iter = 0;

	while ((dev_bucket = next_to_complete(d, &iter))) {
		struct bpos bucket = u64_to_bucket(dev_bucket);
		struct bch_dev *ca = bch2_dev_have_ref(c, bucket.inode);

		ret = lockrestart_do(trans, discard_mark_free(trans, bucket, s, fastpath)) ?: ret;

		scoped_guard(spinlock_irq, &d->lock) {
			discard_in_flight *i = d->in_flight.data + iter;

			if (i > &darray_last(d->in_flight) || i->dev_bucket != dev_bucket)
				i = darray_find_p(d->in_flight, i, i->dev_bucket == dev_bucket);
			BUG_ON(!i->marking_free);
			darray_remove_item(&d->in_flight, i);
		}

		enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_bucket);
	}

	return ret;
}

static int bch2_discard_one_bucket(struct btree_trans *trans,
				   struct bpos bucket,
				   u32 bucket_size,
				   struct discard_state *s,
				   bool fastpath)
{
	struct bch_fs *c = trans->c;

	if (unlikely(dev_bucket_nouse(c, bucket)))
		return 0;

	int ret = discard_in_flight_add(c, bucket, fastpath, true);
	if (ret) {
		if (ret == -EEXIST) {
			s->eexist += bucket_size;
			ret = 0;
		} else {
			s->eagain += bucket_size;
		}

		return ret;
	}

	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, bucket, BTREE_ITER_cached);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	struct bkey_i_alloc_v4 *a = errptr_try(bch2_alloc_to_v4_mut(trans, k));

	if (a->v.journal_seq_empty > c->journal.flushed_seq_ondisk) {
		s->need_journal_commit += bucket_size;
		return 0;
	}

	if (a->v.journal_seq_empty >= c->journal.rewind_seq_ondisk) {
		s->need_rewind_advance += bucket_size;
		return 0;
	}

	if (a->v.data_type != BCH_DATA_need_discard) {
		/* expected race - btree write buffer */
		s->bad_data_type += bucket_size;
		return 0;
	}

	/* Must check after we've looked at and locked the alloc key: */
	if (bch2_bucket_is_open_safe(c, bucket.inode, bucket.offset)) {
		s->open += bucket_size;
		return 0;
	}

	if (discard_opt_enabled_idx(c, bucket.inode) && !c->opts.nochanges) {
		struct bch_dev *ca = bch2_dev_get_ioref(trans->c, bucket.inode, WRITE,
							BCH_DEV_WRITE_REF_discard_bucket);
		if (!ca) {
			s->not_rw += bucket_size;
			return 0;
		}

		ret = discard_in_flight_add(c, bucket, fastpath, false);
		if (!ret) {
			bch2_trans_unlock(trans);
			discard_submit(ca, bucket, fastpath);
			s->discarded += bucket_size;
			return 0;
		}

		enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_bucket);

		if (ret == -EEXIST) {
			s->eexist += bucket_size;
			ret = 0;
		} else {
			s->eagain += bucket_size;
		}
		return ret;
	} else {
		return __discard_mark_free(trans, s, fastpath, &iter, a);
	}
}

static void calculate_discard_sectors_to_release(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct discard_state *s = &c->discards.s;

	/*
	 * Compute the rewind-advance budget per-device: a single device
	 * starving for free buckets needs to drive rewind advance by its own
	 * pressure, not by the fs-wide aggregate. With an fs-wide buffer, a
	 * comfortable fs total can mask one device's need_discard pile-up
	 * indefinitely, leaving its discard worker iterating but finding no
	 * journal-eligible candidates.
	 */
	scoped_guard(rcu)
		for_each_rw_member_rcu(c, ca) {
			struct bch_dev_usage u	= bch2_dev_usage_read(ca);
			u64 sectors		= ca->mi.bucket_size;

			u64 dev_pending		= sectors * u.buckets[BCH_DATA_need_discard];
			u64 dev_free		= sectors * u.buckets[BCH_DATA_free];
			u64 dev_reserve		= sectors * bch2_dev_buckets_reserved(ca, BCH_WATERMARK_stripe);
			u64 dev_capacity	= sectors * ca->mi.nbuckets;
			u64 dev_buffer		= dev_capacity * c->opts.journal_rewind_discard_buffer_percent / 100;
			s64 dev_buffer_clamped	= min_t(s64, dev_buffer,
							max_t(s64, 0,
							      (s64) dev_free - (s64) dev_reserve * 4));
			s64 dev_release		= (s64) dev_pending - dev_buffer_clamped;

			s->r.pending_total	+= dev_pending;
			s->r.free		+= dev_free;
			s->r.reserve		+= dev_reserve;
			s->r.buffer		+= dev_buffer;
			s->r.buffer_clamped	+= dev_buffer_clamped;
			if (dev_release > 0)
				s->r.release	+= dev_release;
		}

	u64 seen = s->seen - s->bad_data_type - s->not_rw;

	s->r.flush_wb		= seen * 2 <= s->r.pending_total && s->r.free < s->r.reserve * 2;

	if (s->r.release <= 0)
		return;

	s64 release = s->r.release;

	for_each_btree_key(trans, iter, BTREE_ID_need_discard, c->discards.s.pos, 0, k, ({
		u64 journal_seq		= k.k->p.inode;
		struct bpos bucket	= u64_to_bucket(k.k->p.offset);
		u32 bucket_size		= dev_bucket_size(c, bucket.inode);

		if (bch2_bucket_is_open_safe(c, bucket.inode, bucket.offset))
			continue;

		s->r.new_rewind_seq = max(s->r.new_rewind_seq, journal_seq + 1);

		if (s->r.free < s->r.reserve * 2 &&
		    c->journal.flushed_seq_ondisk < journal_cur_seq(&c->journal))
			s->r.flush_journal = true;

		release -= bucket_size;
		if (release <= 0)
			break;

		0;
	}));

	if (s->r.free < s->r.reserve * 2 &&
	    s->r.new_rewind_seq > c->journal.rewind_seq)
		s->r.flush_journal = true;
}

static void bch2_do_discards(struct bch_fs *c)
{
	int ret = 0;
	bool again;
	unsigned flushed_wb = 0;

	CLASS(btree_trans, trans)(c);

	do {
		again = false;

		struct discard_state *s = &c->discards.s;
		memset(s, 0, sizeof(*s));

		/*
		 * Iterate need_discard btree (sorted by journal_seq).
		 * Stop when we hit a seq beyond rewind_seq_ondisk.
		 */
		ret = for_each_btree_key(trans, iter,
				BTREE_ID_need_discard, POS_MIN, 0, k, ({
			u64 journal_seq		= k.k->p.inode;
			struct bpos bucket	= u64_to_bucket(k.k->p.offset);
			u32 bucket_size		= dev_bucket_size(c, bucket.inode);

			if (journal_seq >= min(c->journal.rewind_seq_ondisk,
					       c->journal.flushed_seq_ondisk + 1))
				break;

			if (!bpos_eq(s->pos, iter.pos))
				s->seen += bucket_size;
			s->pos = iter.pos;

			int ret2 = bch2_discard_one_bucket(trans,
						bucket, bucket_size,
						s, false);
			if (ret2 == -BCH_ERR_max_discards_in_flight)
				ret2 = bch2_discards_complete(trans, s, false, false) ?:
				btree_trans_restart(trans, BCH_ERR_transaction_restart_nested);
			ret2;
		}));

		ret = bch2_discards_complete(trans, s, false, true) ?: ret;

		/*
		 * Rewind buffer policy: advance rewind_seq when free space
		 * is tight, releasing more buckets for discard.
		 */
		calculate_discard_sectors_to_release(trans);

		if (!ret && s->r.new_rewind_seq)
			bch2_journal_advance_rewind_seq(&c->journal, s->r.new_rewind_seq);

		if (!ret && s->r.flush_journal) {
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
		if (!ret && s->r.flush_wb && flushed_wb < 2) {
			ret = bch2_btree_write_buffer_flush_sync(trans);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
				ret = 0;
			again = true;
			flushed_wb++;
		}

		event_inc_trace(c, bucket_discard_worker, buf, ({
			prt_printf(&buf, "ret %s\n", bch2_err_str(ret));
			bch2_discards_to_text(&buf, c, s);
		}));
	} while (!ret && again);

	if (!bch2_err_matches(ret, EROFS))
		bch_err_fn(c, ret);
}

void bch2_do_discards_going_ro(struct bch_fs *c)
{
	bool must_discard = false;

	scoped_guard(rcu)
		for_each_rw_member_rcu(c, ca) {
			struct bch_dev_usage u	= bch2_dev_usage_read(ca);

			if (u.buckets[BCH_DATA_free] <
			    bch2_dev_buckets_reserved(ca, BCH_WATERMARK_stripe) * 4 &&
			    u.buckets[BCH_DATA_need_discard])
				must_discard = true;
		}

	if (must_discard)
		bch2_do_discards(c);
}

void bch2_do_discards_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, discards.work);

	bch2_do_discards(c);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_do_discards_async(struct bch_fs *c)
{
	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_discard))
		return;

	if (queue_work(c->write_ref_wq, &c->discards.work))
		return;

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard);
}

void bch2_do_discards_fast_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, discard_fast_work);
	struct bch_fs *c = ca->fs;
	struct discard_state s = {};
	int ret = 0;

	{
		CLASS(btree_trans, trans)(c);

		while (1) {
			u64 bucket;

			scoped_guard(mutex, &ca->discard_fast_lock) {
				bucket = ca->discard_fast.nr
					? darray_pop(&ca->discard_fast)
					: 0;
			}

			if (!bucket)
				break;

			do {
				ret = lockrestart_do(trans,
					bch2_discard_one_bucket(trans, POS(ca->dev_idx, bucket),
								ca->mi.bucket_size, &s, true));
				if (ret == -BCH_ERR_max_discards_in_flight)
					ret = bch2_discards_complete(trans, &s, true, false);
			} while (ret == -BCH_ERR_max_discards_in_flight);

			ret = bch2_discards_complete(trans, &s, false, true) ?: ret;
			if (ret)
				break;
		}

		event_inc_trace(c, bucket_discard_fast_worker, buf, ({
			prt_printf(&buf, "dev %s: ret %s\n", ca->name, bch2_err_str(ret));
			__discard_state_to_text(&buf, &s);
		}));
	}

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_discard_one_bucket_fast);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_discard_fast);
}

void bch2_fast_discard_bucket_add(struct bch_dev *ca, u64 bucket)
{
	struct bch_fs *c = ca->fs;

	scoped_guard(mutex, &ca->discard_fast_lock)
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
	prt_printf(out, "%zu\n", ca->discard_fast.nr);
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
	mutex_init(&ca->discard_fast_lock);
	return 0;
}

void bch2_fs_discards_exit(struct bch_fs *c)
{
	darray_exit(&c->discards.in_flight);
	bioset_exit(&c->discards.bioset);
}

int bch2_fs_discards_init(struct bch_fs *c)
{
	darray_make_room(&c->discards.in_flight, 256);

	try(bioset_init(&c->discards.bioset, 4, offsetof(struct discard_bio, bio), 0));
	return 0;
}

void bch2_fs_discards_init_early(struct bch_fs *c)
{
	INIT_WORK(&c->discards.work, bch2_do_discards_work);
	spin_lock_init(&c->discards.lock);
}
