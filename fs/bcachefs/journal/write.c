// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/replicas.h"

#include "btree/interior.h"
#include "btree/write_buffer.h"

#include "data/checksum.h"

#include "init/error.h"
#include "init/fs.h"

#include "journal/journal.h"
#include "journal/read.h"
#include "journal/reclaim.h"
#include "journal/write.h"

#include "sb/clean.h"

#include <linux/ioprio.h>

static void journal_advance_devs_to_next_bucket(struct journal *j,
						struct dev_alloc_list *devs,
						unsigned sectors, __le64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	guard(rcu)();
	darray_for_each(*devs, i) {
		struct bch_dev *ca = rcu_dereference(c->devs[*i]);
		if (!ca)
			continue;

		struct journal_device *ja = &ca->journal;

		if (sectors > ja->sectors_free &&
		    sectors <= ca->mi.bucket_size &&
		    bch2_journal_dev_buckets_available(j, ja,
					journal_space_discarded)) {
			ja->cur_idx = (ja->cur_idx + 1) % ja->nr;
			ja->sectors_free = ca->mi.bucket_size;

			/*
			 * ja->bucket_seq[ja->cur_idx] must always have
			 * something sensible:
			 */
			ja->bucket_seq[ja->cur_idx] = le64_to_cpu(seq);
		}
	}
}

static void __journal_write_alloc(struct journal *j,
				  struct journal_buf *w,
				  struct dev_alloc_list *devs,
				  unsigned sectors,
				  unsigned *replicas,
				  unsigned replicas_want)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	darray_for_each(*devs, i) {
		struct bch_dev *ca = bch2_dev_get_ioref(c, *i, WRITE,
					BCH_DEV_WRITE_REF_journal_write);
		if (!ca)
			continue;

		struct journal_device *ja = &ca->journal;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (!ja->nr ||
		    bch2_bkey_has_device_c(bkey_i_to_s_c(&w->key), ca->dev_idx) ||
		    sectors > ja->sectors_free) {
			enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
			continue;
		}

		bch2_dev_stripe_increment(ca, &j->wp.stripe);

		bch2_bkey_append_ptr(&w->key,
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					ja->buckets[ja->cur_idx]) +
					ca->mi.bucket_size -
					ja->sectors_free,
				  .dev = ca->dev_idx,
		});

		ja->sectors_free -= sectors;
		ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);

		*replicas += ca->mi.durability;

		if (*replicas >= replicas_want)
			break;
	}
}

static int journal_write_alloc(struct journal *j, struct journal_buf *w,
			       unsigned *replicas)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_devs_mask devs;
	struct dev_alloc_list devs_sorted;
	unsigned sectors = vstruct_sectors(w->data, c->block_bits);
	unsigned target = c->opts.metadata_target ?:
		c->opts.foreground_target;
	unsigned replicas_want = READ_ONCE(c->opts.metadata_replicas);
	unsigned replicas_need = min_t(unsigned, replicas_want,
				       READ_ONCE(c->opts.metadata_replicas_required));
	bool advance_done = false;

retry_target:
	devs = target_rw_devs(c, BCH_DATA_journal, target);
	bch2_dev_alloc_list(c, &j->wp.stripe, &devs, &devs_sorted);
retry_alloc:
	__journal_write_alloc(j, w, &devs_sorted, sectors, replicas, replicas_want);

	if (likely(*replicas >= replicas_want))
		goto done;

	if (!advance_done) {
		journal_advance_devs_to_next_bucket(j, &devs_sorted, sectors, w->data->seq);
		advance_done = true;
		goto retry_alloc;
	}

	if (*replicas < replicas_want && target) {
		/* Retry from all devices: */
		target = 0;
		advance_done = false;
		goto retry_target;
	}
done:
	BUG_ON(bkey_val_u64s(&w->key.k) > BCH_REPLICAS_MAX);

#if 0
	/*
	 * XXX: we need a way to alert the user when we go degraded for any
	 * reason
	 */
	if (*replicas < min(replicas_want,
			    dev_mask_nr(&c->rw_devs[BCH_DATA_free]))) {
	}
#endif

	return *replicas >= replicas_need ? 0 : -BCH_ERR_insufficient_journal_devices;
}

static void journal_buf_realloc(struct journal *j, struct journal_buf *buf)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	/* we aren't holding j->lock: */
	unsigned new_size = READ_ONCE(j->buf_size_want);
	void *new_buf;

	if (buf->buf_size >= new_size)
		return;

	size_t btree_write_buffer_size = new_size / 64;

	if (bch2_btree_write_buffer_resize(c, btree_write_buffer_size))
		return;

	new_buf = kvmalloc(new_size, GFP_NOFS|__GFP_NOWARN);
	if (!new_buf)
		return;

	memcpy(new_buf, buf->data, buf->buf_size);

	scoped_guard(spinlock, &j->lock) {
		swap(buf->data,		new_buf);
		swap(buf->buf_size,	new_size);
	}

	kvfree(new_buf);
}

static CLOSURE_CALLBACK(journal_write_done)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	u64 seq = le64_to_cpu(w->data->seq);
	int err = 0;

	bch2_time_stats_update(!JSET_NO_FLUSH(w->data)
			       ? j->flush_write_time
			       : j->noflush_write_time, j->write_start_time);

	if (w->had_error) {
		struct bch_replicas_entry_v1 *r = &journal_seq_pin(j, seq)->devs.e;

		bch2_devlist_to_replicas(r, BCH_DATA_journal, w->devs_written);
	}

	if (!w->devs_written.nr)
		err = bch_err_throw(c, journal_write_err);

	if (err && !bch2_journal_error(j)) {
		CLASS(printbuf, buf)();
		bch2_log_msg_start(c, &buf);

		if (err == -BCH_ERR_journal_write_err)
			prt_printf(&buf, "unable to write journal to sufficient devices\n");
		else
			prt_printf(&buf, "journal write error marking replicas: %s\n",
				   bch2_err_str(err));

		bch2_fs_emergency_read_only2(c, &buf);

		bch2_print_str(c, KERN_ERR, buf.buf);
	}

	closure_debug_destroy(cl);

	spin_lock(&j->lock);
	BUG_ON(seq < j->pin.front);
	if (err && (!j->err_seq || seq < j->err_seq))
		j->err_seq	= seq;
	w->write_done = true;

	if (!j->free_buf || j->free_buf_size < w->buf_size) {
		swap(j->free_buf,	w->data);
		swap(j->free_buf_size,	w->buf_size);
	}

	if (w->data) {
		void *buf = w->data;
		w->data = NULL;
		w->buf_size = 0;

		spin_unlock(&j->lock);
		kvfree(buf);
		spin_lock(&j->lock);
	}

	bool completed = false;
	bool do_discards = false;

	for (seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++) {
		w = j->buf + (seq & JOURNAL_BUF_MASK);
		if (!w->write_done)
			break;

		if (!j->err_seq && !w->noflush) {
			j->flushed_seq_ondisk = seq;
			j->last_seq_ondisk = w->last_seq;

			closure_wake_up(&c->freelist_wait);
			bch2_reset_alloc_cursors(c);
			do_discards = true;
		}

		j->seq_ondisk = seq;

		/*
		 * Updating last_seq_ondisk may let bch2_journal_reclaim_work() discard
		 * more buckets:
		 *
		 * Must come before signaling write completion, for
		 * bch2_fs_journal_stop():
		 */
		if (j->watermark != BCH_WATERMARK_stripe)
			journal_reclaim_kick(&c->journal);

		closure_wake_up(&w->wait);
		completed = true;
	}

	if (completed) {
		bch2_journal_reclaim_fast(j);
		bch2_journal_space_available(j);

		track_event_change(&c->times[BCH_TIME_blocked_journal_max_in_flight], false);

		journal_wake(j);
	}

	if (journal_last_unwritten_seq(j) == journal_cur_seq(j) &&
	    j->reservations.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL) {
		struct journal_buf *buf = journal_cur_buf(j);
		long delta = buf->expires - jiffies;

		/*
		 * We don't close a journal entry to write it while there's
		 * previous entries still in flight - the current journal entry
		 * might want to be written now:
		 */
		mod_delayed_work(j->wq, &j->write_work, max(0L, delta));
	}

	/*
	 * We don't typically trigger journal writes from her - the next journal
	 * write will be triggered immediately after the previous one is
	 * allocated, in bch2_journal_write() - but the journal write error path
	 * is special:
	 */
	bch2_journal_do_writes(j);
	spin_unlock(&j->lock);

	if (do_discards)
		bch2_do_discards(c);

	closure_put(&c->cl);
}

static void journal_write_endio(struct bio *bio)
{
	struct journal_bio *jbio = container_of(bio, struct journal_bio, bio);
	struct bch_dev *ca = jbio->ca;
	struct journal *j = &ca->fs->journal;
	struct journal_buf *w = j->buf + jbio->buf_idx;

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_write,
				   jbio->submit_time, !bio->bi_status);

	if (bio->bi_status) {
		bch_err_dev_ratelimited(ca,
			       "error writing journal entry %llu: %s",
			       le64_to_cpu(w->data->seq),
			       bch2_blk_status_to_str(bio->bi_status));

		unsigned long flags;
		spin_lock_irqsave(&j->err_lock, flags);
		bch2_dev_list_drop_dev(&w->devs_written, ca->dev_idx);
		w->had_error = true;
		spin_unlock_irqrestore(&j->err_lock, flags);
	}

	closure_put(&w->io);
	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
}

static CLOSURE_CALLBACK(journal_write_submit)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned sectors = vstruct_sectors(w->data, c->block_bits);

	extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);

		this_cpu_add(ca->io_done->sectors[WRITE][BCH_DATA_journal],
			     sectors);

		struct journal_device *ja = &ca->journal;
		struct journal_bio *jbio = ja->bio[w->idx];
		struct bio *bio = &jbio->bio;

		jbio->submit_time	= local_clock();

		/*
		 * blk-wbt.c throttles all writes except those that have both
		 * REQ_SYNC and REQ_IDLE set...
		 */
		bio_reset(bio, ca->disk_sb.bdev, REQ_OP_WRITE|REQ_SYNC|REQ_IDLE|REQ_META);
		bio->bi_iter.bi_sector	= ptr->offset;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= ca;
		bio->bi_ioprio		= IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0);

		BUG_ON(bio->bi_iter.bi_sector == ca->prev_journal_sector);
		ca->prev_journal_sector = bio->bi_iter.bi_sector;

		if (!JSET_NO_FLUSH(w->data))
			bio->bi_opf    |= REQ_FUA;
		if (!JSET_NO_FLUSH(w->data) && !w->separate_flush)
			bio->bi_opf    |= REQ_PREFLUSH;

		bch2_bio_map(bio, w->data, sectors << 9);

		trace_and_count(c, journal_write, bio);
		closure_bio_submit(bio, cl);

		ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);
	}

	continue_at(cl, journal_write_done, j->wq);
}

static CLOSURE_CALLBACK(journal_write_preflush)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	/*
	 * Wait for previous journal writes to comelete; they won't necessarily
	 * be flushed if they're still in flight
	 */
	if (j->seq_ondisk + 1 != le64_to_cpu(w->data->seq)) {
		spin_lock(&j->lock);
		if (j->seq_ondisk + 1 != le64_to_cpu(w->data->seq)) {
			closure_wait(&j->async_wait, cl);
			spin_unlock(&j->lock);
			continue_at(cl, journal_write_preflush, j->wq);
			return;
		}
		spin_unlock(&j->lock);
	}

	if (w->separate_flush) {
		for_each_rw_member(c, ca, BCH_DEV_WRITE_REF_journal_write) {
			enumerated_ref_get(&ca->io_ref[WRITE],
					   BCH_DEV_WRITE_REF_journal_write);

			struct journal_device *ja = &ca->journal;
			struct bio *bio = &ja->bio[w->idx]->bio;
			bio_reset(bio, ca->disk_sb.bdev,
				  REQ_OP_WRITE|REQ_SYNC|REQ_META|REQ_PREFLUSH);
			bio->bi_end_io		= journal_write_endio;
			bio->bi_private		= ca;
			closure_bio_submit(bio, cl);
		}

		continue_at(cl, journal_write_submit, j->wq);
	} else {
		/*
		 * no need to punt to another work item if we're not waiting on
		 * preflushes
		 */
		journal_write_submit(&cl->work);
	}
}

static int bch2_journal_write_prep(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct jset_entry *start, *end;
	struct jset *jset = w->data;
	struct journal_keys_to_wb wb = { NULL };
	unsigned u64s;
	unsigned long btree_roots_have = 0;
	u64 seq = le64_to_cpu(jset->seq);
	int ret;

	/*
	 * Simple compaction, dropping empty jset_entries (from journal
	 * reservations that weren't fully used) and merging jset_entries that
	 * can be.
	 *
	 * If we wanted to be really fancy here, we could sort all the keys in
	 * the jset and drop keys that were overwritten - probably not worth it:
	 */
	vstruct_for_each(jset, i) {
		unsigned u64s = le16_to_cpu(i->u64s);

		/* Empty entry: */
		if (!u64s)
			continue;

		/*
		 * New btree roots are set by journalling them; when the journal
		 * entry gets written we have to propagate them to
		 * c->btree_roots
		 *
		 * But, every journal entry we write has to contain all the
		 * btree roots (at least for now); so after we copy btree roots
		 * to c->btree_roots we have to get any missing btree roots and
		 * add them to this journal entry:
		 */
		switch (i->type) {
		case BCH_JSET_ENTRY_btree_root:
			bch2_journal_entry_to_btree_root(c, i);
			__set_bit(i->btree_id, &btree_roots_have);
			break;
		case BCH_JSET_ENTRY_write_buffer_keys:
			EBUG_ON(!w->need_flush_to_write_buffer);

			if (!wb.wb)
				bch2_journal_keys_to_write_buffer_start(c, &wb, seq);

			jset_entry_for_each_key(i, k) {
				ret = bch2_journal_key_to_wb(c, &wb, i->btree_id, k);
				if (ret) {
					bch2_fs_fatal_error(c, "flushing journal keys to btree write buffer: %s",
							    bch2_err_str(ret));
					bch2_journal_keys_to_write_buffer_end(c, &wb);
					return ret;
				}
			}
			i->type = BCH_JSET_ENTRY_btree_keys;
			break;
		}
	}

	if (wb.wb) {
		ret = bch2_journal_keys_to_write_buffer_end(c, &wb);
		if (ret) {
			bch2_fs_fatal_error(c, "error flushing journal keys to btree write buffer: %s",
					    bch2_err_str(ret));
			return ret;
		}
	}

	scoped_guard(spinlock, &c->journal.lock)
		w->need_flush_to_write_buffer = false;

	start = end = vstruct_last(jset);

	end	= bch2_btree_roots_to_journal_entries(c, end, btree_roots_have);

	struct jset_entry_datetime *d =
		container_of(jset_entry_init(&end, sizeof(*d)), struct jset_entry_datetime, entry);
	d->entry.type	= BCH_JSET_ENTRY_datetime;
	d->seconds	= cpu_to_le64(ktime_get_real_seconds());

	bch2_journal_super_entries_add_common(c, &end, seq);
	u64s	= (u64 *) end - (u64 *) start;

	WARN_ON(u64s > j->entry_u64s_reserved);

	le32_add_cpu(&jset->u64s, u64s);

	unsigned sectors = vstruct_sectors(jset, c->block_bits);

	if (sectors > w->sectors) {
		bch2_fs_fatal_error(c, ": journal write overran available space, %zu > %u (extra %u reserved %u/%u)",
				    vstruct_bytes(jset), w->sectors << 9,
				    u64s, w->u64s_reserved, j->entry_u64s_reserved);
		return -EINVAL;
	}

	return 0;
}

static int bch2_journal_write_checksum(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct jset *jset = w->data;
	u64 seq = le64_to_cpu(jset->seq);
	bool validate_before_checksum = false;
	int ret = 0;

	jset->magic		= cpu_to_le64(jset_magic(c));
	jset->version		= cpu_to_le32(c->sb.version);

	SET_JSET_BIG_ENDIAN(jset, CPU_BIG_ENDIAN);
	SET_JSET_CSUM_TYPE(jset, bch2_meta_checksum_type(c));

	if (!JSET_NO_FLUSH(jset) && journal_entry_empty(jset))
		j->last_empty_seq = seq;

	if (bch2_csum_type_is_encryption(JSET_CSUM_TYPE(jset)))
		validate_before_checksum = true;

	if (le32_to_cpu(jset->version) < bcachefs_metadata_version_current)
		validate_before_checksum = true;

	if (validate_before_checksum &&
	    (ret = bch2_jset_validate(c, NULL, jset, 0, WRITE)))
		return ret;

	ret = bch2_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
		    jset->encrypted_start,
		    vstruct_end(jset) - (void *) jset->encrypted_start);
	if (bch2_fs_fatal_err_on(ret, c, "encrypting journal entry: %s", bch2_err_str(ret)))
		return ret;

	jset->csum = csum_vstruct(c, JSET_CSUM_TYPE(jset),
				  journal_nonce(jset), jset);

	if (!validate_before_checksum &&
	    (ret = bch2_jset_validate(c, NULL, jset, 0, WRITE)))
		return ret;

	unsigned sectors = vstruct_sectors(jset, c->block_bits);
	unsigned bytes	= vstruct_bytes(jset);
	memset((void *) jset + bytes, 0, (sectors << 9) - bytes);
	return 0;
}

static int bch2_journal_write_pick_flush(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	int error = bch2_journal_error(j);

	/*
	 * If the journal is in an error state - we did an emergency shutdown -
	 * we prefer to continue doing journal writes. We just mark them as
	 * noflush so they'll never be used, but they'll still be visible by the
	 * list_journal tool - this helps in debugging.
	 *
	 * There's a caveat: the first journal write after marking the
	 * superblock dirty must always be a flush write, because on startup
	 * from a clean shutdown we didn't necessarily read the journal and the
	 * new journal write might overwrite whatever was in the journal
	 * previously - we can't leave the journal without any flush writes in
	 * it.
	 *
	 * So if we're in an error state, and we're still starting up, we don't
	 * write anything at all.
	 */
	if (error && test_bit(JOURNAL_need_flush_write, &j->flags))
		return error;

	if (error ||
	    w->noflush ||
	    (!w->must_flush &&
	     time_before(jiffies, j->last_flush_write +
		 msecs_to_jiffies(c->opts.journal_flush_delay)) &&
	     test_bit(JOURNAL_may_skip_flush, &j->flags))) {
		w->noflush = true;
		SET_JSET_NO_FLUSH(w->data, true);
		w->data->last_seq	= 0;
		w->last_seq		= 0;

		j->nr_noflush_writes++;
	} else {
		w->must_flush = true;
		j->last_flush_write = jiffies;
		j->nr_flush_writes++;
		clear_bit(JOURNAL_need_flush_write, &j->flags);
	}

	return 0;
}

CLOSURE_CALLBACK(bch2_journal_write)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned nr_rw_members = dev_mask_nr(&c->rw_devs[BCH_DATA_free]);
	int ret;

	BUG_ON(BCH_SB_CLEAN(c->disk_sb.sb));
	BUG_ON(!w->write_started);
	BUG_ON(w->write_allocated);
	BUG_ON(w->write_done);

	j->write_start_time = local_clock();

	scoped_guard(spinlock, &j->lock) {
		if (nr_rw_members > 1)
			w->separate_flush = true;

		ret = bch2_journal_write_pick_flush(j, w);
	}

	if (unlikely(ret))
		goto err;

	scoped_guard(mutex, &j->buf_lock) {
		journal_buf_realloc(j, w);

		ret = bch2_journal_write_prep(j, w);
	}

	if (unlikely(ret))
		goto err;

	unsigned replicas_allocated = 0;
	while (1) {
		ret = journal_write_alloc(j, w, &replicas_allocated);
		if (!ret || !j->can_discard)
			break;

		bch2_journal_do_discards(j);
	}

	if (unlikely(ret))
		goto err_allocate_write;

	ret = bch2_journal_write_checksum(j, w);
	if (unlikely(ret))
		goto err;

	scoped_guard(spinlock, &j->lock) {
		/*
		 * write is allocated, no longer need to account for it in
		 * bch2_journal_space_available():
		 */
		w->sectors = 0;
		w->write_allocated = true;
		j->entry_bytes_written += vstruct_bytes(w->data);

		/*
		 * journal entry has been compacted and allocated, recalculate space
		 * available:
		 */
		bch2_journal_space_available(j);
		bch2_journal_do_writes(j);
	}

	w->devs_written = bch2_bkey_devs(bkey_i_to_s_c(&w->key));

	/*
	 * Mark journal replicas before we submit the write to guarantee
	 * recovery will find the journal entries after a crash.
	 */
	struct bch_replicas_entry_v1 *r = &journal_seq_pin(j, le64_to_cpu(w->data->seq))->devs.e;
	bch2_devlist_to_replicas(r, BCH_DATA_journal, w->devs_written);
	ret = bch2_mark_replicas(c, r);
	if (ret)
		goto err;

	if (c->opts.nochanges)
		goto no_io;

	if (!JSET_NO_FLUSH(w->data))
		continue_at(cl, journal_write_preflush, j->wq);
	else
		continue_at(cl, journal_write_submit, j->wq);
	return;
err_allocate_write:
	if (!bch2_journal_error(j)) {
		CLASS(printbuf, buf)();

		bch2_journal_debug_to_text(&buf, j);
		prt_printf(&buf, bch2_fmt(c, "Unable to allocate journal write at seq %llu for %zu sectors: %s"),
					  le64_to_cpu(w->data->seq),
					  vstruct_sectors(w->data, c->block_bits),
					  bch2_err_str(ret));
		bch2_print_str(c, KERN_ERR, buf.buf);
	}
err:
	bch2_fatal_error(c);
no_io:
	extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);
		enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
	}

	continue_at(cl, journal_write_done, j->wq);
}
