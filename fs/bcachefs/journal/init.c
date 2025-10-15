// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "journal/init.h"
#include "journal/journal.h"
#include "journal/read.h"
#include "journal/reclaim.h"
#include "journal/sb.h"
#include "journal/seq_blacklist.h"

#include "alloc/foreground.h"
#include "btree/update.h"

/* allocate journal on a device: */

static int bch2_set_nr_journal_buckets_iter(struct bch_dev *ca, unsigned nr,
					    bool new_fs, struct closure *cl)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	u64 *new_bucket_seq = NULL, *new_buckets = NULL;
	struct open_bucket **ob = NULL;
	long *bu = NULL;
	unsigned i, pos, nr_got = 0, nr_want = nr - ja->nr;
	int ret = 0;

	BUG_ON(nr <= ja->nr);

	bu		= kcalloc(nr_want, sizeof(*bu), GFP_KERNEL);
	ob		= kcalloc(nr_want, sizeof(*ob), GFP_KERNEL);
	new_buckets	= kcalloc(nr, sizeof(u64), GFP_KERNEL);
	new_bucket_seq	= kcalloc(nr, sizeof(u64), GFP_KERNEL);
	if (!bu || !ob || !new_buckets || !new_bucket_seq) {
		ret = bch_err_throw(c, ENOMEM_set_nr_journal_buckets);
		goto err_free;
	}

	for (nr_got = 0; nr_got < nr_want; nr_got++) {
		enum bch_watermark watermark = new_fs
			? BCH_WATERMARK_btree
			: BCH_WATERMARK_normal;

		ob[nr_got] = bch2_bucket_alloc(c, ca, watermark,
					       BCH_DATA_journal, cl);
		ret = PTR_ERR_OR_ZERO(ob[nr_got]);

		if (ret == -BCH_ERR_bucket_alloc_blocked)
			ret = bch_err_throw(c, freelist_empty);
		if (ret == -BCH_ERR_freelist_empty) /* don't if we're actually out of buckets */
			closure_wake_up(&c->freelist_wait);

		if (ret)
			break;

		CLASS(btree_trans, trans)(c);
		ret = bch2_trans_mark_metadata_bucket(trans, ca,
					ob[nr_got]->bucket, BCH_DATA_journal,
					ca->mi.bucket_size, BTREE_TRIGGER_transactional);
		if (ret) {
			bch2_open_bucket_put(c, ob[nr_got]);
			bch_err_msg(c, ret, "marking new journal buckets");
			break;
		}

		bu[nr_got] = ob[nr_got]->bucket;
	}

	if (!nr_got)
		goto err_free;

	/* Don't return an error if we successfully allocated some buckets: */
	ret = 0;

	if (c) {
		bch2_journal_flush_all_pins(&c->journal);
		bch2_journal_block(&c->journal);
		mutex_lock(&c->sb_lock);
	}

	memcpy(new_buckets,	ja->buckets,	ja->nr * sizeof(u64));
	memcpy(new_bucket_seq,	ja->bucket_seq,	ja->nr * sizeof(u64));

	BUG_ON(ja->discard_idx > ja->nr);

	pos = ja->discard_idx ?: ja->nr;

	memmove(new_buckets + pos + nr_got,
		new_buckets + pos,
		sizeof(new_buckets[0]) * (ja->nr - pos));
	memmove(new_bucket_seq + pos + nr_got,
		new_bucket_seq + pos,
		sizeof(new_bucket_seq[0]) * (ja->nr - pos));

	for (i = 0; i < nr_got; i++) {
		new_buckets[pos + i] = bu[i];
		new_bucket_seq[pos + i] = 0;
	}

	nr = ja->nr + nr_got;

	ret = bch2_journal_buckets_to_sb(c, ca, new_buckets, nr);
	if (ret)
		goto err_unblock;

	bch2_write_super(c);

	/* Commit: */
	if (c)
		spin_lock(&c->journal.lock);

	swap(new_buckets,	ja->buckets);
	swap(new_bucket_seq,	ja->bucket_seq);
	ja->nr = nr;

	if (pos <= ja->discard_idx)
		ja->discard_idx = (ja->discard_idx + nr_got) % ja->nr;
	if (pos <= ja->dirty_idx_ondisk)
		ja->dirty_idx_ondisk = (ja->dirty_idx_ondisk + nr_got) % ja->nr;
	if (pos <= ja->dirty_idx)
		ja->dirty_idx = (ja->dirty_idx + nr_got) % ja->nr;
	if (pos <= ja->cur_idx)
		ja->cur_idx = (ja->cur_idx + nr_got) % ja->nr;

	if (c)
		spin_unlock(&c->journal.lock);
err_unblock:
	if (c) {
		bch2_journal_unblock(&c->journal);
		mutex_unlock(&c->sb_lock);
	}

	if (ret) {
		CLASS(btree_trans, trans)(c);
		for (i = 0; i < nr_got; i++)
			bch2_trans_mark_metadata_bucket(trans, ca,
						bu[i], BCH_DATA_free, 0,
						BTREE_TRIGGER_transactional);
	}
err_free:
	for (i = 0; i < nr_got; i++)
		bch2_open_bucket_put(c, ob[i]);

	kfree(new_bucket_seq);
	kfree(new_buckets);
	kfree(ob);
	kfree(bu);
	return ret;
}

static int bch2_set_nr_journal_buckets_loop(struct bch_fs *c, struct bch_dev *ca,
					    unsigned nr, bool new_fs)
{
	struct journal_device *ja = &ca->journal;
	int ret = 0;

	struct closure cl;
	closure_init_stack(&cl);

	/* don't handle reducing nr of buckets yet: */
	if (nr < ja->nr)
		return 0;

	while (!ret && ja->nr < nr) {
		struct disk_reservation disk_res = { 0, 0, 0 };

		/*
		 * note: journal buckets aren't really counted as _sectors_ used yet, so
		 * we don't need the disk reservation to avoid the BUG_ON() in buckets.c
		 * when space used goes up without a reservation - but we do need the
		 * reservation to ensure we'll actually be able to allocate:
		 *
		 * XXX: that's not right, disk reservations only ensure a
		 * filesystem-wide allocation will succeed, this is a device
		 * specific allocation - we can hang here:
		 */
		if (!new_fs) {
			ret = bch2_disk_reservation_get(c, &disk_res,
							bucket_to_sector(ca, nr - ja->nr), 1, 0);
			if (ret)
				break;
		}

		ret = bch2_set_nr_journal_buckets_iter(ca, nr, new_fs, &cl);
		if (ret == -BCH_ERR_open_buckets_empty)
			ret = 0; /* wait and retry */

		bch2_disk_reservation_put(c, &disk_res);
		bch2_wait_on_allocator(c, &cl);
	}

	return ret;
}

/*
 * Allocate more journal space at runtime - not currently making use if it, but
 * the code works:
 */
int bch2_set_nr_journal_buckets(struct bch_fs *c, struct bch_dev *ca,
				unsigned nr)
{
	guard(rwsem_write)(&c->state_lock);
	int ret = bch2_set_nr_journal_buckets_loop(c, ca, nr, false);
	bch_err_fn(c, ret);
	return ret;
}

int bch2_dev_journal_bucket_delete(struct bch_dev *ca, u64 b)
{
	struct bch_fs *c = ca->fs;
	struct journal *j = &c->journal;
	struct journal_device *ja = &ca->journal;

	guard(mutex)(&c->sb_lock);
	unsigned pos;
	for (pos = 0; pos < ja->nr; pos++)
		if (ja->buckets[pos] == b)
			break;

	if (pos == ja->nr) {
		bch_err(ca, "journal bucket %llu not found when deleting", b);
		return -EINVAL;
	}

	u64 *new_buckets = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!new_buckets)
		return bch_err_throw(c, ENOMEM_set_nr_journal_buckets);

	memcpy(new_buckets, ja->buckets, ja->nr * sizeof(u64));
	memmove(&new_buckets[pos],
		&new_buckets[pos + 1],
		(ja->nr - 1 - pos) * sizeof(new_buckets[0]));

	int ret = bch2_journal_buckets_to_sb(c, ca, ja->buckets, ja->nr - 1) ?:
		bch2_write_super(c);
	if (ret) {
		kfree(new_buckets);
		return ret;
	}

	scoped_guard(spinlock, &j->lock) {
		if (pos < ja->discard_idx)
			--ja->discard_idx;
		if (pos < ja->dirty_idx_ondisk)
			--ja->dirty_idx_ondisk;
		if (pos < ja->dirty_idx)
			--ja->dirty_idx;
		if (pos < ja->cur_idx)
			--ja->cur_idx;

		ja->nr--;

		memmove(&ja->buckets[pos],
			&ja->buckets[pos + 1],
			(ja->nr - pos) * sizeof(ja->buckets[0]));

		memmove(&ja->bucket_seq[pos],
			&ja->bucket_seq[pos + 1],
			(ja->nr - pos) * sizeof(ja->bucket_seq[0]));

		bch2_journal_space_available(j);
	}

	kfree(new_buckets);
	return 0;
}

int bch2_dev_journal_alloc(struct bch_dev *ca, bool new_fs)
{
	struct bch_fs *c = ca->fs;

	if (!(ca->mi.data_allowed & BIT(BCH_DATA_journal)))
		return 0;

	if (c->sb.features & BIT_ULL(BCH_FEATURE_small_image)) {
		bch_err(c, "cannot allocate journal, filesystem is an unresized image file");
		return bch_err_throw(c, erofs_filesystem_full);
	}

	unsigned nr;
	int ret;

	if (dynamic_fault("bcachefs:add:journal_alloc")) {
		ret = bch_err_throw(c, ENOMEM_set_nr_journal_buckets);
		goto err;
	}

	/* 1/128th of the device by default: */
	nr = ca->mi.nbuckets >> 7;

	/*
	 * clamp journal size to 8192 buckets or 8GB (in sectors), whichever
	 * is smaller:
	 */
	nr = clamp_t(unsigned, nr,
		     BCH_JOURNAL_BUCKETS_MIN,
		     min(1 << 13,
			 (1 << 24) / ca->mi.bucket_size));

	ret = bch2_set_nr_journal_buckets_loop(c, ca, nr, new_fs);
err:
	bch_err_fn(ca, ret);
	return ret;
}

int bch2_fs_journal_alloc(struct bch_fs *c)
{
	for_each_online_member(c, ca, BCH_DEV_READ_REF_fs_journal_alloc) {
		if (ca->journal.nr)
			continue;

		int ret = bch2_dev_journal_alloc(ca, true);
		if (ret) {
			enumerated_ref_put(&ca->io_ref[READ],
					   BCH_DEV_READ_REF_fs_journal_alloc);
			return ret;
		}
	}

	return 0;
}

/* startup/shutdown: */

static bool bch2_journal_writing_to_device(struct journal *j, unsigned dev_idx)
{
	guard(spinlock)(&j->lock);

	for (u64 seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++) {
		struct journal_buf *buf = journal_seq_to_buf(j, seq);

		if (bch2_bkey_has_device_c(bkey_i_to_s_c(&buf->key), dev_idx))
			return true;
	}

	return false;
}

void bch2_dev_journal_stop(struct journal *j, struct bch_dev *ca)
{
	wait_event(j->wait, !bch2_journal_writing_to_device(j, ca->dev_idx));
}

void bch2_fs_journal_stop(struct journal *j)
{
	if (!test_bit(JOURNAL_running, &j->flags))
		return;

	bch2_journal_reclaim_stop(j);
	bch2_journal_flush_all_pins(j);

	wait_event(j->wait, bch2_journal_entry_close(j));

	/*
	 * Always write a new journal entry, to make sure the clock hands are up
	 * to date (and match the superblock)
	 */
	__bch2_journal_meta(j);

	bch2_journal_quiesce(j);
	cancel_delayed_work_sync(&j->write_work);

	WARN(!bch2_journal_error(j) &&
	     test_bit(JOURNAL_replay_done, &j->flags) &&
	     j->last_empty_seq != journal_cur_seq(j),
	     "journal shutdown error: cur seq %llu but last empty seq %llu",
	     journal_cur_seq(j), j->last_empty_seq);

	if (!bch2_journal_error(j))
		clear_bit(JOURNAL_running, &j->flags);
}

int bch2_fs_journal_start(struct journal *j, u64 last_seq, u64 cur_seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_entry_pin_list *p;
	struct journal_replay *i, **_i;
	struct genradix_iter iter;
	bool had_entries = false;

	/*
	 *
	 * XXX pick most recent non blacklisted sequence number
	 */

	cur_seq = max(cur_seq, bch2_journal_last_blacklisted_seq(c));

	if (cur_seq >= JOURNAL_SEQ_MAX) {
		bch_err(c, "cannot start: journal seq overflow");
		return -EINVAL;
	}

	/* Clean filesystem? */
	if (!last_seq)
		last_seq = cur_seq;

	u64 nr = cur_seq - last_seq;
	if (nr * sizeof(struct journal_entry_pin_list) > 1U << 30) {
		bch_err(c, "too many ntjournal fifo (%llu open entries)", nr);
		return bch_err_throw(c, ENOMEM_journal_pin_fifo);
	}

	/*
	 * Extra fudge factor, in case we crashed when the journal pin fifo was
	 * nearly or completely full. We'll need to be able to open additional
	 * journal entries (at least a few) in order for journal replay to get
	 * going:
	 */
	nr += nr / 4;

	nr = max(nr, JOURNAL_PIN);
	init_fifo(&j->pin, roundup_pow_of_two(nr), GFP_KERNEL);
	if (!j->pin.data) {
		bch_err(c, "error allocating journal fifo (%llu open entries)", nr);
		return bch_err_throw(c, ENOMEM_journal_pin_fifo);
	}

	j->replay_journal_seq	= last_seq;
	j->replay_journal_seq_end = cur_seq;
	j->last_seq_ondisk	= last_seq;
	j->flushed_seq_ondisk	= cur_seq - 1;
	j->seq_write_started	= cur_seq - 1;
	j->seq_ondisk		= cur_seq - 1;
	j->pin.front		= last_seq;
	j->pin.back		= cur_seq;
	atomic64_set(&j->seq, cur_seq - 1);

	u64 seq;
	fifo_for_each_entry_ptr(p, &j->pin, seq)
		journal_pin_list_init(p, 1);

	genradix_for_each(&c->journal_entries, iter, _i) {
		i = *_i;

		if (journal_replay_ignore(i))
			continue;

		seq = le64_to_cpu(i->j.seq);
		BUG_ON(seq >= cur_seq);

		if (seq < last_seq)
			continue;

		if (journal_entry_empty(&i->j))
			j->last_empty_seq = le64_to_cpu(i->j.seq);

		p = journal_seq_pin(j, seq);

		p->devs.nr = 0;
		darray_for_each(i->ptrs, ptr)
			bch2_dev_list_add_dev(&p->devs, ptr->dev);

		had_entries = true;
	}

	if (!had_entries)
		j->last_empty_seq = cur_seq - 1; /* to match j->seq */

	scoped_guard(spinlock, &j->lock) {
		j->last_flush_write = jiffies;
		j->reservations.idx = journal_cur_seq(j);
		c->last_bucket_seq_cleanup = journal_cur_seq(j);
	}

	return 0;
}

void bch2_journal_set_replay_done(struct journal *j)
{
	/*
	 * journal_space_available must happen before setting JOURNAL_running
	 * JOURNAL_running must happen before JOURNAL_replay_done
	 */
	guard(spinlock)(&j->lock);
	bch2_journal_space_available(j);

	set_bit(JOURNAL_need_flush_write, &j->flags);
	set_bit(JOURNAL_running, &j->flags);
	set_bit(JOURNAL_replay_done, &j->flags);
}

/* init/exit: */

void bch2_dev_journal_exit(struct bch_dev *ca)
{
	struct journal_device *ja = &ca->journal;

	for (unsigned i = 0; i < ARRAY_SIZE(ja->bio); i++) {
		kvfree(ja->bio[i]);
		ja->bio[i] = NULL;
	}

	kfree(ja->buckets);
	kfree(ja->bucket_seq);
	ja->buckets	= NULL;
	ja->bucket_seq	= NULL;
}

int bch2_dev_journal_init(struct bch_dev *ca, struct bch_sb *sb)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets =
		bch2_sb_field_get(sb, journal);
	struct bch_sb_field_journal_v2 *journal_buckets_v2 =
		bch2_sb_field_get(sb, journal_v2);

	ja->nr = 0;

	if (journal_buckets_v2) {
		unsigned nr = bch2_sb_field_journal_v2_nr_entries(journal_buckets_v2);

		for (unsigned i = 0; i < nr; i++)
			ja->nr += le64_to_cpu(journal_buckets_v2->d[i].nr);
	} else if (journal_buckets) {
		ja->nr = bch2_nr_journal_buckets(journal_buckets);
	}

	ja->bucket_seq = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->bucket_seq)
		return bch_err_throw(c, ENOMEM_dev_journal_init);

	unsigned nr_bvecs = DIV_ROUND_UP(JOURNAL_ENTRY_SIZE_MAX, PAGE_SIZE);

	for (unsigned i = 0; i < ARRAY_SIZE(ja->bio); i++) {
		/*
		 * kvzalloc() is not what we want to be using here:
		 * JOURNAL_ENTRY_SIZE_MAX is probably quite a bit bigger than it
		 * needs to be.
		 *
		 * But changing that will require performance testing -
		 * performance can be sensitive to anything that affects journal
		 * pipelining.
		 */
		ja->bio[i] = kvzalloc(sizeof(struct bio) + sizeof(struct bio_vec) * nr_bvecs,
				      GFP_KERNEL);
		if (!ja->bio[i])
			return bch_err_throw(c, ENOMEM_dev_journal_init);

		ja->bio[i]->ca = ca;
		ja->bio[i]->buf_idx = i;
		bio_init(&ja->bio[i]->bio, NULL, bio_inline_vecs(&ja->bio[i]->bio), nr_bvecs, 0);
	}

	ja->buckets = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->buckets)
		return bch_err_throw(c, ENOMEM_dev_journal_init);

	if (journal_buckets_v2) {
		unsigned nr = bch2_sb_field_journal_v2_nr_entries(journal_buckets_v2);
		unsigned dst = 0;

		for (unsigned i = 0; i < nr; i++)
			for (unsigned j = 0; j < le64_to_cpu(journal_buckets_v2->d[i].nr); j++)
				ja->buckets[dst++] =
					le64_to_cpu(journal_buckets_v2->d[i].start) + j;
	} else if (journal_buckets) {
		for (unsigned i = 0; i < ja->nr; i++)
			ja->buckets[i] = le64_to_cpu(journal_buckets->buckets[i]);
	}

	return 0;
}

void bch2_fs_journal_exit(struct journal *j)
{
	if (j->wq)
		destroy_workqueue(j->wq);

	darray_exit(&j->early_journal_entries);

	for (unsigned i = 0; i < ARRAY_SIZE(j->buf); i++)
		kvfree(j->buf[i].data);
	kvfree(j->free_buf);
	free_fifo(&j->pin);
}

void bch2_fs_journal_init_early(struct journal *j)
{
	static struct lock_class_key res_key;

	mutex_init(&j->buf_lock);
	spin_lock_init(&j->lock);
	spin_lock_init(&j->err_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, bch2_journal_write_work);
	init_waitqueue_head(&j->reclaim_wait);
	init_waitqueue_head(&j->pin_flush_wait);
	mutex_init(&j->reclaim_lock);
	mutex_init(&j->discard_lock);

	lockdep_init_map(&j->res_map, "journal res", &res_key, 0);

	atomic64_set(&j->reservations.counter,
		((union journal_res_state)
		 { .cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL }).v);
}

int bch2_fs_journal_init(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	j->free_buf_size = j->buf_size_want = JOURNAL_ENTRY_SIZE_MIN;
	j->free_buf = kvmalloc(j->free_buf_size, GFP_KERNEL);
	if (!j->free_buf)
		return bch_err_throw(c, ENOMEM_journal_buf);

	for (unsigned i = 0; i < ARRAY_SIZE(j->buf); i++)
		j->buf[i].idx = i;

	j->wq = alloc_workqueue("bcachefs_journal",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_UNBOUND|WQ_MEM_RECLAIM, 512);
	if (!j->wq)
		return bch_err_throw(c, ENOMEM_fs_other_alloc);
	return 0;
}
