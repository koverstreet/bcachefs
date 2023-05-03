// SPDX-License-Identifier: GPL-2.0
/*
 * bcachefs journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "bkey_methods.h"
#include "btree_gc.h"
#include "buckets.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "journal_seq_blacklist.h"
#include "super-io.h"
#include "trace.h"

static bool __journal_entry_is_open(union journal_res_state state)
{
	return state.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL;
}

static bool journal_entry_is_open(struct journal *j)
{
	return __journal_entry_is_open(j->reservations);
}

static void journal_pin_new_entry(struct journal *j, int count)
{
	struct journal_entry_pin_list *p;

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for journal_last_seq() to be calculated correctly
	 */
	atomic64_inc(&j->seq);
	p = fifo_push_ref(&j->pin);

	INIT_LIST_HEAD(&p->list);
	INIT_LIST_HEAD(&p->flushed);
	atomic_set(&p->count, count);
	p->devs.nr = 0;
}

static void bch2_journal_buf_init(struct journal *j)
{
	struct journal_buf *buf = journal_cur_buf(j);

	memset(buf->has_inode, 0, sizeof(buf->has_inode));

	memset(buf->data, 0, sizeof(*buf->data));
	buf->data->seq	= cpu_to_le64(journal_cur_seq(j));
	buf->data->u64s	= 0;
}

static inline bool journal_entry_empty(struct jset *j)
{
	struct jset_entry *i;

	if (j->seq != j->last_seq)
		return false;

	vstruct_for_each(j, i)
		if (i->type || i->u64s)
			return false;
	return true;
}

void bch2_journal_halt(struct journal *j)
{
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;
		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
			return;

		new.cur_entry_offset = JOURNAL_ENTRY_ERROR_VAL;
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	journal_wake(j);
	closure_wake_up(&journal_cur_buf(j)->wait);
}

/* journal entry close/open: */

void __bch2_journal_buf_put(struct journal *j, bool need_write_just_set)
{
	if (!need_write_just_set &&
	    test_bit(JOURNAL_NEED_WRITE, &j->flags))
		bch2_time_stats_update(j->delay_time,
				       j->need_write_time);

	clear_bit(JOURNAL_NEED_WRITE, &j->flags);

	closure_call(&j->io, bch2_journal_write, system_highpri_wq, NULL);
}

/*
 * Returns true if journal entry is now closed:
 */
static bool __journal_entry_close(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf = journal_cur_buf(j);
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);
	bool set_need_write = false;
	unsigned sectors;

	lockdep_assert_held(&j->lock);

	do {
		old.v = new.v = v;
		if (old.cur_entry_offset == JOURNAL_ENTRY_CLOSED_VAL)
			return true;

		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL) {
			/* this entry will never be written: */
			closure_wake_up(&buf->wait);
			return true;
		}

		if (!test_bit(JOURNAL_NEED_WRITE, &j->flags)) {
			set_bit(JOURNAL_NEED_WRITE, &j->flags);
			j->need_write_time = local_clock();
			set_need_write = true;
		}

		if (new.prev_buf_unwritten)
			return false;

		new.cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL;
		new.idx++;
		new.prev_buf_unwritten = 1;

		BUG_ON(journal_state_count(new, new.idx));
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	buf->data->u64s		= cpu_to_le32(old.cur_entry_offset);

	sectors = vstruct_blocks_plus(buf->data, c->block_bits,
				      buf->u64s_reserved) << c->block_bits;
	BUG_ON(sectors > buf->sectors);
	buf->sectors = sectors;

	bkey_extent_init(&buf->key);

	/*
	 * We have to set last_seq here, _before_ opening a new journal entry:
	 *
	 * A threads may replace an old pin with a new pin on their current
	 * journal reservation - the expectation being that the journal will
	 * contain either what the old pin protected or what the new pin
	 * protects.
	 *
	 * After the old pin is dropped journal_last_seq() won't include the old
	 * pin, so we can only write the updated last_seq on the entry that
	 * contains whatever the new pin protects.
	 *
	 * Restated, we can _not_ update last_seq for a given entry if there
	 * could be a newer entry open with reservations/pins that have been
	 * taken against it.
	 *
	 * Hence, we want update/set last_seq on the current journal entry right
	 * before we open a new one:
	 */
	buf->data->last_seq	= cpu_to_le64(journal_last_seq(j));

	if (journal_entry_empty(buf->data))
		clear_bit(JOURNAL_NOT_EMPTY, &j->flags);
	else
		set_bit(JOURNAL_NOT_EMPTY, &j->flags);

	journal_pin_new_entry(j, 1);

	bch2_journal_buf_init(j);

	cancel_delayed_work(&j->write_work);

	bch2_journal_space_available(j);

	bch2_journal_buf_put(j, old.idx, set_need_write);
	return true;
}

static bool journal_entry_close(struct journal *j)
{
	bool ret;

	spin_lock(&j->lock);
	ret = __journal_entry_close(j);
	spin_unlock(&j->lock);

	return ret;
}

/*
 * should _only_ called from journal_res_get() - when we actually want a
 * journal reservation - journal entry is open means journal is dirty:
 *
 * returns:
 * 0:		success
 * -ENOSPC:	journal currently full, must invoke reclaim
 * -EAGAIN:	journal blocked, must wait
 * -EROFS:	insufficient rw devices or journal error
 */
static int journal_entry_open(struct journal *j)
{
	struct journal_buf *buf = journal_cur_buf(j);
	union journal_res_state old, new;
	int u64s;
	u64 v;

	lockdep_assert_held(&j->lock);
	BUG_ON(journal_entry_is_open(j));

	if (j->blocked)
		return -EAGAIN;

	if (j->cur_entry_error)
		return j->cur_entry_error;

	BUG_ON(!j->cur_entry_sectors);

	buf->u64s_reserved	= j->entry_u64s_reserved;
	buf->disk_sectors	= j->cur_entry_sectors;
	buf->sectors		= min(buf->disk_sectors, buf->buf_size >> 9);

	u64s = (int) (buf->sectors << 9) / sizeof(u64) -
		journal_entry_overhead(j);
	u64s  = clamp_t(int, u64s, 0, JOURNAL_ENTRY_CLOSED_VAL - 1);

	if (u64s <= le32_to_cpu(buf->data->u64s))
		return -ENOSPC;

	/*
	 * Must be set before marking the journal entry as open:
	 */
	j->cur_entry_u64s = u64s;

	v = atomic64_read(&j->reservations.counter);
	do {
		old.v = new.v = v;

		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
			return -EROFS;

		/* Handle any already added entries */
		new.cur_entry_offset = le32_to_cpu(buf->data->u64s);

		EBUG_ON(journal_state_count(new, new.idx));
		journal_state_inc(&new);
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	if (j->res_get_blocked_start)
		bch2_time_stats_update(j->blocked_time,
				       j->res_get_blocked_start);
	j->res_get_blocked_start = 0;

	mod_delayed_work(system_freezable_wq,
			 &j->write_work,
			 msecs_to_jiffies(j->write_delay_ms));
	journal_wake(j);
	return 0;
}

static bool journal_quiesced(struct journal *j)
{
	union journal_res_state state = READ_ONCE(j->reservations);
	bool ret = !state.prev_buf_unwritten && !__journal_entry_is_open(state);

	if (!ret)
		journal_entry_close(j);
	return ret;
}

static void journal_quiesce(struct journal *j)
{
	wait_event(j->wait, journal_quiesced(j));
}

static void journal_write_work(struct work_struct *work)
{
	struct journal *j = container_of(work, struct journal, write_work.work);

	journal_entry_close(j);
}

/*
 * Given an inode number, if that inode number has data in the journal that
 * hasn't yet been flushed, return the journal sequence number that needs to be
 * flushed:
 */
u64 bch2_inode_journal_seq(struct journal *j, u64 inode)
{
	size_t h = hash_64(inode, ilog2(sizeof(j->buf[0].has_inode) * 8));
	u64 seq = 0;

	if (!test_bit(h, j->buf[0].has_inode) &&
	    !test_bit(h, j->buf[1].has_inode))
		return 0;

	spin_lock(&j->lock);
	if (test_bit(h, journal_cur_buf(j)->has_inode))
		seq = journal_cur_seq(j);
	else if (test_bit(h, journal_prev_buf(j)->has_inode))
		seq = journal_cur_seq(j) - 1;
	spin_unlock(&j->lock);

	return seq;
}

static int __journal_res_get(struct journal *j, struct journal_res *res,
			     unsigned flags)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf;
	bool can_discard;
	int ret;
retry:
	if (journal_res_get_fast(j, res, flags))
		return 0;

	if (bch2_journal_error(j))
		return -EROFS;

	spin_lock(&j->lock);

	/*
	 * Recheck after taking the lock, so we don't race with another thread
	 * that just did journal_entry_open() and call journal_entry_close()
	 * unnecessarily
	 */
	if (journal_res_get_fast(j, res, flags)) {
		spin_unlock(&j->lock);
		return 0;
	}

	if (!(flags & JOURNAL_RES_GET_RESERVED) &&
	    !test_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags)) {
		/*
		 * Don't want to close current journal entry, just need to
		 * invoke reclaim:
		 */
		ret = -ENOSPC;
		goto unlock;
	}

	/*
	 * If we couldn't get a reservation because the current buf filled up,
	 * and we had room for a bigger entry on disk, signal that we want to
	 * realloc the journal bufs:
	 */
	buf = journal_cur_buf(j);
	if (journal_entry_is_open(j) &&
	    buf->buf_size >> 9 < buf->disk_sectors &&
	    buf->buf_size < JOURNAL_ENTRY_SIZE_MAX)
		j->buf_size_want = max(j->buf_size_want, buf->buf_size << 1);

	if (journal_entry_is_open(j) &&
	    !__journal_entry_close(j)) {
		/*
		 * We failed to get a reservation on the current open journal
		 * entry because it's full, and we can't close it because
		 * there's still a previous one in flight:
		 */
		trace_journal_entry_full(c);
		ret = -EAGAIN;
	} else {
		ret = journal_entry_open(j);
	}
unlock:
	if ((ret == -EAGAIN || ret == -ENOSPC) &&
	    !j->res_get_blocked_start)
		j->res_get_blocked_start = local_clock() ?: 1;

	can_discard = j->can_discard;
	spin_unlock(&j->lock);

	if (!ret)
		goto retry;

	if (ret == -ENOSPC) {
		BUG_ON(!can_discard && (flags & JOURNAL_RES_GET_RESERVED));

		/*
		 * Journal is full - can't rely on reclaim from work item due to
		 * freezing:
		 */
		trace_journal_full(c);

		if (!(flags & JOURNAL_RES_GET_NONBLOCK)) {
			if (can_discard) {
				bch2_journal_do_discards(j);
				goto retry;
			}

			if (mutex_trylock(&j->reclaim_lock)) {
				bch2_journal_reclaim(j);
				mutex_unlock(&j->reclaim_lock);
			}
		}

		ret = -EAGAIN;
	}

	return ret;
}

/*
 * Essentially the entry function to the journaling code. When bcachefs is doing
 * a btree insert, it calls this function to get the current journal write.
 * Journal write is the structure used set up journal writes. The calling
 * function will then add its keys to the structure, queuing them for the next
 * write.
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks.
 */
int bch2_journal_res_get_slowpath(struct journal *j, struct journal_res *res,
				  unsigned flags)
{
	int ret;

	closure_wait_event(&j->async_wait,
		   (ret = __journal_res_get(j, res, flags)) != -EAGAIN ||
		   (flags & JOURNAL_RES_GET_NONBLOCK));
	return ret;
}

/* journal_preres: */

static bool journal_preres_available(struct journal *j,
				     struct journal_preres *res,
				     unsigned new_u64s)
{
	bool ret = bch2_journal_preres_get_fast(j, res, new_u64s);

	if (!ret)
		bch2_journal_reclaim_work(&j->reclaim_work.work);

	return ret;
}

int __bch2_journal_preres_get(struct journal *j,
			      struct journal_preres *res,
			      unsigned new_u64s)
{
	int ret;

	closure_wait_event(&j->preres_wait,
		   (ret = bch2_journal_error(j)) ||
		   journal_preres_available(j, res, new_u64s));
	return ret;
}

/* journal_entry_res: */

void bch2_journal_entry_res_resize(struct journal *j,
				   struct journal_entry_res *res,
				   unsigned new_u64s)
{
	union journal_res_state state;
	int d = new_u64s - res->u64s;

	spin_lock(&j->lock);

	j->entry_u64s_reserved += d;
	if (d <= 0)
		goto out;

	j->cur_entry_u64s = max_t(int, 0, j->cur_entry_u64s - d);
	smp_mb();
	state = READ_ONCE(j->reservations);

	if (state.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL &&
	    state.cur_entry_offset > j->cur_entry_u64s) {
		j->cur_entry_u64s += d;
		/*
		 * Not enough room in current journal entry, have to flush it:
		 */
		__journal_entry_close(j);
	} else {
		journal_cur_buf(j)->u64s_reserved += d;
	}
out:
	spin_unlock(&j->lock);
	res->u64s += d;
}

/* journal flushing: */

u64 bch2_journal_last_unwritten_seq(struct journal *j)
{
	u64 seq;

	spin_lock(&j->lock);
	seq = journal_cur_seq(j);
	if (j->reservations.prev_buf_unwritten)
		seq--;
	spin_unlock(&j->lock);

	return seq;
}

/**
 * bch2_journal_open_seq_async - try to open a new journal entry if @seq isn't
 * open yet, or wait if we cannot
 *
 * used by the btree interior update machinery, when it needs to write a new
 * btree root - every journal entry contains the roots of all the btrees, so it
 * doesn't need to bother with getting a journal reservation
 */
int bch2_journal_open_seq_async(struct journal *j, u64 seq, struct closure *cl)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	int ret;

	spin_lock(&j->lock);

	/*
	 * Can't try to open more than one sequence number ahead:
	 */
	BUG_ON(journal_cur_seq(j) < seq && !journal_entry_is_open(j));

	if (journal_cur_seq(j) > seq ||
	    journal_entry_is_open(j)) {
		spin_unlock(&j->lock);
		return 0;
	}

	if (journal_cur_seq(j) < seq &&
	    !__journal_entry_close(j)) {
		/* haven't finished writing out the previous one: */
		trace_journal_entry_full(c);
		ret = -EAGAIN;
	} else {
		BUG_ON(journal_cur_seq(j) != seq);

		ret = journal_entry_open(j);
	}

	if ((ret == -EAGAIN || ret == -ENOSPC) &&
	    !j->res_get_blocked_start)
		j->res_get_blocked_start = local_clock() ?: 1;

	if (ret == -EAGAIN || ret == -ENOSPC)
		closure_wait(&j->async_wait, cl);

	spin_unlock(&j->lock);

	if (ret == -ENOSPC) {
		trace_journal_full(c);
		bch2_journal_reclaim_work(&j->reclaim_work.work);
		ret = -EAGAIN;
	}

	return ret;
}

static int journal_seq_error(struct journal *j, u64 seq)
{
	union journal_res_state state = READ_ONCE(j->reservations);

	if (seq == journal_cur_seq(j))
		return bch2_journal_error(j);

	if (seq + 1 == journal_cur_seq(j) &&
	    !state.prev_buf_unwritten &&
	    seq > j->seq_ondisk)
		return -EIO;

	return 0;
}

static inline struct journal_buf *
journal_seq_to_buf(struct journal *j, u64 seq)
{
	/* seq should be for a journal entry that has been opened: */
	BUG_ON(seq > journal_cur_seq(j));
	BUG_ON(seq == journal_cur_seq(j) &&
	       j->reservations.cur_entry_offset == JOURNAL_ENTRY_CLOSED_VAL);

	if (seq == journal_cur_seq(j))
		return journal_cur_buf(j);
	if (seq + 1 == journal_cur_seq(j) &&
	    j->reservations.prev_buf_unwritten)
		return journal_prev_buf(j);
	return NULL;
}

/**
 * bch2_journal_wait_on_seq - wait for a journal entry to be written
 *
 * does _not_ cause @seq to be written immediately - if there is no other
 * activity to cause the relevant journal entry to be filled up or flushed it
 * can wait for an arbitrary amount of time (up to @j->write_delay_ms, which is
 * configurable).
 */
void bch2_journal_wait_on_seq(struct journal *j, u64 seq,
			      struct closure *parent)
{
	struct journal_buf *buf;

	spin_lock(&j->lock);

	if ((buf = journal_seq_to_buf(j, seq))) {
		if (!closure_wait(&buf->wait, parent))
			BUG();

		if (seq == journal_cur_seq(j)) {
			smp_mb();
			if (bch2_journal_error(j))
				closure_wake_up(&buf->wait);
		}
	}

	spin_unlock(&j->lock);
}

/**
 * bch2_journal_flush_seq_async - wait for a journal entry to be written
 *
 * like bch2_journal_wait_on_seq, except that it triggers a write immediately if
 * necessary
 */
void bch2_journal_flush_seq_async(struct journal *j, u64 seq,
				  struct closure *parent)
{
	struct journal_buf *buf;

	spin_lock(&j->lock);

	if (parent &&
	    (buf = journal_seq_to_buf(j, seq)))
		if (!closure_wait(&buf->wait, parent))
			BUG();

	if (seq == journal_cur_seq(j))
		__journal_entry_close(j);
	spin_unlock(&j->lock);
}

static int journal_seq_flushed(struct journal *j, u64 seq)
{
	int ret;

	spin_lock(&j->lock);
	ret = seq <= j->seq_ondisk ? 1 : journal_seq_error(j, seq);

	if (seq == journal_cur_seq(j))
		__journal_entry_close(j);
	spin_unlock(&j->lock);

	return ret;
}

int bch2_journal_flush_seq(struct journal *j, u64 seq)
{
	u64 start_time = local_clock();
	int ret, ret2;

	ret = wait_event_killable(j->wait, (ret2 = journal_seq_flushed(j, seq)));

	bch2_time_stats_update(j->flush_seq_time, start_time);

	return ret ?: ret2 < 0 ? ret2 : 0;
}

/**
 * bch2_journal_meta_async - force a journal entry to be written
 */
void bch2_journal_meta_async(struct journal *j, struct closure *parent)
{
	struct journal_res res;

	memset(&res, 0, sizeof(res));

	bch2_journal_res_get(j, &res, jset_u64s(0), 0);
	bch2_journal_res_put(j, &res);

	bch2_journal_flush_seq_async(j, res.seq, parent);
}

int bch2_journal_meta(struct journal *j)
{
	struct journal_res res;
	int ret;

	memset(&res, 0, sizeof(res));

	ret = bch2_journal_res_get(j, &res, jset_u64s(0), 0);
	if (ret)
		return ret;

	bch2_journal_res_put(j, &res);

	return bch2_journal_flush_seq(j, res.seq);
}

/*
 * bch2_journal_flush_async - if there is an open journal entry, or a journal
 * still being written, write it and wait for the write to complete
 */
void bch2_journal_flush_async(struct journal *j, struct closure *parent)
{
	u64 seq, journal_seq;

	spin_lock(&j->lock);
	journal_seq = journal_cur_seq(j);

	if (journal_entry_is_open(j)) {
		seq = journal_seq;
	} else if (journal_seq) {
		seq = journal_seq - 1;
	} else {
		spin_unlock(&j->lock);
		return;
	}
	spin_unlock(&j->lock);

	bch2_journal_flush_seq_async(j, seq, parent);
}

int bch2_journal_flush(struct journal *j)
{
	u64 seq, journal_seq;

	spin_lock(&j->lock);
	journal_seq = journal_cur_seq(j);

	if (journal_entry_is_open(j)) {
		seq = journal_seq;
	} else if (journal_seq) {
		seq = journal_seq - 1;
	} else {
		spin_unlock(&j->lock);
		return 0;
	}
	spin_unlock(&j->lock);

	return bch2_journal_flush_seq(j, seq);
}

/* block/unlock the journal: */

void bch2_journal_unblock(struct journal *j)
{
	spin_lock(&j->lock);
	j->blocked--;
	spin_unlock(&j->lock);

	journal_wake(j);
}

void bch2_journal_block(struct journal *j)
{
	spin_lock(&j->lock);
	j->blocked++;
	spin_unlock(&j->lock);

	journal_quiesce(j);
}

/* allocate journal on a device: */

static int __bch2_set_nr_journal_buckets(struct bch_dev *ca, unsigned nr,
					 bool new_fs, struct closure *cl)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets;
	u64 *new_bucket_seq = NULL, *new_buckets = NULL;
	int ret = 0;

	/* don't handle reducing nr of buckets yet: */
	if (nr <= ja->nr)
		return 0;

	ret = -ENOMEM;
	new_buckets	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	new_bucket_seq	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	if (!new_buckets || !new_bucket_seq)
		goto err;

	journal_buckets = bch2_sb_resize_journal(&ca->disk_sb,
						 nr + sizeof(*journal_buckets) / sizeof(u64));
	if (!journal_buckets)
		goto err;

	/*
	 * We may be called from the device add path, before the new device has
	 * actually been added to the running filesystem:
	 */
	if (c)
		spin_lock(&c->journal.lock);

	memcpy(new_buckets,	ja->buckets,	ja->nr * sizeof(u64));
	memcpy(new_bucket_seq,	ja->bucket_seq,	ja->nr * sizeof(u64));
	swap(new_buckets,	ja->buckets);
	swap(new_bucket_seq,	ja->bucket_seq);

	if (c)
		spin_unlock(&c->journal.lock);

	while (ja->nr < nr) {
		struct open_bucket *ob = NULL;
		unsigned pos;
		long bucket;

		if (new_fs) {
			bucket = bch2_bucket_alloc_new_fs(ca);
			if (bucket < 0) {
				ret = -ENOSPC;
				goto err;
			}
		} else {
			ob = bch2_bucket_alloc(c, ca, RESERVE_ALLOC,
					       false, cl);
			if (IS_ERR(ob)) {
				ret = cl ? -EAGAIN : -ENOSPC;
				goto err;
			}

			bucket = sector_to_bucket(ca, ob->ptr.offset);
		}

		if (c) {
			percpu_down_read(&c->mark_lock);
			spin_lock(&c->journal.lock);
		}

		pos = ja->nr ? (ja->cur_idx + 1) % ja->nr : 0;
		__array_insert_item(ja->buckets,		ja->nr, pos);
		__array_insert_item(ja->bucket_seq,		ja->nr, pos);
		__array_insert_item(journal_buckets->buckets,	ja->nr, pos);
		ja->nr++;

		ja->buckets[pos] = bucket;
		ja->bucket_seq[pos] = 0;
		journal_buckets->buckets[pos] = cpu_to_le64(bucket);

		if (pos <= ja->discard_idx)
			ja->discard_idx = (ja->discard_idx + 1) % ja->nr;
		if (pos <= ja->dirty_idx_ondisk)
			ja->dirty_idx_ondisk = (ja->dirty_idx_ondisk + 1) % ja->nr;
		if (pos <= ja->dirty_idx)
			ja->dirty_idx = (ja->dirty_idx + 1) % ja->nr;
		if (pos <= ja->cur_idx)
			ja->cur_idx = (ja->cur_idx + 1) % ja->nr;

		bch2_mark_metadata_bucket(c, ca, bucket, BCH_DATA_JOURNAL,
					  ca->mi.bucket_size,
					  gc_phase(GC_PHASE_SB),
					  0);

		if (c) {
			spin_unlock(&c->journal.lock);
			percpu_up_read(&c->mark_lock);
		}

		if (!new_fs)
			bch2_open_bucket_put(c, ob);
	}

	ret = 0;
err:
	kfree(new_bucket_seq);
	kfree(new_buckets);

	return ret;
}

/*
 * Allocate more journal space at runtime - not currently making use if it, but
 * the code works:
 */
int bch2_set_nr_journal_buckets(struct bch_fs *c, struct bch_dev *ca,
				unsigned nr)
{
	struct journal_device *ja = &ca->journal;
	struct closure cl;
	unsigned current_nr;
	int ret;

	closure_init_stack(&cl);

	do {
		struct disk_reservation disk_res = { 0, 0 };

		closure_sync(&cl);

		mutex_lock(&c->sb_lock);
		current_nr = ja->nr;

		/*
		 * note: journal buckets aren't really counted as _sectors_ used yet, so
		 * we don't need the disk reservation to avoid the BUG_ON() in buckets.c
		 * when space used goes up without a reservation - but we do need the
		 * reservation to ensure we'll actually be able to allocate:
		 */

		if (bch2_disk_reservation_get(c, &disk_res,
					      bucket_to_sector(ca, nr - ja->nr), 1, 0)) {
			mutex_unlock(&c->sb_lock);
			return -ENOSPC;
		}

		ret = __bch2_set_nr_journal_buckets(ca, nr, false, &cl);

		bch2_disk_reservation_put(c, &disk_res);

		if (ja->nr != current_nr)
			bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
	} while (ret == -EAGAIN);

	return ret;
}

int bch2_dev_journal_alloc(struct bch_dev *ca)
{
	unsigned nr;

	if (dynamic_fault("bcachefs:add:journal_alloc"))
		return -ENOMEM;

	/*
	 * clamp journal size to 1024 buckets or 512MB (in sectors), whichever
	 * is smaller:
	 */
	nr = clamp_t(unsigned, ca->mi.nbuckets >> 8,
		     BCH_JOURNAL_BUCKETS_MIN,
		     min(1 << 10,
			 (1 << 20) / ca->mi.bucket_size));

	return __bch2_set_nr_journal_buckets(ca, nr, true, NULL);
}

/* startup/shutdown: */

static bool bch2_journal_writing_to_device(struct journal *j, unsigned dev_idx)
{
	union journal_res_state state;
	struct journal_buf *w;
	bool ret;

	spin_lock(&j->lock);
	state = READ_ONCE(j->reservations);
	w = j->buf + !state.idx;

	ret = state.prev_buf_unwritten &&
		bch2_extent_has_device(bkey_i_to_s_c_extent(&w->key), dev_idx);
	spin_unlock(&j->lock);

	return ret;
}

void bch2_dev_journal_stop(struct journal *j, struct bch_dev *ca)
{
	wait_event(j->wait, !bch2_journal_writing_to_device(j, ca->dev_idx));
}

void bch2_fs_journal_stop(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	wait_event(j->wait, journal_entry_close(j));

	/* do we need to write another journal entry? */
	if (test_bit(JOURNAL_NOT_EMPTY, &j->flags) ||
	    c->btree_roots_dirty)
		bch2_journal_meta(j);

	journal_quiesce(j);

	BUG_ON(!bch2_journal_error(j) &&
	       test_bit(JOURNAL_NOT_EMPTY, &j->flags));

	cancel_delayed_work_sync(&j->write_work);
	cancel_delayed_work_sync(&j->reclaim_work);
}

void bch2_fs_journal_start(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_seq_blacklist *bl;
	u64 blacklist = 0;

	list_for_each_entry(bl, &j->seq_blacklist, list)
		blacklist = max(blacklist, bl->end);

	spin_lock(&j->lock);

	set_bit(JOURNAL_STARTED, &j->flags);

	while (journal_cur_seq(j) < blacklist)
		journal_pin_new_entry(j, 0);

	/*
	 * __journal_entry_close() only inits the next journal entry when it
	 * closes an open journal entry - the very first journal entry gets
	 * initialized here:
	 */
	journal_pin_new_entry(j, 1);
	bch2_journal_buf_init(j);

	c->last_bucket_seq_cleanup = journal_cur_seq(j);

	bch2_journal_space_available(j);
	spin_unlock(&j->lock);

	/*
	 * Adding entries to the next journal entry before allocating space on
	 * disk for the next journal entry - this is ok, because these entries
	 * only have to go down with the next journal entry we write:
	 */
	bch2_journal_seq_blacklist_write(j);
}

/* init/exit: */

void bch2_dev_journal_exit(struct bch_dev *ca)
{
	kfree(ca->journal.bio);
	kfree(ca->journal.buckets);
	kfree(ca->journal.bucket_seq);

	ca->journal.bio		= NULL;
	ca->journal.buckets	= NULL;
	ca->journal.bucket_seq	= NULL;
}

int bch2_dev_journal_init(struct bch_dev *ca, struct bch_sb *sb)
{
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets =
		bch2_sb_get_journal(sb);
	unsigned i, nr_bvecs;

	ja->nr = bch2_nr_journal_buckets(journal_buckets);

	ja->bucket_seq = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->bucket_seq)
		return -ENOMEM;

	nr_bvecs = DIV_ROUND_UP(JOURNAL_ENTRY_SIZE_MAX, PAGE_SIZE);

	ca->journal.bio = bio_kmalloc(nr_bvecs, GFP_KERNEL);
	if (!ca->journal.bio)
		return -ENOMEM;

	bio_init(ca->journal.bio, NULL, ca->journal.bio->bi_inline_vecs, nr_bvecs, 0);

	ja->buckets = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->buckets)
		return -ENOMEM;

	for (i = 0; i < ja->nr; i++)
		ja->buckets[i] = le64_to_cpu(journal_buckets->buckets[i]);

	return 0;
}

void bch2_fs_journal_exit(struct journal *j)
{
	kvpfree(j->buf[1].data, j->buf[1].buf_size);
	kvpfree(j->buf[0].data, j->buf[0].buf_size);
	free_fifo(&j->pin);
}

int bch2_fs_journal_init(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	static struct lock_class_key res_key;
	int ret = 0;

	pr_verbose_init(c->opts, "");

	spin_lock_init(&j->lock);
	spin_lock_init(&j->err_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_DELAYED_WORK(&j->reclaim_work, bch2_journal_reclaim_work);
	init_waitqueue_head(&j->pin_flush_wait);
	mutex_init(&j->blacklist_lock);
	INIT_LIST_HEAD(&j->seq_blacklist);
	mutex_init(&j->reclaim_lock);
	mutex_init(&j->discard_lock);

	lockdep_init_map(&j->res_map, "journal res", &res_key, 0);

	j->buf[0].buf_size	= JOURNAL_ENTRY_SIZE_MIN;
	j->buf[1].buf_size	= JOURNAL_ENTRY_SIZE_MIN;
	j->write_delay_ms	= 1000;
	j->reclaim_delay_ms	= 100;

	/* Btree roots: */
	j->entry_u64s_reserved +=
		BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_U64s_MAX);

	atomic64_set(&j->reservations.counter,
		((union journal_res_state)
		 { .cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL }).v);

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->buf[0].data = kvpmalloc(j->buf[0].buf_size, GFP_KERNEL)) ||
	    !(j->buf[1].data = kvpmalloc(j->buf[1].buf_size, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}

	j->pin.front = j->pin.back = 1;
out:
	pr_verbose_init(c->opts, "ret %i", ret);
	return ret;
}

/* debug: */

ssize_t bch2_journal_print_debug(struct journal *j, char *buf)
{
	struct printbuf out = _PBUF(buf, PAGE_SIZE);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	union journal_res_state s;
	struct bch_dev *ca;
	unsigned iter;

	rcu_read_lock();
	spin_lock(&j->lock);
	s = READ_ONCE(j->reservations);

	pr_buf(&out,
	       "active journal entries:\t%llu\n"
	       "seq:\t\t\t%llu\n"
	       "last_seq:\t\t%llu\n"
	       "last_seq_ondisk:\t%llu\n"
	       "prereserved:\t\t%u/%u\n"
	       "current entry sectors:\t%u\n"
	       "current entry:\t\t",
	       fifo_used(&j->pin),
	       journal_cur_seq(j),
	       journal_last_seq(j),
	       j->last_seq_ondisk,
	       j->prereserved.reserved,
	       j->prereserved.remaining,
	       j->cur_entry_sectors);

	switch (s.cur_entry_offset) {
	case JOURNAL_ENTRY_ERROR_VAL:
		pr_buf(&out, "error\n");
		break;
	case JOURNAL_ENTRY_CLOSED_VAL:
		pr_buf(&out, "closed\n");
		break;
	default:
		pr_buf(&out, "%u/%u\n",
		       s.cur_entry_offset,
		       j->cur_entry_u64s);
		break;
	}

	pr_buf(&out,
	       "current entry refs:\t%u\n"
	       "prev entry unwritten:\t",
	       journal_state_count(s, s.idx));

	if (s.prev_buf_unwritten)
		pr_buf(&out, "yes, ref %u sectors %u\n",
		       journal_state_count(s, !s.idx),
		       journal_prev_buf(j)->sectors);
	else
		pr_buf(&out, "no\n");

	pr_buf(&out,
	       "need write:\t\t%i\n"
	       "replay done:\t\t%i\n",
	       test_bit(JOURNAL_NEED_WRITE,	&j->flags),
	       test_bit(JOURNAL_REPLAY_DONE,	&j->flags));

	for_each_member_device_rcu(ca, c, iter,
				   &c->rw_devs[BCH_DATA_JOURNAL]) {
		struct journal_device *ja = &ca->journal;

		if (!ja->nr)
			continue;

		pr_buf(&out,
		       "dev %u:\n"
		       "\tnr\t\t%u\n"
		       "\tavailable\t%u:%u\n"
		       "\tdiscard_idx\t\t%u\n"
		       "\tdirty_idx_ondisk\t%u (seq %llu)\n"
		       "\tdirty_idx\t\t%u (seq %llu)\n"
		       "\tcur_idx\t\t%u (seq %llu)\n",
		       iter, ja->nr,
		       bch2_journal_dev_buckets_available(j, ja, journal_space_discarded),
		       ja->sectors_free,
		       ja->discard_idx,
		       ja->dirty_idx_ondisk,	ja->bucket_seq[ja->dirty_idx_ondisk],
		       ja->dirty_idx,		ja->bucket_seq[ja->dirty_idx],
		       ja->cur_idx,		ja->bucket_seq[ja->cur_idx]);
	}

	spin_unlock(&j->lock);
	rcu_read_unlock();

	return out.pos - buf;
}

ssize_t bch2_journal_print_pins(struct journal *j, char *buf)
{
	struct printbuf out = _PBUF(buf, PAGE_SIZE);
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *pin;
	u64 i;

	spin_lock(&j->lock);
	fifo_for_each_entry_ptr(pin_list, &j->pin, i) {
		pr_buf(&out, "%llu: count %u\n",
		       i, atomic_read(&pin_list->count));

		list_for_each_entry(pin, &pin_list->list, list)
			pr_buf(&out, "\t%p %pf\n",
			       pin, pin->flush);

		if (!list_empty(&pin_list->flushed))
			pr_buf(&out, "flushed:\n");

		list_for_each_entry(pin, &pin_list->flushed, list)
			pr_buf(&out, "\t%p %pf\n",
			       pin, pin->flush);
	}
	spin_unlock(&j->lock);

	return out.pos - buf;
}
