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
#include "btree_update.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "enumerated_ref.h"
#include "error.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "journal_sb.h"
#include "journal_seq_blacklist.h"
#include "trace.h"

static inline bool journal_seq_unwritten(struct journal *j, u64 seq)
{
	return seq > j->seq_ondisk;
}

static bool __journal_entry_is_open(union journal_res_state state)
{
	return state.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL;
}

static inline unsigned nr_unwritten_journal_entries(struct journal *j)
{
	return atomic64_read(&j->seq) - j->seq_ondisk;
}

static bool journal_entry_is_open(struct journal *j)
{
	return __journal_entry_is_open(j->reservations);
}

static void bch2_journal_buf_to_text(struct printbuf *out, struct journal *j, u64 seq)
{
	union journal_res_state s = READ_ONCE(j->reservations);
	unsigned i = seq & JOURNAL_BUF_MASK;
	struct journal_buf *buf = j->buf + i;

	prt_printf(out, "seq:\t%llu\n", seq);
	printbuf_indent_add(out, 2);

	if (!buf->write_started)
		prt_printf(out, "refcount:\t%u\n", journal_state_count(s, i & JOURNAL_STATE_BUF_MASK));

	struct closure *cl = &buf->io;
	int r = atomic_read(&cl->remaining);
	prt_printf(out, "io:\t%pS r %i\n", cl->fn, r & CLOSURE_REMAINING_MASK);

	if (buf->data) {
		prt_printf(out, "size:\t");
		prt_human_readable_u64(out, vstruct_bytes(buf->data));
		prt_newline(out);
	}

	prt_printf(out, "expires:\t%li jiffies\n", buf->expires - jiffies);

	prt_printf(out, "flags:\t");
	if (buf->noflush)
		prt_str(out, "noflush ");
	if (buf->must_flush)
		prt_str(out, "must_flush ");
	if (buf->separate_flush)
		prt_str(out, "separate_flush ");
	if (buf->need_flush_to_write_buffer)
		prt_str(out, "need_flush_to_write_buffer ");
	if (buf->write_started)
		prt_str(out, "write_started ");
	if (buf->write_allocated)
		prt_str(out, "write_allocated ");
	if (buf->write_done)
		prt_str(out, "write_done");
	prt_newline(out);

	printbuf_indent_sub(out, 2);
}

static void bch2_journal_bufs_to_text(struct printbuf *out, struct journal *j)
{
	lockdep_assert_held(&j->lock);
	guard(printbuf_atomic)(out);

	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 24);

	for (u64 seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++)
		bch2_journal_buf_to_text(out, j, seq);
	prt_printf(out, "last buf %s\n", journal_entry_is_open(j) ? "open" : "closed");
}

static inline struct journal_buf *
journal_seq_to_buf(struct journal *j, u64 seq)
{
	struct journal_buf *buf = NULL;

	EBUG_ON(seq > journal_cur_seq(j));

	if (journal_seq_unwritten(j, seq))
		buf = j->buf + (seq & JOURNAL_BUF_MASK);
	return buf;
}

static void journal_pin_list_init(struct journal_entry_pin_list *p, int count)
{
	for (unsigned i = 0; i < ARRAY_SIZE(p->unflushed); i++)
		INIT_LIST_HEAD(&p->unflushed[i]);
	for (unsigned i = 0; i < ARRAY_SIZE(p->flushed); i++)
		INIT_LIST_HEAD(&p->flushed[i]);
	atomic_set(&p->count, count);
	p->devs.nr = 0;
	p->bytes = 0;
}

/*
 * Detect stuck journal conditions and trigger shutdown. Technically the journal
 * can end up stuck for a variety of reasons, such as a blocked I/O, journal
 * reservation lockup, etc. Since this is a fatal error with potentially
 * unpredictable characteristics, we want to be fairly conservative before we
 * decide to shut things down.
 *
 * Consider the journal stuck when it appears full with no ability to commit
 * btree transactions, to discard journal buckets, nor acquire priority
 * (reserved watermark) reservation.
 */
static inline bool
journal_error_check_stuck(struct journal *j, int error, unsigned flags)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	bool stuck = false;
	CLASS(printbuf, buf)();

	guard(printbuf_atomic)(&buf);

	if (!(error == -BCH_ERR_journal_full ||
	      error == -BCH_ERR_journal_pin_full) ||
	    nr_unwritten_journal_entries(j) ||
	    (flags & BCH_WATERMARK_MASK) != BCH_WATERMARK_reclaim)
		return stuck;

	scoped_guard(spinlock, &j->lock) {
		if (j->can_discard)
			return stuck;

		stuck = true;

		/*
		 * The journal shutdown path will set ->err_seq, but do it here first to
		 * serialize against concurrent failures and avoid duplicate error
		 * reports.
		 */
		if (j->err_seq)
			return stuck;

		j->err_seq = journal_cur_seq(j);

		__bch2_journal_debug_to_text(&buf, j);
	}
	prt_printf(&buf, bch2_fmt(c, "Journal stuck! Hava a pre-reservation but journal full (error %s)"),
				  bch2_err_str(error));
	bch2_print_str(c, KERN_ERR, buf.buf);

	printbuf_reset(&buf);
	bch2_journal_pins_to_text(&buf, j);
	bch_err(c, "Journal pins:\n%s", buf.buf);

	bch2_fatal_error(c);
	dump_stack();

	return stuck;
}

void bch2_journal_do_writes(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	for (u64 seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++) {
		unsigned idx = seq & JOURNAL_BUF_MASK;
		struct journal_buf *w = j->buf + idx;

		if (w->write_started && !w->write_allocated)
			break;
		if (w->write_started)
			continue;

		if (!journal_state_seq_count(j, j->reservations, seq)) {
			j->seq_write_started = seq;
			w->write_started = true;
			closure_get(&c->cl);
			closure_call(&w->io, bch2_journal_write, j->wq, NULL);
		}

		break;
	}
}

/*
 * Final processing when the last reference of a journal buffer has been
 * dropped. Drop the pin list reference acquired at journal entry open and write
 * the buffer, if requested.
 */
void bch2_journal_buf_put_final(struct journal *j, u64 seq)
{
	lockdep_assert_held(&j->lock);

	if (__bch2_journal_pin_put(j, seq))
		bch2_journal_reclaim_fast(j);
	bch2_journal_do_writes(j);

	/*
	 * for __bch2_next_write_buffer_flush_journal_buf(), when quiescing an
	 * open journal entry
	 */
	wake_up(&j->wait);
}

/*
 * Returns true if journal entry is now closed:
 *
 * We don't close a journal_buf until the next journal_buf is finished writing,
 * and can be opened again - this also initializes the next journal_buf:
 */
static void __journal_entry_close(struct journal *j, unsigned closed_val, bool trace)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf = journal_cur_buf(j);
	union journal_res_state old, new;
	unsigned sectors;

	BUG_ON(closed_val != JOURNAL_ENTRY_CLOSED_VAL &&
	       closed_val != JOURNAL_ENTRY_ERROR_VAL);

	lockdep_assert_held(&j->lock);

	old.v = atomic64_read(&j->reservations.counter);
	do {
		new.v = old.v;
		new.cur_entry_offset = closed_val;

		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL ||
		    old.cur_entry_offset == new.cur_entry_offset)
			return;
	} while (!atomic64_try_cmpxchg(&j->reservations.counter,
				       &old.v, new.v));

	if (!__journal_entry_is_open(old))
		return;

	if (old.cur_entry_offset == JOURNAL_ENTRY_BLOCKED_VAL)
		old.cur_entry_offset = j->cur_entry_offset_if_blocked;

	/* Close out old buffer: */
	buf->data->u64s		= cpu_to_le32(old.cur_entry_offset);

	struct journal_entry_pin_list *pin_list =
		journal_seq_pin(j, journal_cur_seq(j));
	pin_list->bytes = roundup_pow_of_two(vstruct_bytes(buf->data));
	j->dirty_entry_bytes += pin_list->bytes;

	if (trace_journal_entry_close_enabled() && trace) {
		CLASS(printbuf, err)();
		guard(printbuf_atomic)(&err);

		prt_str(&err, "entry size: ");
		prt_human_readable_u64(&err, vstruct_bytes(buf->data));
		prt_newline(&err);
		bch2_prt_task_backtrace(&err, current, 1, GFP_NOWAIT);
		trace_journal_entry_close(c, err.buf);
	}

	sectors = vstruct_blocks_plus(buf->data, c->block_bits,
				      buf->u64s_reserved) << c->block_bits;
	if (unlikely(sectors > buf->sectors)) {
		CLASS(printbuf, err)();
		guard(printbuf_atomic)(&err);

		prt_printf(&err, "journal entry overran reserved space: %u > %u\n",
			   sectors, buf->sectors);
		prt_printf(&err, "buf u64s %u u64s reserved %u cur_entry_u64s %u block_bits %u\n",
			   le32_to_cpu(buf->data->u64s), buf->u64s_reserved,
			   j->cur_entry_u64s,
			   c->block_bits);
		prt_printf(&err, "fatal error - emergency read only");
		bch2_journal_halt_locked(j);

		bch_err(c, "%s", err.buf);
		return;
	}

	buf->sectors = sectors;

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
	buf->last_seq		= journal_last_seq(j);
	buf->data->last_seq	= cpu_to_le64(buf->last_seq);
	BUG_ON(buf->last_seq > le64_to_cpu(buf->data->seq));

	cancel_delayed_work(&j->write_work);

	bch2_journal_space_available(j);

	__bch2_journal_buf_put(j, le64_to_cpu(buf->data->seq));
}

void bch2_journal_halt_locked(struct journal *j)
{
	lockdep_assert_held(&j->lock);

	__journal_entry_close(j, JOURNAL_ENTRY_ERROR_VAL, true);
	if (!j->err_seq)
		j->err_seq = journal_cur_seq(j);
	journal_wake(j);
}

void bch2_journal_halt(struct journal *j)
{
	guard(spinlock)(&j->lock);
	bch2_journal_halt_locked(j);
}

static bool journal_entry_want_write(struct journal *j)
{
	bool ret = !journal_entry_is_open(j) ||
		journal_cur_seq(j) == journal_last_unwritten_seq(j);

	/* Don't close it yet if we already have a write in flight: */
	if (ret)
		__journal_entry_close(j, JOURNAL_ENTRY_CLOSED_VAL, true);
	else if (nr_unwritten_journal_entries(j)) {
		struct journal_buf *buf = journal_cur_buf(j);

		if (!buf->flush_time) {
			buf->flush_time	= local_clock() ?: 1;
			buf->expires = jiffies;
		}
	}

	return ret;
}

bool bch2_journal_entry_close(struct journal *j)
{
	guard(spinlock)(&j->lock);
	return journal_entry_want_write(j);
}

/*
 * should _only_ called from journal_res_get() - when we actually want a
 * journal reservation - journal entry is open means journal is dirty:
 */
static int journal_entry_open(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf = j->buf +
		((journal_cur_seq(j) + 1) & JOURNAL_BUF_MASK);
	union journal_res_state old, new;
	int u64s;

	lockdep_assert_held(&j->lock);
	BUG_ON(journal_entry_is_open(j));
	BUG_ON(c->sb.clean);

	if (j->blocked)
		return bch_err_throw(c, journal_blocked);

	if (j->cur_entry_error)
		return j->cur_entry_error;

	int ret = bch2_journal_error(j);
	if (unlikely(ret))
		return ret;

	if (!fifo_free(&j->pin))
		return bch_err_throw(c, journal_pin_full);

	if (nr_unwritten_journal_entries(j) == ARRAY_SIZE(j->buf))
		return bch_err_throw(c, journal_max_in_flight);

	if (atomic64_read(&j->seq) - j->seq_write_started == JOURNAL_STATE_BUF_NR)
		return bch_err_throw(c, journal_max_open);

	if (unlikely(journal_cur_seq(j) >= JOURNAL_SEQ_MAX)) {
		bch_err(c, "cannot start: journal seq overflow");
		if (bch2_fs_emergency_read_only_locked(c))
			bch_err(c, "fatal error - emergency read only");
		return bch_err_throw(c, journal_shutdown);
	}

	if (!j->free_buf && !buf->data)
		return bch_err_throw(c, journal_buf_enomem); /* will retry after write completion frees up a buf */

	BUG_ON(!j->cur_entry_sectors);

	if (!buf->data) {
		swap(buf->data,		j->free_buf);
		swap(buf->buf_size,	j->free_buf_size);
	}

	buf->expires		=
		(journal_cur_seq(j) == j->flushed_seq_ondisk
		 ? jiffies
		 : j->last_flush_write) +
		msecs_to_jiffies(c->opts.journal_flush_delay);

	buf->u64s_reserved	= j->entry_u64s_reserved;
	buf->disk_sectors	= j->cur_entry_sectors;
	buf->sectors		= min(buf->disk_sectors, buf->buf_size >> 9);

	u64s = (int) (buf->sectors << 9) / sizeof(u64) -
		journal_entry_overhead(j);
	u64s = clamp_t(int, u64s, 0, JOURNAL_ENTRY_CLOSED_VAL - 1);

	if (u64s <= (ssize_t) j->early_journal_entries.nr)
		return bch_err_throw(c, journal_full);

	if (fifo_empty(&j->pin) && j->reclaim_thread)
		wake_up_process(j->reclaim_thread);

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for journal_last_seq() to be calculated correctly
	 */
	atomic64_inc(&j->seq);
	journal_pin_list_init(fifo_push_ref(&j->pin), 1);

	if (unlikely(bch2_journal_seq_is_blacklisted(c, journal_cur_seq(j), false))) {
		bch_err(c, "attempting to open blacklisted journal seq %llu",
			journal_cur_seq(j));
		if (bch2_fs_emergency_read_only_locked(c))
			bch_err(c, "fatal error - emergency read only");
		return bch_err_throw(c, journal_shutdown);
	}

	BUG_ON(j->pin.back - 1 != atomic64_read(&j->seq));

	BUG_ON(j->buf + (journal_cur_seq(j) & JOURNAL_BUF_MASK) != buf);

	bkey_extent_init(&buf->key);
	buf->noflush		= false;
	buf->must_flush		= false;
	buf->separate_flush	= false;
	buf->flush_time		= 0;
	buf->need_flush_to_write_buffer = true;
	buf->write_started	= false;
	buf->write_allocated	= false;
	buf->write_done		= false;

	memset(buf->data, 0, sizeof(*buf->data));
	buf->data->seq	= cpu_to_le64(journal_cur_seq(j));
	buf->data->u64s	= 0;

	if (j->early_journal_entries.nr) {
		memcpy(buf->data->_data, j->early_journal_entries.data,
		       j->early_journal_entries.nr * sizeof(u64));
		le32_add_cpu(&buf->data->u64s, j->early_journal_entries.nr);
	}

	/*
	 * Must be set before marking the journal entry as open:
	 */
	j->cur_entry_u64s = u64s;

	old.v = atomic64_read(&j->reservations.counter);
	do {
		new.v = old.v;

		BUG_ON(old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL);

		new.idx++;
		BUG_ON(journal_state_count(new, new.idx));
		BUG_ON(new.idx != (journal_cur_seq(j) & JOURNAL_STATE_BUF_MASK));

		journal_state_inc(&new);

		/* Handle any already added entries */
		new.cur_entry_offset = le32_to_cpu(buf->data->u64s);
	} while (!atomic64_try_cmpxchg(&j->reservations.counter,
				       &old.v, new.v));

	if (nr_unwritten_journal_entries(j) == 1)
		mod_delayed_work(j->wq,
				 &j->write_work,
				 msecs_to_jiffies(c->opts.journal_flush_delay));
	journal_wake(j);

	if (j->early_journal_entries.nr)
		darray_exit(&j->early_journal_entries);
	return 0;
}

static bool journal_quiesced(struct journal *j)
{
	bool ret = atomic64_read(&j->seq) == j->seq_ondisk;

	if (!ret)
		bch2_journal_entry_close(j);
	return ret;
}

static void journal_quiesce(struct journal *j)
{
	wait_event(j->wait, journal_quiesced(j));
}

static void journal_write_work(struct work_struct *work)
{
	struct journal *j = container_of(work, struct journal, write_work.work);

	guard(spinlock)(&j->lock);
	if (__journal_entry_is_open(j->reservations)) {
		long delta = journal_cur_buf(j)->expires - jiffies;

		if (delta > 0)
			mod_delayed_work(j->wq, &j->write_work, delta);
		else
			__journal_entry_close(j, JOURNAL_ENTRY_CLOSED_VAL, true);
	}
}

static void journal_buf_prealloc(struct journal *j)
{
	if (j->free_buf &&
	    j->free_buf_size >= j->buf_size_want)
		return;

	unsigned buf_size = j->buf_size_want;

	spin_unlock(&j->lock);
	void *buf = kvmalloc(buf_size, GFP_NOFS);
	spin_lock(&j->lock);

	if (buf &&
	    (!j->free_buf ||
	     buf_size > j->free_buf_size)) {
		swap(buf,	j->free_buf);
		swap(buf_size,	j->free_buf_size);
	}

	if (unlikely(buf)) {
		spin_unlock(&j->lock);
		/* kvfree can sleep */
		kvfree(buf);
		spin_lock(&j->lock);
	}
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

	ret = bch2_journal_error(j);
	if (unlikely(ret))
		return ret;

	if (j->blocked)
		return bch_err_throw(c, journal_blocked);

	if ((flags & BCH_WATERMARK_MASK) < j->watermark) {
		ret = bch_err_throw(c, journal_full);
		can_discard = j->can_discard;
		goto out;
	}

	if (nr_unwritten_journal_entries(j) == ARRAY_SIZE(j->buf) && !journal_entry_is_open(j)) {
		ret = bch_err_throw(c, journal_max_in_flight);
		goto out;
	}

	spin_lock(&j->lock);

	journal_buf_prealloc(j);

	/*
	 * Recheck after taking the lock, so we don't race with another thread
	 * that just did journal_entry_open() and call bch2_journal_entry_close()
	 * unnecessarily
	 */
	if (journal_res_get_fast(j, res, flags)) {
		ret = 0;
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

	__journal_entry_close(j, JOURNAL_ENTRY_CLOSED_VAL, false);
	ret = journal_entry_open(j) ?: -BCH_ERR_journal_retry_open;
unlock:
	can_discard = j->can_discard;
	spin_unlock(&j->lock);
out:
	if (likely(!ret))
		return 0;
	if (ret == -BCH_ERR_journal_retry_open)
		goto retry;

	if (journal_error_check_stuck(j, ret, flags))
		ret = bch_err_throw(c, journal_stuck);

	if (ret == -BCH_ERR_journal_max_in_flight &&
	    track_event_change(&c->times[BCH_TIME_blocked_journal_max_in_flight], true) &&
	    trace_journal_entry_full_enabled()) {
		CLASS(printbuf, buf)();

		bch2_printbuf_make_room(&buf, 4096);

		scoped_guard(spinlock, &j->lock) {
			prt_printf(&buf, "seq %llu\n", journal_cur_seq(j));
			bch2_journal_bufs_to_text(&buf, j);
		}

		trace_journal_entry_full(c, buf.buf);
		count_event(c, journal_entry_full);
	}

	if (ret == -BCH_ERR_journal_max_open &&
	    track_event_change(&c->times[BCH_TIME_blocked_journal_max_open], true) &&
	    trace_journal_entry_full_enabled()) {
		CLASS(printbuf, buf)();

		bch2_printbuf_make_room(&buf, 4096);

		scoped_guard(spinlock, &j->lock) {
			prt_printf(&buf, "seq %llu\n", journal_cur_seq(j));
			bch2_journal_bufs_to_text(&buf, j);
		}

		trace_journal_entry_full(c, buf.buf);
		count_event(c, journal_entry_full);
	}

	/*
	 * Journal is full - can't rely on reclaim from work item due to
	 * freezing:
	 */
	if ((ret == -BCH_ERR_journal_full ||
	     ret == -BCH_ERR_journal_pin_full) &&
	    !(flags & JOURNAL_RES_GET_NONBLOCK)) {
		if (can_discard) {
			bch2_journal_do_discards(j);
			goto retry;
		}

		if (mutex_trylock(&j->reclaim_lock)) {
			bch2_journal_reclaim(j);
			mutex_unlock(&j->reclaim_lock);
		}
	}

	return ret;
}

static unsigned max_dev_latency(struct bch_fs *c)
{
	u64 nsecs = 0;

	guard(rcu)();
	for_each_rw_member_rcu(c, ca)
		nsecs = max(nsecs, ca->io_latency[WRITE].stats.max_duration);

	return nsecs_to_jiffies(nsecs);
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
				  unsigned flags,
				  struct btree_trans *trans)
{
	int ret;

	if (closure_wait_event_timeout(&j->async_wait,
		   !bch2_err_matches(ret = __journal_res_get(j, res, flags), BCH_ERR_operation_blocked) ||
		   (flags & JOURNAL_RES_GET_NONBLOCK),
		   HZ))
		return ret;

	if (trans)
		bch2_trans_unlock_long(trans);

	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	int remaining_wait = max(max_dev_latency(c) * 2, HZ * 10);

	remaining_wait = max(0, remaining_wait - HZ);

	if (closure_wait_event_timeout(&j->async_wait,
		   !bch2_err_matches(ret = __journal_res_get(j, res, flags), BCH_ERR_operation_blocked) ||
		   (flags & JOURNAL_RES_GET_NONBLOCK),
		   remaining_wait))
		return ret;

	CLASS(printbuf, buf)();
	prt_printf(&buf, bch2_fmt(c, "Journal stuck? Waited for 10 seconds, err %s"), bch2_err_str(ret));
	bch2_journal_debug_to_text(&buf, j);
	bch2_print_str(c, KERN_ERR, buf.buf);

	closure_wait_event(&j->async_wait,
		   !bch2_err_matches(ret = __journal_res_get(j, res, flags), BCH_ERR_operation_blocked) ||
		   (flags & JOURNAL_RES_GET_NONBLOCK));
	return ret;
}

/* journal_entry_res: */

void bch2_journal_entry_res_resize(struct journal *j,
				   struct journal_entry_res *res,
				   unsigned new_u64s)
{
	union journal_res_state state;
	int d = new_u64s - res->u64s;

	guard(spinlock)(&j->lock);

	j->entry_u64s_reserved	+= d;
	res->u64s		+= d;

	if (d <= 0)
		return;

	j->cur_entry_u64s = max_t(int, 0, j->cur_entry_u64s - d);
	state = READ_ONCE(j->reservations);

	if (state.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL &&
	    state.cur_entry_offset > j->cur_entry_u64s) {
		j->cur_entry_u64s += d;
		/*
		 * Not enough room in current journal entry, have to flush it:
		 */
		__journal_entry_close(j, JOURNAL_ENTRY_CLOSED_VAL, true);
	} else {
		journal_cur_buf(j)->u64s_reserved += d;
	}
}

/* journal flushing: */

/**
 * bch2_journal_flush_seq_async - wait for a journal entry to be written
 * @j:		journal object
 * @seq:	seq to flush
 * @parent:	closure object to wait with
 * Returns:	1 if @seq has already been flushed, 0 if @seq is being flushed,
 *		-BCH_ERR_journal_flush_err if @seq will never be flushed
 *
 * Like bch2_journal_wait_on_seq, except that it triggers a write immediately if
 * necessary
 */
int bch2_journal_flush_seq_async(struct journal *j, u64 seq,
				 struct closure *parent)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf;
	int ret = 0;

	if (seq <= j->flushed_seq_ondisk)
		return 1;

	spin_lock(&j->lock);

	if (WARN_ONCE(seq > journal_cur_seq(j),
		      "requested to flush journal seq %llu, but currently at %llu",
		      seq, journal_cur_seq(j)))
		goto out;

	/* Recheck under lock: */
	if (j->err_seq && seq >= j->err_seq) {
		ret = bch_err_throw(c, journal_flush_err);
		goto out;
	}

	if (seq <= j->flushed_seq_ondisk) {
		ret = 1;
		goto out;
	}

	/* if seq was written, but not flushed - flush a newer one instead */
	seq = max(seq, journal_last_unwritten_seq(j));

recheck_need_open:
	if (seq > journal_cur_seq(j)) {
		struct journal_res res = { 0 };

		if (journal_entry_is_open(j))
			__journal_entry_close(j, JOURNAL_ENTRY_CLOSED_VAL, true);

		spin_unlock(&j->lock);

		/*
		 * We're called from bch2_journal_flush_seq() -> wait_event();
		 * but this might block. We won't usually block, so we won't
		 * livelock:
		 */
		sched_annotate_sleep();
		ret = bch2_journal_res_get(j, &res, jset_u64s(0), 0, NULL);
		if (ret)
			return ret;

		seq = res.seq;
		buf = journal_seq_to_buf(j, seq);
		buf->must_flush = true;

		if (!buf->flush_time) {
			buf->flush_time	= local_clock() ?: 1;
			buf->expires = jiffies;
		}

		if (parent && !closure_wait(&buf->wait, parent))
			BUG();

		bch2_journal_res_put(j, &res);

		spin_lock(&j->lock);
		goto want_write;
	}

	/*
	 * if write was kicked off without a flush, or if we promised it
	 * wouldn't be a flush, flush the next sequence number instead
	 */
	buf = journal_seq_to_buf(j, seq);
	if (buf->noflush) {
		seq++;
		goto recheck_need_open;
	}

	buf->must_flush = true;
	j->flushing_seq = max(j->flushing_seq, seq);

	if (parent && !closure_wait(&buf->wait, parent))
		BUG();
want_write:
	if (seq == journal_cur_seq(j))
		journal_entry_want_write(j);
out:
	spin_unlock(&j->lock);
	return ret;
}

int bch2_journal_flush_seq(struct journal *j, u64 seq, unsigned task_state)
{
	u64 start_time = local_clock();
	int ret, ret2;

	/*
	 * Don't update time_stats when @seq is already flushed:
	 */
	if (seq <= j->flushed_seq_ondisk)
		return 0;

	ret = wait_event_state(j->wait,
			       (ret2 = bch2_journal_flush_seq_async(j, seq, NULL)),
			       task_state);

	if (!ret)
		bch2_time_stats_update(j->flush_seq_time, start_time);

	return ret ?: ret2 < 0 ? ret2 : 0;
}

/*
 * bch2_journal_flush_async - if there is an open journal entry, or a journal
 * still being written, write it and wait for the write to complete
 */
void bch2_journal_flush_async(struct journal *j, struct closure *parent)
{
	bch2_journal_flush_seq_async(j, atomic64_read(&j->seq), parent);
}

int bch2_journal_flush(struct journal *j)
{
	return bch2_journal_flush_seq(j, atomic64_read(&j->seq), TASK_UNINTERRUPTIBLE);
}

/*
 * bch2_journal_noflush_seq - ask the journal not to issue any flushes in the
 * range [start, end)
 * @seq
 */
bool bch2_journal_noflush_seq(struct journal *j, u64 start, u64 end)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	u64 unwritten_seq;

	if (!(c->sb.features & (1ULL << BCH_FEATURE_journal_no_flush)))
		return false;

	if (c->journal.flushed_seq_ondisk >= start)
		return false;

	guard(spinlock)(&j->lock);

	if (c->journal.flushed_seq_ondisk >= start)
		return false;

	for (unwritten_seq = journal_last_unwritten_seq(j);
	     unwritten_seq < end;
	     unwritten_seq++) {
		struct journal_buf *buf = journal_seq_to_buf(j, unwritten_seq);

		/* journal flush already in flight, or flush requseted */
		if (buf->must_flush)
			return false;

		buf->noflush = true;
	}

	return true;
}

static int __bch2_journal_meta(struct journal *j)
{
	struct journal_res res = {};
	int ret = bch2_journal_res_get(j, &res, jset_u64s(0), 0, NULL);
	if (ret)
		return ret;

	struct journal_buf *buf = j->buf + (res.seq & JOURNAL_BUF_MASK);
	buf->must_flush = true;

	if (!buf->flush_time) {
		buf->flush_time	= local_clock() ?: 1;
		buf->expires = jiffies;
	}

	bch2_journal_res_put(j, &res);

	return bch2_journal_flush_seq(j, res.seq, TASK_UNINTERRUPTIBLE);
}

int bch2_journal_meta(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_journal))
		return bch_err_throw(c, erofs_no_writes);

	int ret = __bch2_journal_meta(j);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_journal);
	return ret;
}

/* block/unlock the journal: */

void bch2_journal_unblock(struct journal *j)
{
	scoped_guard(spinlock, &j->lock)
		if (!--j->blocked &&
		    j->cur_entry_offset_if_blocked < JOURNAL_ENTRY_CLOSED_VAL &&
		    j->reservations.cur_entry_offset == JOURNAL_ENTRY_BLOCKED_VAL) {
			union journal_res_state old, new;

			old.v = atomic64_read(&j->reservations.counter);
			do {
				new.v = old.v;
				new.cur_entry_offset = j->cur_entry_offset_if_blocked;
			} while (!atomic64_try_cmpxchg(&j->reservations.counter, &old.v, new.v));
		}

	journal_wake(j);
}

static void __bch2_journal_block(struct journal *j)
{
	if (!j->blocked++) {
		union journal_res_state old, new;

		old.v = atomic64_read(&j->reservations.counter);
		do {
			j->cur_entry_offset_if_blocked = old.cur_entry_offset;

			if (j->cur_entry_offset_if_blocked >= JOURNAL_ENTRY_CLOSED_VAL)
				break;

			new.v = old.v;
			new.cur_entry_offset = JOURNAL_ENTRY_BLOCKED_VAL;
		} while (!atomic64_try_cmpxchg(&j->reservations.counter, &old.v, new.v));

		if (old.cur_entry_offset < JOURNAL_ENTRY_BLOCKED_VAL)
			journal_cur_buf(j)->data->u64s = cpu_to_le32(old.cur_entry_offset);
	}
}

void bch2_journal_block(struct journal *j)
{
	scoped_guard(spinlock, &j->lock)
		__bch2_journal_block(j);

	journal_quiesce(j);
}

static struct journal_buf *__bch2_next_write_buffer_flush_journal_buf(struct journal *j,
						u64 max_seq, bool *blocked)
{
	struct journal_buf *ret = NULL;

	/* We're inside wait_event(), but using mutex_lock(: */
	sched_annotate_sleep();
	mutex_lock(&j->buf_lock);
	guard(spinlock)(&j->lock);
	max_seq = min(max_seq, journal_cur_seq(j));

	for (u64 seq = journal_last_unwritten_seq(j);
	     seq <= max_seq;
	     seq++) {
		unsigned idx = seq & JOURNAL_BUF_MASK;
		struct journal_buf *buf = j->buf + idx;

		if (buf->need_flush_to_write_buffer) {
			union journal_res_state s;
			s.v = atomic64_read_acquire(&j->reservations.counter);

			unsigned open = seq == journal_cur_seq(j) && __journal_entry_is_open(s);

			if (open && !*blocked) {
				__bch2_journal_block(j);
				s.v = atomic64_read_acquire(&j->reservations.counter);
				*blocked = true;
			}

			ret = journal_state_count(s, idx & JOURNAL_STATE_BUF_MASK) > open
				? ERR_PTR(-EAGAIN)
				: buf;
			break;
		}
	}

	if (IS_ERR_OR_NULL(ret))
		mutex_unlock(&j->buf_lock);
	return ret;
}

struct journal_buf *bch2_next_write_buffer_flush_journal_buf(struct journal *j,
							     u64 max_seq, bool *blocked)
{
	struct journal_buf *ret;
	*blocked = false;

	wait_event(j->wait, (ret = __bch2_next_write_buffer_flush_journal_buf(j,
						max_seq, blocked)) != ERR_PTR(-EAGAIN));
	if (IS_ERR_OR_NULL(ret) && *blocked)
		bch2_journal_unblock(j);

	return ret;
}

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

		if (ret == -BCH_ERR_bucket_alloc_blocked ||
		    ret == -BCH_ERR_open_buckets_empty)
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

	journal_quiesce(j);
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
		ja->bio[i] = kvzalloc(struct_size(ja->bio[i], bio.bi_inline_vecs,
				     nr_bvecs), GFP_KERNEL);
		if (!ja->bio[i])
			return bch_err_throw(c, ENOMEM_dev_journal_init);

		ja->bio[i]->ca = ca;
		ja->bio[i]->buf_idx = i;
		bio_init(&ja->bio[i]->bio, NULL, ja->bio[i]->bio.bi_inline_vecs, nr_bvecs, 0);
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
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
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

/* debug: */

static const char * const bch2_journal_flags_strs[] = {
#define x(n)	#n,
	JOURNAL_FLAGS()
#undef x
	NULL
};

void __bch2_journal_debug_to_text(struct printbuf *out, struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	union journal_res_state s;
	unsigned long now = jiffies;
	u64 nr_writes = j->nr_flush_writes + j->nr_noflush_writes;

	printbuf_tabstops_reset(out);
	printbuf_tabstop_push(out, 28);

	guard(printbuf_atomic)(out);
	guard(rcu)();

	s = READ_ONCE(j->reservations);

	prt_printf(out, "flags:\t");
	prt_bitflags(out, bch2_journal_flags_strs, j->flags);
	prt_newline(out);
	prt_printf(out, "dirty journal entries:\t%llu/%llu\n",	fifo_used(&j->pin), j->pin.size);
	prt_printf(out, "seq:\t%llu\n",				journal_cur_seq(j));
	prt_printf(out, "seq_ondisk:\t%llu\n",			j->seq_ondisk);
	prt_printf(out, "last_seq:\t%llu\n",			journal_last_seq(j));
	prt_printf(out, "last_seq_ondisk:\t%llu\n",		j->last_seq_ondisk);
	prt_printf(out, "flushed_seq_ondisk:\t%llu\n",		j->flushed_seq_ondisk);
	prt_printf(out, "watermark:\t%s\n",			bch2_watermarks[j->watermark]);
	prt_printf(out, "each entry reserved:\t%u\n",		j->entry_u64s_reserved);
	prt_printf(out, "nr flush writes:\t%llu\n",		j->nr_flush_writes);
	prt_printf(out, "nr noflush writes:\t%llu\n",		j->nr_noflush_writes);
	prt_printf(out, "average write size:\t");
	prt_human_readable_u64(out, nr_writes ? div64_u64(j->entry_bytes_written, nr_writes) : 0);
	prt_newline(out);
	prt_printf(out, "free buf:\t%u\n",			j->free_buf ? j->free_buf_size : 0);
	prt_printf(out, "nr direct reclaim:\t%llu\n",		j->nr_direct_reclaim);
	prt_printf(out, "nr background reclaim:\t%llu\n",	j->nr_background_reclaim);
	prt_printf(out, "reclaim kicked:\t%u\n",		j->reclaim_kicked);
	prt_printf(out, "reclaim runs in:\t%u ms\n",		time_after(j->next_reclaim, now)
	       ? jiffies_to_msecs(j->next_reclaim - jiffies) : 0);
	prt_printf(out, "blocked:\t%u\n",			j->blocked);
	prt_printf(out, "current entry sectors:\t%u\n",		j->cur_entry_sectors);
	prt_printf(out, "current entry error:\t%s\n",		bch2_err_str(j->cur_entry_error));
	prt_printf(out, "current entry:\t");

	switch (s.cur_entry_offset) {
	case JOURNAL_ENTRY_ERROR_VAL:
		prt_printf(out, "error\n");
		break;
	case JOURNAL_ENTRY_CLOSED_VAL:
		prt_printf(out, "closed\n");
		break;
	case JOURNAL_ENTRY_BLOCKED_VAL:
		prt_printf(out, "blocked\n");
		break;
	default:
		prt_printf(out, "%u/%u\n", s.cur_entry_offset, j->cur_entry_u64s);
		break;
	}

	prt_printf(out, "unwritten entries:\n");
	bch2_journal_bufs_to_text(out, j);

	prt_printf(out, "space:\n");
	printbuf_indent_add(out, 2);
	prt_printf(out, "discarded\t%u:%u\n",
	       j->space[journal_space_discarded].next_entry,
	       j->space[journal_space_discarded].total);
	prt_printf(out, "clean ondisk\t%u:%u\n",
	       j->space[journal_space_clean_ondisk].next_entry,
	       j->space[journal_space_clean_ondisk].total);
	prt_printf(out, "clean\t%u:%u\n",
	       j->space[journal_space_clean].next_entry,
	       j->space[journal_space_clean].total);
	prt_printf(out, "total\t%u:%u\n",
	       j->space[journal_space_total].next_entry,
	       j->space[journal_space_total].total);
	printbuf_indent_sub(out, 2);

	for_each_member_device_rcu(c, ca, &c->rw_devs[BCH_DATA_journal]) {
		if (!ca->mi.durability)
			continue;

		struct journal_device *ja = &ca->journal;

		if (!test_bit(ca->dev_idx, c->rw_devs[BCH_DATA_journal].d))
			continue;

		if (!ja->nr)
			continue;

		prt_printf(out, "dev %u:\n",			ca->dev_idx);
		prt_printf(out, "durability %u:\n",		ca->mi.durability);
		printbuf_indent_add(out, 2);
		prt_printf(out, "nr\t%u\n",			ja->nr);
		prt_printf(out, "bucket size\t%u\n",		ca->mi.bucket_size);
		prt_printf(out, "available\t%u:%u\n",		bch2_journal_dev_buckets_available(j, ja, journal_space_discarded), ja->sectors_free);
		prt_printf(out, "discard_idx\t%u\n",		ja->discard_idx);
		prt_printf(out, "dirty_ondisk\t%u (seq %llu)\n",ja->dirty_idx_ondisk,	ja->bucket_seq[ja->dirty_idx_ondisk]);
		prt_printf(out, "dirty_idx\t%u (seq %llu)\n",	ja->dirty_idx,		ja->bucket_seq[ja->dirty_idx]);
		prt_printf(out, "cur_idx\t%u (seq %llu)\n",	ja->cur_idx,		ja->bucket_seq[ja->cur_idx]);
		printbuf_indent_sub(out, 2);
	}

	prt_printf(out, "replicas want %u need %u\n", c->opts.metadata_replicas, c->opts.metadata_replicas_required);
}

void bch2_journal_debug_to_text(struct printbuf *out, struct journal *j)
{
	guard(spinlock)(&j->lock);
	__bch2_journal_debug_to_text(out, j);
}
