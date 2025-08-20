// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "errcode.h"
#include "error.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "replicas.h"
#include "sb-members.h"
#include "trace.h"

#include <linux/kthread.h>
#include <linux/sched/mm.h>

static bool __should_discard_bucket(struct journal *, struct journal_device *);

/* Free space calculations: */

static unsigned journal_space_from(struct journal_device *ja,
				   enum journal_space_from from)
{
	switch (from) {
	case journal_space_discarded:
		return ja->discard_idx;
	case journal_space_clean_ondisk:
		return ja->dirty_idx_ondisk;
	case journal_space_clean:
		return ja->dirty_idx;
	default:
		BUG();
	}
}

unsigned bch2_journal_dev_buckets_available(struct journal *j,
					    struct journal_device *ja,
					    enum journal_space_from from)
{
	if (!ja->nr)
		return 0;

	unsigned available = (journal_space_from(ja, from) -
			      ja->cur_idx - 1 + ja->nr) % ja->nr;

	/*
	 * Don't use the last bucket unless writing the new last_seq
	 * will make another bucket available:
	 */
	if (available && ja->dirty_idx_ondisk == ja->dirty_idx)
		--available;

	return available;
}

void bch2_journal_set_watermark(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	bool low_on_space = j->space[journal_space_clean].total * 4 <=
		j->space[journal_space_total].total;
	bool low_on_pin = fifo_free(&j->pin) < j->pin.size / 4;
	bool low_on_wb = bch2_btree_write_buffer_must_wait(c);
	unsigned watermark = low_on_space || low_on_pin || low_on_wb
		? BCH_WATERMARK_reclaim
		: BCH_WATERMARK_stripe;

	if (track_event_change(&c->times[BCH_TIME_blocked_journal_low_on_space], low_on_space) ||
	    track_event_change(&c->times[BCH_TIME_blocked_journal_low_on_pin], low_on_pin) ||
	    track_event_change(&c->times[BCH_TIME_blocked_write_buffer_full], low_on_wb))
		trace_and_count(c, journal_full, c);

	mod_bit(JOURNAL_space_low, &j->flags, low_on_space || low_on_pin);

	swap(watermark, j->watermark);
	if (watermark > j->watermark)
		journal_wake(j);
}

static struct journal_space
journal_dev_space_available(struct journal *j, struct bch_dev *ca,
			    enum journal_space_from from)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_device *ja = &ca->journal;
	unsigned sectors, buckets, unwritten;
	unsigned bucket_size_aligned = round_down(ca->mi.bucket_size, block_sectors(c));
	u64 seq;

	if (from == journal_space_total)
		return (struct journal_space) {
			.next_entry	= bucket_size_aligned,
			.total		= bucket_size_aligned * ja->nr,
		};

	buckets = bch2_journal_dev_buckets_available(j, ja, from);
	sectors = round_down(ja->sectors_free, block_sectors(c));

	/*
	 * We that we don't allocate the space for a journal entry
	 * until we write it out - thus, account for it here:
	 */
	for (seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++) {
		unwritten = j->buf[seq & JOURNAL_BUF_MASK].sectors;

		if (!unwritten)
			continue;

		/* entry won't fit on this device, skip: */
		if (unwritten > bucket_size_aligned)
			continue;

		if (unwritten >= sectors) {
			if (!buckets) {
				sectors = 0;
				break;
			}

			buckets--;
			sectors = bucket_size_aligned;
		}

		sectors -= unwritten;
	}

	if (sectors < ca->mi.bucket_size && buckets) {
		buckets--;
		sectors = bucket_size_aligned;
	}

	return (struct journal_space) {
		.next_entry	= sectors,
		.total		= sectors + buckets * bucket_size_aligned,
	};
}

static struct journal_space __journal_space_available(struct journal *j, unsigned nr_devs_want,
			    enum journal_space_from from)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned pos, nr_devs = 0;
	struct journal_space space, dev_space[BCH_SB_MEMBERS_MAX];
	unsigned min_bucket_size = U32_MAX;

	BUG_ON(nr_devs_want > ARRAY_SIZE(dev_space));

	for_each_member_device_rcu(c, ca, &c->rw_devs[BCH_DATA_journal]) {
		if (!ca->journal.nr ||
		    !ca->mi.durability)
			continue;

		min_bucket_size = min(min_bucket_size, ca->mi.bucket_size);

		space = journal_dev_space_available(j, ca, from);
		if (!space.next_entry)
			continue;

		for (pos = 0; pos < nr_devs; pos++)
			if (space.total > dev_space[pos].total)
				break;

		array_insert_item(dev_space, nr_devs, pos, space);
	}

	if (nr_devs < nr_devs_want)
		return (struct journal_space) { 0, 0 };

	/*
	 * It's possible for bucket size to be misaligned w.r.t. the filesystem
	 * block size:
	 */
	min_bucket_size = round_down(min_bucket_size, block_sectors(c));

	/*
	 * We sorted largest to smallest, and we want the smallest out of the
	 * @nr_devs_want largest devices:
	 */
	space = dev_space[nr_devs_want - 1];
	space.next_entry = min(space.next_entry, min_bucket_size);
	return space;
}

void bch2_journal_space_available(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned clean, clean_ondisk, total;
	unsigned max_entry_size	 = min(j->buf[0].buf_size >> 9,
				       j->buf[1].buf_size >> 9);
	unsigned nr_online = 0, nr_devs_want;
	bool can_discard = false;
	int ret = 0;

	lockdep_assert_held(&j->lock);
	guard(rcu)();

	for_each_member_device_rcu(c, ca, &c->rw_devs[BCH_DATA_journal]) {
		struct journal_device *ja = &ca->journal;

		if (!ja->nr)
			continue;

		while (ja->dirty_idx != ja->cur_idx &&
		       ja->bucket_seq[ja->dirty_idx] < journal_last_seq(j))
			ja->dirty_idx = (ja->dirty_idx + 1) % ja->nr;

		while (ja->dirty_idx_ondisk != ja->dirty_idx &&
		       ja->bucket_seq[ja->dirty_idx_ondisk] < j->last_seq_ondisk)
			ja->dirty_idx_ondisk = (ja->dirty_idx_ondisk + 1) % ja->nr;

		can_discard |= __should_discard_bucket(j, ja);

		max_entry_size = min_t(unsigned, max_entry_size, ca->mi.bucket_size);
		nr_online++;
	}

	j->can_discard = can_discard;

	if (nr_online < metadata_replicas_required(c)) {
		if (!(c->sb.features & BIT_ULL(BCH_FEATURE_small_image))) {
			CLASS(printbuf, buf)();
			guard(printbuf_atomic)(&buf);
			prt_printf(&buf, "insufficient writeable journal devices available: have %u, need %u\n"
				   "rw journal devs:", nr_online, metadata_replicas_required(c));

			for_each_member_device_rcu(c, ca, &c->rw_devs[BCH_DATA_journal])
				prt_printf(&buf, " %s", ca->name);

			bch_err(c, "%s", buf.buf);
		}
		ret = bch_err_throw(c, insufficient_journal_devices);
		goto out;
	}

	nr_devs_want = min_t(unsigned, nr_online, c->opts.metadata_replicas);

	for (unsigned i = 0; i < journal_space_nr; i++)
		j->space[i] = __journal_space_available(j, nr_devs_want, i);

	clean_ondisk	= j->space[journal_space_clean_ondisk].total;
	clean		= j->space[journal_space_clean].total;
	total		= j->space[journal_space_total].total;

	if (!j->space[journal_space_discarded].next_entry)
		ret = bch_err_throw(c, journal_full);

	if ((j->space[journal_space_clean_ondisk].next_entry <
	     j->space[journal_space_clean_ondisk].total) &&
	    (clean - clean_ondisk <= total / 8) &&
	    (clean_ondisk * 2 > clean))
		set_bit(JOURNAL_may_skip_flush, &j->flags);
	else
		clear_bit(JOURNAL_may_skip_flush, &j->flags);

	bch2_journal_set_watermark(j);
out:
	j->cur_entry_sectors	= !ret
		? j->space[journal_space_discarded].next_entry
		: 0;
	j->cur_entry_error	= ret;

	if (!ret)
		journal_wake(j);
}

/* Discards - last part of journal reclaim: */

static bool __should_discard_bucket(struct journal *j, struct journal_device *ja)
{
	unsigned min_free = max(4, ja->nr / 8);

	return bch2_journal_dev_buckets_available(j, ja, journal_space_discarded) <
		min_free &&
		ja->discard_idx != ja->dirty_idx_ondisk;
}

static bool should_discard_bucket(struct journal *j, struct journal_device *ja)
{
	guard(spinlock)(&j->lock);
	return __should_discard_bucket(j, ja);
}

/*
 * Advance ja->discard_idx as long as it points to buckets that are no longer
 * dirty, issuing discards if necessary:
 */
void bch2_journal_do_discards(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	guard(mutex)(&j->discard_lock);

	for_each_rw_member(c, ca, BCH_DEV_WRITE_REF_journal_do_discards) {
		struct journal_device *ja = &ca->journal;

		while (should_discard_bucket(j, ja)) {
			if (!c->opts.nochanges &&
			    bch2_discard_opt_enabled(c, ca) &&
			    bdev_max_discard_sectors(ca->disk_sb.bdev))
				blkdev_issue_discard(ca->disk_sb.bdev,
					bucket_to_sector(ca,
						ja->buckets[ja->discard_idx]),
					ca->mi.bucket_size, GFP_NOFS);

			scoped_guard(spinlock, &j->lock) {
				ja->discard_idx = (ja->discard_idx + 1) % ja->nr;
				bch2_journal_space_available(j);
			}
		}
	}
}

/*
 * Journal entry pinning - machinery for holding a reference on a given journal
 * entry, holding it open to ensure it gets replayed during recovery:
 */

void bch2_journal_reclaim_fast(struct journal *j)
{
	bool popped = false;

	lockdep_assert_held(&j->lock);

	/*
	 * Unpin journal entries whose reference counts reached zero, meaning
	 * all btree nodes got written out
	 */
	struct journal_entry_pin_list *pin_list;
	while (!fifo_empty(&j->pin) &&
	       j->pin.front <= j->seq_ondisk &&
	       !atomic_read(&(pin_list = &fifo_peek_front(&j->pin))->count)) {

		if (WARN_ON(j->dirty_entry_bytes < pin_list->bytes))
			pin_list->bytes = j->dirty_entry_bytes;

		j->dirty_entry_bytes -= pin_list->bytes;
		pin_list->bytes = 0;

		j->pin.front++;
		popped = true;
	}

	if (popped) {
		bch2_journal_space_available(j);
		__closure_wake_up(&j->reclaim_flush_wait);
	}
}

bool __bch2_journal_pin_put(struct journal *j, u64 seq)
{
	struct journal_entry_pin_list *pin_list = journal_seq_pin(j, seq);

	return atomic_dec_and_test(&pin_list->count);
}

void bch2_journal_pin_put(struct journal *j, u64 seq)
{
	if (__bch2_journal_pin_put(j, seq)) {
		guard(spinlock)(&j->lock);
		bch2_journal_reclaim_fast(j);
	}
}

static inline bool __journal_pin_drop(struct journal *j,
				      struct journal_entry_pin *pin)
{
	struct journal_entry_pin_list *pin_list;

	if (!journal_pin_active(pin))
		return false;

	if (j->flush_in_progress == pin)
		j->flush_in_progress_dropped = true;

	pin_list = journal_seq_pin(j, pin->seq);
	pin->seq = 0;
	list_del_init(&pin->list);

	if (j->reclaim_flush_wait.list.first)
		__closure_wake_up(&j->reclaim_flush_wait);

	/*
	 * Unpinning a journal entry may make journal_next_bucket() succeed, if
	 * writing a new last_seq will now make another bucket available:
	 */
	return atomic_dec_and_test(&pin_list->count) &&
		pin_list == &fifo_peek_front(&j->pin);
}

void bch2_journal_pin_drop(struct journal *j,
			   struct journal_entry_pin *pin)
{
	guard(spinlock)(&j->lock);
	if (__journal_pin_drop(j, pin))
		bch2_journal_reclaim_fast(j);
}

static enum journal_pin_type journal_pin_type(struct journal_entry_pin *pin,
					      journal_pin_flush_fn fn)
{
	if (fn == bch2_btree_node_flush0 ||
	    fn == bch2_btree_node_flush1) {
		unsigned idx = fn == bch2_btree_node_flush1;
		struct btree *b = container_of(pin, struct btree, writes[idx].journal);

		return JOURNAL_PIN_TYPE_btree0 - b->c.level;
	} else if (fn == bch2_btree_key_cache_journal_flush)
		return JOURNAL_PIN_TYPE_key_cache;
	else
		return JOURNAL_PIN_TYPE_other;
}

static inline void bch2_journal_pin_set_locked(struct journal *j, u64 seq,
			  struct journal_entry_pin *pin,
			  journal_pin_flush_fn flush_fn,
			  enum journal_pin_type type)
{
	struct journal_entry_pin_list *pin_list = journal_seq_pin(j, seq);

	/*
	 * flush_fn is how we identify journal pins in debugfs, so must always
	 * exist, even if it doesn't do anything:
	 */
	BUG_ON(!flush_fn);

	atomic_inc(&pin_list->count);
	pin->seq	= seq;
	pin->flush	= flush_fn;

	if (list_empty(&pin_list->unflushed[type]) &&
	    j->reclaim_flush_wait.list.first)
		__closure_wake_up(&j->reclaim_flush_wait);

	list_add(&pin->list, &pin_list->unflushed[type]);
}

void bch2_journal_pin_copy(struct journal *j,
			   struct journal_entry_pin *dst,
			   struct journal_entry_pin *src,
			   journal_pin_flush_fn flush_fn)
{
	guard(spinlock)(&j->lock);

	u64 seq = READ_ONCE(src->seq);

	if (seq < journal_last_seq(j)) {
		/*
		 * bch2_journal_pin_copy() raced with bch2_journal_pin_drop() on
		 * the src pin - with the pin dropped, the entry to pin might no
		 * longer to exist, but that means there's no longer anything to
		 * copy and we can bail out here:
		 */
		return;
	}

	bool reclaim = __journal_pin_drop(j, dst);

	bch2_journal_pin_set_locked(j, seq, dst, flush_fn, journal_pin_type(dst, flush_fn));

	if (reclaim)
		bch2_journal_reclaim_fast(j);

	/*
	 * If the journal is currently full,  we might want to call flush_fn
	 * immediately:
	 */
	if (seq == journal_last_seq(j))
		journal_wake(j);
}

void bch2_journal_pin_set(struct journal *j, u64 seq,
			  struct journal_entry_pin *pin,
			  journal_pin_flush_fn flush_fn)
{
	bool wake;

	scoped_guard(spinlock, &j->lock) {
		BUG_ON(seq < journal_last_seq(j));

		bool reclaim = __journal_pin_drop(j, pin);

		bch2_journal_pin_set_locked(j, seq, pin, flush_fn, journal_pin_type(pin, flush_fn));

		if (reclaim)
			bch2_journal_reclaim_fast(j);
		/*
		 * If the journal is currently full,  we might want to call flush_fn
		 * immediately:
		 */
		wake = seq == journal_last_seq(j);
	}

	if (wake)
		journal_wake(j);
}

/**
 * bch2_journal_pin_flush: ensure journal pin callback is no longer running
 * @j:		journal object
 * @pin:	pin to flush
 */
void bch2_journal_pin_flush(struct journal *j, struct journal_entry_pin *pin)
{
	BUG_ON(journal_pin_active(pin));

	wait_event(j->pin_flush_wait, j->flush_in_progress != pin);
}

/*
 * Journal reclaim: flush references to open journal entries to reclaim space in
 * the journal
 *
 * May be done by the journal code in the background as needed to free up space
 * for more journal entries, or as part of doing a clean shutdown, or to migrate
 * data off of a specific device:
 */

static struct journal_entry_pin *
journal_get_next_pin(struct journal *j,
		     u64 seq_to_flush,
		     unsigned allowed_below_seq,
		     unsigned allowed_above_seq,
		     u64 *seq)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *ret = NULL;

	fifo_for_each_entry_ptr(pin_list, &j->pin, *seq) {
		if (*seq > seq_to_flush && !allowed_above_seq)
			break;

		for (unsigned i = 0; i < JOURNAL_PIN_TYPE_NR; i++)
			if (((BIT(i) & allowed_below_seq) && *seq <= seq_to_flush) ||
			    (BIT(i) & allowed_above_seq)) {
				ret = list_first_entry_or_null(&pin_list->unflushed[i],
					struct journal_entry_pin, list);
				if (ret)
					return ret;
			}
	}

	return NULL;
}

/* returns true if we did work */
static size_t journal_flush_pins(struct journal *j,
				 u64 seq_to_flush,
				 unsigned allowed_below_seq,
				 unsigned allowed_above_seq,
				 unsigned min_any,
				 unsigned min_key_cache)
{
	struct journal_entry_pin *pin;
	size_t nr_flushed = 0;
	journal_pin_flush_fn flush_fn;
	u64 seq;
	int err;

	lockdep_assert_held(&j->reclaim_lock);

	while (1) {
		unsigned allowed_above = allowed_above_seq;
		unsigned allowed_below = allowed_below_seq;

		if (min_any) {
			allowed_above |= ~0;
			allowed_below |= ~0;
		}

		if (min_key_cache) {
			allowed_above |= BIT(JOURNAL_PIN_TYPE_key_cache);
			allowed_below |= BIT(JOURNAL_PIN_TYPE_key_cache);
		}

		cond_resched();

		j->last_flushed = jiffies;

		scoped_guard(spinlock, &j->lock) {
			pin = journal_get_next_pin(j, seq_to_flush,
						   allowed_below,
						   allowed_above, &seq);
			if (pin) {
				BUG_ON(j->flush_in_progress);
				j->flush_in_progress = pin;
				j->flush_in_progress_dropped = false;
				flush_fn = pin->flush;
			}
		}

		if (!pin)
			break;

		if (min_key_cache && pin->flush == bch2_btree_key_cache_journal_flush)
			min_key_cache--;

		if (min_any)
			min_any--;

		err = flush_fn(j, pin, seq);

		scoped_guard(spinlock, &j->lock) {
			/* Pin might have been dropped or rearmed: */
			if (likely(!err && !j->flush_in_progress_dropped))
				list_move(&pin->list, &journal_seq_pin(j, seq)->flushed[journal_pin_type(pin, flush_fn)]);
			j->flush_in_progress = NULL;
			j->flush_in_progress_dropped = false;
		}

		wake_up(&j->pin_flush_wait);

		if (err)
			break;

		nr_flushed++;
	}

	return nr_flushed;
}

static u64 journal_seq_to_flush(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	u64 seq_to_flush = 0;

	guard(spinlock)(&j->lock);
	guard(rcu)();

	for_each_rw_member_rcu(c, ca) {
		struct journal_device *ja = &ca->journal;
		unsigned nr_buckets, bucket_to_flush;

		if (!ja->nr)
			continue;

		/* Try to keep the journal at most half full: */
		nr_buckets = ja->nr / 2;

		bucket_to_flush = (ja->cur_idx + nr_buckets) % ja->nr;
		seq_to_flush = max(seq_to_flush,
				   ja->bucket_seq[bucket_to_flush]);
	}

	/* Also flush if the pin fifo is more than half full */
	return max_t(s64, seq_to_flush,
		     (s64) journal_cur_seq(j) -
		     (j->pin.size >> 1));
}

/**
 * __bch2_journal_reclaim - free up journal buckets
 * @j:		journal object
 * @direct:	direct or background reclaim?
 * @kicked:	requested to run since we last ran?
 *
 * Background journal reclaim writes out btree nodes. It should be run
 * early enough so that we never completely run out of journal buckets.
 *
 * High watermarks for triggering background reclaim:
 * - FIFO has fewer than 512 entries left
 * - fewer than 25% journal buckets free
 *
 * Background reclaim runs until low watermarks are reached:
 * - FIFO has more than 1024 entries left
 * - more than 50% journal buckets free
 *
 * As long as a reclaim can complete in the time it takes to fill up
 * 512 journal entries or 25% of all journal buckets, then
 * journal_next_bucket() should not stall.
 */
static int __bch2_journal_reclaim(struct journal *j, bool direct, bool kicked)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct btree_cache *bc = &c->btree_cache;
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	u64 seq_to_flush;
	size_t min_nr, min_key_cache, nr_flushed;
	unsigned flags;
	int ret = 0;

	/*
	 * We can't invoke memory reclaim while holding the reclaim_lock -
	 * journal reclaim is required to make progress for memory reclaim
	 * (cleaning the caches), so we can't get stuck in memory reclaim while
	 * we're holding the reclaim lock:
	 */
	lockdep_assert_held(&j->reclaim_lock);
	flags = memalloc_noreclaim_save();

	do {
		if (kthread && kthread_should_stop())
			break;

		ret = bch2_journal_error(j);
		if (ret)
			break;

		/* XXX shove journal discards off to another thread */
		bch2_journal_do_discards(j);

		seq_to_flush = journal_seq_to_flush(j);
		min_nr = 0;

		/*
		 * If it's been longer than j->reclaim_delay_ms since we last flushed,
		 * make sure to flush at least one journal pin:
		 */
		if (time_after(jiffies, j->last_flushed +
			       msecs_to_jiffies(c->opts.journal_reclaim_delay)))
			min_nr = 1;

		if (j->watermark != BCH_WATERMARK_stripe)
			min_nr = 1;

		size_t btree_cache_live = bc->live[0].nr + bc->live[1].nr;
		if (atomic_long_read(&bc->nr_dirty) * 2 > btree_cache_live)
			min_nr = 1;

		min_key_cache = min(bch2_nr_btree_keys_need_flush(c), (size_t) 128);

		trace_and_count(c, journal_reclaim_start, c,
				direct, kicked,
				min_nr, min_key_cache,
				atomic_long_read(&bc->nr_dirty), btree_cache_live,
				atomic_long_read(&c->btree_key_cache.nr_dirty),
				atomic_long_read(&c->btree_key_cache.nr_keys));

		nr_flushed = journal_flush_pins(j, seq_to_flush,
						~0, 0,
						min_nr, min_key_cache);

		if (direct)
			j->nr_direct_reclaim += nr_flushed;
		else
			j->nr_background_reclaim += nr_flushed;
		trace_and_count(c, journal_reclaim_finish, c, nr_flushed);

		if (nr_flushed)
			wake_up(&j->reclaim_wait);
	} while ((min_nr || min_key_cache) && nr_flushed && !direct);

	memalloc_noreclaim_restore(flags);

	return ret;
}

int bch2_journal_reclaim(struct journal *j)
{
	return __bch2_journal_reclaim(j, true, true);
}

static int bch2_journal_reclaim_thread(void *arg)
{
	struct journal *j = arg;
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned long delay, now;
	bool journal_empty;
	int ret = 0;

	set_freezable();

	j->last_flushed = jiffies;

	while (!ret && !kthread_should_stop()) {
		bool kicked = j->reclaim_kicked;

		j->reclaim_kicked = false;

		scoped_guard(mutex, &j->reclaim_lock)
			ret = __bch2_journal_reclaim(j, false, kicked);

		now = jiffies;
		delay = msecs_to_jiffies(c->opts.journal_reclaim_delay);
		j->next_reclaim = j->last_flushed + delay;

		if (!time_in_range(j->next_reclaim, now, now + delay))
			j->next_reclaim = now + delay;

		while (1) {
			set_current_state(TASK_INTERRUPTIBLE|TASK_FREEZABLE);
			if (kthread_should_stop())
				break;
			if (j->reclaim_kicked)
				break;

			scoped_guard(spinlock, &j->lock)
				journal_empty = fifo_empty(&j->pin);

			long timeout = j->next_reclaim - jiffies;

			if (journal_empty)
				schedule();
			else if (timeout > 0)
				schedule_timeout(timeout);
			else
				break;
		}
		__set_current_state(TASK_RUNNING);
	}

	return 0;
}

void bch2_journal_reclaim_stop(struct journal *j)
{
	struct task_struct *p = j->reclaim_thread;

	j->reclaim_thread = NULL;

	if (p) {
		kthread_stop(p);
		put_task_struct(p);
	}
}

int bch2_journal_reclaim_start(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct task_struct *p;
	int ret;

	if (j->reclaim_thread)
		return 0;

	p = kthread_create(bch2_journal_reclaim_thread, j,
			   "bch-reclaim/%s", c->name);
	ret = PTR_ERR_OR_ZERO(p);
	bch_err_msg(c, ret, "creating journal reclaim thread");
	if (ret)
		return ret;

	get_task_struct(p);
	j->reclaim_thread = p;
	wake_up_process(p);
	return 0;
}

static bool journal_pins_still_flushing(struct journal *j, u64 seq_to_flush,
					unsigned types)
{
	guard(spinlock)(&j->lock);

	struct journal_entry_pin_list *pin_list;
	u64 seq;
	fifo_for_each_entry_ptr(pin_list, &j->pin, seq) {
		if (seq > seq_to_flush)
			break;

		for (unsigned i = 0; i < JOURNAL_PIN_TYPE_NR; i++)
			if ((BIT(i) & types) &&
			    (!list_empty(&pin_list->unflushed[i]) ||
			     !list_empty(&pin_list->flushed[i])))
				return true;
	}

	return false;
}

static bool journal_flush_pins_or_still_flushing(struct journal *j, u64 seq_to_flush,
						 unsigned types)
{
	return  journal_flush_pins(j, seq_to_flush, types, 0, 0, 0) ||
		journal_pins_still_flushing(j, seq_to_flush, types);
}

static int journal_flush_done(struct journal *j, u64 seq_to_flush,
			      bool *did_work)
{
	int ret = 0;

	ret = bch2_journal_error(j);
	if (ret)
		return ret;

	guard(mutex)(&j->reclaim_lock);

	for (int type = JOURNAL_PIN_TYPE_NR - 1;
	     type >= 0;
	     --type)
		if (journal_flush_pins_or_still_flushing(j, seq_to_flush, BIT(type))) {
			*did_work = true;

			/*
			 * Question from Dan Carpenter, on the early return:
			 *
			 * If journal_flush_pins_or_still_flushing() returns
			 * true, then the flush hasn't complete and we must
			 * return 0; we want the outer closure_wait_event() in
			 * journal_flush_pins() to continue.
			 *
			 * The early return is there because we don't want to
			 * call journal_entry_close() until we've finished
			 * flushing all outstanding journal pins - otherwise
			 * seq_to_flush can be U64_MAX, and we'll close a bunch
			 * of journal entries and write tiny ones completely
			 * unnecessarily.
			 *
			 * Having the early return be in the loop where we loop
			 * over types is important, because flushing one journal
			 * pin can cause new journal pins to be added (even of
			 * the same type, btree node writes may generate more
			 * btree node writes, when updating the parent pointer
			 * has a full node and has to trigger a split/compact).
			 *
			 * This is part of our shutdown sequence, where order of
			 * flushing is important in order to make sure that it
			 * terminates...
			 */
			return 0;
		}

	if (seq_to_flush > journal_cur_seq(j))
		bch2_journal_entry_close(j);

	/*
	 * If journal replay hasn't completed, the unreplayed journal entries
	 * hold refs on their corresponding sequence numbers
	 */
	guard(spinlock)(&j->lock);
	ret = !test_bit(JOURNAL_replay_done, &j->flags) ||
		journal_last_seq(j) > seq_to_flush ||
		!fifo_used(&j->pin);
	return ret;
}

bool bch2_journal_flush_pins(struct journal *j, u64 seq_to_flush)
{
	/* time_stats this */
	bool did_work = false;

	if (!test_bit(JOURNAL_running, &j->flags))
		return false;

	closure_wait_event(&j->reclaim_flush_wait,
		journal_flush_done(j, seq_to_flush, &did_work));

	return did_work;
}

int bch2_journal_flush_device_pins(struct journal *j, int dev_idx)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_entry_pin_list *p;
	u64 iter, seq = 0;
	int ret = 0;

	scoped_guard(spinlock, &j->lock)
		fifo_for_each_entry_ptr(p, &j->pin, iter)
			if (dev_idx >= 0
			    ? bch2_dev_list_has_dev(p->devs, dev_idx)
			    : p->devs.nr < c->opts.metadata_replicas)
				seq = iter;

	bch2_journal_flush_pins(j, seq);

	ret = bch2_journal_error(j);
	if (ret)
		return ret;

	guard(mutex)(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_journal);

	/*
	 * Now that we've populated replicas_gc, write to the journal to mark
	 * active journal devices. This handles the case where the journal might
	 * be empty. Otherwise we could clear all journal replicas and
	 * temporarily put the fs into an unrecoverable state. Journal recovery
	 * expects to find devices marked for journal data on unclean mount.
	 */
	ret = bch2_journal_meta(&c->journal);
	if (ret)
		goto err;

	seq = 0;
	scoped_guard(spinlock, &j->lock)
		while (!ret) {
			union bch_replicas_padded replicas;

			seq = max(seq, journal_last_seq(j));
			if (seq >= j->pin.back)
				break;
			bch2_devlist_to_replicas(&replicas.e, BCH_DATA_journal,
						 journal_seq_pin(j, seq)->devs);
			seq++;

			if (replicas.e.nr_devs) {
				spin_unlock(&j->lock);
				ret = bch2_mark_replicas(c, &replicas.e);
				spin_lock(&j->lock);
			}
		}
err:
	return bch2_replicas_gc_end(c, ret);
}

bool bch2_journal_seq_pins_to_text(struct printbuf *out, struct journal *j, u64 *seq)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *pin;

	guard(spinlock)(&j->lock);
	guard(printbuf_atomic)(out);

	if (!test_bit(JOURNAL_running, &j->flags))
		return true;

	*seq = max(*seq, j->pin.front);

	if (*seq >= j->pin.back)
		return true;

	pin_list = journal_seq_pin(j, *seq);

	prt_printf(out, "%llu: count %u\n", *seq, atomic_read(&pin_list->count));
	printbuf_indent_add(out, 2);

	prt_printf(out, "unflushed:\n");
	for (unsigned i = 0; i < ARRAY_SIZE(pin_list->unflushed); i++)
		list_for_each_entry(pin, &pin_list->unflushed[i], list)
			prt_printf(out, "\t%px %ps\n", pin, pin->flush);

	prt_printf(out, "flushed:\n");
	for (unsigned i = 0; i < ARRAY_SIZE(pin_list->flushed); i++)
		list_for_each_entry(pin, &pin_list->flushed[i], list)
			prt_printf(out, "\t%px %ps\n", pin, pin->flush);

	printbuf_indent_sub(out, 2);

	return false;
}

void bch2_journal_pins_to_text(struct printbuf *out, struct journal *j)
{
	u64 seq = 0;

	while (!bch2_journal_seq_pins_to_text(out, j, &seq))
		seq++;
}
