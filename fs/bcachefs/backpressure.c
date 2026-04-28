// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "backpressure.h"

/*
 * Map an FS backpressure type to its blocked-time time_stat slot. Built from
 * the same x-macro that folds the FS bp types into BCH_TIME_STATS, so the
 * names line up by construction.
 */
static const u8 bch2_backpressure_fs_time_stats[] = {
#define x(n, ...)	[BCH_BACKPRESSURE_FS_##n] = BCH_TIME_blocked_##n,
	BCH_BACKPRESSURE_FS_TYPES(x)
#undef x
};

/*
 * Pack one 2-bit level per type into bp->state. Producers call this when
 * their pressure reading crosses a threshold; if the new level is lower
 * than what was there, wake any closures parked on the relevant fs's
 * wait queue so they can re-evaluate. Returns the previous level so
 * callers that want to react to a rise (e.g. kicking journal reclaim)
 * can compare without a separate read.
 */
static enum bch_backpressure_level
__backpressure_set(struct bch_fs *c,
		   struct bch_backpressure *bp,
		   unsigned type,
		   enum bch_backpressure_level new_level,
		   int time_stat)
{
	unsigned shift = type * 2;
	unsigned long mask = 3UL << shift;
	unsigned long val = (unsigned long) new_level << shift;
	unsigned long old = READ_ONCE(bp->state), new;
	enum bch_backpressure_level old_level;

	do {
		old_level = (old >> shift) & 3;
		if (old_level == new_level)
			return old_level;
		new = (old & ~mask) | val;
	} while (!try_cmpxchg(&bp->state, &old, new));

	if (new_level < old_level)
		closure_wake_up(&c->backpressure.wait);

	if (time_stat >= 0)
		track_event_change(&c->times[time_stat], new_level);

	return old_level;
}

enum bch_backpressure_level
__bch2_backpressure_fs_set(struct bch_fs *c,
			   enum bch_backpressure_fs_type type,
			   enum bch_backpressure_level new_level)
{
	return __backpressure_set(c, &c->backpressure, type, new_level,
				  bch2_backpressure_fs_time_stats[type]);
}

enum bch_backpressure_level
__bch2_backpressure_dev_set(struct bch_dev *ca,
			    enum bch_backpressure_dev_type type,
			    enum bch_backpressure_level new_level)
{
	/*
	 * Dev-side time_stats live per-device; not wired through the fs
	 * BCH_TIME_STATS array yet. Pass -1 so __backpressure_set skips it.
	 */
	return __backpressure_set(ca->fs, &ca->backpressure, type, new_level, -1);
}

bool bch2_backpressure_check(struct bch_fs *c, enum bch_process process)
{
	switch (process) {
	case BCH_PROCESS_foreground:
	case BCH_PROCESS_reconcile:
		return c->backpressure.state != 0;
	case BCH_PROCESS_discard:
	case BCH_PROCESS_invalidate:
	case BCH_PROCESS_copygc:
	case BCH_PROCESS_journal_reclaim:
	case BCH_PROCESS_btree_interior_updates:
	case BCH_PROCESS_key_cache_flush:
	case BCH_PROCESS_write_buffer_flush:
		/* TODO: per-process rules */
		return false;
	default:
		return false;
	}
}

void bch2_backpressure_wait(struct bch_fs *c, enum bch_process process)
{
	closure_wait_event(&c->backpressure.wait, !bch2_backpressure_check(c, process));
}
