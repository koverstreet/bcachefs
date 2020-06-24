#ifndef _LINUX_BCACHE_RATELIMIT_H
#define _LINUX_BCACHE_RATELIMIT_H

#include <linux/sched/clock.h>

struct bch_ratelimit {
	/* Next time we want to do some work, in nanoseconds */
	uint64_t		next;

	/*
	 * Rate at which we want to do work, in units per second
	 * The units here correspond to the units passed to bch_next_delay()
	 */
	unsigned		rate;
};

static inline void bch_ratelimit_reset(struct bch_ratelimit *d)
{
	d->next = local_clock();
}

/**
 * bch_ratelimit_delay() - return how long to delay until the next time to do
 * some work
 *
 * @d - the struct bch_ratelimit to update
 *
 * Returns the amount of time to delay by, in jiffies
 */
static inline u64 bch_ratelimit_delay(struct bch_ratelimit *d)
{
	u64 now = local_clock();

	return time_after64(d->next, now)
		? nsecs_to_jiffies(d->next - now)
		: 0;
}

/**
 * bch_ratelimit_increment() - increment @d by the amount of work done
 *
 * @d - the struct bch_ratelimit to update
 * @done - the amount of work done, in arbitrary units
 */
static inline void bch_ratelimit_increment(struct bch_ratelimit *d, u64 done)
{
	u64 now = local_clock();

	d->next += div_u64(done * NSEC_PER_SEC, d->rate);

	/*
	 * Bound the time.  Don't let us fall further than 2 seconds behind
	 * (this prevents unnecessary backlog that would make it impossible
	 * to catch up).  If we're ahead of the desired writeback rate,
	 * don't let us sleep more than 2.5 seconds (so we can notice/respond
	 * if the control system tells us to speed up!).
	 */
	if (time_before64(now + NSEC_PER_SEC, d->next))
		d->next = now + NSEC_PER_SEC;

	if (time_after64(now - NSEC_PER_SEC * 2, d->next))
		d->next = now - NSEC_PER_SEC * 2;
}

/**
 * bch_next_delay() - update ratelimiting statistics and calculate next delay
 * @d: the struct bch_ratelimit to update
 * @done: the amount of work done, in arbitrary units
 *
 * Increment @d by the amount of work done, and return how long to delay in
 * jiffies until the next time to do some work.
 */
static inline u64 bch_next_delay(struct bch_ratelimit *d, u64 done)
{
	bch_ratelimit_increment(d, done);

	return bch_ratelimit_delay(d);
}

#endif /* _LINUX_BCACHE_RATELIMIT_H */
