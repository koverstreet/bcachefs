/*
 * random utiility code, for bcache but in theory not specific to bcache
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/types.h>

#include <linux/freezer.h>
#include <linux/kthread.h>

#include "util.h"

#define simple_strtoint(c, end, base)	simple_strtol(c, end, base)
#define simple_strtouint(c, end, base)	simple_strtoul(c, end, base)

#define STRTO_H(name, type)					\
int bch_ ## name ## _h(const char *cp, type *res)		\
{								\
	int u = 0;						\
	char *e;						\
	type i = simple_ ## name(cp, &e, 10);			\
								\
	switch (tolower(*e)) {					\
	default:						\
		return -EINVAL;					\
	case 'y':						\
	case 'z':						\
		u++;						\
	case 'e':						\
		u++;						\
	case 'p':						\
		u++;						\
	case 't':						\
		u++;						\
	case 'g':						\
		u++;						\
	case 'm':						\
		u++;						\
	case 'k':						\
		u++;						\
		if (e++ == cp)					\
			return -EINVAL;				\
	case '\n':						\
	case '\0':						\
		if (*e == '\n')					\
			e++;					\
	}							\
								\
	if (*e)							\
		return -EINVAL;					\
								\
	while (u--) {						\
		if ((type) ~0 > 0 &&				\
		    (type) ~0 / 1024 <= i)			\
			return -EINVAL;				\
		if ((i > 0 && ANYSINT_MAX(type) / 1024 < i) ||	\
		    (i < 0 && -ANYSINT_MAX(type) / 1024 > i))	\
			return -EINVAL;				\
		i *= 1024;					\
	}							\
								\
	*res = i;						\
	return 0;						\
}								\

STRTO_H(strtoint, int)
STRTO_H(strtouint, unsigned int)
STRTO_H(strtoll, long long)
STRTO_H(strtoull, unsigned long long)

ssize_t bch_hprint(char *buf, int64_t v)
{
	static const char units[] = "?kMGTPEZY";
	char dec[4] = "";
	int u, t = 0;

	for (u = 0; v >= 1024 || v <= -1024; u++) {
		t = v & ~(~0 << 10);
		v >>= 10;
	}

	if (!u)
		return sprintf(buf, "%lli", v);

	/*
	 * 103 is magic: t is in the range [-1023, 1023] and we want
	 * to turn it into [-9, 9]
	 */
	if (v < 100 && v > -100)
		snprintf(dec, sizeof(dec), ".%i", t / 103);

	return sprintf(buf, "%lli%s%c", v, dec, units[u]);
}

ssize_t bch_snprint_string_list(char *buf, size_t size, const char * const list[],
			    size_t selected)
{
	char *out = buf;
	size_t i;

	for (i = 0; list[i]; i++)
		out += snprintf(out, buf + size - out,
				i == selected ? "[%s] " : "%s ", list[i]);

	out[-1] = '\n';
	return out - buf;
}

ssize_t bch_read_string_list(const char *buf, const char * const list[])
{
	size_t i;
	char *s, *d = kstrndup(buf, PAGE_SIZE - 1, GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	s = strim(d);

	for (i = 0; list[i]; i++)
		if (!strcmp(list[i], s))
			break;

	kfree(d);

	if (!list[i])
		return -EINVAL;

	return i;
}

bool bch_is_zero(const char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i])
			return false;
	return true;
}

void bch_time_stats_clear(struct time_stats *stats)
{
	spin_lock(&stats->lock);

	stats->count = 0;
	stats->last_duration = 0;
	stats->max_duration = 0;
	stats->average_duration = 0;
	stats->average_frequency = 0;
	stats->last = 0;

	spin_unlock(&stats->lock);
}

void __bch_time_stats_update(struct time_stats *stats, u64 start_time)
{
	u64 now, duration, last;

	stats->count++;

	now		= local_clock();
	duration	= time_after64(now, start_time)
		? now - start_time : 0;
	last		= time_after64(now, stats->last)
		? now - stats->last : 0;

	stats->last_duration = duration;
	stats->max_duration = max(stats->max_duration, duration);

	if (stats->last) {
		stats->average_duration = ewma_add(stats->average_duration,
						   duration << 8, 3);

		if (stats->average_frequency)
			stats->average_frequency =
				ewma_add(stats->average_frequency,
					 last << 8, 3);
		else
			stats->average_frequency  = last << 8;
	} else {
		stats->average_duration = duration << 8;
	}

	stats->last = now ?: 1;
}

void bch_time_stats_update(struct time_stats *stats, u64 start_time)
{
	spin_lock(&stats->lock);
	__bch_time_stats_update(stats, start_time);
	spin_unlock(&stats->lock);
}

/**
 * bch_ratelimit_delay() - return how long to delay until the next time to do
 * some work
 *
 * @d - the struct bch_ratelimit to update
 *
 * Returns the amount of time to delay by, in jiffies
 */
u64 bch_ratelimit_delay(struct bch_ratelimit *d)
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
void bch_ratelimit_increment(struct bch_ratelimit *d, u64 done)
{
	u64 now = local_clock();

	d->next += div_u64(done * NSEC_PER_SEC, d->rate);

	if (time_before64(now + NSEC_PER_SEC, d->next))
		d->next = now + NSEC_PER_SEC;

	if (time_after64(now - NSEC_PER_SEC * 2, d->next))
		d->next = now - NSEC_PER_SEC * 2;
}

int bch_ratelimit_wait_freezable_stoppable(struct bch_ratelimit *d,
					   struct closure *cl)
{
	while (1) {
		u64 delay = bch_ratelimit_delay(d);

		if (delay)
			set_current_state(TASK_INTERRUPTIBLE);

		if (kthread_should_stop()) {
			closure_sync(cl);
			return 1;
		}

		if (!delay)
			return 0;

		schedule_timeout(delay);
		try_to_freeze();
	}
}

/*
 * Updates pd_controller. Attempts to scale inputed values to units per second.
 * @target: desired value
 * @actual: current value
 *
 * @sign: 1 or -1; 1 if increasing the rate makes actual go up, -1 if increasing
 * it makes actual go down.
 */
void bch_pd_controller_update(struct bch_pd_controller *pd,
			      s64 target, s64 actual, int sign)
{
	s64 proportional, derivative, change;

	unsigned long seconds_since_update = (jiffies - pd->last_update) / HZ;

	if (seconds_since_update == 0)
		return;

	pd->last_update = jiffies;

	proportional = actual - target;
	proportional *= seconds_since_update;
	proportional = div_s64(proportional, pd->p_term_inverse);

	derivative = actual - pd->last_actual;
	derivative = div_s64(derivative, seconds_since_update);
	derivative = ewma_add(pd->smoothed_derivative, derivative,
			      (pd->d_term / seconds_since_update) ?: 1);
	derivative = derivative * pd->d_term;
	derivative = div_s64(derivative, pd->p_term_inverse);

	change = proportional + derivative;

	/* Don't increase rate if not keeping up */
	if (change > 0 &&
	    pd->backpressure &&
	    time_after64(local_clock(),
			 pd->rate.next + NSEC_PER_MSEC))
		change = 0;

	change *= (sign * -1);

	pd->rate.rate = clamp_t(s64, (s64) pd->rate.rate + change,
				1, UINT_MAX);

	pd->last_actual		= actual;
	pd->last_derivative	= derivative;
	pd->last_proportional	= proportional;
	pd->last_change		= change;
	pd->last_target		= target;
}

void bch_pd_controller_init(struct bch_pd_controller *pd)
{
	pd->rate.rate		= 1024;
	pd->last_update		= jiffies;
	pd->p_term_inverse	= 6000;
	pd->d_term		= 30;
	pd->d_smooth		= pd->d_term;
	pd->backpressure	= 1;
}

size_t bch_pd_controller_print_debug(struct bch_pd_controller *pd, char *buf)
{
	/* 2^64 - 1 is 20 digits, plus null byte */
	char rate[21];
	char actual[21];
	char target[21];
	char proportional[21];
	char derivative[21];
	char change[21];
	s64 next_io;

	bch_hprint(rate,	pd->rate.rate);
	bch_hprint(actual,	pd->last_actual);
	bch_hprint(target,	pd->last_target);
	bch_hprint(proportional, pd->last_proportional);
	bch_hprint(derivative,	pd->last_derivative);
	bch_hprint(change,	pd->last_change);

	next_io = div64_s64(pd->rate.next - local_clock(), NSEC_PER_MSEC);

	return sprintf(buf,
		       "rate:\t\t%s/sec\n"
		       "target:\t\t%s\n"
		       "actual:\t\t%s\n"
		       "proportional:\t%s\n"
		       "derivative:\t%s\n"
		       "change:\t\t%s/sec\n"
		       "next io:\t%llims\n",
		       rate, target, actual, proportional,
		       derivative, change, next_io);
}

void bch_bio_map(struct bio *bio, void *base)
{
	size_t size = bio->bi_iter.bi_size;
	struct bio_vec *bv = bio->bi_io_vec;

	BUG_ON(!bio->bi_iter.bi_size);
	BUG_ON(bio->bi_vcnt);

	bv->bv_offset = base ? offset_in_page(base) : 0;
	goto start;

	for (; size; bio->bi_vcnt++, bv++) {
		bv->bv_offset	= 0;
start:		bv->bv_len	= min_t(size_t, PAGE_SIZE - bv->bv_offset,
					size);
		if (base) {
			bv->bv_page = is_vmalloc_addr(base)
				? vmalloc_to_page(base)
				: virt_to_page(base);

			base += bv->bv_len;
		}

		size -= bv->bv_len;
	}
}

size_t bch_rand_range(size_t max)
{
	size_t rand;

	do {
		get_random_bytes(&rand, sizeof(rand));
		rand &= roundup_pow_of_two(max) - 1;
	} while (rand >= max);

	return rand;
}

void memcpy_to_bio(struct bio *dst, struct bvec_iter dst_iter, void *src)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	__bio_for_each_segment(bv, dst, iter, dst_iter) {
		void *dstp = kmap_atomic(bv.bv_page);
		memcpy(dstp + bv.bv_offset, src, bv.bv_len);
		kunmap_atomic(dstp);

		src += bv.bv_len;
	}
}

void memcpy_from_bio(void *dst, struct bio *src, struct bvec_iter src_iter)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	__bio_for_each_segment(bv, src, iter, src_iter) {
		void *srcp = kmap_atomic(bv.bv_page);
		memcpy(dst, srcp + bv.bv_offset, bv.bv_len);
		kunmap_atomic(srcp);

		dst += bv.bv_len;
	}
}
