// SPDX-License-Identifier: GPL-2.0
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
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/log2.h>
#include <linux/math64.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched/clock.h>

#include "eytzinger.h"
#include "util.h"

static const char si_units[] = "?kMGTPEZY";

static int __bch2_strtoh(const char *cp, u64 *res,
			 u64 t_max, bool t_signed)
{
	bool positive = *cp != '-';
	unsigned u;
	u64 v = 0;

	if (*cp == '+' || *cp == '-')
		cp++;

	if (!isdigit(*cp))
		return -EINVAL;

	do {
		if (v > U64_MAX / 10)
			return -ERANGE;
		v *= 10;
		if (v > U64_MAX - (*cp - '0'))
			return -ERANGE;
		v += *cp - '0';
		cp++;
	} while (isdigit(*cp));

	for (u = 1; u < strlen(si_units); u++)
		if (*cp == si_units[u]) {
			cp++;
			goto got_unit;
		}
	u = 0;
got_unit:
	if (*cp == '\n')
		cp++;
	if (*cp)
		return -EINVAL;

	if (fls64(v) + u * 10 > 64)
		return -ERANGE;

	v <<= u * 10;

	if (positive) {
		if (v > t_max)
			return -ERANGE;
	} else {
		if (v && !t_signed)
			return -ERANGE;

		if (v > t_max + 1)
			return -ERANGE;
		v = -v;
	}

	*res = v;
	return 0;
}

#define STRTO_H(name, type)					\
int bch2_ ## name ## _h(const char *cp, type *res)		\
{								\
	u64 v;							\
	int ret = __bch2_strtoh(cp, &v, ANYSINT_MAX(type),	\
			ANYSINT_MAX(type) != ((type) ~0ULL));	\
	*res = v;						\
	return ret;						\
}

STRTO_H(strtoint, int)
STRTO_H(strtouint, unsigned int)
STRTO_H(strtoll, long long)
STRTO_H(strtoull, unsigned long long)
STRTO_H(strtou64, u64)

void bch2_hprint(struct printbuf *buf, s64 v)
{
	int u, t = 0;

	for (u = 0; v >= 1024 || v <= -1024; u++) {
		t = v & ~(~0U << 10);
		v >>= 10;
	}

	pr_buf(buf, "%lli", v);

	/*
	 * 103 is magic: t is in the range [-1023, 1023] and we want
	 * to turn it into [-9, 9]
	 */
	if (u && v < 100 && v > -100)
		pr_buf(buf, ".%i", t / 103);
	if (u)
		pr_buf(buf, "%c", si_units[u]);
}

void bch2_string_opt_to_text(struct printbuf *out,
			     const char * const list[],
			     size_t selected)
{
	size_t i;

	for (i = 0; list[i]; i++)
		pr_buf(out, i == selected ? "[%s] " : "%s ", list[i]);
}

void bch2_flags_to_text(struct printbuf *out,
			const char * const list[], u64 flags)
{
	unsigned bit, nr = 0;
	bool first = true;

	if (out->pos != out->end)
		*out->pos = '\0';

	while (list[nr])
		nr++;

	while (flags && (bit = __ffs(flags)) < nr) {
		if (!first)
			pr_buf(out, ",");
		first = false;
		pr_buf(out, "%s", list[bit]);
		flags ^= 1 << bit;
	}
}

u64 bch2_read_flag_list(char *opt, const char * const list[])
{
	u64 ret = 0;
	char *p, *s, *d = kstrdup(opt, GFP_KERNEL);

	if (!d)
		return -ENOMEM;

	s = strim(d);

	while ((p = strsep(&s, ","))) {
		int flag = match_string(list, -1, p);
		if (flag < 0) {
			ret = -1;
			break;
		}

		ret |= 1 << flag;
	}

	kfree(d);

	return ret;
}

bool bch2_is_zero(const void *_p, size_t n)
{
	const char *p = _p;
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i])
			return false;
	return true;
}

static void bch2_quantiles_update(struct quantiles *q, u64 v)
{
	unsigned i = 0;

	while (i < ARRAY_SIZE(q->entries)) {
		struct quantile_entry *e = q->entries + i;

		if (unlikely(!e->step)) {
			e->m = v;
			e->step = max_t(unsigned, v / 2, 1024);
		} else if (e->m > v) {
			e->m = e->m >= e->step
				? e->m - e->step
				: 0;
		} else if (e->m < v) {
			e->m = e->m + e->step > e->m
				? e->m + e->step
				: U32_MAX;
		}

		if ((e->m > v ? e->m - v : v - e->m) < e->step)
			e->step = max_t(unsigned, e->step / 2, 1);

		if (v >= e->m)
			break;

		i = eytzinger0_child(i, v > e->m);
	}
}

/* time stats: */

static void bch2_time_stats_update_one(struct time_stats *stats,
				       u64 start, u64 end)
{
	u64 duration, freq;

	duration	= time_after64(end, start)
		? end - start : 0;
	freq		= time_after64(end, stats->last_event)
		? end - stats->last_event : 0;

	stats->count++;

	stats->average_duration = stats->average_duration
		? ewma_add(stats->average_duration, duration, 6)
		: duration;

	stats->average_frequency = stats->average_frequency
		? ewma_add(stats->average_frequency, freq, 6)
		: freq;

	stats->max_duration = max(stats->max_duration, duration);

	stats->last_event = end;

	bch2_quantiles_update(&stats->quantiles, duration);
}

void __bch2_time_stats_update(struct time_stats *stats, u64 start, u64 end)
{
	unsigned long flags;

	if (!stats->buffer) {
		spin_lock_irqsave(&stats->lock, flags);
		bch2_time_stats_update_one(stats, start, end);

		if (stats->average_frequency < 32 &&
		    stats->count > 1024)
			stats->buffer =
				alloc_percpu_gfp(struct time_stat_buffer,
						 GFP_ATOMIC);
		spin_unlock_irqrestore(&stats->lock, flags);
	} else {
		struct time_stat_buffer_entry *i;
		struct time_stat_buffer *b;

		preempt_disable();
		b = this_cpu_ptr(stats->buffer);

		BUG_ON(b->nr >= ARRAY_SIZE(b->entries));
		b->entries[b->nr++] = (struct time_stat_buffer_entry) {
			.start = start,
			.end = end
		};

		if (b->nr == ARRAY_SIZE(b->entries)) {
			spin_lock_irqsave(&stats->lock, flags);
			for (i = b->entries;
			     i < b->entries + ARRAY_SIZE(b->entries);
			     i++)
				bch2_time_stats_update_one(stats, i->start, i->end);
			spin_unlock_irqrestore(&stats->lock, flags);

			b->nr = 0;
		}

		preempt_enable();
	}
}

static const struct time_unit {
	const char	*name;
	u32		nsecs;
} time_units[] = {
	{ "ns",		1		},
	{ "us",		NSEC_PER_USEC	},
	{ "ms",		NSEC_PER_MSEC	},
	{ "sec",	NSEC_PER_SEC	},
};

static const struct time_unit *pick_time_units(u64 ns)
{
	const struct time_unit *u;

	for (u = time_units;
	     u + 1 < time_units + ARRAY_SIZE(time_units) &&
	     ns >= u[1].nsecs << 1;
	     u++)
		;

	return u;
}

static void pr_time_units(struct printbuf *out, u64 ns)
{
	const struct time_unit *u = pick_time_units(ns);

	pr_buf(out, "%llu %s", div_u64(ns, u->nsecs), u->name);
}

void bch2_time_stats_to_text(struct printbuf *out, struct time_stats *stats)
{
	const struct time_unit *u;
	u64 freq = READ_ONCE(stats->average_frequency);
	u64 q, last_q = 0;
	int i;

	pr_buf(out, "count:\t\t%llu\n",
			 stats->count);
	pr_buf(out, "rate:\t\t%llu/sec\n",
	       freq ?  div64_u64(NSEC_PER_SEC, freq) : 0);

	pr_buf(out, "frequency:\t");
	pr_time_units(out, freq);

	pr_buf(out, "\navg duration:\t");
	pr_time_units(out, stats->average_duration);

	pr_buf(out, "\nmax duration:\t");
	pr_time_units(out, stats->max_duration);

	i = eytzinger0_first(NR_QUANTILES);
	u = pick_time_units(stats->quantiles.entries[i].m);

	pr_buf(out, "\nquantiles (%s):\t", u->name);
	eytzinger0_for_each(i, NR_QUANTILES) {
		bool is_last = eytzinger0_next(i, NR_QUANTILES) == -1;

		q = max(stats->quantiles.entries[i].m, last_q);
		pr_buf(out, "%llu%s",
		       div_u64(q, u->nsecs),
		       is_last ? "\n" : " ");
		last_q = q;
	}
}

void bch2_time_stats_exit(struct time_stats *stats)
{
	free_percpu(stats->buffer);
}

void bch2_time_stats_init(struct time_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	spin_lock_init(&stats->lock);
}

/* ratelimit: */

/**
 * bch2_ratelimit_delay() - return how long to delay until the next time to do
 * some work
 *
 * @d - the struct bch_ratelimit to update
 *
 * Returns the amount of time to delay by, in jiffies
 */
u64 bch2_ratelimit_delay(struct bch_ratelimit *d)
{
	u64 now = local_clock();

	return time_after64(d->next, now)
		? nsecs_to_jiffies(d->next - now)
		: 0;
}

/**
 * bch2_ratelimit_increment() - increment @d by the amount of work done
 *
 * @d - the struct bch_ratelimit to update
 * @done - the amount of work done, in arbitrary units
 */
void bch2_ratelimit_increment(struct bch_ratelimit *d, u64 done)
{
	u64 now = local_clock();

	d->next += div_u64(done * NSEC_PER_SEC, d->rate);

	if (time_before64(now + NSEC_PER_SEC, d->next))
		d->next = now + NSEC_PER_SEC;

	if (time_after64(now - NSEC_PER_SEC * 2, d->next))
		d->next = now - NSEC_PER_SEC * 2;
}

/* pd controller: */

/*
 * Updates pd_controller. Attempts to scale inputed values to units per second.
 * @target: desired value
 * @actual: current value
 *
 * @sign: 1 or -1; 1 if increasing the rate makes actual go up, -1 if increasing
 * it makes actual go down.
 */
void bch2_pd_controller_update(struct bch_pd_controller *pd,
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

void bch2_pd_controller_init(struct bch_pd_controller *pd)
{
	pd->rate.rate		= 1024;
	pd->last_update		= jiffies;
	pd->p_term_inverse	= 6000;
	pd->d_term		= 30;
	pd->d_smooth		= pd->d_term;
	pd->backpressure	= 1;
}

size_t bch2_pd_controller_print_debug(struct bch_pd_controller *pd, char *buf)
{
	/* 2^64 - 1 is 20 digits, plus null byte */
	char rate[21];
	char actual[21];
	char target[21];
	char proportional[21];
	char derivative[21];
	char change[21];
	s64 next_io;

	bch2_hprint(&PBUF(rate),	pd->rate.rate);
	bch2_hprint(&PBUF(actual),	pd->last_actual);
	bch2_hprint(&PBUF(target),	pd->last_target);
	bch2_hprint(&PBUF(proportional), pd->last_proportional);
	bch2_hprint(&PBUF(derivative),	pd->last_derivative);
	bch2_hprint(&PBUF(change),	pd->last_change);

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

/* misc: */

void bch2_bio_map(struct bio *bio, void *base, size_t size)
{
	while (size) {
		struct page *page = is_vmalloc_addr(base)
				? vmalloc_to_page(base)
				: virt_to_page(base);
		unsigned offset = offset_in_page(base);
		unsigned len = min_t(size_t, PAGE_SIZE - offset, size);

		BUG_ON(!bio_add_page(bio, page, len, offset));
		size -= len;
		base += len;
	}
}

int bch2_bio_alloc_pages(struct bio *bio, size_t size, gfp_t gfp_mask)
{
	while (size) {
		struct page *page = alloc_page(gfp_mask);
		unsigned len = min_t(size_t, PAGE_SIZE, size);

		if (!page)
			return -ENOMEM;

		BUG_ON(!bio_add_page(bio, page, len, 0));
		size -= len;
	}

	return 0;
}

size_t bch2_rand_range(size_t max)
{
	size_t rand;

	if (!max)
		return 0;

	do {
		rand = get_random_long();
		rand &= roundup_pow_of_two(max) - 1;
	} while (rand >= max);

	return rand;
}

void memcpy_to_bio(struct bio *dst, struct bvec_iter dst_iter, const void *src)
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

void bch_scnmemcpy(struct printbuf *out,
		   const char *src, size_t len)
{
	size_t n = printbuf_remaining(out);

	if (n) {
		n = min(n - 1, len);
		memcpy(out->pos, src, n);
		out->pos += n;
		*out->pos = '\0';
	}
}

#include "eytzinger.h"

static int alignment_ok(const void *base, size_t align)
{
	return IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) ||
		((unsigned long)base & (align - 1)) == 0;
}

static void u32_swap(void *a, void *b, size_t size)
{
	u32 t = *(u32 *)a;
	*(u32 *)a = *(u32 *)b;
	*(u32 *)b = t;
}

static void u64_swap(void *a, void *b, size_t size)
{
	u64 t = *(u64 *)a;
	*(u64 *)a = *(u64 *)b;
	*(u64 *)b = t;
}

static void generic_swap(void *a, void *b, size_t size)
{
	char t;

	do {
		t = *(char *)a;
		*(char *)a++ = *(char *)b;
		*(char *)b++ = t;
	} while (--size > 0);
}

static inline int do_cmp(void *base, size_t n, size_t size,
			 int (*cmp_func)(const void *, const void *, size_t),
			 size_t l, size_t r)
{
	return cmp_func(base + inorder_to_eytzinger0(l, n) * size,
			base + inorder_to_eytzinger0(r, n) * size,
			size);
}

static inline void do_swap(void *base, size_t n, size_t size,
			   void (*swap_func)(void *, void *, size_t),
			   size_t l, size_t r)
{
	swap_func(base + inorder_to_eytzinger0(l, n) * size,
		  base + inorder_to_eytzinger0(r, n) * size,
		  size);
}

void eytzinger0_sort(void *base, size_t n, size_t size,
		     int (*cmp_func)(const void *, const void *, size_t),
		     void (*swap_func)(void *, void *, size_t))
{
	int i, c, r;

	if (!swap_func) {
		if (size == 4 && alignment_ok(base, 4))
			swap_func = u32_swap;
		else if (size == 8 && alignment_ok(base, 8))
			swap_func = u64_swap;
		else
			swap_func = generic_swap;
	}

	/* heapify */
	for (i = n / 2 - 1; i >= 0; --i) {
		for (r = i; r * 2 + 1 < n; r = c) {
			c = r * 2 + 1;

			if (c + 1 < n &&
			    do_cmp(base, n, size, cmp_func, c, c + 1) < 0)
				c++;

			if (do_cmp(base, n, size, cmp_func, r, c) >= 0)
				break;

			do_swap(base, n, size, swap_func, r, c);
		}
	}

	/* sort */
	for (i = n - 1; i > 0; --i) {
		do_swap(base, n, size, swap_func, 0, i);

		for (r = 0; r * 2 + 1 < i; r = c) {
			c = r * 2 + 1;

			if (c + 1 < i &&
			    do_cmp(base, n, size, cmp_func, c, c + 1) < 0)
				c++;

			if (do_cmp(base, n, size, cmp_func, r, c) >= 0)
				break;

			do_swap(base, n, size, swap_func, r, c);
		}
	}
}

void sort_cmp_size(void *base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *, size_t),
	  void (*swap_func)(void *, void *, size_t size))
{
	/* pre-scale counters for performance */
	int i = (num/2 - 1) * size, n = num * size, c, r;

	if (!swap_func) {
		if (size == 4 && alignment_ok(base, 4))
			swap_func = u32_swap;
		else if (size == 8 && alignment_ok(base, 8))
			swap_func = u64_swap;
		else
			swap_func = generic_swap;
	}

	/* heapify */
	for ( ; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r  = c) {
			c = r * 2 + size;
			if (c < n - size &&
			    cmp_func(base + c, base + c + size, size) < 0)
				c += size;
			if (cmp_func(base + r, base + c, size) >= 0)
				break;
			swap_func(base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size) {
		swap_func(base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size &&
			    cmp_func(base + c, base + c + size, size) < 0)
				c += size;
			if (cmp_func(base + r, base + c, size) >= 0)
				break;
			swap_func(base + r, base + c, size);
		}
	}
}

static void mempool_free_vp(void *element, void *pool_data)
{
	size_t size = (size_t) pool_data;

	vpfree(element, size);
}

static void *mempool_alloc_vp(gfp_t gfp_mask, void *pool_data)
{
	size_t size = (size_t) pool_data;

	return vpmalloc(size, gfp_mask);
}

int mempool_init_kvpmalloc_pool(mempool_t *pool, int min_nr, size_t size)
{
	return size < PAGE_SIZE
		? mempool_init_kmalloc_pool(pool, min_nr, size)
		: mempool_init(pool, min_nr, mempool_alloc_vp,
			       mempool_free_vp, (void *) size);
}

#if 0
void eytzinger1_test(void)
{
	unsigned inorder, eytz, size;

	pr_info("1 based eytzinger test:");

	for (size = 2;
	     size < 65536;
	     size++) {
		unsigned extra = eytzinger1_extra(size);

		if (!(size % 4096))
			pr_info("tree size %u", size);

		BUG_ON(eytzinger1_prev(0, size) != eytzinger1_last(size));
		BUG_ON(eytzinger1_next(0, size) != eytzinger1_first(size));

		BUG_ON(eytzinger1_prev(eytzinger1_first(size), size)	!= 0);
		BUG_ON(eytzinger1_next(eytzinger1_last(size), size)	!= 0);

		inorder = 1;
		eytzinger1_for_each(eytz, size) {
			BUG_ON(__inorder_to_eytzinger1(inorder, size, extra) != eytz);
			BUG_ON(__eytzinger1_to_inorder(eytz, size, extra) != inorder);
			BUG_ON(eytz != eytzinger1_last(size) &&
			       eytzinger1_prev(eytzinger1_next(eytz, size), size) != eytz);

			inorder++;
		}
	}
}

void eytzinger0_test(void)
{

	unsigned inorder, eytz, size;

	pr_info("0 based eytzinger test:");

	for (size = 1;
	     size < 65536;
	     size++) {
		unsigned extra = eytzinger0_extra(size);

		if (!(size % 4096))
			pr_info("tree size %u", size);

		BUG_ON(eytzinger0_prev(-1, size) != eytzinger0_last(size));
		BUG_ON(eytzinger0_next(-1, size) != eytzinger0_first(size));

		BUG_ON(eytzinger0_prev(eytzinger0_first(size), size)	!= -1);
		BUG_ON(eytzinger0_next(eytzinger0_last(size), size)	!= -1);

		inorder = 0;
		eytzinger0_for_each(eytz, size) {
			BUG_ON(__inorder_to_eytzinger0(inorder, size, extra) != eytz);
			BUG_ON(__eytzinger0_to_inorder(eytz, size, extra) != inorder);
			BUG_ON(eytz != eytzinger0_last(size) &&
			       eytzinger0_prev(eytzinger0_next(eytz, size), size) != eytz);

			inorder++;
		}
	}
}

static inline int cmp_u16(const void *_l, const void *_r, size_t size)
{
	const u16 *l = _l, *r = _r;

	return (*l > *r) - (*r - *l);
}

static void eytzinger0_find_test_val(u16 *test_array, unsigned nr, u16 search)
{
	int i, c1 = -1, c2 = -1;
	ssize_t r;

	r = eytzinger0_find_le(test_array, nr,
			       sizeof(test_array[0]),
			       cmp_u16, &search);
	if (r >= 0)
		c1 = test_array[r];

	for (i = 0; i < nr; i++)
		if (test_array[i] <= search && test_array[i] > c2)
			c2 = test_array[i];

	if (c1 != c2) {
		eytzinger0_for_each(i, nr)
			pr_info("[%3u] = %12u", i, test_array[i]);
		pr_info("find_le(%2u) -> [%2zi] = %2i should be %2i",
			i, r, c1, c2);
	}
}

void eytzinger0_find_test(void)
{
	unsigned i, nr, allocated = 1 << 12;
	u16 *test_array = kmalloc_array(allocated, sizeof(test_array[0]), GFP_KERNEL);

	for (nr = 1; nr < allocated; nr++) {
		pr_info("testing %u elems", nr);

		get_random_bytes(test_array, nr * sizeof(test_array[0]));
		eytzinger0_sort(test_array, nr, sizeof(test_array[0]), cmp_u16, NULL);

		/* verify array is sorted correctly: */
		eytzinger0_for_each(i, nr)
			BUG_ON(i != eytzinger0_last(nr) &&
			       test_array[i] > test_array[eytzinger0_next(i, nr)]);

		for (i = 0; i < U16_MAX; i += 1 << 12)
			eytzinger0_find_test_val(test_array, nr, i);

		for (i = 0; i < nr; i++) {
			eytzinger0_find_test_val(test_array, nr, test_array[i] - 1);
			eytzinger0_find_test_val(test_array, nr, test_array[i]);
			eytzinger0_find_test_val(test_array, nr, test_array[i] + 1);
		}
	}

	kfree(test_array);
}
#endif

/*
 * Accumulate percpu counters onto one cpu's copy - only valid when access
 * against any percpu counter is guarded against
 */
u64 *bch2_acc_percpu_u64s(u64 __percpu *p, unsigned nr)
{
	u64 *ret = this_cpu_ptr(p);
	int cpu;

	for_each_possible_cpu(cpu) {
		u64 *i = per_cpu_ptr(p, cpu);

		if (i != ret) {
			acc_u64s(ret, i, nr);
			memset(i, 0, nr * sizeof(u64));
		}
	}

	return ret;
}
