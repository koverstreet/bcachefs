// SPDX-License-Identifier: GPL-2.0

#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/time.h>
#include <linux/spinlock.h>

#include "eytzinger.h"
#include "time_stats.h"

/* disable automatic switching to percpu mode */
#define TIME_STATS_NONPCPU	((unsigned long) 1)

static const struct time_unit time_units[] = {
	{ "ns",		1		 },
	{ "us",		NSEC_PER_USEC	 },
	{ "ms",		NSEC_PER_MSEC	 },
	{ "s",		NSEC_PER_SEC	 },
	{ "m",          (u64) NSEC_PER_SEC * 60},
	{ "h",          (u64) NSEC_PER_SEC * 3600},
	{ "d",          (u64) NSEC_PER_SEC * 3600 * 24},
	{ "w",          (u64) NSEC_PER_SEC * 3600 * 24 * 7},
	{ "y",          (u64) NSEC_PER_SEC * ((3600 * 24 * 7 * 365) + (3600 * (24 / 4) * 7))}, /* 365.25d */
	{ "eon",        U64_MAX          },
};

const struct time_unit *bch2_pick_time_units(u64 ns)
{
	const struct time_unit *u;

	for (u = time_units;
	     u + 1 < time_units + ARRAY_SIZE(time_units) &&
	     ns >= u[1].nsecs << 1;
	     u++)
		;

	return u;
}

static void quantiles_update(struct quantiles *q, u64 v)
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

static inline void time_stats_update_one(struct bch2_time_stats *stats,
					      u64 start, u64 end)
{
	u64 duration, freq;
	bool initted = stats->last_event != 0;

	if (time_after64(end, start)) {
		struct quantiles *quantiles = time_stats_to_quantiles(stats);

		duration = end - start;
		mean_and_variance_update(&stats->duration_stats, duration);
		mean_and_variance_weighted_update(&stats->duration_stats_weighted,
				duration, initted, TIME_STATS_MV_WEIGHT);
		stats->max_duration = max(stats->max_duration, duration);
		stats->min_duration = min(stats->min_duration, duration);
		stats->total_duration += duration;

		if (quantiles)
			quantiles_update(quantiles, duration);
	}

	if (stats->last_event && time_after64(end, stats->last_event)) {
		freq = end - stats->last_event;
		mean_and_variance_update(&stats->freq_stats, freq);
		mean_and_variance_weighted_update(&stats->freq_stats_weighted,
				freq, initted, TIME_STATS_MV_WEIGHT);
		stats->max_freq = max(stats->max_freq, freq);
		stats->min_freq = min(stats->min_freq, freq);
	}

	stats->last_event = end;
}

void __bch2_time_stats_clear_buffer(struct bch2_time_stats *stats,
				    struct time_stat_buffer *b)
{
	for (struct time_stat_buffer_entry *i = b->entries;
	     i < b->entries + ARRAY_SIZE(b->entries);
	     i++)
		time_stats_update_one(stats, i->start, i->end);
	b->nr = 0;
}

static noinline void time_stats_clear_buffer(struct bch2_time_stats *stats,
					     struct time_stat_buffer *b)
{
	unsigned long flags;

	spin_lock_irqsave(&stats->lock, flags);
	__bch2_time_stats_clear_buffer(stats, b);
	spin_unlock_irqrestore(&stats->lock, flags);
}

void __bch2_time_stats_update(struct bch2_time_stats *stats, u64 start, u64 end)
{
	unsigned long flags;

	if ((unsigned long) stats->buffer <= TIME_STATS_NONPCPU) {
		spin_lock_irqsave(&stats->lock, flags);
		time_stats_update_one(stats, start, end);

		if (!stats->buffer &&
		    mean_and_variance_weighted_get_mean(stats->freq_stats_weighted, TIME_STATS_MV_WEIGHT) < 32 &&
		    stats->duration_stats.n > 1024)
			stats->buffer =
				alloc_percpu_gfp(struct time_stat_buffer,
						 GFP_ATOMIC);
		spin_unlock_irqrestore(&stats->lock, flags);
	} else {
		guard(preempt)();
		struct time_stat_buffer *b = this_cpu_ptr(stats->buffer);

		BUG_ON(b->nr >= ARRAY_SIZE(b->entries));
		b->entries[b->nr++] = (struct time_stat_buffer_entry) {
			.start = start,
			.end = end
		};

		if (unlikely(b->nr == ARRAY_SIZE(b->entries)))
			time_stats_clear_buffer(stats, b);
	}
}

void bch2_time_stats_reset(struct bch2_time_stats *stats)
{
	spin_lock_irq(&stats->lock);
	unsigned offset = offsetof(struct bch2_time_stats, min_duration);
	memset((void *) stats + offset, 0, sizeof(*stats) - offset);

	if ((unsigned long) stats->buffer > TIME_STATS_NONPCPU) {
		int cpu;
		for_each_possible_cpu(cpu)
			per_cpu_ptr(stats->buffer, cpu)->nr = 0;
	}
	spin_unlock_irq(&stats->lock);
}

void bch2_time_stats_exit(struct bch2_time_stats *stats)
{
	if ((unsigned long) stats->buffer > TIME_STATS_NONPCPU)
		free_percpu(stats->buffer);
	stats->buffer = NULL;
}

void bch2_time_stats_init(struct bch2_time_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->min_duration = U64_MAX;
	stats->min_freq = U64_MAX;
	spin_lock_init(&stats->lock);
}

void bch2_time_stats_init_no_pcpu(struct bch2_time_stats *stats)
{
	bch2_time_stats_init(stats);
	stats->buffer = (struct time_stat_buffer __percpu *) TIME_STATS_NONPCPU;
}
