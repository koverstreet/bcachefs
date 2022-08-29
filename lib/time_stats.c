// SPDX-License-Identifier: GPL-2.0-only

#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/seq_buf.h>
#include <linux/spinlock.h>
#include <linux/time_stats.h>
#include <linux/timekeeping.h>

static inline unsigned int eytzinger1_child(unsigned int i, unsigned int child)
{
	return (i << 1) + child;
}

static inline unsigned int eytzinger1_right_child(unsigned int i)
{
	return eytzinger1_child(i, 1);
}

static inline unsigned int eytzinger1_next(unsigned int i, unsigned int size)
{
	if (eytzinger1_right_child(i) <= size) {
		i = eytzinger1_right_child(i);

		i <<= __fls(size + 1) - __fls(i);
		i >>= i > size;
	} else {
		i >>= ffz(i) + 1;
	}

	return i;
}

static inline unsigned int eytzinger0_child(unsigned int i, unsigned int child)
{
	return (i << 1) + 1 + child;
}

static inline unsigned int eytzinger0_first(unsigned int size)
{
	return rounddown_pow_of_two(size) - 1;
}

static inline unsigned int eytzinger0_next(unsigned int i, unsigned int size)
{
	return eytzinger1_next(i + 1, size) - 1;
}

#define eytzinger0_for_each(_i, _size)			\
	for ((_i) = eytzinger0_first((_size));		\
	     (_i) != -1;				\
	     (_i) = eytzinger0_next((_i), (_size)))

#define ewma_add(ewma, val, weight)					\
({									\
	typeof(ewma) _ewma = (ewma);					\
	typeof(weight) _weight = (weight);				\
									\
	(((_ewma << _weight) - _ewma) + (val)) >> _weight;		\
})

static void quantiles_update(struct quantiles *q, u64 v)
{
	unsigned int i = 0;

	while (i < ARRAY_SIZE(q->entries)) {
		struct quantile_entry *e = q->entries + i;

		if (unlikely(!e->step)) {
			e->m = v;
			e->step = max_t(unsigned int, v / 2, 1024);
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
			e->step = max_t(unsigned int, e->step / 2, 1);

		if (v >= e->m)
			break;

		i = eytzinger0_child(i, v > e->m);
	}
}

static void time_stats_update_one(struct time_stats *stats,
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

	quantiles_update(&stats->quantiles, duration);
}

void time_stats_update(struct time_stats *stats, u64 start)
{
	u64 end = ktime_get_ns();
	unsigned long flags;

	if (!stats->buffer) {
		spin_lock_irqsave(&stats->lock, flags);
		time_stats_update_one(stats, start, end);

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
				time_stats_update_one(stats, i->start, i->end);
			spin_unlock_irqrestore(&stats->lock, flags);

			b->nr = 0;
		}

		preempt_enable();
	}
}
EXPORT_SYMBOL(time_stats_update);

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

static void pr_time_units(struct seq_buf *out, u64 ns)
{
	const struct time_unit *u = pick_time_units(ns);

	seq_buf_printf(out, "%llu %s", div_u64(ns, u->nsecs), u->name);
}

void time_stats_to_text(struct seq_buf *out, struct time_stats *stats)
{
	const struct time_unit *u;
	u64 freq = READ_ONCE(stats->average_frequency);
	u64 q, last_q = 0;
	int i;

	seq_buf_printf(out, "count:          %llu\n", stats->count);
	seq_buf_printf(out, "rate:           %llu/sec\n",
		       freq ? div64_u64(NSEC_PER_SEC, freq) : 0);
	seq_buf_printf(out, "frequency:      ");
	pr_time_units(out, freq);
	seq_buf_putc(out, '\n');

	seq_buf_printf(out, "avg duration:   ");
	pr_time_units(out, stats->average_duration);
	seq_buf_putc(out, '\n');

	seq_buf_printf(out, "max duration:   ");
	pr_time_units(out, stats->max_duration);
	seq_buf_putc(out, '\n');

	i = eytzinger0_first(NR_QUANTILES);
	u = pick_time_units(stats->quantiles.entries[i].m);
	seq_buf_printf(out, "quantiles (%s): ", u->name);
	eytzinger0_for_each(i, NR_QUANTILES) {
		q = max(stats->quantiles.entries[i].m, last_q);
		seq_buf_printf(out, "%llu ", div_u64(q, u->nsecs));
		last_q = q;
	}

	seq_buf_putc(out, '\n');
}
EXPORT_SYMBOL_GPL(time_stats_to_text);

void time_stats_exit(struct time_stats *stats)
{
	free_percpu(stats->buffer);
	stats->buffer = NULL;
}
EXPORT_SYMBOL_GPL(time_stats_exit);
