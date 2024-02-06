/* SPDX-License-Identifier: GPL-2.0 */
/*
 * time_stats - collect statistics on events that have a duration, with nicely
 * formatted textual output on demand
 *
 * - percpu buffering of event collection: cheap enough to shotgun
 *   everywhere without worrying about overhead
 *
 * tracks:
 *  - number of events
 *  - maximum event duration ever seen
 *  - sum of all event durations
 *  - average event duration, standard and weighted
 *  - standard deviation of event durations, standard and weighted
 * and analagous statistics for the frequency of events
 *
 * We provide both mean and weighted mean (exponentially weighted), and standard
 * deviation and weighted standard deviation, to give an efficient-to-compute
 * view of current behaviour versus. average behaviour - "did this event source
 * just become wonky, or is this typical?".
 *
 * Particularly useful for tracking down latency issues.
 */
#ifndef _LINUX_TIME_STATS_H
#define _LINUX_TIME_STATS_H

#include <linux/mean_and_variance.h>
#include <linux/sched/clock.h>
#include <linux/spinlock_types.h>
#include <linux/string.h>

struct time_unit {
	const char	*name;
	u64		nsecs;
};

/*
 * given a nanosecond value, pick the preferred time units for printing:
 */
const struct time_unit *pick_time_units(u64 ns);

/*
 * quantiles - do not use:
 *
 * Only enabled if time_stats->quantiles_enabled has been manually set - don't
 * use in new code.
 */

#define NR_QUANTILES	15
#define QUANTILE_IDX(i)	inorder_to_eytzinger0(i, NR_QUANTILES)
#define QUANTILE_FIRST	eytzinger0_first(NR_QUANTILES)
#define QUANTILE_LAST	eytzinger0_last(NR_QUANTILES)

struct quantiles {
	struct quantile_entry {
		u64	m;
		u64	step;
	}		entries[NR_QUANTILES];
};

struct time_stat_buffer {
	unsigned	nr;
	struct time_stat_buffer_entry {
		u64	start;
		u64	end;
	}		entries[31];
};

struct time_stats {
	spinlock_t	lock;
	bool		have_quantiles;
	struct time_stat_buffer __percpu *buffer;
	/* all fields are in nanoseconds */
	u64             min_duration;
	u64		max_duration;
	u64		total_duration;
	u64             max_freq;
	u64             min_freq;
	u64		last_event;
	u64		last_event_start;
	u64		start_time;

	struct mean_and_variance	  duration_stats;
	struct mean_and_variance	  freq_stats;

/* default weight for weighted mean and variance calculations */
#define TIME_STATS_MV_WEIGHT	8

	struct mean_and_variance_weighted duration_stats_weighted;
	struct mean_and_variance_weighted freq_stats_weighted;
};

struct time_stats_quantiles {
	struct time_stats	stats;
	struct quantiles	quantiles;
};

static inline struct quantiles *time_stats_to_quantiles(struct time_stats *stats)
{
	return stats->have_quantiles
		? &container_of(stats, struct time_stats_quantiles, stats)->quantiles
		: NULL;
}

void __time_stats_clear_buffer(struct time_stats *, struct time_stat_buffer *);
void __time_stats_update(struct time_stats *stats, u64, u64);

/**
 * time_stats_update - collect a new event being tracked
 *
 * @stats	- time_stats to update
 * @start	- start time of event, recorded with local_clock()
 *
 * The end duration of the event will be the current time
 */
static inline void time_stats_update(struct time_stats *stats, u64 start)
{
	__time_stats_update(stats, start, local_clock());
}

/**
 * track_event_change - track state change events
 *
 * @stats	- time_stats to update
 * @v		- new state, true or false
 *
 * Use this when tracking time stats for state changes, i.e. resource X becoming
 * blocked/unblocked.
 */
static inline bool track_event_change(struct time_stats *stats, bool v)
{
	if (v != !!stats->last_event_start) {
		if (!v) {
			time_stats_update(stats, stats->last_event_start);
			stats->last_event_start = 0;
		} else {
			stats->last_event_start = local_clock() ?: 1;
			return true;
		}
	}

	return false;
}

void time_stats_reset(struct time_stats *);

#define TIME_STATS_PRINT_NO_ZEROES	(1U << 0)	/* print nothing if zero count */
struct seq_buf;
void time_stats_to_seq_buf(struct seq_buf *, struct time_stats *,
		const char *epoch_name, unsigned int flags);
void time_stats_to_json(struct seq_buf *, struct time_stats *,
		const char *epoch_name, unsigned int flags);

void time_stats_exit(struct time_stats *);
void time_stats_init(struct time_stats *);
void time_stats_init_no_pcpu(struct bch2_time_stats *);

static inline void time_stats_quantiles_exit(struct time_stats_quantiles *statq)
{
	time_stats_exit(&statq->stats);
}
static inline void time_stats_quantiles_init(struct time_stats_quantiles *statq)
{
	time_stats_init(&statq->stats);
	statq->stats.have_quantiles = true;
	memset(&statq->quantiles, 0, sizeof(statq->quantiles));
}

#endif /* _LINUX_TIME_STATS_H */
