/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_TIMESTATS_H
#define _LINUX_TIMESTATS_H

#include <linux/spinlock_types.h>
#include <linux/types.h>

#define NR_QUANTILES	15

struct quantiles {
	struct quantile_entry {
		u64	m;
		u64	step;
	}		entries[NR_QUANTILES];
};

struct time_stat_buffer {
	unsigned int	nr;
	struct time_stat_buffer_entry {
		u64	start;
		u64	end;
	}		entries[32];
};

struct time_stats {
	spinlock_t	lock;
	u64		count;
	/* all fields are in nanoseconds */
	u64		average_duration;
	u64		average_frequency;
	u64		max_duration;
	u64		last_event;
	struct quantiles quantiles;

	struct time_stat_buffer __percpu *buffer;
};

struct seq_buf;
void time_stats_update(struct time_stats *stats, u64 start);
void time_stats_to_text(struct seq_buf *out, struct time_stats *stats);
void time_stats_exit(struct time_stats *stats);

#endif /* _LINUX_TIMESTATS_H */
