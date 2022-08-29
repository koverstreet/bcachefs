/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CODETAG_TIMESTATS_H
#define _LINUX_CODETAG_TIMESTATS_H

/*
 * Code tagging based latency tracking:
 * (C) 2022 Kent Overstreet
 *
 * This allows you to easily instrument code to track latency, and have the
 * results show up in debugfs. To use, add the following two calls to your code
 * at the beginning and end of the event you wish to instrument:
 *
 * code_tag_time_stats_start(start_time);
 * code_tag_time_stats_finish(start_time);
 *
 * Statistics will then show up in debugfs under /sys/kernel/debug/time_stats,
 * listed by file and line number.
 */

#ifdef CONFIG_CODETAG_TIME_STATS

#include <linux/codetag.h>
#include <linux/time_stats.h>
#include <linux/timekeeping.h>

struct codetag_time_stats {
	struct codetag		tag;
	struct time_stats	stats;
};

#define codetag_time_stats_start(_start_time)	u64 _start_time = ktime_get_ns()

#define codetag_time_stats_finish(_start_time)			\
do {								\
	static struct codetag_time_stats			\
	__used							\
	__section("time_stats_tags")				\
	__aligned(8) s = {					\
		.tag	= CODE_TAG_INIT,			\
		.stats.lock = __SPIN_LOCK_UNLOCKED(_lock)	\
	};							\
								\
	WARN_ONCE(!(_start_time), "codetag_time_stats_start() not called");\
	time_stats_update(&s.stats, _start_time);		\
} while (0)

#else

#define codetag_time_stats_finish(_start_time)	do {} while (0)
#define codetag_time_stats_start(_start_time)	do {} while (0)

#endif /* CODETAG_CODETAG_TIME_STATS */

#endif
