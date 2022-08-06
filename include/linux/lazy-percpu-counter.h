/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Lazy percpu counters:
 * (C) 2022 Kent Overstreet
 *
 * Lazy percpu counters start out in atomic mode, then switch to percpu mode if
 * the update rate crosses some threshold.
 *
 * This means we don't have to decide between low memory overhead atomic
 * counters and higher performance percpu counters - we can have our cake and
 * eat it, too!
 *
 * Internally we use an atomic64_t, where the low bit indicates whether we're in
 * percpu mode, and the high 8 bits are a secondary counter that's incremented
 * when the counter is modified - meaning 55 bits of precision are available for
 * the counter itself.
 */

#ifndef _LINUX_LAZY_PERCPU_COUNTER_H
#define _LINUX_LAZY_PERCPU_COUNTER_H

#include <linux/atomic.h>
#include <asm/percpu.h>

struct lazy_percpu_counter {
	atomic64_t			v;
	unsigned long			last_wrap;
};

void lazy_percpu_counter_exit(struct lazy_percpu_counter *c);
void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i);
void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i);
s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c);

/*
 * We use the high bits of the atomic counter for a secondary counter, which is
 * incremented every time the counter is touched. When the secondary counter
 * wraps, we check the time the counter last wrapped, and if it was recent
 * enough that means the update frequency has crossed our threshold and we
 * switch to percpu mode:
 */
#define COUNTER_MOD_BITS		8
#define COUNTER_MOD_MASK		~(~0ULL >> COUNTER_MOD_BITS)
#define COUNTER_MOD_BITS_START		(64 - COUNTER_MOD_BITS)

/*
 * We use the low bit of the counter to indicate whether we're in atomic mode
 * (low bit clear), or percpu mode (low bit set, counter is a pointer to actual
 * percpu counters:
 */
#define COUNTER_IS_PCPU_BIT		1

static inline u64 __percpu *lazy_percpu_counter_is_pcpu(u64 v)
{
	if (!(v & COUNTER_IS_PCPU_BIT))
		return NULL;

	v ^= COUNTER_IS_PCPU_BIT;
	return (u64 __percpu *)(unsigned long)v;
}

/**
 * lazy_percpu_counter_add: Add a value to a lazy_percpu_counter
 *
 * @c: counter to modify
 * @i: value to add
 */
static inline void lazy_percpu_counter_add(struct lazy_percpu_counter *c, s64 i)
{
	u64 v = atomic64_read(&c->v);
	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);

	if (likely(pcpu_v))
		this_cpu_add(*pcpu_v, i);
	else
		lazy_percpu_counter_add_slowpath(c, i);
}

/**
 * lazy_percpu_counter_add_noupgrade: Add a value to a lazy_percpu_counter,
 * without upgrading to percpu mode
 *
 * @c: counter to modify
 * @i: value to add
 */
static inline void lazy_percpu_counter_add_noupgrade(struct lazy_percpu_counter *c, s64 i)
{
	u64 v = atomic64_read(&c->v);
	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);

	if (likely(pcpu_v))
		this_cpu_add(*pcpu_v, i);
	else
		lazy_percpu_counter_add_slowpath_noupgrade(c, i);
}

static inline void lazy_percpu_counter_sub(struct lazy_percpu_counter *c, s64 i)
{
	lazy_percpu_counter_add(c, -i);
}

#endif /* _LINUX_LAZY_PERCPU_COUNTER_H */
