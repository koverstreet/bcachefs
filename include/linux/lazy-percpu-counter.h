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
 *
 * lazy_percpu_counter is 16 bytes (on 64 bit machines), raw_lazy_percpu_counter
 * is 8 bytes but requires a separate unsigned long to record when the counter
 * wraps - because sometimes multiple counters are used together and can share
 * the same timestamp.
 */

#ifndef _LINUX_LAZY_PERCPU_COUNTER_H
#define _LINUX_LAZY_PERCPU_COUNTER_H

struct raw_lazy_percpu_counter {
	atomic64_t			v;
};

void __lazy_percpu_counter_exit(struct raw_lazy_percpu_counter *c);
void __lazy_percpu_counter_add(struct raw_lazy_percpu_counter *c,
			       unsigned long *last_wrap, s64 i);
s64 __lazy_percpu_counter_read(struct raw_lazy_percpu_counter *c);

static inline void __lazy_percpu_counter_sub(struct raw_lazy_percpu_counter *c,
					     unsigned long *last_wrap, s64 i)
{
	__lazy_percpu_counter_add(c, last_wrap, -i);
}

struct lazy_percpu_counter {
	struct raw_lazy_percpu_counter	v;
	unsigned long			last_wrap;
};

static inline void lazy_percpu_counter_exit(struct lazy_percpu_counter *c)
{
	__lazy_percpu_counter_exit(&c->v);
}

static inline void lazy_percpu_counter_add(struct lazy_percpu_counter *c, s64 i)
{
	__lazy_percpu_counter_add(&c->v, &c->last_wrap, i);
}

static inline void lazy_percpu_counter_sub(struct lazy_percpu_counter *c, s64 i)
{
	__lazy_percpu_counter_sub(&c->v, &c->last_wrap, i);
}

static inline s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c)
{
	return __lazy_percpu_counter_read(&c->v);
}

#endif /* _LINUX_LAZY_PERCPU_COUNTER_H */
