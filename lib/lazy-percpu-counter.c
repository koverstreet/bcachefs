// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/lazy-percpu-counter.h>
#include <linux/percpu.h>

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

static inline s64 lazy_percpu_counter_atomic_val(s64 v)
{
	/* Ensure output is sign extended properly: */
	return (v << COUNTER_MOD_BITS) >>
		(COUNTER_MOD_BITS + COUNTER_IS_PCPU_BIT);
}

static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
{
	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);
	u64 old, new, v;

	if (!pcpu_v)
		return;

	preempt_disable();
	v = atomic64_read(&c->v);
	do {
		if (lazy_percpu_counter_is_pcpu(v)) {
			free_percpu(pcpu_v);
			return;
		}

		old = v;
		new = (unsigned long)pcpu_v | 1;

		*this_cpu_ptr(pcpu_v) = lazy_percpu_counter_atomic_val(v);
	} while ((v = atomic64_cmpxchg(&c->v, old, new)) != old);
	preempt_enable();
}

/**
 * __lazy_percpu_counter_exit: Free resources associated with a
 * raw_lazy_percpu_counter
 *
 * @c: counter to exit
 */
void __lazy_percpu_counter_exit(struct raw_lazy_percpu_counter *c)
{
	free_percpu(lazy_percpu_counter_is_pcpu(atomic64_read(&c->v)));
}
EXPORT_SYMBOL_GPL(__lazy_percpu_counter_exit);

/**
 * __lazy_percpu_counter_read: Read current value of a raw_lazy_percpu_counter
 *
 * @c: counter to read
 */
s64 __lazy_percpu_counter_read(struct raw_lazy_percpu_counter *c)
{
	s64 v = atomic64_read(&c->v);
	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);

	if (pcpu_v) {
		int cpu;

		v = 0;
		for_each_possible_cpu(cpu)
			v += *per_cpu_ptr(pcpu_v, cpu);
	} else {
		v = lazy_percpu_counter_atomic_val(v);
	}

	return v;
}
EXPORT_SYMBOL_GPL(__lazy_percpu_counter_read);

/**
 * __lazy_percpu_counter_add: Add a value to a lazy_percpu_counter
 *
 * @c: counter to modify
 * @last_wrap: pointer to a timestamp, updated when mod counter wraps
 * @i: value to add
 */
void __lazy_percpu_counter_add(struct raw_lazy_percpu_counter *c,
			       unsigned long *last_wrap, s64 i)
{
	u64 atomic_i;
	u64 old, v = atomic64_read(&c->v);
	u64 __percpu *pcpu_v;

	atomic_i  = i << COUNTER_IS_PCPU_BIT;
	atomic_i &= ~COUNTER_MOD_MASK;
	atomic_i |= 1ULL << COUNTER_MOD_BITS_START;

	do {
		pcpu_v = lazy_percpu_counter_is_pcpu(v);
		if (pcpu_v) {
			this_cpu_add(*pcpu_v, i);
			return;
		}

		old = v;
	} while ((v = atomic64_cmpxchg(&c->v, old, old + atomic_i)) != old);

	if (unlikely(!(v & COUNTER_MOD_MASK))) {
		unsigned long now = jiffies;

		if (*last_wrap &&
		    unlikely(time_after(*last_wrap + HZ, now)))
			lazy_percpu_counter_switch_to_pcpu(c);
		else
			*last_wrap = now;
	}
}
EXPORT_SYMBOL(__lazy_percpu_counter_add);
