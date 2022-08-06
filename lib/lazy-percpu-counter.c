// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/lazy-percpu-counter.h>
#include <linux/percpu.h>

static inline s64 lazy_percpu_counter_atomic_val(s64 v)
{
	/* Ensure output is sign extended properly: */
	return (v << COUNTER_MOD_BITS) >>
		(COUNTER_MOD_BITS + COUNTER_IS_PCPU_BIT);
}

static void lazy_percpu_counter_switch_to_pcpu(struct lazy_percpu_counter *c)
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
 * lazy_percpu_counter_exit: Free resources associated with a
 * lazy_percpu_counter
 *
 * @c: counter to exit
 */
void lazy_percpu_counter_exit(struct lazy_percpu_counter *c)
{
	free_percpu(lazy_percpu_counter_is_pcpu(atomic64_read(&c->v)));
}
EXPORT_SYMBOL_GPL(lazy_percpu_counter_exit);

/**
 * lazy_percpu_counter_read: Read current value of a lazy_percpu_counter
 *
 * @c: counter to read
 */
s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c)
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
EXPORT_SYMBOL_GPL(lazy_percpu_counter_read);

void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i)
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

		if (c->last_wrap &&
		    unlikely(time_after(c->last_wrap + HZ, now)))
			lazy_percpu_counter_switch_to_pcpu(c);
		else
			c->last_wrap = now;
	}
}
EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath);

void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i)
{
	u64 atomic_i;
	u64 old, v = atomic64_read(&c->v);
	u64 __percpu *pcpu_v;

	atomic_i  = i << COUNTER_IS_PCPU_BIT;
	atomic_i &= ~COUNTER_MOD_MASK;

	do {
		pcpu_v = lazy_percpu_counter_is_pcpu(v);
		if (pcpu_v) {
			this_cpu_add(*pcpu_v, i);
			return;
		}

		old = v;
	} while ((v = atomic64_cmpxchg(&c->v, old, old + atomic_i)) != old);
}
EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath_noupgrade);
