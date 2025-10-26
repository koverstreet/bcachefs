// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "clock.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

static inline bool io_timer_cmp(const void *l, const void *r, void __always_unused *args)
{
	struct io_timer **_l = (struct io_timer **)l;
	struct io_timer **_r = (struct io_timer **)r;

	return (*_l)->expire < (*_r)->expire;
}

static const struct min_heap_callbacks callbacks = {
	.less = io_timer_cmp,
	.swp = NULL,
};

void bch2_io_timer_add(struct io_clock *clock, struct io_timer *timer)
{
	spin_lock(&clock->timer_lock);

	if (time_after_eq64((u64) atomic64_read(&clock->now), timer->expire)) {
		spin_unlock(&clock->timer_lock);
		timer->fn(timer);
		return;
	}

	for (size_t i = 0; i < clock->timers.nr; i++)
		if (clock->timers.data[i] == timer)
			goto out;

	BUG_ON(!min_heap_push(&clock->timers, &timer, &callbacks, NULL));
out:
	spin_unlock(&clock->timer_lock);
}

void bch2_io_timer_del(struct io_clock *clock, struct io_timer *timer)
{
	guard(spinlock)(&clock->timer_lock);

	for (size_t i = 0; i < clock->timers.nr; i++)
		if (clock->timers.data[i] == timer) {
			min_heap_del(&clock->timers, i, &callbacks, NULL);
			return;
		}
}

struct io_clock_wait {
	struct io_timer		io_timer;
	struct task_struct	*task;
	int			expired;
};

static void io_clock_wait_fn(struct io_timer *timer)
{
	struct io_clock_wait *wait = container_of(timer,
				struct io_clock_wait, io_timer);

	wait->expired = 1;
	wake_up_process(wait->task);
}

void bch2_io_clock_schedule_timeout(struct io_clock *clock, u64 until)
{
	struct io_clock_wait wait = {
		.io_timer.expire	= until,
		.io_timer.fn		= io_clock_wait_fn,
		.io_timer.fn2		= (void *) _RET_IP_,
		.task			= current,
	};

	bch2_io_timer_add(clock, &wait.io_timer);
	schedule();
	bch2_io_timer_del(clock, &wait.io_timer);
}

unsigned long bch2_kthread_io_clock_wait_once(struct io_clock *clock,
				     u64 io_until, unsigned long cpu_timeout)
{
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	struct io_clock_wait wait = {
		.io_timer.expire	= io_until,
		.io_timer.fn		= io_clock_wait_fn,
		.io_timer.fn2		= (void *) _RET_IP_,
		.task			= current,
	};

	bch2_io_timer_add(clock, &wait.io_timer);

	set_current_state(TASK_INTERRUPTIBLE);
	if (!(kthread && kthread_should_stop())) {
		cpu_timeout = schedule_timeout(cpu_timeout);
		try_to_freeze();
	}

	__set_current_state(TASK_RUNNING);
	bch2_io_timer_del(clock, &wait.io_timer);
	return cpu_timeout;
}

void bch2_kthread_io_clock_wait(struct io_clock *clock,
				u64 io_until, unsigned long cpu_timeout)
{
	bool kthread = (current->flags & PF_KTHREAD) != 0;

	while (!(kthread && kthread_should_stop()) &&
	       cpu_timeout &&
	       atomic64_read(&clock->now) < io_until)
		cpu_timeout = bch2_kthread_io_clock_wait_once(clock, io_until, cpu_timeout);
}

static struct io_timer *get_expired_timer(struct io_clock *clock, u64 now)
{
	struct io_timer *ret = NULL;

	if (clock->timers.nr &&
	    time_after_eq64(now, clock->timers.data[0]->expire)) {
		ret = *min_heap_peek(&clock->timers);
		min_heap_pop(&clock->timers, &callbacks, NULL);
	}

	return ret;
}

void __bch2_increment_clock(struct io_clock *clock, u64 sectors)
{
	struct io_timer *timer;
	u64 now = atomic64_add_return(sectors, &clock->now);

	guard(spinlock)(&clock->timer_lock);

	while ((timer = get_expired_timer(clock, now)))
		timer->fn(timer);
}

void bch2_io_timers_to_text(struct printbuf *out, struct io_clock *clock)
{
	u64 now = atomic64_read(&clock->now);

	printbuf_tabstop_push(out, 40);
	prt_printf(out, "current time:\t%llu\n", now);

	guard(printbuf_atomic)(out);
	guard(spinlock)(&clock->timer_lock);

	for (unsigned i = 0; i < clock->timers.nr; i++)
		prt_printf(out, "%ps %ps:\t%llu\n",
		       clock->timers.data[i]->fn,
		       clock->timers.data[i]->fn2,
		       clock->timers.data[i]->expire);
}

void bch2_io_clock_exit(struct io_clock *clock)
{
	free_heap(&clock->timers);
	free_percpu(clock->pcpu_buf);
}

int bch2_io_clock_init(struct io_clock *clock)
{
	atomic64_set(&clock->now, 0);
	spin_lock_init(&clock->timer_lock);

	clock->max_slop = IO_CLOCK_PCPU_SECTORS * num_possible_cpus();

	clock->pcpu_buf = alloc_percpu(*clock->pcpu_buf);
	if (!clock->pcpu_buf)
		return -BCH_ERR_ENOMEM_io_clock_init;

	if (!init_heap(&clock->timers, NR_IO_TIMERS, GFP_KERNEL))
		return -BCH_ERR_ENOMEM_io_clock_init;

	return 0;
}
