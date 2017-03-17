#include "bcachefs.h"
#include "clock.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

static inline long io_timer_cmp(io_timer_heap *h,
				struct io_timer *l,
				struct io_timer *r)
{
	return l->expire - r->expire;
}

void bch2_io_timer_add(struct io_clock *clock, struct io_timer *timer)
{
	size_t i;

	spin_lock(&clock->timer_lock);
	for (i = 0; i < clock->timers.used; i++)
		if (clock->timers.data[i] == timer)
			goto out;

	BUG_ON(!heap_add(&clock->timers, timer, io_timer_cmp));
out:
	spin_unlock(&clock->timer_lock);
}

void bch2_io_timer_del(struct io_clock *clock, struct io_timer *timer)
{
	size_t i;

	spin_lock(&clock->timer_lock);

	for (i = 0; i < clock->timers.used; i++)
		if (clock->timers.data[i] == timer) {
			heap_del(&clock->timers, i, io_timer_cmp);
			break;
		}

	spin_unlock(&clock->timer_lock);
}

struct io_clock_wait {
	struct io_timer		timer;
	struct task_struct	*task;
	int			expired;
};

static void io_clock_wait_fn(struct io_timer *timer)
{
	struct io_clock_wait *wait = container_of(timer,
				struct io_clock_wait, timer);

	wait->expired = 1;
	wake_up_process(wait->task);
}

void bch2_io_clock_schedule_timeout(struct io_clock *clock, unsigned long until)
{
	struct io_clock_wait wait;

	/* XXX: calculate sleep time rigorously */
	wait.timer.expire	= until;
	wait.timer.fn		= io_clock_wait_fn;
	wait.task		= current;
	wait.expired		= 0;
	bch2_io_timer_add(clock, &wait.timer);

	schedule();

	bch2_io_timer_del(clock, &wait.timer);
}

/*
 * _only_ to be used from a kthread
 */
void bch2_kthread_io_clock_wait(struct io_clock *clock,
			       unsigned long until)
{
	struct io_clock_wait wait;

	/* XXX: calculate sleep time rigorously */
	wait.timer.expire	= until;
	wait.timer.fn		= io_clock_wait_fn;
	wait.task		= current;
	wait.expired		= 0;
	bch2_io_timer_add(clock, &wait.timer);

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		if (wait.expired)
			break;

		schedule();
		try_to_freeze();
	}

	__set_current_state(TASK_RUNNING);
	bch2_io_timer_del(clock, &wait.timer);
}

static struct io_timer *get_expired_timer(struct io_clock *clock,
					  unsigned long now)
{
	struct io_timer *ret = NULL;

	spin_lock(&clock->timer_lock);

	if (clock->timers.used &&
	    time_after_eq(now, clock->timers.data[0]->expire))
		heap_pop(&clock->timers, ret, io_timer_cmp);

	spin_unlock(&clock->timer_lock);

	return ret;
}

void bch2_increment_clock(struct bch_fs *c, unsigned sectors, int rw)
{
	struct io_clock *clock = &c->io_clock[rw];
	struct io_timer *timer;
	unsigned long now;

	/* Buffer up one megabyte worth of IO in the percpu counter */
	preempt_disable();

	if (likely(this_cpu_add_return(*clock->pcpu_buf, sectors) <
		   IO_CLOCK_PCPU_SECTORS)) {
		preempt_enable();
		return;
	}

	sectors = this_cpu_xchg(*clock->pcpu_buf, 0);
	preempt_enable();
	now = atomic_long_add_return(sectors, &clock->now);

	while ((timer = get_expired_timer(clock, now)))
		timer->fn(timer);
}

void bch2_io_clock_exit(struct io_clock *clock)
{
	free_heap(&clock->timers);
	free_percpu(clock->pcpu_buf);
}

int bch2_io_clock_init(struct io_clock *clock)
{
	atomic_long_set(&clock->now, 0);
	spin_lock_init(&clock->timer_lock);

	clock->pcpu_buf = alloc_percpu(*clock->pcpu_buf);
	if (!clock->pcpu_buf)
		return -ENOMEM;

	if (!init_heap(&clock->timers, NR_IO_TIMERS, GFP_KERNEL))
		return -ENOMEM;

	return 0;
}
