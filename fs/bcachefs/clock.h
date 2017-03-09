#ifndef _BCACHE_CLOCK_H
#define _BCACHE_CLOCK_H

void bch_io_timer_add(struct io_clock *, struct io_timer *);
void bch_io_timer_del(struct io_clock *, struct io_timer *);
void bch_kthread_io_clock_wait(struct io_clock *, unsigned long);
void bch_increment_clock(struct bch_fs *, unsigned, int);

void bch_io_clock_schedule_timeout(struct io_clock *, unsigned long);

#define bch_kthread_wait_event_ioclock_timeout(condition, clock, timeout)\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_timeout(wq, condition, timeout);	\
	__ret;								\
})

void bch_io_clock_exit(struct io_clock *);
int bch_io_clock_init(struct io_clock *);

#endif /* _BCACHE_CLOCK_H */
