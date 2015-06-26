#ifndef _BCACHE_CLOCK_H
#define _BCACHE_CLOCK_H

void bch_io_timer_add(struct io_clock *, struct io_timer *);
void bch_kthread_io_clock_wait(struct io_clock *, unsigned long);
void bch_increment_clock(struct cache_set *, unsigned, int);

void bch_io_clock_exit(struct io_clock *);
int bch_io_clock_init(struct io_clock *);

#endif /* _BCACHE_CLOCK_H */
