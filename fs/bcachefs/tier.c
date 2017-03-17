
#include "bcachefs.h"
#include "alloc.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "disk_groups.h"
#include "extents.h"
#include "io.h"
#include "move.h"
#include "super-io.h"
#include "tier.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/sched/cputime.h>
#include <trace/events/bcachefs.h>

static inline bool rebalance_ptr_pred(struct bch_fs *c,
				      const struct bch_extent_ptr *ptr,
				      struct bch_extent_crc_unpacked crc,
				      struct bch_io_opts *io_opts)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);

	if (io_opts->background_target &&
	    !dev_in_target(ca, io_opts->background_target) &&
	    !ptr->cached)
		return true;

	if (io_opts->background_compression &&
	    crc.compression_type !=
	    bch2_compression_opt_to_type[io_opts->background_compression])
		return true;

	return false;
}

void bch2_rebalance_add_key(struct bch_fs *c,
			    struct bkey_s_c k,
			    struct bch_io_opts *io_opts)
{
	const struct bch_extent_ptr *ptr;
	struct bch_extent_crc_unpacked crc;
	struct bkey_s_c_extent e;

	if (!bkey_extent_is_data(k.k))
		return;

	if (!io_opts->background_target &&
	    !io_opts->background_compression)
		return;

	e = bkey_s_c_to_extent(k);

	extent_for_each_ptr_crc(e, ptr, crc)
		if (rebalance_ptr_pred(c, ptr, crc, io_opts)) {
			struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);

			if (!atomic64_add_return(crc.compressed_size,
						 &ca->rebalance_work))
				rebalance_wakeup(c);
		}
}

void bch2_rebalance_add_work(struct bch_fs *c, u64 sectors)
{
	if (!atomic64_add_return(sectors, &c->rebalance_work_unknown_dev))
		rebalance_wakeup(c);
}

static enum data_cmd rebalance_pred(struct bch_fs *c, void *arg,
				    enum bkey_type type,
				    struct bkey_s_c_extent e,
				    struct bch_io_opts *io_opts,
				    struct data_opts *data_opts)
{
	const struct bch_extent_ptr *ptr;
	struct bch_extent_crc_unpacked crc;

	/* Make sure we have room to add a new pointer: */
	if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_U64s_MAX >
	    BKEY_EXTENT_VAL_U64s_MAX)
		return DATA_SKIP;

	extent_for_each_ptr_crc(e, ptr, crc)
		if (rebalance_ptr_pred(c, ptr, crc, io_opts))
			goto found;

	return DATA_SKIP;
found:
	data_opts->target		= io_opts->background_target;
	data_opts->btree_insert_flags	= 0;
	return DATA_ADD_REPLICAS;
}

struct rebalance_work {
	unsigned	dev_most_full_percent;
	u64		dev_most_full_work;
	u64		dev_most_full_capacity;
	u64		total_work;
};

static struct rebalance_work rebalance_work(struct bch_fs *c)
{
	struct bch_dev *ca;
	struct rebalance_work ret = { 0 };
	unsigned i;

	for_each_online_member(ca, c, i) {
		u64 capacity = bucket_to_sector(ca, ca->mi.nbuckets -
						ca->mi.first_bucket);
		u64 work = atomic64_read(&ca->rebalance_work) +
			atomic64_read(&c->rebalance_work_unknown_dev);
		unsigned percent_full = div_u64(work * 100, capacity);

		if (percent_full > ret.dev_most_full_percent) {
			ret.dev_most_full_percent	= percent_full;
			ret.dev_most_full_work		= work;
			ret.dev_most_full_capacity	= capacity;
		}

		ret.total_work += atomic64_read(&ca->rebalance_work);
	}

	ret.total_work += atomic64_read(&c->rebalance_work_unknown_dev);

	return ret;
}

static void rebalance_work_reset(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	for_each_online_member(ca, c, i)
		atomic64_set(&ca->rebalance_work, 0);

	atomic64_set(&c->rebalance_work_unknown_dev, 0);
}

static unsigned long curr_cputime(void)
{
	u64 utime, stime;

	task_cputime_adjusted(current, &utime, &stime);
	return nsecs_to_jiffies(utime + stime);
}

static int bch2_rebalance_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	struct rebalance_work w, p;
	unsigned long start, prev_start;
	unsigned long prev_run_time, prev_run_cputime;
	unsigned long cputime, prev_cputime;

	set_freezable();

	p		= rebalance_work(c);
	prev_start	= jiffies;
	prev_cputime	= curr_cputime();

	while (!kthread_wait_freezable(c->rebalance_enabled)) {
		struct bch_move_stats move_stats = { 0 };

		w			= rebalance_work(c);
		start			= jiffies;
		cputime			= curr_cputime();

		prev_run_time		= start - prev_start;
		prev_run_cputime	= cputime - prev_cputime;

		if (!w.total_work) {
			kthread_wait_freezable(rebalance_work(c).total_work);
			continue;
		}

		if (w.dev_most_full_percent < 20 &&
		    prev_run_cputime * 5 > prev_run_time) {
			if (w.dev_most_full_capacity) {
				bch2_kthread_io_clock_wait(clock,
					atomic_long_read(&clock->now) +
					div_u64(w.dev_most_full_capacity, 5));
			} else {

				set_current_state(TASK_INTERRUPTIBLE);
				if (kthread_should_stop())
					break;

				schedule_timeout(prev_run_cputime * 5 -
						 prev_run_time);
				continue;
			}
		}

		/* minimum 1 mb/sec: */
		c->rebalance_pd.rate.rate =
			max_t(u64, 1 << 11,
			      c->rebalance_pd.rate.rate *
			      max(p.dev_most_full_percent, 1U) /
			      max(w.dev_most_full_percent, 1U));

		rebalance_work_reset(c);

		bch2_move_data(c, &c->rebalance_pd.rate,
			       writepoint_ptr(&c->rebalance_write_point),
			       POS_MIN, POS_MAX,
			       rebalance_pred, NULL,
			       &move_stats);
	}

	return 0;
}

void bch2_rebalance_stop(struct bch_fs *c)
{
	struct task_struct *p;

	c->rebalance_pd.rate.rate = UINT_MAX;
	bch2_ratelimit_reset(&c->rebalance_pd.rate);

	p = c->rebalance_thread;
	c->rebalance_thread = NULL;

	if (p) {
		/* for sychronizing with rebalance_wakeup() */
		synchronize_rcu();

		kthread_stop(p);
		put_task_struct(p);
	}
}

int bch2_rebalance_start(struct bch_fs *c)
{
	struct task_struct *p;

	if (c->opts.nochanges)
		return 0;

	p = kthread_create(bch2_rebalance_thread, c, "bch_rebalance");
	if (IS_ERR(p))
		return PTR_ERR(p);

	get_task_struct(p);

	rcu_assign_pointer(c->rebalance_thread, p);
	wake_up_process(c->rebalance_thread);
	return 0;
}

void bch2_fs_rebalance_init(struct bch_fs *c)
{
	bch2_pd_controller_init(&c->rebalance_pd);

	atomic64_set(&c->rebalance_work_unknown_dev, S64_MAX);
}
