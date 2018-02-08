
#include "bcachefs.h"
#include "alloc.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "move.h"
#include "super-io.h"
#include "tier.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

static bool __tiering_pred(struct bch_fs *c, struct bch_tier *tier,
			   struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;
	unsigned replicas = 0;

	/* Make sure we have room to add a new pointer: */
	if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_U64s_MAX >
	    BKEY_EXTENT_VAL_U64s_MAX)
		return false;

	extent_for_each_ptr(e, ptr)
		if (bch_dev_bkey_exists(c, ptr->dev)->mi.tier >= tier->idx)
			replicas++;

	return replicas < c->opts.data_replicas;
}

static enum data_cmd tiering_pred(struct bch_fs *c, void *arg,
				  enum bkey_type type,
				  struct bkey_s_c_extent e,
				  struct bch_io_opts *io_opts,
				  struct data_opts *data_opts)
{
	struct bch_tier *tier = arg;

	if (!__tiering_pred(c, tier, e))
		return DATA_SKIP;

	data_opts->btree_insert_flags = 0;
	return DATA_ADD_REPLICAS;
}

static int bch2_tiering_thread(void *arg)
{
	struct bch_tier *tier = arg;
	struct bch_fs *c = container_of(tier, struct bch_fs, tiers[tier->idx]);
	struct io_clock *clock = &c->io_clock[WRITE];
	struct bch_dev *ca;
	struct bch_move_stats move_stats;
	u64 tier_capacity, available_sectors;
	unsigned long last;
	unsigned i, nr_devices;

	memset(&move_stats, 0, sizeof(move_stats));
	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   (nr_devices = dev_mask_nr(&tier->devs))))
			break;

		while (1) {
			struct bch_tier *faster_tier;

			last = atomic_long_read(&clock->now);

			tier_capacity = available_sectors = 0;
			for (faster_tier = c->tiers;
			     faster_tier != tier;
			     faster_tier++) {
				rcu_read_lock();
				for_each_member_device_rcu(ca, c, i,
						&faster_tier->devs) {
					tier_capacity +=
						bucket_to_sector(ca,
							ca->mi.nbuckets -
							ca->mi.first_bucket);
					available_sectors +=
						bucket_to_sector(ca,
							dev_buckets_available(c, ca));
				}
				rcu_read_unlock();
			}

			if (available_sectors < (tier_capacity >> 1))
				break;

			bch2_kthread_io_clock_wait(clock,
						  last +
						  available_sectors -
						  (tier_capacity >> 1));
			if (kthread_should_stop())
				return 0;
		}

		bch2_move_data(c, &tier->pd.rate,
			       SECTORS_IN_FLIGHT_PER_DEVICE * nr_devices,
			       &tier->devs,
			       writepoint_ptr(&tier->wp),
			       POS_MIN, POS_MAX,
			       tiering_pred, tier,
			       &move_stats);
	}

	return 0;
}

static void __bch2_tiering_stop(struct bch_tier *tier)
{
	tier->pd.rate.rate = UINT_MAX;
	bch2_ratelimit_reset(&tier->pd.rate);

	if (tier->migrate)
		kthread_stop(tier->migrate);

	tier->migrate = NULL;
}

void bch2_tiering_stop(struct bch_fs *c)
{
	struct bch_tier *tier;

	for (tier = c->tiers; tier < c->tiers + ARRAY_SIZE(c->tiers); tier++)
		__bch2_tiering_stop(tier);
}

static int __bch2_tiering_start(struct bch_tier *tier)
{
	if (!tier->migrate) {
		struct task_struct *p =
			kthread_create(bch2_tiering_thread, tier,
				       "bch_tier[%u]", tier->idx);
		if (IS_ERR(p))
			return PTR_ERR(p);

		tier->migrate = p;
	}

	wake_up_process(tier->migrate);
	return 0;
}

int bch2_tiering_start(struct bch_fs *c)
{
	struct bch_tier *tier;
	bool have_faster_tier = false;

	if (c->opts.nochanges)
		return 0;

	for (tier = c->tiers; tier < c->tiers + ARRAY_SIZE(c->tiers); tier++) {
		if (!dev_mask_nr(&tier->devs))
			continue;

		if (have_faster_tier) {
			int ret = __bch2_tiering_start(tier);
			if (ret)
				return ret;
		} else {
			__bch2_tiering_stop(tier);
		}

		have_faster_tier = true;
	}

	return 0;
}

void bch2_fs_tiering_init(struct bch_fs *c)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->tiers); i++) {
		c->tiers[i].idx = i;
		bch2_pd_controller_init(&c->tiers[i].pd);
	}
}
