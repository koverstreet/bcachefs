
#include "bcachefs.h"
#include "alloc.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "super-io.h"
#include "tier.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

struct tiering_state {
	struct bch_tier		*tier;
	unsigned		sectors;
	unsigned		stripe_size;
	unsigned		dev_idx;
	struct bch_dev		*ca;
};

static bool tiering_pred(struct bch_fs *c,
			 struct bch_tier *tier,
			 struct bkey_s_c k)
{
	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const struct bch_extent_ptr *ptr;
		unsigned replicas = 0;

		/* Make sure we have room to add a new pointer: */
		if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_U64s_MAX >
		    BKEY_EXTENT_VAL_U64s_MAX)
			return false;

		extent_for_each_ptr(e, ptr)
			if (c->devs[ptr->dev]->mi.tier >= tier->idx)
				replicas++;

		return replicas < c->opts.data_replicas;
	}

	return false;
}

static int issue_tiering_move(struct bch_fs *c,
			      struct bch_tier *tier,
			      struct moving_context *ctxt,
			      struct bkey_s_c k)
{
	int ret;

	ret = bch2_data_move(c, ctxt, &tier->devs,
			     writepoint_ptr(&tier->wp),
			     k, false);
	if (!ret)
		trace_tiering_copy(k.k);
	else
		trace_tiering_alloc_fail(c, k.k->size);

	return ret;
}

/**
 * tiering_next_cache - issue a move to write an extent to the next cache
 * device in round robin order
 */
static s64 read_tiering(struct bch_fs *c, struct bch_tier *tier)
{
	struct moving_context ctxt;
	struct btree_iter iter;
	struct bkey_s_c k;
	unsigned nr_devices = dev_mask_nr(&tier->devs);
	int ret;

	if (!nr_devices)
		return 0;

	trace_tiering_start(c);

	bch2_move_ctxt_init(&ctxt, &tier->pd.rate,
			   nr_devices * SECTORS_IN_FLIGHT_PER_DEVICE);
	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_PREFETCH);

	while (!kthread_should_stop() &&
	       !bch2_move_ctxt_wait(&ctxt) &&
	       (k = bch2_btree_iter_peek(&iter)).k &&
	       !btree_iter_err(k)) {
		if (!tiering_pred(c, tier, k))
			goto next;

		ret = issue_tiering_move(c, tier, &ctxt, k);
		if (ret) {
			bch2_btree_iter_unlock(&iter);

			/* memory allocation failure, wait for some IO to finish */
			bch2_move_ctxt_wait_for_io(&ctxt);
			continue;
		}
next:
		bch2_btree_iter_advance_pos(&iter);
		//bch2_btree_iter_cond_resched(&iter);

		/* unlock before calling moving_context_wait() */
		bch2_btree_iter_unlock(&iter);
		cond_resched();
	}

	bch2_btree_iter_unlock(&iter);
	bch2_move_ctxt_exit(&ctxt);
	trace_tiering_end(c, ctxt.sectors_moved, ctxt.keys_moved);

	return ctxt.sectors_moved;
}

static int bch2_tiering_thread(void *arg)
{
	struct bch_tier *tier = arg;
	struct bch_fs *c = container_of(tier, struct bch_fs, tiers[tier->idx]);
	struct io_clock *clock = &c->io_clock[WRITE];
	struct bch_dev *ca;
	u64 tier_capacity, available_sectors;
	unsigned long last;
	unsigned i;

	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   dev_mask_nr(&tier->devs)))
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

		read_tiering(c, tier);
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
