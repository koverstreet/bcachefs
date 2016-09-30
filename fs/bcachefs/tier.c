
#include "bcache.h"
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
	struct cache_group	*tier;
	unsigned		tier_idx;
	unsigned		sectors;
	unsigned		stripe_size;
	unsigned		dev_idx;
	struct cache		*ca;
};

static bool tiering_pred(struct cache_set *c,
			 struct tiering_state *s,
			 struct bkey_s_c k)
{
	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const struct bch_extent_ptr *ptr;
		struct cache_member_rcu *mi;
		unsigned replicas = 0;

		/* Make sure we have room to add a new pointer: */
		if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_U64s_MAX >
		    BKEY_EXTENT_VAL_U64s_MAX)
			return false;

		mi = cache_member_info_get(c);
		extent_for_each_ptr(e, ptr)
			if (ptr->dev < mi->nr_devices &&
			    mi->m[ptr->dev].tier >= s->tier_idx)
				replicas++;
		cache_member_info_put();

		return replicas < c->opts.data_replicas;
	}

	return false;
}

static void tier_put_device(struct tiering_state *s)
{
	if (s->ca)
		percpu_ref_put(&s->ca->ref);
	s->ca = NULL;
}

/**
 * refill_next - move on to refilling the next cache's tiering keylist
 */
static void tier_next_device(struct cache_set *c, struct tiering_state *s)
{
	if (!s->ca || s->sectors > s->stripe_size) {
		tier_put_device(s);
		s->sectors = 0;
		s->dev_idx++;

		spin_lock(&s->tier->lock);
		if (s->dev_idx >= s->tier->nr_devices)
			s->dev_idx = 0;

		if (s->tier->nr_devices) {
			s->ca = s->tier->d[s->dev_idx].dev;
			percpu_ref_get(&s->ca->ref);
		}
		spin_unlock(&s->tier->lock);
	}
}

static int issue_tiering_move(struct cache_set *c,
			      struct tiering_state *s,
			      struct moving_context *ctxt,
			      struct bkey_s_c k)
{
	int ret;

	ret = bch_data_move(c, ctxt, &s->ca->tiering_write_point, k, NULL);
	if (!ret) {
		trace_bcache_tiering_copy(k.k);
		s->sectors += k.k->size;
	} else {
		trace_bcache_tiering_alloc_fail(c, k.k->size);
	}

	return ret;
}

/**
 * tiering_next_cache - issue a move to write an extent to the next cache
 * device in round robin order
 */
static s64 read_tiering(struct cache_set *c, struct cache_group *tier)
{
	struct moving_context ctxt;
	struct tiering_state s;
	struct btree_iter iter;
	struct bkey_s_c k;
	unsigned nr_devices = READ_ONCE(tier->nr_devices);
	int ret;

	if (!nr_devices)
		return 0;

	trace_bcache_tiering_start(c);

	memset(&s, 0, sizeof(s));
	s.tier		= tier;
	s.tier_idx	= tier - c->cache_tiers;
	s.stripe_size	= 2048; /* 1 mb for now */

	bch_move_ctxt_init(&ctxt, &c->tiering_pd.rate,
			   nr_devices * SECTORS_IN_FLIGHT_PER_DEVICE);
	bch_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

	while (!kthread_should_stop() &&
	       !bch_move_ctxt_wait(&ctxt) &&
	       (k = bch_btree_iter_peek(&iter)).k &&
	       !btree_iter_err(k)) {
		if (!tiering_pred(c, &s, k))
			goto next;

		tier_next_device(c, &s);
		if (!s.ca)
			break;

		ret = issue_tiering_move(c, &s, &ctxt, k);
		if (ret) {
			bch_btree_iter_unlock(&iter);

			/* memory allocation failure, wait for some IO to finish */
			bch_move_ctxt_wait_for_io(&ctxt);
			continue;
		}
next:
		bch_btree_iter_advance_pos(&iter);
		//bch_btree_iter_cond_resched(&iter);

		/* unlock before calling moving_context_wait() */
		bch_btree_iter_unlock(&iter);
		cond_resched();
	}

	bch_btree_iter_unlock(&iter);
	tier_put_device(&s);
	bch_move_ctxt_exit(&ctxt);
	trace_bcache_tiering_end(c, ctxt.sectors_moved, ctxt.keys_moved);

	return ctxt.sectors_moved;
}

static int bch_tiering_thread(void *arg)
{
	struct cache_set *c = arg;
	struct cache_group *tier = &c->cache_tiers[1];
	struct io_clock *clock = &c->io_clock[WRITE];
	struct cache *ca;
	u64 tier_capacity, available_sectors;
	unsigned long last;
	unsigned i;

	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   tier->nr_devices))
			break;

		while (1) {
			struct cache_group *faster_tier;

			last = atomic_long_read(&clock->now);

			tier_capacity = available_sectors = 0;
			rcu_read_lock();
			for (faster_tier = c->cache_tiers;
			     faster_tier != tier;
			     faster_tier++) {
				group_for_each_cache_rcu(ca, faster_tier, i) {
					tier_capacity +=
						(ca->mi.nbuckets -
						 ca->mi.first_bucket) << ca->bucket_bits;
					available_sectors +=
						buckets_available_cache(ca) << ca->bucket_bits;
				}
			}
			rcu_read_unlock();

			if (available_sectors < (tier_capacity >> 1))
				break;

			bch_kthread_io_clock_wait(clock,
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

void bch_tiering_init_cache_set(struct cache_set *c)
{
	bch_pd_controller_init(&c->tiering_pd);
}

int bch_tiering_read_start(struct cache_set *c)
{
	struct task_struct *t;

	if (c->opts.nochanges)
		return 0;

	t = kthread_create(bch_tiering_thread, c, "bch_tier_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	c->tiering_read = t;
	wake_up_process(c->tiering_read);

	return 0;
}

void bch_tiering_read_stop(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(c->tiering_read)) {
		kthread_stop(c->tiering_read);
		c->tiering_read = NULL;
	}
}
