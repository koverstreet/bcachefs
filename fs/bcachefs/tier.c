
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

static bool tiering_pred(struct scan_keylist *kl, struct bkey *k)
{
	struct cache_set *c = container_of(kl, struct cache_set, tiering_keys);
	struct cache_member_rcu *mi;
	unsigned dev;
	bool ret;

	if (!bch_extent_ptrs(k))
		return false;

	/*
	 * Should not happen except in a pathological situation (too many
	 * pointers on the wrong tier?
	 */
	if (bch_extent_ptrs(k) == BKEY_EXTENT_PTRS_MAX)
		return false;

	/* Need at least CACHE_SET_DATA_REPLICAS_WANT ptrs not on tier 0 */
	dev = max_t(int, 0, PTR_DEV(k, bch_extent_ptrs(k) -
				    CACHE_SET_DATA_REPLICAS_WANT(&c->sb)));

	mi = cache_member_info_get(c);
	ret = dev < mi->nr_in_set && !CACHE_TIER(&mi->m[dev]);
	cache_member_info_put();

	return ret;
}

static void read_tiering(struct cache_set *c)
{
	struct bkey *k;
	struct moving_io *io;
	struct closure cl;
	struct moving_io_stats stats;

	trace_bcache_tiering_start(c);
	closure_init_stack(&cl);

	memset(&stats, 0, sizeof(stats));

	/* XXX: if we error, background writeback could stall indefinitely */

	c->tiering_keys.last_scanned = ZERO_KEY;

	while (!bch_ratelimit_wait_freezable_stoppable(&c->tiering_pd.rate,
						       &cl)) {
		k = bch_scan_keylist_next_rescan(c,
						 &c->tiering_keys,
						 &MAX_KEY,
						 tiering_pred);
		if (k == NULL)
			break;

		io = moving_io_alloc(k);
		if (!io) {
			trace_bcache_tiering_alloc_fail(c, KEY_SIZE(k));
			break;
		}

		io->stats = &stats;
		io->in_flight = &c->tiering_in_flight;

		/* This also copies k into both insert_key and replace_key */

		bch_write_op_init(&io->op, c, &io->bio.bio,
				  &c->tier_write_points[1],
				  true, false, false,
				  k, k);
		io->op.io_wq	= c->tiering_write;
		io->op.btree_alloc_reserve = RESERVE_TIERING_BTREE;

		trace_bcache_tiering_copy(k);

		bch_ratelimit_increment(&c->tiering_pd.rate,
					KEY_SIZE(k) << 9);

		bch_scan_keylist_advance(&c->tiering_keys);

		closure_call(&io->cl, bch_data_move, NULL, &cl);
	}

	closure_sync(&cl);

	trace_bcache_tiering_end(c, stats.sectors_moved, stats.keys_moved);
}

static int bch_tiering_thread(void *arg)
{
	struct cache_set *c = arg;
	unsigned long last = jiffies;

	do {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   c->cache_tiers[1].nr_devices))
			break;

		read_tiering(c);
	} while (!bch_kthread_loop_ratelimit(&last,
					     c->btree_scan_ratelimit * HZ));

	return 0;
}

void bch_tiering_init_cache_set(struct cache_set *c)
{
	sema_init(&c->tiering_in_flight, BTREE_SCAN_BATCH / 2);
	bch_scan_keylist_init(&c->tiering_keys, BTREE_SCAN_BATCH);
	bch_pd_controller_init(&c->tiering_pd);
}

int bch_tiering_thread_start(struct cache_set *c)
{
	struct task_struct *t;

	c->tiering_write = alloc_workqueue("bch_tier_write",
					   WQ_UNBOUND|WQ_MEM_RECLAIM, 1);
	if (!c->tiering_write)
		return -ENOMEM;

	t = kthread_create(bch_tiering_thread, c, "bch_tier_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	c->tiering_read = t;
	wake_up_process(c->tiering_read);

	return 0;
}
