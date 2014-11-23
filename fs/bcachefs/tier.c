
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
	struct cache_set *c = container_of(kl, struct cache_set,
					   tiering_queue.keys);
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

static int issue_tiering_move(struct moving_queue *q,
			      struct moving_context *ctxt,
			      struct bkey *k)
{
	struct cache_set *c = container_of(q, struct cache_set, tiering_queue);
	struct moving_io *io;

	io = moving_io_alloc(k);
	if (!io) {
		trace_bcache_tiering_alloc_fail(c, KEY_SIZE(k));
		return -ENOMEM;
	}

	bch_write_op_init(&io->op, c, &io->bio.bio,
			  &c->tier_write_points[1],
			  true, false, false,
			  &io->key, &io->key);
	io->op.io_wq = q->wq;
	io->op.btree_alloc_reserve = RESERVE_TIERING_BTREE;

	trace_bcache_tiering_copy(k);
	bch_scan_keylist_dequeue(&q->keys);

	bch_data_move(q, ctxt, io);
	return 0;
}

static void read_tiering(struct cache_set *c)
{
	struct moving_context ctxt;
	struct bkey *k;

	trace_bcache_tiering_start(c);

	bch_moving_context_init(&ctxt);

	while (!bch_ratelimit_wait_freezable_stoppable(&c->tiering_pd.rate,
						       &ctxt.cl)) {
		if (bch_queue_full(&c->tiering_queue)) {
			bch_moving_wait(&ctxt);
			continue;
		}

		k = bch_scan_keylist_next_rescan(c,
						 &c->tiering_queue.keys,
						 &ctxt.last_scanned,
						 &MAX_KEY,
						 tiering_pred);
		if (k == NULL)
			break;

		issue_tiering_move(&c->tiering_queue, &ctxt, k);
	}

	closure_sync(&ctxt.cl);

	trace_bcache_tiering_end(c, ctxt.sectors_moved, ctxt.keys_moved);
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

#define TIERING_KEYS_MAX_SIZE DFLT_SCAN_KEYLIST_MAX_SIZE
#define TIERING_NR 64
#define TIERING_READ_NR 8
#define TIERING_WRITE_NR 32

void bch_tiering_init_cache_set(struct cache_set *c)
{
	bch_pd_controller_init(&c->tiering_pd);
	bch_queue_init(&c->tiering_queue,
		       TIERING_KEYS_MAX_SIZE,
		       TIERING_NR,
		       TIERING_READ_NR,
		       TIERING_WRITE_NR);
}

int bch_tiering_thread_start(struct cache_set *c)
{
	struct task_struct *t;
	int ret;

	ret = bch_queue_start(&c->tiering_queue,
			      "bch_tier_write");
	if (ret)
		return ret;

	t = kthread_create(bch_tiering_thread, c, "bch_tier_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	c->tiering_read = t;
	wake_up_process(c->tiering_read);

	return 0;
}

void bch_tiering_stop(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(c->tiering_read)) {
		kthread_stop(c->tiering_read);
		c->tiering_read = NULL;
	}

	bch_queue_destroy(&c->tiering_queue);
}
