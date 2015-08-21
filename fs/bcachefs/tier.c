
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "keybuf.h"
#include "move.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

static bool tiering_pred(struct keybuf *buf, struct bkey *k)
{
	struct cache_set *c = container_of(buf, struct cache_set, tiering_keys);
	unsigned dev;

	if (!bch_extent_ptrs(k))
		return false;

	/* need at least CACHE_SET_DATA_REPLICAS_WANT ptrs not on tier 0 */

	dev = max_t(int, 0, PTR_DEV(k, bch_extent_ptrs(k) -
				    CACHE_SET_DATA_REPLICAS_WANT(&c->sb)));

	return dev < c->sb.nr_in_set &&
		!CACHE_TIER(&c->members[dev]);
}

static void read_tiering(struct cache_set *c)
{
	struct keybuf_key *w;
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
		w = bch_keybuf_next_rescan(c, &c->tiering_keys,
					   &MAX_KEY, tiering_pred);
		if (!w)
			break;

		io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io) {
			trace_bcache_tiering_alloc_fail(c, KEY_SIZE(&w->key));
			bch_keybuf_put(&c->tiering_keys, w);
			break;
		}

		io->w = w;
		io->keybuf = &c->tiering_keys;
		io->stats = &stats;

		bch_write_op_init(&io->op, c, &io->bio.bio,
				  &c->tier_write_points[1],
				  true, false, false,
				  &io->w->key, &io->w->key);
		io->op.io_wq	= c->tiering_write;
		io->op.btree_alloc_reserve = RESERVE_TIERING_BTREE;

		trace_bcache_tiering_copy(&w->key);

		bch_ratelimit_increment(&c->tiering_pd.rate,
					KEY_SIZE(&w->key) << 9);

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
	bch_keybuf_init(&c->tiering_keys);
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
