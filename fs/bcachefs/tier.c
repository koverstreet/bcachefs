
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "keybuf.h"
#include "move.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

#define TIERING_THRESHOLD	100

static void __update_tiering_rate(struct cache_set *c)
{
	unsigned i, j;
	u64 tier_dirty[CACHE_TIERS];
	u64 tier_size[CACHE_TIERS];

	for (i = 0; i < CACHE_TIERS; i++) {
		struct cache_tier *tier = c->cache_by_alloc + i;

		for (j = 0; j < tier->nr_devices; j++) {
			struct cache *ca = tier->devices[j];

			tier_size[i] += ca->sb.nbuckets - ca->sb.first_bucket;
			tier_dirty[i] += ca->sb.nbuckets - ca->sb.first_bucket -
				ca->buckets_free;
		}
	}

	if (tier_size[1]) {
		u64 target = div64_u64(tier_size[0] * tier_dirty[1],
				       tier_size[1]);

		bch_pd_controller_update(&c->tiering_pd,
					 target << (c->bucket_bits + 9),
					 tier_dirty[0] << (c->bucket_bits + 9));
	}
}

static void update_tiering_rate(struct work_struct *work)
{
	struct cache_set *c = container_of(to_delayed_work(work),
					   struct cache_set,
					   tiering_pd.update);
	__update_tiering_rate(c);

	schedule_delayed_work(&c->tiering_pd.update,
			      c->tiering_pd.update_seconds * HZ);
}

static bool tiering_pred(struct keybuf *buf, struct bkey *k)
{
	struct cache_set *c = container_of(buf, struct cache_set, tiering_keys);

	return bch_extent_ptrs(k) &&
		ptr_available(c, k, bch_extent_ptrs(k) - 1) &&
		!PTR_TIER(c, k, bch_extent_ptrs(k) - 1);
}

static void read_tiering(struct cache_set *c)
{
	struct keybuf_key *w;
	struct moving_io *io;
	struct closure cl;

	closure_init_stack(&cl);

	/* XXX: if we error, background writeback could stall indefinitely */

	c->tiering_keys.last_scanned = ZERO_KEY;

	while (!bch_ratelimit_wait_freezable_stoppable(&c->tiering_pd.rate,
						       &cl)) {
		w = bch_keybuf_next_rescan(c, &c->tiering_keys,
					   &MAX_KEY, tiering_pred);
		if (!w)
			break;

		if (ptr_stale(c, &w->key, 0)) {
			bch_keybuf_del(&c->tiering_keys, w);
			continue;
		}

		io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io)
			goto err;

		w->private	= io;
		io->w		= w;
		io->keybuf	= &c->tiering_keys;

		bch_data_insert_op_init(&io->op, c, c->tiering_wq,
					&io->bio.bio, 0,
					false, false, false,
					&io->w->key, &io->w->key);

		io->op.tier	= PTR_TIER(c, &w->key,
					   bch_extent_ptrs(&w->key) - 1) + 1;

		bch_ratelimit_increment(&c->tiering_pd.rate,
					KEY_SIZE(&w->key) << 9);

		closure_call(&io->cl, bch_data_move, NULL, &cl);
	}

	if (0) {
err:		if (!IS_ERR_OR_NULL(w->private))
			kfree(w->private);

		bch_keybuf_del(&c->tiering_keys, w);
	}

	closure_sync(&cl);
}

static int bch_tiering_thread(void *arg)
{
	struct cache_set *c = arg;
	unsigned long last = jiffies;

	do {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   c->cache_by_alloc[1].nr_devices))
			break;

		read_tiering(c);
	} while (!bch_kthread_loop_ratelimit(&last,
					     c->btree_scan_ratelimit * HZ));

	return 0;
}

void bch_tiering_init_cache_set(struct cache_set *c)
{
	bch_keybuf_init(&c->tiering_keys);
	INIT_DELAYED_WORK(&c->tiering_pd.update, update_tiering_rate);
}

int bch_tiering_thread_start(struct cache_set *c)
{
	c->tiering_thread = kthread_create(bch_tiering_thread, c,
					   "bcache_tier");
	if (IS_ERR(c->tiering_thread))
		return PTR_ERR(c->tiering_thread);

	bch_pd_controller_start(&c->tiering_pd);
	wake_up_process(c->tiering_thread);

	return 0;
}
