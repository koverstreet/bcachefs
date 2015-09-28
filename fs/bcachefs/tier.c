
#include "bcache.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

/**
 * tiering_pred - check if tiering should copy an extent to tier 1
 */
static bool tiering_pred(struct scan_keylist *kl, struct bkey_s_c k)
{
	struct cache *ca = container_of(kl, struct cache,
					tiering_queue.keys);
	struct cache_set *c = ca->set;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const struct bch_extent_ptr *ptr;
		struct cache_member_rcu *mi;
		unsigned replicas = 0;

		/* Make sure we have room to add a new pointer: */
		if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_MAX_U64s >
		    BKEY_EXTENT_VAL_U64s_MAX)
			return false;

		mi = cache_member_info_get(c);
		extent_for_each_ptr(e, ptr)
			if (ptr->dev < mi->nr_in_set &&
			    CACHE_TIER(&mi->m[ptr->dev]))
				replicas++;
		cache_member_info_put();

		return replicas < CACHE_SET_DATA_REPLICAS_WANT(&c->sb);
	}

	return false;
}

struct tiering_refill {
	struct bpos		start;
	struct cache		*ca;
	int			cache_iter;
	u64			sectors;
};

static void refill_done(struct tiering_refill *refill)
{
	if (refill->ca) {
		percpu_ref_put(&refill->ca->ref);
		refill->ca = NULL;
	}
}

/**
 * refill_next - move on to refilling the next cache's tiering keylist
 */
static void refill_next(struct cache_set *c, struct tiering_refill *refill)
{
	struct cache_group *tier;

	refill_done(refill);

	rcu_read_lock();
	tier = &c->cache_tiers[1];
	if (tier->nr_devices == 0)
		goto out;

	while (1) {
		while (refill->cache_iter < tier->nr_devices) {
			refill->ca = rcu_dereference(
					tier->devices[refill->cache_iter]);
			if (refill->ca != NULL) {
				percpu_ref_get(&refill->ca->ref);
				goto out;
			}
			refill->cache_iter++;
		}

		/* Reached the end, wrap around */
		refill->cache_iter = 0;
	}

out:
	rcu_read_unlock();
}

/*
 * refill_init - Start refilling a random cache device -- this ensures we
 * distribute data sanely even if each tiering pass discovers only a few
 * keys to tier
 */
static void refill_init(struct cache_set *c, struct tiering_refill *refill)
{
	struct cache_group *tier;

	memset(refill, 0, sizeof(*refill));
	refill->start = POS_MIN;

	rcu_read_lock();
	tier = &c->cache_tiers[1];
	if (tier->nr_devices != 0)
		refill->cache_iter = bch_rand_range(tier->nr_devices);
	rcu_read_unlock();

	refill_next(c, refill);
}

/**
 * tiering_keylist_full - we accumulate tiering_stripe_size sectors in a cache
 * device's tiering keylist before we move on to the next cache device
 */
static bool tiering_keylist_full(struct tiering_refill *refill)
{
	return (refill->sectors >= refill->ca->tiering_stripe_size);
}

/**
 * tiering_keylist_empty - to prevent a keylist from growing to more than twice
 * the tiering stripe size, we stop refill when a keylist has more than a single
 * stripe of sectors
 */
static bool tiering_keylist_empty(struct cache *ca)
{
	return (bch_scan_keylist_sectors(&ca->tiering_queue.keys)
		<= ca->tiering_stripe_size);
}

/**
 * tiering_refill - to keep all queues busy as much as possible, we add
 * up to a single stripe of sectors to each cache device's queue, iterating
 * over all cache devices twice, so each one has two stripe's of writes
 * queued up, before we have to wait for move operations to complete.
 */
static void tiering_refill(struct cache_set *c, struct tiering_refill *refill)
{
	struct scan_keylist *keys;
	struct btree_iter iter;
	struct bkey_s_c k;

	if (bkey_cmp(refill->start, POS_MAX) >= 0)
		return;

	if (refill->ca == NULL)
		return;

	if (!tiering_keylist_empty(refill->ca))
		return;

	trace_bcache_tiering_refill_start(c);

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, refill->start, k) {
		keys = &refill->ca->tiering_queue.keys;

		if (!tiering_pred(keys, k)) {
			refill->start = k.k->p;
			goto next;
		}

		/* Growing the keylist might fail */
		if (bch_scan_keylist_add(keys, k))
			goto done;

		/* TODO: split key if refill->sectors is now > stripe_size */
		refill->sectors += k.k->size;
		refill->start = k.k->p;

		/* Check if we've added enough keys to this keylist */
		if (tiering_keylist_full(refill)) {
			/* Move on to refill the next cache device's keylist */
			refill->sectors = 0;
			refill->cache_iter++;
			refill_next(c, refill);

			/* All cache devices got removed somehow */
			if (refill->ca == NULL)
				goto done;

			/*
			 * If the next cache's keylist is not sufficiently
			 * empty, wait for it to drain before refilling
			 * anything.  We prioritize even distribution of data
			 * over maximizing write bandwidth.
			 */
			if (!tiering_keylist_empty(refill->ca))
				goto done;
		}
next:
		bch_btree_iter_cond_resched(&iter);
	}
	/* Reached the end of the keyspace */
	refill->start = POS_MAX;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_tiering_refill_end(c);
}

static int issue_tiering_move(struct moving_queue *q,
			      struct moving_context *ctxt,
			      struct bkey_s_c k)
{
	struct cache *ca = container_of(q, struct cache, tiering_queue);
	struct cache_set *c = ca->set;
	struct moving_io *io;

	io = moving_io_alloc(k);
	if (!io) {
		trace_bcache_tiering_alloc_fail(c, k.k->size);
		return -ENOMEM;
	}

	bch_write_op_init(&io->op, c, &io->bio,
			  &ca->tiering_write_point,
			  bkey_i_to_s_c(&io->key),
			  bkey_i_to_s_c(&io->key), NULL, 0);
	io->op.io_wq = q->wq;

	trace_bcache_tiering_copy(k.k);

	/*
	 * IMPORTANT: We must call bch_data_move before we dequeue so
	 * that the key can always be found in either the pending list
	 * in the moving queue or in the scan keylist list in the
	 * moving queue.
	 * If we reorder, there is a window where a key is not found
	 * by btree gc marking.
	 */
	bch_data_move(q, ctxt, io);
	bch_scan_keylist_dequeue(&q->keys);
	return 0;
}

/**
 * tiering_next_cache - issue a move to write an extent to the next cache
 * device in round robin order
 */
static int tiering_next_cache(struct cache_set *c,
			      int *cache_iter,
			      struct moving_context *ctxt,
			      struct tiering_refill *refill)
{
	struct cache_group *tier;
	int start = *cache_iter;
	struct cache *ca;

	/* If true at the end of the loop, all keylists were empty, so we
	 * have reached the end of the keyspace */
	bool done = true;
	/* If true at the end of the loop, all queues were full, so we must
	 * wait for some ops to finish */
	bool full = true;

	do {
		rcu_read_lock();
		tier = &c->cache_tiers[1];
		if (tier->nr_devices == 0) {
			rcu_read_unlock();
			return 0;
		}

		if (*cache_iter >= tier->nr_devices) {
			rcu_read_unlock();
			*cache_iter = 0;
			continue;
		}

		ca = rcu_dereference(tier->devices[*cache_iter]);
		if (ca == NULL
		    || CACHE_STATE(&ca->mi) != CACHE_ACTIVE
		    || ca->tiering_queue.stopped) {
			rcu_read_unlock();
			(*cache_iter)++;
			continue;
		}

		percpu_ref_get(&ca->ref);
		rcu_read_unlock();
		(*cache_iter)++;

		tiering_refill(c, refill);

		if (bch_queue_full(&ca->tiering_queue)) {
			done = false;
		} else {
			struct bkey_i *k =
				bch_scan_keylist_next(&ca->tiering_queue.keys);
			if (k) {
				issue_tiering_move(&ca->tiering_queue, ctxt,
						   bkey_i_to_s_c(k));
				done = false;
				full = false;
			}
		}

		percpu_ref_put(&ca->ref);
	} while (*cache_iter != start);

	if (done) {
		/*
		 * All devices have an empty keylist now, just wait for
		 * pending moves to finish and we're done.
		 */
		return 0;
	} else if (full) {
		/*
		 * No device with keys still remaining on its keylist has a
		 * queue that is not full. In this case, we have to wait for
		 * at least one read to complete before trying again.
		 * Otherwise, we could issue a read for this device.
		 */
		return -EAGAIN;
	} else {
		/* Try again immediately */
		return -EIOCBQUEUED;
	}
}

static u64 read_tiering(struct cache_set *c)
{
	struct moving_context ctxt;
	struct tiering_refill refill;
	int cache_iter = 0;
	int ret;

	trace_bcache_tiering_start(c);

	refill_init(c, &refill);

	bch_moving_context_init(&ctxt, &c->tiering_pd.rate,
				MOVING_PURPOSE_TIERING);

	while (!bch_moving_context_wait(&ctxt)) {
		cond_resched();

		ret = tiering_next_cache(c, &cache_iter, &ctxt, &refill);
		if (ret == -EAGAIN)
			bch_moving_wait(&ctxt);
		else if (!ret)
			break;
	}

	closure_sync(&ctxt.cl);
	refill_done(&refill);

	trace_bcache_tiering_end(c, ctxt.sectors_moved, ctxt.keys_moved);

	return ctxt.sectors_moved;
}

static int bch_tiering_thread(void *arg)
{
	struct cache_set *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	struct cache *ca;
	u64 sectors, tier_capacity;
	unsigned long last;
	unsigned i;

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->tiering_enabled &&
					   c->cache_tiers[1].nr_devices))
			break;

		last = atomic_long_read(&clock->now);

		sectors = read_tiering(c);

		tier_capacity = 0;
		rcu_read_lock();
		group_for_each_cache_rcu(ca, &c->cache_tiers[0], i)
			tier_capacity +=
				(ca->mi.nbuckets -
				 ca->mi.first_bucket) << ca->bucket_bits;
		rcu_read_unlock();

		if (sectors < tier_capacity >> 4)
			bch_kthread_io_clock_wait(clock,
					  last + (tier_capacity >> 5));
	}

	return 0;
}

#define TIERING_KEYS_MAX_SIZE DFLT_SCAN_KEYLIST_MAX_SIZE
#define TIERING_NR 64
#define TIERING_READ_NR 8
#define TIERING_WRITE_NR 32

void bch_tiering_init_cache_set(struct cache_set *c)
{
	bch_pd_controller_init(&c->tiering_pd);
}

void bch_tiering_init_cache(struct cache *ca)
{
	bch_queue_init(&ca->tiering_queue,
		       ca->set,
		       TIERING_KEYS_MAX_SIZE,
		       TIERING_NR,
		       TIERING_READ_NR,
		       TIERING_WRITE_NR,
		       false);

	ca->tiering_stripe_size = ca->mi.bucket_size * 2;
}

int bch_tiering_write_start(struct cache *ca)
{
	return bch_queue_start(&ca->tiering_queue, "bch_tier_write");
}

int bch_tiering_read_start(struct cache_set *c)
{
	struct task_struct *t;

	t = kthread_create(bch_tiering_thread, c, "bch_tier_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	c->tiering_read = t;
	wake_up_process(c->tiering_read);

	return 0;
}

void bch_tiering_write_destroy(struct cache *ca)
{
	bch_queue_destroy(&ca->tiering_queue);
}

void bch_tiering_write_stop(struct cache *ca)
{
	bch_queue_stop(&ca->tiering_queue);

	/*
	 * Make sure that it is empty so that gc marking doesn't keep
	 * marking stale entries from when last used.
	 */
	bch_scan_keylist_reset(&ca->tiering_queue.keys);
}

void bch_tiering_read_stop(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(c->tiering_read)) {
		kthread_stop(c->tiering_read);
		c->tiering_read = NULL;
	}
}
