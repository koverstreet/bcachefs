// SPDX-License-Identifier: GPL-2.0
/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/foreground.h"
#include "btree/iter.h"
#include "btree/update.h"
#include "btree/write_buffer.h"
#include "data/ec.h"
#include "errcode.h"
#include "error.h"
#include "alloc/lru.h"
#include "data/move.h"
#include "data/copygc.h"
#include "trace.h"

#include "util/clock.h"

#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/sched/task.h>
#include <linux/wait.h>

struct buckets_in_flight {
	struct rhashtable	*table;
	struct move_bucket	*first;
	struct move_bucket	*last;
	size_t			nr;
	size_t			sectors;

	DARRAY(struct move_bucket *) to_evacuate;
};

static const struct rhashtable_params bch_move_bucket_params = {
	.head_offset		= offsetof(struct move_bucket, hash),
	.key_offset		= offsetof(struct move_bucket, k),
	.key_len		= sizeof(struct move_bucket_key),
	.automatic_shrinking	= true,
};

static void move_bucket_in_flight_add(struct buckets_in_flight *list, struct move_bucket *b)
{
	if (!list->first)
		list->first = b;
	else
		list->last->next = b;

	list->last = b;
	list->nr++;
	list->sectors += b->sectors;
}

static int bch2_bucket_is_movable(struct btree_trans *trans,
				  struct move_bucket *b, u64 time)
{
	struct bch_fs *c = trans->c;

	/*
	 * Valid bucket?
	 *
	 * XXX: we should kill the LRU entry here if it's not
	 */
	CLASS(bch2_dev_bucket_tryget, ca)(c, b->k.bucket);
	if (!ca)
		return 0;

	if (ca->mi.state != BCH_MEMBER_STATE_rw ||
	    !bch2_dev_is_online(ca)) {
		bch_err_throw(c, bucket_not_moveable_dev_not_rw);
		return 0;
	}

	/* Bucket still being written? */
	if (bch2_bucket_is_open(c, b->k.bucket.inode, b->k.bucket.offset)) {
		bch_err_throw(c, bucket_not_moveable_bucket_open);
		return 0;
	}

	/* We won't be able to evacuate it if there's missing backpointers */
	if (bch2_bucket_bitmap_test(&ca->bucket_backpointer_mismatch, b->k.bucket.offset)) {
		bch_err_throw(c, bucket_not_moveable_bp_mismatch);
		return 0;
	}

	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, b->k.bucket, BTREE_ITER_cached);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (ret)
		return ret;

	struct bch_alloc_v4 _a;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &_a);
	b->k.gen	= a->gen;
	b->sectors	= bch2_bucket_sectors_dirty(*a);
	u64 lru_idx	= alloc_lru_idx_fragmentation(*a, ca);

	if (!lru_idx || lru_idx > time) {
		bch_err_throw(c, bucket_not_moveable_lru_race);
		return 0;
	}

	return true;
}

static void move_bucket_free(struct buckets_in_flight *list,
			     struct move_bucket *b)
{
	int ret = rhashtable_remove_fast(list->table, &b->hash,
					 bch_move_bucket_params);
	BUG_ON(ret);
	kfree(b);
}

static void move_buckets_wait(struct moving_context *ctxt,
			      struct buckets_in_flight *list,
			      bool flush)
{
	struct move_bucket *i;

	while ((i = list->first)) {
		if (flush)
			move_ctxt_wait_event(ctxt, !atomic_read(&i->count));

		if (atomic_read(&i->count))
			break;

		list->first = i->next;
		if (!list->first)
			list->last = NULL;

		list->nr--;
		list->sectors -= i->sectors;

		move_bucket_free(list, i);
	}

	bch2_trans_unlock_long(ctxt->trans);
}

static bool bucket_in_flight(struct buckets_in_flight *list,
			     struct move_bucket_key k)
{
	return rhashtable_lookup_fast(list->table, &k, bch_move_bucket_params);
}

static int try_add_copygc_bucket(struct btree_trans *trans,
				 struct buckets_in_flight *buckets_in_flight,
				 struct bpos bucket, u64 lru_time)
{
	struct move_bucket b = { .k.bucket = bucket };

	int ret = bch2_bucket_is_movable(trans, &b, lru_time);
	if (ret <= 0)
		return ret;

	if (bucket_in_flight(buckets_in_flight, b.k))
		return 0;

	struct move_bucket *b_i = kmalloc(sizeof(*b_i), GFP_KERNEL);
	if (!b_i)
		return -ENOMEM;

	*b_i = b;

	ret = darray_push(&buckets_in_flight->to_evacuate, b_i);
	if (ret) {
		kfree(b_i);
		return ret;
	}

	ret = rhashtable_lookup_insert_fast(buckets_in_flight->table, &b_i->hash,
					    bch_move_bucket_params);
	BUG_ON(ret);

	size_t nr_to_get = max_t(size_t, 16U, buckets_in_flight->nr / 4);
	return buckets_in_flight->to_evacuate.nr >= nr_to_get;
}

static int bch2_copygc_get_buckets(struct moving_context *ctxt,
			struct buckets_in_flight *buckets_in_flight)
{
	struct btree_trans *trans = ctxt->trans;

	int ret = for_each_btree_key_max(trans, iter, BTREE_ID_lru,
				  lru_start(BCH_LRU_BUCKET_FRAGMENTATION),
				  lru_end(BCH_LRU_BUCKET_FRAGMENTATION),
				  0, k,
		try_add_copygc_bucket(trans, buckets_in_flight,
				      u64_to_bucket(k.k->p.offset),
				      lru_pos_time(k.k->p))
	);

	return ret < 0 ? ret : 0;
}

static int bch2_copygc_get_stripe_buckets(struct moving_context *ctxt,
			struct buckets_in_flight *buckets_in_flight)
{
	struct btree_trans *trans = ctxt->trans;

	int ret = for_each_btree_key_max(trans, iter, BTREE_ID_lru,
				  lru_start(BCH_LRU_STRIPE_FRAGMENTATION),
				  lru_end(BCH_LRU_STRIPE_FRAGMENTATION),
				  0, lru_k, ({
		CLASS(btree_iter, s_iter)(trans, BTREE_ID_stripes, POS(0, lru_k.k->p.offset), 0);
		struct bkey_s_c s_k = bch2_btree_iter_peek_slot(&s_iter);
		int ret2 = bkey_err(s_k);
		if (ret2)
			goto err;

		if (s_k.k->type != KEY_TYPE_stripe)
			continue;

		const struct bch_stripe *s = bkey_s_c_to_stripe(s_k).v;

		/* write buffer race? */
		if (stripe_lru_pos(s) != lru_pos_time(lru_k.k->p))
			continue;

		unsigned nr_data = s->nr_blocks - s->nr_redundant;
		for (unsigned i = 0; i < nr_data; i++) {
			if (!stripe_blockcount_get(s, i))
				continue;

			const struct bch_extent_ptr *ptr = s->ptrs + i;
			CLASS(bch2_dev_tryget, ca)(trans->c, ptr->dev);
			if (unlikely(!ca))
				continue;

			ret2 = try_add_copygc_bucket(trans, buckets_in_flight,
						     PTR_BUCKET_POS(ca, ptr), U64_MAX);
			if (ret2)
				break;
		}
err:
		ret2;
	}));

	return ret < 0 ? ret : 0;
}

static bool should_do_ec_copygc(struct btree_trans *trans)
{
	u64 stripe_frag_ratio = 0;

	for_each_btree_key_max(trans, iter, BTREE_ID_lru,
			       lru_start(BCH_LRU_STRIPE_FRAGMENTATION),
			       lru_end(BCH_LRU_STRIPE_FRAGMENTATION),
			       0, lru_k, ({
		CLASS(btree_iter, s_iter)(trans, BTREE_ID_stripes, POS(0, lru_k.k->p.offset), 0);
		struct bkey_s_c s_k = bch2_btree_iter_peek_slot(&s_iter);
		int ret = bkey_err(s_k);
		if (ret)
			goto err;

		if (s_k.k->type != KEY_TYPE_stripe)
			continue;

		const struct bch_stripe *s = bkey_s_c_to_stripe(s_k).v;

		/* write buffer race? */
		if (stripe_lru_pos(s) != lru_pos_time(lru_k.k->p))
			continue;

		unsigned nr_data = s->nr_blocks - s->nr_redundant, blocks_nonempty = 0;
		for (unsigned i = 0; i < nr_data; i++)
			blocks_nonempty += !!stripe_blockcount_get(s, i);

		/* stripe is pending delete */
		if (!blocks_nonempty)
			continue;

		/* This matches the calculation in alloc_lru_idx_fragmentation, so we can
		 * directly compare without actually looking up the bucket pointed to by the
		 * bucket fragmentation lru:
		 */
		stripe_frag_ratio = div_u64(blocks_nonempty * (1ULL << 31), nr_data);
		break;
err:
		ret;
	}));

	CLASS(btree_iter, iter)(trans, BTREE_ID_lru, lru_start(BCH_LRU_BUCKET_FRAGMENTATION), 0);
	struct bkey_s_c lru_k;

	lockrestart_do(trans, bkey_err(lru_k = bch2_btree_iter_peek_max(&iter,
							lru_end(BCH_LRU_BUCKET_FRAGMENTATION))));

	u64 bucket_frag_ratio = lru_k.k && !bkey_err(lru_k) ? lru_pos_time(lru_k.k->p) : 0;

	/* Prefer normal bucket copygc */
	return stripe_frag_ratio && stripe_frag_ratio * 2 < bucket_frag_ratio;
}

noinline
static int bch2_copygc(struct moving_context *ctxt,
		       struct buckets_in_flight *buckets_in_flight,
		       bool *did_work)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;
	struct data_update_opts data_opts = {
		.btree_insert_flags = BCH_WATERMARK_copygc,
	};
	u64 sectors_seen	= atomic64_read(&ctxt->stats->sectors_seen);
	u64 sectors_moved	= atomic64_read(&ctxt->stats->sectors_moved);
	int ret = 0;

	move_buckets_wait(ctxt, buckets_in_flight, false);

	ret = bch2_btree_write_buffer_tryflush(trans);
	if (bch2_err_matches(ret, EROFS))
		goto err;

	if (bch2_fs_fatal_err_on(ret, c, "%s: from bch2_btree_write_buffer_tryflush()", bch2_err_str(ret)))
		goto err;

	ret = should_do_ec_copygc(trans)
		? bch2_copygc_get_stripe_buckets(ctxt, buckets_in_flight)
		: bch2_copygc_get_buckets(ctxt, buckets_in_flight);
	if (ret)
		goto err;

	darray_for_each(buckets_in_flight->to_evacuate, i) {
		if (kthread_should_stop() || freezing(current))
			break;

		struct move_bucket *b = *i;
		*i = NULL;

		move_bucket_in_flight_add(buckets_in_flight, b);

		ret = bch2_evacuate_bucket(ctxt, b, b->k.bucket, b->k.gen, data_opts);
		if (ret)
			goto err;

		*did_work = true;
	}
err:
	/* no entries in LRU btree found, or got to end: */
	if (bch2_err_matches(ret, ENOENT))
		ret = 0;

	if (ret < 0 && !bch2_err_matches(ret, EROFS))
		bch_err_msg(c, ret, "from bch2_move_data()");

	sectors_seen	= atomic64_read(&ctxt->stats->sectors_seen) - sectors_seen;
	sectors_moved	= atomic64_read(&ctxt->stats->sectors_moved) - sectors_moved;
	trace_and_count(c, copygc, c, buckets_in_flight->to_evacuate.nr, sectors_seen, sectors_moved);

	darray_for_each(buckets_in_flight->to_evacuate, i)
		if (*i)
			move_bucket_free(buckets_in_flight, *i);
	darray_exit(&buckets_in_flight->to_evacuate);
	return ret;
}

static u64 bch2_copygc_dev_wait_amount(struct bch_dev *ca)
{
	struct bch_dev_usage_full usage_full = bch2_dev_usage_full_read(ca);
	struct bch_dev_usage usage;

	for (unsigned i = 0; i < BCH_DATA_NR; i++)
		usage.buckets[i] = usage_full.d[i].buckets;

	s64 fragmented_allowed = ((__dev_buckets_available(ca, usage, BCH_WATERMARK_stripe) *
				   ca->mi.bucket_size) >> 1);
	s64 fragmented = 0;

	for (unsigned i = 0; i < BCH_DATA_NR; i++)
		if (data_type_movable(i))
			fragmented += usage_full.d[i].buckets * ca->mi.bucket_size -
				usage_full.d[i].sectors;

	return max(0LL, fragmented_allowed - fragmented);
}

/*
 * Copygc runs when the amount of fragmented data is above some arbitrary
 * threshold:
 *
 * The threshold at the limit - when the device is full - is the amount of space
 * we reserved in bch2_recalc_capacity; we can't have more than that amount of
 * disk space stranded due to fragmentation and store everything we have
 * promised to store.
 *
 * But we don't want to be running copygc unnecessarily when the device still
 * has plenty of free space - rather, we want copygc to smoothly run every so
 * often and continually reduce the amount of fragmented space as the device
 * fills up. So, we increase the threshold by half the current free space.
 */
u64 bch2_copygc_wait_amount(struct bch_fs *c)
{
	u64 wait = U64_MAX;

	guard(rcu)();
	for_each_rw_member_rcu(c, ca)
		wait = min(wait, bch2_copygc_dev_wait_amount(ca));
	return wait;
}

void bch2_copygc_wait_to_text(struct printbuf *out, struct bch_fs *c)
{
	printbuf_tabstop_push(out, 32);
	prt_printf(out, "running:\t%u\n",		c->copygc_running);
	prt_printf(out, "copygc_wait:\t%llu\n",		c->copygc_wait);
	prt_printf(out, "copygc_wait_at:\t%llu\n",	c->copygc_wait_at);

	prt_printf(out, "Currently waiting for:\t");
	prt_human_readable_u64(out, max(0LL, c->copygc_wait -
					atomic64_read(&c->io_clock[WRITE].now)) << 9);
	prt_newline(out);

	prt_printf(out, "Currently waiting since:\t");
	prt_human_readable_u64(out, max(0LL,
					atomic64_read(&c->io_clock[WRITE].now) -
					c->copygc_wait_at) << 9);
	prt_newline(out);

	bch2_printbuf_make_room(out, 4096);

	struct task_struct *t;
	scoped_guard(rcu) {
		guard(printbuf_atomic)(out);
		prt_printf(out, "Currently calculated wait:\n");
		for_each_rw_member_rcu(c, ca) {
			prt_printf(out, "  %s:\t", ca->name);
			prt_human_readable_u64(out, bch2_copygc_dev_wait_amount(ca));
			prt_newline(out);
		}

		t = rcu_dereference(c->copygc_thread);
		if (t)
			get_task_struct(t);
	}

	if (t) {
		bch2_prt_task_backtrace(out, t, 0, GFP_KERNEL);
		put_task_struct(t);
	}
}

static int bch2_copygc_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct moving_context ctxt;
	struct bch_move_stats move_stats;
	struct io_clock *clock = &c->io_clock[WRITE];
	struct buckets_in_flight buckets = {};
	u64 last, wait;

	buckets.table = kzalloc(sizeof(*buckets.table), GFP_KERNEL);
	int ret = !buckets.table
		? -ENOMEM
		: rhashtable_init(buckets.table, &bch_move_bucket_params);
	bch_err_msg(c, ret, "allocating copygc buckets in flight");
	if (ret)
		goto err;

	set_freezable();

	/*
	 * Data move operations can't run until after check_snapshots has
	 * completed, and bch2_snapshot_is_ancestor() is available.
	 */
	kthread_wait_freezable(c->recovery.pass_done > BCH_RECOVERY_PASS_check_snapshots ||
			       kthread_should_stop());

	bch2_move_stats_init(&move_stats, "copygc");
	bch2_moving_ctxt_init(&ctxt, c, NULL, &move_stats,
			      writepoint_ptr(&c->copygc_write_point),
			      false);

	while (!ret && !kthread_should_stop()) {
		bool did_work = false;

		bch2_trans_unlock_long(ctxt.trans);
		cond_resched();

		if (!c->opts.copygc_enabled) {
			move_buckets_wait(&ctxt, &buckets, true);
			kthread_wait_freezable(c->opts.copygc_enabled ||
					       kthread_should_stop());
		}

		if (unlikely(freezing(current))) {
			move_buckets_wait(&ctxt, &buckets, true);
			__refrigerator(false);
			continue;
		}

		last = atomic64_read(&clock->now);
		wait = bch2_copygc_wait_amount(c);

		if (wait > clock->max_slop) {
			c->copygc_wait_at = last;
			c->copygc_wait = last + wait;
			move_buckets_wait(&ctxt, &buckets, true);
			trace_and_count(c, copygc_wait, c, wait, last + wait);
			bch2_kthread_io_clock_wait(clock, last + wait,
					MAX_SCHEDULE_TIMEOUT);
			continue;
		}

		c->copygc_wait = 0;

		c->copygc_running = true;
		ret = bch2_copygc(&ctxt, &buckets, &did_work);
		c->copygc_running = false;

		wake_up(&c->copygc_running_wq);

		if (!wait && !did_work) {
			u64 min_member_capacity = bch2_min_rw_member_capacity(c);

			if (min_member_capacity == U64_MAX)
				min_member_capacity = 128 * 2048;

			move_buckets_wait(&ctxt, &buckets, true);
			bch2_kthread_io_clock_wait(clock, last + (min_member_capacity >> 6),
					MAX_SCHEDULE_TIMEOUT);
		}
	}

	move_buckets_wait(&ctxt, &buckets, true);
	rhashtable_destroy(buckets.table);
	bch2_moving_ctxt_exit(&ctxt);
	bch2_move_stats_exit(&move_stats, c);
err:
	kfree(buckets.table);
	return ret;
}

void bch2_copygc_stop(struct bch_fs *c)
{
	if (c->copygc_thread) {
		kthread_stop(c->copygc_thread);
		put_task_struct(c->copygc_thread);
	}
	c->copygc_thread = NULL;
}

int bch2_copygc_start(struct bch_fs *c)
{
	struct task_struct *t;
	int ret;

	if (c->copygc_thread)
		return 0;

	if (c->opts.nochanges)
		return 0;

	if (bch2_fs_init_fault("copygc_start"))
		return -ENOMEM;

	t = kthread_create(bch2_copygc_thread, c, "bch-copygc/%s", c->name);
	ret = PTR_ERR_OR_ZERO(t);
	bch_err_msg(c, ret, "creating copygc thread");
	if (ret)
		return ret;

	get_task_struct(t);

	c->copygc_thread = t;
	wake_up_process(c->copygc_thread);

	return 0;
}

void bch2_fs_copygc_init(struct bch_fs *c)
{
	init_waitqueue_head(&c->copygc_running_wq);
	c->copygc_running = false;
}
