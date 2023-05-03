// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2012 Google, Inc.
 *
 * Foreground allocator code: allocate buckets from freelist, and allocate in
 * sector granularity from writepoints.
 *
 * bch2_bucket_alloc() allocates a single bucket from a specific device.
 *
 * bch2_bucket_alloc_set() allocates one or more buckets from different devices
 * in a given filesystem.
 */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "btree_iter.h"
#include "btree_update.h"
#include "btree_gc.h"
#include "buckets.h"
#include "buckets_waiting_for_journal.h"
#include "clock.h"
#include "debug.h"
#include "disk_groups.h"
#include "ec.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "movinggc.h"
#include "trace.h"

#include <linux/math64.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>

const char * const bch2_alloc_reserves[] = {
#define x(t) #t,
	BCH_ALLOC_RESERVES()
#undef x
	NULL
};

/*
 * Open buckets represent a bucket that's currently being allocated from.  They
 * serve two purposes:
 *
 *  - They track buckets that have been partially allocated, allowing for
 *    sub-bucket sized allocations - they're used by the sector allocator below
 *
 *  - They provide a reference to the buckets they own that mark and sweep GC
 *    can find, until the new allocation has a pointer to it inserted into the
 *    btree
 *
 * When allocating some space with the sector allocator, the allocation comes
 * with a reference to an open bucket - the caller is required to put that
 * reference _after_ doing the index update that makes its allocation reachable.
 */

void bch2_reset_alloc_cursors(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	rcu_read_lock();
	for_each_member_device_rcu(ca, c, i, NULL)
		ca->alloc_cursor = 0;
	rcu_read_unlock();
}

static void bch2_open_bucket_hash_add(struct bch_fs *c, struct open_bucket *ob)
{
	open_bucket_idx_t idx = ob - c->open_buckets;
	open_bucket_idx_t *slot = open_bucket_hashslot(c, ob->dev, ob->bucket);

	ob->hash = *slot;
	*slot = idx;
}

static void bch2_open_bucket_hash_remove(struct bch_fs *c, struct open_bucket *ob)
{
	open_bucket_idx_t idx = ob - c->open_buckets;
	open_bucket_idx_t *slot = open_bucket_hashslot(c, ob->dev, ob->bucket);

	while (*slot != idx) {
		BUG_ON(!*slot);
		slot = &c->open_buckets[*slot].hash;
	}

	*slot = ob->hash;
	ob->hash = 0;
}

void __bch2_open_bucket_put(struct bch_fs *c, struct open_bucket *ob)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, ob->dev);

	if (ob->ec) {
		bch2_ec_bucket_written(c, ob);
		return;
	}

	percpu_down_read(&c->mark_lock);
	spin_lock(&ob->lock);

	ob->valid = false;
	ob->data_type = 0;

	spin_unlock(&ob->lock);
	percpu_up_read(&c->mark_lock);

	spin_lock(&c->freelist_lock);
	bch2_open_bucket_hash_remove(c, ob);

	ob->freelist = c->open_buckets_freelist;
	c->open_buckets_freelist = ob - c->open_buckets;

	c->open_buckets_nr_free++;
	ca->nr_open_buckets--;
	spin_unlock(&c->freelist_lock);

	closure_wake_up(&c->open_buckets_wait);
}

void bch2_open_bucket_write_error(struct bch_fs *c,
				  struct open_buckets *obs,
				  unsigned dev)
{
	struct open_bucket *ob;
	unsigned i;

	open_bucket_for_each(c, obs, ob, i)
		if (ob->dev == dev && ob->ec)
			bch2_ec_bucket_cancel(c, ob);
}

static struct open_bucket *bch2_open_bucket_alloc(struct bch_fs *c)
{
	struct open_bucket *ob;

	BUG_ON(!c->open_buckets_freelist || !c->open_buckets_nr_free);

	ob = c->open_buckets + c->open_buckets_freelist;
	c->open_buckets_freelist = ob->freelist;
	atomic_set(&ob->pin, 1);
	ob->data_type = 0;

	c->open_buckets_nr_free--;
	return ob;
}

static void open_bucket_free_unused(struct bch_fs *c,
				    struct write_point *wp,
				    struct open_bucket *ob)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, ob->dev);
	bool may_realloc = wp->data_type == BCH_DATA_user;

	BUG_ON(ca->open_buckets_partial_nr >
	       ARRAY_SIZE(ca->open_buckets_partial));

	if (ca->open_buckets_partial_nr <
	    ARRAY_SIZE(ca->open_buckets_partial) &&
	    may_realloc) {
		spin_lock(&c->freelist_lock);
		ob->on_partial_list = true;
		ca->open_buckets_partial[ca->open_buckets_partial_nr++] =
			ob - c->open_buckets;
		spin_unlock(&c->freelist_lock);

		closure_wake_up(&c->open_buckets_wait);
		closure_wake_up(&c->freelist_wait);
	} else {
		bch2_open_bucket_put(c, ob);
	}
}

/* _only_ for allocating the journal on a new device: */
long bch2_bucket_alloc_new_fs(struct bch_dev *ca)
{
	while (ca->new_fs_bucket_idx < ca->mi.nbuckets) {
		u64 b = ca->new_fs_bucket_idx++;

		if (!is_superblock_bucket(ca, b) &&
		    (!ca->buckets_nouse || !test_bit(b, ca->buckets_nouse)))
			return b;
	}

	return -1;
}

static inline unsigned open_buckets_reserved(enum alloc_reserve reserve)
{
	switch (reserve) {
	case RESERVE_btree:
	case RESERVE_btree_movinggc:
		return 0;
	case RESERVE_movinggc:
		return OPEN_BUCKETS_COUNT / 4;
	default:
		return OPEN_BUCKETS_COUNT / 2;
	}
}

static struct open_bucket *__try_alloc_bucket(struct bch_fs *c, struct bch_dev *ca,
					      u64 bucket,
					      enum alloc_reserve reserve,
					      struct bch_alloc_v4 *a,
					      u64 *skipped_open,
					      u64 *skipped_need_journal_commit,
					      u64 *skipped_nouse,
					      struct closure *cl)
{
	struct open_bucket *ob;

	if (unlikely(ca->buckets_nouse && test_bit(bucket, ca->buckets_nouse))) {
		(*skipped_nouse)++;
		return NULL;
	}

	if (bch2_bucket_is_open(c, ca->dev_idx, bucket)) {
		(*skipped_open)++;
		return NULL;
	}

	if (bch2_bucket_needs_journal_commit(&c->buckets_waiting_for_journal,
			c->journal.flushed_seq_ondisk, ca->dev_idx, bucket)) {
		(*skipped_need_journal_commit)++;
		return NULL;
	}

	spin_lock(&c->freelist_lock);

	if (unlikely(c->open_buckets_nr_free <= open_buckets_reserved(reserve))) {
		if (cl)
			closure_wait(&c->open_buckets_wait, cl);

		if (!c->blocked_allocate_open_bucket)
			c->blocked_allocate_open_bucket = local_clock();

		spin_unlock(&c->freelist_lock);
		return ERR_PTR(-OPEN_BUCKETS_EMPTY);
	}

	/* Recheck under lock: */
	if (bch2_bucket_is_open(c, ca->dev_idx, bucket)) {
		spin_unlock(&c->freelist_lock);
		(*skipped_open)++;
		return NULL;
	}

	ob = bch2_open_bucket_alloc(c);

	spin_lock(&ob->lock);

	ob->valid	= true;
	ob->sectors_free = ca->mi.bucket_size;
	ob->alloc_reserve = reserve;
	ob->dev		= ca->dev_idx;
	ob->gen		= a->gen;
	ob->bucket	= bucket;
	spin_unlock(&ob->lock);

	ca->nr_open_buckets++;
	bch2_open_bucket_hash_add(c, ob);

	if (c->blocked_allocate_open_bucket) {
		bch2_time_stats_update(
			&c->times[BCH_TIME_blocked_allocate_open_bucket],
			c->blocked_allocate_open_bucket);
		c->blocked_allocate_open_bucket = 0;
	}

	if (c->blocked_allocate) {
		bch2_time_stats_update(
			&c->times[BCH_TIME_blocked_allocate],
			c->blocked_allocate);
		c->blocked_allocate = 0;
	}

	spin_unlock(&c->freelist_lock);
	return ob;
}

static struct open_bucket *try_alloc_bucket(struct btree_trans *trans, struct bch_dev *ca,
					    enum alloc_reserve reserve, u64 free_entry,
					    u64 *skipped_open,
					    u64 *skipped_need_journal_commit,
					    u64 *skipped_nouse,
					    struct bkey_s_c freespace_k,
					    struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter = { NULL };
	struct bkey_s_c k;
	struct open_bucket *ob;
	struct bch_alloc_v4 a;
	u64 b = free_entry & ~(~0ULL << 56);
	unsigned genbits = free_entry >> 56;
	struct printbuf buf = PRINTBUF;
	int ret;

	if (b < ca->mi.first_bucket || b >= ca->mi.nbuckets) {
		prt_printf(&buf, "freespace btree has bucket outside allowed range %u-%llu\n"
		       "  freespace key ",
			ca->mi.first_bucket, ca->mi.nbuckets);
		bch2_bkey_val_to_text(&buf, c, freespace_k);
		bch2_trans_inconsistent(trans, "%s", buf.buf);
		ob = ERR_PTR(-EIO);
		goto err;
	}

	bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc, POS(ca->dev_idx, b), BTREE_ITER_CACHED);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret) {
		ob = ERR_PTR(ret);
		goto err;
	}

	bch2_alloc_to_v4(k, &a);

	if (genbits != (alloc_freespace_genbits(a) >> 56)) {
		prt_printf(&buf, "bucket in freespace btree with wrong genbits (got %u should be %llu)\n"
		       "  freespace key ",
		       genbits, alloc_freespace_genbits(a) >> 56);
		bch2_bkey_val_to_text(&buf, c, freespace_k);
		prt_printf(&buf, "\n  ");
		bch2_bkey_val_to_text(&buf, c, k);
		bch2_trans_inconsistent(trans, "%s", buf.buf);
		ob = ERR_PTR(-EIO);
		goto err;

	}

	if (a.data_type != BCH_DATA_free) {
		prt_printf(&buf, "non free bucket in freespace btree\n"
		       "  freespace key ");
		bch2_bkey_val_to_text(&buf, c, freespace_k);
		prt_printf(&buf, "\n  ");
		bch2_bkey_val_to_text(&buf, c, k);
		bch2_trans_inconsistent(trans, "%s", buf.buf);
		ob = ERR_PTR(-EIO);
		goto err;
	}

	ob = __try_alloc_bucket(c, ca, b, reserve, &a,
				skipped_open,
				skipped_need_journal_commit,
				skipped_nouse,
				cl);
	if (!ob)
		iter.path->preserve = false;
err:
	bch2_trans_iter_exit(trans, &iter);
	printbuf_exit(&buf);
	return ob;
}

static struct open_bucket *try_alloc_partial_bucket(struct bch_fs *c, struct bch_dev *ca,
						    enum alloc_reserve reserve)
{
	struct open_bucket *ob;
	int i;

	spin_lock(&c->freelist_lock);

	for (i = ca->open_buckets_partial_nr - 1; i >= 0; --i) {
		ob = c->open_buckets + ca->open_buckets_partial[i];

		if (reserve <= ob->alloc_reserve) {
			array_remove_item(ca->open_buckets_partial,
					  ca->open_buckets_partial_nr,
					  i);
			ob->on_partial_list = false;
			ob->alloc_reserve = reserve;
			spin_unlock(&c->freelist_lock);
			return ob;
		}
	}

	spin_unlock(&c->freelist_lock);
	return NULL;
}

/*
 * This path is for before the freespace btree is initialized:
 *
 * If ca->new_fs_bucket_idx is nonzero, we haven't yet marked superblock &
 * journal buckets - journal buckets will be < ca->new_fs_bucket_idx
 */
static noinline struct open_bucket *
bch2_bucket_alloc_early(struct btree_trans *trans,
			struct bch_dev *ca,
			enum alloc_reserve reserve,
			u64 *buckets_seen,
			u64 *skipped_open,
			u64 *skipped_need_journal_commit,
			u64 *skipped_nouse,
			struct closure *cl)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct open_bucket *ob = NULL;
	u64 alloc_start = max_t(u64, ca->mi.first_bucket, ca->new_fs_bucket_idx);
	u64 alloc_cursor = max(alloc_start, READ_ONCE(ca->alloc_cursor));
	int ret;
again:
	for_each_btree_key(trans, iter, BTREE_ID_alloc, POS(ca->dev_idx, alloc_cursor),
			   BTREE_ITER_SLOTS, k, ret) {
		struct bch_alloc_v4 a;

		if (bkey_cmp(k.k->p, POS(ca->dev_idx, ca->mi.nbuckets)) >= 0)
			break;

		if (ca->new_fs_bucket_idx &&
		    is_superblock_bucket(ca, k.k->p.offset))
			continue;

		bch2_alloc_to_v4(k, &a);

		if (a.data_type != BCH_DATA_free)
			continue;

		(*buckets_seen)++;

		ob = __try_alloc_bucket(trans->c, ca, k.k->p.offset, reserve, &a,
					skipped_open,
					skipped_need_journal_commit,
					skipped_nouse,
					cl);
		if (ob)
			break;
	}
	bch2_trans_iter_exit(trans, &iter);

	ca->alloc_cursor = alloc_cursor;

	if (!ob && alloc_cursor > alloc_start) {
		alloc_cursor = alloc_start;
		goto again;
	}

	return ob ?: ERR_PTR(ret ?: -FREELIST_EMPTY);
}

static struct open_bucket *bch2_bucket_alloc_freelist(struct btree_trans *trans,
						   struct bch_dev *ca,
						   enum alloc_reserve reserve,
						   u64 *buckets_seen,
						   u64 *skipped_open,
						   u64 *skipped_need_journal_commit,
						   u64 *skipped_nouse,
						   struct closure *cl)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct open_bucket *ob = NULL;
	u64 alloc_start = max_t(u64, ca->mi.first_bucket, READ_ONCE(ca->alloc_cursor));
	u64 alloc_cursor = alloc_start;
	int ret;

	BUG_ON(ca->new_fs_bucket_idx);
again:
	for_each_btree_key_norestart(trans, iter, BTREE_ID_freespace,
				     POS(ca->dev_idx, alloc_cursor), 0, k, ret) {
		if (k.k->p.inode != ca->dev_idx)
			break;

		for (alloc_cursor = max(alloc_cursor, bkey_start_offset(k.k));
		     alloc_cursor < k.k->p.offset;
		     alloc_cursor++) {
			if (btree_trans_too_many_iters(trans)) {
				ob = ERR_PTR(-EINTR);
				break;
			}

			(*buckets_seen)++;

			ob = try_alloc_bucket(trans, ca, reserve,
					      alloc_cursor,
					      skipped_open,
					      skipped_need_journal_commit,
					      skipped_nouse,
					      k, cl);
			if (ob) {
				iter.path->preserve = false;
				break;
			}
		}
		if (ob)
			break;
	}
	bch2_trans_iter_exit(trans, &iter);

	ca->alloc_cursor = alloc_cursor;

	if (!ob && ret)
		ob = ERR_PTR(ret);

	if (!ob && alloc_start > ca->mi.first_bucket) {
		alloc_cursor = alloc_start = ca->mi.first_bucket;
		goto again;
	}

	return ob;
}

/**
 * bch_bucket_alloc - allocate a single bucket from a specific device
 *
 * Returns index of bucket on success, 0 on failure
 * */
static struct open_bucket *bch2_bucket_alloc_trans(struct btree_trans *trans,
				      struct bch_dev *ca,
				      enum alloc_reserve reserve,
				      bool may_alloc_partial,
				      struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob = NULL;
	struct bch_dev_usage usage;
	u64 avail;
	u64 buckets_seen = 0;
	u64 skipped_open = 0;
	u64 skipped_need_journal_commit = 0;
	u64 skipped_nouse = 0;
	bool waiting = false;
again:
	usage = bch2_dev_usage_read(ca);
	avail = dev_buckets_free(ca, usage, reserve);

	if (usage.d[BCH_DATA_need_discard].buckets > avail)
		bch2_do_discards(c);

	if (usage.d[BCH_DATA_need_gc_gens].buckets > avail)
		bch2_do_gc_gens(c);

	if (should_invalidate_buckets(ca, usage))
		bch2_do_invalidates(c);

	if (!avail) {
		if (cl && !waiting) {
			closure_wait(&c->freelist_wait, cl);
			waiting = true;
			goto again;
		}

		if (!c->blocked_allocate)
			c->blocked_allocate = local_clock();

		ob = ERR_PTR(-FREELIST_EMPTY);
		goto err;
	}

	if (waiting)
		closure_wake_up(&c->freelist_wait);

	if (may_alloc_partial) {
		ob = try_alloc_partial_bucket(c, ca, reserve);
		if (ob)
			return ob;
	}

	ob = likely(ca->mi.freespace_initialized)
		? bch2_bucket_alloc_freelist(trans, ca, reserve,
					&buckets_seen,
					&skipped_open,
					&skipped_need_journal_commit,
					&skipped_nouse,
					cl)
		: bch2_bucket_alloc_early(trans, ca, reserve,
					&buckets_seen,
					&skipped_open,
					&skipped_need_journal_commit,
					&skipped_nouse,
					cl);

	if (skipped_need_journal_commit * 2 > avail)
		bch2_journal_flush_async(&c->journal, NULL);
err:
	if (!ob)
		ob = ERR_PTR(-FREELIST_EMPTY);

	if (!IS_ERR(ob)) {
		trace_bucket_alloc(ca, bch2_alloc_reserves[reserve],
				   usage.d[BCH_DATA_free].buckets,
				   avail,
				   bch2_copygc_wait_amount(c),
				   c->copygc_wait - atomic64_read(&c->io_clock[WRITE].now),
				   buckets_seen,
				   skipped_open,
				   skipped_need_journal_commit,
				   skipped_nouse,
				   cl == NULL, PTR_ERR_OR_ZERO(ob));
	} else {
		trace_bucket_alloc_fail(ca, bch2_alloc_reserves[reserve],
				   usage.d[BCH_DATA_free].buckets,
				   avail,
				   bch2_copygc_wait_amount(c),
				   c->copygc_wait - atomic64_read(&c->io_clock[WRITE].now),
				   buckets_seen,
				   skipped_open,
				   skipped_need_journal_commit,
				   skipped_nouse,
				   cl == NULL, PTR_ERR_OR_ZERO(ob));
		atomic_long_inc(&c->bucket_alloc_fail);
	}

	return ob;
}

struct open_bucket *bch2_bucket_alloc(struct bch_fs *c, struct bch_dev *ca,
				      enum alloc_reserve reserve,
				      bool may_alloc_partial,
				      struct closure *cl)
{
	struct open_bucket *ob;

	bch2_trans_do(c, NULL, NULL, 0,
		      PTR_ERR_OR_ZERO(ob = bch2_bucket_alloc_trans(&trans, ca, reserve,
								   may_alloc_partial, cl)));
	return ob;
}

static int __dev_stripe_cmp(struct dev_stripe_state *stripe,
			    unsigned l, unsigned r)
{
	return ((stripe->next_alloc[l] > stripe->next_alloc[r]) -
		(stripe->next_alloc[l] < stripe->next_alloc[r]));
}

#define dev_stripe_cmp(l, r) __dev_stripe_cmp(stripe, l, r)

struct dev_alloc_list bch2_dev_alloc_list(struct bch_fs *c,
					  struct dev_stripe_state *stripe,
					  struct bch_devs_mask *devs)
{
	struct dev_alloc_list ret = { .nr = 0 };
	unsigned i;

	for_each_set_bit(i, devs->d, BCH_SB_MEMBERS_MAX)
		ret.devs[ret.nr++] = i;

	bubble_sort(ret.devs, ret.nr, dev_stripe_cmp);
	return ret;
}

void bch2_dev_stripe_increment(struct bch_dev *ca,
			       struct dev_stripe_state *stripe)
{
	u64 *v = stripe->next_alloc + ca->dev_idx;
	u64 free_space = dev_buckets_available(ca, RESERVE_none);
	u64 free_space_inv = free_space
		? div64_u64(1ULL << 48, free_space)
		: 1ULL << 48;
	u64 scale = *v / 4;

	if (*v + free_space_inv >= *v)
		*v += free_space_inv;
	else
		*v = U64_MAX;

	for (v = stripe->next_alloc;
	     v < stripe->next_alloc + ARRAY_SIZE(stripe->next_alloc); v++)
		*v = *v < scale ? 0 : *v - scale;
}

#define BUCKET_MAY_ALLOC_PARTIAL	(1 << 0)
#define BUCKET_ALLOC_USE_DURABILITY	(1 << 1)

static void add_new_bucket(struct bch_fs *c,
			   struct open_buckets *ptrs,
			   struct bch_devs_mask *devs_may_alloc,
			   unsigned *nr_effective,
			   bool *have_cache,
			   unsigned flags,
			   struct open_bucket *ob)
{
	unsigned durability =
		bch_dev_bkey_exists(c, ob->dev)->mi.durability;

	__clear_bit(ob->dev, devs_may_alloc->d);
	*nr_effective	+= (flags & BUCKET_ALLOC_USE_DURABILITY)
		? durability : 1;
	*have_cache	|= !durability;

	ob_push(c, ptrs, ob);
}

static int bch2_bucket_alloc_set_trans(struct btree_trans *trans,
		      struct open_buckets *ptrs,
		      struct dev_stripe_state *stripe,
		      struct bch_devs_mask *devs_may_alloc,
		      unsigned nr_replicas,
		      unsigned *nr_effective,
		      bool *have_cache,
		      enum alloc_reserve reserve,
		      unsigned flags,
		      struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct dev_alloc_list devs_sorted =
		bch2_dev_alloc_list(c, stripe, devs_may_alloc);
	unsigned dev;
	struct bch_dev *ca;
	int ret = 0;
	unsigned i;

	BUG_ON(*nr_effective >= nr_replicas);

	for (i = 0; i < devs_sorted.nr; i++) {
		struct open_bucket *ob;

		dev = devs_sorted.devs[i];

		rcu_read_lock();
		ca = rcu_dereference(c->devs[dev]);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca)
			continue;

		if (!ca->mi.durability && *have_cache) {
			percpu_ref_put(&ca->ref);
			continue;
		}

		ob = bch2_bucket_alloc_trans(trans, ca, reserve,
				flags & BUCKET_MAY_ALLOC_PARTIAL, cl);
		if (!IS_ERR(ob))
			bch2_dev_stripe_increment(ca, stripe);
		percpu_ref_put(&ca->ref);

		ret = PTR_ERR_OR_ZERO(ob);
		if (ret) {
			if (ret == -EINTR || cl)
				break;
			continue;
		}

		add_new_bucket(c, ptrs, devs_may_alloc,
			       nr_effective, have_cache, flags, ob);

		if (*nr_effective >= nr_replicas)
			break;
	}

	if (*nr_effective >= nr_replicas)
		ret = 0;
	else if (!ret)
		ret = -INSUFFICIENT_DEVICES;

	return ret;
}

int bch2_bucket_alloc_set(struct bch_fs *c,
		      struct open_buckets *ptrs,
		      struct dev_stripe_state *stripe,
		      struct bch_devs_mask *devs_may_alloc,
		      unsigned nr_replicas,
		      unsigned *nr_effective,
		      bool *have_cache,
		      enum alloc_reserve reserve,
		      unsigned flags,
		      struct closure *cl)
{
	return bch2_trans_do(c, NULL, NULL, 0,
		      bch2_bucket_alloc_set_trans(&trans, ptrs, stripe,
					      devs_may_alloc, nr_replicas,
					      nr_effective, have_cache, reserve,
					      flags, cl));
}

/* Allocate from stripes: */

/*
 * if we can't allocate a new stripe because there are already too many
 * partially filled stripes, force allocating from an existing stripe even when
 * it's to a device we don't want:
 */

static int bucket_alloc_from_stripe(struct bch_fs *c,
			 struct open_buckets *ptrs,
			 struct write_point *wp,
			 struct bch_devs_mask *devs_may_alloc,
			 u16 target,
			 unsigned erasure_code,
			 unsigned nr_replicas,
			 unsigned *nr_effective,
			 bool *have_cache,
			 unsigned flags,
			 struct closure *cl)
{
	struct dev_alloc_list devs_sorted;
	struct ec_stripe_head *h;
	struct open_bucket *ob;
	struct bch_dev *ca;
	unsigned i, ec_idx;

	if (!erasure_code)
		return 0;

	if (nr_replicas < 2)
		return 0;

	if (ec_open_bucket(c, ptrs))
		return 0;

	h = bch2_ec_stripe_head_get(c, target, 0, nr_replicas - 1,
				    wp == &c->copygc_write_point,
				    cl);
	if (IS_ERR(h))
		return -PTR_ERR(h);
	if (!h)
		return 0;

	devs_sorted = bch2_dev_alloc_list(c, &wp->stripe, devs_may_alloc);

	for (i = 0; i < devs_sorted.nr; i++)
		for (ec_idx = 0; ec_idx < h->s->nr_data; ec_idx++) {
			if (!h->s->blocks[ec_idx])
				continue;

			ob = c->open_buckets + h->s->blocks[ec_idx];
			if (ob->dev == devs_sorted.devs[i] &&
			    !test_and_set_bit(ec_idx, h->s->blocks_allocated))
				goto got_bucket;
		}
	goto out_put_head;
got_bucket:
	ca = bch_dev_bkey_exists(c, ob->dev);

	ob->ec_idx	= ec_idx;
	ob->ec		= h->s;

	add_new_bucket(c, ptrs, devs_may_alloc,
		       nr_effective, have_cache, flags, ob);
	atomic_inc(&h->s->pin);
out_put_head:
	bch2_ec_stripe_head_put(c, h);
	return 0;
}

/* Sector allocator */

static void get_buckets_from_writepoint(struct bch_fs *c,
					struct open_buckets *ptrs,
					struct write_point *wp,
					struct bch_devs_mask *devs_may_alloc,
					unsigned nr_replicas,
					unsigned *nr_effective,
					bool *have_cache,
					unsigned flags,
					bool need_ec)
{
	struct open_buckets ptrs_skip = { .nr = 0 };
	struct open_bucket *ob;
	unsigned i;

	open_bucket_for_each(c, &wp->ptrs, ob, i) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ob->dev);

		if (*nr_effective < nr_replicas &&
		    test_bit(ob->dev, devs_may_alloc->d) &&
		    (ca->mi.durability ||
		     (wp->data_type == BCH_DATA_user && !*have_cache)) &&
		    (ob->ec || !need_ec)) {
			add_new_bucket(c, ptrs, devs_may_alloc,
				       nr_effective, have_cache,
				       flags, ob);
		} else {
			ob_push(c, &ptrs_skip, ob);
		}
	}
	wp->ptrs = ptrs_skip;
}

static int open_bucket_add_buckets(struct btree_trans *trans,
			struct open_buckets *ptrs,
			struct write_point *wp,
			struct bch_devs_list *devs_have,
			u16 target,
			unsigned erasure_code,
			unsigned nr_replicas,
			unsigned *nr_effective,
			bool *have_cache,
			enum alloc_reserve reserve,
			unsigned flags,
			struct closure *_cl)
{
	struct bch_fs *c = trans->c;
	struct bch_devs_mask devs;
	struct open_bucket *ob;
	struct closure *cl = NULL;
	int ret;
	unsigned i;

	rcu_read_lock();
	devs = target_rw_devs(c, wp->data_type, target);
	rcu_read_unlock();

	/* Don't allocate from devices we already have pointers to: */
	for (i = 0; i < devs_have->nr; i++)
		__clear_bit(devs_have->devs[i], devs.d);

	open_bucket_for_each(c, ptrs, ob, i)
		__clear_bit(ob->dev, devs.d);

	if (erasure_code) {
		if (!ec_open_bucket(c, ptrs)) {
			get_buckets_from_writepoint(c, ptrs, wp, &devs,
						    nr_replicas, nr_effective,
						    have_cache, flags, true);
			if (*nr_effective >= nr_replicas)
				return 0;
		}

		if (!ec_open_bucket(c, ptrs)) {
			ret = bucket_alloc_from_stripe(c, ptrs, wp, &devs,
						 target, erasure_code,
						 nr_replicas, nr_effective,
						 have_cache, flags, _cl);
			if (ret == -EINTR ||
			    ret == -FREELIST_EMPTY ||
			    ret == -OPEN_BUCKETS_EMPTY)
				return ret;
			if (*nr_effective >= nr_replicas)
				return 0;
		}
	}

	get_buckets_from_writepoint(c, ptrs, wp, &devs,
				    nr_replicas, nr_effective,
				    have_cache, flags, false);
	if (*nr_effective >= nr_replicas)
		return 0;

retry_blocking:
	/*
	 * Try nonblocking first, so that if one device is full we'll try from
	 * other devices:
	 */
	ret = bch2_bucket_alloc_set_trans(trans, ptrs, &wp->stripe, &devs,
				nr_replicas, nr_effective, have_cache,
				reserve, flags, cl);
	if (ret &&
	    ret != -EINTR &&
	    ret != -INSUFFICIENT_DEVICES &&
	    !cl && _cl) {
		cl = _cl;
		goto retry_blocking;
	}

	return ret;
}

void bch2_open_buckets_stop_dev(struct bch_fs *c, struct bch_dev *ca,
				struct open_buckets *obs)
{
	struct open_buckets ptrs = { .nr = 0 };
	struct open_bucket *ob, *ob2;
	unsigned i, j;

	open_bucket_for_each(c, obs, ob, i) {
		bool drop = !ca || ob->dev == ca->dev_idx;

		if (!drop && ob->ec) {
			mutex_lock(&ob->ec->lock);
			for (j = 0; j < ob->ec->new_stripe.key.v.nr_blocks; j++) {
				if (!ob->ec->blocks[j])
					continue;

				ob2 = c->open_buckets + ob->ec->blocks[j];
				drop |= ob2->dev == ca->dev_idx;
			}
			mutex_unlock(&ob->ec->lock);
		}

		if (drop)
			bch2_open_bucket_put(c, ob);
		else
			ob_push(c, &ptrs, ob);
	}

	*obs = ptrs;
}

void bch2_writepoint_stop(struct bch_fs *c, struct bch_dev *ca,
			  struct write_point *wp)
{
	mutex_lock(&wp->lock);
	bch2_open_buckets_stop_dev(c, ca, &wp->ptrs);
	mutex_unlock(&wp->lock);
}

static inline struct hlist_head *writepoint_hash(struct bch_fs *c,
						 unsigned long write_point)
{
	unsigned hash =
		hash_long(write_point, ilog2(ARRAY_SIZE(c->write_points_hash)));

	return &c->write_points_hash[hash];
}

static struct write_point *__writepoint_find(struct hlist_head *head,
					     unsigned long write_point)
{
	struct write_point *wp;

	rcu_read_lock();
	hlist_for_each_entry_rcu(wp, head, node)
		if (wp->write_point == write_point)
			goto out;
	wp = NULL;
out:
	rcu_read_unlock();
	return wp;
}

static inline bool too_many_writepoints(struct bch_fs *c, unsigned factor)
{
	u64 stranded	= c->write_points_nr * c->bucket_size_max;
	u64 free	= bch2_fs_usage_read_short(c).free;

	return stranded * factor > free;
}

static bool try_increase_writepoints(struct bch_fs *c)
{
	struct write_point *wp;

	if (c->write_points_nr == ARRAY_SIZE(c->write_points) ||
	    too_many_writepoints(c, 32))
		return false;

	wp = c->write_points + c->write_points_nr++;
	hlist_add_head_rcu(&wp->node, writepoint_hash(c, wp->write_point));
	return true;
}

static bool try_decrease_writepoints(struct bch_fs *c,
				     unsigned old_nr)
{
	struct write_point *wp;

	mutex_lock(&c->write_points_hash_lock);
	if (c->write_points_nr < old_nr) {
		mutex_unlock(&c->write_points_hash_lock);
		return true;
	}

	if (c->write_points_nr == 1 ||
	    !too_many_writepoints(c, 8)) {
		mutex_unlock(&c->write_points_hash_lock);
		return false;
	}

	wp = c->write_points + --c->write_points_nr;

	hlist_del_rcu(&wp->node);
	mutex_unlock(&c->write_points_hash_lock);

	bch2_writepoint_stop(c, NULL, wp);
	return true;
}

static void bch2_trans_mutex_lock(struct btree_trans *trans,
				  struct mutex *lock)
{
	if (!mutex_trylock(lock)) {
		bch2_trans_unlock(trans);
		mutex_lock(lock);
	}
}

static struct write_point *writepoint_find(struct btree_trans *trans,
					   unsigned long write_point)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp, *oldest;
	struct hlist_head *head;

	if (!(write_point & 1UL)) {
		wp = (struct write_point *) write_point;
		bch2_trans_mutex_lock(trans, &wp->lock);
		return wp;
	}

	head = writepoint_hash(c, write_point);
restart_find:
	wp = __writepoint_find(head, write_point);
	if (wp) {
lock_wp:
		bch2_trans_mutex_lock(trans, &wp->lock);
		if (wp->write_point == write_point)
			goto out;
		mutex_unlock(&wp->lock);
		goto restart_find;
	}
restart_find_oldest:
	oldest = NULL;
	for (wp = c->write_points;
	     wp < c->write_points + c->write_points_nr; wp++)
		if (!oldest || time_before64(wp->last_used, oldest->last_used))
			oldest = wp;

	bch2_trans_mutex_lock(trans, &oldest->lock);
	bch2_trans_mutex_lock(trans, &c->write_points_hash_lock);
	if (oldest >= c->write_points + c->write_points_nr ||
	    try_increase_writepoints(c)) {
		mutex_unlock(&c->write_points_hash_lock);
		mutex_unlock(&oldest->lock);
		goto restart_find_oldest;
	}

	wp = __writepoint_find(head, write_point);
	if (wp && wp != oldest) {
		mutex_unlock(&c->write_points_hash_lock);
		mutex_unlock(&oldest->lock);
		goto lock_wp;
	}

	wp = oldest;
	hlist_del_rcu(&wp->node);
	wp->write_point = write_point;
	hlist_add_head_rcu(&wp->node, head);
	mutex_unlock(&c->write_points_hash_lock);
out:
	wp->last_used = sched_clock();
	return wp;
}

/*
 * Get us an open_bucket we can allocate from, return with it locked:
 */
int bch2_alloc_sectors_start_trans(struct btree_trans *trans,
			     unsigned target,
			     unsigned erasure_code,
			     struct write_point_specifier write_point,
			     struct bch_devs_list *devs_have,
			     unsigned nr_replicas,
			     unsigned nr_replicas_required,
			     enum alloc_reserve reserve,
			     unsigned flags,
			     struct closure *cl,
			     struct write_point **wp_ret)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp;
	struct open_bucket *ob;
	struct open_buckets ptrs;
	unsigned nr_effective, write_points_nr;
	unsigned ob_flags = 0;
	bool have_cache;
	int ret;
	int i;

	if (!(flags & BCH_WRITE_ONLY_SPECIFIED_DEVS))
		ob_flags |= BUCKET_ALLOC_USE_DURABILITY;

	BUG_ON(!nr_replicas || !nr_replicas_required);
retry:
	ptrs.nr		= 0;
	nr_effective	= 0;
	write_points_nr = c->write_points_nr;
	have_cache	= false;

	*wp_ret = wp = writepoint_find(trans, write_point.v);

	if (wp->data_type == BCH_DATA_user)
		ob_flags |= BUCKET_MAY_ALLOC_PARTIAL;

	/* metadata may not allocate on cache devices: */
	if (wp->data_type != BCH_DATA_user)
		have_cache = true;

	if (!target || (flags & BCH_WRITE_ONLY_SPECIFIED_DEVS)) {
		ret = open_bucket_add_buckets(trans, &ptrs, wp, devs_have,
					      target, erasure_code,
					      nr_replicas, &nr_effective,
					      &have_cache, reserve,
					      ob_flags, cl);
	} else {
		ret = open_bucket_add_buckets(trans, &ptrs, wp, devs_have,
					      target, erasure_code,
					      nr_replicas, &nr_effective,
					      &have_cache, reserve,
					      ob_flags, NULL);
		if (!ret || ret == -EINTR)
			goto alloc_done;

		ret = open_bucket_add_buckets(trans, &ptrs, wp, devs_have,
					      0, erasure_code,
					      nr_replicas, &nr_effective,
					      &have_cache, reserve,
					      ob_flags, cl);
	}
alloc_done:
	BUG_ON(!ret && nr_effective < nr_replicas);

	if (erasure_code && !ec_open_bucket(c, &ptrs))
		pr_debug("failed to get ec bucket: ret %u", ret);

	if (ret == -INSUFFICIENT_DEVICES &&
	    nr_effective >= nr_replicas_required)
		ret = 0;

	if (ret)
		goto err;

	/* Free buckets we didn't use: */
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		open_bucket_free_unused(c, wp, ob);

	wp->ptrs = ptrs;

	wp->sectors_free = UINT_MAX;

	open_bucket_for_each(c, &wp->ptrs, ob, i)
		wp->sectors_free = min(wp->sectors_free, ob->sectors_free);

	BUG_ON(!wp->sectors_free || wp->sectors_free == UINT_MAX);

	return 0;
err:
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		if (ptrs.nr < ARRAY_SIZE(ptrs.v))
			ob_push(c, &ptrs, ob);
		else
			open_bucket_free_unused(c, wp, ob);
	wp->ptrs = ptrs;

	mutex_unlock(&wp->lock);

	if (ret == -FREELIST_EMPTY &&
	    try_decrease_writepoints(c, write_points_nr))
		goto retry;

	switch (ret) {
	case -OPEN_BUCKETS_EMPTY:
	case -FREELIST_EMPTY:
		return cl ? -EAGAIN : -ENOSPC;
	case -INSUFFICIENT_DEVICES:
		return -EROFS;
	default:
		return ret;
	}
}

int bch2_alloc_sectors_start(struct bch_fs *c,
			     unsigned target,
			     unsigned erasure_code,
			     struct write_point_specifier write_point,
			     struct bch_devs_list *devs_have,
			     unsigned nr_replicas,
			     unsigned nr_replicas_required,
			     enum alloc_reserve reserve,
			     unsigned flags,
			     struct closure *cl,
			     struct write_point **wp_ret)
{
	return bch2_trans_do(c, NULL, NULL, 0,
			     bch2_alloc_sectors_start_trans(&trans, target,
							    erasure_code,
							    write_point,
							    devs_have,
							    nr_replicas,
							    nr_replicas_required,
							    reserve,
							    flags, cl, wp_ret));
}

struct bch_extent_ptr bch2_ob_ptr(struct bch_fs *c, struct open_bucket *ob)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, ob->dev);

	return (struct bch_extent_ptr) {
		.type	= 1 << BCH_EXTENT_ENTRY_ptr,
		.gen	= ob->gen,
		.dev	= ob->dev,
		.offset	= bucket_to_sector(ca, ob->bucket) +
			ca->mi.bucket_size -
			ob->sectors_free,
	};
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch2_alloc_sectors_append_ptrs(struct bch_fs *c, struct write_point *wp,
				    struct bkey_i *k, unsigned sectors,
				    bool cached)
{
	struct open_bucket *ob;
	unsigned i;

	BUG_ON(sectors > wp->sectors_free);
	wp->sectors_free	-= sectors;
	wp->sectors_allocated	+= sectors;

	open_bucket_for_each(c, &wp->ptrs, ob, i) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ob->dev);
		struct bch_extent_ptr ptr = bch2_ob_ptr(c, ob);

		ptr.cached = cached ||
			(!ca->mi.durability &&
			 wp->data_type == BCH_DATA_user);

		bch2_bkey_append_ptr(k, ptr);

		BUG_ON(sectors > ob->sectors_free);
		ob->sectors_free -= sectors;
	}
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch2_alloc_sectors_done(struct bch_fs *c, struct write_point *wp)
{
	struct open_buckets ptrs = { .nr = 0 }, keep = { .nr = 0 };
	struct open_bucket *ob;
	unsigned i;

	open_bucket_for_each(c, &wp->ptrs, ob, i)
		ob_push(c, !ob->sectors_free ? &ptrs : &keep, ob);
	wp->ptrs = keep;

	mutex_unlock(&wp->lock);

	bch2_open_buckets_put(c, &ptrs);
}

static inline void writepoint_init(struct write_point *wp,
				   enum bch_data_type type)
{
	mutex_init(&wp->lock);
	wp->data_type = type;

	INIT_WORK(&wp->index_update_work, bch2_write_point_do_index_updates);
	INIT_LIST_HEAD(&wp->writes);
	spin_lock_init(&wp->writes_lock);
}

void bch2_fs_allocator_foreground_init(struct bch_fs *c)
{
	struct open_bucket *ob;
	struct write_point *wp;

	mutex_init(&c->write_points_hash_lock);
	c->write_points_nr = ARRAY_SIZE(c->write_points);

	/* open bucket 0 is a sentinal NULL: */
	spin_lock_init(&c->open_buckets[0].lock);

	for (ob = c->open_buckets + 1;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets); ob++) {
		spin_lock_init(&ob->lock);
		c->open_buckets_nr_free++;

		ob->freelist = c->open_buckets_freelist;
		c->open_buckets_freelist = ob - c->open_buckets;
	}

	writepoint_init(&c->btree_write_point,		BCH_DATA_btree);
	writepoint_init(&c->rebalance_write_point,	BCH_DATA_user);
	writepoint_init(&c->copygc_write_point,		BCH_DATA_user);

	for (wp = c->write_points;
	     wp < c->write_points + c->write_points_nr; wp++) {
		writepoint_init(wp, BCH_DATA_user);

		wp->last_used	= sched_clock();
		wp->write_point	= (unsigned long) wp;
		hlist_add_head_rcu(&wp->node,
				   writepoint_hash(c, wp->write_point));
	}
}

void bch2_open_buckets_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct open_bucket *ob;

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++) {
		spin_lock(&ob->lock);
		if (ob->valid && !ob->on_partial_list) {
			prt_printf(out, "%zu ref %u type %s %u:%llu:%u\n",
			       ob - c->open_buckets,
			       atomic_read(&ob->pin),
			       bch2_data_types[ob->data_type],
			       ob->dev, ob->bucket, ob->gen);
		}
		spin_unlock(&ob->lock);
	}
}

static const char * const bch2_write_point_states[] = {
#define x(n)	#n,
	WRITE_POINT_STATES()
#undef x
	NULL
};

void bch2_write_points_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct write_point *wp;
	unsigned i;

	for (wp = c->write_points;
	     wp < c->write_points + ARRAY_SIZE(c->write_points);
	     wp++) {
		prt_printf(out, "%lu: ", wp->write_point);
		prt_human_readable_u64(out, wp->sectors_allocated);

		prt_printf(out, " last wrote: ");
		bch2_pr_time_units(out, sched_clock() - wp->last_used);

		for (i = 0; i < WRITE_POINT_STATE_NR; i++) {
			prt_printf(out, " %s: ", bch2_write_point_states[i]);
			bch2_pr_time_units(out, wp->time[i]);
		}

		prt_newline(out);
	}
}
