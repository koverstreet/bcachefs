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
#include "backpointers.h"
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
#include "io_write.h"
#include "journal.h"
#include "movinggc.h"
#include "nocow_locking.h"
#include "trace.h"

#include <linux/math64.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>

static void bch2_trans_mutex_lock_norelock(struct btree_trans *trans,
					   struct mutex *lock)
{
	if (!mutex_trylock(lock)) {
		bch2_trans_unlock(trans);
		mutex_lock(lock);
	}
}

const char * const bch2_watermarks[] = {
#define x(t) #t,
	BCH_WATERMARKS()
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
	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL)
		memset(ca->alloc_cursor, 0, sizeof(ca->alloc_cursor));
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
	struct bch_dev *ca = ob_dev(c, ob);

	if (ob->ec) {
		ec_stripe_new_put(c, ob->ec, STRIPE_REF_io);
		return;
	}

	spin_lock(&ob->lock);
	ob->valid = false;
	ob->data_type = 0;
	spin_unlock(&ob->lock);

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
				  unsigned dev, int err)
{
	struct open_bucket *ob;
	unsigned i;

	open_bucket_for_each(c, obs, ob, i)
		if (ob->dev == dev && ob->ec)
			bch2_ec_bucket_cancel(c, ob, err);
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

static inline bool is_superblock_bucket(struct bch_fs *c, struct bch_dev *ca, u64 b)
{
	if (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_trans_mark_dev_sbs))
		return false;

	return bch2_is_superblock_bucket(ca, b);
}

static void open_bucket_free_unused(struct bch_fs *c, struct open_bucket *ob)
{
	BUG_ON(c->open_buckets_partial_nr >=
	       ARRAY_SIZE(c->open_buckets_partial));

	spin_lock(&c->freelist_lock);
	scoped_guard(rcu)
		bch2_dev_rcu(c, ob->dev)->nr_partial_buckets++;

	ob->on_partial_list = true;
	c->open_buckets_partial[c->open_buckets_partial_nr++] =
		ob - c->open_buckets;
	spin_unlock(&c->freelist_lock);

	closure_wake_up(&c->open_buckets_wait);
	closure_wake_up(&c->freelist_wait);
}

static inline bool may_alloc_bucket(struct bch_fs *c,
				    struct alloc_request *req,
				    struct bpos bucket)
{
	if (bch2_bucket_is_open(c, bucket.inode, bucket.offset)) {
		req->counters.skipped_open++;
		return false;
	}

	u64 journal_seq_ready =
		bch2_bucket_journal_seq_ready(&c->buckets_waiting_for_journal,
					      bucket.inode, bucket.offset);
	if (journal_seq_ready > c->journal.flushed_seq_ondisk) {
		if (journal_seq_ready > c->journal.flushing_seq)
			req->counters.need_journal_commit++;
		req->counters.skipped_need_journal_commit++;
		return false;
	}

	if (bch2_bucket_nocow_is_locked(&c->nocow_locks, bucket)) {
		req->counters.skipped_nocow++;
		return false;
	}

	return true;
}

static struct open_bucket *__try_alloc_bucket(struct bch_fs *c,
					      struct alloc_request *req,
					      u64 bucket, u8 gen,
					      struct closure *cl)
{
	struct bch_dev *ca = req->ca;

	if (unlikely(is_superblock_bucket(c, ca, bucket)))
		return NULL;

	if (unlikely(ca->buckets_nouse && test_bit(bucket, ca->buckets_nouse))) {
		req->counters.skipped_nouse++;
		return NULL;
	}

	spin_lock(&c->freelist_lock);

	if (unlikely(c->open_buckets_nr_free <= bch2_open_buckets_reserved(req->watermark))) {
		if (cl)
			closure_wait(&c->open_buckets_wait, cl);

		track_event_change(&c->times[BCH_TIME_blocked_allocate_open_bucket], true);
		spin_unlock(&c->freelist_lock);
		return ERR_PTR(bch_err_throw(c, open_buckets_empty));
	}

	/* Recheck under lock: */
	if (bch2_bucket_is_open(c, ca->dev_idx, bucket)) {
		spin_unlock(&c->freelist_lock);
		req->counters.skipped_open++;
		return NULL;
	}

	struct open_bucket *ob = bch2_open_bucket_alloc(c);

	spin_lock(&ob->lock);
	ob->valid	= true;
	ob->sectors_free = ca->mi.bucket_size;
	ob->dev		= ca->dev_idx;
	ob->gen		= gen;
	ob->bucket	= bucket;
	spin_unlock(&ob->lock);

	ca->nr_open_buckets++;
	bch2_open_bucket_hash_add(c, ob);

	track_event_change(&c->times[BCH_TIME_blocked_allocate_open_bucket], false);
	track_event_change(&c->times[BCH_TIME_blocked_allocate], false);

	spin_unlock(&c->freelist_lock);
	return ob;
}

static struct open_bucket *try_alloc_bucket(struct btree_trans *trans,
					    struct alloc_request *req,
					    struct btree_iter *freespace_iter,
					    struct closure *cl)
{
	struct bch_fs *c = trans->c;
	u64 b = freespace_iter->pos.offset & ~(~0ULL << 56);

	if (!may_alloc_bucket(c, req, POS(req->ca->dev_idx, b)))
		return NULL;

	u8 gen;
	int ret = bch2_check_discard_freespace_key_async(trans, freespace_iter, &gen);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret)
		return NULL;

	return __try_alloc_bucket(c, req, b, gen, cl);
}

/*
 * This path is for before the freespace btree is initialized:
 */
static noinline struct open_bucket *
bch2_bucket_alloc_early(struct btree_trans *trans,
			struct alloc_request *req,
			struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = req->ca;
	struct btree_iter iter, citer;
	struct bkey_s_c k, ck;
	struct open_bucket *ob = NULL;
	u64 first_bucket = ca->mi.first_bucket;
	u64 *dev_alloc_cursor = &ca->alloc_cursor[req->btree_bitmap];
	u64 alloc_start = max(first_bucket, *dev_alloc_cursor);
	u64 alloc_cursor = alloc_start;
	int ret;

	/*
	 * Scan with an uncached iterator to avoid polluting the key cache. An
	 * uncached iter will return a cached key if one exists, but if not
	 * there is no other underlying protection for the associated key cache
	 * slot. To avoid racing bucket allocations, look up the cached key slot
	 * of any likely allocation candidate before attempting to proceed with
	 * the allocation. This provides proper exclusion on the associated
	 * bucket.
	 */
again:
	for_each_btree_key_norestart(trans, iter, BTREE_ID_alloc, POS(ca->dev_idx, alloc_cursor),
			   BTREE_ITER_slots, k, ret) {
		u64 bucket = k.k->p.offset;

		if (bkey_ge(k.k->p, POS(ca->dev_idx, ca->mi.nbuckets)))
			break;

		if (req->btree_bitmap != BTREE_BITMAP_ANY &&
		    req->btree_bitmap != bch2_dev_btree_bitmap_marked_sectors(ca,
				bucket_to_sector(ca, bucket), ca->mi.bucket_size)) {
			if (req->btree_bitmap == BTREE_BITMAP_YES &&
			    bucket_to_sector(ca, bucket) > 64ULL << ca->mi.btree_bitmap_shift)
				break;

			bucket = sector_to_bucket(ca,
					round_up(bucket_to_sector(ca, bucket) + 1,
						 1ULL << ca->mi.btree_bitmap_shift));
			bch2_btree_iter_set_pos(trans, &iter, POS(ca->dev_idx, bucket));
			req->counters.buckets_seen++;
			req->counters.skipped_mi_btree_bitmap++;
			continue;
		}

		struct bch_alloc_v4 a_convert;
		const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);
		if (a->data_type != BCH_DATA_free)
			continue;

		/* now check the cached key to serialize concurrent allocs of the bucket */
		ck = bch2_bkey_get_iter(trans, &citer, BTREE_ID_alloc, k.k->p, BTREE_ITER_cached);
		ret = bkey_err(ck);
		if (ret)
			break;

		a = bch2_alloc_to_v4(ck, &a_convert);
		if (a->data_type != BCH_DATA_free)
			goto next;

		req->counters.buckets_seen++;

		ob = may_alloc_bucket(c, req, k.k->p)
			? __try_alloc_bucket(c, req, k.k->p.offset, a->gen, cl)
			: NULL;
next:
		bch2_set_btree_iter_dontneed(trans, &citer);
		bch2_trans_iter_exit(trans, &citer);
		if (ob)
			break;
	}
	bch2_trans_iter_exit(trans, &iter);

	alloc_cursor = iter.pos.offset;

	if (!ob && ret)
		ob = ERR_PTR(ret);

	if (!ob && alloc_start > first_bucket) {
		alloc_cursor = alloc_start = first_bucket;
		goto again;
	}

	*dev_alloc_cursor = alloc_cursor;

	return ob;
}

static struct open_bucket *bch2_bucket_alloc_freelist(struct btree_trans *trans,
						      struct alloc_request *req,
						      struct closure *cl)
{
	struct bch_dev *ca = req->ca;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct open_bucket *ob = NULL;
	u64 *dev_alloc_cursor = &ca->alloc_cursor[req->btree_bitmap];
	u64 alloc_start = max_t(u64, ca->mi.first_bucket, READ_ONCE(*dev_alloc_cursor));
	u64 alloc_cursor = alloc_start;
	int ret;
again:
	for_each_btree_key_max_norestart(trans, iter, BTREE_ID_freespace,
					 POS(ca->dev_idx, alloc_cursor),
					 POS(ca->dev_idx, U64_MAX),
					 0, k, ret) {
		/*
		 * peek normally dosen't trim extents - they can span iter.pos,
		 * which is not what we want here:
		 */
		iter.k.size = iter.k.p.offset - iter.pos.offset;

		while (iter.k.size) {
			req->counters.buckets_seen++;

			u64 bucket = iter.pos.offset & ~(~0ULL << 56);
			if (req->btree_bitmap != BTREE_BITMAP_ANY &&
			    req->btree_bitmap != bch2_dev_btree_bitmap_marked_sectors(ca,
					bucket_to_sector(ca, bucket), ca->mi.bucket_size)) {
				if (req->btree_bitmap == BTREE_BITMAP_YES &&
				    bucket_to_sector(ca, bucket) > 64ULL << ca->mi.btree_bitmap_shift)
					goto fail;

				bucket = sector_to_bucket(ca,
						round_up(bucket_to_sector(ca, bucket + 1),
							 1ULL << ca->mi.btree_bitmap_shift));
				alloc_cursor = bucket|(iter.pos.offset & (~0ULL << 56));

				bch2_btree_iter_set_pos(trans, &iter, POS(ca->dev_idx, alloc_cursor));
				req->counters.skipped_mi_btree_bitmap++;
				goto next;
			}

			ob = try_alloc_bucket(trans, req, &iter, cl);
			if (ob) {
				if (!IS_ERR(ob))
					*dev_alloc_cursor = iter.pos.offset;
				bch2_set_btree_iter_dontneed(trans, &iter);
				break;
			}

			iter.k.size--;
			iter.pos.offset++;
		}
next:
		if (ob || ret)
			break;
	}
fail:
	bch2_trans_iter_exit(trans, &iter);

	BUG_ON(ob && ret);

	if (ret)
		ob = ERR_PTR(ret);

	if (!ob && alloc_start > ca->mi.first_bucket) {
		alloc_cursor = alloc_start = ca->mi.first_bucket;
		goto again;
	}

	return ob;
}

static noinline void trace_bucket_alloc2(struct bch_fs *c,
					 struct alloc_request *req,
					 struct closure *cl,
					 struct open_bucket *ob)
{
	struct printbuf buf = PRINTBUF;

	printbuf_tabstop_push(&buf, 24);

	prt_printf(&buf, "dev\t%s (%u)\n",	req->ca->name, req->ca->dev_idx);
	prt_printf(&buf, "watermark\t%s\n",	bch2_watermarks[req->watermark]);
	prt_printf(&buf, "data type\t%s\n",	__bch2_data_types[req->data_type]);
	prt_printf(&buf, "blocking\t%u\n",	cl != NULL);
	prt_printf(&buf, "free\t%llu\n",	req->usage.buckets[BCH_DATA_free]);
	prt_printf(&buf, "avail\t%llu\n",	dev_buckets_free(req->ca, req->usage, req->watermark));
	prt_printf(&buf, "copygc_wait\t%llu/%lli\n",
		   bch2_copygc_wait_amount(c),
		   c->copygc_wait - atomic64_read(&c->io_clock[WRITE].now));
	prt_printf(&buf, "seen\t%llu\n",	req->counters.buckets_seen);
	prt_printf(&buf, "open\t%llu\n",	req->counters.skipped_open);
	prt_printf(&buf, "need journal commit\t%llu\n", req->counters.skipped_need_journal_commit);
	prt_printf(&buf, "nocow\t%llu\n",	req->counters.skipped_nocow);
	prt_printf(&buf, "nouse\t%llu\n",	req->counters.skipped_nouse);
	prt_printf(&buf, "mi_btree_bitmap\t%llu\n", req->counters.skipped_mi_btree_bitmap);

	if (!IS_ERR(ob)) {
		prt_printf(&buf, "allocated\t%llu\n", ob->bucket);
		trace_bucket_alloc(c, buf.buf);
	} else {
		prt_printf(&buf, "err\t%s\n", bch2_err_str(PTR_ERR(ob)));
		trace_bucket_alloc_fail(c, buf.buf);
	}

	printbuf_exit(&buf);
}

/**
 * bch2_bucket_alloc_trans - allocate a single bucket from a specific device
 * @trans:	transaction object
 * @req:	state for the entire allocation
 * @cl:		if not NULL, closure to be used to wait if buckets not available
 * @nowait:	if true, do not wait for buckets to become available
 *
 * Returns:	an open_bucket on success, or an ERR_PTR() on failure.
 */
static struct open_bucket *bch2_bucket_alloc_trans(struct btree_trans *trans,
						   struct alloc_request *req,
						   struct closure *cl,
						   bool nowait)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = req->ca;
	struct open_bucket *ob = NULL;
	bool freespace = READ_ONCE(ca->mi.freespace_initialized);
	u64 avail;
	bool waiting = nowait;

	req->btree_bitmap = req->data_type == BCH_DATA_btree;
	memset(&req->counters, 0, sizeof(req->counters));
again:
	bch2_dev_usage_read_fast(ca, &req->usage);
	avail = dev_buckets_free(ca, req->usage, req->watermark);

	if (req->usage.buckets[BCH_DATA_need_discard] >
	    min(avail, ca->mi.nbuckets >> 7))
		bch2_dev_do_discards(ca);

	if (req->usage.buckets[BCH_DATA_need_gc_gens] > avail)
		bch2_gc_gens_async(c);

	if (should_invalidate_buckets(ca, req->usage))
		bch2_dev_do_invalidates(ca);

	if (!avail) {
		if (req->watermark > BCH_WATERMARK_normal &&
		    c->recovery.pass_done < BCH_RECOVERY_PASS_check_allocations)
			goto alloc;

		if (cl && !waiting) {
			closure_wait(&c->freelist_wait, cl);
			waiting = true;
			goto again;
		}

		track_event_change(&c->times[BCH_TIME_blocked_allocate], true);

		ob = ERR_PTR(bch_err_throw(c, freelist_empty));
		goto err;
	}

	if (waiting)
		closure_wake_up(&c->freelist_wait);
alloc:
	ob = likely(freespace)
		? bch2_bucket_alloc_freelist(trans, req, cl)
		: bch2_bucket_alloc_early(trans, req, cl);

	if (req->counters.need_journal_commit * 2 > avail)
		bch2_journal_flush_async(&c->journal, NULL);

	if (!ob && req->btree_bitmap != BTREE_BITMAP_ANY) {
		req->btree_bitmap = BTREE_BITMAP_ANY;
		goto alloc;
	}

	if (!ob && freespace && c->recovery.pass_done < BCH_RECOVERY_PASS_check_alloc_info) {
		freespace = false;
		goto alloc;
	}
err:
	if (!ob)
		ob = ERR_PTR(bch_err_throw(c, no_buckets_found));

	if (!IS_ERR(ob))
		ob->data_type = req->data_type;

	if (!IS_ERR(ob))
		count_event(c, bucket_alloc);
	else if (!bch2_err_matches(PTR_ERR(ob), BCH_ERR_transaction_restart))
		count_event(c, bucket_alloc_fail);

	if (!IS_ERR(ob)
	    ? trace_bucket_alloc_enabled()
	    : trace_bucket_alloc_fail_enabled())
		trace_bucket_alloc2(c, req, cl, ob);

	return ob;
}

struct open_bucket *bch2_bucket_alloc(struct bch_fs *c, struct bch_dev *ca,
				      enum bch_watermark watermark,
				      enum bch_data_type data_type,
				      struct closure *cl)
{
	struct open_bucket *ob;
	struct alloc_request req = {
		.watermark	= watermark,
		.data_type	= data_type,
		.ca		= ca,
	};

	bch2_trans_do(c,
		PTR_ERR_OR_ZERO(ob = bch2_bucket_alloc_trans(trans, &req, cl, false)));
	return ob;
}

static int __dev_stripe_cmp(struct dev_stripe_state *stripe,
			    unsigned l, unsigned r)
{
	return cmp_int(stripe->next_alloc[l], stripe->next_alloc[r]);
}

#define dev_stripe_cmp(l, r) __dev_stripe_cmp(stripe, l, r)

void bch2_dev_alloc_list(struct bch_fs *c,
			 struct dev_stripe_state *stripe,
			 struct bch_devs_mask *devs,
			 struct dev_alloc_list *ret)
{
	ret->nr = 0;

	unsigned i;
	for_each_set_bit(i, devs->d, BCH_SB_MEMBERS_MAX)
		ret->data[ret->nr++] = i;

	bubble_sort(ret->data, ret->nr, dev_stripe_cmp);
}

static const u64 stripe_clock_hand_rescale	= 1ULL << 62; /* trigger rescale at */
static const u64 stripe_clock_hand_max		= 1ULL << 56; /* max after rescale */
static const u64 stripe_clock_hand_inv		= 1ULL << 52; /* max increment, if a device is empty */

static noinline void bch2_stripe_state_rescale(struct dev_stripe_state *stripe)
{
	/*
	 * Avoid underflowing clock hands if at all possible, if clock hands go
	 * to 0 then we lose information - clock hands can be in a wide range if
	 * we have devices we rarely try to allocate from, if we generally
	 * allocate from a specified target but only sometimes have to fall back
	 * to the whole filesystem.
	 */
	u64 scale_max = U64_MAX;	/* maximum we can subtract without underflow */
	u64 scale_min = 0;		/* minumum we must subtract to avoid overflow */

	for (u64 *v = stripe->next_alloc;
	     v < stripe->next_alloc + ARRAY_SIZE(stripe->next_alloc); v++) {
		if (*v)
			scale_max = min(scale_max, *v);
		if (*v > stripe_clock_hand_max)
			scale_min = max(scale_min, *v - stripe_clock_hand_max);
	}

	u64 scale = max(scale_min, scale_max);

	for (u64 *v = stripe->next_alloc;
	     v < stripe->next_alloc + ARRAY_SIZE(stripe->next_alloc); v++)
		*v = *v < scale ? 0 : *v - scale;
}

static inline void bch2_dev_stripe_increment_inlined(struct bch_dev *ca,
			       struct dev_stripe_state *stripe,
			       struct bch_dev_usage *usage)
{
	/*
	 * Stripe state has a per device clock hand: we allocate from the device
	 * with the smallest clock hand.
	 *
	 * When we allocate, we don't do a simple increment; we add the inverse
	 * of the device's free space. This results in round robin behavior that
	 * biases in favor of the device(s) with more free space.
	 */

	u64 *v = stripe->next_alloc + ca->dev_idx;
	u64 free_space = __dev_buckets_available(ca, *usage, BCH_WATERMARK_normal);
	u64 free_space_inv = free_space
		? div64_u64(stripe_clock_hand_inv, free_space)
		: stripe_clock_hand_inv;

	/* Saturating add, avoid overflow: */
	u64 sum = *v + free_space_inv;
	*v = sum >= *v ? sum : U64_MAX;

	if (unlikely(*v > stripe_clock_hand_rescale))
		bch2_stripe_state_rescale(stripe);
}

void bch2_dev_stripe_increment(struct bch_dev *ca,
			       struct dev_stripe_state *stripe)
{
	struct bch_dev_usage usage;

	bch2_dev_usage_read_fast(ca, &usage);
	bch2_dev_stripe_increment_inlined(ca, stripe, &usage);
}

static int add_new_bucket(struct bch_fs *c,
			  struct alloc_request *req,
			  struct open_bucket *ob)
{
	unsigned durability = ob_dev(c, ob)->mi.durability;

	BUG_ON(req->nr_effective >= req->nr_replicas);

	__clear_bit(ob->dev, req->devs_may_alloc.d);
	req->nr_effective	+= durability;
	req->have_cache	|= !durability;

	ob_push(c, &req->ptrs, ob);

	if (req->nr_effective >= req->nr_replicas)
		return 1;
	if (ob->ec)
		return 1;
	return 0;
}

inline int bch2_bucket_alloc_set_trans(struct btree_trans *trans,
				       struct alloc_request *req,
				       struct dev_stripe_state *stripe,
				       struct closure *cl)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	BUG_ON(req->nr_effective >= req->nr_replicas);

	bch2_dev_alloc_list(c, stripe, &req->devs_may_alloc, &req->devs_sorted);

	darray_for_each(req->devs_sorted, i) {
		req->ca = bch2_dev_tryget_noerror(c, *i);
		if (!req->ca)
			continue;

		if (!req->ca->mi.durability && req->have_cache) {
			bch2_dev_put(req->ca);
			continue;
		}

		struct open_bucket *ob = bch2_bucket_alloc_trans(trans, req, cl,
							req->flags & BCH_WRITE_alloc_nowait);
		if (!IS_ERR(ob))
			bch2_dev_stripe_increment_inlined(req->ca, stripe, &req->usage);
		bch2_dev_put(req->ca);

		if (IS_ERR(ob)) {
			ret = PTR_ERR(ob);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart) || cl)
				break;
			continue;
		}

		ret = add_new_bucket(c, req, ob);
		if (ret)
			break;
	}

	if (ret == 1)
		return 0;
	if (ret)
		return ret;
	return bch_err_throw(c, insufficient_devices);
}

/* Allocate from stripes: */

/*
 * if we can't allocate a new stripe because there are already too many
 * partially filled stripes, force allocating from an existing stripe even when
 * it's to a device we don't want:
 */

static int bucket_alloc_from_stripe(struct btree_trans *trans,
				    struct alloc_request *req,
				    struct closure *cl)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	if (req->nr_replicas < 2)
		return 0;

	if (ec_open_bucket(c, &req->ptrs))
		return 0;

	struct ec_stripe_head *h =
		bch2_ec_stripe_head_get(trans, req, 0, cl);
	if (IS_ERR(h))
		return PTR_ERR(h);
	if (!h)
		return 0;

	bch2_dev_alloc_list(c, &req->wp->stripe, &req->devs_may_alloc, &req->devs_sorted);

	darray_for_each(req->devs_sorted, i)
		for (unsigned ec_idx = 0; ec_idx < h->s->nr_data; ec_idx++) {
			if (!h->s->blocks[ec_idx])
				continue;

			struct open_bucket *ob = c->open_buckets + h->s->blocks[ec_idx];
			if (ob->dev == *i && !test_and_set_bit(ec_idx, h->s->blocks_allocated)) {
				ob->ec_idx	= ec_idx;
				ob->ec		= h->s;
				ec_stripe_new_get(h->s, STRIPE_REF_io);

				ret = add_new_bucket(c, req, ob);
				goto out;
			}
		}
out:
	bch2_ec_stripe_head_put(c, h);
	return ret;
}

/* Sector allocator */

static bool want_bucket(struct bch_fs *c,
			struct alloc_request *req,
			struct open_bucket *ob)
{
	struct bch_dev *ca = ob_dev(c, ob);

	if (!test_bit(ob->dev, req->devs_may_alloc.d))
		return false;

	if (ob->data_type != req->wp->data_type)
		return false;

	if (!ca->mi.durability &&
	    (req->wp->data_type == BCH_DATA_btree || req->ec || req->have_cache))
		return false;

	if (req->ec != (ob->ec != NULL))
		return false;

	return true;
}

static int bucket_alloc_set_writepoint(struct bch_fs *c,
				       struct alloc_request *req)
{
	struct open_bucket *ob;
	unsigned i;
	int ret = 0;

	req->scratch_ptrs.nr = 0;

	open_bucket_for_each(c, &req->wp->ptrs, ob, i) {
		if (!ret && want_bucket(c, req, ob))
			ret = add_new_bucket(c, req, ob);
		else
			ob_push(c, &req->scratch_ptrs, ob);
	}
	req->wp->ptrs = req->scratch_ptrs;

	return ret;
}

static int bucket_alloc_set_partial(struct bch_fs *c,
				    struct alloc_request *req)
{
	int i, ret = 0;

	if (!c->open_buckets_partial_nr)
		return 0;

	spin_lock(&c->freelist_lock);

	if (!c->open_buckets_partial_nr)
		goto unlock;

	for (i = c->open_buckets_partial_nr - 1; i >= 0; --i) {
		struct open_bucket *ob = c->open_buckets + c->open_buckets_partial[i];

		if (want_bucket(c, req, ob)) {
			struct bch_dev *ca = ob_dev(c, ob);
			u64 avail;

			bch2_dev_usage_read_fast(ca, &req->usage);
			avail = dev_buckets_free(ca, req->usage, req->watermark) + ca->nr_partial_buckets;
			if (!avail)
				continue;

			array_remove_item(c->open_buckets_partial,
					  c->open_buckets_partial_nr,
					  i);
			ob->on_partial_list = false;

			scoped_guard(rcu)
				bch2_dev_rcu(c, ob->dev)->nr_partial_buckets--;

			ret = add_new_bucket(c, req, ob);
			if (ret)
				break;
		}
	}
unlock:
	spin_unlock(&c->freelist_lock);
	return ret;
}

static int __open_bucket_add_buckets(struct btree_trans *trans,
				     struct alloc_request *req,
				     struct closure *_cl)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob;
	struct closure *cl = NULL;
	unsigned i;
	int ret;

	req->devs_may_alloc = target_rw_devs(c, req->wp->data_type, req->target);

	/* Don't allocate from devices we already have pointers to: */
	darray_for_each(*req->devs_have, i)
		__clear_bit(*i, req->devs_may_alloc.d);

	open_bucket_for_each(c, &req->ptrs, ob, i)
		__clear_bit(ob->dev, req->devs_may_alloc.d);

	ret = bucket_alloc_set_writepoint(c, req);
	if (ret)
		return ret;

	ret = bucket_alloc_set_partial(c, req);
	if (ret)
		return ret;

	if (req->ec) {
		ret = bucket_alloc_from_stripe(trans, req, _cl);
	} else {
retry_blocking:
		/*
		 * Try nonblocking first, so that if one device is full we'll try from
		 * other devices:
		 */
		ret = bch2_bucket_alloc_set_trans(trans, req, &req->wp->stripe, cl);
		if (ret &&
		    !bch2_err_matches(ret, BCH_ERR_transaction_restart) &&
		    !bch2_err_matches(ret, BCH_ERR_insufficient_devices) &&
		    !cl && _cl) {
			cl = _cl;
			goto retry_blocking;
		}
	}

	return ret;
}

static int open_bucket_add_buckets(struct btree_trans *trans,
				   struct alloc_request *req,
				   struct closure *cl)
{
	int ret;

	if (req->ec && !ec_open_bucket(trans->c, &req->ptrs)) {
		ret = __open_bucket_add_buckets(trans, req, cl);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
		    bch2_err_matches(ret, BCH_ERR_operation_blocked) ||
		    bch2_err_matches(ret, BCH_ERR_freelist_empty) ||
		    bch2_err_matches(ret, BCH_ERR_open_buckets_empty))
			return ret;
		if (req->nr_effective >= req->nr_replicas)
			return 0;
	}

	bool ec = false;
	swap(ec, req->ec);
	ret = __open_bucket_add_buckets(trans, req, cl);
	swap(ec, req->ec);

	return ret < 0 ? ret : 0;
}

/**
 * should_drop_bucket - check if this is open_bucket should go away
 * @ob:		open_bucket to predicate on
 * @c:		filesystem handle
 * @ca:		if set, we're killing buckets for a particular device
 * @ec:		if true, we're shutting down erasure coding and killing all ec
 *		open_buckets
 *		otherwise, return true
 * Returns: true if we should kill this open_bucket
 *
 * We're killing open_buckets because we're shutting down a device, erasure
 * coding, or the entire filesystem - check if this open_bucket matches:
 */
static bool should_drop_bucket(struct open_bucket *ob, struct bch_fs *c,
			       struct bch_dev *ca, bool ec)
{
	if (ec) {
		return ob->ec != NULL;
	} else if (ca) {
		bool drop = ob->dev == ca->dev_idx;
		struct open_bucket *ob2;
		unsigned i;

		if (!drop && ob->ec) {
			unsigned nr_blocks;

			mutex_lock(&ob->ec->lock);
			nr_blocks = bkey_i_to_stripe(&ob->ec->new_stripe.key)->v.nr_blocks;

			for (i = 0; i < nr_blocks; i++) {
				if (!ob->ec->blocks[i])
					continue;

				ob2 = c->open_buckets + ob->ec->blocks[i];
				drop |= ob2->dev == ca->dev_idx;
			}
			mutex_unlock(&ob->ec->lock);
		}

		return drop;
	} else {
		return true;
	}
}

static void bch2_writepoint_stop(struct bch_fs *c, struct bch_dev *ca,
				 bool ec, struct write_point *wp)
{
	struct open_buckets ptrs = { .nr = 0 };
	struct open_bucket *ob;
	unsigned i;

	mutex_lock(&wp->lock);
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		if (should_drop_bucket(ob, c, ca, ec))
			bch2_open_bucket_put(c, ob);
		else
			ob_push(c, &ptrs, ob);
	wp->ptrs = ptrs;
	mutex_unlock(&wp->lock);
}

void bch2_open_buckets_stop(struct bch_fs *c, struct bch_dev *ca,
			    bool ec)
{
	unsigned i;

	/* Next, close write points that point to this device... */
	for (i = 0; i < ARRAY_SIZE(c->write_points); i++)
		bch2_writepoint_stop(c, ca, ec, &c->write_points[i]);

	bch2_writepoint_stop(c, ca, ec, &c->copygc_write_point);
	bch2_writepoint_stop(c, ca, ec, &c->rebalance_write_point);
	bch2_writepoint_stop(c, ca, ec, &c->btree_write_point);

	mutex_lock(&c->btree_reserve_cache_lock);
	while (c->btree_reserve_cache_nr) {
		struct btree_alloc *a =
			&c->btree_reserve_cache[--c->btree_reserve_cache_nr];

		bch2_open_buckets_put(c, &a->ob);
	}
	mutex_unlock(&c->btree_reserve_cache_lock);

	spin_lock(&c->freelist_lock);
	i = 0;
	while (i < c->open_buckets_partial_nr) {
		struct open_bucket *ob =
			c->open_buckets + c->open_buckets_partial[i];

		if (should_drop_bucket(ob, c, ca, ec)) {
			--c->open_buckets_partial_nr;
			swap(c->open_buckets_partial[i],
			     c->open_buckets_partial[c->open_buckets_partial_nr]);

			ob->on_partial_list = false;

			scoped_guard(rcu)
				bch2_dev_rcu(c, ob->dev)->nr_partial_buckets--;

			spin_unlock(&c->freelist_lock);
			bch2_open_bucket_put(c, ob);
			spin_lock(&c->freelist_lock);
		} else {
			i++;
		}
	}
	spin_unlock(&c->freelist_lock);

	bch2_ec_stop_dev(c, ca);
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

	guard(rcu)();
	hlist_for_each_entry_rcu(wp, head, node)
		if (wp->write_point == write_point)
			return wp;
	return NULL;
}

static inline bool too_many_writepoints(struct bch_fs *c, unsigned factor)
{
	u64 stranded	= c->write_points_nr * c->bucket_size_max;
	u64 free	= bch2_fs_usage_read_short(c).free;

	return stranded * factor > free;
}

static noinline bool try_increase_writepoints(struct bch_fs *c)
{
	struct write_point *wp;

	if (c->write_points_nr == ARRAY_SIZE(c->write_points) ||
	    too_many_writepoints(c, 32))
		return false;

	wp = c->write_points + c->write_points_nr++;
	hlist_add_head_rcu(&wp->node, writepoint_hash(c, wp->write_point));
	return true;
}

static noinline bool try_decrease_writepoints(struct btree_trans *trans, unsigned old_nr)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp;
	struct open_bucket *ob;
	unsigned i;

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

	bch2_trans_mutex_lock_norelock(trans, &wp->lock);
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		open_bucket_free_unused(c, ob);
	wp->ptrs.nr = 0;
	mutex_unlock(&wp->lock);
	return true;
}

static struct write_point *writepoint_find(struct btree_trans *trans,
					   unsigned long write_point)
{
	struct bch_fs *c = trans->c;
	struct write_point *wp, *oldest;
	struct hlist_head *head;

	if (!(write_point & 1UL)) {
		wp = (struct write_point *) write_point;
		bch2_trans_mutex_lock_norelock(trans, &wp->lock);
		return wp;
	}

	head = writepoint_hash(c, write_point);
restart_find:
	wp = __writepoint_find(head, write_point);
	if (wp) {
lock_wp:
		bch2_trans_mutex_lock_norelock(trans, &wp->lock);
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

	bch2_trans_mutex_lock_norelock(trans, &oldest->lock);
	bch2_trans_mutex_lock_norelock(trans, &c->write_points_hash_lock);
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
	wp->last_used = local_clock();
	return wp;
}

static noinline void
deallocate_extra_replicas(struct bch_fs *c,
			  struct alloc_request *req)
{
	struct open_bucket *ob;
	unsigned extra_replicas = req->nr_effective - req->nr_replicas;
	unsigned i;

	req->scratch_ptrs.nr = 0;

	open_bucket_for_each(c, &req->ptrs, ob, i) {
		unsigned d = ob_dev(c, ob)->mi.durability;

		if (d && d <= extra_replicas) {
			extra_replicas -= d;
			ob_push(c, &req->wp->ptrs, ob);
		} else {
			ob_push(c, &req->scratch_ptrs, ob);
		}
	}

	req->ptrs = req->scratch_ptrs;
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
			     enum bch_watermark watermark,
			     enum bch_write_flags flags,
			     struct closure *cl,
			     struct write_point **wp_ret)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob;
	unsigned write_points_nr;
	int i;

	struct alloc_request *req = bch2_trans_kmalloc_nomemzero(trans, sizeof(*req));
	int ret = PTR_ERR_OR_ZERO(req);
	if (unlikely(ret))
		return ret;

	if (!IS_ENABLED(CONFIG_BCACHEFS_ERASURE_CODING))
		erasure_code = false;

	req->nr_replicas	= nr_replicas;
	req->target		= target;
	req->ec			= erasure_code;
	req->watermark		= watermark;
	req->flags		= flags;
	req->devs_have		= devs_have;

	BUG_ON(!nr_replicas || !nr_replicas_required);
retry:
	req->ptrs.nr		= 0;
	req->nr_effective	= 0;
	req->have_cache		= false;
	write_points_nr		= c->write_points_nr;

	*wp_ret = req->wp = writepoint_find(trans, write_point.v);

	req->data_type		= req->wp->data_type;

	ret = bch2_trans_relock(trans);
	if (ret)
		goto err;

	/* metadata may not allocate on cache devices: */
	if (req->data_type != BCH_DATA_user)
		req->have_cache = true;

	if (target && !(flags & BCH_WRITE_only_specified_devs)) {
		ret = open_bucket_add_buckets(trans, req, NULL);
		if (!ret ||
		    bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto alloc_done;

		/* Don't retry from all devices if we're out of open buckets: */
		if (bch2_err_matches(ret, BCH_ERR_open_buckets_empty)) {
			int ret2 = open_bucket_add_buckets(trans, req, cl);
			if (!ret2 ||
			    bch2_err_matches(ret2, BCH_ERR_transaction_restart) ||
			    bch2_err_matches(ret2, BCH_ERR_open_buckets_empty)) {
				ret = ret2;
				goto alloc_done;
			}
		}

		/*
		 * Only try to allocate cache (durability = 0 devices) from the
		 * specified target:
		 */
		req->have_cache	= true;
		req->target	= 0;

		ret = open_bucket_add_buckets(trans, req, cl);
	} else {
		ret = open_bucket_add_buckets(trans, req, cl);
	}
alloc_done:
	BUG_ON(!ret && req->nr_effective < req->nr_replicas);

	if (erasure_code && !ec_open_bucket(c, &req->ptrs))
		pr_debug("failed to get ec bucket: ret %u", ret);

	if (ret == -BCH_ERR_insufficient_devices &&
	    req->nr_effective >= nr_replicas_required)
		ret = 0;

	if (ret)
		goto err;

	if (req->nr_effective > req->nr_replicas)
		deallocate_extra_replicas(c, req);

	/* Free buckets we didn't use: */
	open_bucket_for_each(c, &req->wp->ptrs, ob, i)
		open_bucket_free_unused(c, ob);

	req->wp->ptrs = req->ptrs;

	req->wp->sectors_free = UINT_MAX;

	open_bucket_for_each(c, &req->wp->ptrs, ob, i) {
		/*
		 * Ensure proper write alignment - either due to misaligned
		 * bucket sizes (from buggy bcachefs-tools), or writes that mix
		 * logical/physical alignment:
		 */
		struct bch_dev *ca = ob_dev(c, ob);
		u64 offset = bucket_to_sector(ca, ob->bucket) +
			ca->mi.bucket_size -
			ob->sectors_free;
		unsigned align = round_up(offset, block_sectors(c)) - offset;

		ob->sectors_free = max_t(int, 0, ob->sectors_free - align);

		req->wp->sectors_free = min(req->wp->sectors_free, ob->sectors_free);
	}

	req->wp->sectors_free = rounddown(req->wp->sectors_free, block_sectors(c));

	/* Did alignment use up space in an open_bucket? */
	if (unlikely(!req->wp->sectors_free)) {
		bch2_alloc_sectors_done(c, req->wp);
		goto retry;
	}

	BUG_ON(!req->wp->sectors_free || req->wp->sectors_free == UINT_MAX);

	return 0;
err:
	open_bucket_for_each(c, &req->wp->ptrs, ob, i)
		if (req->ptrs.nr < ARRAY_SIZE(req->ptrs.v))
			ob_push(c, &req->ptrs, ob);
		else
			open_bucket_free_unused(c, ob);
	req->wp->ptrs = req->ptrs;

	mutex_unlock(&req->wp->lock);

	if (bch2_err_matches(ret, BCH_ERR_freelist_empty) &&
	    try_decrease_writepoints(trans, write_points_nr))
		goto retry;

	if (cl && bch2_err_matches(ret, BCH_ERR_open_buckets_empty))
		ret = bch_err_throw(c, bucket_alloc_blocked);

	if (cl && !(flags & BCH_WRITE_alloc_nowait) &&
	    bch2_err_matches(ret, BCH_ERR_freelist_empty))
		ret = bch_err_throw(c, bucket_alloc_blocked);

	return ret;
}

void bch2_alloc_sectors_append_ptrs(struct bch_fs *c, struct write_point *wp,
				    struct bkey_i *k, unsigned sectors,
				    bool cached)
{
	bch2_alloc_sectors_append_ptrs_inlined(c, wp, k, sectors, cached);
}

/*
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob
 */
void bch2_alloc_sectors_done(struct bch_fs *c, struct write_point *wp)
{
	bch2_alloc_sectors_done_inlined(c, wp);
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

		wp->last_used	= local_clock();
		wp->write_point	= (unsigned long) wp;
		hlist_add_head_rcu(&wp->node,
				   writepoint_hash(c, wp->write_point));
	}
}

void bch2_open_bucket_to_text(struct printbuf *out, struct bch_fs *c, struct open_bucket *ob)
{
	struct bch_dev *ca = ob_dev(c, ob);
	unsigned data_type = ob->data_type;
	barrier(); /* READ_ONCE() doesn't work on bitfields */

	prt_printf(out, "%zu ref %u ",
		   ob - c->open_buckets,
		   atomic_read(&ob->pin));
	bch2_prt_data_type(out, data_type);
	prt_printf(out, " %u:%llu gen %u allocated %u/%u",
		   ob->dev, ob->bucket, ob->gen,
		   ca->mi.bucket_size - ob->sectors_free, ca->mi.bucket_size);
	if (ob->ec)
		prt_printf(out, " ec idx %llu", ob->ec->idx);
	if (ob->on_partial_list)
		prt_str(out, " partial");
	prt_newline(out);
}

void bch2_open_buckets_to_text(struct printbuf *out, struct bch_fs *c,
			       struct bch_dev *ca)
{
	struct open_bucket *ob;

	out->atomic++;

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++) {
		spin_lock(&ob->lock);
		if (ob->valid && (!ca || ob->dev == ca->dev_idx))
			bch2_open_bucket_to_text(out, c, ob);
		spin_unlock(&ob->lock);
	}

	--out->atomic;
}

void bch2_open_buckets_partial_to_text(struct printbuf *out, struct bch_fs *c)
{
	unsigned i;

	out->atomic++;
	spin_lock(&c->freelist_lock);

	for (i = 0; i < c->open_buckets_partial_nr; i++)
		bch2_open_bucket_to_text(out, c,
				c->open_buckets + c->open_buckets_partial[i]);

	spin_unlock(&c->freelist_lock);
	--out->atomic;
}

static const char * const bch2_write_point_states[] = {
#define x(n)	#n,
	WRITE_POINT_STATES()
#undef x
	NULL
};

static void bch2_write_point_to_text(struct printbuf *out, struct bch_fs *c,
				     struct write_point *wp)
{
	struct open_bucket *ob;
	unsigned i;

	mutex_lock(&wp->lock);

	prt_printf(out, "%lu: ", wp->write_point);
	prt_human_readable_u64(out, wp->sectors_allocated << 9);

	prt_printf(out, " last wrote: ");
	bch2_pr_time_units(out, sched_clock() - wp->last_used);

	for (i = 0; i < WRITE_POINT_STATE_NR; i++) {
		prt_printf(out, " %s: ", bch2_write_point_states[i]);
		bch2_pr_time_units(out, wp->time[i]);
	}

	prt_newline(out);

	printbuf_indent_add(out, 2);
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		bch2_open_bucket_to_text(out, c, ob);
	printbuf_indent_sub(out, 2);

	mutex_unlock(&wp->lock);
}

void bch2_write_points_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct write_point *wp;

	prt_str(out, "Foreground write points\n");
	for (wp = c->write_points;
	     wp < c->write_points + ARRAY_SIZE(c->write_points);
	     wp++)
		bch2_write_point_to_text(out, c, wp);

	prt_str(out, "Copygc write point\n");
	bch2_write_point_to_text(out, c, &c->copygc_write_point);

	prt_str(out, "Rebalance write point\n");
	bch2_write_point_to_text(out, c, &c->rebalance_write_point);

	prt_str(out, "Btree write point\n");
	bch2_write_point_to_text(out, c, &c->btree_write_point);
}

void bch2_fs_alloc_debug_to_text(struct printbuf *out, struct bch_fs *c)
{
	unsigned nr[BCH_DATA_NR];

	memset(nr, 0, sizeof(nr));

	for (unsigned i = 0; i < ARRAY_SIZE(c->open_buckets); i++)
		nr[c->open_buckets[i].data_type]++;

	printbuf_tabstops_reset(out);
	printbuf_tabstop_push(out, 24);

	prt_printf(out, "capacity\t%llu\n",		c->capacity);
	prt_printf(out, "reserved\t%llu\n",		c->reserved);
	prt_printf(out, "hidden\t%llu\n",		percpu_u64_get(&c->usage->hidden));
	prt_printf(out, "btree\t%llu\n",		percpu_u64_get(&c->usage->btree));
	prt_printf(out, "data\t%llu\n",			percpu_u64_get(&c->usage->data));
	prt_printf(out, "cached\t%llu\n",		percpu_u64_get(&c->usage->cached));
	prt_printf(out, "reserved\t%llu\n",		percpu_u64_get(&c->usage->reserved));
	prt_printf(out, "online_reserved\t%llu\n",	percpu_u64_get(c->online_reserved));
	prt_printf(out, "nr_inodes\t%llu\n",		percpu_u64_get(&c->usage->nr_inodes));

	prt_newline(out);
	prt_printf(out, "freelist_wait\t%s\n",			c->freelist_wait.list.first ? "waiting" : "empty");
	prt_printf(out, "open buckets allocated\t%i\n",		OPEN_BUCKETS_COUNT - c->open_buckets_nr_free);
	prt_printf(out, "open buckets total\t%u\n",		OPEN_BUCKETS_COUNT);
	prt_printf(out, "open_buckets_wait\t%s\n",		c->open_buckets_wait.list.first ? "waiting" : "empty");
	prt_printf(out, "open_buckets_btree\t%u\n",		nr[BCH_DATA_btree]);
	prt_printf(out, "open_buckets_user\t%u\n",		nr[BCH_DATA_user]);
	prt_printf(out, "btree reserve cache\t%u\n",		c->btree_reserve_cache_nr);
}

void bch2_dev_alloc_debug_to_text(struct printbuf *out, struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bch_dev_usage_full stats = bch2_dev_usage_full_read(ca);
	unsigned nr[BCH_DATA_NR];

	memset(nr, 0, sizeof(nr));

	for (unsigned i = 0; i < ARRAY_SIZE(c->open_buckets); i++)
		nr[c->open_buckets[i].data_type]++;

	bch2_dev_usage_to_text(out, ca, &stats);

	prt_newline(out);

	prt_printf(out, "reserves:\n");
	for (unsigned i = 0; i < BCH_WATERMARK_NR; i++)
		prt_printf(out, "%s\t%llu\r\n", bch2_watermarks[i], bch2_dev_buckets_reserved(ca, i));

	prt_newline(out);

	printbuf_tabstops_reset(out);
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 16);

	prt_printf(out, "open buckets\t%i\r\n",	ca->nr_open_buckets);
	prt_printf(out, "buckets to invalidate\t%llu\r\n",
		   should_invalidate_buckets(ca, bch2_dev_usage_read(ca)));
}

static noinline void bch2_print_allocator_stuck(struct bch_fs *c)
{
	struct printbuf buf = PRINTBUF;

	prt_printf(&buf, "Allocator stuck? Waited for %u seconds\n",
		   c->opts.allocator_stuck_timeout);

	prt_printf(&buf, "Allocator debug:\n");
	printbuf_indent_add(&buf, 2);
	bch2_fs_alloc_debug_to_text(&buf, c);
	printbuf_indent_sub(&buf, 2);
	prt_newline(&buf);

	bch2_printbuf_make_room(&buf, 4096);

	buf.atomic++;
	scoped_guard(rcu)
		for_each_online_member_rcu(c, ca) {
			prt_printf(&buf, "Dev %u:\n", ca->dev_idx);
			printbuf_indent_add(&buf, 2);
			bch2_dev_alloc_debug_to_text(&buf, ca);
			printbuf_indent_sub(&buf, 2);
			prt_newline(&buf);
		}
	--buf.atomic;

	prt_printf(&buf, "Copygc debug:\n");
	printbuf_indent_add(&buf, 2);
	bch2_copygc_wait_to_text(&buf, c);
	printbuf_indent_sub(&buf, 2);
	prt_newline(&buf);

	prt_printf(&buf, "Journal debug:\n");
	printbuf_indent_add(&buf, 2);
	bch2_journal_debug_to_text(&buf, &c->journal);
	printbuf_indent_sub(&buf, 2);

	bch2_print_str(c, KERN_ERR, buf.buf);
	printbuf_exit(&buf);
}

static inline unsigned allocator_wait_timeout(struct bch_fs *c)
{
	if (c->allocator_last_stuck &&
	    time_after(c->allocator_last_stuck + HZ * 60 * 2, jiffies))
		return 0;

	return c->opts.allocator_stuck_timeout * HZ;
}

void __bch2_wait_on_allocator(struct bch_fs *c, struct closure *cl)
{
	unsigned t = allocator_wait_timeout(c);

	if (t && closure_sync_timeout(cl, t)) {
		c->allocator_last_stuck = jiffies;
		bch2_print_allocator_stuck(c);
	}

	closure_sync(cl);
}
