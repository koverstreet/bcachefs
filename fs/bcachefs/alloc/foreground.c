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

#include "alloc/backpointers.h"
#include "alloc/buckets_waiting_for_journal.h"
#include "alloc/buckets.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/iter.h"
#include "btree/update.h"
#include "btree/check.h"

#include "data/copygc.h"
#include "data/ec/create.h"
#include "data/ec/init.h"
#include "data/nocow_locking.h"
#include "data/write.h"

#include "init/dev.h"
#include "init/error.h"

#include "journal/journal.h"

#include "sb/counters.h"

#include "util/clock.h"

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
	open_bucket_idx_t idx = ob - c->allocator.open_buckets;
	open_bucket_idx_t *slot = open_bucket_hashslot(c, ob->dev, ob->bucket);

	ob->hash = *slot;
	*slot = idx;
}

static void bch2_open_bucket_hash_remove(struct bch_fs *c, struct open_bucket *ob)
{
	open_bucket_idx_t idx = ob - c->allocator.open_buckets;
	open_bucket_idx_t *slot = open_bucket_hashslot(c, ob->dev, ob->bucket);

	while (*slot != idx) {
		BUG_ON(!*slot);
		slot = &c->allocator.open_buckets[*slot].hash;
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

	scoped_guard(spinlock, &ob->lock) {
		ob->valid = false;
		ob->data_type = 0;
	}

	scoped_guard(spinlock, &c->allocator.freelist_lock) {
		bch2_open_bucket_hash_remove(c, ob);

		ob->freelist = c->allocator.open_buckets_freelist;
		c->allocator.open_buckets_freelist = ob - c->allocator.open_buckets;

		c->allocator.open_buckets_nr_free++;
		ca->nr_open_buckets--;
	}

	closure_wake_up(&c->allocator.open_buckets_wait);
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

static struct open_bucket *bch2_open_bucket_alloc(struct bch_fs_allocator *c)
{
	BUG_ON(!c->open_buckets_freelist || !c->open_buckets_nr_free);

	struct open_bucket *ob = c->open_buckets + c->open_buckets_freelist;
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
	BUG_ON(c->allocator.open_buckets_partial_nr >=
	       ARRAY_SIZE(c->allocator.open_buckets_partial));

	scoped_guard(spinlock, &c->allocator.freelist_lock) {
		guard(rcu)();
		bch2_dev_rcu(c, ob->dev)->nr_partial_buckets++;

		ob->on_partial_list = true;
		c->allocator.open_buckets_partial[c->allocator.open_buckets_partial_nr++] =
			ob - c->allocator.open_buckets;
	}

	closure_wake_up(&c->allocator.open_buckets_wait);
	closure_wake_up(&c->allocator.freelist_wait);
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
					      u64 bucket, u8 gen)
{
	struct bch_dev *ca = req->ca;

	if (unlikely(is_superblock_bucket(c, ca, bucket)))
		return NULL;

	if (unlikely(ca->buckets_nouse && test_bit(bucket, ca->buckets_nouse))) {
		req->counters.skipped_nouse++;
		return NULL;
	}

	guard(spinlock)(&c->allocator.freelist_lock);

	if (unlikely(c->allocator.open_buckets_nr_free <= bch2_open_buckets_reserved(req->watermark))) {
		track_event_change(&c->times[BCH_TIME_blocked_allocate_open_bucket], true);

		int ret;
		if (req->cl) {
			closure_wait(&c->allocator.open_buckets_wait, req->cl);
			ret = bch_err_throw(c, open_bucket_alloc_blocked);
		} else {
			ret = bch_err_throw(c, open_buckets_empty);
		}

		return ERR_PTR(ret);
	}

	/* Recheck under lock: */
	if (bch2_bucket_is_open(c, ca->dev_idx, bucket)) {
		req->counters.skipped_open++;
		return NULL;
	}

	struct open_bucket *ob = bch2_open_bucket_alloc(&c->allocator);

	scoped_guard(spinlock, &ob->lock) {
		ob->valid	= true;
		ob->sectors_free = ca->mi.bucket_size;
		ob->dev		= ca->dev_idx;
		ob->gen		= gen;
		ob->bucket	= bucket;
	}

	ca->nr_open_buckets++;
	bch2_open_bucket_hash_add(c, ob);

	track_event_change(&c->times[BCH_TIME_blocked_allocate_open_bucket], false);
	track_event_change(&c->times[BCH_TIME_blocked_allocate], false);

	return ob;
}

static struct open_bucket *try_alloc_bucket(struct btree_trans *trans,
					    struct alloc_request *req,
					    struct btree_iter *freespace_iter)
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

	return __try_alloc_bucket(c, req, b, gen);
}

/*
 * This path is for before the freespace btree is initialized:
 */
static noinline struct open_bucket *
bch2_bucket_alloc_early(struct btree_trans *trans,
			struct alloc_request *req)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = req->ca;
	struct bkey_s_c k;
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
		u64 bucket = alloc_cursor = k.k->p.offset;

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
			bch2_btree_iter_set_pos(&iter, POS(ca->dev_idx, bucket));
			req->counters.buckets_seen++;
			req->counters.skipped_mi_btree_bitmap++;
			continue;
		}

		struct bch_alloc_v4 a_convert;
		const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);
		if (a->data_type != BCH_DATA_free)
			continue;

		/* now check the cached key to serialize concurrent allocs of the bucket */
		CLASS(btree_iter, citer)(trans, BTREE_ID_alloc, k.k->p, BTREE_ITER_cached|BTREE_ITER_nopreserve);
		struct bkey_s_c ck = bch2_btree_iter_peek_slot(&citer);
		ret = bkey_err(ck);
		if (ret)
			break;

		a = bch2_alloc_to_v4(ck, &a_convert);
		if (a->data_type == BCH_DATA_free) {
			req->counters.buckets_seen++;

			ob = may_alloc_bucket(c, req, k.k->p)
				? __try_alloc_bucket(c, req, k.k->p.offset, a->gen)
				: NULL;
			if (ob)
				break;
		}
	}

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
						      struct alloc_request *req)
{
	struct bch_dev *ca = req->ca;
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

				bch2_btree_iter_set_pos(&iter, POS(ca->dev_idx, alloc_cursor));
				req->counters.skipped_mi_btree_bitmap++;
				goto next;
			}

			ob = try_alloc_bucket(trans, req, &iter);
			if (ob) {
				if (!IS_ERR(ob))
					*dev_alloc_cursor = iter.pos.offset;
				bch2_set_btree_iter_dontneed(&iter);
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

	BUG_ON(ob && ret);

	if (ret)
		ob = ERR_PTR(ret);

	if (!ob && alloc_start > ca->mi.first_bucket) {
		alloc_cursor = alloc_start = ca->mi.first_bucket;
		goto again;
	}

	return ob;
}

static noinline void bucket_alloc_to_text(struct printbuf *out,
					  struct bch_fs *c,
					  struct alloc_request *req,
					  struct open_bucket *ob)
{
	printbuf_tabstop_push(out, 32);

	if (req->ca) {
		prt_printf(out, "dev\t%s (%u)\n",	req->ca->name, req->ca->dev_idx);
		prt_printf(out, "avail\t%llu\n",	__dev_buckets_free(req->ca, req->usage, req->watermark));
	}

	prt_printf(out, "watermark\t%s\n",	bch2_watermarks[req->watermark]);
	prt_printf(out, "data type\t%s\n",	__bch2_data_types[req->data_type]);
	prt_printf(out, "will_retry_target_devices\t%u\n",	req->will_retry_target_devices);
	prt_printf(out, "will_retry_all_devices\t%u\n",	req->will_retry_all_devices);
	prt_printf(out, "blocking\t%u\n", !(req->flags & BCH_WRITE_alloc_nowait));
	prt_printf(out, "free\t%llu\n",	req->usage.buckets[BCH_DATA_free]);
	prt_printf(out, "copygc_wait\t%llu/%lli\n",
		   bch2_copygc_wait_amount(c),
		   c->copygc.wait - atomic64_read(&c->io_clock[WRITE].now));
	prt_printf(out, "seen\t%llu\n",	req->counters.buckets_seen);
	prt_printf(out, "open\t%llu\n",	req->counters.skipped_open);
	prt_printf(out, "need journal commit\t%llu\n", req->counters.skipped_need_journal_commit);
	prt_printf(out, "nocow\t%llu\n",	req->counters.skipped_nocow);
	prt_printf(out, "nouse\t%llu\n",	req->counters.skipped_nouse);
	prt_printf(out, "mi_btree_bitmap\t%llu\n", req->counters.skipped_mi_btree_bitmap);

	if (!IS_ERR_OR_NULL(ob))
		prt_printf(out, "allocated\t%llu\n", ob->bucket);
	else
		prt_printf(out, "err\t%s\n", bch2_err_str(PTR_ERR(ob)));
}

/**
 * bch2_bucket_alloc_trans - allocate a single bucket from a specific device
 * @trans:	transaction object
 * @req:	state for the entire allocation
 *
 * Returns:	an open_bucket on success, or an ERR_PTR() on failure.
 */
static struct open_bucket *bch2_bucket_alloc_trans(struct btree_trans *trans,
						   struct alloc_request *req)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = req->ca;
	struct open_bucket *ob = NULL;
	bool freespace = READ_ONCE(ca->mi.freespace_initialized);
	bool waiting = false;

	req->btree_bitmap = req->data_type == BCH_DATA_btree;
	memset(&req->counters, 0, sizeof(req->counters));
again:
	bch2_dev_usage_read_fast(ca, &req->usage);
	u64 avail = __dev_buckets_free(ca, req->usage, req->watermark);

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

		track_event_change(&c->times[BCH_TIME_blocked_allocate], true);

		if (req->cl &&
		    !(req->flags & BCH_WRITE_alloc_nowait) &&
		    !req->will_retry_target_devices &&
		    !req->will_retry_all_devices) {
			if (!waiting) {
				closure_wait(&c->allocator.freelist_wait, req->cl);
				waiting = true;
				goto again;
			}

			bch2_copygc_wakeup(c);
			ob = ERR_PTR(bch_err_throw(c, bucket_alloc_blocked));
		} else {
			ob = ERR_PTR(bch_err_throw(c, freelist_empty));
		}

		goto err;
	}

	if (waiting)
		closure_wake_up(&c->allocator.freelist_wait);
alloc:
	ob = likely(freespace)
		? bch2_bucket_alloc_freelist(trans, req)
		: bch2_bucket_alloc_early(trans, req);

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

	int ret = PTR_ERR_OR_ZERO(ob);

	if (!ret) {
		ob->data_type = req->data_type;

		event_inc_trace(c, bucket_alloc, buf,
			bucket_alloc_to_text(&buf, c, req, ob));
	} else if (ret == -BCH_ERR_open_buckets_empty ||
		   ret == -BCH_ERR_open_bucket_alloc_blocked) {
		event_inc_trace(c, open_bucket_alloc_fail, buf,
			bch2_fs_open_buckets_to_text(&buf, c));
	} else if (!bch2_err_matches(ret, BCH_ERR_transaction_restart) &&
		   !req->will_retry_target_devices &&
		   !req->will_retry_all_devices)
		event_inc_trace(c, bucket_alloc_fail, buf,
			bucket_alloc_to_text(&buf, c, req, ob));

	if (!bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
		unsigned idx = req->trace.nr % ARRAY_SIZE(req->trace.entries);
		struct alloc_trace_entry *e = &req->trace.entries[idx];

		e->dev		= ca->dev_idx;
		e->err		= ret;
		req->trace.nr++;
	}

	return ob;
}

struct open_bucket *bch2_bucket_alloc(struct bch_fs *c, struct bch_dev *ca,
				      enum bch_watermark watermark,
				      enum bch_data_type data_type,
				      struct closure *cl)
{
	struct open_bucket *ob;
	struct alloc_request req = {
		.cl		= cl,
		.watermark	= watermark,
		.data_type	= data_type,
		.ca		= ca,
	};

	CLASS(btree_trans, trans)(c);
	lockrestart_do(trans, PTR_ERR_OR_ZERO(ob = bch2_bucket_alloc_trans(trans, &req)));
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

int bch2_bucket_alloc_set_trans(struct btree_trans *trans,
				struct alloc_request *req,
				struct dev_stripe_state *stripe)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	BUG_ON(req->nr_effective >= req->nr_replicas);

	if (req->devs_sorted.nr <= 1)
		req->will_retry_target_devices = false;

	bch2_dev_alloc_list(c, stripe, &req->devs_may_alloc, &req->devs_sorted);

	darray_for_each(req->devs_sorted, i) {
		req->ca = bch2_dev_tryget_noerror(c, *i);
		if (!req->ca)
			continue;

		if (!req->ca->mi.durability && req->have_cache) {
			bch2_dev_put(req->ca);
			req->ca = NULL;
			continue;
		}

		struct open_bucket *ob = bch2_bucket_alloc_trans(trans, req);
		if (!IS_ERR(ob))
			bch2_dev_stripe_increment_inlined(req->ca, stripe, &req->usage);

		bch2_dev_put(req->ca);
		req->ca = NULL;

		if (IS_ERR(ob)) { /* don't squash error */
			ret = PTR_ERR(ob);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
			    bch2_err_matches(ret, BCH_ERR_operation_blocked) ||
			    bch2_err_matches(ret, BCH_ERR_open_buckets_empty))
				return ret;
		} else if (add_new_bucket(c, req, ob))
			return 0;
	}

	return ret ?: bch_err_throw(c, insufficient_devices);
}

/* Allocate from stripes: */

/*
 * if we can't allocate a new stripe because there are already too many
 * partially filled stripes, force allocating from an existing stripe even when
 * it's to a device we don't want:
 */

static int bucket_alloc_from_stripe(struct btree_trans *trans,
				    struct alloc_request *req)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	struct ec_stripe_head *h = errptr_try(bch2_ec_stripe_head_get(trans, req, 0));
	if (!h)
		return 0;

	bch2_dev_alloc_list(c, &req->wp->stripe, &req->devs_may_alloc, &req->devs_sorted);

	darray_for_each(req->devs_sorted, i)
		for (unsigned ec_idx = 0; ec_idx < h->s->nr_data; ec_idx++) {
			if (!h->s->blocks[ec_idx])
				continue;

			struct open_bucket *ob = c->allocator.open_buckets + h->s->blocks[ec_idx];
			if (ob->dev == *i && !test_and_set_bit(ec_idx, h->s->blocks_allocated)) {
				ob->ec_idx	= ec_idx;
				ob->ec		= h->s;
				ec_stripe_new_get(h->s, STRIPE_REF_io);

				ret = add_new_bucket(c, req, ob);

				event_inc_trace(c, bucket_alloc_from_stripe, buf, ({
					bch2_open_bucket_to_text(&buf, c, ob);
				}));

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
	struct bch_fs_allocator *a = &c->allocator;

	if (!a->open_buckets_partial_nr)
		return 0;

	guard(spinlock)(&a->freelist_lock);

	if (!a->open_buckets_partial_nr)
		return 0;

	for (int i = a->open_buckets_partial_nr - 1; i >= 0; --i) {
		struct open_bucket *ob = a->open_buckets + a->open_buckets_partial[i];

		if (want_bucket(c, req, ob)) {
			struct bch_dev *ca = ob_dev(c, ob);
			u64 avail;

			bch2_dev_usage_read_fast(ca, &req->usage);
			avail = __dev_buckets_free(ca, req->usage, req->watermark) + ca->nr_partial_buckets;
			if (!avail)
				continue;

			array_remove_item(a->open_buckets_partial,
					  a->open_buckets_partial_nr,
					  i);
			ob->on_partial_list = false;

			scoped_guard(rcu)
				bch2_dev_rcu(c, ob->dev)->nr_partial_buckets--;

			try(add_new_bucket(c, req, ob));
		}
	}

	return 0;
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
	struct bch_fs_allocator *a = &c->allocator;

	if (ec) {
		return ob->ec != NULL;
	} else if (ca) {
		bool drop = ob->dev == ca->dev_idx;

		if (!drop && ob->ec) {
			guard(mutex)(&ob->ec->lock);
			unsigned nr_blocks = ob->ec->new_stripe.key.v.nr_blocks;

			for (unsigned i = 0; i < nr_blocks; i++) {
				if (!ob->ec->blocks[i])
					continue;

				struct open_bucket *ob2 = a->open_buckets + ob->ec->blocks[i];
				drop |= ob2->dev == ca->dev_idx;
			}
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

	guard(mutex)(&wp->lock);
	open_bucket_for_each(c, &wp->ptrs, ob, i)
		if (should_drop_bucket(ob, c, ca, ec))
			bch2_open_bucket_put(c, ob);
		else
			ob_push(c, &ptrs, ob);
	wp->ptrs = ptrs;
}

void bch2_open_buckets_stop(struct bch_fs *c, struct bch_dev *ca,
			    bool ec)
{
	struct bch_fs_allocator *a = &c->allocator;
	unsigned i;

	/* Next, close write points that point to this device... */
	for (i = 0; i < ARRAY_SIZE(a->write_points); i++)
		bch2_writepoint_stop(c, ca, ec, &a->write_points[i]);

	bch2_writepoint_stop(c, ca, ec, &c->copygc.write_point);
	bch2_writepoint_stop(c, ca, ec, &a->reconcile_write_point);
	bch2_writepoint_stop(c, ca, ec, &a->btree_write_point);

	scoped_guard(mutex, &c->btree.reserve_cache.lock)
		while (c->btree.reserve_cache.nr) {
			struct btree_alloc *a =
				&c->btree.reserve_cache.data[--c->btree.reserve_cache.nr];

			bch2_open_buckets_put(c, &a->ob);
		}

	i = 0;
	scoped_guard(spinlock, &a->freelist_lock)
		while (i < a->open_buckets_partial_nr) {
			struct open_bucket *ob =
				a->open_buckets + a->open_buckets_partial[i];

			if (should_drop_bucket(ob, c, ca, ec)) {
				--a->open_buckets_partial_nr;
				swap(a->open_buckets_partial[i],
				     a->open_buckets_partial[a->open_buckets_partial_nr]);

				ob->on_partial_list = false;

				scoped_guard(rcu)
					bch2_dev_rcu(c, ob->dev)->nr_partial_buckets--;

				spin_unlock(&a->freelist_lock);
				bch2_open_bucket_put(c, ob);
				spin_lock(&a->freelist_lock);
			} else {
				i++;
			}
		}

	bch2_ec_stop_dev(c, ca);
}

static inline struct hlist_head *writepoint_hash(struct bch_fs_allocator *a,
						 unsigned long write_point)
{
	unsigned hash =
		hash_long(write_point, ilog2(ARRAY_SIZE(a->write_points_hash)));

	return &a->write_points_hash[hash];
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
	u64 stranded	= c->allocator.write_points_nr * c->capacity.bucket_size_max;
	u64 free	= bch2_fs_usage_read_short(c).free;

	return stranded * factor > free;
}

static noinline bool try_increase_writepoints(struct bch_fs *c)
{
	struct bch_fs_allocator *a = &c->allocator;
	struct write_point *wp;

	if (a->write_points_nr == ARRAY_SIZE(a->write_points) ||
	    too_many_writepoints(c, 32))
		return false;

	wp = a->write_points + a->write_points_nr++;
	hlist_add_head_rcu(&wp->node, writepoint_hash(a, wp->write_point));
	return true;
}

static noinline bool try_decrease_writepoints(struct btree_trans *trans, unsigned old_nr)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_allocator *a = &c->allocator;
	struct write_point *wp;
	struct open_bucket *ob;
	unsigned i;

	scoped_guard(mutex, &a->write_points_hash_lock) {
		if (a->write_points_nr < old_nr)
			return true;

		if (a->write_points_nr == 1 ||
		    !too_many_writepoints(c, 8))
			return false;

		wp = a->write_points + --a->write_points_nr;
		hlist_del_rcu(&wp->node);
	}

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
	struct bch_fs_allocator *a = &c->allocator;
	struct write_point *wp, *oldest;
	struct hlist_head *head;

	if (!(write_point & 1UL)) {
		wp = (struct write_point *) write_point;
		bch2_trans_mutex_lock_norelock(trans, &wp->lock);
		return wp;
	}

	head = writepoint_hash(a, write_point);
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
	for (wp = a->write_points;
	     wp < a->write_points + a->write_points_nr; wp++)
		if (!oldest || time_before64(wp->last_used, oldest->last_used))
			oldest = wp;

	bch2_trans_mutex_lock_norelock(trans, &oldest->lock);
	bch2_trans_mutex_lock_norelock(trans, &a->write_points_hash_lock);
	if (oldest >= a->write_points + a->write_points_nr ||
	    try_increase_writepoints(c)) {
		mutex_unlock(&a->write_points_hash_lock);
		mutex_unlock(&oldest->lock);
		goto restart_find_oldest;
	}

	wp = __writepoint_find(head, write_point);
	if (wp && wp != oldest) {
		mutex_unlock(&a->write_points_hash_lock);
		mutex_unlock(&oldest->lock);
		goto lock_wp;
	}

	wp = oldest;
	hlist_del_rcu(&wp->node);
	wp->write_point = write_point;
	hlist_add_head_rcu(&wp->node, head);
	mutex_unlock(&a->write_points_hash_lock);
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
int bch2_alloc_sectors_req(struct btree_trans *trans,
			   struct alloc_request *req,
			   struct write_point_specifier write_point,
			   struct write_point **wp_ret)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_allocator *a = &c->allocator;
	struct open_bucket *ob;
	unsigned write_points_nr;
	int i;

	BUG_ON(!req->nr_replicas);
retry:
	req->ca				= NULL;
	req->will_retry_all_devices	= req->target && !(req->flags & BCH_WRITE_only_specified_devs);
	req->will_retry_target_devices	= !(req->flags & BCH_WRITE_alloc_nowait);
	req->ptrs.nr			= 0;
	req->nr_effective		= 0;
	req->have_cache			= req->flags & BCH_WRITE_move;
	write_points_nr			= a->write_points_nr;

	*wp_ret = req->wp = writepoint_find(trans, write_point.v);

	req->data_type		= req->wp->data_type;

	/* metadata may not allocate on cache devices: */
	if (req->data_type != BCH_DATA_user)
		req->have_cache = true;

	int ret = bch2_trans_relock(trans);
	if (ret)
		goto err;

	while (1) {
		req->devs_may_alloc = target_rw_devs(c, req->wp->data_type, req->target);

		/* Don't allocate from devices we already have pointers to: */
		darray_for_each(*req->devs_have, i)
			__clear_bit(*i, req->devs_may_alloc.d);

		open_bucket_for_each(c, &req->ptrs, ob, i)
			__clear_bit(ob->dev, req->devs_may_alloc.d);

		ret =   bucket_alloc_set_writepoint(c, req) ?:
			bucket_alloc_set_partial(c, req) ?:
			(req->ec
			 ? bucket_alloc_from_stripe(trans, req)
			 : bch2_bucket_alloc_set_trans(trans, req, &req->wp->stripe));

		ret = min(ret, 0); /* We return 1 earlier to terminate allocating */

		if (ret &&
		    ret != -BCH_ERR_freelist_empty &&
		    ret != -BCH_ERR_insufficient_devices)
			goto err;

		if (ret && req->will_retry_all_devices) {
			/*
			 * Only try to allocate cache (durability = 0 devices) from the
			 * specified target:
			 */
			req->have_cache			= true;
			req->target			= 0;
			req->will_retry_all_devices	= false;
			continue;
		}

		if (ret && req->will_retry_target_devices) {
			/*
			 * When allocating from a target with multiple devices,
			 * bch2_bucket_alloc_trans() won't block until we've
			 * attempted all devices in the target once
			 */
			req->will_retry_target_devices = false;
			continue;
		}

		if (req->nr_effective < req->nr_replicas && req->ec) {
			if ((req->flags & BCH_WRITE_must_ec)) {
				ret = bch_err_throw(c, ec_alloc_failed);
				goto err;
			}

			req->ec				= false;
			req->will_retry_target_devices	= true;
			req->will_retry_all_devices	= req->target && !(req->flags & BCH_WRITE_only_specified_devs);
			continue;
		}

		if (ret == -BCH_ERR_insufficient_devices &&
		    req->nr_effective)
			ret = 0;

		if (ret)
			goto err;

		BUG_ON(!req->nr_effective);
		break;
	}

	if (req->ec &&
	    (req->flags & BCH_WRITE_must_ec) &&
	    !ec_open_bucket(c, &req->ptrs)) {
		ret = bch_err_throw(c, ec_alloc_failed);
		goto err;
	}

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

	req->wp->prev_sectors_free = req->wp->sectors_free;
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

	if ((bch2_err_matches(ret, BCH_ERR_freelist_empty) ||
	     bch2_err_matches(ret, BCH_ERR_bucket_alloc_blocked)) &&
	    try_decrease_writepoints(trans, write_points_nr)) {
		if (bch2_err_matches(ret, BCH_ERR_bucket_alloc_blocked))
			closure_wake_up(&c->allocator.freelist_wait);
		goto retry;
	}

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
	struct bch_fs_allocator *a = &c->allocator;
	struct open_bucket *ob;
	struct write_point *wp;

	mutex_init(&a->write_points_hash_lock);
	a->write_points_nr = ARRAY_SIZE(a->write_points);

	/* open bucket 0 is a sentinal NULL: */
	spin_lock_init(&a->open_buckets[0].lock);

	for (ob = a->open_buckets + 1;
	     ob < a->open_buckets + ARRAY_SIZE(a->open_buckets); ob++) {
		spin_lock_init(&ob->lock);
		a->open_buckets_nr_free++;

		ob->freelist = a->open_buckets_freelist;
		a->open_buckets_freelist = ob - a->open_buckets;
	}

	writepoint_init(&a->btree_write_point,		BCH_DATA_btree);
	writepoint_init(&a->reconcile_write_point,	BCH_DATA_user);
	writepoint_init(&c->copygc.write_point,		BCH_DATA_user);

	for (wp = a->write_points;
	     wp < a->write_points + a->write_points_nr; wp++) {
		writepoint_init(wp, BCH_DATA_user);

		wp->last_used	= local_clock();
		wp->write_point	= (unsigned long) wp;
		hlist_add_head_rcu(&wp->node,
				   writepoint_hash(a, wp->write_point));
	}
}

void bch2_open_bucket_to_text(struct printbuf *out, struct bch_fs *c, struct open_bucket *ob)
{
	struct bch_fs_allocator *a = &c->allocator;
	struct bch_dev *ca = ob_dev(c, ob);
	unsigned data_type = ob->data_type;
	barrier(); /* READ_ONCE() doesn't work on bitfields */

	prt_printf(out, "%zu ref %u ",
		   ob - a->open_buckets,
		   atomic_read(&ob->pin));
	bch2_prt_data_type(out, data_type);
	prt_printf(out, " %u:%llu gen %u allocated %u/%u",
		   ob->dev, ob->bucket, ob->gen,
		   ca->mi.bucket_size - ob->sectors_free, ca->mi.bucket_size);
	if (ob->ec)
		prt_printf(out, " ec idx %llu", ob->ec->new_stripe.key.k.p.offset);
	if (ob->on_partial_list)
		prt_str(out, " partial");
	prt_newline(out);
}

void bch2_open_buckets_to_text(struct printbuf *out, struct bch_fs *c,
			       struct bch_dev *ca)
{
	struct bch_fs_allocator *a = &c->allocator;
	guard(printbuf_atomic)(out);

	for (struct open_bucket *ob = a->open_buckets;
	     ob < a->open_buckets + ARRAY_SIZE(a->open_buckets);
	     ob++) {
		guard(spinlock)(&ob->lock);
		if (ob->valid && (!ca || ob->dev == ca->dev_idx))
			bch2_open_bucket_to_text(out, c, ob);
	}
}

void bch2_open_buckets_partial_to_text(struct printbuf *out, struct bch_fs *c)
{
	guard(printbuf_atomic)(out);
	guard(spinlock)(&c->allocator.freelist_lock);

	for (unsigned i = 0; i < c->allocator.open_buckets_partial_nr; i++)
		bch2_open_bucket_to_text(out, c,
				c->allocator.open_buckets + c->allocator.open_buckets_partial[i]);
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

	guard(mutex)(&wp->lock);

	prt_printf(out, "%lu: ", wp->write_point);
	prt_human_readable_u64(out, wp->sectors_allocated << 9);

	prt_printf(out, " last wrote: ");
	bch2_pr_time_units(out, sched_clock() - wp->last_used);

	for (i = 0; i < WRITE_POINT_STATE_NR; i++) {
		prt_printf(out, " %s: ", bch2_write_point_states[i]);
		bch2_pr_time_units(out, wp->time[i]);
	}

	prt_newline(out);

	scoped_guard(printbuf_indent, out)
		open_bucket_for_each(c, &wp->ptrs, ob, i)
			bch2_open_bucket_to_text(out, c, ob);
}

void bch2_write_points_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct bch_fs_allocator *a = &c->allocator;
	struct write_point *wp;

	prt_str(out, "Foreground write points\n");
	for (wp = a->write_points;
	     wp < a->write_points + ARRAY_SIZE(a->write_points);
	     wp++)
		bch2_write_point_to_text(out, c, wp);

	prt_str(out, "Copygc write point\n");
	bch2_write_point_to_text(out, c, &c->copygc.write_point);

	prt_str(out, "Rebalance write point\n");
	bch2_write_point_to_text(out, c, &a->reconcile_write_point);

	prt_str(out, "Btree write point\n");
	bch2_write_point_to_text(out, c, &a->btree_write_point);
}

void bch2_fs_open_buckets_to_text(struct printbuf *out, struct bch_fs *c)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 24);

	struct bch_fs_allocator *a = &c->allocator;
	unsigned nr[BCH_DATA_NR];
	memset(nr, 0, sizeof(nr));

	for (struct open_bucket *ob = a->open_buckets;
	     ob < a->open_buckets + ARRAY_SIZE(a->open_buckets);
	     ob++)
		if (atomic_read(&ob->pin))
			nr[ob->data_type]++;

	prt_printf(out, "open buckets allocated\t%i\n",		OPEN_BUCKETS_COUNT - a->open_buckets_nr_free);
	prt_printf(out, "open buckets total\t%u\n",		OPEN_BUCKETS_COUNT);

	for (unsigned i = 0; i < ARRAY_SIZE(nr); i++)
		if (nr[i])
			prt_printf(out, "open_buckets %s:\t%u\n", __bch2_data_types[i], nr[i]);

	prt_printf(out, "open_buckets_wait\t%s\n",		a->open_buckets_wait.list.first ? "waiting" : "empty");
}

void bch2_fs_alloc_debug_to_text(struct printbuf *out, struct bch_fs *c)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 24);

	struct bch_fs_allocator *a = &c->allocator;
	prt_printf(out, "capacity\t%llu\n",		c->capacity.capacity);
	prt_printf(out, "used\t%llu\n",			bch2_fs_usage_read_short(c).used);
	prt_printf(out, "reserved\t%llu\n",		c->capacity.reserved);
	prt_printf(out, "hidden\t%llu\n",		percpu_u64_get(&c->capacity.usage->hidden));
	prt_printf(out, "btree\t%llu\n",		percpu_u64_get(&c->capacity.usage->btree));
	prt_printf(out, "data\t%llu\n",			percpu_u64_get(&c->capacity.usage->data));
	prt_printf(out, "cached\t%llu\n",		percpu_u64_get(&c->capacity.usage->cached));
	prt_printf(out, "reserved\t%llu\n",		percpu_u64_get(&c->capacity.usage->reserved));
	prt_printf(out, "online_reserved\t%llu\n",	percpu_u64_get(&c->capacity.pcpu->online_reserved));

	prt_newline(out);
	prt_printf(out, "freelist_wait\t%s\n",			a->freelist_wait.list.first ? "waiting" : "empty");
	prt_printf(out, "btree reserve cache\t%u\n",		c->btree.reserve_cache.nr);
	prt_newline(out);
}

void bch2_dev_alloc_debug_to_text(struct printbuf *out, struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bch_fs_allocator *a = &c->allocator;
	struct bch_dev_usage_full stats = bch2_dev_usage_full_read(ca);
	unsigned nr[BCH_DATA_NR];

	memset(nr, 0, sizeof(nr));

	for (unsigned i = 0; i < ARRAY_SIZE(a->open_buckets); i++)
		nr[a->open_buckets[i].data_type]++;

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

static void dev_alloc_debug_header(struct printbuf *out, struct bch_dev *ca)
{
	prt_printf(out, "Dev %s (%u): %s",
		   ca->name, ca->dev_idx,
		   bch2_member_states[ca->mi.state]);
	if (!bch2_dev_is_online(ca))
		prt_str(out, " (offline)");
	prt_newline(out);

	prt_printf(out, "Data allowed:\t");
	if (ca->mi.data_allowed)
		prt_bitflags(out, __bch2_data_types, ca->mi.data_allowed);
	else
		prt_printf(out, "(none)");
	prt_newline(out);
	scoped_guard(printbuf_indent, out)
		bch2_dev_alloc_debug_to_text(out, ca);
	prt_newline(out);
}

static inline bool dev_may_alloc(struct bch_fs *c, struct bch_dev *ca, struct alloc_request *req)
{
	if ((req->flags & BCH_WRITE_only_specified_devs) &&
	    req->target &&
	    !test_bit(ca->dev_idx, bch2_target_to_mask(c, req->target)->d))
		return false;

	return ca->mi.state == BCH_MEMBER_STATE_rw &&
		bch2_dev_is_online(ca) &&
		(ca->mi.data_allowed & BIT(req->data_type));
}

static void alloc_trace_to_text(struct printbuf *out, struct bch_fs *c,
			       struct alloc_trace *trace)
{
	if (!trace->nr)
		return;

	unsigned start = trace->nr > ARRAY_SIZE(trace->entries)
		? trace->nr - ARRAY_SIZE(trace->entries) : 0;

	prt_printf(out, "Allocation attempts (%u total):\n", trace->nr);
	scoped_guard(printbuf_indent, out)
		for (unsigned i = start; i < trace->nr; i++) {
			struct alloc_trace_entry *e =
				&trace->entries[i % ARRAY_SIZE(trace->entries)];

			prt_printf(out, "dev %u -> %s\n",
				   e->dev,
				   e->err ? bch2_err_str(e->err) : "ok");
		}
}

static noinline void bch2_print_allocator_stuck(struct bch_fs *c, struct alloc_request *req, int err)
{
	CLASS(printbuf, buf)();

	prt_printf(&buf, "Allocator stuck? Waited for %u seconds, err %s\n",
		   c->opts.allocator_stuck_timeout,
		   bch2_err_str(err));

	if (req) {
		printbuf_tabstop_push(&buf, 16);
		prt_str(&buf, "Allocation:\n");
		guard(printbuf_indent)(&buf);
		prt_printf(&buf, "nr_replicas:\t%u\n", req->nr_replicas);
		prt_str(&buf, "target:\t");
		bch2_target_to_text(&buf, c, req->target);
		prt_newline(&buf);

		prt_printf(&buf, "watermark:\t%s\n", bch2_watermarks[req->watermark]);
		prt_printf(&buf, "data_type:\t%s\n", __bch2_data_types[req->data_type]);

		prt_str(&buf, "flags:\t");
		prt_bitflags(&buf, bch2_write_flags, req->flags);
		prt_newline(&buf);

		if (req->devs_have && req->devs_have->nr) {
			prt_printf(&buf, "devs_have:\t");
			bch2_devs_list_to_text(&buf, c, req->devs_have);
			prt_newline(&buf);
		}

		alloc_trace_to_text(&buf, c, &req->trace);
		prt_newline(&buf);
	}

	if (err == -BCH_ERR_bucket_alloc_blocked) {
		prt_printf(&buf, "Allocator debug:\n");
		scoped_guard(printbuf_indent, &buf)
			bch2_fs_alloc_debug_to_text(&buf, c);
		prt_newline(&buf);

		bch2_printbuf_make_room(&buf, 4096);

		scoped_guard(rcu) {
			guard(printbuf_atomic)(&buf);
			prt_printf(&buf, "Devices elligible for allocation\n");
			for_each_member_device_rcu(c, ca, NULL)
				if (dev_may_alloc(c, ca, req))
					dev_alloc_debug_header(&buf, ca);

			prt_printf(&buf, "Devices inelligible for allocation\n");
			for_each_member_device_rcu(c, ca, NULL)
				if (!dev_may_alloc(c, ca, req))
					dev_alloc_debug_header(&buf, ca);
		}

		prt_printf(&buf, "Copygc debug:\n");
		scoped_guard(printbuf_indent, &buf)
			bch2_copygc_wait_to_text(&buf, c);
		prt_newline(&buf);
	}

	if (err == -BCH_ERR_open_bucket_alloc_blocked)
		bch2_fs_open_buckets_to_text(&buf, c);

	prt_printf(&buf, "Journal debug:\n");
	scoped_guard(printbuf_indent, &buf)
		bch2_journal_debug_to_text(&buf, &c->journal);

	bch2_print_str(c, KERN_ERR, buf.buf);
}

static inline unsigned allocator_wait_timeout(struct bch_fs *c)
{
	if (c->allocator.last_stuck &&
	    time_after(c->allocator.last_stuck + HZ * 60 * 2, jiffies))
		return 0;

	return c->opts.allocator_stuck_timeout * HZ;
}

void __bch2_wait_on_allocator(struct bch_fs *c, struct alloc_request *req,
			      int err, struct closure *cl)
{
	unsigned t = allocator_wait_timeout(c);

	if (t && closure_sync_timeout(cl, t)) {
		c->allocator.last_stuck = jiffies;
		bch2_print_allocator_stuck(c, req, err);
	}

	closure_sync(cl);
}
