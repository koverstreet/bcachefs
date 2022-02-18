// SPDX-License-Identifier: GPL-2.0
/*
 * Block multiqueue core code
 *
 * Copyright (C) 2013-2014 Jens Axboe
 * Copyright (C) 2013-2014 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/kmemleak.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/llist.h>
#include <linux/cpu.h>
#include <linux/cache.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/topology.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/crash_dump.h>
#include <linux/prefetch.h>
#include <linux/blk-crypto.h>

#include <trace/events/block.h>

#include <linux/blk-mq.h>
#include <linux/t10-pi.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-tag.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"

static DEFINE_PER_CPU(struct llist_head, blk_cpu_done);

static void blk_mq_poll_stats_start(struct request_queue *q);
static void blk_mq_poll_stats_fn(struct blk_stat_callback *cb);

static int blk_mq_poll_stats_bkt(const struct request *rq)
{
	int ddir, sectors, bucket;

	ddir = rq_data_dir(rq);
	sectors = blk_rq_stats_sectors(rq);

	bucket = ddir + 2 * ilog2(sectors);

	if (bucket < 0)
		return -1;
	else if (bucket >= BLK_MQ_POLL_STATS_BKTS)
		return ddir + BLK_MQ_POLL_STATS_BKTS - 2;

	return bucket;
}

#define BLK_QC_T_SHIFT		16
#define BLK_QC_T_INTERNAL	(1U << 31)

static inline struct blk_mq_hw_ctx *blk_qc_to_hctx(struct request_queue *q,
		blk_qc_t qc)
{
	return q->queue_hw_ctx[(qc & ~BLK_QC_T_INTERNAL) >> BLK_QC_T_SHIFT];
}

static inline struct request *blk_qc_to_rq(struct blk_mq_hw_ctx *hctx,
		blk_qc_t qc)
{
	unsigned int tag = qc & ((1U << BLK_QC_T_SHIFT) - 1);

	if (qc & BLK_QC_T_INTERNAL)
		return blk_mq_tag_to_rq(hctx->sched_tags, tag);
	return blk_mq_tag_to_rq(hctx->tags, tag);
}

static inline blk_qc_t blk_rq_to_qc(struct request *rq)
{
	return (rq->mq_hctx->queue_num << BLK_QC_T_SHIFT) |
		(rq->tag != -1 ?
		 rq->tag : (rq->internal_tag | BLK_QC_T_INTERNAL));
}

/*
 * Check if any of the ctx, dispatch list or elevator
 * have pending work in this hardware queue.
 */
static bool blk_mq_hctx_has_pending(struct blk_mq_hw_ctx *hctx)
{
	return !list_empty_careful(&hctx->dispatch) ||
		sbitmap_any_bit_set(&hctx->ctx_map) ||
			blk_mq_sched_has_work(hctx);
}

/*
 * Mark this ctx as having pending work in this hardware queue
 */
static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
				     struct blk_mq_ctx *ctx)
{
	const int bit = ctx->index_hw[hctx->type];

	if (!sbitmap_test_bit(&hctx->ctx_map, bit))
		sbitmap_set_bit(&hctx->ctx_map, bit);
}

static void blk_mq_hctx_clear_pending(struct blk_mq_hw_ctx *hctx,
				      struct blk_mq_ctx *ctx)
{
	const int bit = ctx->index_hw[hctx->type];

	sbitmap_clear_bit(&hctx->ctx_map, bit);
}

struct mq_inflight {
	struct block_device *part;
	unsigned int inflight[2];
};

static bool blk_mq_check_inflight(struct blk_mq_hw_ctx *hctx,
				  struct request *rq, void *priv,
				  bool reserved)
{
	struct mq_inflight *mi = priv;

	if ((!mi->part->bd_partno || rq->part == mi->part) &&
	    blk_mq_rq_state(rq) == MQ_RQ_IN_FLIGHT)
		mi->inflight[rq_data_dir(rq)]++;

	return true;
}

unsigned int blk_mq_in_flight(struct request_queue *q,
		struct block_device *part)
{
	struct mq_inflight mi = { .part = part };

	blk_mq_queue_tag_busy_iter(q, blk_mq_check_inflight, &mi);

	return mi.inflight[0] + mi.inflight[1];
}

void blk_mq_in_flight_rw(struct request_queue *q, struct block_device *part,
		unsigned int inflight[2])
{
	struct mq_inflight mi = { .part = part };

	blk_mq_queue_tag_busy_iter(q, blk_mq_check_inflight, &mi);
	inflight[0] = mi.inflight[0];
	inflight[1] = mi.inflight[1];
}

void blk_freeze_queue_start(struct request_queue *q)
{
	mutex_lock(&q->mq_freeze_lock);
	if (++q->mq_freeze_depth == 1) {
		percpu_ref_kill(&q->q_usage_counter);
		mutex_unlock(&q->mq_freeze_lock);
		if (queue_is_mq(q))
			blk_mq_run_hw_queues(q, false);
	} else {
		mutex_unlock(&q->mq_freeze_lock);
	}
}
EXPORT_SYMBOL_GPL(blk_freeze_queue_start);

void blk_mq_freeze_queue_wait(struct request_queue *q)
{
	wait_event(q->mq_freeze_wq, percpu_ref_is_zero(&q->q_usage_counter));
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue_wait);

int blk_mq_freeze_queue_wait_timeout(struct request_queue *q,
				     unsigned long timeout)
{
	return wait_event_timeout(q->mq_freeze_wq,
					percpu_ref_is_zero(&q->q_usage_counter),
					timeout);
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue_wait_timeout);

/*
 * Guarantee no request is in use, so we can change any data structure of
 * the queue afterward.
 */
void blk_freeze_queue(struct request_queue *q)
{
	/*
	 * In the !blk_mq case we are only calling this to kill the
	 * q_usage_counter, otherwise this increases the freeze depth
	 * and waits for it to return to zero.  For this reason there is
	 * no blk_unfreeze_queue(), and blk_freeze_queue() is not
	 * exported to drivers as the only user for unfreeze is blk_mq.
	 */
	blk_freeze_queue_start(q);
	blk_mq_freeze_queue_wait(q);
}

void blk_mq_freeze_queue(struct request_queue *q)
{
	/*
	 * ...just an alias to keep freeze and unfreeze actions balanced
	 * in the blk_mq_* namespace
	 */
	blk_freeze_queue(q);
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue);

void __blk_mq_unfreeze_queue(struct request_queue *q, bool force_atomic)
{
	mutex_lock(&q->mq_freeze_lock);
	if (force_atomic)
		q->q_usage_counter.data->force_atomic = true;
	q->mq_freeze_depth--;
	WARN_ON_ONCE(q->mq_freeze_depth < 0);
	if (!q->mq_freeze_depth) {
		percpu_ref_resurrect(&q->q_usage_counter);
		wake_up_all(&q->mq_freeze_wq);
	}
	mutex_unlock(&q->mq_freeze_lock);
}

void blk_mq_unfreeze_queue(struct request_queue *q)
{
	__blk_mq_unfreeze_queue(q, false);
}
EXPORT_SYMBOL_GPL(blk_mq_unfreeze_queue);

/*
 * FIXME: replace the scsi_internal_device_*block_nowait() calls in the
 * mpt3sas driver such that this function can be removed.
 */
void blk_mq_quiesce_queue_nowait(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(&q->queue_lock, flags);
	if (!q->quiesce_depth++)
		blk_queue_flag_set(QUEUE_FLAG_QUIESCED, q);
	spin_unlock_irqrestore(&q->queue_lock, flags);
}
EXPORT_SYMBOL_GPL(blk_mq_quiesce_queue_nowait);

/**
 * blk_mq_wait_quiesce_done() - wait until in-progress quiesce is done
 * @q: request queue.
 *
 * Note: it is driver's responsibility for making sure that quiesce has
 * been started.
 */
void blk_mq_wait_quiesce_done(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;
	bool rcu = false;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (hctx->flags & BLK_MQ_F_BLOCKING)
			synchronize_srcu(hctx->srcu);
		else
			rcu = true;
	}
	if (rcu)
		synchronize_rcu();
}
EXPORT_SYMBOL_GPL(blk_mq_wait_quiesce_done);

/**
 * blk_mq_quiesce_queue() - wait until all ongoing dispatches have finished
 * @q: request queue.
 *
 * Note: this function does not prevent that the struct request end_io()
 * callback function is invoked. Once this function is returned, we make
 * sure no dispatch can happen until the queue is unquiesced via
 * blk_mq_unquiesce_queue().
 */
void blk_mq_quiesce_queue(struct request_queue *q)
{
	blk_mq_quiesce_queue_nowait(q);
	blk_mq_wait_quiesce_done(q);
}
EXPORT_SYMBOL_GPL(blk_mq_quiesce_queue);

/*
 * blk_mq_unquiesce_queue() - counterpart of blk_mq_quiesce_queue()
 * @q: request queue.
 *
 * This function recovers queue into the state before quiescing
 * which is done by blk_mq_quiesce_queue.
 */
void blk_mq_unquiesce_queue(struct request_queue *q)
{
	unsigned long flags;
	bool run_queue = false;

	spin_lock_irqsave(&q->queue_lock, flags);
	if (WARN_ON_ONCE(q->quiesce_depth <= 0)) {
		;
	} else if (!--q->quiesce_depth) {
		blk_queue_flag_clear(QUEUE_FLAG_QUIESCED, q);
		run_queue = true;
	}
	spin_unlock_irqrestore(&q->queue_lock, flags);

	/* dispatch requests which are inserted during quiescing */
	if (run_queue)
		blk_mq_run_hw_queues(q, true);
}
EXPORT_SYMBOL_GPL(blk_mq_unquiesce_queue);

void blk_mq_wake_waiters(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i)
		if (blk_mq_hw_queue_mapped(hctx))
			blk_mq_tag_wakeup_all(hctx->tags, true);
}

static struct request *blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
		struct blk_mq_tags *tags, unsigned int tag, u64 alloc_time_ns)
{
	struct blk_mq_ctx *ctx = data->ctx;
	struct blk_mq_hw_ctx *hctx = data->hctx;
	struct request_queue *q = data->q;
	struct request *rq = tags->static_rqs[tag];

	rq->q = q;
	rq->mq_ctx = ctx;
	rq->mq_hctx = hctx;
	rq->cmd_flags = data->cmd_flags;

	if (data->flags & BLK_MQ_REQ_PM)
		data->rq_flags |= RQF_PM;
	if (blk_queue_io_stat(q))
		data->rq_flags |= RQF_IO_STAT;
	rq->rq_flags = data->rq_flags;

	if (!(data->rq_flags & RQF_ELV)) {
		rq->tag = tag;
		rq->internal_tag = BLK_MQ_NO_TAG;
	} else {
		rq->tag = BLK_MQ_NO_TAG;
		rq->internal_tag = tag;
	}
	rq->timeout = 0;

	if (blk_mq_need_time_stamp(rq))
		rq->start_time_ns = ktime_get_ns();
	else
		rq->start_time_ns = 0;
	rq->rq_disk = NULL;
	rq->part = NULL;
#ifdef CONFIG_BLK_RQ_ALLOC_TIME
	rq->alloc_time_ns = alloc_time_ns;
#endif
	rq->io_start_time_ns = 0;
	rq->stats_sectors = 0;
	rq->nr_phys_segments = 0;
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	rq->nr_integrity_segments = 0;
#endif
	rq->end_io = NULL;
	rq->end_io_data = NULL;

	blk_crypto_rq_set_defaults(rq);
	INIT_LIST_HEAD(&rq->queuelist);
	/* tag was already set */
	WRITE_ONCE(rq->deadline, 0);
	refcount_set(&rq->ref, 1);

	if (rq->rq_flags & RQF_ELV) {
		struct elevator_queue *e = data->q->elevator;

		rq->elv.icq = NULL;
		INIT_HLIST_NODE(&rq->hash);
		RB_CLEAR_NODE(&rq->rb_node);

		if (!op_is_flush(data->cmd_flags) &&
		    e->type->ops.prepare_request) {
			if (e->type->icq_cache)
				blk_mq_sched_assign_ioc(rq);

			e->type->ops.prepare_request(rq);
			rq->rq_flags |= RQF_ELVPRIV;
		}
	}

	return rq;
}

static inline struct request *
__blk_mq_alloc_requests_batch(struct blk_mq_alloc_data *data,
		u64 alloc_time_ns)
{
	unsigned int tag, tag_offset;
	struct blk_mq_tags *tags;
	struct request *rq;
	unsigned long tag_mask;
	int i, nr = 0;

	tag_mask = blk_mq_get_tags(data, data->nr_tags, &tag_offset);
	if (unlikely(!tag_mask))
		return NULL;

	tags = blk_mq_tags_from_data(data);
	for (i = 0; tag_mask; i++) {
		if (!(tag_mask & (1UL << i)))
			continue;
		tag = tag_offset + i;
		prefetch(tags->static_rqs[tag]);
		tag_mask &= ~(1UL << i);
		rq = blk_mq_rq_ctx_init(data, tags, tag, alloc_time_ns);
		rq_list_add(data->cached_rq, rq);
		nr++;
	}
	/* caller already holds a reference, add for remainder */
	percpu_ref_get_many(&data->q->q_usage_counter, nr - 1);
	data->nr_tags -= nr;

	return rq_list_pop(data->cached_rq);
}

static struct request *__blk_mq_alloc_requests(struct blk_mq_alloc_data *data)
{
	struct request_queue *q = data->q;
	u64 alloc_time_ns = 0;
	struct request *rq;
	unsigned int tag;

	/* alloc_time includes depth and tag waits */
	if (blk_queue_rq_alloc_time(q))
		alloc_time_ns = ktime_get_ns();

	if (data->cmd_flags & REQ_NOWAIT)
		data->flags |= BLK_MQ_REQ_NOWAIT;

	if (q->elevator) {
		struct elevator_queue *e = q->elevator;

		data->rq_flags |= RQF_ELV;

		/*
		 * Flush/passthrough requests are special and go directly to the
		 * dispatch list. Don't include reserved tags in the
		 * limiting, as it isn't useful.
		 */
		if (!op_is_flush(data->cmd_flags) &&
		    !blk_op_is_passthrough(data->cmd_flags) &&
		    e->type->ops.limit_depth &&
		    !(data->flags & BLK_MQ_REQ_RESERVED))
			e->type->ops.limit_depth(data->cmd_flags, data);
	}

retry:
	data->ctx = blk_mq_get_ctx(q);
	data->hctx = blk_mq_map_queue(q, data->cmd_flags, data->ctx);
	if (!(data->rq_flags & RQF_ELV))
		blk_mq_tag_busy(data->hctx);

	/*
	 * Try batched alloc if we want more than 1 tag.
	 */
	if (data->nr_tags > 1) {
		rq = __blk_mq_alloc_requests_batch(data, alloc_time_ns);
		if (rq)
			return rq;
		data->nr_tags = 1;
	}

	/*
	 * Waiting allocations only fail because of an inactive hctx.  In that
	 * case just retry the hctx assignment and tag allocation as CPU hotplug
	 * should have migrated us to an online CPU by now.
	 */
	tag = blk_mq_get_tag(data);
	if (tag == BLK_MQ_NO_TAG) {
		if (data->flags & BLK_MQ_REQ_NOWAIT)
			return NULL;
		/*
		 * Give up the CPU and sleep for a random short time to
		 * ensure that thread using a realtime scheduling class
		 * are migrated off the CPU, and thus off the hctx that
		 * is going away.
		 */
		msleep(3);
		goto retry;
	}

	return blk_mq_rq_ctx_init(data, blk_mq_tags_from_data(data), tag,
					alloc_time_ns);
}

struct request *blk_mq_alloc_request(struct request_queue *q, unsigned int op,
		blk_mq_req_flags_t flags)
{
	struct blk_mq_alloc_data data = {
		.q		= q,
		.flags		= flags,
		.cmd_flags	= op,
		.nr_tags	= 1,
	};
	struct request *rq;
	int ret;

	ret = blk_queue_enter(q, flags);
	if (ret)
		return ERR_PTR(ret);

	rq = __blk_mq_alloc_requests(&data);
	if (!rq)
		goto out_queue_exit;
	rq->__data_len = 0;
	rq->__sector = (sector_t) -1;
	rq->bio = rq->biotail = NULL;
	return rq;
out_queue_exit:
	blk_queue_exit(q);
	return ERR_PTR(-EWOULDBLOCK);
}
EXPORT_SYMBOL(blk_mq_alloc_request);

struct request *blk_mq_alloc_request_hctx(struct request_queue *q,
	unsigned int op, blk_mq_req_flags_t flags, unsigned int hctx_idx)
{
	struct blk_mq_alloc_data data = {
		.q		= q,
		.flags		= flags,
		.cmd_flags	= op,
		.nr_tags	= 1,
	};
	u64 alloc_time_ns = 0;
	unsigned int cpu;
	unsigned int tag;
	int ret;

	/* alloc_time includes depth and tag waits */
	if (blk_queue_rq_alloc_time(q))
		alloc_time_ns = ktime_get_ns();

	/*
	 * If the tag allocator sleeps we could get an allocation for a
	 * different hardware context.  No need to complicate the low level
	 * allocator for this for the rare use case of a command tied to
	 * a specific queue.
	 */
	if (WARN_ON_ONCE(!(flags & (BLK_MQ_REQ_NOWAIT | BLK_MQ_REQ_RESERVED))))
		return ERR_PTR(-EINVAL);

	if (hctx_idx >= q->nr_hw_queues)
		return ERR_PTR(-EIO);

	ret = blk_queue_enter(q, flags);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * Check if the hardware context is actually mapped to anything.
	 * If not tell the caller that it should skip this queue.
	 */
	ret = -EXDEV;
	data.hctx = q->queue_hw_ctx[hctx_idx];
	if (!blk_mq_hw_queue_mapped(data.hctx))
		goto out_queue_exit;
	cpu = cpumask_first_and(data.hctx->cpumask, cpu_online_mask);
	data.ctx = __blk_mq_get_ctx(q, cpu);

	if (!q->elevator)
		blk_mq_tag_busy(data.hctx);
	else
		data.rq_flags |= RQF_ELV;

	ret = -EWOULDBLOCK;
	tag = blk_mq_get_tag(&data);
	if (tag == BLK_MQ_NO_TAG)
		goto out_queue_exit;
	return blk_mq_rq_ctx_init(&data, blk_mq_tags_from_data(&data), tag,
					alloc_time_ns);

out_queue_exit:
	blk_queue_exit(q);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(blk_mq_alloc_request_hctx);

static void __blk_mq_free_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
	const int sched_tag = rq->internal_tag;

	blk_crypto_free_request(rq);
	blk_pm_mark_last_busy(rq);
	rq->mq_hctx = NULL;
	if (rq->tag != BLK_MQ_NO_TAG)
		blk_mq_put_tag(hctx->tags, ctx, rq->tag);
	if (sched_tag != BLK_MQ_NO_TAG)
		blk_mq_put_tag(hctx->sched_tags, ctx, sched_tag);
	blk_mq_sched_restart(hctx);
	blk_queue_exit(q);
}

void blk_mq_free_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	if (rq->rq_flags & RQF_ELVPRIV) {
		struct elevator_queue *e = q->elevator;

		if (e->type->ops.finish_request)
			e->type->ops.finish_request(rq);
		if (rq->elv.icq) {
			put_io_context(rq->elv.icq->ioc);
			rq->elv.icq = NULL;
		}
	}

	if (rq->rq_flags & RQF_MQ_INFLIGHT)
		__blk_mq_dec_active_requests(hctx);

	if (unlikely(laptop_mode && !blk_rq_is_passthrough(rq)))
		laptop_io_completion(q->disk->bdi);

	rq_qos_done(q, rq);

	WRITE_ONCE(rq->state, MQ_RQ_IDLE);
	if (refcount_dec_and_test(&rq->ref))
		__blk_mq_free_request(rq);
}
EXPORT_SYMBOL_GPL(blk_mq_free_request);

void blk_mq_free_plug_rqs(struct blk_plug *plug)
{
	struct request *rq;

	while ((rq = rq_list_pop(&plug->cached_rq)) != NULL)
		blk_mq_free_request(rq);
}

static void req_bio_endio(struct request *rq, struct bio *bio,
			  unsigned int nbytes, blk_status_t error)
{
	if (unlikely(error)) {
		bio->bi_status = error;
	} else if (req_op(rq) == REQ_OP_ZONE_APPEND) {
		/*
		 * Partial zone append completions cannot be supported as the
		 * BIO fragments may end up not being written sequentially.
		 */
		if (bio->bi_iter.bi_size != nbytes)
			bio->bi_status = BLK_STS_IOERR;
		else
			bio->bi_iter.bi_sector = rq->__sector;
	}

	bio_advance(bio, nbytes);

	if (unlikely(rq->rq_flags & RQF_QUIET))
		bio_set_flag(bio, BIO_QUIET);
	/* don't actually finish bio if it's part of flush sequence */
	if (bio->bi_iter.bi_size == 0 && !(rq->rq_flags & RQF_FLUSH_SEQ))
		bio_endio(bio);
}

static void blk_account_io_completion(struct request *req, unsigned int bytes)
{
	if (req->part && blk_do_io_stat(req)) {
		const int sgrp = op_stat_group(req_op(req));

		part_stat_lock();
		part_stat_add(req->part, sectors[sgrp], bytes >> 9);
		part_stat_unlock();
	}
}

/**
 * blk_update_request - Complete multiple bytes without completing the request
 * @req:      the request being processed
 * @error:    block status code
 * @nr_bytes: number of bytes to complete for @req
 *
 * Description:
 *     Ends I/O on a number of bytes attached to @req, but doesn't complete
 *     the request structure even if @req doesn't have leftover.
 *     If @req has leftover, sets it up for the next range of segments.
 *
 *     Passing the result of blk_rq_bytes() as @nr_bytes guarantees
 *     %false return from this function.
 *
 * Note:
 *	The RQF_SPECIAL_PAYLOAD flag is ignored on purpose in this function
 *      except in the consistency check at the end of this function.
 *
 * Return:
 *     %false - this request doesn't have any more data
 *     %true  - this request has more data
 **/
bool blk_update_request(struct request *req, blk_status_t error,
		unsigned int nr_bytes)
{
	int total_bytes;

	trace_block_rq_complete(req, error, nr_bytes);

	if (!req->bio)
		return false;

#ifdef CONFIG_BLK_DEV_INTEGRITY
	if (blk_integrity_rq(req) && req_op(req) == REQ_OP_READ &&
	    error == BLK_STS_OK)
		req->q->integrity.profile->complete_fn(req, nr_bytes);
#endif

	if (unlikely(error && !blk_rq_is_passthrough(req) &&
		     !(req->rq_flags & RQF_QUIET)))
		blk_print_req_error(req, error);

	blk_account_io_completion(req, nr_bytes);

	total_bytes = 0;
	while (req->bio) {
		struct bio *bio = req->bio;
		unsigned bio_bytes = min(bio->bi_iter.bi_size, nr_bytes);

		if (bio_bytes == bio->bi_iter.bi_size)
			req->bio = bio->bi_next;

		/* Completion has already been traced */
		bio_clear_flag(bio, BIO_TRACE_COMPLETION);
		req_bio_endio(req, bio, bio_bytes, error);

		total_bytes += bio_bytes;
		nr_bytes -= bio_bytes;

		if (!nr_bytes)
			break;
	}

	/*
	 * completely done
	 */
	if (!req->bio) {
		/*
		 * Reset counters so that the request stacking driver
		 * can find how many bytes remain in the request
		 * later.
		 */
		req->__data_len = 0;
		return false;
	}

	req->__data_len -= total_bytes;

	/* update sector only for requests with clear definition of sector */
	if (!blk_rq_is_passthrough(req))
		req->__sector += total_bytes >> 9;

	/* mixed attributes always follow the first bio */
	if (req->rq_flags & RQF_MIXED_MERGE) {
		req->cmd_flags &= ~REQ_FAILFAST_MASK;
		req->cmd_flags |= req->bio->bi_opf & REQ_FAILFAST_MASK;
	}

	if (!(req->rq_flags & RQF_SPECIAL_PAYLOAD)) {
		/*
		 * If total number of sectors is less than the first segment
		 * size, something has gone terribly wrong.
		 */
		if (blk_rq_bytes(req) < blk_rq_cur_bytes(req)) {
			blk_dump_rq_flags(req, "request botched");
			req->__data_len = blk_rq_cur_bytes(req);
		}

		/* recalculate the number of segments */
		req->nr_phys_segments = blk_recalc_rq_segments(req);
	}

	return true;
}
EXPORT_SYMBOL_GPL(blk_update_request);

static inline void __blk_mq_end_request_acct(struct request *rq, u64 now)
{
	if (rq->rq_flags & RQF_STATS) {
		blk_mq_poll_stats_start(rq->q);
		blk_stat_add(rq, now);
	}

	blk_mq_sched_completed_request(rq, now);
	blk_account_io_done(rq, now);
}

inline void __blk_mq_end_request(struct request *rq, blk_status_t error)
{
	if (blk_mq_need_time_stamp(rq))
		__blk_mq_end_request_acct(rq, ktime_get_ns());

	if (rq->end_io) {
		rq_qos_done(rq->q, rq);
		rq->end_io(rq, error);
	} else {
		blk_mq_free_request(rq);
	}
}
EXPORT_SYMBOL(__blk_mq_end_request);

void blk_mq_end_request(struct request *rq, blk_status_t error)
{
	if (blk_update_request(rq, error, blk_rq_bytes(rq)))
		BUG();
	__blk_mq_end_request(rq, error);
}
EXPORT_SYMBOL(blk_mq_end_request);

#define TAG_COMP_BATCH		32

static inline void blk_mq_flush_tag_batch(struct blk_mq_hw_ctx *hctx,
					  int *tag_array, int nr_tags)
{
	struct request_queue *q = hctx->queue;

	/*
	 * All requests should have been marked as RQF_MQ_INFLIGHT, so
	 * update hctx->nr_active in batch
	 */
	if (hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED)
		__blk_mq_sub_active_requests(hctx, nr_tags);

	blk_mq_put_tags(hctx->tags, tag_array, nr_tags);
	percpu_ref_put_many(&q->q_usage_counter, nr_tags);
}

void blk_mq_end_request_batch(struct io_comp_batch *iob)
{
	int tags[TAG_COMP_BATCH], nr_tags = 0;
	struct blk_mq_hw_ctx *cur_hctx = NULL;
	struct request *rq;
	u64 now = 0;

	if (iob->need_ts)
		now = ktime_get_ns();

	while ((rq = rq_list_pop(&iob->req_list)) != NULL) {
		prefetch(rq->bio);
		prefetch(rq->rq_next);

		blk_update_request(rq, BLK_STS_OK, blk_rq_bytes(rq));
		if (iob->need_ts)
			__blk_mq_end_request_acct(rq, now);

		rq_qos_done(rq->q, rq);

		WRITE_ONCE(rq->state, MQ_RQ_IDLE);
		if (!refcount_dec_and_test(&rq->ref))
			continue;

		blk_crypto_free_request(rq);
		blk_pm_mark_last_busy(rq);

		if (nr_tags == TAG_COMP_BATCH || cur_hctx != rq->mq_hctx) {
			if (cur_hctx)
				blk_mq_flush_tag_batch(cur_hctx, tags, nr_tags);
			nr_tags = 0;
			cur_hctx = rq->mq_hctx;
		}
		tags[nr_tags++] = rq->tag;
	}

	if (nr_tags)
		blk_mq_flush_tag_batch(cur_hctx, tags, nr_tags);
}
EXPORT_SYMBOL_GPL(blk_mq_end_request_batch);

static void blk_complete_reqs(struct llist_head *list)
{
	struct llist_node *entry = llist_reverse_order(llist_del_all(list));
	struct request *rq, *next;

	llist_for_each_entry_safe(rq, next, entry, ipi_list)
		rq->q->mq_ops->complete(rq);
}

static __latent_entropy void blk_done_softirq(struct softirq_action *h)
{
	blk_complete_reqs(this_cpu_ptr(&blk_cpu_done));
}

static int blk_softirq_cpu_dead(unsigned int cpu)
{
	blk_complete_reqs(&per_cpu(blk_cpu_done, cpu));
	return 0;
}

static void __blk_mq_complete_request_remote(void *data)
{
	__raise_softirq_irqoff(BLOCK_SOFTIRQ);
}

static inline bool blk_mq_complete_need_ipi(struct request *rq)
{
	int cpu = raw_smp_processor_id();

	if (!IS_ENABLED(CONFIG_SMP) ||
	    !test_bit(QUEUE_FLAG_SAME_COMP, &rq->q->queue_flags))
		return false;
	/*
	 * With force threaded interrupts enabled, raising softirq from an SMP
	 * function call will always result in waking the ksoftirqd thread.
	 * This is probably worse than completing the request on a different
	 * cache domain.
	 */
	if (force_irqthreads())
		return false;

	/* same CPU or cache domain?  Complete locally */
	if (cpu == rq->mq_ctx->cpu ||
	    (!test_bit(QUEUE_FLAG_SAME_FORCE, &rq->q->queue_flags) &&
	     cpus_share_cache(cpu, rq->mq_ctx->cpu)))
		return false;

	/* don't try to IPI to an offline CPU */
	return cpu_online(rq->mq_ctx->cpu);
}

static void blk_mq_complete_send_ipi(struct request *rq)
{
	struct llist_head *list;
	unsigned int cpu;

	cpu = rq->mq_ctx->cpu;
	list = &per_cpu(blk_cpu_done, cpu);
	if (llist_add(&rq->ipi_list, list)) {
		INIT_CSD(&rq->csd, __blk_mq_complete_request_remote, rq);
		smp_call_function_single_async(cpu, &rq->csd);
	}
}

static void blk_mq_raise_softirq(struct request *rq)
{
	struct llist_head *list;

	preempt_disable();
	list = this_cpu_ptr(&blk_cpu_done);
	if (llist_add(&rq->ipi_list, list))
		raise_softirq(BLOCK_SOFTIRQ);
	preempt_enable();
}

bool blk_mq_complete_request_remote(struct request *rq)
{
	WRITE_ONCE(rq->state, MQ_RQ_COMPLETE);

	/*
	 * For a polled request, always complete locallly, it's pointless
	 * to redirect the completion.
	 */
	if (rq->cmd_flags & REQ_POLLED)
		return false;

	if (blk_mq_complete_need_ipi(rq)) {
		blk_mq_complete_send_ipi(rq);
		return true;
	}

	if (rq->q->nr_hw_queues == 1) {
		blk_mq_raise_softirq(rq);
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(blk_mq_complete_request_remote);

/**
 * blk_mq_complete_request - end I/O on a request
 * @rq:		the request being processed
 *
 * Description:
 *	Complete a request by scheduling the ->complete_rq operation.
 **/
void blk_mq_complete_request(struct request *rq)
{
	if (!blk_mq_complete_request_remote(rq))
		rq->q->mq_ops->complete(rq);
}
EXPORT_SYMBOL(blk_mq_complete_request);

static void hctx_unlock(struct blk_mq_hw_ctx *hctx, int srcu_idx)
	__releases(hctx->srcu)
{
	if (!(hctx->flags & BLK_MQ_F_BLOCKING))
		rcu_read_unlock();
	else
		srcu_read_unlock(hctx->srcu, srcu_idx);
}

static void hctx_lock(struct blk_mq_hw_ctx *hctx, int *srcu_idx)
	__acquires(hctx->srcu)
{
	if (!(hctx->flags & BLK_MQ_F_BLOCKING)) {
		/* shut up gcc false positive */
		*srcu_idx = 0;
		rcu_read_lock();
	} else
		*srcu_idx = srcu_read_lock(hctx->srcu);
}

/**
 * blk_mq_start_request - Start processing a request
 * @rq: Pointer to request to be started
 *
 * Function used by device drivers to notify the block layer that a request
 * is going to be processed now, so blk layer can do proper initializations
 * such as starting the timeout timer.
 */
void blk_mq_start_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	trace_block_rq_issue(rq);

	if (test_bit(QUEUE_FLAG_STATS, &q->queue_flags)) {
		u64 start_time;
#ifdef CONFIG_BLK_CGROUP
		if (rq->bio)
			start_time = bio_issue_time(&rq->bio->bi_issue);
		else
#endif
			start_time = ktime_get_ns();
		rq->io_start_time_ns = start_time;
		rq->stats_sectors = blk_rq_sectors(rq);
		rq->rq_flags |= RQF_STATS;
		rq_qos_issue(q, rq);
	}

	WARN_ON_ONCE(blk_mq_rq_state(rq) != MQ_RQ_IDLE);

	blk_add_timer(rq);
	WRITE_ONCE(rq->state, MQ_RQ_IN_FLIGHT);

#ifdef CONFIG_BLK_DEV_INTEGRITY
	if (blk_integrity_rq(rq) && req_op(rq) == REQ_OP_WRITE)
		q->integrity.profile->prepare_fn(rq);
#endif
	if (rq->bio && rq->bio->bi_opf & REQ_POLLED)
	        WRITE_ONCE(rq->bio->bi_cookie, blk_rq_to_qc(rq));
}
EXPORT_SYMBOL(blk_mq_start_request);

static void __blk_mq_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	blk_mq_put_driver_tag(rq);

	trace_block_rq_requeue(rq);
	rq_qos_requeue(q, rq);

	if (blk_mq_request_started(rq)) {
		WRITE_ONCE(rq->state, MQ_RQ_IDLE);
		rq->rq_flags &= ~RQF_TIMED_OUT;
	}
}

void blk_mq_requeue_request(struct request *rq, bool kick_requeue_list)
{
	__blk_mq_requeue_request(rq);

	/* this request will be re-inserted to io scheduler queue */
	blk_mq_sched_requeue_request(rq);

	blk_mq_add_to_requeue_list(rq, true, kick_requeue_list);
}
EXPORT_SYMBOL(blk_mq_requeue_request);

static void blk_mq_requeue_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, requeue_work.work);
	LIST_HEAD(rq_list);
	struct request *rq, *next;

	spin_lock_irq(&q->requeue_lock);
	list_splice_init(&q->requeue_list, &rq_list);
	spin_unlock_irq(&q->requeue_lock);

	list_for_each_entry_safe(rq, next, &rq_list, queuelist) {
		if (!(rq->rq_flags & (RQF_SOFTBARRIER | RQF_DONTPREP)))
			continue;

		rq->rq_flags &= ~RQF_SOFTBARRIER;
		list_del_init(&rq->queuelist);
		/*
		 * If RQF_DONTPREP, rq has contained some driver specific
		 * data, so insert it to hctx dispatch list to avoid any
		 * merge.
		 */
		if (rq->rq_flags & RQF_DONTPREP)
			blk_mq_request_bypass_insert(rq, false, false);
		else
			blk_mq_sched_insert_request(rq, true, false, false);
	}

	while (!list_empty(&rq_list)) {
		rq = list_entry(rq_list.next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		blk_mq_sched_insert_request(rq, false, false, false);
	}

	blk_mq_run_hw_queues(q, false);
}

void blk_mq_add_to_requeue_list(struct request *rq, bool at_head,
				bool kick_requeue_list)
{
	struct request_queue *q = rq->q;
	unsigned long flags;

	/*
	 * We abuse this flag that is otherwise used by the I/O scheduler to
	 * request head insertion from the workqueue.
	 */
	BUG_ON(rq->rq_flags & RQF_SOFTBARRIER);

	spin_lock_irqsave(&q->requeue_lock, flags);
	if (at_head) {
		rq->rq_flags |= RQF_SOFTBARRIER;
		list_add(&rq->queuelist, &q->requeue_list);
	} else {
		list_add_tail(&rq->queuelist, &q->requeue_list);
	}
	spin_unlock_irqrestore(&q->requeue_lock, flags);

	if (kick_requeue_list)
		blk_mq_kick_requeue_list(q);
}

void blk_mq_kick_requeue_list(struct request_queue *q)
{
	kblockd_mod_delayed_work_on(WORK_CPU_UNBOUND, &q->requeue_work, 0);
}
EXPORT_SYMBOL(blk_mq_kick_requeue_list);

void blk_mq_delay_kick_requeue_list(struct request_queue *q,
				    unsigned long msecs)
{
	kblockd_mod_delayed_work_on(WORK_CPU_UNBOUND, &q->requeue_work,
				    msecs_to_jiffies(msecs));
}
EXPORT_SYMBOL(blk_mq_delay_kick_requeue_list);

static bool blk_mq_rq_inflight(struct blk_mq_hw_ctx *hctx, struct request *rq,
			       void *priv, bool reserved)
{
	/*
	 * If we find a request that isn't idle and the queue matches,
	 * we know the queue is busy. Return false to stop the iteration.
	 */
	if (blk_mq_request_started(rq) && rq->q == hctx->queue) {
		bool *busy = priv;

		*busy = true;
		return false;
	}

	return true;
}

bool blk_mq_queue_inflight(struct request_queue *q)
{
	bool busy = false;

	blk_mq_queue_tag_busy_iter(q, blk_mq_rq_inflight, &busy);
	return busy;
}
EXPORT_SYMBOL_GPL(blk_mq_queue_inflight);

static void blk_mq_rq_timed_out(struct request *req, bool reserved)
{
	req->rq_flags |= RQF_TIMED_OUT;
	if (req->q->mq_ops->timeout) {
		enum blk_eh_timer_return ret;

		ret = req->q->mq_ops->timeout(req, reserved);
		if (ret == BLK_EH_DONE)
			return;
		WARN_ON_ONCE(ret != BLK_EH_RESET_TIMER);
	}

	blk_add_timer(req);
}

static bool blk_mq_req_expired(struct request *rq, unsigned long *next)
{
	unsigned long deadline;

	if (blk_mq_rq_state(rq) != MQ_RQ_IN_FLIGHT)
		return false;
	if (rq->rq_flags & RQF_TIMED_OUT)
		return false;

	deadline = READ_ONCE(rq->deadline);
	if (time_after_eq(jiffies, deadline))
		return true;

	if (*next == 0)
		*next = deadline;
	else if (time_after(*next, deadline))
		*next = deadline;
	return false;
}

void blk_mq_put_rq_ref(struct request *rq)
{
	if (is_flush_rq(rq))
		rq->end_io(rq, 0);
	else if (refcount_dec_and_test(&rq->ref))
		__blk_mq_free_request(rq);
}

static bool blk_mq_check_expired(struct blk_mq_hw_ctx *hctx,
		struct request *rq, void *priv, bool reserved)
{
	unsigned long *next = priv;

	/*
	 * blk_mq_queue_tag_busy_iter() has locked the request, so it cannot
	 * be reallocated underneath the timeout handler's processing, then
	 * the expire check is reliable. If the request is not expired, then
	 * it was completed and reallocated as a new request after returning
	 * from blk_mq_check_expired().
	 */
	if (blk_mq_req_expired(rq, next))
		blk_mq_rq_timed_out(rq, reserved);
	return true;
}

static void blk_mq_timeout_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, timeout_work);
	unsigned long next = 0;
	struct blk_mq_hw_ctx *hctx;
	int i;

	/* A deadlock might occur if a request is stuck requiring a
	 * timeout at the same time a queue freeze is waiting
	 * completion, since the timeout code would not be able to
	 * acquire the queue reference here.
	 *
	 * That's why we don't use blk_queue_enter here; instead, we use
	 * percpu_ref_tryget directly, because we need to be able to
	 * obtain a reference even in the short window between the queue
	 * starting to freeze, by dropping the first reference in
	 * blk_freeze_queue_start, and the moment the last request is
	 * consumed, marked by the instant q_usage_counter reaches
	 * zero.
	 */
	if (!percpu_ref_tryget(&q->q_usage_counter))
		return;

	blk_mq_queue_tag_busy_iter(q, blk_mq_check_expired, &next);

	if (next != 0) {
		mod_timer(&q->timeout, next);
	} else {
		/*
		 * Request timeouts are handled as a forward rolling timer. If
		 * we end up here it means that no requests are pending and
		 * also that no request has been pending for a while. Mark
		 * each hctx as idle.
		 */
		queue_for_each_hw_ctx(q, hctx, i) {
			/* the hctx may be unmapped, so check it here */
			if (blk_mq_hw_queue_mapped(hctx))
				blk_mq_tag_idle(hctx);
		}
	}
	blk_queue_exit(q);
}

struct flush_busy_ctx_data {
	struct blk_mq_hw_ctx *hctx;
	struct list_head *list;
};

static bool flush_busy_ctx(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_busy_ctx_data *flush_data = data;
	struct blk_mq_hw_ctx *hctx = flush_data->hctx;
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];
	enum hctx_type type = hctx->type;

	spin_lock(&ctx->lock);
	list_splice_tail_init(&ctx->rq_lists[type], flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&ctx->lock);
	return true;
}

/*
 * Process software queues that have been marked busy, splicing them
 * to the for-dispatch
 */
void blk_mq_flush_busy_ctxs(struct blk_mq_hw_ctx *hctx, struct list_head *list)
{
	struct flush_busy_ctx_data data = {
		.hctx = hctx,
		.list = list,
	};

	sbitmap_for_each_set(&hctx->ctx_map, flush_busy_ctx, &data);
}
EXPORT_SYMBOL_GPL(blk_mq_flush_busy_ctxs);

struct dispatch_rq_data {
	struct blk_mq_hw_ctx *hctx;
	struct request *rq;
};

static bool dispatch_rq_from_ctx(struct sbitmap *sb, unsigned int bitnr,
		void *data)
{
	struct dispatch_rq_data *dispatch_data = data;
	struct blk_mq_hw_ctx *hctx = dispatch_data->hctx;
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];
	enum hctx_type type = hctx->type;

	spin_lock(&ctx->lock);
	if (!list_empty(&ctx->rq_lists[type])) {
		dispatch_data->rq = list_entry_rq(ctx->rq_lists[type].next);
		list_del_init(&dispatch_data->rq->queuelist);
		if (list_empty(&ctx->rq_lists[type]))
			sbitmap_clear_bit(sb, bitnr);
	}
	spin_unlock(&ctx->lock);

	return !dispatch_data->rq;
}

struct request *blk_mq_dequeue_from_ctx(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_ctx *start)
{
	unsigned off = start ? start->index_hw[hctx->type] : 0;
	struct dispatch_rq_data data = {
		.hctx = hctx,
		.rq   = NULL,
	};

	__sbitmap_for_each_set(&hctx->ctx_map, off,
			       dispatch_rq_from_ctx, &data);

	return data.rq;
}

static bool __blk_mq_alloc_driver_tag(struct request *rq)
{
	struct sbitmap_queue *bt = &rq->mq_hctx->tags->bitmap_tags;
	unsigned int tag_offset = rq->mq_hctx->tags->nr_reserved_tags;
	int tag;

	blk_mq_tag_busy(rq->mq_hctx);

	if (blk_mq_tag_is_reserved(rq->mq_hctx->sched_tags, rq->internal_tag)) {
		bt = &rq->mq_hctx->tags->breserved_tags;
		tag_offset = 0;
	} else {
		if (!hctx_may_queue(rq->mq_hctx, bt))
			return false;
	}

	tag = __sbitmap_queue_get(bt);
	if (tag == BLK_MQ_NO_TAG)
		return false;

	rq->tag = tag + tag_offset;
	return true;
}

bool __blk_mq_get_driver_tag(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	if (rq->tag == BLK_MQ_NO_TAG && !__blk_mq_alloc_driver_tag(rq))
		return false;

	if ((hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED) &&
			!(rq->rq_flags & RQF_MQ_INFLIGHT)) {
		rq->rq_flags |= RQF_MQ_INFLIGHT;
		__blk_mq_inc_active_requests(hctx);
	}
	hctx->tags->rqs[rq->tag] = rq;
	return true;
}

static int blk_mq_dispatch_wake(wait_queue_entry_t *wait, unsigned mode,
				int flags, void *key)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(wait, struct blk_mq_hw_ctx, dispatch_wait);

	spin_lock(&hctx->dispatch_wait_lock);
	if (!list_empty(&wait->entry)) {
		struct sbitmap_queue *sbq;

		list_del_init(&wait->entry);
		sbq = &hctx->tags->bitmap_tags;
		atomic_dec(&sbq->ws_active);
	}
	spin_unlock(&hctx->dispatch_wait_lock);

	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

/*
 * Mark us waiting for a tag. For shared tags, this involves hooking us into
 * the tag wakeups. For non-shared tags, we can simply mark us needing a
 * restart. For both cases, take care to check the condition again after
 * marking us as waiting.
 */
static bool blk_mq_mark_tag_wait(struct blk_mq_hw_ctx *hctx,
				 struct request *rq)
{
	struct sbitmap_queue *sbq = &hctx->tags->bitmap_tags;
	struct wait_queue_head *wq;
	wait_queue_entry_t *wait;
	bool ret;

	if (!(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
		blk_mq_sched_mark_restart_hctx(hctx);

		/*
		 * It's possible that a tag was freed in the window between the
		 * allocation failure and adding the hardware queue to the wait
		 * queue.
		 *
		 * Don't clear RESTART here, someone else could have set it.
		 * At most this will cost an extra queue run.
		 */
		return blk_mq_get_driver_tag(rq);
	}

	wait = &hctx->dispatch_wait;
	if (!list_empty_careful(&wait->entry))
		return false;

	wq = &bt_wait_ptr(sbq, hctx)->wait;

	spin_lock_irq(&wq->lock);
	spin_lock(&hctx->dispatch_wait_lock);
	if (!list_empty(&wait->entry)) {
		spin_unlock(&hctx->dispatch_wait_lock);
		spin_unlock_irq(&wq->lock);
		return false;
	}

	atomic_inc(&sbq->ws_active);
	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(wq, wait);

	/*
	 * It's possible that a tag was freed in the window between the
	 * allocation failure and adding the hardware queue to the wait
	 * queue.
	 */
	ret = blk_mq_get_driver_tag(rq);
	if (!ret) {
		spin_unlock(&hctx->dispatch_wait_lock);
		spin_unlock_irq(&wq->lock);
		return false;
	}

	/*
	 * We got a tag, remove ourselves from the wait queue to ensure
	 * someone else gets the wakeup.
	 */
	list_del_init(&wait->entry);
	atomic_dec(&sbq->ws_active);
	spin_unlock(&hctx->dispatch_wait_lock);
	spin_unlock_irq(&wq->lock);

	return true;
}

#define BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT  8
#define BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR  4
/*
 * Update dispatch busy with the Exponential Weighted Moving Average(EWMA):
 * - EWMA is one simple way to compute running average value
 * - weight(7/8 and 1/8) is applied so that it can decrease exponentially
 * - take 4 as factor for avoiding to get too small(0) result, and this
 *   factor doesn't matter because EWMA decreases exponentially
 */
static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
	unsigned int ewma;

	ewma = hctx->dispatch_busy;

	if (!ewma && !busy)
		return;

	ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
	if (busy)
		ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
	ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

	hctx->dispatch_busy = ewma;
}

#define BLK_MQ_RESOURCE_DELAY	3		/* ms units */

static void blk_mq_handle_dev_resource(struct request *rq,
				       struct list_head *list)
{
	struct request *next =
		list_first_entry_or_null(list, struct request, queuelist);

	/*
	 * If an I/O scheduler has been configured and we got a driver tag for
	 * the next request already, free it.
	 */
	if (next)
		blk_mq_put_driver_tag(next);

	list_add(&rq->queuelist, list);
	__blk_mq_requeue_request(rq);
}

static void blk_mq_handle_zone_resource(struct request *rq,
					struct list_head *zone_list)
{
	/*
	 * If we end up here it is because we cannot dispatch a request to a
	 * specific zone due to LLD level zone-write locking or other zone
	 * related resource not being available. In this case, set the request
	 * aside in zone_list for retrying it later.
	 */
	list_add(&rq->queuelist, zone_list);
	__blk_mq_requeue_request(rq);
}

enum prep_dispatch {
	PREP_DISPATCH_OK,
	PREP_DISPATCH_NO_TAG,
	PREP_DISPATCH_NO_BUDGET,
};

static enum prep_dispatch blk_mq_prep_dispatch_rq(struct request *rq,
						  bool need_budget)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
	int budget_token = -1;

	if (need_budget) {
		budget_token = blk_mq_get_dispatch_budget(rq->q);
		if (budget_token < 0) {
			blk_mq_put_driver_tag(rq);
			return PREP_DISPATCH_NO_BUDGET;
		}
		blk_mq_set_rq_budget_token(rq, budget_token);
	}

	if (!blk_mq_get_driver_tag(rq)) {
		/*
		 * The initial allocation attempt failed, so we need to
		 * rerun the hardware queue when a tag is freed. The
		 * waitqueue takes care of that. If the queue is run
		 * before we add this entry back on the dispatch list,
		 * we'll re-run it below.
		 */
		if (!blk_mq_mark_tag_wait(hctx, rq)) {
			/*
			 * All budgets not got from this function will be put
			 * together during handling partial dispatch
			 */
			if (need_budget)
				blk_mq_put_dispatch_budget(rq->q, budget_token);
			return PREP_DISPATCH_NO_TAG;
		}
	}

	return PREP_DISPATCH_OK;
}

/* release all allocated budgets before calling to blk_mq_dispatch_rq_list */
static void blk_mq_release_budgets(struct request_queue *q,
		struct list_head *list)
{
	struct request *rq;

	list_for_each_entry(rq, list, queuelist) {
		int budget_token = blk_mq_get_rq_budget_token(rq);

		if (budget_token >= 0)
			blk_mq_put_dispatch_budget(q, budget_token);
	}
}

/*
 * Returns true if we did some work AND can potentially do more.
 */
bool blk_mq_dispatch_rq_list(struct blk_mq_hw_ctx *hctx, struct list_head *list,
			     unsigned int nr_budgets)
{
	enum prep_dispatch prep;
	struct request_queue *q = hctx->queue;
	struct request *rq, *nxt;
	int errors, queued;
	blk_status_t ret = BLK_STS_OK;
	LIST_HEAD(zone_list);
	bool needs_resource = false;

	if (list_empty(list))
		return false;

	/*
	 * Now process all the entries, sending them to the driver.
	 */
	errors = queued = 0;
	do {
		struct blk_mq_queue_data bd;

		rq = list_first_entry(list, struct request, queuelist);

		WARN_ON_ONCE(hctx != rq->mq_hctx);
		prep = blk_mq_prep_dispatch_rq(rq, !nr_budgets);
		if (prep != PREP_DISPATCH_OK)
			break;

		list_del_init(&rq->queuelist);

		bd.rq = rq;

		/*
		 * Flag last if we have no more requests, or if we have more
		 * but can't assign a driver tag to it.
		 */
		if (list_empty(list))
			bd.last = true;
		else {
			nxt = list_first_entry(list, struct request, queuelist);
			bd.last = !blk_mq_get_driver_tag(nxt);
		}

		/*
		 * once the request is queued to lld, no need to cover the
		 * budget any more
		 */
		if (nr_budgets)
			nr_budgets--;
		ret = q->mq_ops->queue_rq(hctx, &bd);
		switch (ret) {
		case BLK_STS_OK:
			queued++;
			break;
		case BLK_STS_RESOURCE:
			needs_resource = true;
			fallthrough;
		case BLK_STS_DEV_RESOURCE:
			blk_mq_handle_dev_resource(rq, list);
			goto out;
		case BLK_STS_ZONE_RESOURCE:
			/*
			 * Move the request to zone_list and keep going through
			 * the dispatch list to find more requests the drive can
			 * accept.
			 */
			blk_mq_handle_zone_resource(rq, &zone_list);
			needs_resource = true;
			break;
		default:
			errors++;
			blk_mq_end_request(rq, ret);
		}
	} while (!list_empty(list));
out:
	if (!list_empty(&zone_list))
		list_splice_tail_init(&zone_list, list);

	/* If we didn't flush the entire list, we could have told the driver
	 * there was more coming, but that turned out to be a lie.
	 */
	if ((!list_empty(list) || errors) && q->mq_ops->commit_rqs && queued)
		q->mq_ops->commit_rqs(hctx);
	/*
	 * Any items that need requeuing? Stuff them into hctx->dispatch,
	 * that is where we will continue on next queue run.
	 */
	if (!list_empty(list)) {
		bool needs_restart;
		/* For non-shared tags, the RESTART check will suffice */
		bool no_tag = prep == PREP_DISPATCH_NO_TAG &&
			(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED);

		if (nr_budgets)
			blk_mq_release_budgets(q, list);

		spin_lock(&hctx->lock);
		list_splice_tail_init(list, &hctx->dispatch);
		spin_unlock(&hctx->lock);

		/*
		 * Order adding requests to hctx->dispatch and checking
		 * SCHED_RESTART flag. The pair of this smp_mb() is the one
		 * in blk_mq_sched_restart(). Avoid restart code path to
		 * miss the new added requests to hctx->dispatch, meantime
		 * SCHED_RESTART is observed here.
		 */
		smp_mb();

		/*
		 * If SCHED_RESTART was set by the caller of this function and
		 * it is no longer set that means that it was cleared by another
		 * thread and hence that a queue rerun is needed.
		 *
		 * If 'no_tag' is set, that means that we failed getting
		 * a driver tag with an I/O scheduler attached. If our dispatch
		 * waitqueue is no longer active, ensure that we run the queue
		 * AFTER adding our entries back to the list.
		 *
		 * If no I/O scheduler has been configured it is possible that
		 * the hardware queue got stopped and restarted before requests
		 * were pushed back onto the dispatch list. Rerun the queue to
		 * avoid starvation. Notes:
		 * - blk_mq_run_hw_queue() checks whether or not a queue has
		 *   been stopped before rerunning a queue.
		 * - Some but not all block drivers stop a queue before
		 *   returning BLK_STS_RESOURCE. Two exceptions are scsi-mq
		 *   and dm-rq.
		 *
		 * If driver returns BLK_STS_RESOURCE and SCHED_RESTART
		 * bit is set, run queue after a delay to avoid IO stalls
		 * that could otherwise occur if the queue is idle.  We'll do
		 * similar if we couldn't get budget or couldn't lock a zone
		 * and SCHED_RESTART is set.
		 */
		needs_restart = blk_mq_sched_needs_restart(hctx);
		if (prep == PREP_DISPATCH_NO_BUDGET)
			needs_resource = true;
		if (!needs_restart ||
		    (no_tag && list_empty_careful(&hctx->dispatch_wait.entry)))
			blk_mq_run_hw_queue(hctx, true);
		else if (needs_restart && needs_resource)
			blk_mq_delay_run_hw_queue(hctx, BLK_MQ_RESOURCE_DELAY);

		blk_mq_update_dispatch_busy(hctx, true);
		return false;
	} else
		blk_mq_update_dispatch_busy(hctx, false);

	return (queued + errors) != 0;
}

/**
 * __blk_mq_run_hw_queue - Run a hardware queue.
 * @hctx: Pointer to the hardware queue to run.
 *
 * Send pending requests to the hardware.
 */
static void __blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	int srcu_idx;

	/*
	 * We can't run the queue inline with ints disabled. Ensure that
	 * we catch bad users of this early.
	 */
	WARN_ON_ONCE(in_interrupt());

	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	hctx_lock(hctx, &srcu_idx);
	blk_mq_sched_dispatch_requests(hctx);
	hctx_unlock(hctx, srcu_idx);
}

static inline int blk_mq_first_mapped_cpu(struct blk_mq_hw_ctx *hctx)
{
	int cpu = cpumask_first_and(hctx->cpumask, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(hctx->cpumask);
	return cpu;
}

/*
 * It'd be great if the workqueue API had a way to pass
 * in a mask and had some smarts for more clever placement.
 * For now we just round-robin here, switching for every
 * BLK_MQ_CPU_WORK_BATCH queued items.
 */
static int blk_mq_hctx_next_cpu(struct blk_mq_hw_ctx *hctx)
{
	bool tried = false;
	int next_cpu = hctx->next_cpu;

	if (hctx->queue->nr_hw_queues == 1)
		return WORK_CPU_UNBOUND;

	if (--hctx->next_cpu_batch <= 0) {
select_cpu:
		next_cpu = cpumask_next_and(next_cpu, hctx->cpumask,
				cpu_online_mask);
		if (next_cpu >= nr_cpu_ids)
			next_cpu = blk_mq_first_mapped_cpu(hctx);
		hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
	}

	/*
	 * Do unbound schedule if we can't find a online CPU for this hctx,
	 * and it should only happen in the path of handling CPU DEAD.
	 */
	if (!cpu_online(next_cpu)) {
		if (!tried) {
			tried = true;
			goto select_cpu;
		}

		/*
		 * Make sure to re-select CPU next time once after CPUs
		 * in hctx->cpumask become online again.
		 */
		hctx->next_cpu = next_cpu;
		hctx->next_cpu_batch = 1;
		return WORK_CPU_UNBOUND;
	}

	hctx->next_cpu = next_cpu;
	return next_cpu;
}

/**
 * __blk_mq_delay_run_hw_queue - Run (or schedule to run) a hardware queue.
 * @hctx: Pointer to the hardware queue to run.
 * @async: If we want to run the queue asynchronously.
 * @msecs: Milliseconds of delay to wait before running the queue.
 *
 * If !@async, try to run the queue now. Else, run the queue asynchronously and
 * with a delay of @msecs.
 */
static void __blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async,
					unsigned long msecs)
{
	if (unlikely(blk_mq_hctx_stopped(hctx)))
		return;

	if (!async && !(hctx->flags & BLK_MQ_F_BLOCKING)) {
		int cpu = get_cpu();
		if (cpumask_test_cpu(cpu, hctx->cpumask)) {
			__blk_mq_run_hw_queue(hctx);
			put_cpu();
			return;
		}

		put_cpu();
	}

	kblockd_mod_delayed_work_on(blk_mq_hctx_next_cpu(hctx), &hctx->run_work,
				    msecs_to_jiffies(msecs));
}

/**
 * blk_mq_delay_run_hw_queue - Run a hardware queue asynchronously.
 * @hctx: Pointer to the hardware queue to run.
 * @msecs: Milliseconds of delay to wait before running the queue.
 *
 * Run a hardware queue asynchronously with a delay of @msecs.
 */
void blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, unsigned long msecs)
{
	__blk_mq_delay_run_hw_queue(hctx, true, msecs);
}
EXPORT_SYMBOL(blk_mq_delay_run_hw_queue);

/**
 * blk_mq_run_hw_queue - Start to run a hardware queue.
 * @hctx: Pointer to the hardware queue to run.
 * @async: If we want to run the queue asynchronously.
 *
 * Check if the request queue is not in a quiesced state and if there are
 * pending requests to be sent. If this is true, run the queue to send requests
 * to hardware.
 */
void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
	int srcu_idx;
	bool need_run;

	/*
	 * When queue is quiesced, we may be switching io scheduler, or
	 * updating nr_hw_queues, or other things, and we can't run queue
	 * any more, even __blk_mq_hctx_has_pending() can't be called safely.
	 *
	 * And queue will be rerun in blk_mq_unquiesce_queue() if it is
	 * quiesced.
	 */
	hctx_lock(hctx, &srcu_idx);
	need_run = !blk_queue_quiesced(hctx->queue) &&
		blk_mq_hctx_has_pending(hctx);
	hctx_unlock(hctx, srcu_idx);

	if (need_run)
		__blk_mq_delay_run_hw_queue(hctx, async, 0);
}
EXPORT_SYMBOL(blk_mq_run_hw_queue);

/*
 * Is the request queue handled by an IO scheduler that does not respect
 * hardware queues when dispatching?
 */
static bool blk_mq_has_sqsched(struct request_queue *q)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.dispatch_request &&
	    !(e->type->elevator_features & ELEVATOR_F_MQ_AWARE))
		return true;
	return false;
}

/*
 * Return prefered queue to dispatch from (if any) for non-mq aware IO
 * scheduler.
 */
static struct blk_mq_hw_ctx *blk_mq_get_sq_hctx(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;

	/*
	 * If the IO scheduler does not respect hardware queues when
	 * dispatching, we just don't bother with multiple HW queues and
	 * dispatch from hctx for the current CPU since running multiple queues
	 * just causes lock contention inside the scheduler and pointless cache
	 * bouncing.
	 */
	hctx = blk_mq_map_queue_type(q, HCTX_TYPE_DEFAULT,
				     raw_smp_processor_id());
	if (!blk_mq_hctx_stopped(hctx))
		return hctx;
	return NULL;
}

/**
 * blk_mq_run_hw_queues - Run all hardware queues in a request queue.
 * @q: Pointer to the request queue to run.
 * @async: If we want to run the queue asynchronously.
 */
void blk_mq_run_hw_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx, *sq_hctx;
	int i;

	sq_hctx = NULL;
	if (blk_mq_has_sqsched(q))
		sq_hctx = blk_mq_get_sq_hctx(q);
	queue_for_each_hw_ctx(q, hctx, i) {
		if (blk_mq_hctx_stopped(hctx))
			continue;
		/*
		 * Dispatch from this hctx either if there's no hctx preferred
		 * by IO scheduler or if it has requests that bypass the
		 * scheduler.
		 */
		if (!sq_hctx || sq_hctx == hctx ||
		    !list_empty_careful(&hctx->dispatch))
			blk_mq_run_hw_queue(hctx, async);
	}
}
EXPORT_SYMBOL(blk_mq_run_hw_queues);

/**
 * blk_mq_delay_run_hw_queues - Run all hardware queues asynchronously.
 * @q: Pointer to the request queue to run.
 * @msecs: Milliseconds of delay to wait before running the queues.
 */
void blk_mq_delay_run_hw_queues(struct request_queue *q, unsigned long msecs)
{
	struct blk_mq_hw_ctx *hctx, *sq_hctx;
	int i;

	sq_hctx = NULL;
	if (blk_mq_has_sqsched(q))
		sq_hctx = blk_mq_get_sq_hctx(q);
	queue_for_each_hw_ctx(q, hctx, i) {
		if (blk_mq_hctx_stopped(hctx))
			continue;
		/*
		 * Dispatch from this hctx either if there's no hctx preferred
		 * by IO scheduler or if it has requests that bypass the
		 * scheduler.
		 */
		if (!sq_hctx || sq_hctx == hctx ||
		    !list_empty_careful(&hctx->dispatch))
			blk_mq_delay_run_hw_queue(hctx, msecs);
	}
}
EXPORT_SYMBOL(blk_mq_delay_run_hw_queues);

/**
 * blk_mq_queue_stopped() - check whether one or more hctxs have been stopped
 * @q: request queue.
 *
 * The caller is responsible for serializing this function against
 * blk_mq_{start,stop}_hw_queue().
 */
bool blk_mq_queue_stopped(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		if (blk_mq_hctx_stopped(hctx))
			return true;

	return false;
}
EXPORT_SYMBOL(blk_mq_queue_stopped);

/*
 * This function is often used for pausing .queue_rq() by driver when
 * there isn't enough resource or some conditions aren't satisfied, and
 * BLK_STS_RESOURCE is usually returned.
 *
 * We do not guarantee that dispatch can be drained or blocked
 * after blk_mq_stop_hw_queue() returns. Please use
 * blk_mq_quiesce_queue() for that requirement.
 */
void blk_mq_stop_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	cancel_delayed_work(&hctx->run_work);

	set_bit(BLK_MQ_S_STOPPED, &hctx->state);
}
EXPORT_SYMBOL(blk_mq_stop_hw_queue);

/*
 * This function is often used for pausing .queue_rq() by driver when
 * there isn't enough resource or some conditions aren't satisfied, and
 * BLK_STS_RESOURCE is usually returned.
 *
 * We do not guarantee that dispatch can be drained or blocked
 * after blk_mq_stop_hw_queues() returns. Please use
 * blk_mq_quiesce_queue() for that requirement.
 */
void blk_mq_stop_hw_queues(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_stop_hw_queue(hctx);
}
EXPORT_SYMBOL(blk_mq_stop_hw_queues);

void blk_mq_start_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	clear_bit(BLK_MQ_S_STOPPED, &hctx->state);

	blk_mq_run_hw_queue(hctx, false);
}
EXPORT_SYMBOL(blk_mq_start_hw_queue);

void blk_mq_start_hw_queues(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_start_hw_queue(hctx);
}
EXPORT_SYMBOL(blk_mq_start_hw_queues);

void blk_mq_start_stopped_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
	if (!blk_mq_hctx_stopped(hctx))
		return;

	clear_bit(BLK_MQ_S_STOPPED, &hctx->state);
	blk_mq_run_hw_queue(hctx, async);
}
EXPORT_SYMBOL_GPL(blk_mq_start_stopped_hw_queue);

void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_start_stopped_hw_queue(hctx, async);
}
EXPORT_SYMBOL(blk_mq_start_stopped_hw_queues);

static void blk_mq_run_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, run_work.work);

	/*
	 * If we are stopped, don't run the queue.
	 */
	if (blk_mq_hctx_stopped(hctx))
		return;

	__blk_mq_run_hw_queue(hctx);
}

static inline void __blk_mq_insert_req_list(struct blk_mq_hw_ctx *hctx,
					    struct request *rq,
					    bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	enum hctx_type type = hctx->type;

	lockdep_assert_held(&ctx->lock);

	trace_block_rq_insert(rq);

	if (at_head)
		list_add(&rq->queuelist, &ctx->rq_lists[type]);
	else
		list_add_tail(&rq->queuelist, &ctx->rq_lists[type]);
}

void __blk_mq_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			     bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	lockdep_assert_held(&ctx->lock);

	__blk_mq_insert_req_list(hctx, rq, at_head);
	blk_mq_hctx_mark_pending(hctx, ctx);
}

/**
 * blk_mq_request_bypass_insert - Insert a request at dispatch list.
 * @rq: Pointer to request to be inserted.
 * @at_head: true if the request should be inserted at the head of the list.
 * @run_queue: If we should run the hardware queue after inserting the request.
 *
 * Should only be used carefully, when the caller knows we want to
 * bypass a potential IO scheduler on the target device.
 */
void blk_mq_request_bypass_insert(struct request *rq, bool at_head,
				  bool run_queue)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	spin_lock(&hctx->lock);
	if (at_head)
		list_add(&rq->queuelist, &hctx->dispatch);
	else
		list_add_tail(&rq->queuelist, &hctx->dispatch);
	spin_unlock(&hctx->lock);

	if (run_queue)
		blk_mq_run_hw_queue(hctx, false);
}

void blk_mq_insert_requests(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
			    struct list_head *list)

{
	struct request *rq;
	enum hctx_type type = hctx->type;

	/*
	 * preemption doesn't flush plug list, so it's possible ctx->cpu is
	 * offline now
	 */
	list_for_each_entry(rq, list, queuelist) {
		BUG_ON(rq->mq_ctx != ctx);
		trace_block_rq_insert(rq);
	}

	spin_lock(&ctx->lock);
	list_splice_tail_init(list, &ctx->rq_lists[type]);
	blk_mq_hctx_mark_pending(hctx, ctx);
	spin_unlock(&ctx->lock);
}

static void blk_mq_commit_rqs(struct blk_mq_hw_ctx *hctx, int *queued,
			      bool from_schedule)
{
	if (hctx->queue->mq_ops->commit_rqs) {
		trace_block_unplug(hctx->queue, *queued, !from_schedule);
		hctx->queue->mq_ops->commit_rqs(hctx);
	}
	*queued = 0;
}

static void blk_mq_plug_issue_direct(struct blk_plug *plug, bool from_schedule)
{
	struct blk_mq_hw_ctx *hctx = NULL;
	struct request *rq;
	int queued = 0;
	int errors = 0;

	while ((rq = rq_list_pop(&plug->mq_list))) {
		bool last = rq_list_empty(plug->mq_list);
		blk_status_t ret;

		if (hctx != rq->mq_hctx) {
			if (hctx)
				blk_mq_commit_rqs(hctx, &queued, from_schedule);
			hctx = rq->mq_hctx;
		}

		ret = blk_mq_request_issue_directly(rq, last);
		switch (ret) {
		case BLK_STS_OK:
			queued++;
			break;
		case BLK_STS_RESOURCE:
		case BLK_STS_DEV_RESOURCE:
			blk_mq_request_bypass_insert(rq, false, last);
			blk_mq_commit_rqs(hctx, &queued, from_schedule);
			return;
		default:
			blk_mq_end_request(rq, ret);
			errors++;
			break;
		}
	}

	/*
	 * If we didn't flush the entire list, we could have told the driver
	 * there was more coming, but that turned out to be a lie.
	 */
	if (errors)
		blk_mq_commit_rqs(hctx, &queued, from_schedule);
}

void blk_mq_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
	struct blk_mq_hw_ctx *this_hctx;
	struct blk_mq_ctx *this_ctx;
	unsigned int depth;
	LIST_HEAD(list);

	if (rq_list_empty(plug->mq_list))
		return;
	plug->rq_count = 0;

	if (!plug->multiple_queues && !plug->has_elevator && !from_schedule) {
		blk_mq_plug_issue_direct(plug, false);
		if (rq_list_empty(plug->mq_list))
			return;
	}

	this_hctx = NULL;
	this_ctx = NULL;
	depth = 0;
	do {
		struct request *rq;

		rq = rq_list_pop(&plug->mq_list);

		if (!this_hctx) {
			this_hctx = rq->mq_hctx;
			this_ctx = rq->mq_ctx;
		} else if (this_hctx != rq->mq_hctx || this_ctx != rq->mq_ctx) {
			trace_block_unplug(this_hctx->queue, depth,
						!from_schedule);
			blk_mq_sched_insert_requests(this_hctx, this_ctx,
						&list, from_schedule);
			depth = 0;
			this_hctx = rq->mq_hctx;
			this_ctx = rq->mq_ctx;

		}

		list_add(&rq->queuelist, &list);
		depth++;
	} while (!rq_list_empty(plug->mq_list));

	if (!list_empty(&list)) {
		trace_block_unplug(this_hctx->queue, depth, !from_schedule);
		blk_mq_sched_insert_requests(this_hctx, this_ctx, &list,
						from_schedule);
	}
}

static void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
		unsigned int nr_segs)
{
	int err;

	if (bio->bi_opf & REQ_RAHEAD)
		rq->cmd_flags |= REQ_FAILFAST_MASK;

	rq->__sector = bio->bi_iter.bi_sector;
	rq->write_hint = bio->bi_write_hint;
	blk_rq_bio_prep(rq, bio, nr_segs);

	/* This can't fail, since GFP_NOIO includes __GFP_DIRECT_RECLAIM. */
	err = blk_crypto_rq_bio_prep(rq, bio, GFP_NOIO);
	WARN_ON_ONCE(err);

	blk_account_io_start(rq);
}

static blk_status_t __blk_mq_issue_directly(struct blk_mq_hw_ctx *hctx,
					    struct request *rq, bool last)
{
	struct request_queue *q = rq->q;
	struct blk_mq_queue_data bd = {
		.rq = rq,
		.last = last,
	};
	blk_status_t ret;

	/*
	 * For OK queue, we are done. For error, caller may kill it.
	 * Any other error (busy), just add it to our list as we
	 * previously would have done.
	 */
	ret = q->mq_ops->queue_rq(hctx, &bd);
	switch (ret) {
	case BLK_STS_OK:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	case BLK_STS_RESOURCE:
	case BLK_STS_DEV_RESOURCE:
		blk_mq_update_dispatch_busy(hctx, true);
		__blk_mq_requeue_request(rq);
		break;
	default:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	}

	return ret;
}

static blk_status_t __blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
						struct request *rq,
						bool bypass_insert, bool last)
{
	struct request_queue *q = rq->q;
	bool run_queue = true;
	int budget_token;

	/*
	 * RCU or SRCU read lock is needed before checking quiesced flag.
	 *
	 * When queue is stopped or quiesced, ignore 'bypass_insert' from
	 * blk_mq_request_issue_directly(), and return BLK_STS_OK to caller,
	 * and avoid driver to try to dispatch again.
	 */
	if (blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)) {
		run_queue = false;
		bypass_insert = false;
		goto insert;
	}

	if ((rq->rq_flags & RQF_ELV) && !bypass_insert)
		goto insert;

	budget_token = blk_mq_get_dispatch_budget(q);
	if (budget_token < 0)
		goto insert;

	blk_mq_set_rq_budget_token(rq, budget_token);

	if (!blk_mq_get_driver_tag(rq)) {
		blk_mq_put_dispatch_budget(q, budget_token);
		goto insert;
	}

	return __blk_mq_issue_directly(hctx, rq, last);
insert:
	if (bypass_insert)
		return BLK_STS_RESOURCE;

	blk_mq_sched_insert_request(rq, false, run_queue, false);

	return BLK_STS_OK;
}

/**
 * blk_mq_try_issue_directly - Try to send a request directly to device driver.
 * @hctx: Pointer of the associated hardware queue.
 * @rq: Pointer to request to be sent.
 *
 * If the device has enough resources to accept a new request now, send the
 * request directly to device driver. Else, insert at hctx->dispatch queue, so
 * we can try send it another time in the future. Requests inserted at this
 * queue have higher priority.
 */
static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
		struct request *rq)
{
	blk_status_t ret;
	int srcu_idx;

	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	hctx_lock(hctx, &srcu_idx);

	ret = __blk_mq_try_issue_directly(hctx, rq, false, true);
	if (ret == BLK_STS_RESOURCE || ret == BLK_STS_DEV_RESOURCE)
		blk_mq_request_bypass_insert(rq, false, true);
	else if (ret != BLK_STS_OK)
		blk_mq_end_request(rq, ret);

	hctx_unlock(hctx, srcu_idx);
}

blk_status_t blk_mq_request_issue_directly(struct request *rq, bool last)
{
	blk_status_t ret;
	int srcu_idx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	hctx_lock(hctx, &srcu_idx);
	ret = __blk_mq_try_issue_directly(hctx, rq, true, last);
	hctx_unlock(hctx, srcu_idx);

	return ret;
}

void blk_mq_try_issue_list_directly(struct blk_mq_hw_ctx *hctx,
		struct list_head *list)
{
	int queued = 0;
	int errors = 0;

	while (!list_empty(list)) {
		blk_status_t ret;
		struct request *rq = list_first_entry(list, struct request,
				queuelist);

		list_del_init(&rq->queuelist);
		ret = blk_mq_request_issue_directly(rq, list_empty(list));
		if (ret != BLK_STS_OK) {
			if (ret == BLK_STS_RESOURCE ||
					ret == BLK_STS_DEV_RESOURCE) {
				blk_mq_request_bypass_insert(rq, false,
							list_empty(list));
				break;
			}
			blk_mq_end_request(rq, ret);
			errors++;
		} else
			queued++;
	}

	/*
	 * If we didn't flush the entire list, we could have told
	 * the driver there was more coming, but that turned out to
	 * be a lie.
	 */
	if ((!list_empty(list) || errors) &&
	     hctx->queue->mq_ops->commit_rqs && queued)
		hctx->queue->mq_ops->commit_rqs(hctx);
}

static void blk_add_rq_to_plug(struct blk_plug *plug, struct request *rq)
{
	if (!plug->multiple_queues) {
		struct request *nxt = rq_list_peek(&plug->mq_list);

		if (nxt && nxt->q != rq->q)
			plug->multiple_queues = true;
	}
	if (!plug->has_elevator && (rq->rq_flags & RQF_ELV))
		plug->has_elevator = true;
	rq->rq_next = NULL;
	rq_list_add(&plug->mq_list, rq);
	plug->rq_count++;
}

/*
 * Allow 2x BLK_MAX_REQUEST_COUNT requests on plug queue for multiple
 * queues. This is important for md arrays to benefit from merging
 * requests.
 */
static inline unsigned short blk_plug_max_rq_count(struct blk_plug *plug)
{
	if (plug->multiple_queues)
		return BLK_MAX_REQUEST_COUNT * 2;
	return BLK_MAX_REQUEST_COUNT;
}

static bool blk_mq_attempt_bio_merge(struct request_queue *q,
				     struct bio *bio, unsigned int nr_segs,
				     bool *same_queue_rq)
{
	if (!blk_queue_nomerges(q) && bio_mergeable(bio)) {
		if (blk_attempt_plug_merge(q, bio, nr_segs, same_queue_rq))
			return true;
		if (blk_mq_sched_bio_merge(q, bio, nr_segs))
			return true;
	}
	return false;
}

static struct request *blk_mq_get_new_requests(struct request_queue *q,
					       struct blk_plug *plug,
					       struct bio *bio,
					       unsigned int nsegs,
					       bool *same_queue_rq)
{
	struct blk_mq_alloc_data data = {
		.q		= q,
		.nr_tags	= 1,
		.cmd_flags	= bio->bi_opf,
	};
	struct request *rq;

	if (blk_mq_attempt_bio_merge(q, bio, nsegs, same_queue_rq))
		return NULL;

	rq_qos_throttle(q, bio);

	if (plug) {
		data.nr_tags = plug->nr_ios;
		plug->nr_ios = 1;
		data.cached_rq = &plug->cached_rq;
	}

	rq = __blk_mq_alloc_requests(&data);
	if (rq)
		return rq;

	rq_qos_cleanup(q, bio);
	if (bio->bi_opf & REQ_NOWAIT)
		bio_wouldblock_error(bio);

	return NULL;
}

static inline bool blk_mq_can_use_cached_rq(struct request *rq, struct bio *bio)
{
	if (blk_mq_get_hctx_type(bio->bi_opf) != rq->mq_hctx->type)
		return false;

	if (op_is_flush(rq->cmd_flags) != op_is_flush(bio->bi_opf))
		return false;

	return true;
}

static inline struct request *blk_mq_get_request(struct request_queue *q,
						 struct blk_plug *plug,
						 struct bio *bio,
						 unsigned int nsegs,
						 bool *same_queue_rq)
{
	struct request *rq;
	bool checked = false;

	if (plug) {
		rq = rq_list_peek(&plug->cached_rq);
		if (rq && rq->q == q) {
			if (unlikely(!submit_bio_checks(bio)))
				return NULL;
			if (blk_mq_attempt_bio_merge(q, bio, nsegs,
						same_queue_rq))
				return NULL;
			checked = true;
			if (!blk_mq_can_use_cached_rq(rq, bio))
				goto fallback;
			rq->cmd_flags = bio->bi_opf;
			plug->cached_rq = rq_list_next(rq);
			INIT_LIST_HEAD(&rq->queuelist);
			rq_qos_throttle(q, bio);
			return rq;
		}
	}

fallback:
	if (unlikely(bio_queue_enter(bio)))
		return NULL;
	if (unlikely(!checked && !submit_bio_checks(bio)))
		goto out_put;
	rq = blk_mq_get_new_requests(q, plug, bio, nsegs, same_queue_rq);
	if (rq)
		return rq;
out_put:
	blk_queue_exit(q);
	return NULL;
}

/**
 * blk_mq_submit_bio - Create and send a request to block device.
 * @bio: Bio pointer.
 *
 * Builds up a request structure from @q and @bio and send to the device. The
 * request may not be queued directly to hardware if:
 * * This request can be merged with another one
 * * We want to place request at plug queue for possible future merging
 * * There is an IO scheduler active at this queue
 *
 * It will not queue the request if there is an error with the bio, or at the
 * request creation.
 */
void blk_mq_submit_bio(struct bio *bio)
{
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	const int is_sync = op_is_sync(bio->bi_opf);
	struct request *rq;
	struct blk_plug *plug;
	bool same_queue_rq = false;
	unsigned int nr_segs = 1;
	blk_status_t ret;

	if (unlikely(!blk_crypto_bio_prep(&bio)))
		return;

	blk_queue_bounce(q, &bio);
	if (blk_may_split(q, bio))
		__blk_queue_split(q, &bio, &nr_segs);

	if (!bio_integrity_prep(bio))
		return;

	plug = blk_mq_plug(q, bio);
	rq = blk_mq_get_request(q, plug, bio, nr_segs, &same_queue_rq);
	if (unlikely(!rq))
		return;

	trace_block_getrq(bio);

	rq_qos_track(q, rq, bio);

	blk_mq_bio_to_request(rq, bio, nr_segs);

	ret = blk_crypto_init_request(rq);
	if (ret != BLK_STS_OK) {
		bio->bi_status = ret;
		bio_endio(bio);
		blk_mq_free_request(rq);
		return;
	}

	if (op_is_flush(bio->bi_opf)) {
		blk_insert_flush(rq);
		return;
	}

	if (plug && (q->nr_hw_queues == 1 ||
	    blk_mq_is_shared_tags(rq->mq_hctx->flags) ||
	    q->mq_ops->commit_rqs || !blk_queue_nonrot(q))) {
		/*
		 * Use plugging if we have a ->commit_rqs() hook as well, as
		 * we know the driver uses bd->last in a smart fashion.
		 *
		 * Use normal plugging if this disk is slow HDD, as sequential
		 * IO may benefit a lot from plug merging.
		 */
		unsigned int request_count = plug->rq_count;
		struct request *last = NULL;

		if (!request_count) {
			trace_block_plug(q);
		} else if (!blk_queue_nomerges(q)) {
			last = rq_list_peek(&plug->mq_list);
			if (blk_rq_bytes(last) < BLK_PLUG_FLUSH_SIZE)
				last = NULL;
		}

		if (request_count >= blk_plug_max_rq_count(plug) || last) {
			blk_mq_flush_plug_list(plug, false);
			trace_block_plug(q);
		}

		blk_add_rq_to_plug(plug, rq);
	} else if (rq->rq_flags & RQF_ELV) {
		/* Insert the request at the IO scheduler queue */
		blk_mq_sched_insert_request(rq, false, true, true);
	} else if (plug && !blk_queue_nomerges(q)) {
		struct request *next_rq = NULL;

		/*
		 * We do limited plugging. If the bio can be merged, do that.
		 * Otherwise the existing request in the plug list will be
		 * issued. So the plug list will have one request at most
		 * The plug list might get flushed before this. If that happens,
		 * the plug list is empty, and same_queue_rq is invalid.
		 */
		if (same_queue_rq) {
			next_rq = rq_list_pop(&plug->mq_list);
			plug->rq_count--;
		}
		blk_add_rq_to_plug(plug, rq);
		trace_block_plug(q);

		if (next_rq) {
			trace_block_unplug(q, 1, true);
			blk_mq_try_issue_directly(next_rq->mq_hctx, next_rq);
		}
	} else if ((q->nr_hw_queues > 1 && is_sync) ||
		   !rq->mq_hctx->dispatch_busy) {
		/*
		 * There is no scheduler and we can try to send directly
		 * to the hardware.
		 */
		blk_mq_try_issue_directly(rq->mq_hctx, rq);
	} else {
		/* Default case. */
		blk_mq_sched_insert_request(rq, false, true, true);
	}
}

static size_t order_to_size(unsigned int order)
{
	return (size_t)PAGE_SIZE << order;
}

/* called before freeing request pool in @tags */
static void blk_mq_clear_rq_mapping(struct blk_mq_tags *drv_tags,
				    struct blk_mq_tags *tags)
{
	struct page *page;
	unsigned long flags;

	/* There is no need to clear a driver tags own mapping */
	if (drv_tags == tags)
		return;

	list_for_each_entry(page, &tags->page_list, lru) {
		unsigned long start = (unsigned long)page_address(page);
		unsigned long end = start + order_to_size(page->private);
		int i;

		for (i = 0; i < drv_tags->nr_tags; i++) {
			struct request *rq = drv_tags->rqs[i];
			unsigned long rq_addr = (unsigned long)rq;

			if (rq_addr >= start && rq_addr < end) {
				WARN_ON_ONCE(refcount_read(&rq->ref) != 0);
				cmpxchg(&drv_tags->rqs[i], rq, NULL);
			}
		}
	}

	/*
	 * Wait until all pending iteration is done.
	 *
	 * Request reference is cleared and it is guaranteed to be observed
	 * after the ->lock is released.
	 */
	spin_lock_irqsave(&drv_tags->lock, flags);
	spin_unlock_irqrestore(&drv_tags->lock, flags);
}

void blk_mq_free_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx)
{
	struct blk_mq_tags *drv_tags;
	struct page *page;

	if (blk_mq_is_shared_tags(set->flags))
		drv_tags = set->shared_tags;
	else
		drv_tags = set->tags[hctx_idx];

	if (tags->static_rqs && set->ops->exit_request) {
		int i;

		for (i = 0; i < tags->nr_tags; i++) {
			struct request *rq = tags->static_rqs[i];

			if (!rq)
				continue;
			set->ops->exit_request(set, rq, hctx_idx);
			tags->static_rqs[i] = NULL;
		}
	}

	blk_mq_clear_rq_mapping(drv_tags, tags);

	while (!list_empty(&tags->page_list)) {
		page = list_first_entry(&tags->page_list, struct page, lru);
		list_del_init(&page->lru);
		/*
		 * Remove kmemleak object previously allocated in
		 * blk_mq_alloc_rqs().
		 */
		kmemleak_free(page_address(page));
		__free_pages(page, page->private);
	}
}

void blk_mq_free_rq_map(struct blk_mq_tags *tags)
{
	kfree(tags->rqs);
	tags->rqs = NULL;
	kfree(tags->static_rqs);
	tags->static_rqs = NULL;

	blk_mq_free_tags(tags);
}

static struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
					       unsigned int hctx_idx,
					       unsigned int nr_tags,
					       unsigned int reserved_tags)
{
	struct blk_mq_tags *tags;
	int node;

	node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], hctx_idx);
	if (node == NUMA_NO_NODE)
		node = set->numa_node;

	tags = blk_mq_init_tags(nr_tags, reserved_tags, node,
				BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags));
	if (!tags)
		return NULL;

	tags->rqs = kcalloc_node(nr_tags, sizeof(struct request *),
				 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
				 node);
	if (!tags->rqs) {
		blk_mq_free_tags(tags);
		return NULL;
	}

	tags->static_rqs = kcalloc_node(nr_tags, sizeof(struct request *),
					GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
					node);
	if (!tags->static_rqs) {
		kfree(tags->rqs);
		blk_mq_free_tags(tags);
		return NULL;
	}

	return tags;
}

static int blk_mq_init_request(struct blk_mq_tag_set *set, struct request *rq,
			       unsigned int hctx_idx, int node)
{
	int ret;

	if (set->ops->init_request) {
		ret = set->ops->init_request(set, rq, hctx_idx, node);
		if (ret)
			return ret;
	}

	WRITE_ONCE(rq->state, MQ_RQ_IDLE);
	return 0;
}

static int blk_mq_alloc_rqs(struct blk_mq_tag_set *set,
			    struct blk_mq_tags *tags,
			    unsigned int hctx_idx, unsigned int depth)
{
	unsigned int i, j, entries_per_page, max_order = 4;
	size_t rq_size, left;
	int node;

	node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], hctx_idx);
	if (node == NUMA_NO_NODE)
		node = set->numa_node;

	INIT_LIST_HEAD(&tags->page_list);

	/*
	 * rq_size is the size of the request plus driver payload, rounded
	 * to the cacheline size
	 */
	rq_size = round_up(sizeof(struct request) + set->cmd_size,
				cache_line_size());
	left = rq_size * depth;

	for (i = 0; i < depth; ) {
		int this_order = max_order;
		struct page *page;
		int to_do;
		void *p;

		while (this_order && left < order_to_size(this_order - 1))
			this_order--;

		do {
			page = alloc_pages_node(node,
				GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
				this_order);
			if (page)
				break;
			if (!this_order--)
				break;
			if (order_to_size(this_order) < rq_size)
				break;
		} while (1);

		if (!page)
			goto fail;

		page->private = this_order;
		list_add_tail(&page->lru, &tags->page_list);

		p = page_address(page);
		/*
		 * Allow kmemleak to scan these pages as they contain pointers
		 * to additional allocations like via ops->init_request().
		 */
		kmemleak_alloc(p, order_to_size(this_order), 1, GFP_NOIO);
		entries_per_page = order_to_size(this_order) / rq_size;
		to_do = min(entries_per_page, depth - i);
		left -= to_do * rq_size;
		for (j = 0; j < to_do; j++) {
			struct request *rq = p;

			tags->static_rqs[i] = rq;
			if (blk_mq_init_request(set, rq, hctx_idx, node)) {
				tags->static_rqs[i] = NULL;
				goto fail;
			}

			p += rq_size;
			i++;
		}
	}
	return 0;

fail:
	blk_mq_free_rqs(set, tags, hctx_idx);
	return -ENOMEM;
}

struct rq_iter_data {
	struct blk_mq_hw_ctx *hctx;
	bool has_rq;
};

static bool blk_mq_has_request(struct request *rq, void *data, bool reserved)
{
	struct rq_iter_data *iter_data = data;

	if (rq->mq_hctx != iter_data->hctx)
		return true;
	iter_data->has_rq = true;
	return false;
}

static bool blk_mq_hctx_has_requests(struct blk_mq_hw_ctx *hctx)
{
	struct blk_mq_tags *tags = hctx->sched_tags ?
			hctx->sched_tags : hctx->tags;
	struct rq_iter_data data = {
		.hctx	= hctx,
	};

	blk_mq_all_tag_iter(tags, blk_mq_has_request, &data);
	return data.has_rq;
}

static inline bool blk_mq_last_cpu_in_hctx(unsigned int cpu,
		struct blk_mq_hw_ctx *hctx)
{
	if (cpumask_next_and(-1, hctx->cpumask, cpu_online_mask) != cpu)
		return false;
	if (cpumask_next_and(cpu, hctx->cpumask, cpu_online_mask) < nr_cpu_ids)
		return false;
	return true;
}

static int blk_mq_hctx_notify_offline(unsigned int cpu, struct hlist_node *node)
{
	struct blk_mq_hw_ctx *hctx = hlist_entry_safe(node,
			struct blk_mq_hw_ctx, cpuhp_online);

	if (!cpumask_test_cpu(cpu, hctx->cpumask) ||
	    !blk_mq_last_cpu_in_hctx(cpu, hctx))
		return 0;

	/*
	 * Prevent new request from being allocated on the current hctx.
	 *
	 * The smp_mb__after_atomic() Pairs with the implied barrier in
	 * test_and_set_bit_lock in sbitmap_get().  Ensures the inactive flag is
	 * seen once we return from the tag allocator.
	 */
	set_bit(BLK_MQ_S_INACTIVE, &hctx->state);
	smp_mb__after_atomic();

	/*
	 * Try to grab a reference to the queue and wait for any outstanding
	 * requests.  If we could not grab a reference the queue has been
	 * frozen and there are no requests.
	 */
	if (percpu_ref_tryget(&hctx->queue->q_usage_counter)) {
		while (blk_mq_hctx_has_requests(hctx))
			msleep(5);
		percpu_ref_put(&hctx->queue->q_usage_counter);
	}

	return 0;
}

static int blk_mq_hctx_notify_online(unsigned int cpu, struct hlist_node *node)
{
	struct blk_mq_hw_ctx *hctx = hlist_entry_safe(node,
			struct blk_mq_hw_ctx, cpuhp_online);

	if (cpumask_test_cpu(cpu, hctx->cpumask))
		clear_bit(BLK_MQ_S_INACTIVE, &hctx->state);
	return 0;
}

/*
 * 'cpu' is going away. splice any existing rq_list entries from this
 * software queue to the hw queue dispatch list, and ensure that it
 * gets run.
 */
static int blk_mq_hctx_notify_dead(unsigned int cpu, struct hlist_node *node)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	LIST_HEAD(tmp);
	enum hctx_type type;

	hctx = hlist_entry_safe(node, struct blk_mq_hw_ctx, cpuhp_dead);
	if (!cpumask_test_cpu(cpu, hctx->cpumask))
		return 0;

	ctx = __blk_mq_get_ctx(hctx->queue, cpu);
	type = hctx->type;

	spin_lock(&ctx->lock);
	if (!list_empty(&ctx->rq_lists[type])) {
		list_splice_init(&ctx->rq_lists[type], &tmp);
		blk_mq_hctx_clear_pending(hctx, ctx);
	}
	spin_unlock(&ctx->lock);

	if (list_empty(&tmp))
		return 0;

	spin_lock(&hctx->lock);
	list_splice_tail_init(&tmp, &hctx->dispatch);
	spin_unlock(&hctx->lock);

	blk_mq_run_hw_queue(hctx, true);
	return 0;
}

static void blk_mq_remove_cpuhp(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_STACKING))
		cpuhp_state_remove_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
						    &hctx->cpuhp_online);
	cpuhp_state_remove_instance_nocalls(CPUHP_BLK_MQ_DEAD,
					    &hctx->cpuhp_dead);
}

/*
 * Before freeing hw queue, clearing the flush request reference in
 * tags->rqs[] for avoiding potential UAF.
 */
static void blk_mq_clear_flush_rq_mapping(struct blk_mq_tags *tags,
		unsigned int queue_depth, struct request *flush_rq)
{
	int i;
	unsigned long flags;

	/* The hw queue may not be mapped yet */
	if (!tags)
		return;

	WARN_ON_ONCE(refcount_read(&flush_rq->ref) != 0);

	for (i = 0; i < queue_depth; i++)
		cmpxchg(&tags->rqs[i], flush_rq, NULL);

	/*
	 * Wait until all pending iteration is done.
	 *
	 * Request reference is cleared and it is guaranteed to be observed
	 * after the ->lock is released.
	 */
	spin_lock_irqsave(&tags->lock, flags);
	spin_unlock_irqrestore(&tags->lock, flags);
}

/* hctx->ctxs will be freed in queue's release handler */
static void blk_mq_exit_hctx(struct request_queue *q,
		struct blk_mq_tag_set *set,
		struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct request *flush_rq = hctx->fq->flush_rq;

	if (blk_mq_hw_queue_mapped(hctx))
		blk_mq_tag_idle(hctx);

	blk_mq_clear_flush_rq_mapping(set->tags[hctx_idx],
			set->queue_depth, flush_rq);
	if (set->ops->exit_request)
		set->ops->exit_request(set, flush_rq, hctx_idx);

	if (set->ops->exit_hctx)
		set->ops->exit_hctx(hctx, hctx_idx);

	blk_mq_remove_cpuhp(hctx);

	spin_lock(&q->unused_hctx_lock);
	list_add(&hctx->hctx_list, &q->unused_hctx_list);
	spin_unlock(&q->unused_hctx_lock);
}

static void blk_mq_exit_hw_queues(struct request_queue *q,
		struct blk_mq_tag_set *set, int nr_queue)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (i == nr_queue)
			break;
		blk_mq_debugfs_unregister_hctx(hctx);
		blk_mq_exit_hctx(q, set, hctx, i);
	}
}

static int blk_mq_hw_ctx_size(struct blk_mq_tag_set *tag_set)
{
	int hw_ctx_size = sizeof(struct blk_mq_hw_ctx);

	BUILD_BUG_ON(ALIGN(offsetof(struct blk_mq_hw_ctx, srcu),
			   __alignof__(struct blk_mq_hw_ctx)) !=
		     sizeof(struct blk_mq_hw_ctx));

	if (tag_set->flags & BLK_MQ_F_BLOCKING)
		hw_ctx_size += sizeof(struct srcu_struct);

	return hw_ctx_size;
}

static int blk_mq_init_hctx(struct request_queue *q,
		struct blk_mq_tag_set *set,
		struct blk_mq_hw_ctx *hctx, unsigned hctx_idx)
{
	hctx->queue_num = hctx_idx;

	if (!(hctx->flags & BLK_MQ_F_STACKING))
		cpuhp_state_add_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
				&hctx->cpuhp_online);
	cpuhp_state_add_instance_nocalls(CPUHP_BLK_MQ_DEAD, &hctx->cpuhp_dead);

	hctx->tags = set->tags[hctx_idx];

	if (set->ops->init_hctx &&
	    set->ops->init_hctx(hctx, set->driver_data, hctx_idx))
		goto unregister_cpu_notifier;

	if (blk_mq_init_request(set, hctx->fq->flush_rq, hctx_idx,
				hctx->numa_node))
		goto exit_hctx;
	return 0;

 exit_hctx:
	if (set->ops->exit_hctx)
		set->ops->exit_hctx(hctx, hctx_idx);
 unregister_cpu_notifier:
	blk_mq_remove_cpuhp(hctx);
	return -1;
}

static struct blk_mq_hw_ctx *
blk_mq_alloc_hctx(struct request_queue *q, struct blk_mq_tag_set *set,
		int node)
{
	struct blk_mq_hw_ctx *hctx;
	gfp_t gfp = GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY;

	hctx = kzalloc_node(blk_mq_hw_ctx_size(set), gfp, node);
	if (!hctx)
		goto fail_alloc_hctx;

	if (!zalloc_cpumask_var_node(&hctx->cpumask, gfp, node))
		goto free_hctx;

	atomic_set(&hctx->nr_active, 0);
	if (node == NUMA_NO_NODE)
		node = set->numa_node;
	hctx->numa_node = node;

	INIT_DELAYED_WORK(&hctx->run_work, blk_mq_run_work_fn);
	spin_lock_init(&hctx->lock);
	INIT_LIST_HEAD(&hctx->dispatch);
	hctx->queue = q;
	hctx->flags = set->flags & ~BLK_MQ_F_TAG_QUEUE_SHARED;

	INIT_LIST_HEAD(&hctx->hctx_list);

	/*
	 * Allocate space for all possible cpus to avoid allocation at
	 * runtime
	 */
	hctx->ctxs = kmalloc_array_node(nr_cpu_ids, sizeof(void *),
			gfp, node);
	if (!hctx->ctxs)
		goto free_cpumask;

	if (sbitmap_init_node(&hctx->ctx_map, nr_cpu_ids, ilog2(8),
				gfp, node, false, false))
		goto free_ctxs;
	hctx->nr_ctx = 0;

	spin_lock_init(&hctx->dispatch_wait_lock);
	init_waitqueue_func_entry(&hctx->dispatch_wait, blk_mq_dispatch_wake);
	INIT_LIST_HEAD(&hctx->dispatch_wait.entry);

	hctx->fq = blk_alloc_flush_queue(hctx->numa_node, set->cmd_size, gfp);
	if (!hctx->fq)
		goto free_bitmap;

	if (hctx->flags & BLK_MQ_F_BLOCKING)
		init_srcu_struct(hctx->srcu);
	blk_mq_hctx_kobj_init(hctx);

	return hctx;

 free_bitmap:
	sbitmap_free(&hctx->ctx_map);
 free_ctxs:
	kfree(hctx->ctxs);
 free_cpumask:
	free_cpumask_var(hctx->cpumask);
 free_hctx:
	kfree(hctx);
 fail_alloc_hctx:
	return NULL;
}

static void blk_mq_init_cpu_queues(struct request_queue *q,
				   unsigned int nr_hw_queues)
{
	struct blk_mq_tag_set *set = q->tag_set;
	unsigned int i, j;

	for_each_possible_cpu(i) {
		struct blk_mq_ctx *__ctx = per_cpu_ptr(q->queue_ctx, i);
		struct blk_mq_hw_ctx *hctx;
		int k;

		__ctx->cpu = i;
		spin_lock_init(&__ctx->lock);
		for (k = HCTX_TYPE_DEFAULT; k < HCTX_MAX_TYPES; k++)
			INIT_LIST_HEAD(&__ctx->rq_lists[k]);

		__ctx->queue = q;

		/*
		 * Set local node, IFF we have more than one hw queue. If
		 * not, we remain on the home node of the device
		 */
		for (j = 0; j < set->nr_maps; j++) {
			hctx = blk_mq_map_queue_type(q, j, i);
			if (nr_hw_queues > 1 && hctx->numa_node == NUMA_NO_NODE)
				hctx->numa_node = cpu_to_node(i);
		}
	}
}

struct blk_mq_tags *blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
					     unsigned int hctx_idx,
					     unsigned int depth)
{
	struct blk_mq_tags *tags;
	int ret;

	tags = blk_mq_alloc_rq_map(set, hctx_idx, depth, set->reserved_tags);
	if (!tags)
		return NULL;

	ret = blk_mq_alloc_rqs(set, tags, hctx_idx, depth);
	if (ret) {
		blk_mq_free_rq_map(tags);
		return NULL;
	}

	return tags;
}

static bool __blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
				       int hctx_idx)
{
	if (blk_mq_is_shared_tags(set->flags)) {
		set->tags[hctx_idx] = set->shared_tags;

		return true;
	}

	set->tags[hctx_idx] = blk_mq_alloc_map_and_rqs(set, hctx_idx,
						       set->queue_depth);

	return set->tags[hctx_idx];
}

void blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
			     struct blk_mq_tags *tags,
			     unsigned int hctx_idx)
{
	if (tags) {
		blk_mq_free_rqs(set, tags, hctx_idx);
		blk_mq_free_rq_map(tags);
	}
}

static void __blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
				      unsigned int hctx_idx)
{
	if (!blk_mq_is_shared_tags(set->flags))
		blk_mq_free_map_and_rqs(set, set->tags[hctx_idx], hctx_idx);

	set->tags[hctx_idx] = NULL;
}

static void blk_mq_map_swqueue(struct request_queue *q)
{
	unsigned int i, j, hctx_idx;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	struct blk_mq_tag_set *set = q->tag_set;

	queue_for_each_hw_ctx(q, hctx, i) {
		cpumask_clear(hctx->cpumask);
		hctx->nr_ctx = 0;
		hctx->dispatch_from = NULL;
	}

	/*
	 * Map software to hardware queues.
	 *
	 * If the cpu isn't present, the cpu is mapped to first hctx.
	 */
	for_each_possible_cpu(i) {

		ctx = per_cpu_ptr(q->queue_ctx, i);
		for (j = 0; j < set->nr_maps; j++) {
			if (!set->map[j].nr_queues) {
				ctx->hctxs[j] = blk_mq_map_queue_type(q,
						HCTX_TYPE_DEFAULT, i);
				continue;
			}
			hctx_idx = set->map[j].mq_map[i];
			/* unmapped hw queue can be remapped after CPU topo changed */
			if (!set->tags[hctx_idx] &&
			    !__blk_mq_alloc_map_and_rqs(set, hctx_idx)) {
				/*
				 * If tags initialization fail for some hctx,
				 * that hctx won't be brought online.  In this
				 * case, remap the current ctx to hctx[0] which
				 * is guaranteed to always have tags allocated
				 */
				set->map[j].mq_map[i] = 0;
			}

			hctx = blk_mq_map_queue_type(q, j, i);
			ctx->hctxs[j] = hctx;
			/*
			 * If the CPU is already set in the mask, then we've
			 * mapped this one already. This can happen if
			 * devices share queues across queue maps.
			 */
			if (cpumask_test_cpu(i, hctx->cpumask))
				continue;

			cpumask_set_cpu(i, hctx->cpumask);
			hctx->type = j;
			ctx->index_hw[hctx->type] = hctx->nr_ctx;
			hctx->ctxs[hctx->nr_ctx++] = ctx;

			/*
			 * If the nr_ctx type overflows, we have exceeded the
			 * amount of sw queues we can support.
			 */
			BUG_ON(!hctx->nr_ctx);
		}

		for (; j < HCTX_MAX_TYPES; j++)
			ctx->hctxs[j] = blk_mq_map_queue_type(q,
					HCTX_TYPE_DEFAULT, i);
	}

	queue_for_each_hw_ctx(q, hctx, i) {
		/*
		 * If no software queues are mapped to this hardware queue,
		 * disable it and free the request entries.
		 */
		if (!hctx->nr_ctx) {
			/* Never unmap queue 0.  We need it as a
			 * fallback in case of a new remap fails
			 * allocation
			 */
			if (i)
				__blk_mq_free_map_and_rqs(set, i);

			hctx->tags = NULL;
			continue;
		}

		hctx->tags = set->tags[i];
		WARN_ON(!hctx->tags);

		/*
		 * Set the map size to the number of mapped software queues.
		 * This is more accurate and more efficient than looping
		 * over all possibly mapped software queues.
		 */
		sbitmap_resize(&hctx->ctx_map, hctx->nr_ctx);

		/*
		 * Initialize batch roundrobin counts
		 */
		hctx->next_cpu = blk_mq_first_mapped_cpu(hctx);
		hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
	}
}

/*
 * Caller needs to ensure that we're either frozen/quiesced, or that
 * the queue isn't live yet.
 */
static void queue_set_hctx_shared(struct request_queue *q, bool shared)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (shared) {
			hctx->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
		} else {
			blk_mq_tag_idle(hctx);
			hctx->flags &= ~BLK_MQ_F_TAG_QUEUE_SHARED;
		}
	}
}

static void blk_mq_update_tag_set_shared(struct blk_mq_tag_set *set,
					 bool shared)
{
	struct request_queue *q;

	lockdep_assert_held(&set->tag_list_lock);

	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_freeze_queue(q);
		queue_set_hctx_shared(q, shared);
		blk_mq_unfreeze_queue(q);
	}
}

static void blk_mq_del_queue_tag_set(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;

	mutex_lock(&set->tag_list_lock);
	list_del(&q->tag_set_list);
	if (list_is_singular(&set->tag_list)) {
		/* just transitioned to unshared */
		set->flags &= ~BLK_MQ_F_TAG_QUEUE_SHARED;
		/* update existing queue */
		blk_mq_update_tag_set_shared(set, false);
	}
	mutex_unlock(&set->tag_list_lock);
	INIT_LIST_HEAD(&q->tag_set_list);
}

static void blk_mq_add_queue_tag_set(struct blk_mq_tag_set *set,
				     struct request_queue *q)
{
	mutex_lock(&set->tag_list_lock);

	/*
	 * Check to see if we're transitioning to shared (from 1 to 2 queues).
	 */
	if (!list_empty(&set->tag_list) &&
	    !(set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
		set->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
		/* update existing queue */
		blk_mq_update_tag_set_shared(set, true);
	}
	if (set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)
		queue_set_hctx_shared(q, true);
	list_add_tail(&q->tag_set_list, &set->tag_list);

	mutex_unlock(&set->tag_list_lock);
}

/* All allocations will be freed in release handler of q->mq_kobj */
static int blk_mq_alloc_ctxs(struct request_queue *q)
{
	struct blk_mq_ctxs *ctxs;
	int cpu;

	ctxs = kzalloc(sizeof(*ctxs), GFP_KERNEL);
	if (!ctxs)
		return -ENOMEM;

	ctxs->queue_ctx = alloc_percpu(struct blk_mq_ctx);
	if (!ctxs->queue_ctx)
		goto fail;

	for_each_possible_cpu(cpu) {
		struct blk_mq_ctx *ctx = per_cpu_ptr(ctxs->queue_ctx, cpu);
		ctx->ctxs = ctxs;
	}

	q->mq_kobj = &ctxs->kobj;
	q->queue_ctx = ctxs->queue_ctx;

	return 0;
 fail:
	kfree(ctxs);
	return -ENOMEM;
}

/*
 * It is the actual release handler for mq, but we do it from
 * request queue's release handler for avoiding use-after-free
 * and headache because q->mq_kobj shouldn't have been introduced,
 * but we can't group ctx/kctx kobj without it.
 */
void blk_mq_release(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx, *next;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		WARN_ON_ONCE(hctx && list_empty(&hctx->hctx_list));

	/* all hctx are in .unused_hctx_list now */
	list_for_each_entry_safe(hctx, next, &q->unused_hctx_list, hctx_list) {
		list_del_init(&hctx->hctx_list);
		kobject_put(&hctx->kobj);
	}

	kfree(q->queue_hw_ctx);

	/*
	 * release .mq_kobj and sw queue's kobject now because
	 * both share lifetime with request queue.
	 */
	blk_mq_sysfs_deinit(q);
}

static struct request_queue *blk_mq_init_queue_data(struct blk_mq_tag_set *set,
		void *queuedata)
{
	struct request_queue *q;
	int ret;

	q = blk_alloc_queue(set->numa_node);
	if (!q)
		return ERR_PTR(-ENOMEM);
	q->queuedata = queuedata;
	ret = blk_mq_init_allocated_queue(set, q);
	if (ret) {
		blk_cleanup_queue(q);
		return ERR_PTR(ret);
	}
	return q;
}

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
	return blk_mq_init_queue_data(set, NULL);
}
EXPORT_SYMBOL(blk_mq_init_queue);

struct gendisk *__blk_mq_alloc_disk(struct blk_mq_tag_set *set, void *queuedata,
		struct lock_class_key *lkclass)
{
	struct request_queue *q;
	struct gendisk *disk;

	q = blk_mq_init_queue_data(set, queuedata);
	if (IS_ERR(q))
		return ERR_CAST(q);

	disk = __alloc_disk_node(q, set->numa_node, lkclass);
	if (!disk) {
		blk_cleanup_queue(q);
		return ERR_PTR(-ENOMEM);
	}
	return disk;
}
EXPORT_SYMBOL(__blk_mq_alloc_disk);

static struct blk_mq_hw_ctx *blk_mq_alloc_and_init_hctx(
		struct blk_mq_tag_set *set, struct request_queue *q,
		int hctx_idx, int node)
{
	struct blk_mq_hw_ctx *hctx = NULL, *tmp;

	/* reuse dead hctx first */
	spin_lock(&q->unused_hctx_lock);
	list_for_each_entry(tmp, &q->unused_hctx_list, hctx_list) {
		if (tmp->numa_node == node) {
			hctx = tmp;
			break;
		}
	}
	if (hctx)
		list_del_init(&hctx->hctx_list);
	spin_unlock(&q->unused_hctx_lock);

	if (!hctx)
		hctx = blk_mq_alloc_hctx(q, set, node);
	if (!hctx)
		goto fail;

	if (blk_mq_init_hctx(q, set, hctx, hctx_idx))
		goto free_hctx;

	return hctx;

 free_hctx:
	kobject_put(&hctx->kobj);
 fail:
	return NULL;
}

static void blk_mq_realloc_hw_ctxs(struct blk_mq_tag_set *set,
						struct request_queue *q)
{
	int i, j, end;
	struct blk_mq_hw_ctx **hctxs = q->queue_hw_ctx;

	if (q->nr_hw_queues < set->nr_hw_queues) {
		struct blk_mq_hw_ctx **new_hctxs;

		new_hctxs = kcalloc_node(set->nr_hw_queues,
				       sizeof(*new_hctxs), GFP_KERNEL,
				       set->numa_node);
		if (!new_hctxs)
			return;
		if (hctxs)
			memcpy(new_hctxs, hctxs, q->nr_hw_queues *
			       sizeof(*hctxs));
		q->queue_hw_ctx = new_hctxs;
		kfree(hctxs);
		hctxs = new_hctxs;
	}

	/* protect against switching io scheduler  */
	mutex_lock(&q->sysfs_lock);
	for (i = 0; i < set->nr_hw_queues; i++) {
		int node;
		struct blk_mq_hw_ctx *hctx;

		node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], i);
		/*
		 * If the hw queue has been mapped to another numa node,
		 * we need to realloc the hctx. If allocation fails, fallback
		 * to use the previous one.
		 */
		if (hctxs[i] && (hctxs[i]->numa_node == node))
			continue;

		hctx = blk_mq_alloc_and_init_hctx(set, q, i, node);
		if (hctx) {
			if (hctxs[i])
				blk_mq_exit_hctx(q, set, hctxs[i], i);
			hctxs[i] = hctx;
		} else {
			if (hctxs[i])
				pr_warn("Allocate new hctx on node %d fails,\
						fallback to previous one on node %d\n",
						node, hctxs[i]->numa_node);
			else
				break;
		}
	}
	/*
	 * Increasing nr_hw_queues fails. Free the newly allocated
	 * hctxs and keep the previous q->nr_hw_queues.
	 */
	if (i != set->nr_hw_queues) {
		j = q->nr_hw_queues;
		end = i;
	} else {
		j = i;
		end = q->nr_hw_queues;
		q->nr_hw_queues = set->nr_hw_queues;
	}

	for (; j < end; j++) {
		struct blk_mq_hw_ctx *hctx = hctxs[j];

		if (hctx) {
			blk_mq_exit_hctx(q, set, hctx, j);
			hctxs[j] = NULL;
		}
	}
	mutex_unlock(&q->sysfs_lock);
}

int blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
		struct request_queue *q)
{
	/* mark the queue as mq asap */
	q->mq_ops = set->ops;

	q->poll_cb = blk_stat_alloc_callback(blk_mq_poll_stats_fn,
					     blk_mq_poll_stats_bkt,
					     BLK_MQ_POLL_STATS_BKTS, q);
	if (!q->poll_cb)
		goto err_exit;

	if (blk_mq_alloc_ctxs(q))
		goto err_poll;

	/* init q->mq_kobj and sw queues' kobjects */
	blk_mq_sysfs_init(q);

	INIT_LIST_HEAD(&q->unused_hctx_list);
	spin_lock_init(&q->unused_hctx_lock);

	blk_mq_realloc_hw_ctxs(set, q);
	if (!q->nr_hw_queues)
		goto err_hctxs;

	INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
	blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);

	q->tag_set = set;

	q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;
	if (set->nr_maps > HCTX_TYPE_POLL &&
	    set->map[HCTX_TYPE_POLL].nr_queues)
		blk_queue_flag_set(QUEUE_FLAG_POLL, q);

	INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
	INIT_LIST_HEAD(&q->requeue_list);
	spin_lock_init(&q->requeue_lock);

	q->nr_requests = set->queue_depth;

	/*
	 * Default to classic polling
	 */
	q->poll_nsec = BLK_MQ_POLL_CLASSIC;

	blk_mq_init_cpu_queues(q, set->nr_hw_queues);
	blk_mq_add_queue_tag_set(set, q);
	blk_mq_map_swqueue(q);
	return 0;

err_hctxs:
	kfree(q->queue_hw_ctx);
	q->nr_hw_queues = 0;
	blk_mq_sysfs_deinit(q);
err_poll:
	blk_stat_free_callback(q->poll_cb);
	q->poll_cb = NULL;
err_exit:
	q->mq_ops = NULL;
	return -ENOMEM;
}
EXPORT_SYMBOL(blk_mq_init_allocated_queue);

/* tags can _not_ be used after returning from blk_mq_exit_queue */
void blk_mq_exit_queue(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;

	/* Checks hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED. */
	blk_mq_exit_hw_queues(q, set, set->nr_hw_queues);
	/* May clear BLK_MQ_F_TAG_QUEUE_SHARED in hctx->flags. */
	blk_mq_del_queue_tag_set(q);
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
	int i;

	if (blk_mq_is_shared_tags(set->flags)) {
		set->shared_tags = blk_mq_alloc_map_and_rqs(set,
						BLK_MQ_NO_HCTX_IDX,
						set->queue_depth);
		if (!set->shared_tags)
			return -ENOMEM;
	}

	for (i = 0; i < set->nr_hw_queues; i++) {
		if (!__blk_mq_alloc_map_and_rqs(set, i))
			goto out_unwind;
		cond_resched();
	}

	return 0;

out_unwind:
	while (--i >= 0)
		__blk_mq_free_map_and_rqs(set, i);

	if (blk_mq_is_shared_tags(set->flags)) {
		blk_mq_free_map_and_rqs(set, set->shared_tags,
					BLK_MQ_NO_HCTX_IDX);
	}

	return -ENOMEM;
}

/*
 * Allocate the request maps associated with this tag_set. Note that this
 * may reduce the depth asked for, if memory is tight. set->queue_depth
 * will be updated to reflect the allocated depth.
 */
static int blk_mq_alloc_set_map_and_rqs(struct blk_mq_tag_set *set)
{
	unsigned int depth;
	int err;

	depth = set->queue_depth;
	do {
		err = __blk_mq_alloc_rq_maps(set);
		if (!err)
			break;

		set->queue_depth >>= 1;
		if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
			err = -ENOMEM;
			break;
		}
	} while (set->queue_depth);

	if (!set->queue_depth || err) {
		pr_err("blk-mq: failed to allocate request map\n");
		return -ENOMEM;
	}

	if (depth != set->queue_depth)
		pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
						depth, set->queue_depth);

	return 0;
}

static int blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
	/*
	 * blk_mq_map_queues() and multiple .map_queues() implementations
	 * expect that set->map[HCTX_TYPE_DEFAULT].nr_queues is set to the
	 * number of hardware queues.
	 */
	if (set->nr_maps == 1)
		set->map[HCTX_TYPE_DEFAULT].nr_queues = set->nr_hw_queues;

	if (set->ops->map_queues && !is_kdump_kernel()) {
		int i;

		/*
		 * transport .map_queues is usually done in the following
		 * way:
		 *
		 * for (queue = 0; queue < set->nr_hw_queues; queue++) {
		 * 	mask = get_cpu_mask(queue)
		 * 	for_each_cpu(cpu, mask)
		 * 		set->map[x].mq_map[cpu] = queue;
		 * }
		 *
		 * When we need to remap, the table has to be cleared for
		 * killing stale mapping since one CPU may not be mapped
		 * to any hw queue.
		 */
		for (i = 0; i < set->nr_maps; i++)
			blk_mq_clear_mq_map(&set->map[i]);

		return set->ops->map_queues(set);
	} else {
		BUG_ON(set->nr_maps > 1);
		return blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
	}
}

static int blk_mq_realloc_tag_set_tags(struct blk_mq_tag_set *set,
				  int cur_nr_hw_queues, int new_nr_hw_queues)
{
	struct blk_mq_tags **new_tags;

	if (cur_nr_hw_queues >= new_nr_hw_queues)
		return 0;

	new_tags = kcalloc_node(new_nr_hw_queues, sizeof(struct blk_mq_tags *),
				GFP_KERNEL, set->numa_node);
	if (!new_tags)
		return -ENOMEM;

	if (set->tags)
		memcpy(new_tags, set->tags, cur_nr_hw_queues *
		       sizeof(*set->tags));
	kfree(set->tags);
	set->tags = new_tags;
	set->nr_hw_queues = new_nr_hw_queues;

	return 0;
}

static int blk_mq_alloc_tag_set_tags(struct blk_mq_tag_set *set,
				int new_nr_hw_queues)
{
	return blk_mq_realloc_tag_set_tags(set, 0, new_nr_hw_queues);
}

/*
 * Alloc a tag set to be associated with one or more request queues.
 * May fail with EINVAL for various error conditions. May adjust the
 * requested depth down, if it's too large. In that case, the set
 * value will be stored in set->queue_depth.
 */
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
	int i, ret;

	BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

	if (!set->nr_hw_queues)
		return -EINVAL;
	if (!set->queue_depth)
		return -EINVAL;
	if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
		return -EINVAL;

	if (!set->ops->queue_rq)
		return -EINVAL;

	if (!set->ops->get_budget ^ !set->ops->put_budget)
		return -EINVAL;

	if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
		pr_info("blk-mq: reduced tag depth to %u\n",
			BLK_MQ_MAX_DEPTH);
		set->queue_depth = BLK_MQ_MAX_DEPTH;
	}

	if (!set->nr_maps)
		set->nr_maps = 1;
	else if (set->nr_maps > HCTX_MAX_TYPES)
		return -EINVAL;

	/*
	 * If a crashdump is active, then we are potentially in a very
	 * memory constrained environment. Limit us to 1 queue and
	 * 64 tags to prevent using too much memory.
	 */
	if (is_kdump_kernel()) {
		set->nr_hw_queues = 1;
		set->nr_maps = 1;
		set->queue_depth = min(64U, set->queue_depth);
	}
	/*
	 * There is no use for more h/w queues than cpus if we just have
	 * a single map
	 */
	if (set->nr_maps == 1 && set->nr_hw_queues > nr_cpu_ids)
		set->nr_hw_queues = nr_cpu_ids;

	if (blk_mq_alloc_tag_set_tags(set, set->nr_hw_queues) < 0)
		return -ENOMEM;

	ret = -ENOMEM;
	for (i = 0; i < set->nr_maps; i++) {
		set->map[i].mq_map = kcalloc_node(nr_cpu_ids,
						  sizeof(set->map[i].mq_map[0]),
						  GFP_KERNEL, set->numa_node);
		if (!set->map[i].mq_map)
			goto out_free_mq_map;
		set->map[i].nr_queues = is_kdump_kernel() ? 1 : set->nr_hw_queues;
	}

	ret = blk_mq_update_queue_map(set);
	if (ret)
		goto out_free_mq_map;

	ret = blk_mq_alloc_set_map_and_rqs(set);
	if (ret)
		goto out_free_mq_map;

	mutex_init(&set->tag_list_lock);
	INIT_LIST_HEAD(&set->tag_list);

	return 0;

out_free_mq_map:
	for (i = 0; i < set->nr_maps; i++) {
		kfree(set->map[i].mq_map);
		set->map[i].mq_map = NULL;
	}
	kfree(set->tags);
	set->tags = NULL;
	return ret;
}
EXPORT_SYMBOL(blk_mq_alloc_tag_set);

/* allocate and initialize a tagset for a simple single-queue device */
int blk_mq_alloc_sq_tag_set(struct blk_mq_tag_set *set,
		const struct blk_mq_ops *ops, unsigned int queue_depth,
		unsigned int set_flags)
{
	memset(set, 0, sizeof(*set));
	set->ops = ops;
	set->nr_hw_queues = 1;
	set->nr_maps = 1;
	set->queue_depth = queue_depth;
	set->numa_node = NUMA_NO_NODE;
	set->flags = set_flags;
	return blk_mq_alloc_tag_set(set);
}
EXPORT_SYMBOL_GPL(blk_mq_alloc_sq_tag_set);

void blk_mq_free_tag_set(struct blk_mq_tag_set *set)
{
	int i, j;

	for (i = 0; i < set->nr_hw_queues; i++)
		__blk_mq_free_map_and_rqs(set, i);

	if (blk_mq_is_shared_tags(set->flags)) {
		blk_mq_free_map_and_rqs(set, set->shared_tags,
					BLK_MQ_NO_HCTX_IDX);
	}

	for (j = 0; j < set->nr_maps; j++) {
		kfree(set->map[j].mq_map);
		set->map[j].mq_map = NULL;
	}

	kfree(set->tags);
	set->tags = NULL;
}
EXPORT_SYMBOL(blk_mq_free_tag_set);

int blk_mq_update_nr_requests(struct request_queue *q, unsigned int nr)
{
	struct blk_mq_tag_set *set = q->tag_set;
	struct blk_mq_hw_ctx *hctx;
	int i, ret;

	if (!set)
		return -EINVAL;

	if (q->nr_requests == nr)
		return 0;

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	ret = 0;
	queue_for_each_hw_ctx(q, hctx, i) {
		if (!hctx->tags)
			continue;
		/*
		 * If we're using an MQ scheduler, just update the scheduler
		 * queue depth. This is similar to what the old code would do.
		 */
		if (hctx->sched_tags) {
			ret = blk_mq_tag_update_depth(hctx, &hctx->sched_tags,
						      nr, true);
		} else {
			ret = blk_mq_tag_update_depth(hctx, &hctx->tags, nr,
						      false);
		}
		if (ret)
			break;
		if (q->elevator && q->elevator->type->ops.depth_updated)
			q->elevator->type->ops.depth_updated(hctx);
	}
	if (!ret) {
		q->nr_requests = nr;
		if (blk_mq_is_shared_tags(set->flags)) {
			if (q->elevator)
				blk_mq_tag_update_sched_shared_tags(q);
			else
				blk_mq_tag_resize_shared_tags(set, nr);
		}
	}

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);

	return ret;
}

/*
 * request_queue and elevator_type pair.
 * It is just used by __blk_mq_update_nr_hw_queues to cache
 * the elevator_type associated with a request_queue.
 */
struct blk_mq_qe_pair {
	struct list_head node;
	struct request_queue *q;
	struct elevator_type *type;
};

/*
 * Cache the elevator_type in qe pair list and switch the
 * io scheduler to 'none'
 */
static bool blk_mq_elv_switch_none(struct list_head *head,
		struct request_queue *q)
{
	struct blk_mq_qe_pair *qe;

	if (!q->elevator)
		return true;

	qe = kmalloc(sizeof(*qe), GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY);
	if (!qe)
		return false;

	INIT_LIST_HEAD(&qe->node);
	qe->q = q;
	qe->type = q->elevator->type;
	list_add(&qe->node, head);

	mutex_lock(&q->sysfs_lock);
	/*
	 * After elevator_switch_mq, the previous elevator_queue will be
	 * released by elevator_release. The reference of the io scheduler
	 * module get by elevator_get will also be put. So we need to get
	 * a reference of the io scheduler module here to prevent it to be
	 * removed.
	 */
	__module_get(qe->type->elevator_owner);
	elevator_switch_mq(q, NULL);
	mutex_unlock(&q->sysfs_lock);

	return true;
}

static void blk_mq_elv_switch_back(struct list_head *head,
		struct request_queue *q)
{
	struct blk_mq_qe_pair *qe;
	struct elevator_type *t = NULL;

	list_for_each_entry(qe, head, node)
		if (qe->q == q) {
			t = qe->type;
			break;
		}

	if (!t)
		return;

	list_del(&qe->node);
	kfree(qe);

	mutex_lock(&q->sysfs_lock);
	elevator_switch_mq(q, t);
	mutex_unlock(&q->sysfs_lock);
}

static void __blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set,
							int nr_hw_queues)
{
	struct request_queue *q;
	LIST_HEAD(head);
	int prev_nr_hw_queues;

	lockdep_assert_held(&set->tag_list_lock);

	if (set->nr_maps == 1 && nr_hw_queues > nr_cpu_ids)
		nr_hw_queues = nr_cpu_ids;
	if (nr_hw_queues < 1)
		return;
	if (set->nr_maps == 1 && nr_hw_queues == set->nr_hw_queues)
		return;

	list_for_each_entry(q, &set->tag_list, tag_set_list)
		blk_mq_freeze_queue(q);
	/*
	 * Switch IO scheduler to 'none', cleaning up the data associated
	 * with the previous scheduler. We will switch back once we are done
	 * updating the new sw to hw queue mappings.
	 */
	list_for_each_entry(q, &set->tag_list, tag_set_list)
		if (!blk_mq_elv_switch_none(&head, q))
			goto switch_back;

	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_debugfs_unregister_hctxs(q);
		blk_mq_sysfs_unregister(q);
	}

	prev_nr_hw_queues = set->nr_hw_queues;
	if (blk_mq_realloc_tag_set_tags(set, set->nr_hw_queues, nr_hw_queues) <
	    0)
		goto reregister;

	set->nr_hw_queues = nr_hw_queues;
fallback:
	blk_mq_update_queue_map(set);
	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_realloc_hw_ctxs(set, q);
		if (q->nr_hw_queues != set->nr_hw_queues) {
			int i = prev_nr_hw_queues;

			pr_warn("Increasing nr_hw_queues to %d fails, fallback to %d\n",
					nr_hw_queues, prev_nr_hw_queues);
			for (; i < set->nr_hw_queues; i++)
				__blk_mq_free_map_and_rqs(set, i);

			set->nr_hw_queues = prev_nr_hw_queues;
			blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
			goto fallback;
		}
		blk_mq_map_swqueue(q);
	}

reregister:
	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_sysfs_register(q);
		blk_mq_debugfs_register_hctxs(q);
	}

switch_back:
	list_for_each_entry(q, &set->tag_list, tag_set_list)
		blk_mq_elv_switch_back(&head, q);

	list_for_each_entry(q, &set->tag_list, tag_set_list)
		blk_mq_unfreeze_queue(q);
}

void blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set, int nr_hw_queues)
{
	mutex_lock(&set->tag_list_lock);
	__blk_mq_update_nr_hw_queues(set, nr_hw_queues);
	mutex_unlock(&set->tag_list_lock);
}
EXPORT_SYMBOL_GPL(blk_mq_update_nr_hw_queues);

/* Enable polling stats and return whether they were already enabled. */
static bool blk_poll_stats_enable(struct request_queue *q)
{
	if (test_bit(QUEUE_FLAG_POLL_STATS, &q->queue_flags) ||
	    blk_queue_flag_test_and_set(QUEUE_FLAG_POLL_STATS, q))
		return true;
	blk_stat_add_callback(q, q->poll_cb);
	return false;
}

static void blk_mq_poll_stats_start(struct request_queue *q)
{
	/*
	 * We don't arm the callback if polling stats are not enabled or the
	 * callback is already active.
	 */
	if (!test_bit(QUEUE_FLAG_POLL_STATS, &q->queue_flags) ||
	    blk_stat_is_active(q->poll_cb))
		return;

	blk_stat_activate_msecs(q->poll_cb, 100);
}

static void blk_mq_poll_stats_fn(struct blk_stat_callback *cb)
{
	struct request_queue *q = cb->data;
	int bucket;

	for (bucket = 0; bucket < BLK_MQ_POLL_STATS_BKTS; bucket++) {
		if (cb->stat[bucket].nr_samples)
			q->poll_stat[bucket] = cb->stat[bucket];
	}
}

static unsigned long blk_mq_poll_nsecs(struct request_queue *q,
				       struct request *rq)
{
	unsigned long ret = 0;
	int bucket;

	/*
	 * If stats collection isn't on, don't sleep but turn it on for
	 * future users
	 */
	if (!blk_poll_stats_enable(q))
		return 0;

	/*
	 * As an optimistic guess, use half of the mean service time
	 * for this type of request. We can (and should) make this smarter.
	 * For instance, if the completion latencies are tight, we can
	 * get closer than just half the mean. This is especially
	 * important on devices where the completion latencies are longer
	 * than ~10 usec. We do use the stats for the relevant IO size
	 * if available which does lead to better estimates.
	 */
	bucket = blk_mq_poll_stats_bkt(rq);
	if (bucket < 0)
		return ret;

	if (q->poll_stat[bucket].nr_samples)
		ret = (q->poll_stat[bucket].mean + 1) / 2;

	return ret;
}

static bool blk_mq_poll_hybrid(struct request_queue *q, blk_qc_t qc)
{
	struct blk_mq_hw_ctx *hctx = blk_qc_to_hctx(q, qc);
	struct request *rq = blk_qc_to_rq(hctx, qc);
	struct hrtimer_sleeper hs;
	enum hrtimer_mode mode;
	unsigned int nsecs;
	ktime_t kt;

	/*
	 * If a request has completed on queue that uses an I/O scheduler, we
	 * won't get back a request from blk_qc_to_rq.
	 */
	if (!rq || (rq->rq_flags & RQF_MQ_POLL_SLEPT))
		return false;

	/*
	 * If we get here, hybrid polling is enabled. Hence poll_nsec can be:
	 *
	 *  0:	use half of prev avg
	 * >0:	use this specific value
	 */
	if (q->poll_nsec > 0)
		nsecs = q->poll_nsec;
	else
		nsecs = blk_mq_poll_nsecs(q, rq);

	if (!nsecs)
		return false;

	rq->rq_flags |= RQF_MQ_POLL_SLEPT;

	/*
	 * This will be replaced with the stats tracking code, using
	 * 'avg_completion_time / 2' as the pre-sleep target.
	 */
	kt = nsecs;

	mode = HRTIMER_MODE_REL;
	hrtimer_init_sleeper_on_stack(&hs, CLOCK_MONOTONIC, mode);
	hrtimer_set_expires(&hs.timer, kt);

	do {
		if (blk_mq_rq_state(rq) == MQ_RQ_COMPLETE)
			break;
		set_current_state(TASK_UNINTERRUPTIBLE);
		hrtimer_sleeper_start_expires(&hs, mode);
		if (hs.task)
			io_schedule();
		hrtimer_cancel(&hs.timer);
		mode = HRTIMER_MODE_ABS;
	} while (hs.task && !signal_pending(current));

	__set_current_state(TASK_RUNNING);
	destroy_hrtimer_on_stack(&hs.timer);

	/*
	 * If we sleep, have the caller restart the poll loop to reset the
	 * state.  Like for the other success return cases, the caller is
	 * responsible for checking if the IO completed.  If the IO isn't
	 * complete, we'll get called again and will go straight to the busy
	 * poll loop.
	 */
	return true;
}

static int blk_mq_poll_classic(struct request_queue *q, blk_qc_t cookie,
			       struct io_comp_batch *iob, unsigned int flags)
{
	struct blk_mq_hw_ctx *hctx = blk_qc_to_hctx(q, cookie);
	long state = get_current_state();
	int ret;

	do {
		ret = q->mq_ops->poll(hctx, iob);
		if (ret > 0) {
			__set_current_state(TASK_RUNNING);
			return ret;
		}

		if (signal_pending_state(state, current))
			__set_current_state(TASK_RUNNING);
		if (task_is_running(current))
			return 1;

		if (ret < 0 || (flags & BLK_POLL_ONESHOT))
			break;
		cpu_relax();
	} while (!need_resched());

	__set_current_state(TASK_RUNNING);
	return 0;
}

int blk_mq_poll(struct request_queue *q, blk_qc_t cookie, struct io_comp_batch *iob,
		unsigned int flags)
{
	if (!(flags & BLK_POLL_NOSLEEP) &&
	    q->poll_nsec != BLK_MQ_POLL_CLASSIC) {
		if (blk_mq_poll_hybrid(q, cookie))
			return 1;
	}
	return blk_mq_poll_classic(q, cookie, iob, flags);
}

unsigned int blk_mq_rq_cpu(struct request *rq)
{
	return rq->mq_ctx->cpu;
}
EXPORT_SYMBOL(blk_mq_rq_cpu);

void blk_mq_cancel_work_sync(struct request_queue *q)
{
	if (queue_is_mq(q)) {
		struct blk_mq_hw_ctx *hctx;
		int i;

		cancel_delayed_work_sync(&q->requeue_work);

		queue_for_each_hw_ctx(q, hctx, i)
			cancel_delayed_work_sync(&hctx->run_work);
	}
}

static int __init blk_mq_init(void)
{
	int i;

	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(blk_cpu_done, i));
	open_softirq(BLOCK_SOFTIRQ, blk_done_softirq);

	cpuhp_setup_state_nocalls(CPUHP_BLOCK_SOFTIRQ_DEAD,
				  "block/softirq:dead", NULL,
				  blk_softirq_cpu_dead);
	cpuhp_setup_state_multi(CPUHP_BLK_MQ_DEAD, "block/mq:dead", NULL,
				blk_mq_hctx_notify_dead);
	cpuhp_setup_state_multi(CPUHP_AP_BLK_MQ_ONLINE, "block/mq:online",
				blk_mq_hctx_notify_online,
				blk_mq_hctx_notify_offline);
	return 0;
}
subsys_initcall(blk_mq_init);
