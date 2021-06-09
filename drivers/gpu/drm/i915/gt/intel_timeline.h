/*
 * Copyright © 2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#ifndef I915_TIMELINE_H
#define I915_TIMELINE_H

#include <linux/lockdep.h>

#include "i915_active.h"
#include "i915_syncmap.h"
#include "intel_timeline_types.h"

struct drm_printer;

struct intel_timeline *
__intel_timeline_create(struct intel_gt *gt,
			struct i915_vma *global_hwsp,
			unsigned int offset);

static inline struct intel_timeline *
intel_timeline_create(struct intel_gt *gt)
{
	return __intel_timeline_create(gt, NULL, 0);
}

struct intel_timeline *
intel_timeline_create_from_engine(struct intel_engine_cs *engine,
				  unsigned int offset);

static inline struct intel_timeline *
intel_timeline_get(struct intel_timeline *timeline)
{
	kref_get(&timeline->kref);
	return timeline;
}

void __intel_timeline_free(struct kref *kref);
static inline void intel_timeline_put(struct intel_timeline *timeline)
{
	kref_put(&timeline->kref, __intel_timeline_free);
}

static inline int __intel_timeline_sync_set(struct intel_timeline *tl,
					    u64 context, u32 seqno)
{
	return i915_syncmap_set(&tl->sync, context, seqno);
}

static inline int intel_timeline_sync_set(struct intel_timeline *tl,
					  const struct dma_fence *fence)
{
	return __intel_timeline_sync_set(tl, fence->context, fence->seqno);
}

static inline bool __intel_timeline_sync_is_later(struct intel_timeline *tl,
						  u64 context, u32 seqno)
{
	return i915_syncmap_is_later(&tl->sync, context, seqno);
}

static inline bool intel_timeline_sync_is_later(struct intel_timeline *tl,
						const struct dma_fence *fence)
{
	return __intel_timeline_sync_is_later(tl, fence->context, fence->seqno);
}

void __intel_timeline_pin(struct intel_timeline *tl);
int intel_timeline_pin(struct intel_timeline *tl, struct i915_gem_ww_ctx *ww);
void intel_timeline_enter(struct intel_timeline *tl);
int intel_timeline_get_seqno(struct intel_timeline *tl,
			     struct i915_request *rq,
			     u32 *seqno);
void intel_timeline_exit(struct intel_timeline *tl);
void intel_timeline_unpin(struct intel_timeline *tl);

void intel_timeline_reset_seqno(const struct intel_timeline *tl);

int intel_timeline_read_hwsp(struct i915_request *from,
			     struct i915_request *until,
			     u32 *hwsp_offset);

void intel_gt_init_timelines(struct intel_gt *gt);
void intel_gt_fini_timelines(struct intel_gt *gt);

void intel_gt_show_timelines(struct intel_gt *gt,
			     struct drm_printer *m,
			     void (*show_request)(struct drm_printer *m,
						  const struct i915_request *rq,
						  const char *prefix,
						  int indent));

static inline bool
intel_timeline_is_last(const struct intel_timeline *tl,
		       const struct i915_request *rq)
{
	return list_is_last_rcu(&rq->link, &tl->requests);
}

#endif
