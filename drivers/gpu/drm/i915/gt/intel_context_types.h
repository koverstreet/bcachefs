/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2019 Intel Corporation
 */

#ifndef __INTEL_CONTEXT_TYPES__
#define __INTEL_CONTEXT_TYPES__

#include <linux/average.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "i915_active_types.h"
#include "i915_utils.h"
#include "intel_engine_types.h"
#include "intel_sseu.h"

#define CONTEXT_REDZONE POISON_INUSE

DECLARE_EWMA(runtime, 3, 8);

struct i915_gem_context;
struct i915_vma;
struct intel_context;
struct intel_ring;

struct intel_context_ops {
	int (*alloc)(struct intel_context *ce);

	int (*pin)(struct intel_context *ce);
	void (*unpin)(struct intel_context *ce);

	void (*enter)(struct intel_context *ce);
	void (*exit)(struct intel_context *ce);

	void (*reset)(struct intel_context *ce);
	void (*destroy)(struct kref *kref);
};

struct intel_context {
	struct kref ref;

	struct intel_engine_cs *engine;
	struct intel_engine_cs *inflight;
#define intel_context_inflight(ce) ptr_mask_bits(READ_ONCE((ce)->inflight), 2)
#define intel_context_inflight_count(ce) ptr_unmask_bits(READ_ONCE((ce)->inflight), 2)

	struct i915_address_space *vm;
	struct i915_gem_context __rcu *gem_context;

	struct list_head signal_link;
	struct list_head signals;

	struct i915_vma *state;
	struct intel_ring *ring;
	struct intel_timeline *timeline;

	unsigned long flags;
#define CONTEXT_BARRIER_BIT		0
#define CONTEXT_ALLOC_BIT		1
#define CONTEXT_VALID_BIT		2
#define CONTEXT_CLOSED_BIT		3
#define CONTEXT_USE_SEMAPHORES		4
#define CONTEXT_BANNED			5
#define CONTEXT_FORCE_SINGLE_SUBMISSION	6
#define CONTEXT_NOPREEMPT		7

	u32 *lrc_reg_state;
	union {
		struct {
			u32 lrca;
			u32 ccid;
		};
		u64 desc;
	} lrc;
	u32 tag; /* cookie passed to HW to track this context on submission */

	/* Time on GPU as tracked by the hw. */
	struct {
		struct ewma_runtime avg;
		u64 total;
		u32 last;
		I915_SELFTEST_DECLARE(u32 num_underflow);
		I915_SELFTEST_DECLARE(u32 max_underflow);
	} runtime;

	unsigned int active_count; /* protected by timeline->mutex */

	atomic_t pin_count;
	struct mutex pin_mutex; /* guards pinning and associated on-gpuing */

	/**
	 * active: Active tracker for the rq activity (inc. external) on this
	 * intel_context object.
	 */
	struct i915_active active;

	const struct intel_context_ops *ops;

	/** sseu: Control eu/slice partitioning */
	struct intel_sseu sseu;

	u8 wa_bb_page; /* if set, page num reserved for context workarounds */
};

#endif /* __INTEL_CONTEXT_TYPES__ */
