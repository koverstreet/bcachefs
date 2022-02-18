/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2014-2019 Intel Corporation
 */

#ifndef _INTEL_GUC_H_
#define _INTEL_GUC_H_

#include <linux/xarray.h>
#include <linux/delay.h>

#include "intel_uncore.h"
#include "intel_guc_fw.h"
#include "intel_guc_fwif.h"
#include "intel_guc_ct.h"
#include "intel_guc_log.h"
#include "intel_guc_reg.h"
#include "intel_guc_slpc_types.h"
#include "intel_uc_fw.h"
#include "i915_utils.h"
#include "i915_vma.h"

struct __guc_ads_blob;

/**
 * struct intel_guc - Top level structure of GuC.
 *
 * It handles firmware loading and manages client pool. intel_guc owns an
 * i915_sched_engine for submission.
 */
struct intel_guc {
	/** @fw: the GuC firmware */
	struct intel_uc_fw fw;
	/** @log: sub-structure containing GuC log related data and objects */
	struct intel_guc_log log;
	/** @ct: the command transport communication channel */
	struct intel_guc_ct ct;
	/** @slpc: sub-structure containing SLPC related data and objects */
	struct intel_guc_slpc slpc;

	/** @sched_engine: Global engine used to submit requests to GuC */
	struct i915_sched_engine *sched_engine;
	/**
	 * @stalled_request: if GuC can't process a request for any reason, we
	 * save it until GuC restarts processing. No other request can be
	 * submitted until the stalled request is processed.
	 */
	struct i915_request *stalled_request;
	/**
	 * @submission_stall_reason: reason why submission is stalled
	 */
	enum {
		STALL_NONE,
		STALL_REGISTER_CONTEXT,
		STALL_MOVE_LRC_TAIL,
		STALL_ADD_REQUEST,
	} submission_stall_reason;

	/* intel_guc_recv interrupt related state */
	/** @irq_lock: protects GuC irq state */
	spinlock_t irq_lock;
	/**
	 * @msg_enabled_mask: mask of events that are processed when receiving
	 * an INTEL_GUC_ACTION_DEFAULT G2H message.
	 */
	unsigned int msg_enabled_mask;

	/**
	 * @outstanding_submission_g2h: number of outstanding GuC to Host
	 * responses related to GuC submission, used to determine if the GT is
	 * idle
	 */
	atomic_t outstanding_submission_g2h;

	/** @interrupts: pointers to GuC interrupt-managing functions. */
	struct {
		void (*reset)(struct intel_guc *guc);
		void (*enable)(struct intel_guc *guc);
		void (*disable)(struct intel_guc *guc);
	} interrupts;

	/**
	 * @submission_state: sub-structure for submission state protected by
	 * single lock
	 */
	struct {
		/**
		 * @lock: protects everything in submission_state,
		 * ce->guc_id.id, and ce->guc_id.ref when transitioning in and
		 * out of zero
		 */
		spinlock_t lock;
		/**
		 * @guc_ids: used to allocate new guc_ids, single-lrc
		 */
		struct ida guc_ids;
		/**
		 * @guc_ids_bitmap: used to allocate new guc_ids, multi-lrc
		 */
		unsigned long *guc_ids_bitmap;
		/**
		 * @guc_id_list: list of intel_context with valid guc_ids but no
		 * refs
		 */
		struct list_head guc_id_list;
		/**
		 * @destroyed_contexts: list of contexts waiting to be destroyed
		 * (deregistered with the GuC)
		 */
		struct list_head destroyed_contexts;
		/**
		 * @destroyed_worker: worker to deregister contexts, need as we
		 * need to take a GT PM reference and can't from destroy
		 * function as it might be in an atomic context (no sleeping)
		 */
		struct work_struct destroyed_worker;
	} submission_state;

	/**
	 * @submission_supported: tracks whether we support GuC submission on
	 * the current platform
	 */
	bool submission_supported;
	/** @submission_selected: tracks whether the user enabled GuC submission */
	bool submission_selected;
	/**
	 * @rc_supported: tracks whether we support GuC rc on the current platform
	 */
	bool rc_supported;
	/** @rc_selected: tracks whether the user enabled GuC rc */
	bool rc_selected;

	/** @ads_vma: object allocated to hold the GuC ADS */
	struct i915_vma *ads_vma;
	/** @ads_blob: contents of the GuC ADS */
	struct __guc_ads_blob *ads_blob;
	/** @ads_regset_size: size of the save/restore regsets in the ADS */
	u32 ads_regset_size;
	/** @ads_golden_ctxt_size: size of the golden contexts in the ADS */
	u32 ads_golden_ctxt_size;

	/** @lrc_desc_pool: object allocated to hold the GuC LRC descriptor pool */
	struct i915_vma *lrc_desc_pool;
	/** @lrc_desc_pool_vaddr: contents of the GuC LRC descriptor pool */
	void *lrc_desc_pool_vaddr;

	/**
	 * @context_lookup: used to resolve intel_context from guc_id, if a
	 * context is present in this structure it is registered with the GuC
	 */
	struct xarray context_lookup;

	/** @params: Control params for fw initialization */
	u32 params[GUC_CTL_MAX_DWORDS];

	/** @send_regs: GuC's FW specific registers used for sending MMIO H2G */
	struct {
		u32 base;
		unsigned int count;
		enum forcewake_domains fw_domains;
	} send_regs;

	/** @notify_reg: register used to send interrupts to the GuC FW */
	i915_reg_t notify_reg;

	/**
	 * @mmio_msg: notification bitmask that the GuC writes in one of its
	 * registers when the CT channel is disabled, to be processed when the
	 * channel is back up.
	 */
	u32 mmio_msg;

	/** @send_mutex: used to serialize the intel_guc_send actions */
	struct mutex send_mutex;
};

static inline struct intel_guc *log_to_guc(struct intel_guc_log *log)
{
	return container_of(log, struct intel_guc, log);
}

static
inline int intel_guc_send(struct intel_guc *guc, const u32 *action, u32 len)
{
	return intel_guc_ct_send(&guc->ct, action, len, NULL, 0, 0);
}

static
inline int intel_guc_send_nb(struct intel_guc *guc, const u32 *action, u32 len,
			     u32 g2h_len_dw)
{
	return intel_guc_ct_send(&guc->ct, action, len, NULL, 0,
				 MAKE_SEND_FLAGS(g2h_len_dw));
}

static inline int
intel_guc_send_and_receive(struct intel_guc *guc, const u32 *action, u32 len,
			   u32 *response_buf, u32 response_buf_size)
{
	return intel_guc_ct_send(&guc->ct, action, len,
				 response_buf, response_buf_size, 0);
}

static inline int intel_guc_send_busy_loop(struct intel_guc *guc,
					   const u32 *action,
					   u32 len,
					   u32 g2h_len_dw,
					   bool loop)
{
	int err;
	unsigned int sleep_period_ms = 1;
	bool not_atomic = !in_atomic() && !irqs_disabled();

	/*
	 * FIXME: Have caller pass in if we are in an atomic context to avoid
	 * using in_atomic(). It is likely safe here as we check for irqs
	 * disabled which basically all the spin locks in the i915 do but
	 * regardless this should be cleaned up.
	 */

	/* No sleeping with spin locks, just busy loop */
	might_sleep_if(loop && not_atomic);

retry:
	err = intel_guc_send_nb(guc, action, len, g2h_len_dw);
	if (unlikely(err == -EBUSY && loop)) {
		if (likely(not_atomic)) {
			if (msleep_interruptible(sleep_period_ms))
				return -EINTR;
			sleep_period_ms = sleep_period_ms << 1;
		} else {
			cpu_relax();
		}
		goto retry;
	}

	return err;
}

static inline void intel_guc_to_host_event_handler(struct intel_guc *guc)
{
	intel_guc_ct_event_handler(&guc->ct);
}

/* GuC addresses above GUC_GGTT_TOP also don't map through the GTT */
#define GUC_GGTT_TOP	0xFEE00000

/**
 * intel_guc_ggtt_offset() - Get and validate the GGTT offset of @vma
 * @guc: intel_guc structure.
 * @vma: i915 graphics virtual memory area.
 *
 * GuC does not allow any gfx GGTT address that falls into range
 * [0, ggtt.pin_bias), which is reserved for Boot ROM, SRAM and WOPCM.
 * Currently, in order to exclude [0, ggtt.pin_bias) address space from
 * GGTT, all gfx objects used by GuC are allocated with intel_guc_allocate_vma()
 * and pinned with PIN_OFFSET_BIAS along with the value of ggtt.pin_bias.
 *
 * Return: GGTT offset of the @vma.
 */
static inline u32 intel_guc_ggtt_offset(struct intel_guc *guc,
					struct i915_vma *vma)
{
	u32 offset = i915_ggtt_offset(vma);

	GEM_BUG_ON(offset < i915_ggtt_pin_bias(vma));
	GEM_BUG_ON(range_overflows_t(u64, offset, vma->size, GUC_GGTT_TOP));

	return offset;
}

void intel_guc_init_early(struct intel_guc *guc);
void intel_guc_init_late(struct intel_guc *guc);
void intel_guc_init_send_regs(struct intel_guc *guc);
void intel_guc_write_params(struct intel_guc *guc);
int intel_guc_init(struct intel_guc *guc);
void intel_guc_fini(struct intel_guc *guc);
void intel_guc_notify(struct intel_guc *guc);
int intel_guc_send_mmio(struct intel_guc *guc, const u32 *action, u32 len,
			u32 *response_buf, u32 response_buf_size);
int intel_guc_to_host_process_recv_msg(struct intel_guc *guc,
				       const u32 *payload, u32 len);
int intel_guc_auth_huc(struct intel_guc *guc, u32 rsa_offset);
int intel_guc_suspend(struct intel_guc *guc);
int intel_guc_resume(struct intel_guc *guc);
struct i915_vma *intel_guc_allocate_vma(struct intel_guc *guc, u32 size);
int intel_guc_allocate_and_map_vma(struct intel_guc *guc, u32 size,
				   struct i915_vma **out_vma, void **out_vaddr);

static inline bool intel_guc_is_supported(struct intel_guc *guc)
{
	return intel_uc_fw_is_supported(&guc->fw);
}

static inline bool intel_guc_is_wanted(struct intel_guc *guc)
{
	return intel_uc_fw_is_enabled(&guc->fw);
}

static inline bool intel_guc_is_used(struct intel_guc *guc)
{
	GEM_BUG_ON(__intel_uc_fw_status(&guc->fw) == INTEL_UC_FIRMWARE_SELECTED);
	return intel_uc_fw_is_available(&guc->fw);
}

static inline bool intel_guc_is_fw_running(struct intel_guc *guc)
{
	return intel_uc_fw_is_running(&guc->fw);
}

static inline bool intel_guc_is_ready(struct intel_guc *guc)
{
	return intel_guc_is_fw_running(guc) && intel_guc_ct_enabled(&guc->ct);
}

static inline void intel_guc_reset_interrupts(struct intel_guc *guc)
{
	guc->interrupts.reset(guc);
}

static inline void intel_guc_enable_interrupts(struct intel_guc *guc)
{
	guc->interrupts.enable(guc);
}

static inline void intel_guc_disable_interrupts(struct intel_guc *guc)
{
	guc->interrupts.disable(guc);
}

static inline int intel_guc_sanitize(struct intel_guc *guc)
{
	intel_uc_fw_sanitize(&guc->fw);
	intel_guc_disable_interrupts(guc);
	intel_guc_ct_sanitize(&guc->ct);
	guc->mmio_msg = 0;

	return 0;
}

static inline void intel_guc_enable_msg(struct intel_guc *guc, u32 mask)
{
	spin_lock_irq(&guc->irq_lock);
	guc->msg_enabled_mask |= mask;
	spin_unlock_irq(&guc->irq_lock);
}

static inline void intel_guc_disable_msg(struct intel_guc *guc, u32 mask)
{
	spin_lock_irq(&guc->irq_lock);
	guc->msg_enabled_mask &= ~mask;
	spin_unlock_irq(&guc->irq_lock);
}

int intel_guc_wait_for_idle(struct intel_guc *guc, long timeout);

int intel_guc_deregister_done_process_msg(struct intel_guc *guc,
					  const u32 *msg, u32 len);
int intel_guc_sched_done_process_msg(struct intel_guc *guc,
				     const u32 *msg, u32 len);
int intel_guc_context_reset_process_msg(struct intel_guc *guc,
					const u32 *msg, u32 len);
int intel_guc_engine_failure_process_msg(struct intel_guc *guc,
					 const u32 *msg, u32 len);

void intel_guc_find_hung_context(struct intel_engine_cs *engine);

int intel_guc_global_policies_update(struct intel_guc *guc);

void intel_guc_context_ban(struct intel_context *ce, struct i915_request *rq);

void intel_guc_submission_reset_prepare(struct intel_guc *guc);
void intel_guc_submission_reset(struct intel_guc *guc, bool stalled);
void intel_guc_submission_reset_finish(struct intel_guc *guc);
void intel_guc_submission_cancel_requests(struct intel_guc *guc);

void intel_guc_load_status(struct intel_guc *guc, struct drm_printer *p);

void intel_guc_write_barrier(struct intel_guc *guc);

#endif
