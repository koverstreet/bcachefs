/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_X86_XSAVE_H
#define __ASM_X86_XSAVE_H

#include <linux/uaccess.h>
#include <linux/types.h>

#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/user.h>

/* Bit 63 of XCR0 is reserved for future expansion */
#define XFEATURE_MASK_EXTEND	(~(XFEATURE_MASK_FPSSE | (1ULL << 63)))

#define XSTATE_CPUID		0x0000000d

#define TILE_CPUID		0x0000001d

#define FXSAVE_SIZE	512

#define XSAVE_HDR_SIZE	    64
#define XSAVE_HDR_OFFSET    FXSAVE_SIZE

#define XSAVE_YMM_SIZE	    256
#define XSAVE_YMM_OFFSET    (XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

#define XSAVE_ALIGNMENT     64

/* All currently supported user features */
#define XFEATURE_MASK_USER_SUPPORTED (XFEATURE_MASK_FP | \
				      XFEATURE_MASK_SSE | \
				      XFEATURE_MASK_YMM | \
				      XFEATURE_MASK_OPMASK | \
				      XFEATURE_MASK_ZMM_Hi256 | \
				      XFEATURE_MASK_Hi16_ZMM	 | \
				      XFEATURE_MASK_PKRU | \
				      XFEATURE_MASK_BNDREGS | \
				      XFEATURE_MASK_BNDCSR | \
				      XFEATURE_MASK_XTILE)

/*
 * Features which are restored when returning to user space.
 * PKRU is not restored on return to user space because PKRU
 * is switched eagerly in switch_to() and flush_thread()
 */
#define XFEATURE_MASK_USER_RESTORE	\
	(XFEATURE_MASK_USER_SUPPORTED & ~XFEATURE_MASK_PKRU)

/* Features which are dynamically enabled for a process on request */
#define XFEATURE_MASK_USER_DYNAMIC	XFEATURE_MASK_XTILE_DATA

/* All currently supported supervisor features */
#define XFEATURE_MASK_SUPERVISOR_SUPPORTED (XFEATURE_MASK_PASID)

/*
 * A supervisor state component may not always contain valuable information,
 * and its size may be huge. Saving/restoring such supervisor state components
 * at each context switch can cause high CPU and space overhead, which should
 * be avoided. Such supervisor state components should only be saved/restored
 * on demand. The on-demand supervisor features are set in this mask.
 *
 * Unlike the existing supported supervisor features, an independent supervisor
 * feature does not allocate a buffer in task->fpu, and the corresponding
 * supervisor state component cannot be saved/restored at each context switch.
 *
 * To support an independent supervisor feature, a developer should follow the
 * dos and don'ts as below:
 * - Do dynamically allocate a buffer for the supervisor state component.
 * - Do manually invoke the XSAVES/XRSTORS instruction to save/restore the
 *   state component to/from the buffer.
 * - Don't set the bit corresponding to the independent supervisor feature in
 *   IA32_XSS at run time, since it has been set at boot time.
 */
#define XFEATURE_MASK_INDEPENDENT (XFEATURE_MASK_LBR)

/*
 * Unsupported supervisor features. When a supervisor feature in this mask is
 * supported in the future, move it to the supported supervisor feature mask.
 */
#define XFEATURE_MASK_SUPERVISOR_UNSUPPORTED (XFEATURE_MASK_PT)

/* All supervisor states including supported and unsupported states. */
#define XFEATURE_MASK_SUPERVISOR_ALL (XFEATURE_MASK_SUPERVISOR_SUPPORTED | \
				      XFEATURE_MASK_INDEPENDENT | \
				      XFEATURE_MASK_SUPERVISOR_UNSUPPORTED)

/*
 * The feature mask required to restore FPU state:
 * - All user states which are not eagerly switched in switch_to()/exec()
 * - The suporvisor states
 */
#define XFEATURE_MASK_FPSTATE	(XFEATURE_MASK_USER_RESTORE | \
				 XFEATURE_MASK_SUPERVISOR_SUPPORTED)

/*
 * Features in this mask have space allocated in the signal frame, but may not
 * have that space initialized when the feature is in its init state.
 */
#define XFEATURE_MASK_SIGFRAME_INITOPT	(XFEATURE_MASK_XTILE | \
					 XFEATURE_MASK_USER_DYNAMIC)

extern u64 xstate_fx_sw_bytes[USER_XSTATE_FX_SW_WORDS];

extern void __init update_regset_xstate_info(unsigned int size,
					     u64 xstate_mask);

int xfeature_size(int xfeature_nr);

void xsaves(struct xregs_state *xsave, u64 mask);
void xrstors(struct xregs_state *xsave, u64 mask);

int xfd_enable_feature(u64 xfd_err);

#ifdef CONFIG_X86_64
DECLARE_STATIC_KEY_FALSE(__fpu_state_size_dynamic);
#endif

#ifdef CONFIG_X86_64
DECLARE_STATIC_KEY_FALSE(__fpu_state_size_dynamic);

static __always_inline __pure bool fpu_state_size_dynamic(void)
{
	return static_branch_unlikely(&__fpu_state_size_dynamic);
}
#else
static __always_inline __pure bool fpu_state_size_dynamic(void)
{
	return false;
}
#endif

#endif
