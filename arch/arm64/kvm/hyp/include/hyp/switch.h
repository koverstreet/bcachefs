// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM64_KVM_HYP_SWITCH_H__
#define __ARM64_KVM_HYP_SWITCH_H__

#include <hyp/adjust_pc.h>
#include <hyp/fault.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/extable.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>

struct kvm_exception_table_entry {
	int insn, fixup;
};

extern struct kvm_exception_table_entry __start___kvm_ex_table;
extern struct kvm_exception_table_entry __stop___kvm_ex_table;

/* Check whether the FP regs were dirtied while in the host-side run loop: */
static inline bool update_fp_enabled(struct kvm_vcpu *vcpu)
{
	/*
	 * When the system doesn't support FP/SIMD, we cannot rely on
	 * the _TIF_FOREIGN_FPSTATE flag. However, we always inject an
	 * abort on the very first access to FP and thus we should never
	 * see KVM_ARM64_FP_ENABLED. For added safety, make sure we always
	 * trap the accesses.
	 */
	if (!system_supports_fpsimd() ||
	    vcpu->arch.host_thread_info->flags & _TIF_FOREIGN_FPSTATE)
		vcpu->arch.flags &= ~(KVM_ARM64_FP_ENABLED |
				      KVM_ARM64_FP_HOST);

	return !!(vcpu->arch.flags & KVM_ARM64_FP_ENABLED);
}

/* Save the 32-bit only FPSIMD system register state */
static inline void __fpsimd_save_fpexc32(struct kvm_vcpu *vcpu)
{
	if (!vcpu_el1_is_32bit(vcpu))
		return;

	__vcpu_sys_reg(vcpu, FPEXC32_EL2) = read_sysreg(fpexc32_el2);
}

static inline void __activate_traps_fpsimd32(struct kvm_vcpu *vcpu)
{
	/*
	 * We are about to set CPTR_EL2.TFP to trap all floating point
	 * register accesses to EL2, however, the ARM ARM clearly states that
	 * traps are only taken to EL2 if the operation would not otherwise
	 * trap to EL1.  Therefore, always make sure that for 32-bit guests,
	 * we set FPEXC.EN to prevent traps to EL1, when setting the TFP bit.
	 * If FP/ASIMD is not implemented, FPEXC is UNDEFINED and any access to
	 * it will cause an exception.
	 */
	if (vcpu_el1_is_32bit(vcpu) && system_supports_fpsimd()) {
		write_sysreg(1 << 30, fpexc32_el2);
		isb();
	}
}

static inline void __activate_traps_common(struct kvm_vcpu *vcpu)
{
	/* Trap on AArch32 cp15 c15 (impdef sysregs) accesses (EL1 or EL0) */
	write_sysreg(1 << 15, hstr_el2);

	/*
	 * Make sure we trap PMU access from EL0 to EL2. Also sanitize
	 * PMSELR_EL0 to make sure it never contains the cycle
	 * counter, which could make a PMXEVCNTR_EL0 access UNDEF at
	 * EL1 instead of being trapped to EL2.
	 */
	if (kvm_arm_support_pmu_v3()) {
		write_sysreg(0, pmselr_el0);
		write_sysreg(ARMV8_PMU_USERENR_MASK, pmuserenr_el0);
	}

	vcpu->arch.mdcr_el2_host = read_sysreg(mdcr_el2);
	write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);
}

static inline void __deactivate_traps_common(struct kvm_vcpu *vcpu)
{
	write_sysreg(vcpu->arch.mdcr_el2_host, mdcr_el2);

	write_sysreg(0, hstr_el2);
	if (kvm_arm_support_pmu_v3())
		write_sysreg(0, pmuserenr_el0);
}

static inline void ___activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = vcpu->arch.hcr_el2;

	if (cpus_have_final_cap(ARM64_WORKAROUND_CAVIUM_TX2_219_TVM))
		hcr |= HCR_TVM;

	write_sysreg(hcr, hcr_el2);

	if (cpus_have_final_cap(ARM64_HAS_RAS_EXTN) && (hcr & HCR_VSE))
		write_sysreg_s(vcpu->arch.vsesr_el2, SYS_VSESR_EL2);
}

static inline void ___deactivate_traps(struct kvm_vcpu *vcpu)
{
	/*
	 * If we pended a virtual abort, preserve it until it gets
	 * cleared. See D1.14.3 (Virtual Interrupts) for details, but
	 * the crucial bit is "On taking a vSError interrupt,
	 * HCR_EL2.VSE is cleared to 0."
	 */
	if (vcpu->arch.hcr_el2 & HCR_VSE) {
		vcpu->arch.hcr_el2 &= ~HCR_VSE;
		vcpu->arch.hcr_el2 |= read_sysreg(hcr_el2) & HCR_VSE;
	}
}

static inline bool __populate_fault_info(struct kvm_vcpu *vcpu)
{
	return __get_fault_info(vcpu->arch.fault.esr_el2, &vcpu->arch.fault);
}

static inline void __hyp_sve_save_host(struct kvm_vcpu *vcpu)
{
	struct thread_struct *thread;

	thread = container_of(vcpu->arch.host_fpsimd_state, struct thread_struct,
			      uw.fpsimd_state);

	__sve_save_state(sve_pffr(thread), &vcpu->arch.host_fpsimd_state->fpsr);
}

static inline void __hyp_sve_restore_guest(struct kvm_vcpu *vcpu)
{
	sve_cond_update_zcr_vq(vcpu_sve_max_vq(vcpu) - 1, SYS_ZCR_EL2);
	__sve_restore_state(vcpu_sve_pffr(vcpu),
			    &vcpu->arch.ctxt.fp_regs.fpsr);
	write_sysreg_el1(__vcpu_sys_reg(vcpu, ZCR_EL1), SYS_ZCR);
}

/*
 * We trap the first access to the FP/SIMD to save the host context and
 * restore the guest context lazily.
 * If FP/SIMD is not implemented, handle the trap and inject an undefined
 * instruction exception to the guest. Similarly for trapped SVE accesses.
 */
static bool kvm_hyp_handle_fpsimd(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	bool sve_guest, sve_host;
	u8 esr_ec;
	u64 reg;

	if (!system_supports_fpsimd())
		return false;

	if (system_supports_sve()) {
		sve_guest = vcpu_has_sve(vcpu);
		sve_host = vcpu->arch.flags & KVM_ARM64_HOST_SVE_IN_USE;
	} else {
		sve_guest = false;
		sve_host = false;
	}

	esr_ec = kvm_vcpu_trap_get_class(vcpu);

	/* Don't handle SVE traps for non-SVE vcpus here: */
	if (!sve_guest && esr_ec != ESR_ELx_EC_FP_ASIMD)
		return false;

	/* Valid trap.  Switch the context: */
	if (has_vhe()) {
		reg = CPACR_EL1_FPEN;
		if (sve_guest)
			reg |= CPACR_EL1_ZEN;

		sysreg_clear_set(cpacr_el1, 0, reg);
	} else {
		reg = CPTR_EL2_TFP;
		if (sve_guest)
			reg |= CPTR_EL2_TZ;

		sysreg_clear_set(cptr_el2, reg, 0);
	}
	isb();

	if (vcpu->arch.flags & KVM_ARM64_FP_HOST) {
		if (sve_host)
			__hyp_sve_save_host(vcpu);
		else
			__fpsimd_save_state(vcpu->arch.host_fpsimd_state);

		vcpu->arch.flags &= ~KVM_ARM64_FP_HOST;
	}

	if (sve_guest)
		__hyp_sve_restore_guest(vcpu);
	else
		__fpsimd_restore_state(&vcpu->arch.ctxt.fp_regs);

	/* Skip restoring fpexc32 for AArch64 guests */
	if (!(read_sysreg(hcr_el2) & HCR_RW))
		write_sysreg(__vcpu_sys_reg(vcpu, FPEXC32_EL2), fpexc32_el2);

	vcpu->arch.flags |= KVM_ARM64_FP_ENABLED;

	return true;
}

static inline bool handle_tx2_tvm(struct kvm_vcpu *vcpu)
{
	u32 sysreg = esr_sys64_to_sysreg(kvm_vcpu_get_esr(vcpu));
	int rt = kvm_vcpu_sys_get_rt(vcpu);
	u64 val = vcpu_get_reg(vcpu, rt);

	/*
	 * The normal sysreg handling code expects to see the traps,
	 * let's not do anything here.
	 */
	if (vcpu->arch.hcr_el2 & HCR_TVM)
		return false;

	switch (sysreg) {
	case SYS_SCTLR_EL1:
		write_sysreg_el1(val, SYS_SCTLR);
		break;
	case SYS_TTBR0_EL1:
		write_sysreg_el1(val, SYS_TTBR0);
		break;
	case SYS_TTBR1_EL1:
		write_sysreg_el1(val, SYS_TTBR1);
		break;
	case SYS_TCR_EL1:
		write_sysreg_el1(val, SYS_TCR);
		break;
	case SYS_ESR_EL1:
		write_sysreg_el1(val, SYS_ESR);
		break;
	case SYS_FAR_EL1:
		write_sysreg_el1(val, SYS_FAR);
		break;
	case SYS_AFSR0_EL1:
		write_sysreg_el1(val, SYS_AFSR0);
		break;
	case SYS_AFSR1_EL1:
		write_sysreg_el1(val, SYS_AFSR1);
		break;
	case SYS_MAIR_EL1:
		write_sysreg_el1(val, SYS_MAIR);
		break;
	case SYS_AMAIR_EL1:
		write_sysreg_el1(val, SYS_AMAIR);
		break;
	case SYS_CONTEXTIDR_EL1:
		write_sysreg_el1(val, SYS_CONTEXTIDR);
		break;
	default:
		return false;
	}

	__kvm_skip_instr(vcpu);
	return true;
}

static inline bool esr_is_ptrauth_trap(u32 esr)
{
	switch (esr_sys64_to_sysreg(esr)) {
	case SYS_APIAKEYLO_EL1:
	case SYS_APIAKEYHI_EL1:
	case SYS_APIBKEYLO_EL1:
	case SYS_APIBKEYHI_EL1:
	case SYS_APDAKEYLO_EL1:
	case SYS_APDAKEYHI_EL1:
	case SYS_APDBKEYLO_EL1:
	case SYS_APDBKEYHI_EL1:
	case SYS_APGAKEYLO_EL1:
	case SYS_APGAKEYHI_EL1:
		return true;
	}

	return false;
}

#define __ptrauth_save_key(ctxt, key)					\
	do {								\
	u64 __val;                                                      \
	__val = read_sysreg_s(SYS_ ## key ## KEYLO_EL1);                \
	ctxt_sys_reg(ctxt, key ## KEYLO_EL1) = __val;                   \
	__val = read_sysreg_s(SYS_ ## key ## KEYHI_EL1);                \
	ctxt_sys_reg(ctxt, key ## KEYHI_EL1) = __val;                   \
} while(0)

DECLARE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);

static bool kvm_hyp_handle_ptrauth(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	struct kvm_cpu_context *ctxt;
	u64 val;

	if (!vcpu_has_ptrauth(vcpu))
		return false;

	ctxt = this_cpu_ptr(&kvm_hyp_ctxt);
	__ptrauth_save_key(ctxt, APIA);
	__ptrauth_save_key(ctxt, APIB);
	__ptrauth_save_key(ctxt, APDA);
	__ptrauth_save_key(ctxt, APDB);
	__ptrauth_save_key(ctxt, APGA);

	vcpu_ptrauth_enable(vcpu);

	val = read_sysreg(hcr_el2);
	val |= (HCR_API | HCR_APK);
	write_sysreg(val, hcr_el2);

	return true;
}

static bool kvm_hyp_handle_sysreg(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	if (cpus_have_final_cap(ARM64_WORKAROUND_CAVIUM_TX2_219_TVM) &&
	    handle_tx2_tvm(vcpu))
		return true;

	if (static_branch_unlikely(&vgic_v3_cpuif_trap) &&
	    __vgic_v3_perform_cpuif_access(vcpu) == 1)
		return true;

	if (esr_is_ptrauth_trap(kvm_vcpu_get_esr(vcpu)))
		return kvm_hyp_handle_ptrauth(vcpu, exit_code);

	return false;
}

static bool kvm_hyp_handle_cp15_32(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	if (static_branch_unlikely(&vgic_v3_cpuif_trap) &&
	    __vgic_v3_perform_cpuif_access(vcpu) == 1)
		return true;

	return false;
}

static bool kvm_hyp_handle_iabt_low(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	if (!__populate_fault_info(vcpu))
		return true;

	return false;
}

static bool kvm_hyp_handle_dabt_low(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	if (!__populate_fault_info(vcpu))
		return true;

	if (static_branch_unlikely(&vgic_v2_cpuif_trap)) {
		bool valid;

		valid = kvm_vcpu_trap_get_fault_type(vcpu) == FSC_FAULT &&
			kvm_vcpu_dabt_isvalid(vcpu) &&
			!kvm_vcpu_abt_issea(vcpu) &&
			!kvm_vcpu_abt_iss1tw(vcpu);

		if (valid) {
			int ret = __vgic_v2_perform_cpuif_access(vcpu);

			if (ret == 1)
				return true;

			/* Promote an illegal access to an SError.*/
			if (ret == -1)
				*exit_code = ARM_EXCEPTION_EL1_SERROR;
		}
	}

	return false;
}

typedef bool (*exit_handler_fn)(struct kvm_vcpu *, u64 *);

static const exit_handler_fn *kvm_get_exit_handler_array(struct kvm_vcpu *vcpu);

static void early_exit_filter(struct kvm_vcpu *vcpu, u64 *exit_code);

/*
 * Allow the hypervisor to handle the exit with an exit handler if it has one.
 *
 * Returns true if the hypervisor handled the exit, and control should go back
 * to the guest, or false if it hasn't.
 */
static inline bool kvm_hyp_handle_exit(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	const exit_handler_fn *handlers = kvm_get_exit_handler_array(vcpu);
	exit_handler_fn fn;

	fn = handlers[kvm_vcpu_trap_get_class(vcpu)];

	if (fn)
		return fn(vcpu, exit_code);

	return false;
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop.
 */
static inline bool fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	/*
	 * Save PSTATE early so that we can evaluate the vcpu mode
	 * early on.
	 */
	vcpu->arch.ctxt.regs.pstate = read_sysreg_el2(SYS_SPSR);

	/*
	 * Check whether we want to repaint the state one way or
	 * another.
	 */
	early_exit_filter(vcpu, exit_code);

	if (ARM_EXCEPTION_CODE(*exit_code) != ARM_EXCEPTION_IRQ)
		vcpu->arch.fault.esr_el2 = read_sysreg_el2(SYS_ESR);

	if (ARM_SERROR_PENDING(*exit_code)) {
		u8 esr_ec = kvm_vcpu_trap_get_class(vcpu);

		/*
		 * HVC already have an adjusted PC, which we need to
		 * correct in order to return to after having injected
		 * the SError.
		 *
		 * SMC, on the other hand, is *trapped*, meaning its
		 * preferred return address is the SMC itself.
		 */
		if (esr_ec == ESR_ELx_EC_HVC32 || esr_ec == ESR_ELx_EC_HVC64)
			write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 4, SYS_ELR);
	}

	/*
	 * We're using the raw exception code in order to only process
	 * the trap if no SError is pending. We will come back to the
	 * same PC once the SError has been injected, and replay the
	 * trapping instruction.
	 */
	if (*exit_code != ARM_EXCEPTION_TRAP)
		goto exit;

	/* Check if there's an exit handler and allow it to handle the exit. */
	if (kvm_hyp_handle_exit(vcpu, exit_code))
		goto guest;
exit:
	/* Return to the host kernel and handle the exit */
	return false;

guest:
	/* Re-enter the guest */
	asm(ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412));
	return true;
}

static inline void __kvm_unexpected_el2_exception(void)
{
	extern char __guest_exit_panic[];
	unsigned long addr, fixup;
	struct kvm_exception_table_entry *entry, *end;
	unsigned long elr_el2 = read_sysreg(elr_el2);

	entry = &__start___kvm_ex_table;
	end = &__stop___kvm_ex_table;

	while (entry < end) {
		addr = (unsigned long)&entry->insn + entry->insn;
		fixup = (unsigned long)&entry->fixup + entry->fixup;

		if (addr != elr_el2) {
			entry++;
			continue;
		}

		write_sysreg(fixup, elr_el2);
		return;
	}

	/* Trigger a panic after restoring the hyp context. */
	write_sysreg(__guest_exit_panic, elr_el2);
}

#endif /* __ARM64_KVM_HYP_SWITCH_H__ */
