/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

#include <asm/virt.h>

#define	VCPU_WORKAROUND_2_FLAG_SHIFT	0
#define	VCPU_WORKAROUND_2_FLAG		(_AC(1, UL) << VCPU_WORKAROUND_2_FLAG_SHIFT)

#define ARM_EXIT_WITH_SERROR_BIT  31
#define ARM_EXCEPTION_CODE(x)	  ((x) & ~(1U << ARM_EXIT_WITH_SERROR_BIT))
#define ARM_EXCEPTION_IS_TRAP(x)  (ARM_EXCEPTION_CODE((x)) == ARM_EXCEPTION_TRAP)
#define ARM_SERROR_PENDING(x)	  !!((x) & (1U << ARM_EXIT_WITH_SERROR_BIT))

#define ARM_EXCEPTION_IRQ	  0
#define ARM_EXCEPTION_EL1_SERROR  1
#define ARM_EXCEPTION_TRAP	  2
#define ARM_EXCEPTION_IL	  3
/* The hyp-stub will return this for any kvm_call_hyp() call */
#define ARM_EXCEPTION_HYP_GONE	  HVC_STUB_ERR

#define kvm_arm_exception_type					\
	{ARM_EXCEPTION_IRQ,		"IRQ"		},	\
	{ARM_EXCEPTION_EL1_SERROR, 	"SERROR"	},	\
	{ARM_EXCEPTION_TRAP, 		"TRAP"		},	\
	{ARM_EXCEPTION_HYP_GONE,	"HYP_GONE"	}

/*
 * Size of the HYP vectors preamble. kvm_patch_vector_branch() generates code
 * that jumps over this.
 */
#define KVM_VECTOR_PREAMBLE	(2 * AARCH64_INSN_SIZE)

#define __SMCCC_WORKAROUND_1_SMC_SZ 36

#ifndef __ASSEMBLY__

#include <linux/mm.h>

/* Translate a kernel address of @sym into its equivalent linear mapping */
#define kvm_ksym_ref(sym)						\
	({								\
		void *val = &sym;					\
		if (!is_kernel_in_hyp_mode())				\
			val = lm_alias(&sym);				\
		val;							\
	 })

struct kvm;
struct kvm_vcpu;

extern char __kvm_hyp_init[];
extern char __kvm_hyp_init_end[];

extern char __kvm_hyp_vector[];

extern void __kvm_flush_vm_context(void);
extern void __kvm_tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa);
extern void __kvm_tlb_flush_vmid(struct kvm *kvm);
extern void __kvm_tlb_flush_local_vmid(struct kvm_vcpu *vcpu);

extern void __kvm_timer_set_cntvoff(u64 cntvoff);

extern int kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu);

extern int __kvm_vcpu_run_nvhe(struct kvm_vcpu *vcpu);

extern void __kvm_enable_ssbs(void);

extern u64 __vgic_v3_get_ich_vtr_el2(void);
extern u64 __vgic_v3_read_vmcr(void);
extern void __vgic_v3_write_vmcr(u32 vmcr);
extern void __vgic_v3_init_lrs(void);

extern u32 __kvm_get_mdcr_el2(void);

extern char __smccc_workaround_1_smc[__SMCCC_WORKAROUND_1_SMC_SZ];

/*
 * Obtain the PC-relative address of a kernel symbol
 * s: symbol
 *
 * The goal of this macro is to return a symbol's address based on a
 * PC-relative computation, as opposed to a loading the VA from a
 * constant pool or something similar. This works well for HYP, as an
 * absolute VA is guaranteed to be wrong. Only use this if trying to
 * obtain the address of a symbol (i.e. not something you obtained by
 * following a pointer).
 */
#define hyp_symbol_addr(s)						\
	({								\
		typeof(s) *addr;					\
		asm("adrp	%0, %1\n"				\
		    "add	%0, %0, :lo12:%1\n"			\
		    : "=r" (addr) : "S" (&s));				\
		addr;							\
	})

/*
 * Home-grown __this_cpu_{ptr,read} variants that always work at HYP,
 * provided that sym is really a *symbol* and not a pointer obtained from
 * a data structure. As for SHIFT_PERCPU_PTR(), the creative casting keeps
 * sparse quiet.
 */
#define __hyp_this_cpu_ptr(sym)						\
	({								\
		void *__ptr;						\
		__verify_pcpu_ptr(&sym);				\
		__ptr = hyp_symbol_addr(sym);				\
		__ptr += read_sysreg(tpidr_el2);			\
		(typeof(sym) __kernel __force *)__ptr;			\
	 })

#define __hyp_this_cpu_read(sym)					\
	({								\
		*__hyp_this_cpu_ptr(sym);				\
	 })

#else /* __ASSEMBLY__ */

.macro hyp_adr_this_cpu reg, sym, tmp
	adr_l	\reg, \sym
	mrs	\tmp, tpidr_el2
	add	\reg, \reg, \tmp
.endm

.macro hyp_ldr_this_cpu reg, sym, tmp
	adr_l	\reg, \sym
	mrs	\tmp, tpidr_el2
	ldr	\reg,  [\reg, \tmp]
.endm

.macro get_host_ctxt reg, tmp
	hyp_adr_this_cpu \reg, kvm_host_data, \tmp
	add	\reg, \reg, #HOST_DATA_CONTEXT
.endm

.macro get_vcpu_ptr vcpu, ctxt
	get_host_ctxt \ctxt, \vcpu
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]
	kern_hyp_va	\vcpu
.endm

#endif

#endif /* __ARM_KVM_ASM_H__ */
