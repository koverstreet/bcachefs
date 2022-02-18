/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_S390_FTRACE_H
#define _ASM_S390_FTRACE_H

#define HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
#define ARCH_SUPPORTS_FTRACE_OPS 1
#define MCOUNT_INSN_SIZE	6

#ifndef __ASSEMBLY__

#ifdef CONFIG_CC_IS_CLANG
/* https://bugs.llvm.org/show_bug.cgi?id=41424 */
#define ftrace_return_address(n) 0UL
#else
#define ftrace_return_address(n) __builtin_return_address(n)
#endif

void ftrace_caller(void);

extern void *ftrace_func;

struct dyn_arch_ftrace { };

#define MCOUNT_ADDR 0
#define FTRACE_ADDR ((unsigned long)ftrace_caller)

#define KPROBE_ON_FTRACE_NOP	0
#define KPROBE_ON_FTRACE_CALL	1

struct module;
struct dyn_ftrace;

bool ftrace_need_init_nop(void);
#define ftrace_need_init_nop ftrace_need_init_nop

int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec);
#define ftrace_init_nop ftrace_init_nop

static inline unsigned long ftrace_call_adjust(unsigned long addr)
{
	return addr;
}

struct ftrace_regs {
	struct pt_regs regs;
};

static __always_inline struct pt_regs *arch_ftrace_get_regs(struct ftrace_regs *fregs)
{
	return &fregs->regs;
}

static __always_inline void ftrace_instruction_pointer_set(struct ftrace_regs *fregs,
							   unsigned long ip)
{
	struct pt_regs *regs = arch_ftrace_get_regs(fregs);

	regs->psw.addr = ip;
}

/*
 * When an ftrace registered caller is tracing a function that is
 * also set by a register_ftrace_direct() call, it needs to be
 * differentiated in the ftrace_caller trampoline. To do this,
 * place the direct caller in the ORIG_GPR2 part of pt_regs. This
 * tells the ftrace_caller that there's a direct caller.
 */
static inline void arch_ftrace_set_direct_caller(struct pt_regs *regs, unsigned long addr)
{
	regs->orig_gpr2 = addr;
}

/*
 * Even though the system call numbers are identical for s390/s390x a
 * different system call table is used for compat tasks. This may lead
 * to e.g. incorrect or missing trace event sysfs files.
 * Therefore simply do not trace compat system calls at all.
 * See kernel/trace/trace_syscalls.c.
 */
#define ARCH_TRACE_IGNORE_COMPAT_SYSCALLS
static inline bool arch_trace_is_compat_syscall(struct pt_regs *regs)
{
	return is_compat_task();
}

#define ARCH_HAS_SYSCALL_MATCH_SYM_NAME
static inline bool arch_syscall_match_sym_name(const char *sym,
					       const char *name)
{
	/*
	 * Skip __s390_ and __s390x_ prefix - due to compat wrappers
	 * and aliasing some symbols of 64 bit system call functions
	 * may get the __s390_ prefix instead of the __s390x_ prefix.
	 */
	return !strcmp(sym + 7, name) || !strcmp(sym + 8, name);
}

#endif /* __ASSEMBLY__ */

#ifdef CONFIG_FUNCTION_TRACER

#define FTRACE_NOP_INSN .word 0xc004, 0x0000, 0x0000 /* brcl 0,0 */

#ifndef CC_USING_HOTPATCH

#define FTRACE_GEN_MCOUNT_RECORD(name)		\
	.section __mcount_loc, "a", @progbits;	\
	.quad name;				\
	.previous;

#else /* !CC_USING_HOTPATCH */

#define FTRACE_GEN_MCOUNT_RECORD(name)

#endif /* !CC_USING_HOTPATCH */

#define FTRACE_GEN_NOP_ASM(name)		\
	FTRACE_GEN_MCOUNT_RECORD(name)		\
	FTRACE_NOP_INSN

#else /* CONFIG_FUNCTION_TRACER */

#define FTRACE_GEN_NOP_ASM(name)

#endif /* CONFIG_FUNCTION_TRACER */

#endif /* _ASM_S390_FTRACE_H */
