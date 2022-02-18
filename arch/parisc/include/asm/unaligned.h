/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_PARISC_UNALIGNED_H
#define _ASM_PARISC_UNALIGNED_H

#include <asm-generic/unaligned.h>

struct pt_regs;
void handle_unaligned(struct pt_regs *regs);
int check_unaligned(struct pt_regs *regs);

#endif /* _ASM_PARISC_UNALIGNED_H */
