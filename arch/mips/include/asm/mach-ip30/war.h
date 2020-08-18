/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002, 2004, 2007 by Ralf Baechle <ralf@linux-mips.org>
 */
#ifndef __ASM_MIPS_MACH_IP30_WAR_H
#define __ASM_MIPS_MACH_IP30_WAR_H

#define R4600_V1_INDEX_ICACHEOP_WAR	0
#define R4600_V1_HIT_CACHEOP_WAR	0
#define R4600_V2_HIT_CACHEOP_WAR	0
#define BCM1250_M3_WAR			0
#define SIBYTE_1956_WAR			0
#define MIPS4K_ICACHE_REFILL_WAR	0
#define MIPS_CACHE_SYNC_WAR		0
#define TX49XX_ICACHE_INDEX_INV_WAR	0
#define ICACHE_REFILLS_WORKAROUND_WAR	0
#ifdef CONFIG_CPU_R10000
#define R10000_LLSC_WAR			1
#else
#define R10000_LLSC_WAR			0
#endif
#define MIPS34K_MISSED_ITLB_WAR		0

#endif /* __ASM_MIPS_MACH_IP30_WAR_H */
