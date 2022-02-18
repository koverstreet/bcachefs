/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers for Intel SoC model detection
 *
 * Copyright (c) 2019, Intel Corporation.
 */

#ifndef __PLATFORM_DATA_X86_SOC_H
#define __PLATFORM_DATA_X86_SOC_H

#if IS_ENABLED(CONFIG_X86)

#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>

#define SOC_INTEL_IS_CPU(soc, type)				\
static inline bool soc_intel_is_##soc(void)			\
{								\
	static const struct x86_cpu_id soc##_cpu_ids[] = {	\
		X86_MATCH_INTEL_FAM6_MODEL(type, NULL),		\
		{}						\
	};							\
	const struct x86_cpu_id *id;				\
								\
	id = x86_match_cpu(soc##_cpu_ids);			\
	if (id)							\
		return true;					\
	return false;						\
}

SOC_INTEL_IS_CPU(byt, ATOM_SILVERMONT);
SOC_INTEL_IS_CPU(cht, ATOM_AIRMONT);
SOC_INTEL_IS_CPU(apl, ATOM_GOLDMONT);
SOC_INTEL_IS_CPU(glk, ATOM_GOLDMONT_PLUS);
SOC_INTEL_IS_CPU(cml, KABYLAKE_L);

#else /* IS_ENABLED(CONFIG_X86) */

static inline bool soc_intel_is_byt(void)
{
	return false;
}

static inline bool soc_intel_is_cht(void)
{
	return false;
}

static inline bool soc_intel_is_apl(void)
{
	return false;
}

static inline bool soc_intel_is_glk(void)
{
	return false;
}

static inline bool soc_intel_is_cml(void)
{
	return false;
}
#endif /* IS_ENABLED(CONFIG_X86) */

#endif /* __PLATFORM_DATA_X86_SOC_H */
