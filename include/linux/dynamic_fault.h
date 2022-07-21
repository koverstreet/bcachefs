/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_DYNAMIC_FAULT_H
#define _LINUX_DYNAMIC_FAULT_H

/*
 * Dynamic/code tagging fault injection:
 *
 * Originally based on the dynamic debug trick of putting types in a special elf
 * section, then rewritten using code tagging:
 *
 * To use, simply insert a call to dynamic_fault("fault_class"), which will
 * return true if an error should be injected.
 *
 * Fault injection sites may be listed and enabled via debugfs, under
 * /sys/kernel/debug/dynamic_faults.
 */

#ifdef CONFIG_CODETAG_FAULT_INJECTION

#include <linux/codetag.h>
#include <linux/jump_label.h>

#define DFAULT_STATES()		\
	x(disabled)		\
	x(enabled)		\
	x(oneshot)

enum dfault_enabled {
#define x(n)	DFAULT_##n,
	DFAULT_STATES()
#undef x
};

union dfault_state {
	struct {
		unsigned int		enabled:2;
		unsigned int		count:30;
	};

	struct {
		unsigned int		v;
	};
};

struct dfault {
	struct codetag		tag;
	const char		*class;
	unsigned int		frequency;
	union dfault_state	state;
	struct static_key_false	enabled;
};

bool __dynamic_fault_enabled(struct dfault *df);

#define dynamic_fault(_class)				\
({							\
	static struct dfault				\
	__used						\
	__section("dynamic_fault_tags")			\
	__aligned(8) df = {				\
		.tag	= CODE_TAG_INIT,		\
		.class	= _class,			\
		.enabled = STATIC_KEY_FALSE_INIT,	\
	};						\
							\
	static_key_false(&df.enabled.key) &&		\
		__dynamic_fault_enabled(&df);		\
})

#else

#define dynamic_fault(_class)	false

#endif /* CODETAG_FAULT_INJECTION */

#define memory_fault()		dynamic_fault("memory")

#endif /* _LINUX_DYNAMIC_FAULT_H */
