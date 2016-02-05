#ifndef _DYNAMIC_FAULT_H
#define _DYNAMIC_FAULT_H

#include <linux/bio.h>
#include <linux/jump_label.h>
#include <linux/slab.h>

enum dfault_enabled {
	DFAULT_DISABLED,
	DFAULT_ENABLED,
	DFAULT_ONESHOT,
};

union dfault_state {
	struct {
		unsigned		enabled:2;
		unsigned		count:30;
	};

	struct {
		unsigned		v;
	};
};

/*
 * An instance of this structure is created in a special
 * ELF section at every dynamic fault callsite.  At runtime,
 * the special section is treated as an array of these.
 */
struct _dfault {
	const char		*modname;
	const char		*function;
	const char		*filename;
	const char		*class;

	const u16		line;

	unsigned		frequency;
	union dfault_state	state;

	struct static_key	enabled;
} __aligned(8);


#ifdef CONFIG_DYNAMIC_FAULT

int dfault_add_module(struct _dfault *tab, unsigned int n, const char *mod);
int dfault_remove_module(char *mod_name);
bool __dynamic_fault_enabled(struct _dfault *);

#define dynamic_fault(_class)						\
({									\
	static struct _dfault descriptor				\
	__used __aligned(8) __attribute__((section("__faults"))) = {	\
		.modname	= KBUILD_MODNAME,			\
		.function	= __func__,				\
		.filename	= __FILE__,				\
		.line		= __LINE__,				\
		.class		= _class,				\
	};								\
									\
	static_key_false(&descriptor.enabled) &&			\
		__dynamic_fault_enabled(&descriptor);			\
})

#define memory_fault()		dynamic_fault("memory")
#define race_fault()		dynamic_fault("race")

#define kmalloc(...)							\
	(memory_fault() ? NULL	: kmalloc(__VA_ARGS__))
#define kzalloc(...)							\
	(memory_fault() ? NULL	: kzalloc(__VA_ARGS__))
#define krealloc(...)							\
	(memory_fault() ? NULL	: krealloc(__VA_ARGS__))

#define mempool_alloc(pool, gfp_mask)					\
	((!gfpflags_allow_blocking(gfp_mask) && memory_fault())		\
		? NULL : mempool_alloc(pool, gfp_mask))

#define __get_free_pages(...)						\
	(memory_fault() ? 0	: __get_free_pages(__VA_ARGS__))
#define alloc_pages_node(...)						\
	(memory_fault() ? NULL	: alloc_pages_node(__VA_ARGS__))
#define alloc_pages_nodemask(...)					\
	(memory_fault() ? NULL	: alloc_pages_nodemask(__VA_ARGS__))

#define bio_alloc_bioset(gfp_mask, ...)					\
	((!gfpflags_allow_blocking(gfp_mask) && memory_fault())		\
	 ? NULL	: bio_alloc_bioset(gfp_mask, __VA_ARGS__))

#define bio_clone(bio, gfp_mask)					\
	((!gfpflags_allow_blocking(gfp_mask) && memory_fault())		\
	 ? NULL	: bio_clone(bio, gfp_mask))

#define bio_clone_bioset(bio, gfp_mask, bs)				\
	((!gfpflags_allow_blocking(gfp_mask) && memory_fault())		\
	 ? NULL	: bio_clone_bioset(bio, gfp_mask, bs))

#define bio_kmalloc(...)						\
	(memory_fault() ? NULL		: bio_kmalloc(__VA_ARGS__))
#define bio_clone_kmalloc(...)						\
	(memory_fault() ? NULL		: bio_clone_kmalloc(__VA_ARGS__))
#define bio_alloc_pages(...)						\
	(memory_fault() ? -ENOMEM	: bio_alloc_pages(__VA_ARGS__))

#define bio_iov_iter_get_pages(...)					\
	(memory_fault() ? -ENOMEM	: bio_iov_iter_get_pages(__VA_ARGS__))

#else /* CONFIG_DYNAMIC_FAULT */

#define dfault_add_module(tab, n, modname)	0
#define dfault_remove_module(mod)		0
#define dynamic_fault(_class)			0
#define memory_fault()				0
#define race_fault()				0

#endif /* CONFIG_DYNAMIC_FAULT */

#endif
