/* SPDX-License-Identifier: GPL-2.0 */
/*
 * code tagging framework
 */
#ifndef _LINUX_CODETAG_H
#define _LINUX_CODETAG_H

#include <linux/types.h>

struct codetag_iter;
struct codetag_type;
struct codetag_module;
struct seq_buf;
struct module;

/*
 * An instance of this structure is created in a special ELF section at every
 * code location being tagged.  At runtime, the special section is treated as
 * an array of these.
 */
struct codetag {
	u16		idx;
	u16		flags; /* used in later patches */
	u32		lineno;
	const char	*modname;
	const char	*function;
	const char	*filename;
} __aligned(8);

union codetag_ref {
	struct codetag *ct;
};

struct codetag_type_desc {
	const char *section;
	size_t tag_size;
	void (*module_load)(struct codetag_type *cttype,
			    struct codetag_module *cmod);
	bool (*module_unload)(struct codetag_type *cttype,
			      struct codetag_module *cmod);
};

struct codetag_iter {
	struct codetag_type *cttype;
	struct codetag_module *cmod;
	unsigned idx;
};

#ifdef MODULE
#define CT_MODULE_NAME KBUILD_MODNAME
#else
#define CT_MODULE_NAME NULL
#endif

#define CODE_TAG_INIT {					\
	.modname	= CT_MODULE_NAME,		\
	.function	= __func__,			\
	.filename	= __FILE__,			\
	.lineno		= __LINE__,			\
	.flags		= 0,				\
}

struct codetag *idx_to_codetag(struct codetag_type *cttype, unsigned idx);

void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
bool codetag_trylock_module_list(struct codetag_type *cttype);

static inline struct codetag_iter codetag_iter_init(struct codetag_type *cttype, unsigned idx)
{
	return (struct codetag_iter) { .cttype = cttype, .idx = idx };
}

static inline void codetag_iter_advance(struct codetag_iter *iter)
{
	iter->idx++;
}

struct codetag *codetag_iter_peek(struct codetag_iter *);

#define for_each_codetag(_cttype, _iter, _ct)				\
	for (struct codetag_iter _iter = codetag_iter_init(_cttype, 0);	\
	     (_ct = codetag_iter_peek(&_iter));				\
	     codetag_iter_advance(&_iter))

void codetag_to_text(struct seq_buf *out, struct codetag *ct);

struct codetag_type *
codetag_register_type(const struct codetag_type_desc *desc);

#if defined(CONFIG_CODE_TAGGING) && defined(CONFIG_MODULES)
void codetag_load_module(struct module *mod);
bool codetag_unload_module(struct module *mod);
#else
static inline void codetag_load_module(struct module *mod) {}
static inline bool codetag_unload_module(struct module *mod) { return true; }
#endif

#endif /* _LINUX_CODETAG_H */
