/* SPDX-License-Identifier: GPL-2.0 */
/*
 * code tagging framework
 */
#ifndef _LINUX_CODETAG_H
#define _LINUX_CODETAG_H

#include <linux/types.h>

struct codetag_iterator;
struct codetag_type;
struct seq_buf;
struct module;

/*
 * An instance of this structure is created in a special ELF section at every
 * code location being tagged.  At runtime, the special section is treated as
 * an array of these.
 */
struct codetag {
	unsigned int flags; /* used in later patches */
	unsigned int lineno;
	const char *modname;
	const char *function;
	const char *filename;
} __aligned(8);

union codetag_ref {
	struct codetag *ct;
};

struct codetag_range {
	struct codetag *start;
	struct codetag *stop;
};

struct codetag_module {
	struct module *mod;
	struct codetag_range range;
};

struct codetag_type_desc {
	const char *section;
	size_t tag_size;
	void (*module_load)(struct codetag_type *cttype,
			    struct codetag_module *cmod);
	void (*module_unload)(struct codetag_type *cttype,
			      struct codetag_module *cmod);
};

struct codetag_iterator {
	struct codetag_type *cttype;
	struct codetag_module *cmod;
	unsigned long mod_id;
	struct codetag *ct;
};

#define CODE_TAG_INIT {					\
	.modname	= KBUILD_MODNAME,		\
	.function	= __func__,			\
	.filename	= __FILE__,			\
	.lineno		= __LINE__,			\
	.flags		= 0,				\
}

void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
struct codetag *codetag_next_ct(struct codetag_iterator *iter);

void codetag_to_text(struct seq_buf *out, struct codetag *ct);

struct codetag_type *
codetag_register_type(const struct codetag_type_desc *desc);

#ifdef CONFIG_CODE_TAGGING
void codetag_load_module(struct module *mod);
void codetag_unload_module(struct module *mod);
#else
static inline void codetag_load_module(struct module *mod) {}
static inline void codetag_unload_module(struct module *mod) {}
#endif

/* Codetag query parsing */

struct codetag_query {
	const char	*filename;
	const char	*module;
	const char	*function;
	const char	*class;
	unsigned int	first_line, last_line;
	unsigned int	first_index, last_index;
	unsigned int	cur_index;

	bool		match_line:1;
	bool		match_index:1;

	unsigned int	set_enabled:1;
	unsigned int	enabled:2;

	unsigned int	set_frequency:1;
	unsigned int	frequency;
};

char *codetag_query_parse(struct codetag_query *q, char *buf);
bool codetag_matches_query(struct codetag_query *q,
			   const struct codetag *ct,
			   const struct codetag_module *mod,
			   const char *class);

#endif /* _LINUX_CODETAG_H */
