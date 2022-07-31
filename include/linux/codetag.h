/* SPDX-License-Identifier: GPL-2.0 */
/*
 * code tagging framework
 */
#ifndef _LINUX_CODETAG_H
#define _LINUX_CODETAG_H

#include <linux/container_of.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct kref;
struct codetag_ctx;
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
	unsigned int flags; /* has to be the first member shared with codetag_ctx */
	unsigned int lineno;
	const char *modname;
	const char *function;
	const char *filename;
} __aligned(8);

/* codetag_with_ctx flags */
#define CTC_FLAG_CTX_PTR	(1 << 0)
#define CTC_FLAG_CTX_READY	(1 << 1)
#define CTC_FLAG_CTX_ENABLED	(1 << 2)

/*
 * Code tag with context capture support. Contains a list to store context for
 * each tag hit, a lock protecting the list and a flag to indicate whether
 * context capture is enabled for the tag.
 */
struct codetag_with_ctx {
	struct codetag ct;
	struct list_head ctx_head;
	spinlock_t ctx_lock;
} __aligned(8);

/*
 * Tag reference can point to codetag directly or indirectly via codetag_ctx.
 * Direct codetag pointer is used when context capture is disabled or not
 * supported. When context capture for the tag is used, the reference points
 * to the codetag_ctx through which the codetag can be reached.
 */
union codetag_ref {
	struct codetag *ct;
	struct codetag_ctx *ctx;
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
	void (*free_ctx)(struct kref *ref);
};

struct codetag_iterator {
	struct codetag_type *cttype;
	struct codetag_module *cmod;
	unsigned long mod_id;
	struct codetag *ct;
	struct codetag_ctx *ctx;
};

#define CODE_TAG_INIT {					\
	.modname	= KBUILD_MODNAME,		\
	.function	= __func__,			\
	.filename	= __FILE__,			\
	.lineno		= __LINE__,			\
	.flags		= 0,				\
}

static inline bool is_codetag_ctx_ref(union codetag_ref *ref)
{
	return !!(ref->ct->flags & CTC_FLAG_CTX_PTR);
}

static inline
struct codetag_with_ctx *ct_to_ctc(struct codetag *ct)
{
	return container_of(ct, struct codetag_with_ctx, ct);
}

void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
struct codetag *codetag_next_ct(struct codetag_iterator *iter);
struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter);

bool codetag_enable_ctx(struct codetag_with_ctx *ctc, bool enable);
static inline bool codetag_ctx_enabled(struct codetag_with_ctx *ctc)
{
	return !!(ctc->ct.flags & CTC_FLAG_CTX_ENABLED);
}
bool codetag_has_ctx(struct codetag_with_ctx *ctc);

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
