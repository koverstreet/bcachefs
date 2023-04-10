/* SPDX-License-Identifier: GPL-2.0 */
/*
 * allocation tagging
 */
#ifndef _LINUX_ALLOC_TAG_H
#define _LINUX_ALLOC_TAG_H

#include <linux/bug.h>
#include <linux/codetag.h>
#include <linux/container_of.h>
#include <asm/percpu.h>
#include <linux/cpumask.h>
#include <linux/static_key.h>

/*
 * An instance of this structure is created in a special ELF section at every
 * allocation callsite. At runtime, the special section is treated as
 * an array of these. Embedded codetag utilizes codetag framework.
 */
struct alloc_tag {
	struct codetag			ct;
	u64 __percpu			*bytes_allocated;
} __aligned(8);

#ifdef CONFIG_MEM_ALLOC_PROFILING

void alloc_tags_show_mem_report(struct seq_buf *s);

static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
{
	return container_of(ct, struct alloc_tag, ct);
}

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)				\
	static struct alloc_tag _alloc_tag __used __aligned(8)		\
	__section("alloc_tags") = { .ct = CODE_TAG_INIT };		\
	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)

DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
			mem_alloc_profiling_key);

static inline bool mem_alloc_profiling_enabled(void)
{
	return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
				   &mem_alloc_profiling_key);
}

static inline u64 alloc_tag_read(struct alloc_tag *tag)
{
	u64 v = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		v += *per_cpu_ptr(tag->bytes_allocated, cpu);

	return v;
}

static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	struct alloc_tag *tag;

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
#endif
	if (!ref || !ref->ct)
		return;

	tag = ct_to_alloc_tag(ref->ct);

	this_cpu_add(*tag->bytes_allocated, -bytes);
	ref->ct = NULL;
}

static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	__alloc_tag_sub(ref, bytes);
}

static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
{
	__alloc_tag_sub(ref, bytes);
}

static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
{
#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
	WARN_ONCE(ref && ref->ct,
		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
		  ref->ct->filename, ref->ct->lineno);

	WARN_ONCE(!tag, "current->alloc_tag not set");
#endif
	if (!ref || !tag)
		return;

	ref->ct = &tag->ct;
	this_cpu_add(*tag->bytes_allocated, bytes);
}

#else

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
				 size_t bytes) {}

#endif

#define alloc_hooks(_do_alloc)						\
({									\
	typeof(_do_alloc) _res;						\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
									\
	_res = _do_alloc;						\
	alloc_tag_restore(&_alloc_tag, _old);				\
	_res;								\
})

/*
 * workaround for a sparse bug: it complains about res_type_to_err() when
 * typeof(_do_alloc) is a __percpu pointer, but gcc won't let us add a separate
 * __percpu case to res_type_to_err():
 */
#define alloc_hooks_pcpu(_do_alloc)					\
({									\
	typeof(_do_alloc) _res;						\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
									\
	_res = !memory_fault() ? _do_alloc : NULL;			\
	alloc_tag_restore(&_alloc_tag, _old);				\
	_res;								\
})

#endif /* _LINUX_ALLOC_TAG_H */
