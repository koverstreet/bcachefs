/* SPDX-License-Identifier: GPL-2.0 */
/*
 * allocation tagging
 */
#ifndef _LINUX_ALLOC_TAG_H
#define _LINUX_ALLOC_TAG_H

#include <linux/bug.h>
#include <linux/codetag.h>
#include <linux/container_of.h>
#include <linux/preempt.h>
#include <asm/percpu.h>
#include <linux/cpumask.h>
#include <linux/static_key.h>

struct alloc_tag_counters {
	u64 bytes;
	u64 calls;
};

/*
 * An instance of this structure is created in a special ELF section at every
 * allocation callsite. At runtime, the special section is treated as
 * an array of these. Embedded codetag utilizes codetag framework.
 */
struct alloc_tag {
	struct codetag			ct;
	struct alloc_tag_counters __percpu	*counters;
} __aligned(8);

#ifdef CONFIG_MEM_ALLOC_PROFILING

static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
{
	return container_of(ct, struct alloc_tag, ct);
}

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)					\
	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
	static struct alloc_tag _alloc_tag __used __aligned(8)			\
	__section("alloc_tags") = {						\
		.ct = CODE_TAG_INIT,						\
		.counters = &_alloc_tag_cntr };					\
	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)

DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
			mem_alloc_profiling_key);

static inline bool mem_alloc_profiling_enabled(void)
{
	return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
				   &mem_alloc_profiling_key);
}

static inline struct alloc_tag_counters alloc_tag_read(struct alloc_tag *tag)
{
	struct alloc_tag_counters v = { 0, 0 };
	struct alloc_tag_counters *counter;
	int cpu;

	for_each_possible_cpu(cpu) {
		counter = per_cpu_ptr(tag->counters, cpu);
		v.bytes += counter->bytes;
		v.calls += counter->calls;
	}

	return v;
}

static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	struct alloc_tag_counters *counter;
	struct alloc_tag *tag;

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
#endif
	if (!ref || !ref->ct)
		return;

	tag = ct_to_alloc_tag(ref->ct);

	counter = get_cpu_ptr(tag->counters);
	counter->bytes -= bytes;
	counter->calls--;
	put_cpu_ptr(tag->counters);
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
	struct alloc_tag_counters *counter;

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
	WARN_ONCE(ref && ref->ct,
		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
		  ref->ct->filename, ref->ct->lineno);

	WARN_ONCE(!tag, "current->alloc_tag not set");
#endif
	if (!ref || !tag)
		return;

	ref->ct = &tag->ct;
	counter = get_cpu_ptr(tag->counters);
	counter->bytes += bytes;
	counter->calls++;
	put_cpu_ptr(tag->counters);
}

#else

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
				 size_t bytes) {}

#endif

#endif /* _LINUX_ALLOC_TAG_H */
