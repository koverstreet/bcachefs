// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/jitalloc.h>
#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/text-patching.h>

static DEFINE_MUTEX(jit_alloc_lock);

struct jit_cache {
	unsigned		obj_size_bits;
	unsigned		objs_per_slab;
	struct list_head	partial;
};

#define JITALLOC_MIN_SIZE	16
#define NR_JIT_CACHES		ilog2(PAGE_SIZE / JITALLOC_MIN_SIZE)

static struct jit_cache jit_caches[NR_JIT_CACHES];

struct jit_slab {
	unsigned long		__page_flags;

	struct jit_cache	*cache;
	void			*executably_mapped;;
	unsigned long		*objs_allocated; /* bitmap of free objects */
	struct list_head	list;
};

#define folio_jit_slab(folio)		(_Generic((folio),			\
	const struct folio *:		(const struct jit_slab *)(folio),	\
	struct folio *:			(struct jit_slab *)(folio)))

#define jit_slab_folio(s)		(_Generic((s),				\
	const struct jit_slab *:	(const struct folio *)s,		\
	struct jit_slab *:		(struct folio *)s))

static struct jit_slab *jit_slab_alloc(struct jit_cache *cache)
{
	void *executably_mapped = module_alloc(PAGE_SIZE);
	struct page *page;
	struct folio *folio;
	struct jit_slab *slab;
	unsigned long *objs_allocated;

	if (!executably_mapped)
		return NULL;

	objs_allocated = kcalloc(BITS_TO_LONGS(cache->objs_per_slab), sizeof(unsigned long), GFP_KERNEL);
	if (!objs_allocated ) {
		vfree(executably_mapped);
		return NULL;
	}

	set_vm_flush_reset_perms(executably_mapped);
	set_memory_rox((unsigned long) executably_mapped, 1);

	page = vmalloc_to_page(executably_mapped);
	folio = page_folio(page);

	__folio_set_slab(folio);
	slab			= folio_jit_slab(folio);
	slab->cache		= cache;
	slab->executably_mapped	= executably_mapped;
	slab->objs_allocated = objs_allocated;
	INIT_LIST_HEAD(&slab->list);

	return slab;
}

static void *jit_cache_alloc(void *buf, size_t len, struct jit_cache *cache)
{
	struct jit_slab *s =
		list_first_entry_or_null(&cache->partial, struct jit_slab, list) ?:
		jit_slab_alloc(cache);
	unsigned obj_idx, nr_allocated;

	if (!s)
		return NULL;

	obj_idx = find_first_zero_bit(s->objs_allocated, cache->objs_per_slab);

	BUG_ON(obj_idx >= cache->objs_per_slab);
	__set_bit(obj_idx, s->objs_allocated);

	nr_allocated = bitmap_weight(s->objs_allocated, s->cache->objs_per_slab);

	if (nr_allocated == s->cache->objs_per_slab) {
		list_del_init(&s->list);
	} else if (nr_allocated == 1) {
		list_del(&s->list);
		list_add(&s->list, &s->cache->partial);
	}

	return s->executably_mapped + (obj_idx << cache->obj_size_bits);
}

void jit_update(void *buf, void *new_buf, size_t len)
{
	text_poke_copy(buf, new_buf, len);
}
EXPORT_SYMBOL_GPL(jit_update);

void jit_free(void *buf)
{
	struct page *page;
	struct folio *folio;
	struct jit_slab *s;
	unsigned obj_idx, nr_allocated;
	size_t offset;

	if (!buf)
		return;

	page	= vmalloc_to_page(buf);
	folio	= page_folio(page);
	offset	= offset_in_folio(folio, buf);

	if (!folio_test_slab(folio)) {
		vfree(buf);
		return;
	}

	s = folio_jit_slab(folio);

	mutex_lock(&jit_alloc_lock);
	obj_idx = offset >> s->cache->obj_size_bits;

	__clear_bit(obj_idx, s->objs_allocated);

	nr_allocated = bitmap_weight(s->objs_allocated, s->cache->objs_per_slab);

	if (nr_allocated == 0) {
		list_del(&s->list);
		kfree(s->objs_allocated);
		folio_put(folio);
	} else if (nr_allocated + 1 == s->cache->objs_per_slab) {
		list_del(&s->list);
		list_add(&s->list, &s->cache->partial);
	}

	mutex_unlock(&jit_alloc_lock);
}
EXPORT_SYMBOL_GPL(jit_free);

void *jit_alloc(void *buf, size_t len)
{
	unsigned jit_cache_idx = ilog2(roundup_pow_of_two(len) / 16);
	void *p;

	if (jit_cache_idx < NR_JIT_CACHES) {
		mutex_lock(&jit_alloc_lock);
		p = jit_cache_alloc(buf, len, &jit_caches[jit_cache_idx]);
		mutex_unlock(&jit_alloc_lock);
	} else {
		p = module_alloc(len);
		if (p) {
			set_vm_flush_reset_perms(p);
			set_memory_rox((unsigned long) p, DIV_ROUND_UP(len, PAGE_SIZE));
		}
	}

	if (p && buf)
		jit_update(p, buf, len);

	return p;
}
EXPORT_SYMBOL_GPL(jit_alloc);

static int __init jit_alloc_init(void)
{
	for (unsigned i = 0; i < ARRAY_SIZE(jit_caches); i++) {
		jit_caches[i].obj_size_bits	= ilog2(JITALLOC_MIN_SIZE) + i;
		jit_caches[i].objs_per_slab	= PAGE_SIZE >> jit_caches[i].obj_size_bits;

		INIT_LIST_HEAD(&jit_caches[i].partial);
	}

	return 0;
}
core_initcall(jit_alloc_init);
