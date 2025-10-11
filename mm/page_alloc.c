// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/pagevec.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmstat.h>
#include <linux/fault-inject.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <trace/events/oom.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/sched/mm.h>
#include <linux/page_owner.h>
#include <linux/page_table_check.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/lockdep.h>
#include <linux/psi.h>
#include <linux/khugepaged.h>
#include <linux/delayacct.h>
#include <linux/cacheinfo.h>
#include <linux/pgalloc_tag.h>
#include <asm/div64.h>
#include "internal.h"
#include "shuffle.h"
#include "page_reporting.h"

/* Free Page Internal flags: for internal, non-pcp variants of free_pages(). */
typedef int __bitwise fpi_t;

/* No special request */
#define FPI_NONE		((__force fpi_t)0)

/*
 * Skip free page reporting notification for the (possibly merged) page.
 * This does not hinder free page reporting from grabbing the page,
 * reporting it and marking it "reported" -  it only skips notifying
 * the free page reporting infrastructure about a newly freed page. For
 * example, used when temporarily pulling a page from a freelist and
 * putting it back unmodified.
 */
#define FPI_SKIP_REPORT_NOTIFY	((__force fpi_t)BIT(0))

/*
 * Place the (possibly merged) page to the tail of the freelist. Will ignore
 * page shuffling (relevant code - e.g., memory onlining - is expected to
 * shuffle the whole zone).
 *
 * Note: No code should rely on this flag for correctness - it's purely
 *       to allow for optimizations when handing back either fresh pages
 *       (memory onlining) or untouched pages (page isolation, free page
 *       reporting).
 */
#define FPI_TO_TAIL		((__force fpi_t)BIT(1))

/* Free the page without taking locks. Rely on trylock only. */
#define FPI_TRYLOCK		((__force fpi_t)BIT(2))

/* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields */
static DEFINE_MUTEX(pcp_batch_high_lock);
#define MIN_PERCPU_PAGELIST_HIGH_FRACTION (8)

#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT)
/*
 * On SMP, spin_trylock is sufficient protection.
 * On PREEMPT_RT, spin_trylock is equivalent on both SMP and UP.
 */
#define pcp_trylock_prepare(flags)	do { } while (0)
#define pcp_trylock_finish(flag)	do { } while (0)
#else

/* UP spin_trylock always succeeds so disable IRQs to prevent re-entrancy. */
#define pcp_trylock_prepare(flags)	local_irq_save(flags)
#define pcp_trylock_finish(flags)	local_irq_restore(flags)
#endif

/*
 * Locking a pcp requires a PCP lookup followed by a spinlock. To avoid
 * a migration causing the wrong PCP to be locked and remote memory being
 * potentially allocated, pin the task to the CPU for the lookup+lock.
 * preempt_disable is used on !RT because it is faster than migrate_disable.
 * migrate_disable is used on RT because otherwise RT spinlock usage is
 * interfered with and a high priority task cannot preempt the allocator.
 */
#ifndef CONFIG_PREEMPT_RT
#define pcpu_task_pin()		preempt_disable()
#define pcpu_task_unpin()	preempt_enable()
#else
#define pcpu_task_pin()		migrate_disable()
#define pcpu_task_unpin()	migrate_enable()
#endif

/*
 * Generic helper to lookup and a per-cpu variable with an embedded spinlock.
 * Return value should be used with equivalent unlock helper.
 */
#define pcpu_spin_lock(type, member, ptr)				\
({									\
	type *_ret;							\
	pcpu_task_pin();						\
	_ret = this_cpu_ptr(ptr);					\
	spin_lock(&_ret->member);					\
	_ret;								\
})

#define pcpu_spin_trylock(type, member, ptr)				\
({									\
	type *_ret;							\
	pcpu_task_pin();						\
	_ret = this_cpu_ptr(ptr);					\
	if (!spin_trylock(&_ret->member)) {				\
		pcpu_task_unpin();					\
		_ret = NULL;						\
	}								\
	_ret;								\
})

#define pcpu_spin_unlock(member, ptr)					\
({									\
	spin_unlock(&ptr->member);					\
	pcpu_task_unpin();						\
})

/* struct per_cpu_pages specific helpers. */
#define pcp_spin_lock(ptr)						\
	pcpu_spin_lock(struct per_cpu_pages, lock, ptr)

#define pcp_spin_trylock(ptr)						\
	pcpu_spin_trylock(struct per_cpu_pages, lock, ptr)

#define pcp_spin_unlock(ptr)						\
	pcpu_spin_unlock(lock, ptr)

#ifdef CONFIG_USE_PERCPU_NUMA_NODE_ID
DEFINE_PER_CPU(int, numa_node);
EXPORT_PER_CPU_SYMBOL(numa_node);
#endif

DEFINE_STATIC_KEY_TRUE(vm_numa_stat_key);

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
/*
 * N.B., Do NOT reference the '_numa_mem_' per cpu variable directly.
 * It will not be defined when CONFIG_HAVE_MEMORYLESS_NODES is not defined.
 * Use the accessor functions set_numa_mem(), numa_mem_id() and cpu_to_mem()
 * defined in <linux/topology.h>.
 */
DEFINE_PER_CPU(int, _numa_mem_);		/* Kernel "local memory" node */
EXPORT_PER_CPU_SYMBOL(_numa_mem_);
#endif

static DEFINE_MUTEX(pcpu_drain_mutex);

#ifdef CONFIG_GCC_PLUGIN_LATENT_ENTROPY
volatile unsigned long latent_entropy __latent_entropy;
EXPORT_SYMBOL(latent_entropy);
#endif

/*
 * Array of node states.
 */
nodemask_t node_states[NR_NODE_STATES] __read_mostly = {
	[N_POSSIBLE] = NODE_MASK_ALL,
	[N_ONLINE] = { { [0] = 1UL } },
#ifndef CONFIG_NUMA
	[N_NORMAL_MEMORY] = { { [0] = 1UL } },
#ifdef CONFIG_HIGHMEM
	[N_HIGH_MEMORY] = { { [0] = 1UL } },
#endif
	[N_MEMORY] = { { [0] = 1UL } },
	[N_CPU] = { { [0] = 1UL } },
#endif	/* NUMA */
};
EXPORT_SYMBOL(node_states);

gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE
unsigned int pageblock_order __read_mostly;
#endif

static void __free_pages_ok(struct page *page, unsigned int order,
			    fpi_t fpi_flags);

/*
 * results with 256, 32 in the lowmem_reserve sysctl:
 *	1G machine -> (16M dma, 800M-16M normal, 1G-800M high)
 *	1G machine -> (16M dma, 784M normal, 224M high)
 *	NORMAL allocation will leave 784M/256 of ram reserved in the ZONE_DMA
 *	HIGHMEM allocation will leave 224M/32 of ram reserved in ZONE_NORMAL
 *	HIGHMEM allocation will leave (224M+784M)/256 of ram reserved in ZONE_DMA
 *
 * TBD: should special case ZONE_DMA32 machines here - in those we normally
 * don't need any ZONE_NORMAL reservation
 */
static int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	[ZONE_DMA] = 256,
#endif
#ifdef CONFIG_ZONE_DMA32
	[ZONE_DMA32] = 256,
#endif
	[ZONE_NORMAL] = 32,
#ifdef CONFIG_HIGHMEM
	[ZONE_HIGHMEM] = 0,
#endif
	[ZONE_MOVABLE] = 0,
};

char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	 "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
	 "DMA32",
#endif
	 "Normal",
#ifdef CONFIG_HIGHMEM
	 "HighMem",
#endif
	 "Movable",
#ifdef CONFIG_ZONE_DEVICE
	 "Device",
#endif
};

const char * const migratetype_names[MIGRATE_TYPES] = {
	"Unmovable",
	"Movable",
	"Reclaimable",
	"HighAtomic",
#ifdef CONFIG_CMA
	"CMA",
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	"Isolate",
#endif
};

int min_free_kbytes = 1024;
int user_min_free_kbytes = -1;
static int watermark_boost_factor __read_mostly = 15000;
static int watermark_scale_factor = 10;
int defrag_mode;

/* movable_zone is the "real" zone pages in ZONE_MOVABLE are taken from */
int movable_zone;
EXPORT_SYMBOL(movable_zone);

#if MAX_NUMNODES > 1
unsigned int nr_node_ids __read_mostly = MAX_NUMNODES;
unsigned int nr_online_nodes __read_mostly = 1;
EXPORT_SYMBOL(nr_node_ids);
EXPORT_SYMBOL(nr_online_nodes);
#endif

static bool page_contains_unaccepted(struct page *page, unsigned int order);
static bool cond_accept_memory(struct zone *zone, unsigned int order,
			       int alloc_flags);
static bool __free_unaccepted(struct page *page);

int page_group_by_mobility_disabled __read_mostly;

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
/*
 * During boot we initialize deferred pages on-demand, as needed, but once
 * page_alloc_init_late() has finished, the deferred pages are all initialized,
 * and we can permanently disable that path.
 */
DEFINE_STATIC_KEY_TRUE(deferred_pages);

static inline bool deferred_pages_enabled(void)
{
	return static_branch_unlikely(&deferred_pages);
}

/*
 * deferred_grow_zone() is __init, but it is called from
 * get_page_from_freelist() during early boot until deferred_pages permanently
 * disables this call. This is why we have refdata wrapper to avoid warning,
 * and to ensure that the function body gets unloaded.
 */
static bool __ref
_deferred_grow_zone(struct zone *zone, unsigned int order)
{
	return deferred_grow_zone(zone, order);
}
#else
static inline bool deferred_pages_enabled(void)
{
	return false;
}

static inline bool _deferred_grow_zone(struct zone *zone, unsigned int order)
{
	return false;
}
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *get_pageblock_bitmap(const struct page *page,
							unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	return section_to_usemap(__pfn_to_section(pfn));
#else
	return page_zone(page)->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static inline int pfn_to_bitidx(const struct page *page, unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	pfn &= (PAGES_PER_SECTION-1);
#else
	pfn = pfn - pageblock_start_pfn(page_zone(page)->zone_start_pfn);
#endif /* CONFIG_SPARSEMEM */
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
}

static __always_inline bool is_standalone_pb_bit(enum pageblock_bits pb_bit)
{
	return pb_bit > PB_migrate_end && pb_bit < __NR_PAGEBLOCK_BITS;
}

static __always_inline void
get_pfnblock_bitmap_bitidx(const struct page *page, unsigned long pfn,
			   unsigned long **bitmap_word, unsigned long *bitidx)
{
	unsigned long *bitmap;
	unsigned long word_bitidx;

#ifdef CONFIG_MEMORY_ISOLATION
	BUILD_BUG_ON(NR_PAGEBLOCK_BITS != 8);
#else
	BUILD_BUG_ON(NR_PAGEBLOCK_BITS != 4);
#endif
	BUILD_BUG_ON(__MIGRATE_TYPE_END >= (1 << PB_migratetype_bits));
	VM_BUG_ON_PAGE(!zone_spans_pfn(page_zone(page), pfn), page);

	bitmap = get_pageblock_bitmap(page, pfn);
	*bitidx = pfn_to_bitidx(page, pfn);
	word_bitidx = *bitidx / BITS_PER_LONG;
	*bitidx &= (BITS_PER_LONG - 1);
	*bitmap_word = &bitmap[word_bitidx];
}


/**
 * __get_pfnblock_flags_mask - Return the requested group of flags for
 * a pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @mask: mask of bits that the caller is interested in
 *
 * Return: pageblock_bits flags
 */
static unsigned long __get_pfnblock_flags_mask(const struct page *page,
					       unsigned long pfn,
					       unsigned long mask)
{
	unsigned long *bitmap_word;
	unsigned long bitidx;
	unsigned long word;

	get_pfnblock_bitmap_bitidx(page, pfn, &bitmap_word, &bitidx);
	/*
	 * This races, without locks, with set_pfnblock_migratetype(). Ensure
	 * a consistent read of the memory array, so that results, even though
	 * racy, are not corrupted.
	 */
	word = READ_ONCE(*bitmap_word);
	return (word >> bitidx) & mask;
}

/**
 * get_pfnblock_bit - Check if a standalone bit of a pageblock is set
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @pb_bit: pageblock bit to check
 *
 * Return: true if the bit is set, otherwise false
 */
bool get_pfnblock_bit(const struct page *page, unsigned long pfn,
		      enum pageblock_bits pb_bit)
{
	unsigned long *bitmap_word;
	unsigned long bitidx;

	if (WARN_ON_ONCE(!is_standalone_pb_bit(pb_bit)))
		return false;

	get_pfnblock_bitmap_bitidx(page, pfn, &bitmap_word, &bitidx);

	return test_bit(bitidx + pb_bit, bitmap_word);
}

/**
 * get_pfnblock_migratetype - Return the migratetype of a pageblock
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 *
 * Return: The migratetype of the pageblock
 *
 * Use get_pfnblock_migratetype() if caller already has both @page and @pfn
 * to save a call to page_to_pfn().
 */
__always_inline enum migratetype
get_pfnblock_migratetype(const struct page *page, unsigned long pfn)
{
	unsigned long mask = MIGRATETYPE_AND_ISO_MASK;
	unsigned long flags;

	flags = __get_pfnblock_flags_mask(page, pfn, mask);

#ifdef CONFIG_MEMORY_ISOLATION
	if (flags & BIT(PB_migrate_isolate))
		return MIGRATE_ISOLATE;
#endif
	return flags & MIGRATETYPE_MASK;
}

/**
 * __set_pfnblock_flags_mask - Set the requested group of flags for
 * a pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @flags: The flags to set
 * @mask: mask of bits that the caller is interested in
 */
static void __set_pfnblock_flags_mask(struct page *page, unsigned long pfn,
				      unsigned long flags, unsigned long mask)
{
	unsigned long *bitmap_word;
	unsigned long bitidx;
	unsigned long word;

	get_pfnblock_bitmap_bitidx(page, pfn, &bitmap_word, &bitidx);

	mask <<= bitidx;
	flags <<= bitidx;

	word = READ_ONCE(*bitmap_word);
	do {
	} while (!try_cmpxchg(bitmap_word, &word, (word & ~mask) | flags));
}

/**
 * set_pfnblock_bit - Set a standalone bit of a pageblock
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @pb_bit: pageblock bit to set
 */
void set_pfnblock_bit(const struct page *page, unsigned long pfn,
		      enum pageblock_bits pb_bit)
{
	unsigned long *bitmap_word;
	unsigned long bitidx;

	if (WARN_ON_ONCE(!is_standalone_pb_bit(pb_bit)))
		return;

	get_pfnblock_bitmap_bitidx(page, pfn, &bitmap_word, &bitidx);

	set_bit(bitidx + pb_bit, bitmap_word);
}

/**
 * clear_pfnblock_bit - Clear a standalone bit of a pageblock
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @pb_bit: pageblock bit to clear
 */
void clear_pfnblock_bit(const struct page *page, unsigned long pfn,
			enum pageblock_bits pb_bit)
{
	unsigned long *bitmap_word;
	unsigned long bitidx;

	if (WARN_ON_ONCE(!is_standalone_pb_bit(pb_bit)))
		return;

	get_pfnblock_bitmap_bitidx(page, pfn, &bitmap_word, &bitidx);

	clear_bit(bitidx + pb_bit, bitmap_word);
}

/**
 * set_pageblock_migratetype - Set the migratetype of a pageblock
 * @page: The page within the block of interest
 * @migratetype: migratetype to set
 */
static void set_pageblock_migratetype(struct page *page,
				      enum migratetype migratetype)
{
	if (unlikely(page_group_by_mobility_disabled &&
		     migratetype < MIGRATE_PCPTYPES))
		migratetype = MIGRATE_UNMOVABLE;

#ifdef CONFIG_MEMORY_ISOLATION
	if (migratetype == MIGRATE_ISOLATE) {
		VM_WARN_ONCE(1,
			"Use set_pageblock_isolate() for pageblock isolation");
		return;
	}
	VM_WARN_ONCE(get_pfnblock_bit(page, page_to_pfn(page),
				      PB_migrate_isolate),
		     "Use clear_pageblock_isolate() to unisolate pageblock");
	/* MIGRATETYPE_AND_ISO_MASK clears PB_migrate_isolate if it is set */
#endif
	__set_pfnblock_flags_mask(page, page_to_pfn(page),
				  (unsigned long)migratetype,
				  MIGRATETYPE_AND_ISO_MASK);
}

void __meminit init_pageblock_migratetype(struct page *page,
					  enum migratetype migratetype,
					  bool isolate)
{
	unsigned long flags;

	if (unlikely(page_group_by_mobility_disabled &&
		     migratetype < MIGRATE_PCPTYPES))
		migratetype = MIGRATE_UNMOVABLE;

	flags = migratetype;

#ifdef CONFIG_MEMORY_ISOLATION
	if (migratetype == MIGRATE_ISOLATE) {
		VM_WARN_ONCE(
			1,
			"Set isolate=true to isolate pageblock with a migratetype");
		return;
	}
	if (isolate)
		flags |= BIT(PB_migrate_isolate);
#endif
	__set_pfnblock_flags_mask(page, page_to_pfn(page), flags,
				  MIGRATETYPE_AND_ISO_MASK);
}

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);
	unsigned long sp, start_pfn;

	do {
		seq = zone_span_seqbegin(zone);
		start_pfn = zone->zone_start_pfn;
		sp = zone->spanned_pages;
		ret = !zone_spans_pfn(zone, pfn);
	} while (zone_span_seqretry(zone, seq));

	if (ret)
		pr_err("page 0x%lx outside node %d zone %s [ 0x%lx - 0x%lx ]\n",
			pfn, zone_to_nid(zone), zone->name,
			start_pfn, start_pfn + sp);

	return ret;
}

/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static bool __maybe_unused bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return true;
	if (zone != page_zone(page))
		return true;

	return false;
}
#else
static inline bool __maybe_unused bad_range(struct zone *zone, struct page *page)
{
	return false;
}
#endif

static void bad_page(struct page *page, const char *reason)
{
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			goto out;
		}
		if (nr_unshown) {
			pr_alert(
			      "BUG: Bad page state: %lu messages suppressed\n",
				nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	pr_alert("BUG: Bad page state in process %s  pfn:%05lx\n",
		current->comm, page_to_pfn(page));
	dump_page(page, reason);

	print_modules();
	dump_stack();
out:
	/* Leave bad fields for debug, except PageBuddy could make trouble */
	if (PageBuddy(page))
		__ClearPageBuddy(page);
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static inline unsigned int order_to_pindex(int migratetype, int order)
{

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	bool movable;
	if (order > PAGE_ALLOC_COSTLY_ORDER) {
		VM_BUG_ON(order != HPAGE_PMD_ORDER);

		movable = migratetype == MIGRATE_MOVABLE;

		return NR_LOWORDER_PCP_LISTS + movable;
	}
#else
	VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
#endif

	return (MIGRATE_PCPTYPES * order) + migratetype;
}

static inline int pindex_to_order(unsigned int pindex)
{
	int order = pindex / MIGRATE_PCPTYPES;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pindex >= NR_LOWORDER_PCP_LISTS)
		order = HPAGE_PMD_ORDER;
#else
	VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
#endif

	return order;
}

static inline bool pcp_allowed_order(unsigned int order)
{
	if (order <= PAGE_ALLOC_COSTLY_ORDER)
		return true;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (order == HPAGE_PMD_ORDER)
		return true;
#endif
	return false;
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page" and have PG_head set.
 *
 * The remaining PAGE_SIZE pages are called "tail pages". PageTail() is encoded
 * in bit 0 of page->compound_head. The rest of bits is pointer to head page.
 *
 * The first tail page's ->compound_order holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

void prep_compound_page(struct page *page, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;

	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++)
		prep_compound_tail(page, i);

	prep_compound_head(page, order);
}

static inline void set_buddy_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

#ifdef CONFIG_COMPACTION
static inline struct capture_control *task_capc(struct zone *zone)
{
	struct capture_control *capc = current->capture_control;

	return unlikely(capc) &&
		!(current->flags & PF_KTHREAD) &&
		!capc->page &&
		capc->cc->zone == zone ? capc : NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
		   int order, int migratetype)
{
	if (!capc || order != capc->cc->order)
		return false;

	/* Do not accidentally pollute CMA or isolated regions*/
	if (is_migrate_cma(migratetype) ||
	    is_migrate_isolate(migratetype))
		return false;

	/*
	 * Do not let lower order allocations pollute a movable pageblock
	 * unless compaction is also requesting movable pages.
	 * This might let an unmovable request use a reclaimable pageblock
	 * and vice-versa but no more than normal fallback logic which can
	 * have trouble finding a high-order free page.
	 */
	if (order < pageblock_order && migratetype == MIGRATE_MOVABLE &&
	    capc->cc->migratetype != MIGRATE_MOVABLE)
		return false;

	if (migratetype != capc->cc->migratetype)
		trace_mm_page_alloc_extfrag(page, capc->cc->order, order,
					    capc->cc->migratetype, migratetype);

	capc->page = page;
	return true;
}

#else
static inline struct capture_control *task_capc(struct zone *zone)
{
	return NULL;
}

static inline bool
compaction_capture(struct capture_control *capc, struct page *page,
		   int order, int migratetype)
{
	return false;
}
#endif /* CONFIG_COMPACTION */

static inline void account_freepages(struct zone *zone, int nr_pages,
				     int migratetype)
{
	lockdep_assert_held(&zone->lock);

	if (is_migrate_isolate(migratetype))
		return;

	__mod_zone_page_state(zone, NR_FREE_PAGES, nr_pages);

	if (is_migrate_cma(migratetype))
		__mod_zone_page_state(zone, NR_FREE_CMA_PAGES, nr_pages);
	else if (is_migrate_highatomic(migratetype))
		WRITE_ONCE(zone->nr_free_highatomic,
			   zone->nr_free_highatomic + nr_pages);
}

/* Used for pages not on another list */
static inline void __add_to_free_list(struct page *page, struct zone *zone,
				      unsigned int order, int migratetype,
				      bool tail)
{
	struct free_area *area = &zone->free_area[order];
	int nr_pages = 1 << order;

	VM_WARN_ONCE(get_pageblock_migratetype(page) != migratetype,
		     "page type is %d, passed migratetype is %d (nr=%d)\n",
		     get_pageblock_migratetype(page), migratetype, nr_pages);

	if (tail)
		list_add_tail(&page->buddy_list, &area->free_list[migratetype]);
	else
		list_add(&page->buddy_list, &area->free_list[migratetype]);
	area->nr_free++;

	if (order >= pageblock_order && !is_migrate_isolate(migratetype))
		__mod_zone_page_state(zone, NR_FREE_PAGES_BLOCKS, nr_pages);
}

/*
 * Used for pages which are on another list. Move the pages to the tail
 * of the list - so the moved pages won't immediately be considered for
 * allocation again (e.g., optimization for memory onlining).
 */
static inline void move_to_free_list(struct page *page, struct zone *zone,
				     unsigned int order, int old_mt, int new_mt)
{
	struct free_area *area = &zone->free_area[order];
	int nr_pages = 1 << order;

	/* Free page moving can fail, so it happens before the type update */
	VM_WARN_ONCE(get_pageblock_migratetype(page) != old_mt,
		     "page type is %d, passed migratetype is %d (nr=%d)\n",
		     get_pageblock_migratetype(page), old_mt, nr_pages);

	list_move_tail(&page->buddy_list, &area->free_list[new_mt]);

	account_freepages(zone, -nr_pages, old_mt);
	account_freepages(zone, nr_pages, new_mt);

	if (order >= pageblock_order &&
	    is_migrate_isolate(old_mt) != is_migrate_isolate(new_mt)) {
		if (!is_migrate_isolate(old_mt))
			nr_pages = -nr_pages;
		__mod_zone_page_state(zone, NR_FREE_PAGES_BLOCKS, nr_pages);
	}
}

static inline void __del_page_from_free_list(struct page *page, struct zone *zone,
					     unsigned int order, int migratetype)
{
	int nr_pages = 1 << order;

        VM_WARN_ONCE(get_pageblock_migratetype(page) != migratetype,
		     "page type is %d, passed migratetype is %d (nr=%d)\n",
		     get_pageblock_migratetype(page), migratetype, nr_pages);

	/* clear reported state and update reported page count */
	if (page_reported(page))
		__ClearPageReported(page);

	list_del(&page->buddy_list);
	__ClearPageBuddy(page);
	set_page_private(page, 0);
	zone->free_area[order].nr_free--;

	if (order >= pageblock_order && !is_migrate_isolate(migratetype))
		__mod_zone_page_state(zone, NR_FREE_PAGES_BLOCKS, -nr_pages);
}

static inline void del_page_from_free_list(struct page *page, struct zone *zone,
					   unsigned int order, int migratetype)
{
	__del_page_from_free_list(page, zone, order, migratetype);
	account_freepages(zone, -(1 << order), migratetype);
}

static inline struct page *get_page_from_free_area(struct free_area *area,
					    int migratetype)
{
	return list_first_entry_or_null(&area->free_list[migratetype],
					struct page, buddy_list);
}

/*
 * If this is less than the 2nd largest possible page, check if the buddy
 * of the next-higher order is free. If it is, it's possible
 * that pages are being freed that will coalesce soon. In case,
 * that is happening, add the free page to the tail of the list
 * so it's less likely to be used soon and more likely to be merged
 * as a 2-level higher order page
 */
static inline bool
buddy_merge_likely(unsigned long pfn, unsigned long buddy_pfn,
		   struct page *page, unsigned int order)
{
	unsigned long higher_page_pfn;
	struct page *higher_page;

	if (order >= MAX_PAGE_ORDER - 1)
		return false;

	higher_page_pfn = buddy_pfn & pfn;
	higher_page = page + (higher_page_pfn - pfn);

	return find_buddy_page_pfn(higher_page, higher_page_pfn, order + 1,
			NULL) != NULL;
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with PageBuddy.
 * Page's order is recorded in page_private(page) field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were
 * free, the remainder of the region must be split into blocks.
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.
 *
 * -- nyc
 */

static inline void __free_one_page(struct page *page,
		unsigned long pfn,
		struct zone *zone, unsigned int order,
		int migratetype, fpi_t fpi_flags)
{
	struct capture_control *capc = task_capc(zone);
	unsigned long buddy_pfn = 0;
	unsigned long combined_pfn;
	struct page *buddy;
	bool to_tail;

	VM_BUG_ON(!zone_is_initialized(zone));
	VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

	VM_BUG_ON(migratetype == -1);
	VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);
	VM_BUG_ON_PAGE(bad_range(zone, page), page);

	account_freepages(zone, 1 << order, migratetype);

	while (order < MAX_PAGE_ORDER) {
		int buddy_mt = migratetype;

		if (compaction_capture(capc, page, order, migratetype)) {
			account_freepages(zone, -(1 << order), migratetype);
			return;
		}

		buddy = find_buddy_page_pfn(page, pfn, order, &buddy_pfn);
		if (!buddy)
			goto done_merging;

		if (unlikely(order >= pageblock_order)) {
			/*
			 * We want to prevent merge between freepages on pageblock
			 * without fallbacks and normal pageblock. Without this,
			 * pageblock isolation could cause incorrect freepage or CMA
			 * accounting or HIGHATOMIC accounting.
			 */
			buddy_mt = get_pfnblock_migratetype(buddy, buddy_pfn);

			if (migratetype != buddy_mt &&
			    (!migratetype_is_mergeable(migratetype) ||
			     !migratetype_is_mergeable(buddy_mt)))
				goto done_merging;
		}

		/*
		 * Our buddy is free or it is CONFIG_DEBUG_PAGEALLOC guard page,
		 * merge with it and move up one order.
		 */
		if (page_is_guard(buddy))
			clear_page_guard(zone, buddy, order);
		else
			__del_page_from_free_list(buddy, zone, order, buddy_mt);

		if (unlikely(buddy_mt != migratetype)) {
			/*
			 * Match buddy type. This ensures that an
			 * expand() down the line puts the sub-blocks
			 * on the right freelists.
			 */
			set_pageblock_migratetype(buddy, migratetype);
		}

		combined_pfn = buddy_pfn & pfn;
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		order++;
	}

done_merging:
	set_buddy_order(page, order);

	if (fpi_flags & FPI_TO_TAIL)
		to_tail = true;
	else if (is_shuffle_order(order))
		to_tail = shuffle_pick_tail();
	else
		to_tail = buddy_merge_likely(pfn, buddy_pfn, page, order);

	__add_to_free_list(page, zone, order, migratetype, to_tail);

	/* Notify page reporting subsystem of freed page */
	if (!(fpi_flags & FPI_SKIP_REPORT_NOTIFY))
		page_reporting_notify_free(order);
}

/*
 * A bad page could be due to a number of fields. Instead of multiple branches,
 * try and check multiple fields with one check. The caller must do a detailed
 * check if necessary.
 */
static inline bool page_expected_state(struct page *page,
					unsigned long check_flags)
{
	if (unlikely(atomic_read(&page->_mapcount) != -1))
		return false;

	if (unlikely((unsigned long)page->mapping |
			page_ref_count(page) |
#ifdef CONFIG_MEMCG
			page->memcg_data |
#endif
			page_pool_page_is_pp(page) |
			(page->flags & check_flags)))
		return false;

	return true;
}

static const char *page_bad_reason(struct page *page, unsigned long flags)
{
	const char *bad_reason = NULL;

	if (unlikely(atomic_read(&page->_mapcount) != -1))
		bad_reason = "nonzero mapcount";
	if (unlikely(page->mapping != NULL))
		bad_reason = "non-NULL mapping";
	if (unlikely(page_ref_count(page) != 0))
		bad_reason = "nonzero _refcount";
	if (unlikely(page->flags & flags)) {
		if (flags == PAGE_FLAGS_CHECK_AT_PREP)
			bad_reason = "PAGE_FLAGS_CHECK_AT_PREP flag(s) set";
		else
			bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
	}
#ifdef CONFIG_MEMCG
	if (unlikely(page->memcg_data))
		bad_reason = "page still charged to cgroup";
#endif
	if (unlikely(page_pool_page_is_pp(page)))
		bad_reason = "page_pool leak";
	return bad_reason;
}

static inline bool free_page_is_bad(struct page *page)
{
	if (likely(page_expected_state(page, PAGE_FLAGS_CHECK_AT_FREE)))
		return false;

	/* Something has gone sideways, find it */
	bad_page(page, page_bad_reason(page, PAGE_FLAGS_CHECK_AT_FREE));
	return true;
}

static inline bool is_check_pages_enabled(void)
{
	return static_branch_unlikely(&check_pages_enabled);
}

static int free_tail_page_prepare(struct page *head_page, struct page *page)
{
	struct folio *folio = (struct folio *)head_page;
	int ret = 1;

	/*
	 * We rely page->lru.next never has bit 0 set, unless the page
	 * is PageTail(). Let's make sure that's true even for poisoned ->lru.
	 */
	BUILD_BUG_ON((unsigned long)LIST_POISON1 & 1);

	if (!is_check_pages_enabled()) {
		ret = 0;
		goto out;
	}
	switch (page - head_page) {
	case 1:
		/* the first tail page: these may be in place of ->mapping */
		if (unlikely(folio_large_mapcount(folio))) {
			bad_page(page, "nonzero large_mapcount");
			goto out;
		}
		if (IS_ENABLED(CONFIG_PAGE_MAPCOUNT) &&
		    unlikely(atomic_read(&folio->_nr_pages_mapped))) {
			bad_page(page, "nonzero nr_pages_mapped");
			goto out;
		}
		if (IS_ENABLED(CONFIG_MM_ID)) {
			if (unlikely(folio->_mm_id_mapcount[0] != -1)) {
				bad_page(page, "nonzero mm mapcount 0");
				goto out;
			}
			if (unlikely(folio->_mm_id_mapcount[1] != -1)) {
				bad_page(page, "nonzero mm mapcount 1");
				goto out;
			}
		}
		if (IS_ENABLED(CONFIG_64BIT)) {
			if (unlikely(atomic_read(&folio->_entire_mapcount) + 1)) {
				bad_page(page, "nonzero entire_mapcount");
				goto out;
			}
			if (unlikely(atomic_read(&folio->_pincount))) {
				bad_page(page, "nonzero pincount");
				goto out;
			}
		}
		break;
	case 2:
		/* the second tail page: deferred_list overlaps ->mapping */
		if (unlikely(!list_empty(&folio->_deferred_list))) {
			bad_page(page, "on deferred list");
			goto out;
		}
		if (!IS_ENABLED(CONFIG_64BIT)) {
			if (unlikely(atomic_read(&folio->_entire_mapcount) + 1)) {
				bad_page(page, "nonzero entire_mapcount");
				goto out;
			}
			if (unlikely(atomic_read(&folio->_pincount))) {
				bad_page(page, "nonzero pincount");
				goto out;
			}
		}
		break;
	case 3:
		/* the third tail page: hugetlb specifics overlap ->mappings */
		if (IS_ENABLED(CONFIG_HUGETLB_PAGE))
			break;
		fallthrough;
	default:
		if (page->mapping != TAIL_MAPPING) {
			bad_page(page, "corrupted mapping in tail page");
			goto out;
		}
		break;
	}
	if (unlikely(!PageTail(page))) {
		bad_page(page, "PageTail not set");
		goto out;
	}
	if (unlikely(compound_head(page) != head_page)) {
		bad_page(page, "compound_head not consistent");
		goto out;
	}
	ret = 0;
out:
	page->mapping = NULL;
	clear_compound_head(page);
	return ret;
}

/*
 * Skip KASAN memory poisoning when either:
 *
 * 1. For generic KASAN: deferred memory initialization has not yet completed.
 *    Tag-based KASAN modes skip pages freed via deferred memory initialization
 *    using page tags instead (see below).
 * 2. For tag-based KASAN modes: the page has a match-all KASAN tag, indicating
 *    that error detection is disabled for accesses via the page address.
 *
 * Pages will have match-all tags in the following circumstances:
 *
 * 1. Pages are being initialized for the first time, including during deferred
 *    memory init; see the call to page_kasan_tag_reset in __init_single_page.
 * 2. The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with the
 *    exception of pages unpoisoned by kasan_unpoison_vmalloc.
 * 3. The allocation was excluded from being checked due to sampling,
 *    see the call to kasan_unpoison_pages.
 *
 * Poisoning pages during deferred memory init will greatly lengthen the
 * process and cause problem in large memory systems as the deferred pages
 * initialization is done with interrupt disabled.
 *
 * Assuming that there will be no reference to those newly initialized
 * pages before they are ever allocated, this should have no effect on
 * KASAN memory tracking as the poison will be properly inserted at page
 * allocation time. The only corner case is when pages are allocated by
 * on-demand allocation and then freed again before the deferred pages
 * initialization is done, but this is not likely to happen.
 */
static inline bool should_skip_kasan_poison(struct page *page)
{
	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
		return deferred_pages_enabled();

	return page_kasan_tag(page) == KASAN_TAG_KERNEL;
}

static void kernel_init_pages(struct page *page, int numpages)
{
	int i;

	/* s390's use of memset() could override KASAN redzones. */
	kasan_disable_current();
	for (i = 0; i < numpages; i++)
		clear_highpage_kasan_tagged(page + i);
	kasan_enable_current();
}

#ifdef CONFIG_MEM_ALLOC_PROFILING

/* Should be called only if mem_alloc_profiling_enabled() */
void __clear_page_tag_ref(struct page *page)
{
	union pgtag_ref_handle handle;
	union codetag_ref ref;

	if (get_page_tag_ref(page, &ref, &handle)) {
		set_codetag_empty(&ref);
		update_page_tag_ref(handle, &ref);
		put_page_tag_ref(handle);
	}
}

/* Should be called only if mem_alloc_profiling_enabled() */
static noinline
void __pgalloc_tag_add(struct page *page, struct task_struct *task,
		       unsigned int nr)
{
	union pgtag_ref_handle handle;
	union codetag_ref ref;

	if (get_page_tag_ref(page, &ref, &handle)) {
		alloc_tag_add(&ref, task->alloc_tag, PAGE_SIZE * nr);
		update_page_tag_ref(handle, &ref);
		put_page_tag_ref(handle);
	}
}

static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
				   unsigned int nr)
{
	if (mem_alloc_profiling_enabled())
		__pgalloc_tag_add(page, task, nr);
}

int bcachefs_shutdown;

/* Should be called only if mem_alloc_profiling_enabled() */
static noinline
void __pgalloc_tag_sub(struct page *page, unsigned int nr)
{
	if (PageBcachefsWarn(page) && bcachefs_shutdown) {
		BUG();
		dump_stack();
	}

	ClearPageBcachefsWarn(page);

	union pgtag_ref_handle handle;
	union codetag_ref ref;

	if (get_page_tag_ref(page, &ref, &handle)) {
		alloc_tag_sub(&ref, PAGE_SIZE * nr);
		update_page_tag_ref(handle, &ref);
		put_page_tag_ref(handle);
	}
}

static inline void pgalloc_tag_sub(struct page *page, unsigned int nr)
{
	if (mem_alloc_profiling_enabled())
		__pgalloc_tag_sub(page, nr);
}

/* When tag is not NULL, assuming mem_alloc_profiling_enabled */
static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr)
{
	if (tag)
		this_cpu_sub(tag->counters->bytes, PAGE_SIZE * nr);
}

#else /* CONFIG_MEM_ALLOC_PROFILING */

static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
				   unsigned int nr) {}
static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr) {}

#endif /* CONFIG_MEM_ALLOC_PROFILING */

__always_inline bool free_pages_prepare(struct page *page,
			unsigned int order)
{
	int bad = 0;
	bool skip_kasan_poison = should_skip_kasan_poison(page);
	bool init = want_init_on_free();
	bool compound = PageCompound(page);
	struct folio *folio = page_folio(page);

	VM_BUG_ON_PAGE(PageTail(page), page);

	trace_mm_page_free(page, order);
	kmsan_free_page(page, order);

	if (memcg_kmem_online() && PageMemcgKmem(page))
		__memcg_kmem_uncharge_page(page, order);

	/*
	 * In rare cases, when truncation or holepunching raced with
	 * munlock after VM_LOCKED was cleared, Mlocked may still be
	 * found set here.  This does not indicate a problem, unless
	 * "unevictable_pgs_cleared" appears worryingly large.
	 */
	if (unlikely(folio_test_mlocked(folio))) {
		long nr_pages = folio_nr_pages(folio);

		__folio_clear_mlocked(folio);
		zone_stat_mod_folio(folio, NR_MLOCK, -nr_pages);
		count_vm_events(UNEVICTABLE_PGCLEARED, nr_pages);
	}

	if (unlikely(PageHWPoison(page)) && !order) {
		/* Do not let hwpoison pages hit pcplists/buddy */
		reset_page_owner(page, order);
		page_table_check_free(page, order);
		pgalloc_tag_sub(page, 1 << order);

		/*
		 * The page is isolated and accounted for.
		 * Mark the codetag as empty to avoid accounting error
		 * when the page is freed by unpoison_memory().
		 */
		clear_page_tag_ref(page);
		return false;
	}

	VM_BUG_ON_PAGE(compound && compound_order(page) != order, page);

	/*
	 * Check tail pages before head page information is cleared to
	 * avoid checking PageCompound for order-0 pages.
	 */
	if (unlikely(order)) {
		int i;

		if (compound) {
			page[1].flags &= ~PAGE_FLAGS_SECOND;
#ifdef NR_PAGES_IN_LARGE_FOLIO
			folio->_nr_pages = 0;
#endif
		}
		for (i = 1; i < (1 << order); i++) {
			if (compound)
				bad += free_tail_page_prepare(page, page + i);
			if (is_check_pages_enabled()) {
				if (free_page_is_bad(page + i)) {
					bad++;
					continue;
				}
			}
			(page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
		}
	}
	if (folio_test_anon(folio)) {
		mod_mthp_stat(order, MTHP_STAT_NR_ANON, -1);
		folio->mapping = NULL;
	}
	if (unlikely(page_has_type(page)))
		/* Reset the page_type (which overlays _mapcount) */
		page->page_type = UINT_MAX;

	if (is_check_pages_enabled()) {
		if (free_page_is_bad(page))
			bad++;
		if (bad)
			return false;
	}

	page_cpupid_reset_last(page);
	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	reset_page_owner(page, order);
	page_table_check_free(page, order);
	pgalloc_tag_sub(page, 1 << order);

	if (!PageHighMem(page)) {
		debug_check_no_locks_freed(page_address(page),
					   PAGE_SIZE << order);
		debug_check_no_obj_freed(page_address(page),
					   PAGE_SIZE << order);
	}

	kernel_poison_pages(page, 1 << order);

	/*
	 * As memory initialization might be integrated into KASAN,
	 * KASAN poisoning and memory initialization code must be
	 * kept together to avoid discrepancies in behavior.
	 *
	 * With hardware tag-based KASAN, memory tags must be set before the
	 * page becomes unavailable via debug_pagealloc or arch_free_page.
	 */
	if (!skip_kasan_poison) {
		kasan_poison_pages(page, order, init);

		/* Memory is already initialized if KASAN did it internally. */
		if (kasan_has_integrated_init())
			init = false;
	}
	if (init)
		kernel_init_pages(page, 1 << order);

	/*
	 * arch_free_page() can make the page's contents inaccessible.  s390
	 * does this.  So nothing which can access the page's contents should
	 * happen after this.
	 */
	arch_free_page(page, order);

	debug_pagealloc_unmap_pages(page, 1 << order);

	return true;
}

/*
 * Frees a number of pages from the PCP lists
 * Assumes all pages on list are in same zone.
 * count is the number of pages to free.
 */
static void free_pcppages_bulk(struct zone *zone, int count,
					struct per_cpu_pages *pcp,
					int pindex)
{
	unsigned long flags;
	unsigned int order;
	struct page *page;

	/*
	 * Ensure proper count is passed which otherwise would stuck in the
	 * below while (list_empty(list)) loop.
	 */
	count = min(pcp->count, count);

	/* Ensure requested pindex is drained first. */
	pindex = pindex - 1;

	spin_lock_irqsave(&zone->lock, flags);

	while (count > 0) {
		struct list_head *list;
		int nr_pages;

		/* Remove pages from lists in a round-robin fashion. */
		do {
			if (++pindex > NR_PCP_LISTS - 1)
				pindex = 0;
			list = &pcp->lists[pindex];
		} while (list_empty(list));

		order = pindex_to_order(pindex);
		nr_pages = 1 << order;
		do {
			unsigned long pfn;
			int mt;

			page = list_last_entry(list, struct page, pcp_list);
			pfn = page_to_pfn(page);
			mt = get_pfnblock_migratetype(page, pfn);

			/* must delete to avoid corrupting pcp list */
			list_del(&page->pcp_list);
			count -= nr_pages;
			pcp->count -= nr_pages;

			__free_one_page(page, pfn, zone, order, mt, FPI_NONE);
			trace_mm_page_pcpu_drain(page, order, mt);
		} while (count > 0 && !list_empty(list));
	}

	spin_unlock_irqrestore(&zone->lock, flags);
}

/* Split a multi-block free page into its individual pageblocks. */
static void split_large_buddy(struct zone *zone, struct page *page,
			      unsigned long pfn, int order, fpi_t fpi)
{
	unsigned long end = pfn + (1 << order);

	VM_WARN_ON_ONCE(!IS_ALIGNED(pfn, 1 << order));
	/* Caller removed page from freelist, buddy info cleared! */
	VM_WARN_ON_ONCE(PageBuddy(page));

	if (order > pageblock_order)
		order = pageblock_order;

	do {
		int mt = get_pfnblock_migratetype(page, pfn);

		__free_one_page(page, pfn, zone, order, mt, fpi);
		pfn += 1 << order;
		if (pfn == end)
			break;
		page = pfn_to_page(pfn);
	} while (1);
}

static void add_page_to_zone_llist(struct zone *zone, struct page *page,
				   unsigned int order)
{
	/* Remember the order */
	page->order = order;
	/* Add the page to the free list */
	llist_add(&page->pcp_llist, &zone->trylock_free_pages);
}

static void free_one_page(struct zone *zone, struct page *page,
			  unsigned long pfn, unsigned int order,
			  fpi_t fpi_flags)
{
	struct llist_head *llhead;
	unsigned long flags;

	if (unlikely(fpi_flags & FPI_TRYLOCK)) {
		if (!spin_trylock_irqsave(&zone->lock, flags)) {
			add_page_to_zone_llist(zone, page, order);
			return;
		}
	} else {
		spin_lock_irqsave(&zone->lock, flags);
	}

	/* The lock succeeded. Process deferred pages. */
	llhead = &zone->trylock_free_pages;
	if (unlikely(!llist_empty(llhead) && !(fpi_flags & FPI_TRYLOCK))) {
		struct llist_node *llnode;
		struct page *p, *tmp;

		llnode = llist_del_all(llhead);
		llist_for_each_entry_safe(p, tmp, llnode, pcp_llist) {
			unsigned int p_order = p->order;

			split_large_buddy(zone, p, page_to_pfn(p), p_order, fpi_flags);
			__count_vm_events(PGFREE, 1 << p_order);
		}
	}
	split_large_buddy(zone, page, pfn, order, fpi_flags);
	spin_unlock_irqrestore(&zone->lock, flags);

	__count_vm_events(PGFREE, 1 << order);
}

static void __free_pages_ok(struct page *page, unsigned int order,
			    fpi_t fpi_flags)
{
	unsigned long pfn = page_to_pfn(page);
	struct zone *zone = page_zone(page);

	if (free_pages_prepare(page, order))
		free_one_page(zone, page, pfn, order, fpi_flags);
}

void __meminit __free_pages_core(struct page *page, unsigned int order,
		enum meminit_context context)
{
	unsigned int nr_pages = 1 << order;
	struct page *p = page;
	unsigned int loop;

	/*
	 * When initializing the memmap, __init_single_page() sets the refcount
	 * of all pages to 1 ("allocated"/"not free"). We have to set the
	 * refcount of all involved pages to 0.
	 *
	 * Note that hotplugged memory pages are initialized to PageOffline().
	 * Pages freed from memblock might be marked as reserved.
	 */
	if (IS_ENABLED(CONFIG_MEMORY_HOTPLUG) &&
	    unlikely(context == MEMINIT_HOTPLUG)) {
		for (loop = 0; loop < nr_pages; loop++, p++) {
			VM_WARN_ON_ONCE(PageReserved(p));
			__ClearPageOffline(p);
			set_page_count(p, 0);
		}

		adjust_managed_page_count(page, nr_pages);
	} else {
		for (loop = 0; loop < nr_pages; loop++, p++) {
			__ClearPageReserved(p);
			set_page_count(p, 0);
		}

		/* memblock adjusts totalram_pages() manually. */
		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
	}

	if (page_contains_unaccepted(page, order)) {
		if (order == MAX_PAGE_ORDER && __free_unaccepted(page))
			return;

		accept_memory(page_to_phys(page), PAGE_SIZE << order);
	}

	/*
	 * Bypass PCP and place fresh pages right to the tail, primarily
	 * relevant for memory onlining.
	 */
	__free_pages_ok(page, order, FPI_TO_TAIL);
}

/*
 * Check that the whole (or subset of) a pageblock given by the interval of
 * [start_pfn, end_pfn) is valid and within the same zone, before scanning it
 * with the migration of free compaction scanner.
 *
 * Return struct page pointer of start_pfn, or NULL if checks were not passed.
 *
 * It's possible on some configurations to have a setup like node0 node1 node0
 * i.e. it's possible that all pages within a zones range of pages do not
 * belong to a single zone. We assume that a border between node0 and node1
 * can occur within a single pageblock, but not a node0 node1 node0
 * interleaving within a single pageblock. It is therefore sufficient to check
 * the first and last page of a pageblock and avoid checking each individual
 * page in a pageblock.
 *
 * Note: the function may return non-NULL struct page even for a page block
 * which contains a memory hole (i.e. there is no physical memory for a subset
 * of the pfn range). For example, if the pageblock order is MAX_PAGE_ORDER, which
 * will fall into 2 sub-sections, and the end pfn of the pageblock may be hole
 * even though the start pfn is online and valid. This should be safe most of
 * the time because struct pages are still initialized via init_unavailable_range()
 * and pfn walkers shouldn't touch any physical memory range for which they do
 * not recognize any specific metadata in struct pages.
 */
struct page *__pageblock_pfn_to_page(unsigned long start_pfn,
				     unsigned long end_pfn, struct zone *zone)
{
	struct page *start_page;
	struct page *end_page;

	/* end_pfn is one past the range we are checking */
	end_pfn--;

	if (!pfn_valid(end_pfn))
		return NULL;

	start_page = pfn_to_online_page(start_pfn);
	if (!start_page)
		return NULL;

	if (page_zone(start_page) != zone)
		return NULL;

	end_page = pfn_to_page(end_pfn);

	/* This gives a shorter code than deriving page_zone(end_page) */
	if (page_zone_id(start_page) != page_zone_id(end_page))
		return NULL;

	return start_page;
}

/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- nyc
 */
static inline unsigned int expand(struct zone *zone, struct page *page, int low,
				  int high, int migratetype)
{
	unsigned int size = 1 << high;
	unsigned int nr_added = 0;

	while (high > low) {
		high--;
		size >>= 1;
		VM_BUG_ON_PAGE(bad_range(zone, &page[size]), &page[size]);

		/*
		 * Mark as guard pages (or page), that will allow to
		 * merge back to allocator when buddy will be freed.
		 * Corresponding page table entries will not be touched,
		 * pages will stay not present in virtual address space
		 */
		if (set_page_guard(zone, &page[size], high))
			continue;

		__add_to_free_list(&page[size], zone, high, migratetype, false);
		set_buddy_order(&page[size], high);
		nr_added += size;
	}

	return nr_added;
}

static __always_inline void page_del_and_expand(struct zone *zone,
						struct page *page, int low,
						int high, int migratetype)
{
	int nr_pages = 1 << high;

	__del_page_from_free_list(page, zone, high, migratetype);
	nr_pages -= expand(zone, page, low, high, migratetype);
	account_freepages(zone, -nr_pages, migratetype);
}

static void check_new_page_bad(struct page *page)
{
	if (unlikely(PageHWPoison(page))) {
		/* Don't complain about hwpoisoned pages */
		if (PageBuddy(page))
			__ClearPageBuddy(page);
		return;
	}

	bad_page(page,
		 page_bad_reason(page, PAGE_FLAGS_CHECK_AT_PREP));
}

/*
 * This page is about to be returned from the page allocator
 */
static bool check_new_page(struct page *page)
{
	if (likely(page_expected_state(page,
				PAGE_FLAGS_CHECK_AT_PREP|__PG_HWPOISON)))
		return false;

	check_new_page_bad(page);
	return true;
}

static inline bool check_new_pages(struct page *page, unsigned int order)
{
	if (is_check_pages_enabled()) {
		for (int i = 0; i < (1 << order); i++) {
			struct page *p = page + i;

			if (check_new_page(p))
				return true;
		}
	}

	return false;
}

static inline bool should_skip_kasan_unpoison(gfp_t flags)
{
	/* Don't skip if a software KASAN mode is enabled. */
	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
		return false;

	/* Skip, if hardware tag-based KASAN is not enabled. */
	if (!kasan_hw_tags_enabled())
		return true;

	/*
	 * With hardware tag-based KASAN enabled, skip if this has been
	 * requested via __GFP_SKIP_KASAN.
	 */
	return flags & __GFP_SKIP_KASAN;
}

static inline bool should_skip_init(gfp_t flags)
{
	/* Don't skip, if hardware tag-based KASAN is not enabled. */
	if (!kasan_hw_tags_enabled())
		return false;

	/* For hardware tag-based KASAN, skip if requested. */
	return (flags & __GFP_SKIP_ZERO);
}

inline void post_alloc_hook(struct page *page, unsigned int order,
				gfp_t gfp_flags)
{
	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
			!should_skip_init(gfp_flags);
	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
	int i;

	set_page_private(page, 0);

	arch_alloc_page(page, order);
	debug_pagealloc_map_pages(page, 1 << order);

	/*
	 * Page unpoisoning must happen before memory initialization.
	 * Otherwise, the poison pattern will be overwritten for __GFP_ZERO
	 * allocations and the page unpoisoning code will complain.
	 */
	kernel_unpoison_pages(page, 1 << order);

	/*
	 * As memory initialization might be integrated into KASAN,
	 * KASAN unpoisoning and memory initializion code must be
	 * kept together to avoid discrepancies in behavior.
	 */

	/*
	 * If memory tags should be zeroed
	 * (which happens only when memory should be initialized as well).
	 */
	if (zero_tags) {
		/* Initialize both memory and memory tags. */
		for (i = 0; i != 1 << order; ++i)
			tag_clear_highpage(page + i);

		/* Take note that memory was initialized by the loop above. */
		init = false;
	}
	if (!should_skip_kasan_unpoison(gfp_flags) &&
	    kasan_unpoison_pages(page, order, init)) {
		/* Take note that memory was initialized by KASAN. */
		if (kasan_has_integrated_init())
			init = false;
	} else {
		/*
		 * If memory tags have not been set by KASAN, reset the page
		 * tags to ensure page_address() dereferencing does not fault.
		 */
		for (i = 0; i != 1 << order; ++i)
			page_kasan_tag_reset(page + i);
	}
	/* If memory is still not initialized, initialize it now. */
	if (init)
		kernel_init_pages(page, 1 << order);

	set_page_owner(page, order, gfp_flags);
	page_table_check_alloc(page, order);
	pgalloc_tag_add(page, current, 1 << order);
}

static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
							unsigned int alloc_flags)
{
	post_alloc_hook(page, order, gfp_flags);

	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);

	/*
	 * page is set pfmemalloc when ALLOC_NO_WATERMARKS was necessary to
	 * allocate the page. The expectation is that the caller is taking
	 * steps that will free more memory. The caller should avoid the page
	 * being used for !PFMEMALLOC purposes.
	 */
	if (alloc_flags & ALLOC_NO_WATERMARKS)
		set_page_pfmemalloc(page);
	else
		clear_page_pfmemalloc(page);
}

/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */
static __always_inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < NR_PAGE_ORDERS; ++current_order) {
		area = &(zone->free_area[current_order]);
		page = get_page_from_free_area(area, migratetype);
		if (!page)
			continue;

		page_del_and_expand(zone, page, order, current_order,
				    migratetype);
		trace_mm_page_alloc_zone_locked(page, order, migratetype,
				pcp_allowed_order(order) &&
				migratetype < MIGRATE_PCPTYPES);
		return page;
	}

	return NULL;
}


/*
 * This array describes the order lists are fallen back to when
 * the free lists for the desirable migrate type are depleted
 *
 * The other migratetypes do not have fallbacks.
 */
static int fallbacks[MIGRATE_PCPTYPES][MIGRATE_PCPTYPES - 1] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE   },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE   },
};

#ifdef CONFIG_CMA
static __always_inline struct page *__rmqueue_cma_fallback(struct zone *zone,
					unsigned int order)
{
	return __rmqueue_smallest(zone, order, MIGRATE_CMA);
}
#else
static inline struct page *__rmqueue_cma_fallback(struct zone *zone,
					unsigned int order) { return NULL; }
#endif

/*
 * Move all free pages of a block to new type's freelist. Caller needs to
 * change the block type.
 */
static int __move_freepages_block(struct zone *zone, unsigned long start_pfn,
				  int old_mt, int new_mt)
{
	struct page *page;
	unsigned long pfn, end_pfn;
	unsigned int order;
	int pages_moved = 0;

	VM_WARN_ON(start_pfn & (pageblock_nr_pages - 1));
	end_pfn = pageblock_end_pfn(start_pfn);

	for (pfn = start_pfn; pfn < end_pfn;) {
		page = pfn_to_page(pfn);
		if (!PageBuddy(page)) {
			pfn++;
			continue;
		}

		/* Make sure we are not inadvertently changing nodes */
		VM_BUG_ON_PAGE(page_to_nid(page) != zone_to_nid(zone), page);
		VM_BUG_ON_PAGE(page_zone(page) != zone, page);

		order = buddy_order(page);

		move_to_free_list(page, zone, order, old_mt, new_mt);

		pfn += 1 << order;
		pages_moved += 1 << order;
	}

	return pages_moved;
}

static bool prep_move_freepages_block(struct zone *zone, struct page *page,
				      unsigned long *start_pfn,
				      int *num_free, int *num_movable)
{
	unsigned long pfn, start, end;

	pfn = page_to_pfn(page);
	start = pageblock_start_pfn(pfn);
	end = pageblock_end_pfn(pfn);

	/*
	 * The caller only has the lock for @zone, don't touch ranges
	 * that straddle into other zones. While we could move part of
	 * the range that's inside the zone, this call is usually
	 * accompanied by other operations such as migratetype updates
	 * which also should be locked.
	 */
	if (!zone_spans_pfn(zone, start))
		return false;
	if (!zone_spans_pfn(zone, end - 1))
		return false;

	*start_pfn = start;

	if (num_free) {
		*num_free = 0;
		*num_movable = 0;
		for (pfn = start; pfn < end;) {
			page = pfn_to_page(pfn);
			if (PageBuddy(page)) {
				int nr = 1 << buddy_order(page);

				*num_free += nr;
				pfn += nr;
				continue;
			}
			/*
			 * We assume that pages that could be isolated for
			 * migration are movable. But we don't actually try
			 * isolating, as that would be expensive.
			 */
			if (PageLRU(page) || page_has_movable_ops(page))
				(*num_movable)++;
			pfn++;
		}
	}

	return true;
}

static int move_freepages_block(struct zone *zone, struct page *page,
				int old_mt, int new_mt)
{
	unsigned long start_pfn;
	int res;

	if (!prep_move_freepages_block(zone, page, &start_pfn, NULL, NULL))
		return -1;

	res = __move_freepages_block(zone, start_pfn, old_mt, new_mt);
	set_pageblock_migratetype(pfn_to_page(start_pfn), new_mt);

	return res;

}

#ifdef CONFIG_MEMORY_ISOLATION
/* Look for a buddy that straddles start_pfn */
static unsigned long find_large_buddy(unsigned long start_pfn)
{
	int order = 0;
	struct page *page;
	unsigned long pfn = start_pfn;

	while (!PageBuddy(page = pfn_to_page(pfn))) {
		/* Nothing found */
		if (++order > MAX_PAGE_ORDER)
			return start_pfn;
		pfn &= ~0UL << order;
	}

	/*
	 * Found a preceding buddy, but does it straddle?
	 */
	if (pfn + (1 << buddy_order(page)) > start_pfn)
		return pfn;

	/* Nothing found */
	return start_pfn;
}

static inline void toggle_pageblock_isolate(struct page *page, bool isolate)
{
	if (isolate)
		set_pfnblock_bit(page, page_to_pfn(page), PB_migrate_isolate);
	else
		clear_pfnblock_bit(page, page_to_pfn(page), PB_migrate_isolate);
}

/**
 * __move_freepages_block_isolate - move free pages in block for page isolation
 * @zone: the zone
 * @page: the pageblock page
 * @isolate: to isolate the given pageblock or unisolate it
 *
 * This is similar to move_freepages_block(), but handles the special
 * case encountered in page isolation, where the block of interest
 * might be part of a larger buddy spanning multiple pageblocks.
 *
 * Unlike the regular page allocator path, which moves pages while
 * stealing buddies off the freelist, page isolation is interested in
 * arbitrary pfn ranges that may have overlapping buddies on both ends.
 *
 * This function handles that. Straddling buddies are split into
 * individual pageblocks. Only the block of interest is moved.
 *
 * Returns %true if pages could be moved, %false otherwise.
 */
static bool __move_freepages_block_isolate(struct zone *zone,
		struct page *page, bool isolate)
{
	unsigned long start_pfn, pfn;
	int from_mt;
	int to_mt;

	if (isolate == get_pageblock_isolate(page)) {
		VM_WARN_ONCE(1, "%s a pageblock that is already in that state",
			     isolate ? "Isolate" : "Unisolate");
		return false;
	}

	if (!prep_move_freepages_block(zone, page, &start_pfn, NULL, NULL))
		return false;

	/* No splits needed if buddies can't span multiple blocks */
	if (pageblock_order == MAX_PAGE_ORDER)
		goto move;

	/* We're a tail block in a larger buddy */
	pfn = find_large_buddy(start_pfn);
	if (pfn != start_pfn) {
		struct page *buddy = pfn_to_page(pfn);
		int order = buddy_order(buddy);

		del_page_from_free_list(buddy, zone, order,
					get_pfnblock_migratetype(buddy, pfn));
		toggle_pageblock_isolate(page, isolate);
		split_large_buddy(zone, buddy, pfn, order, FPI_NONE);
		return true;
	}

	/* We're the starting block of a larger buddy */
	if (PageBuddy(page) && buddy_order(page) > pageblock_order) {
		int order = buddy_order(page);

		del_page_from_free_list(page, zone, order,
					get_pfnblock_migratetype(page, pfn));
		toggle_pageblock_isolate(page, isolate);
		split_large_buddy(zone, page, pfn, order, FPI_NONE);
		return true;
	}
move:
	/* Use MIGRATETYPE_MASK to get non-isolate migratetype */
	if (isolate) {
		from_mt = __get_pfnblock_flags_mask(page, page_to_pfn(page),
						    MIGRATETYPE_MASK);
		to_mt = MIGRATE_ISOLATE;
	} else {
		from_mt = MIGRATE_ISOLATE;
		to_mt = __get_pfnblock_flags_mask(page, page_to_pfn(page),
						  MIGRATETYPE_MASK);
	}

	__move_freepages_block(zone, start_pfn, from_mt, to_mt);
	toggle_pageblock_isolate(pfn_to_page(start_pfn), isolate);

	return true;
}

bool pageblock_isolate_and_move_free_pages(struct zone *zone, struct page *page)
{
	return __move_freepages_block_isolate(zone, page, true);
}

bool pageblock_unisolate_and_move_free_pages(struct zone *zone, struct page *page)
{
	return __move_freepages_block_isolate(zone, page, false);
}

#endif /* CONFIG_MEMORY_ISOLATION */

static void change_pageblock_range(struct page *pageblock_page,
					int start_order, int migratetype)
{
	int nr_pageblocks = 1 << (start_order - pageblock_order);

	while (nr_pageblocks--) {
		set_pageblock_migratetype(pageblock_page, migratetype);
		pageblock_page += pageblock_nr_pages;
	}
}

static inline bool boost_watermark(struct zone *zone)
{
	unsigned long max_boost;

	if (!watermark_boost_factor)
		return false;
	/*
	 * Don't bother in zones that are unlikely to produce results.
	 * On small machines, including kdump capture kernels running
	 * in a small area, boosting the watermark can cause an out of
	 * memory situation immediately.
	 */
	if ((pageblock_nr_pages * 4) > zone_managed_pages(zone))
		return false;

	max_boost = mult_frac(zone->_watermark[WMARK_HIGH],
			watermark_boost_factor, 10000);

	/*
	 * high watermark may be uninitialised if fragmentation occurs
	 * very early in boot so do not boost. We do not fall
	 * through and boost by pageblock_nr_pages as failing
	 * allocations that early means that reclaim is not going
	 * to help and it may even be impossible to reclaim the
	 * boosted watermark resulting in a hang.
	 */
	if (!max_boost)
		return false;

	max_boost = max(pageblock_nr_pages, max_boost);

	zone->watermark_boost = min(zone->watermark_boost + pageblock_nr_pages,
		max_boost);

	return true;
}

/*
 * When we are falling back to another migratetype during allocation, should we
 * try to claim an entire block to satisfy further allocations, instead of
 * polluting multiple pageblocks?
 */
static bool should_try_claim_block(unsigned int order, int start_mt)
{
	/*
	 * Leaving this order check is intended, although there is
	 * relaxed order check in next check. The reason is that
	 * we can actually claim the whole pageblock if this condition met,
	 * but, below check doesn't guarantee it and that is just heuristic
	 * so could be changed anytime.
	 */
	if (order >= pageblock_order)
		return true;

	/*
	 * Above a certain threshold, always try to claim, as it's likely there
	 * will be more free pages in the pageblock.
	 */
	if (order >= pageblock_order / 2)
		return true;

	/*
	 * Unmovable/reclaimable allocations would cause permanent
	 * fragmentations if they fell back to allocating from a movable block
	 * (polluting it), so we try to claim the whole block regardless of the
	 * allocation size. Later movable allocations can always steal from this
	 * block, which is less problematic.
	 */
	if (start_mt == MIGRATE_RECLAIMABLE || start_mt == MIGRATE_UNMOVABLE)
		return true;

	if (page_group_by_mobility_disabled)
		return true;

	/*
	 * Movable pages won't cause permanent fragmentation, so when you alloc
	 * small pages, we just need to temporarily steal unmovable or
	 * reclaimable pages that are closest to the request size. After a
	 * while, memory compaction may occur to form large contiguous pages,
	 * and the next movable allocation may not need to steal.
	 */
	return false;
}

/*
 * Check whether there is a suitable fallback freepage with requested order.
 * If claimable is true, this function returns fallback_mt only if
 * we would do this whole-block claiming. This would help to reduce
 * fragmentation due to mixed migratetype pages in one pageblock.
 */
int find_suitable_fallback(struct free_area *area, unsigned int order,
			   int migratetype, bool claimable)
{
	int i;

	if (claimable && !should_try_claim_block(order, migratetype))
		return -2;

	if (area->nr_free == 0)
		return -1;

	for (i = 0; i < MIGRATE_PCPTYPES - 1 ; i++) {
		int fallback_mt = fallbacks[migratetype][i];

		if (!free_area_empty(area, fallback_mt))
			return fallback_mt;
	}

	return -1;
}

/*
 * This function implements actual block claiming behaviour. If order is large
 * enough, we can claim the whole pageblock for the requested migratetype. If
 * not, we check the pageblock for constituent pages; if at least half of the
 * pages are free or compatible, we can still claim the whole block, so pages
 * freed in the future will be put on the correct free list.
 */
static struct page *
try_to_claim_block(struct zone *zone, struct page *page,
		   int current_order, int order, int start_type,
		   int block_type, unsigned int alloc_flags)
{
	int free_pages, movable_pages, alike_pages;
	unsigned long start_pfn;

	/* Take ownership for orders >= pageblock_order */
	if (current_order >= pageblock_order) {
		unsigned int nr_added;

		del_page_from_free_list(page, zone, current_order, block_type);
		change_pageblock_range(page, current_order, start_type);
		nr_added = expand(zone, page, order, current_order, start_type);
		account_freepages(zone, nr_added, start_type);
		return page;
	}

	/*
	 * Boost watermarks to increase reclaim pressure to reduce the
	 * likelihood of future fallbacks. Wake kswapd now as the node
	 * may be balanced overall and kswapd will not wake naturally.
	 */
	if (boost_watermark(zone) && (alloc_flags & ALLOC_KSWAPD))
		set_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);

	/* moving whole block can fail due to zone boundary conditions */
	if (!prep_move_freepages_block(zone, page, &start_pfn, &free_pages,
				       &movable_pages))
		return NULL;

	/*
	 * Determine how many pages are compatible with our allocation.
	 * For movable allocation, it's the number of movable pages which
	 * we just obtained. For other types it's a bit more tricky.
	 */
	if (start_type == MIGRATE_MOVABLE) {
		alike_pages = movable_pages;
	} else {
		/*
		 * If we are falling back a RECLAIMABLE or UNMOVABLE allocation
		 * to MOVABLE pageblock, consider all non-movable pages as
		 * compatible. If it's UNMOVABLE falling back to RECLAIMABLE or
		 * vice versa, be conservative since we can't distinguish the
		 * exact migratetype of non-movable pages.
		 */
		if (block_type == MIGRATE_MOVABLE)
			alike_pages = pageblock_nr_pages
						- (free_pages + movable_pages);
		else
			alike_pages = 0;
	}
	/*
	 * If a sufficient number of pages in the block are either free or of
	 * compatible migratability as our allocation, claim the whole block.
	 */
	if (free_pages + alike_pages >= (1 << (pageblock_order-1)) ||
			page_group_by_mobility_disabled) {
		__move_freepages_block(zone, start_pfn, block_type, start_type);
		set_pageblock_migratetype(pfn_to_page(start_pfn), start_type);
		return __rmqueue_smallest(zone, order, start_type);
	}

	return NULL;
}

/*
 * Try to allocate from some fallback migratetype by claiming the entire block,
 * i.e. converting it to the allocation's start migratetype.
 *
 * The use of signed ints for order and current_order is a deliberate
 * deviation from the rest of this file, to make the for loop
 * condition simpler.
 */
static __always_inline struct page *
__rmqueue_claim(struct zone *zone, int order, int start_migratetype,
						unsigned int alloc_flags)
{
	struct free_area *area;
	int current_order;
	int min_order = order;
	struct page *page;
	int fallback_mt;

	/*
	 * Do not steal pages from freelists belonging to other pageblocks
	 * i.e. orders < pageblock_order. If there are no local zones free,
	 * the zonelists will be reiterated without ALLOC_NOFRAGMENT.
	 */
	if (order < pageblock_order && alloc_flags & ALLOC_NOFRAGMENT)
		min_order = pageblock_order;

	/*
	 * Find the largest available free page in the other list. This roughly
	 * approximates finding the pageblock with the most free pages, which
	 * would be too costly to do exactly.
	 */
	for (current_order = MAX_PAGE_ORDER; current_order >= min_order;
				--current_order) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
						     start_migratetype, true);

		/* No block in that order */
		if (fallback_mt == -1)
			continue;

		/* Advanced into orders too low to claim, abort */
		if (fallback_mt == -2)
			break;

		page = get_page_from_free_area(area, fallback_mt);
		page = try_to_claim_block(zone, page, current_order, order,
					  start_migratetype, fallback_mt,
					  alloc_flags);
		if (page) {
			trace_mm_page_alloc_extfrag(page, order, current_order,
						    start_migratetype, fallback_mt);
			return page;
		}
	}

	return NULL;
}

/*
 * Try to steal a single page from some fallback migratetype. Leave the rest of
 * the block as its current migratetype, potentially causing fragmentation.
 */
static __always_inline struct page *
__rmqueue_steal(struct zone *zone, int order, int start_migratetype)
{
	struct free_area *area;
	int current_order;
	struct page *page;
	int fallback_mt;

	for (current_order = order; current_order < NR_PAGE_ORDERS; current_order++) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
						     start_migratetype, false);
		if (fallback_mt == -1)
			continue;

		page = get_page_from_free_area(area, fallback_mt);
		page_del_and_expand(zone, page, order, current_order, fallback_mt);
		trace_mm_page_alloc_extfrag(page, order, current_order,
					    start_migratetype, fallback_mt);
		return page;
	}

	return NULL;
}

enum rmqueue_mode {
	RMQUEUE_NORMAL,
	RMQUEUE_CMA,
	RMQUEUE_CLAIM,
	RMQUEUE_STEAL,
};

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static __always_inline struct page *
__rmqueue(struct zone *zone, unsigned int order, int migratetype,
	  unsigned int alloc_flags, enum rmqueue_mode *mode)
{
	struct page *page;

	if (IS_ENABLED(CONFIG_CMA)) {
		/*
		 * Balance movable allocations between regular and CMA areas by
		 * allocating from CMA when over half of the zone's free memory
		 * is in the CMA area.
		 */
		if (alloc_flags & ALLOC_CMA &&
		    zone_page_state(zone, NR_FREE_CMA_PAGES) >
		    zone_page_state(zone, NR_FREE_PAGES) / 2) {
			page = __rmqueue_cma_fallback(zone, order);
			if (page)
				return page;
		}
	}

	/*
	 * First try the freelists of the requested migratetype, then try
	 * fallbacks modes with increasing levels of fragmentation risk.
	 *
	 * The fallback logic is expensive and rmqueue_bulk() calls in
	 * a loop with the zone->lock held, meaning the freelists are
	 * not subject to any outside changes. Remember in *mode where
	 * we found pay dirt, to save us the search on the next call.
	 */
	switch (*mode) {
	case RMQUEUE_NORMAL:
		page = __rmqueue_smallest(zone, order, migratetype);
		if (page)
			return page;
		fallthrough;
	case RMQUEUE_CMA:
		if (alloc_flags & ALLOC_CMA) {
			page = __rmqueue_cma_fallback(zone, order);
			if (page) {
				*mode = RMQUEUE_CMA;
				return page;
			}
		}
		fallthrough;
	case RMQUEUE_CLAIM:
		page = __rmqueue_claim(zone, order, migratetype, alloc_flags);
		if (page) {
			/* Replenished preferred freelist, back to normal mode. */
			*mode = RMQUEUE_NORMAL;
			return page;
		}
		fallthrough;
	case RMQUEUE_STEAL:
		if (!(alloc_flags & ALLOC_NOFRAGMENT)) {
			page = __rmqueue_steal(zone, order, migratetype);
			if (page) {
				*mode = RMQUEUE_STEAL;
				return page;
			}
		}
	}
	return NULL;
}

/*
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int rmqueue_bulk(struct zone *zone, unsigned int order,
			unsigned long count, struct list_head *list,
			int migratetype, unsigned int alloc_flags)
{
	enum rmqueue_mode rmqm = RMQUEUE_NORMAL;
	unsigned long flags;
	int i;

	if (unlikely(alloc_flags & ALLOC_TRYLOCK)) {
		if (!spin_trylock_irqsave(&zone->lock, flags))
			return 0;
	} else {
		spin_lock_irqsave(&zone->lock, flags);
	}
	for (i = 0; i < count; ++i) {
		struct page *page = __rmqueue(zone, order, migratetype,
					      alloc_flags, &rmqm);
		if (unlikely(page == NULL))
			break;

		/*
		 * Split buddy pages returned by expand() are received here in
		 * physical page order. The page is added to the tail of
		 * caller's list. From the callers perspective, the linked list
		 * is ordered by page number under some conditions. This is
		 * useful for IO devices that can forward direction from the
		 * head, thus also in the physical page order. This is useful
		 * for IO devices that can merge IO requests if the physical
		 * pages are ordered properly.
		 */
		list_add_tail(&page->pcp_list, list);
	}
	spin_unlock_irqrestore(&zone->lock, flags);

	return i;
}

/*
 * Called from the vmstat counter updater to decay the PCP high.
 * Return whether there are addition works to do.
 */
int decay_pcp_high(struct zone *zone, struct per_cpu_pages *pcp)
{
	int high_min, to_drain, batch;
	int todo = 0;

	high_min = READ_ONCE(pcp->high_min);
	batch = READ_ONCE(pcp->batch);
	/*
	 * Decrease pcp->high periodically to try to free possible
	 * idle PCP pages.  And, avoid to free too many pages to
	 * control latency.  This caps pcp->high decrement too.
	 */
	if (pcp->high > high_min) {
		pcp->high = max3(pcp->count - (batch << CONFIG_PCP_BATCH_SCALE_MAX),
				 pcp->high - (pcp->high >> 3), high_min);
		if (pcp->high > high_min)
			todo++;
	}

	to_drain = pcp->count - pcp->high;
	if (to_drain > 0) {
		spin_lock(&pcp->lock);
		free_pcppages_bulk(zone, to_drain, pcp, 0);
		spin_unlock(&pcp->lock);
		todo++;
	}

	return todo;
}

#ifdef CONFIG_NUMA
/*
 * Called from the vmstat counter updater to drain pagesets of this
 * currently executing processor on remote nodes after they have
 * expired.
 */
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp)
{
	int to_drain, batch;

	batch = READ_ONCE(pcp->batch);
	to_drain = min(pcp->count, batch);
	if (to_drain > 0) {
		spin_lock(&pcp->lock);
		free_pcppages_bulk(zone, to_drain, pcp, 0);
		spin_unlock(&pcp->lock);
	}
}
#endif

/*
 * Drain pcplists of the indicated processor and zone.
 */
static void drain_pages_zone(unsigned int cpu, struct zone *zone)
{
	struct per_cpu_pages *pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
	int count;

	do {
		spin_lock(&pcp->lock);
		count = pcp->count;
		if (count) {
			int to_drain = min(count,
				pcp->batch << CONFIG_PCP_BATCH_SCALE_MAX);

			free_pcppages_bulk(zone, to_drain, pcp, 0);
			count -= to_drain;
		}
		spin_unlock(&pcp->lock);
	} while (count);
}

/*
 * Drain pcplists of all zones on the indicated processor.
 */
static void drain_pages(unsigned int cpu)
{
	struct zone *zone;

	for_each_populated_zone(zone) {
		drain_pages_zone(cpu, zone);
	}
}

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 */
void drain_local_pages(struct zone *zone)
{
	int cpu = smp_processor_id();

	if (zone)
		drain_pages_zone(cpu, zone);
	else
		drain_pages(cpu);
}

/*
 * The implementation of drain_all_pages(), exposing an extra parameter to
 * drain on all cpus.
 *
 * drain_all_pages() is optimized to only execute on cpus where pcplists are
 * not empty. The check for non-emptiness can however race with a free to
 * pcplist that has not yet increased the pcp->count from 0 to 1. Callers
 * that need the guarantee that every CPU has drained can disable the
 * optimizing racy check.
 */
static void __drain_all_pages(struct zone *zone, bool force_all_cpus)
{
	int cpu;

	/*
	 * Allocate in the BSS so we won't require allocation in
	 * direct reclaim path for CONFIG_CPUMASK_OFFSTACK=y
	 */
	static cpumask_t cpus_with_pcps;

	/*
	 * Do not drain if one is already in progress unless it's specific to
	 * a zone. Such callers are primarily CMA and memory hotplug and need
	 * the drain to be complete when the call returns.
	 */
	if (unlikely(!mutex_trylock(&pcpu_drain_mutex))) {
		if (!zone)
			return;
		mutex_lock(&pcpu_drain_mutex);
	}

	/*
	 * We don't care about racing with CPU hotplug event
	 * as offline notification will cause the notified
	 * cpu to drain that CPU pcps and on_each_cpu_mask
	 * disables preemption as part of its processing
	 */
	for_each_online_cpu(cpu) {
		struct per_cpu_pages *pcp;
		struct zone *z;
		bool has_pcps = false;

		if (force_all_cpus) {
			/*
			 * The pcp.count check is racy, some callers need a
			 * guarantee that no cpu is missed.
			 */
			has_pcps = true;
		} else if (zone) {
			pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
			if (pcp->count)
				has_pcps = true;
		} else {
			for_each_populated_zone(z) {
				pcp = per_cpu_ptr(z->per_cpu_pageset, cpu);
				if (pcp->count) {
					has_pcps = true;
					break;
				}
			}
		}

		if (has_pcps)
			cpumask_set_cpu(cpu, &cpus_with_pcps);
		else
			cpumask_clear_cpu(cpu, &cpus_with_pcps);
	}

	for_each_cpu(cpu, &cpus_with_pcps) {
		if (zone)
			drain_pages_zone(cpu, zone);
		else
			drain_pages(cpu);
	}

	mutex_unlock(&pcpu_drain_mutex);
}

/*
 * Spill all the per-cpu pages from all CPUs back into the buddy allocator.
 *
 * When zone parameter is non-NULL, spill just the single zone's pages.
 */
void drain_all_pages(struct zone *zone)
{
	__drain_all_pages(zone, false);
}

static int nr_pcp_free(struct per_cpu_pages *pcp, int batch, int high, bool free_high)
{
	int min_nr_free, max_nr_free;

	/* Free as much as possible if batch freeing high-order pages. */
	if (unlikely(free_high))
		return min(pcp->count, batch << CONFIG_PCP_BATCH_SCALE_MAX);

	/* Check for PCP disabled or boot pageset */
	if (unlikely(high < batch))
		return 1;

	/* Leave at least pcp->batch pages on the list */
	min_nr_free = batch;
	max_nr_free = high - batch;

	/*
	 * Increase the batch number to the number of the consecutive
	 * freed pages to reduce zone lock contention.
	 */
	batch = clamp_t(int, pcp->free_count, min_nr_free, max_nr_free);

	return batch;
}

static int nr_pcp_high(struct per_cpu_pages *pcp, struct zone *zone,
		       int batch, bool free_high)
{
	int high, high_min, high_max;

	high_min = READ_ONCE(pcp->high_min);
	high_max = READ_ONCE(pcp->high_max);
	high = pcp->high = clamp(pcp->high, high_min, high_max);

	if (unlikely(!high))
		return 0;

	if (unlikely(free_high)) {
		pcp->high = max(high - (batch << CONFIG_PCP_BATCH_SCALE_MAX),
				high_min);
		return 0;
	}

	/*
	 * If reclaim is active, limit the number of pages that can be
	 * stored on pcp lists
	 */
	if (test_bit(ZONE_RECLAIM_ACTIVE, &zone->flags)) {
		int free_count = max_t(int, pcp->free_count, batch);

		pcp->high = max(high - free_count, high_min);
		return min(batch << 2, pcp->high);
	}

	if (high_min == high_max)
		return high;

	if (test_bit(ZONE_BELOW_HIGH, &zone->flags)) {
		int free_count = max_t(int, pcp->free_count, batch);

		pcp->high = max(high - free_count, high_min);
		high = max(pcp->count, high_min);
	} else if (pcp->count >= high) {
		int need_high = pcp->free_count + batch;

		/* pcp->high should be large enough to hold batch freed pages */
		if (pcp->high < need_high)
			pcp->high = clamp(need_high, high_min, high_max);
	}

	return high;
}

static void free_frozen_page_commit(struct zone *zone,
		struct per_cpu_pages *pcp, struct page *page, int migratetype,
		unsigned int order, fpi_t fpi_flags)
{
	int high, batch;
	int pindex;
	bool free_high = false;

	/*
	 * On freeing, reduce the number of pages that are batch allocated.
	 * See nr_pcp_alloc() where alloc_factor is increased for subsequent
	 * allocations.
	 */
	pcp->alloc_factor >>= 1;
	__count_vm_events(PGFREE, 1 << order);
	pindex = order_to_pindex(migratetype, order);
	list_add(&page->pcp_list, &pcp->lists[pindex]);
	pcp->count += 1 << order;

	batch = READ_ONCE(pcp->batch);
	/*
	 * As high-order pages other than THP's stored on PCP can contribute
	 * to fragmentation, limit the number stored when PCP is heavily
	 * freeing without allocation. The remainder after bulk freeing
	 * stops will be drained from vmstat refresh context.
	 */
	if (order && order <= PAGE_ALLOC_COSTLY_ORDER) {
		free_high = (pcp->free_count >= (batch + pcp->high_min / 2) &&
			     (pcp->flags & PCPF_PREV_FREE_HIGH_ORDER) &&
			     (!(pcp->flags & PCPF_FREE_HIGH_BATCH) ||
			      pcp->count >= batch));
		pcp->flags |= PCPF_PREV_FREE_HIGH_ORDER;
	} else if (pcp->flags & PCPF_PREV_FREE_HIGH_ORDER) {
		pcp->flags &= ~PCPF_PREV_FREE_HIGH_ORDER;
	}
	if (pcp->free_count < (batch << CONFIG_PCP_BATCH_SCALE_MAX))
		pcp->free_count += (1 << order);

	if (unlikely(fpi_flags & FPI_TRYLOCK)) {
		/*
		 * Do not attempt to take a zone lock. Let pcp->count get
		 * over high mark temporarily.
		 */
		return;
	}
	high = nr_pcp_high(pcp, zone, batch, free_high);
	if (pcp->count >= high) {
		free_pcppages_bulk(zone, nr_pcp_free(pcp, batch, high, free_high),
				   pcp, pindex);
		if (test_bit(ZONE_BELOW_HIGH, &zone->flags) &&
		    zone_watermark_ok(zone, 0, high_wmark_pages(zone),
				      ZONE_MOVABLE, 0))
			clear_bit(ZONE_BELOW_HIGH, &zone->flags);
	}
}

/*
 * Free a pcp page
 */
static void __free_frozen_pages(struct page *page, unsigned int order,
				fpi_t fpi_flags)
{
	unsigned long __maybe_unused UP_flags;
	struct per_cpu_pages *pcp;
	struct zone *zone;
	unsigned long pfn = page_to_pfn(page);
	int migratetype;

	if (!pcp_allowed_order(order)) {
		__free_pages_ok(page, order, fpi_flags);
		return;
	}

	if (!free_pages_prepare(page, order))
		return;

	/*
	 * We only track unmovable, reclaimable and movable on pcp lists.
	 * Place ISOLATE pages on the isolated list because they are being
	 * offlined but treat HIGHATOMIC and CMA as movable pages so we can
	 * get those areas back if necessary. Otherwise, we may have to free
	 * excessively into the page allocator
	 */
	zone = page_zone(page);
	migratetype = get_pfnblock_migratetype(page, pfn);
	if (unlikely(migratetype >= MIGRATE_PCPTYPES)) {
		if (unlikely(is_migrate_isolate(migratetype))) {
			free_one_page(zone, page, pfn, order, fpi_flags);
			return;
		}
		migratetype = MIGRATE_MOVABLE;
	}

	if (unlikely((fpi_flags & FPI_TRYLOCK) && IS_ENABLED(CONFIG_PREEMPT_RT)
		     && (in_nmi() || in_hardirq()))) {
		add_page_to_zone_llist(zone, page, order);
		return;
	}
	pcp_trylock_prepare(UP_flags);
	pcp = pcp_spin_trylock(zone->per_cpu_pageset);
	if (pcp) {
		free_frozen_page_commit(zone, pcp, page, migratetype, order, fpi_flags);
		pcp_spin_unlock(pcp);
	} else {
		free_one_page(zone, page, pfn, order, fpi_flags);
	}
	pcp_trylock_finish(UP_flags);
}

void free_frozen_pages(struct page *page, unsigned int order)
{
	__free_frozen_pages(page, order, FPI_NONE);
}

/*
 * Free a batch of folios
 */
void free_unref_folios(struct folio_batch *folios)
{
	unsigned long __maybe_unused UP_flags;
	struct per_cpu_pages *pcp = NULL;
	struct zone *locked_zone = NULL;
	int i, j;

	/* Prepare folios for freeing */
	for (i = 0, j = 0; i < folios->nr; i++) {
		struct folio *folio = folios->folios[i];
		unsigned long pfn = folio_pfn(folio);
		unsigned int order = folio_order(folio);

		if (!free_pages_prepare(&folio->page, order))
			continue;
		/*
		 * Free orders not handled on the PCP directly to the
		 * allocator.
		 */
		if (!pcp_allowed_order(order)) {
			free_one_page(folio_zone(folio), &folio->page,
				      pfn, order, FPI_NONE);
			continue;
		}
		folio->private = (void *)(unsigned long)order;
		if (j != i)
			folios->folios[j] = folio;
		j++;
	}
	folios->nr = j;

	for (i = 0; i < folios->nr; i++) {
		struct folio *folio = folios->folios[i];
		struct zone *zone = folio_zone(folio);
		unsigned long pfn = folio_pfn(folio);
		unsigned int order = (unsigned long)folio->private;
		int migratetype;

		folio->private = NULL;
		migratetype = get_pfnblock_migratetype(&folio->page, pfn);

		/* Different zone requires a different pcp lock */
		if (zone != locked_zone ||
		    is_migrate_isolate(migratetype)) {
			if (pcp) {
				pcp_spin_unlock(pcp);
				pcp_trylock_finish(UP_flags);
				locked_zone = NULL;
				pcp = NULL;
			}

			/*
			 * Free isolated pages directly to the
			 * allocator, see comment in free_frozen_pages.
			 */
			if (is_migrate_isolate(migratetype)) {
				free_one_page(zone, &folio->page, pfn,
					      order, FPI_NONE);
				continue;
			}

			/*
			 * trylock is necessary as folios may be getting freed
			 * from IRQ or SoftIRQ context after an IO completion.
			 */
			pcp_trylock_prepare(UP_flags);
			pcp = pcp_spin_trylock(zone->per_cpu_pageset);
			if (unlikely(!pcp)) {
				pcp_trylock_finish(UP_flags);
				free_one_page(zone, &folio->page, pfn,
					      order, FPI_NONE);
				continue;
			}
			locked_zone = zone;
		}

		/*
		 * Non-isolated types over MIGRATE_PCPTYPES get added
		 * to the MIGRATE_MOVABLE pcp list.
		 */
		if (unlikely(migratetype >= MIGRATE_PCPTYPES))
			migratetype = MIGRATE_MOVABLE;

		trace_mm_page_free_batched(&folio->page);
		free_frozen_page_commit(zone, pcp, &folio->page, migratetype,
					order, FPI_NONE);
	}

	if (pcp) {
		pcp_spin_unlock(pcp);
		pcp_trylock_finish(UP_flags);
	}
	folio_batch_reinit(folios);
}

/*
 * split_page takes a non-compound higher-order page, and splits it into
 * n (1<<order) sub-pages: page[0..n]
 * Each sub-page must be freed individually.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
void split_page(struct page *page, unsigned int order)
{
	int i;

	VM_BUG_ON_PAGE(PageCompound(page), page);
	VM_BUG_ON_PAGE(!page_count(page), page);

	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
	split_page_owner(page, order, 0);
	pgalloc_tag_split(page_folio(page), order, 0);
	split_page_memcg(page, order);
}
EXPORT_SYMBOL_GPL(split_page);

int __isolate_free_page(struct page *page, unsigned int order)
{
	struct zone *zone = page_zone(page);
	int mt = get_pageblock_migratetype(page);

	if (!is_migrate_isolate(mt)) {
		unsigned long watermark;
		/*
		 * Obey watermarks as if the page was being allocated. We can
		 * emulate a high-order watermark check with a raised order-0
		 * watermark, because we already know our high-order page
		 * exists.
		 */
		watermark = zone->_watermark[WMARK_MIN] + (1UL << order);
		if (!zone_watermark_ok(zone, 0, watermark, 0, ALLOC_CMA))
			return 0;
	}

	del_page_from_free_list(page, zone, order, mt);

	/*
	 * Set the pageblock if the isolated page is at least half of a
	 * pageblock
	 */
	if (order >= pageblock_order - 1) {
		struct page *endpage = page + (1 << order) - 1;
		for (; page < endpage; page += pageblock_nr_pages) {
			int mt = get_pageblock_migratetype(page);
			/*
			 * Only change normal pageblocks (i.e., they can merge
			 * with others)
			 */
			if (migratetype_is_mergeable(mt))
				move_freepages_block(zone, page, mt,
						     MIGRATE_MOVABLE);
		}
	}

	return 1UL << order;
}

/**
 * __putback_isolated_page - Return a now-isolated page back where we got it
 * @page: Page that was isolated
 * @order: Order of the isolated page
 * @mt: The page's pageblock's migratetype
 *
 * This function is meant to return a page pulled from the free lists via
 * __isolate_free_page back to the free lists they were pulled from.
 */
void __putback_isolated_page(struct page *page, unsigned int order, int mt)
{
	struct zone *zone = page_zone(page);

	/* zone lock should be held when this function is called */
	lockdep_assert_held(&zone->lock);

	/* Return isolated page to tail of freelist. */
	__free_one_page(page, page_to_pfn(page), zone, order, mt,
			FPI_SKIP_REPORT_NOTIFY | FPI_TO_TAIL);
}

/*
 * Update NUMA hit/miss statistics
 */
static inline void zone_statistics(struct zone *preferred_zone, struct zone *z,
				   long nr_account)
{
#ifdef CONFIG_NUMA
	enum numa_stat_item local_stat = NUMA_LOCAL;

	/* skip numa counters update if numa stats is disabled */
	if (!static_branch_likely(&vm_numa_stat_key))
		return;

	if (zone_to_nid(z) != numa_node_id())
		local_stat = NUMA_OTHER;

	if (zone_to_nid(z) == zone_to_nid(preferred_zone))
		__count_numa_events(z, NUMA_HIT, nr_account);
	else {
		__count_numa_events(z, NUMA_MISS, nr_account);
		__count_numa_events(preferred_zone, NUMA_FOREIGN, nr_account);
	}
	__count_numa_events(z, local_stat, nr_account);
#endif
}

static __always_inline
struct page *rmqueue_buddy(struct zone *preferred_zone, struct zone *zone,
			   unsigned int order, unsigned int alloc_flags,
			   int migratetype)
{
	struct page *page;
	unsigned long flags;

	do {
		page = NULL;
		if (unlikely(alloc_flags & ALLOC_TRYLOCK)) {
			if (!spin_trylock_irqsave(&zone->lock, flags))
				return NULL;
		} else {
			spin_lock_irqsave(&zone->lock, flags);
		}
		if (alloc_flags & ALLOC_HIGHATOMIC)
			page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);
		if (!page) {
			enum rmqueue_mode rmqm = RMQUEUE_NORMAL;

			page = __rmqueue(zone, order, migratetype, alloc_flags, &rmqm);

			/*
			 * If the allocation fails, allow OOM handling and
			 * order-0 (atomic) allocs access to HIGHATOMIC
			 * reserves as failing now is worse than failing a
			 * high-order atomic allocation in the future.
			 */
			if (!page && (alloc_flags & (ALLOC_OOM|ALLOC_NON_BLOCK)))
				page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);

			if (!page) {
				spin_unlock_irqrestore(&zone->lock, flags);
				return NULL;
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	} while (check_new_pages(page, order));

	__count_zid_vm_events(PGALLOC, page_zonenum(page), 1 << order);
	zone_statistics(preferred_zone, zone, 1);

	return page;
}

static int nr_pcp_alloc(struct per_cpu_pages *pcp, struct zone *zone, int order)
{
	int high, base_batch, batch, max_nr_alloc;
	int high_max, high_min;

	base_batch = READ_ONCE(pcp->batch);
	high_min = READ_ONCE(pcp->high_min);
	high_max = READ_ONCE(pcp->high_max);
	high = pcp->high = clamp(pcp->high, high_min, high_max);

	/* Check for PCP disabled or boot pageset */
	if (unlikely(high < base_batch))
		return 1;

	if (order)
		batch = base_batch;
	else
		batch = (base_batch << pcp->alloc_factor);

	/*
	 * If we had larger pcp->high, we could avoid to allocate from
	 * zone.
	 */
	if (high_min != high_max && !test_bit(ZONE_BELOW_HIGH, &zone->flags))
		high = pcp->high = min(high + batch, high_max);

	if (!order) {
		max_nr_alloc = max(high - pcp->count - base_batch, base_batch);
		/*
		 * Double the number of pages allocated each time there is
		 * subsequent allocation of order-0 pages without any freeing.
		 */
		if (batch <= max_nr_alloc &&
		    pcp->alloc_factor < CONFIG_PCP_BATCH_SCALE_MAX)
			pcp->alloc_factor++;
		batch = min(batch, max_nr_alloc);
	}

	/*
	 * Scale batch relative to order if batch implies free pages
	 * can be stored on the PCP. Batch can be 1 for small zones or
	 * for boot pagesets which should never store free pages as
	 * the pages may belong to arbitrary zones.
	 */
	if (batch > 1)
		batch = max(batch >> order, 2);

	return batch;
}

/* Remove page from the per-cpu list, caller must protect the list */
static inline
struct page *__rmqueue_pcplist(struct zone *zone, unsigned int order,
			int migratetype,
			unsigned int alloc_flags,
			struct per_cpu_pages *pcp,
			struct list_head *list)
{
	struct page *page;

	do {
		if (list_empty(list)) {
			int batch = nr_pcp_alloc(pcp, zone, order);
			int alloced;

			alloced = rmqueue_bulk(zone, order,
					batch, list,
					migratetype, alloc_flags);

			pcp->count += alloced << order;
			if (unlikely(list_empty(list)))
				return NULL;
		}

		page = list_first_entry(list, struct page, pcp_list);
		list_del(&page->pcp_list);
		pcp->count -= 1 << order;
	} while (check_new_pages(page, order));

	return page;
}

/* Lock and remove page from the per-cpu list */
static struct page *rmqueue_pcplist(struct zone *preferred_zone,
			struct zone *zone, unsigned int order,
			int migratetype, unsigned int alloc_flags)
{
	struct per_cpu_pages *pcp;
	struct list_head *list;
	struct page *page;
	unsigned long __maybe_unused UP_flags;

	/* spin_trylock may fail due to a parallel drain or IRQ reentrancy. */
	pcp_trylock_prepare(UP_flags);
	pcp = pcp_spin_trylock(zone->per_cpu_pageset);
	if (!pcp) {
		pcp_trylock_finish(UP_flags);
		return NULL;
	}

	/*
	 * On allocation, reduce the number of pages that are batch freed.
	 * See nr_pcp_free() where free_factor is increased for subsequent
	 * frees.
	 */
	pcp->free_count >>= 1;
	list = &pcp->lists[order_to_pindex(migratetype, order)];
	page = __rmqueue_pcplist(zone, order, migratetype, alloc_flags, pcp, list);
	pcp_spin_unlock(pcp);
	pcp_trylock_finish(UP_flags);
	if (page) {
		__count_zid_vm_events(PGALLOC, page_zonenum(page), 1 << order);
		zone_statistics(preferred_zone, zone, 1);
	}
	return page;
}

/*
 * Allocate a page from the given zone.
 * Use pcplists for THP or "cheap" high-order allocations.
 */

/*
 * Do not instrument rmqueue() with KMSAN. This function may call
 * __msan_poison_alloca() through a call to set_pfnblock_migratetype().
 * If __msan_poison_alloca() attempts to allocate pages for the stack depot, it
 * may call rmqueue() again, which will result in a deadlock.
 */
__no_sanitize_memory
static inline
struct page *rmqueue(struct zone *preferred_zone,
			struct zone *zone, unsigned int order,
			gfp_t gfp_flags, unsigned int alloc_flags,
			int migratetype)
{
	struct page *page;

	if (likely(pcp_allowed_order(order))) {
		page = rmqueue_pcplist(preferred_zone, zone, order,
				       migratetype, alloc_flags);
		if (likely(page))
			goto out;
	}

	page = rmqueue_buddy(preferred_zone, zone, order, alloc_flags,
							migratetype);

out:
	/* Separate test+clear to avoid unnecessary atomics */
	if ((alloc_flags & ALLOC_KSWAPD) &&
	    unlikely(test_bit(ZONE_BOOSTED_WATERMARK, &zone->flags))) {
		clear_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);
		wakeup_kswapd(zone, 0, 0, zone_idx(zone));
	}

	VM_BUG_ON_PAGE(page && bad_range(zone, page), page);
	return page;
}

/*
 * Reserve the pageblock(s) surrounding an allocation request for
 * exclusive use of high-order atomic allocations if there are no
 * empty page blocks that contain a page with a suitable order
 */
static void reserve_highatomic_pageblock(struct page *page, int order,
					 struct zone *zone)
{
	int mt;
	unsigned long max_managed, flags;

	/*
	 * The number reserved as: minimum is 1 pageblock, maximum is
	 * roughly 1% of a zone. But if 1% of a zone falls below a
	 * pageblock size, then don't reserve any pageblocks.
	 * Check is race-prone but harmless.
	 */
	if ((zone_managed_pages(zone) / 100) < pageblock_nr_pages)
		return;
	max_managed = ALIGN((zone_managed_pages(zone) / 100), pageblock_nr_pages);
	if (zone->nr_reserved_highatomic >= max_managed)
		return;

	spin_lock_irqsave(&zone->lock, flags);

	/* Recheck the nr_reserved_highatomic limit under the lock */
	if (zone->nr_reserved_highatomic >= max_managed)
		goto out_unlock;

	/* Yoink! */
	mt = get_pageblock_migratetype(page);
	/* Only reserve normal pageblocks (i.e., they can merge with others) */
	if (!migratetype_is_mergeable(mt))
		goto out_unlock;

	if (order < pageblock_order) {
		if (move_freepages_block(zone, page, mt, MIGRATE_HIGHATOMIC) == -1)
			goto out_unlock;
		zone->nr_reserved_highatomic += pageblock_nr_pages;
	} else {
		change_pageblock_range(page, order, MIGRATE_HIGHATOMIC);
		zone->nr_reserved_highatomic += 1 << order;
	}

out_unlock:
	spin_unlock_irqrestore(&zone->lock, flags);
}

/*
 * Used when an allocation is about to fail under memory pressure. This
 * potentially hurts the reliability of high-order allocations when under
 * intense memory pressure but failed atomic allocations should be easier
 * to recover from than an OOM.
 *
 * If @force is true, try to unreserve pageblocks even though highatomic
 * pageblock is exhausted.
 */
static bool unreserve_highatomic_pageblock(const struct alloc_context *ac,
						bool force)
{
	struct zonelist *zonelist = ac->zonelist;
	unsigned long flags;
	struct zoneref *z;
	struct zone *zone;
	struct page *page;
	int order;
	int ret;

	for_each_zone_zonelist_nodemask(zone, z, zonelist, ac->highest_zoneidx,
								ac->nodemask) {
		/*
		 * Preserve at least one pageblock unless memory pressure
		 * is really high.
		 */
		if (!force && zone->nr_reserved_highatomic <=
					pageblock_nr_pages)
			continue;

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < NR_PAGE_ORDERS; order++) {
			struct free_area *area = &(zone->free_area[order]);
			unsigned long size;

			page = get_page_from_free_area(area, MIGRATE_HIGHATOMIC);
			if (!page)
				continue;

			size = max(pageblock_nr_pages, 1UL << order);
			/*
			 * It should never happen but changes to
			 * locking could inadvertently allow a per-cpu
			 * drain to add pages to MIGRATE_HIGHATOMIC
			 * while unreserving so be safe and watch for
			 * underflows.
			 */
			if (WARN_ON_ONCE(size > zone->nr_reserved_highatomic))
				size = zone->nr_reserved_highatomic;
			zone->nr_reserved_highatomic -= size;

			/*
			 * Convert to ac->migratetype and avoid the normal
			 * pageblock stealing heuristics. Minimally, the caller
			 * is doing the work and needs the pages. More
			 * importantly, if the block was always converted to
			 * MIGRATE_UNMOVABLE or another type then the number
			 * of pageblocks that cannot be completely freed
			 * may increase.
			 */
			if (order < pageblock_order)
				ret = move_freepages_block(zone, page,
							   MIGRATE_HIGHATOMIC,
							   ac->migratetype);
			else {
				move_to_free_list(page, zone, order,
						  MIGRATE_HIGHATOMIC,
						  ac->migratetype);
				change_pageblock_range(page, order,
						       ac->migratetype);
				ret = 1;
			}
			/*
			 * Reserving the block(s) already succeeded,
			 * so this should not fail on zone boundaries.
			 */
			WARN_ON_ONCE(ret == -1);
			if (ret > 0) {
				spin_unlock_irqrestore(&zone->lock, flags);
				return ret;
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	}

	return false;
}

static inline long __zone_watermark_unusable_free(struct zone *z,
				unsigned int order, unsigned int alloc_flags)
{
	long unusable_free = (1 << order) - 1;

	/*
	 * If the caller does not have rights to reserves below the min
	 * watermark then subtract the free pages reserved for highatomic.
	 */
	if (likely(!(alloc_flags & ALLOC_RESERVES)))
		unusable_free += READ_ONCE(z->nr_free_highatomic);

#ifdef CONFIG_CMA
	/* If allocation can't use CMA areas don't use free CMA pages */
	if (!(alloc_flags & ALLOC_CMA))
		unusable_free += zone_page_state(z, NR_FREE_CMA_PAGES);
#endif

	return unusable_free;
}

/*
 * Return true if free base pages are above 'mark'. For high-order checks it
 * will return true of the order-0 watermark is reached and there is at least
 * one free page of a suitable size. Checking now avoids taking the zone lock
 * to check in the allocation paths if no pages are free.
 */
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int highest_zoneidx, unsigned int alloc_flags,
			 long free_pages)
{
	long min = mark;
	int o;

	/* free_pages may go negative - that's OK */
	free_pages -= __zone_watermark_unusable_free(z, order, alloc_flags);

	if (unlikely(alloc_flags & ALLOC_RESERVES)) {
		/*
		 * __GFP_HIGH allows access to 50% of the min reserve as well
		 * as OOM.
		 */
		if (alloc_flags & ALLOC_MIN_RESERVE) {
			min -= min / 2;

			/*
			 * Non-blocking allocations (e.g. GFP_ATOMIC) can
			 * access more reserves than just __GFP_HIGH. Other
			 * non-blocking allocations requests such as GFP_NOWAIT
			 * or (GFP_KERNEL & ~__GFP_DIRECT_RECLAIM) do not get
			 * access to the min reserve.
			 */
			if (alloc_flags & ALLOC_NON_BLOCK)
				min -= min / 4;
		}

		/*
		 * OOM victims can try even harder than the normal reserve
		 * users on the grounds that it's definitely going to be in
		 * the exit path shortly and free memory. Any allocation it
		 * makes during the free path will be small and short-lived.
		 */
		if (alloc_flags & ALLOC_OOM)
			min -= min / 2;
	}

	/*
	 * Check watermarks for an order-0 allocation request. If these
	 * are not met, then a high-order request also cannot go ahead
	 * even if a suitable page happened to be free.
	 */
	if (free_pages <= min + z->lowmem_reserve[highest_zoneidx])
		return false;

	/* If this is an order-0 request then the watermark is fine */
	if (!order)
		return true;

	/* For a high-order request, check at least one suitable page is free */
	for (o = order; o < NR_PAGE_ORDERS; o++) {
		struct free_area *area = &z->free_area[o];
		int mt;

		if (!area->nr_free)
			continue;

		for (mt = 0; mt < MIGRATE_PCPTYPES; mt++) {
			if (!free_area_empty(area, mt))
				return true;
		}

#ifdef CONFIG_CMA
		if ((alloc_flags & ALLOC_CMA) &&
		    !free_area_empty(area, MIGRATE_CMA)) {
			return true;
		}
#endif
		if ((alloc_flags & (ALLOC_HIGHATOMIC|ALLOC_OOM)) &&
		    !free_area_empty(area, MIGRATE_HIGHATOMIC)) {
			return true;
		}
	}
	return false;
}

bool zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
		      int highest_zoneidx, unsigned int alloc_flags)
{
	return __zone_watermark_ok(z, order, mark, highest_zoneidx, alloc_flags,
					zone_page_state(z, NR_FREE_PAGES));
}

static inline bool zone_watermark_fast(struct zone *z, unsigned int order,
				unsigned long mark, int highest_zoneidx,
				unsigned int alloc_flags, gfp_t gfp_mask)
{
	long free_pages;

	free_pages = zone_page_state(z, NR_FREE_PAGES);

	/*
	 * Fast check for order-0 only. If this fails then the reserves
	 * need to be calculated.
	 */
	if (!order) {
		long usable_free;
		long reserved;

		usable_free = free_pages;
		reserved = __zone_watermark_unusable_free(z, 0, alloc_flags);

		/* reserved may over estimate high-atomic reserves. */
		usable_free -= min(usable_free, reserved);
		if (usable_free > mark + z->lowmem_reserve[highest_zoneidx])
			return true;
	}

	if (__zone_watermark_ok(z, order, mark, highest_zoneidx, alloc_flags,
					free_pages))
		return true;

	/*
	 * Ignore watermark boosting for __GFP_HIGH order-0 allocations
	 * when checking the min watermark. The min watermark is the
	 * point where boosting is ignored so that kswapd is woken up
	 * when below the low watermark.
	 */
	if (unlikely(!order && (alloc_flags & ALLOC_MIN_RESERVE) && z->watermark_boost
		&& ((alloc_flags & ALLOC_WMARK_MASK) == WMARK_MIN))) {
		mark = z->_watermark[WMARK_MIN];
		return __zone_watermark_ok(z, order, mark, highest_zoneidx,
					alloc_flags, free_pages);
	}

	return false;
}

#ifdef CONFIG_NUMA
int __read_mostly node_reclaim_distance = RECLAIM_DISTANCE;

static bool zone_allows_reclaim(struct zone *local_zone, struct zone *zone)
{
	return node_distance(zone_to_nid(local_zone), zone_to_nid(zone)) <=
				node_reclaim_distance;
}
#else	/* CONFIG_NUMA */
static bool zone_allows_reclaim(struct zone *local_zone, struct zone *zone)
{
	return true;
}
#endif	/* CONFIG_NUMA */

/*
 * The restriction on ZONE_DMA32 as being a suitable zone to use to avoid
 * fragmentation is subtle. If the preferred zone was HIGHMEM then
 * premature use of a lower zone may cause lowmem pressure problems that
 * are worse than fragmentation. If the next zone is ZONE_DMA then it is
 * probably too small. It only makes sense to spread allocations to avoid
 * fragmentation between the Normal and DMA32 zones.
 */
static inline unsigned int
alloc_flags_nofragment(struct zone *zone, gfp_t gfp_mask)
{
	unsigned int alloc_flags;

	/*
	 * __GFP_KSWAPD_RECLAIM is assumed to be the same as ALLOC_KSWAPD
	 * to save a branch.
	 */
	alloc_flags = (__force int) (gfp_mask & __GFP_KSWAPD_RECLAIM);

	if (defrag_mode) {
		alloc_flags |= ALLOC_NOFRAGMENT;
		return alloc_flags;
	}

#ifdef CONFIG_ZONE_DMA32
	if (!zone)
		return alloc_flags;

	if (zone_idx(zone) != ZONE_NORMAL)
		return alloc_flags;

	/*
	 * If ZONE_DMA32 exists, assume it is the one after ZONE_NORMAL and
	 * the pointer is within zone->zone_pgdat->node_zones[]. Also assume
	 * on UMA that if Normal is populated then so is DMA32.
	 */
	BUILD_BUG_ON(ZONE_NORMAL - ZONE_DMA32 != 1);
	if (nr_online_nodes > 1 && !populated_zone(--zone))
		return alloc_flags;

	alloc_flags |= ALLOC_NOFRAGMENT;
#endif /* CONFIG_ZONE_DMA32 */
	return alloc_flags;
}

/* Must be called after current_gfp_context() which can change gfp_mask */
static inline unsigned int gfp_to_alloc_flags_cma(gfp_t gfp_mask,
						  unsigned int alloc_flags)
{
#ifdef CONFIG_CMA
	if (gfp_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}

/*
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
						const struct alloc_context *ac)
{
	struct zoneref *z;
	struct zone *zone;
	struct pglist_data *last_pgdat = NULL;
	bool last_pgdat_dirty_ok = false;
	bool no_fallback;

retry:
	/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also cpuset_current_node_allowed() comment in kernel/cgroup/cpuset.c.
	 */
	no_fallback = alloc_flags & ALLOC_NOFRAGMENT;
	z = ac->preferred_zoneref;
	for_next_zone_zonelist_nodemask(zone, z, ac->highest_zoneidx,
					ac->nodemask) {
		struct page *page;
		unsigned long mark;

		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!__cpuset_zone_allowed(zone, gfp_mask))
				continue;
		/*
		 * When allocating a page cache page for writing, we
		 * want to get it from a node that is within its dirty
		 * limit, such that no single node holds more than its
		 * proportional share of globally allowed dirty pages.
		 * The dirty limits take into account the node's
		 * lowmem reserves and high watermark so that kswapd
		 * should be able to balance it without having to
		 * write pages from its LRU list.
		 *
		 * XXX: For now, allow allocations to potentially
		 * exceed the per-node dirty limit in the slowpath
		 * (spread_dirty_pages unset) before going into reclaim,
		 * which is important when on a NUMA setup the allowed
		 * nodes are together not big enough to reach the
		 * global limit.  The proper fix for these situations
		 * will require awareness of nodes in the
		 * dirty-throttling and the flusher threads.
		 */
		if (ac->spread_dirty_pages) {
			if (last_pgdat != zone->zone_pgdat) {
				last_pgdat = zone->zone_pgdat;
				last_pgdat_dirty_ok = node_dirty_ok(zone->zone_pgdat);
			}

			if (!last_pgdat_dirty_ok)
				continue;
		}

		if (no_fallback && !defrag_mode && nr_online_nodes > 1 &&
		    zone != zonelist_zone(ac->preferred_zoneref)) {
			int local_nid;

			/*
			 * If moving to a remote node, retry but allow
			 * fragmenting fallbacks. Locality is more important
			 * than fragmentation avoidance.
			 */
			local_nid = zonelist_node_idx(ac->preferred_zoneref);
			if (zone_to_nid(zone) != local_nid) {
				alloc_flags &= ~ALLOC_NOFRAGMENT;
				goto retry;
			}
		}

		cond_accept_memory(zone, order, alloc_flags);

		/*
		 * Detect whether the number of free pages is below high
		 * watermark.  If so, we will decrease pcp->high and free
		 * PCP pages in free path to reduce the possibility of
		 * premature page reclaiming.  Detection is done here to
		 * avoid to do that in hotter free path.
		 */
		if (test_bit(ZONE_BELOW_HIGH, &zone->flags))
			goto check_alloc_wmark;

		mark = high_wmark_pages(zone);
		if (zone_watermark_fast(zone, order, mark,
					ac->highest_zoneidx, alloc_flags,
					gfp_mask))
			goto try_this_zone;
		else
			set_bit(ZONE_BELOW_HIGH, &zone->flags);

check_alloc_wmark:
		mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK);
		if (!zone_watermark_fast(zone, order, mark,
				       ac->highest_zoneidx, alloc_flags,
				       gfp_mask)) {
			int ret;

			if (cond_accept_memory(zone, order, alloc_flags))
				goto try_this_zone;

			/*
			 * Watermark failed for this zone, but see if we can
			 * grow this zone if it contains deferred pages.
			 */
			if (deferred_pages_enabled()) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
			/* Checked here to keep the fast path fast */
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			if (!node_reclaim_enabled() ||
			    !zone_allows_reclaim(zonelist_zone(ac->preferred_zoneref), zone))
				continue;

			ret = node_reclaim(zone->zone_pgdat, gfp_mask, order);
			switch (ret) {
			case NODE_RECLAIM_NOSCAN:
				/* did not scan */
				continue;
			case NODE_RECLAIM_FULL:
				/* scanned but unreclaimable */
				continue;
			default:
				/* did we reclaim enough */
				if (zone_watermark_ok(zone, order, mark,
					ac->highest_zoneidx, alloc_flags))
					goto try_this_zone;

				continue;
			}
		}

try_this_zone:
		page = rmqueue(zonelist_zone(ac->preferred_zoneref), zone, order,
				gfp_mask, alloc_flags, ac->migratetype);
		if (page) {
			prep_new_page(page, order, gfp_mask, alloc_flags);

			/*
			 * If this is a high-order atomic allocation then check
			 * if the pageblock should be reserved for the future
			 */
			if (unlikely(alloc_flags & ALLOC_HIGHATOMIC))
				reserve_highatomic_pageblock(page, order, zone);

			return page;
		} else {
			if (cond_accept_memory(zone, order, alloc_flags))
				goto try_this_zone;

			/* Try again if zone has deferred pages */
			if (deferred_pages_enabled()) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
		}
	}

	/*
	 * It's possible on a UMA machine to get through all zones that are
	 * fragmented. If avoiding fragmentation, reset and try again.
	 */
	if (no_fallback && !defrag_mode) {
		alloc_flags &= ~ALLOC_NOFRAGMENT;
		goto retry;
	}

	return NULL;
}

static void warn_alloc_show_mem(gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned int filter = SHOW_MEM_FILTER_NODES;

	/*
	 * This documents exceptions given to allocations in certain
	 * contexts that are allowed to allocate outside current's set
	 * of allowed nodes.
	 */
	if (!(gfp_mask & __GFP_NOMEMALLOC))
		if (tsk_is_oom_victim(current) ||
		    (current->flags & (PF_MEMALLOC | PF_EXITING)))
			filter &= ~SHOW_MEM_FILTER_NODES;
	if (!in_task() || !(gfp_mask & __GFP_DIRECT_RECLAIM))
		filter &= ~SHOW_MEM_FILTER_NODES;

	__show_mem(filter, nodemask, gfp_zone(gfp_mask));
}

void warn_alloc(gfp_t gfp_mask, nodemask_t *nodemask, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	static DEFINE_RATELIMIT_STATE(nopage_rs, 10*HZ, 1);

	if ((gfp_mask & __GFP_NOWARN) ||
	     !__ratelimit(&nopage_rs) ||
	     ((gfp_mask & __GFP_DMA) && !has_managed_dma()))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_warn("%s: %pV, mode:%#x(%pGg), nodemask=%*pbl",
			current->comm, &vaf, gfp_mask, &gfp_mask,
			nodemask_pr_args(nodemask));
	va_end(args);

	cpuset_print_current_mems_allowed();
	pr_cont("\n");
	dump_stack();
	warn_alloc_show_mem(gfp_mask, nodemask);
}

static inline struct page *
__alloc_pages_cpuset_fallback(gfp_t gfp_mask, unsigned int order,
			      unsigned int alloc_flags,
			      const struct alloc_context *ac)
{
	struct page *page;

	page = get_page_from_freelist(gfp_mask, order,
			alloc_flags|ALLOC_CPUSET, ac);
	/*
	 * fallback to ignore cpuset restriction if our nodes
	 * are depleted
	 */
	if (!page)
		page = get_page_from_freelist(gfp_mask, order,
				alloc_flags, ac);
	return page;
}

static inline struct page *
__alloc_pages_may_oom(gfp_t gfp_mask, unsigned int order,
	const struct alloc_context *ac, unsigned long *did_some_progress)
{
	struct oom_control oc = {
		.zonelist = ac->zonelist,
		.nodemask = ac->nodemask,
		.memcg = NULL,
		.gfp_mask = gfp_mask,
		.order = order,
	};
	struct page *page;

	*did_some_progress = 0;

	/*
	 * Acquire the oom lock.  If that fails, somebody else is
	 * making progress for us.
	 */
	if (!mutex_trylock(&oom_lock)) {
		*did_some_progress = 1;
		schedule_timeout_uninterruptible(1);
		return NULL;
	}

	/*
	 * Go through the zonelist yet one more time, keep very high watermark
	 * here, this is only to catch a parallel oom killing, we must fail if
	 * we're still under heavy pressure. But make sure that this reclaim
	 * attempt shall not depend on __GFP_DIRECT_RECLAIM && !__GFP_NORETRY
	 * allocation which will never fail due to oom_lock already held.
	 */
	page = get_page_from_freelist((gfp_mask | __GFP_HARDWALL) &
				      ~__GFP_DIRECT_RECLAIM, order,
				      ALLOC_WMARK_HIGH|ALLOC_CPUSET, ac);
	if (page)
		goto out;

	/* Coredumps can quickly deplete all memory reserves */
	if (current->flags & PF_DUMPCORE)
		goto out;
	/* The OOM killer will not help higher order allocs */
	if (order > PAGE_ALLOC_COSTLY_ORDER)
		goto out;
	/*
	 * We have already exhausted all our reclaim opportunities without any
	 * success so it is time to admit defeat. We will skip the OOM killer
	 * because it is very likely that the caller has a more reasonable
	 * fallback than shooting a random task.
	 *
	 * The OOM killer may not free memory on a specific node.
	 */
	if (gfp_mask & (__GFP_RETRY_MAYFAIL | __GFP_THISNODE))
		goto out;
	/* The OOM killer does not needlessly kill tasks for lowmem */
	if (ac->highest_zoneidx < ZONE_NORMAL)
		goto out;
	if (pm_suspended_storage())
		goto out;
	/*
	 * XXX: GFP_NOFS allocations should rather fail than rely on
	 * other request to make a forward progress.
	 * We are in an unfortunate situation where out_of_memory cannot
	 * do much for this context but let's try it to at least get
	 * access to memory reserved if the current task is killed (see
	 * out_of_memory). Once filesystems are ready to handle allocation
	 * failures more gracefully we should just bail out here.
	 */

	/* Exhausted what can be done so it's blame time */
	if (out_of_memory(&oc) ||
	    WARN_ON_ONCE_GFP(gfp_mask & __GFP_NOFAIL, gfp_mask)) {
		*did_some_progress = 1;

		/*
		 * Help non-failing allocations by giving them access to memory
		 * reserves
		 */
		if (gfp_mask & __GFP_NOFAIL)
			page = __alloc_pages_cpuset_fallback(gfp_mask, order,
					ALLOC_NO_WATERMARKS, ac);
	}
out:
	mutex_unlock(&oom_lock);
	return page;
}

/*
 * Maximum number of compaction retries with a progress before OOM
 * killer is consider as the only way to move forward.
 */
#define MAX_COMPACT_RETRIES 16

#ifdef CONFIG_COMPACTION
/* Try memory compaction for high-order allocations before reclaim */
static struct page *
__alloc_pages_direct_compact(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		enum compact_priority prio, enum compact_result *compact_result)
{
	struct page *page = NULL;
	unsigned long pflags;
	unsigned int noreclaim_flag;

	if (!order)
		return NULL;

	psi_memstall_enter(&pflags);
	delayacct_compact_start();
	noreclaim_flag = memalloc_noreclaim_save();

	*compact_result = try_to_compact_pages(gfp_mask, order, alloc_flags, ac,
								prio, &page);

	memalloc_noreclaim_restore(noreclaim_flag);
	psi_memstall_leave(&pflags);
	delayacct_compact_end();

	if (*compact_result == COMPACT_SKIPPED)
		return NULL;
	/*
	 * At least in one zone compaction wasn't deferred or skipped, so let's
	 * count a compaction stall
	 */
	count_vm_event(COMPACTSTALL);

	/* Prep a captured page if available */
	if (page)
		prep_new_page(page, order, gfp_mask, alloc_flags);

	/* Try get a page from the freelist if available */
	if (!page)
		page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);

	if (page) {
		struct zone *zone = page_zone(page);

		zone->compact_blockskip_flush = false;
		compaction_defer_reset(zone, order, true);
		count_vm_event(COMPACTSUCCESS);
		return page;
	}

	/*
	 * It's bad if compaction run occurs and fails. The most likely reason
	 * is that pages exist, but not enough to satisfy watermarks.
	 */
	count_vm_event(COMPACTFAIL);

	cond_resched();

	return NULL;
}

static inline bool
should_compact_retry(struct alloc_context *ac, int order, int alloc_flags,
		     enum compact_result compact_result,
		     enum compact_priority *compact_priority,
		     int *compaction_retries)
{
	int max_retries = MAX_COMPACT_RETRIES;
	int min_priority;
	bool ret = false;
	int retries = *compaction_retries;
	enum compact_priority priority = *compact_priority;

	if (!order)
		return false;

	if (fatal_signal_pending(current))
		return false;

	/*
	 * Compaction was skipped due to a lack of free order-0
	 * migration targets. Continue if reclaim can help.
	 */
	if (compact_result == COMPACT_SKIPPED) {
		ret = compaction_zonelist_suitable(ac, order, alloc_flags);
		goto out;
	}

	/*
	 * Compaction managed to coalesce some page blocks, but the
	 * allocation failed presumably due to a race. Retry some.
	 */
	if (compact_result == COMPACT_SUCCESS) {
		/*
		 * !costly requests are much more important than
		 * __GFP_RETRY_MAYFAIL costly ones because they are de
		 * facto nofail and invoke OOM killer to move on while
		 * costly can fail and users are ready to cope with
		 * that. 1/4 retries is rather arbitrary but we would
		 * need much more detailed feedback from compaction to
		 * make a better decision.
		 */
		if (order > PAGE_ALLOC_COSTLY_ORDER)
			max_retries /= 4;

		if (++(*compaction_retries) <= max_retries) {
			ret = true;
			goto out;
		}
	}

	/*
	 * Compaction failed. Retry with increasing priority.
	 */
	min_priority = (order > PAGE_ALLOC_COSTLY_ORDER) ?
			MIN_COMPACT_COSTLY_PRIORITY : MIN_COMPACT_PRIORITY;

	if (*compact_priority > min_priority) {
		(*compact_priority)--;
		*compaction_retries = 0;
		ret = true;
	}
out:
	trace_compact_retry(order, priority, compact_result, retries, max_retries, ret);
	return ret;
}
#else
static inline struct page *
__alloc_pages_direct_compact(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		enum compact_priority prio, enum compact_result *compact_result)
{
	*compact_result = COMPACT_SKIPPED;
	return NULL;
}

static inline bool
should_compact_retry(struct alloc_context *ac, unsigned int order, int alloc_flags,
		     enum compact_result compact_result,
		     enum compact_priority *compact_priority,
		     int *compaction_retries)
{
	struct zone *zone;
	struct zoneref *z;

	if (!order || order > PAGE_ALLOC_COSTLY_ORDER)
		return false;

	/*
	 * There are setups with compaction disabled which would prefer to loop
	 * inside the allocator rather than hit the oom killer prematurely.
	 * Let's give them a good hope and keep retrying while the order-0
	 * watermarks are OK.
	 */
	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist,
				ac->highest_zoneidx, ac->nodemask) {
		if (zone_watermark_ok(zone, 0, min_wmark_pages(zone),
					ac->highest_zoneidx, alloc_flags))
			return true;
	}
	return false;
}
#endif /* CONFIG_COMPACTION */

#ifdef CONFIG_LOCKDEP
static struct lockdep_map __fs_reclaim_map =
	STATIC_LOCKDEP_MAP_INIT("fs_reclaim", &__fs_reclaim_map);

static bool __need_reclaim(gfp_t gfp_mask)
{
	/* no reclaim without waiting on it */
	if (!(gfp_mask & __GFP_DIRECT_RECLAIM))
		return false;

	/* this guy won't enter reclaim */
	if (current->flags & PF_MEMALLOC)
		return false;

	if (gfp_mask & __GFP_NOLOCKDEP)
		return false;

	return true;
}

void __fs_reclaim_acquire(unsigned long ip)
{
	lock_acquire_exclusive(&__fs_reclaim_map, 0, 0, NULL, ip);
}

void __fs_reclaim_release(unsigned long ip)
{
	lock_release(&__fs_reclaim_map, ip);
}

void fs_reclaim_acquire(gfp_t gfp_mask)
{
	gfp_mask = current_gfp_context(gfp_mask);

	if (__need_reclaim(gfp_mask)) {
		if (gfp_mask & __GFP_FS)
			__fs_reclaim_acquire(_RET_IP_);

#ifdef CONFIG_MMU_NOTIFIER
		lock_map_acquire(&__mmu_notifier_invalidate_range_start_map);
		lock_map_release(&__mmu_notifier_invalidate_range_start_map);
#endif

	}
}
EXPORT_SYMBOL_GPL(fs_reclaim_acquire);

void fs_reclaim_release(gfp_t gfp_mask)
{
	gfp_mask = current_gfp_context(gfp_mask);

	if (__need_reclaim(gfp_mask)) {
		if (gfp_mask & __GFP_FS)
			__fs_reclaim_release(_RET_IP_);
	}
}
EXPORT_SYMBOL_GPL(fs_reclaim_release);
#endif

/*
 * Zonelists may change due to hotplug during allocation. Detect when zonelists
 * have been rebuilt so allocation retries. Reader side does not lock and
 * retries the allocation if zonelist changes. Writer side is protected by the
 * embedded spin_lock.
 */
static DEFINE_SEQLOCK(zonelist_update_seq);

static unsigned int zonelist_iter_begin(void)
{
	if (IS_ENABLED(CONFIG_MEMORY_HOTREMOVE))
		return read_seqbegin(&zonelist_update_seq);

	return 0;
}

static unsigned int check_retry_zonelist(unsigned int seq)
{
	if (IS_ENABLED(CONFIG_MEMORY_HOTREMOVE))
		return read_seqretry(&zonelist_update_seq, seq);

	return seq;
}

/* Perform direct synchronous page reclaim */
static unsigned long
__perform_reclaim(gfp_t gfp_mask, unsigned int order,
					const struct alloc_context *ac)
{
	unsigned int noreclaim_flag;
	unsigned long progress;

	cond_resched();

	/* We now go into synchronous reclaim */
	cpuset_memory_pressure_bump();
	fs_reclaim_acquire(gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();

	progress = try_to_free_pages(ac->zonelist, order, gfp_mask,
								ac->nodemask);

	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(gfp_mask);

	cond_resched();

	return progress;
}

/* The really slow allocator path where we enter direct reclaim */
static inline struct page *
__alloc_pages_direct_reclaim(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		unsigned long *did_some_progress)
{
	struct page *page = NULL;
	unsigned long pflags;
	bool drained = false;

	psi_memstall_enter(&pflags);
	*did_some_progress = __perform_reclaim(gfp_mask, order, ac);
	if (unlikely(!(*did_some_progress)))
		goto out;

retry:
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);

	/*
	 * If an allocation failed after direct reclaim, it could be because
	 * pages are pinned on the per-cpu lists or in high alloc reserves.
	 * Shrink them and try again
	 */
	if (!page && !drained) {
		unreserve_highatomic_pageblock(ac, false);
		drain_all_pages(NULL);
		drained = true;
		goto retry;
	}
out:
	psi_memstall_leave(&pflags);

	return page;
}

static void wake_all_kswapds(unsigned int order, gfp_t gfp_mask,
			     const struct alloc_context *ac)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *last_pgdat = NULL;
	enum zone_type highest_zoneidx = ac->highest_zoneidx;
	unsigned int reclaim_order;

	if (defrag_mode)
		reclaim_order = max(order, pageblock_order);
	else
		reclaim_order = order;

	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist, highest_zoneidx,
					ac->nodemask) {
		if (!managed_zone(zone))
			continue;
		if (last_pgdat == zone->zone_pgdat)
			continue;
		wakeup_kswapd(zone, gfp_mask, reclaim_order, highest_zoneidx);
		last_pgdat = zone->zone_pgdat;
	}
}

static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask, unsigned int order)
{
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;

	/*
	 * __GFP_HIGH is assumed to be the same as ALLOC_MIN_RESERVE
	 * and __GFP_KSWAPD_RECLAIM is assumed to be the same as ALLOC_KSWAPD
	 * to save two branches.
	 */
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_MIN_RESERVE);
	BUILD_BUG_ON(__GFP_KSWAPD_RECLAIM != (__force gfp_t) ALLOC_KSWAPD);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_NON_BLOCK and ALLOC_MIN_RESERVE(__GFP_HIGH).
	 */
	alloc_flags |= (__force int)
		(gfp_mask & (__GFP_HIGH | __GFP_KSWAPD_RECLAIM));

	if (!(gfp_mask & __GFP_DIRECT_RECLAIM)) {
		/*
		 * Not worth trying to allocate harder for __GFP_NOMEMALLOC even
		 * if it can't schedule.
		 */
		if (!(gfp_mask & __GFP_NOMEMALLOC)) {
			alloc_flags |= ALLOC_NON_BLOCK;

			if (order > 0)
				alloc_flags |= ALLOC_HIGHATOMIC;
		}

		/*
		 * Ignore cpuset mems for non-blocking __GFP_HIGH (probably
		 * GFP_ATOMIC) rather than fail, see the comment for
		 * cpuset_current_node_allowed().
		 */
		if (alloc_flags & ALLOC_MIN_RESERVE)
			alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_or_dl_task(current)) && in_task())
		alloc_flags |= ALLOC_MIN_RESERVE;

	alloc_flags = gfp_to_alloc_flags_cma(gfp_mask, alloc_flags);

	if (defrag_mode)
		alloc_flags |= ALLOC_NOFRAGMENT;

	return alloc_flags;
}

static bool oom_reserves_allowed(struct task_struct *tsk)
{
	if (!tsk_is_oom_victim(tsk))
		return false;

	/*
	 * !MMU doesn't have oom reaper so give access to memory reserves
	 * only to the thread with TIF_MEMDIE set
	 */
	if (!IS_ENABLED(CONFIG_MMU) && !test_thread_flag(TIF_MEMDIE))
		return false;

	return true;
}

/*
 * Distinguish requests which really need access to full memory
 * reserves from oom victims which can live with a portion of it
 */
static inline int __gfp_pfmemalloc_flags(gfp_t gfp_mask)
{
	if (unlikely(gfp_mask & __GFP_NOMEMALLOC))
		return 0;
	if (gfp_mask & __GFP_MEMALLOC)
		return ALLOC_NO_WATERMARKS;
	if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
		return ALLOC_NO_WATERMARKS;
	if (!in_interrupt()) {
		if (current->flags & PF_MEMALLOC)
			return ALLOC_NO_WATERMARKS;
		else if (oom_reserves_allowed(current))
			return ALLOC_OOM;
	}

	return 0;
}

bool gfp_pfmemalloc_allowed(gfp_t gfp_mask)
{
	return !!__gfp_pfmemalloc_flags(gfp_mask);
}

/*
 * Checks whether it makes sense to retry the reclaim to make a forward progress
 * for the given allocation request.
 *
 * We give up when we either have tried MAX_RECLAIM_RETRIES in a row
 * without success, or when we couldn't even meet the watermark if we
 * reclaimed all remaining pages on the LRU lists.
 *
 * Returns true if a retry is viable or false to enter the oom path.
 */
static inline bool
should_reclaim_retry(gfp_t gfp_mask, unsigned order,
		     struct alloc_context *ac, int alloc_flags,
		     bool did_some_progress, int *no_progress_loops)
{
	struct zone *zone;
	struct zoneref *z;
	bool ret = false;

	/*
	 * Costly allocations might have made a progress but this doesn't mean
	 * their order will become available due to high fragmentation so
	 * always increment the no progress counter for them
	 */
	if (did_some_progress && order <= PAGE_ALLOC_COSTLY_ORDER)
		*no_progress_loops = 0;
	else
		(*no_progress_loops)++;

	if (*no_progress_loops > MAX_RECLAIM_RETRIES)
		goto out;


	/*
	 * Keep reclaiming pages while there is a chance this will lead
	 * somewhere.  If none of the target zones can satisfy our allocation
	 * request even if all reclaimable pages are considered then we are
	 * screwed and have to go OOM.
	 */
	for_each_zone_zonelist_nodemask(zone, z, ac->zonelist,
				ac->highest_zoneidx, ac->nodemask) {
		unsigned long available;
		unsigned long reclaimable;
		unsigned long min_wmark = min_wmark_pages(zone);
		bool wmark;

		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!__cpuset_zone_allowed(zone, gfp_mask))
				continue;

		available = reclaimable = zone_reclaimable_pages(zone);
		available += zone_page_state_snapshot(zone, NR_FREE_PAGES);

		/*
		 * Would the allocation succeed if we reclaimed all
		 * reclaimable pages?
		 */
		wmark = __zone_watermark_ok(zone, order, min_wmark,
				ac->highest_zoneidx, alloc_flags, available);
		trace_reclaim_retry_zone(z, order, reclaimable,
				available, min_wmark, *no_progress_loops, wmark);
		if (wmark) {
			ret = true;
			break;
		}
	}

	/*
	 * Memory allocation/reclaim might be called from a WQ context and the
	 * current implementation of the WQ concurrency control doesn't
	 * recognize that a particular WQ is congested if the worker thread is
	 * looping without ever sleeping. Therefore we have to do a short sleep
	 * here rather than calling cond_resched().
	 */
	if (current->flags & PF_WQ_WORKER)
		schedule_timeout_uninterruptible(1);
	else
		cond_resched();
out:
	/* Before OOM, exhaust highatomic_reserve */
	if (!ret)
		return unreserve_highatomic_pageblock(ac, true);

	return ret;
}

static inline bool
check_retry_cpuset(int cpuset_mems_cookie, struct alloc_context *ac)
{
	/*
	 * It's possible that cpuset's mems_allowed and the nodemask from
	 * mempolicy don't intersect. This should be normally dealt with by
	 * policy_nodemask(), but it's possible to race with cpuset update in
	 * such a way the check therein was true, and then it became false
	 * before we got our cpuset_mems_cookie here.
	 * This assumes that for all allocations, ac->nodemask can come only
	 * from MPOL_BIND mempolicy (whose documented semantics is to be ignored
	 * when it does not intersect with the cpuset restrictions) or the
	 * caller can deal with a violated nodemask.
	 */
	if (cpusets_enabled() && ac->nodemask &&
			!cpuset_nodemask_valid_mems_allowed(ac->nodemask)) {
		ac->nodemask = NULL;
		return true;
	}

	/*
	 * When updating a task's mems_allowed or mempolicy nodemask, it is
	 * possible to race with parallel threads in such a way that our
	 * allocation can fail while the mask is being updated. If we are about
	 * to fail, check if the cpuset changed during allocation and if so,
	 * retry.
	 */
	if (read_mems_allowed_retry(cpuset_mems_cookie))
		return true;

	return false;
}

static inline struct page *
__alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
						struct alloc_context *ac)
{
	bool can_direct_reclaim = gfp_mask & __GFP_DIRECT_RECLAIM;
	bool can_compact = gfp_compaction_allowed(gfp_mask);
	bool nofail = gfp_mask & __GFP_NOFAIL;
	const bool costly_order = order > PAGE_ALLOC_COSTLY_ORDER;
	struct page *page = NULL;
	unsigned int alloc_flags;
	unsigned long did_some_progress;
	enum compact_priority compact_priority;
	enum compact_result compact_result;
	int compaction_retries;
	int no_progress_loops;
	unsigned int cpuset_mems_cookie;
	unsigned int zonelist_iter_cookie;
	int reserve_flags;

	if (unlikely(nofail)) {
		/*
		 * We most definitely don't want callers attempting to
		 * allocate greater than order-1 page units with __GFP_NOFAIL.
		 */
		WARN_ON_ONCE(order > 1);
		/*
		 * Also we don't support __GFP_NOFAIL without __GFP_DIRECT_RECLAIM,
		 * otherwise, we may result in lockup.
		 */
		WARN_ON_ONCE(!can_direct_reclaim);
		/*
		 * PF_MEMALLOC request from this context is rather bizarre
		 * because we cannot reclaim anything and only can loop waiting
		 * for somebody to do a work for us.
		 */
		WARN_ON_ONCE(current->flags & PF_MEMALLOC);
	}

restart:
	compaction_retries = 0;
	no_progress_loops = 0;
	compact_result = COMPACT_SKIPPED;
	compact_priority = DEF_COMPACT_PRIORITY;
	cpuset_mems_cookie = read_mems_allowed_begin();
	zonelist_iter_cookie = zonelist_iter_begin();

	/*
	 * The fast path uses conservative alloc_flags to succeed only until
	 * kswapd needs to be woken up, and to avoid the cost of setting up
	 * alloc_flags precisely. So we do that now.
	 */
	alloc_flags = gfp_to_alloc_flags(gfp_mask, order);

	/*
	 * We need to recalculate the starting point for the zonelist iterator
	 * because we might have used different nodemask in the fast path, or
	 * there was a cpuset modification and we are retrying - otherwise we
	 * could end up iterating over non-eligible zones endlessly.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	if (!zonelist_zone(ac->preferred_zoneref))
		goto nopage;

	/*
	 * Check for insane configurations where the cpuset doesn't contain
	 * any suitable zone to satisfy the request - e.g. non-movable
	 * GFP_HIGHUSER allocations from MOVABLE nodes only.
	 */
	if (cpusets_insane_config() && (gfp_mask & __GFP_HARDWALL)) {
		struct zoneref *z = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx,
					&cpuset_current_mems_allowed);
		if (!zonelist_zone(z))
			goto nopage;
	}

	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	/*
	 * The adjusted alloc_flags might result in immediate success, so try
	 * that first
	 */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/*
	 * For costly allocations, try direct compaction first, as it's likely
	 * that we have enough base pages and don't need to reclaim. For non-
	 * movable high-order allocations, do that as well, as compaction will
	 * try prevent permanent fragmentation by migrating from blocks of the
	 * same migratetype.
	 * Don't try this for allocations that are allowed to ignore
	 * watermarks, as the ALLOC_NO_WATERMARKS attempt didn't yet happen.
	 */
	if (can_direct_reclaim && can_compact &&
			(costly_order ||
			   (order > 0 && ac->migratetype != MIGRATE_MOVABLE))
			&& !gfp_pfmemalloc_allowed(gfp_mask)) {
		page = __alloc_pages_direct_compact(gfp_mask, order,
						alloc_flags, ac,
						INIT_COMPACT_PRIORITY,
						&compact_result);
		if (page)
			goto got_pg;

		/*
		 * Checks for costly allocations with __GFP_NORETRY, which
		 * includes some THP page fault allocations
		 */
		if (costly_order && (gfp_mask & __GFP_NORETRY)) {
			/*
			 * If allocating entire pageblock(s) and compaction
			 * failed because all zones are below low watermarks
			 * or is prohibited because it recently failed at this
			 * order, fail immediately unless the allocator has
			 * requested compaction and reclaim retry.
			 *
			 * Reclaim is
			 *  - potentially very expensive because zones are far
			 *    below their low watermarks or this is part of very
			 *    bursty high order allocations,
			 *  - not guaranteed to help because isolate_freepages()
			 *    may not iterate over freed pages as part of its
			 *    linear scan, and
			 *  - unlikely to make entire pageblocks free on its
			 *    own.
			 */
			if (compact_result == COMPACT_SKIPPED ||
			    compact_result == COMPACT_DEFERRED)
				goto nopage;

			/*
			 * Looks like reclaim/compaction is worth trying, but
			 * sync compaction could be very expensive, so keep
			 * using async compaction.
			 */
			compact_priority = INIT_COMPACT_PRIORITY;
		}
	}

retry:
	/*
	 * Deal with possible cpuset update races or zonelist updates to avoid
	 * infinite retries.
	 */
	if (check_retry_cpuset(cpuset_mems_cookie, ac) ||
	    check_retry_zonelist(zonelist_iter_cookie))
		goto restart;

	/* Ensure kswapd doesn't accidentally go to sleep as long as we loop */
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	reserve_flags = __gfp_pfmemalloc_flags(gfp_mask);
	if (reserve_flags)
		alloc_flags = gfp_to_alloc_flags_cma(gfp_mask, reserve_flags) |
					  (alloc_flags & ALLOC_KSWAPD);

	/*
	 * Reset the nodemask and zonelist iterators if memory policies can be
	 * ignored. These allocations are high priority and system rather than
	 * user oriented.
	 */
	if (!(alloc_flags & ALLOC_CPUSET) || reserve_flags) {
		ac->nodemask = NULL;
		ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	}

	/* Attempt with potentially adjusted zonelist and alloc_flags */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/* Caller is not willing to reclaim, we can't balance anything */
	if (!can_direct_reclaim)
		goto nopage;

	/* Avoid recursion of direct reclaim */
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	/* Try direct reclaim and then allocating */
	page = __alloc_pages_direct_reclaim(gfp_mask, order, alloc_flags, ac,
							&did_some_progress);
	if (page)
		goto got_pg;

	/* Try direct compaction and then allocating */
	page = __alloc_pages_direct_compact(gfp_mask, order, alloc_flags, ac,
					compact_priority, &compact_result);
	if (page)
		goto got_pg;

	/* Do not loop if specifically requested */
	if (gfp_mask & __GFP_NORETRY)
		goto nopage;

	/*
	 * Do not retry costly high order allocations unless they are
	 * __GFP_RETRY_MAYFAIL and we can compact
	 */
	if (costly_order && (!can_compact ||
			     !(gfp_mask & __GFP_RETRY_MAYFAIL)))
		goto nopage;

	if (should_reclaim_retry(gfp_mask, order, ac, alloc_flags,
				 did_some_progress > 0, &no_progress_loops))
		goto retry;

	/*
	 * It doesn't make any sense to retry for the compaction if the order-0
	 * reclaim is not able to make any progress because the current
	 * implementation of the compaction depends on the sufficient amount
	 * of free memory (see __compaction_suitable)
	 */
	if (did_some_progress > 0 && can_compact &&
			should_compact_retry(ac, order, alloc_flags,
				compact_result, &compact_priority,
				&compaction_retries))
		goto retry;

	/* Reclaim/compaction failed to prevent the fallback */
	if (defrag_mode && (alloc_flags & ALLOC_NOFRAGMENT)) {
		alloc_flags &= ~ALLOC_NOFRAGMENT;
		goto retry;
	}

	/*
	 * Deal with possible cpuset update races or zonelist updates to avoid
	 * a unnecessary OOM kill.
	 */
	if (check_retry_cpuset(cpuset_mems_cookie, ac) ||
	    check_retry_zonelist(zonelist_iter_cookie))
		goto restart;

	/* Reclaim has failed us, start killing things */
	page = __alloc_pages_may_oom(gfp_mask, order, ac, &did_some_progress);
	if (page)
		goto got_pg;

	/* Avoid allocations with no watermarks from looping endlessly */
	if (tsk_is_oom_victim(current) &&
	    (alloc_flags & ALLOC_OOM ||
	     (gfp_mask & __GFP_NOMEMALLOC)))
		goto nopage;

	/* Retry as long as the OOM killer is making progress */
	if (did_some_progress) {
		no_progress_loops = 0;
		goto retry;
	}

nopage:
	/*
	 * Deal with possible cpuset update races or zonelist updates to avoid
	 * a unnecessary OOM kill.
	 */
	if (check_retry_cpuset(cpuset_mems_cookie, ac) ||
	    check_retry_zonelist(zonelist_iter_cookie))
		goto restart;

	/*
	 * Make sure that __GFP_NOFAIL request doesn't leak out and make sure
	 * we always retry
	 */
	if (unlikely(nofail)) {
		/*
		 * Lacking direct_reclaim we can't do anything to reclaim memory,
		 * we disregard these unreasonable nofail requests and still
		 * return NULL
		 */
		if (!can_direct_reclaim)
			goto fail;

		/*
		 * Help non-failing allocations by giving some access to memory
		 * reserves normally used for high priority non-blocking
		 * allocations but do not use ALLOC_NO_WATERMARKS because this
		 * could deplete whole memory reserves which would just make
		 * the situation worse.
		 */
		page = __alloc_pages_cpuset_fallback(gfp_mask, order, ALLOC_MIN_RESERVE, ac);
		if (page)
			goto got_pg;

		cond_resched();
		goto retry;
	}
fail:
	warn_alloc(gfp_mask, ac->nodemask,
			"page allocation failure: order:%u", order);
got_pg:
	return page;
}

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_gfp,
		unsigned int *alloc_flags)
{
	ac->highest_zoneidx = gfp_zone(gfp_mask);
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	ac->nodemask = nodemask;
	ac->migratetype = gfp_migratetype(gfp_mask);

	if (cpusets_enabled()) {
		*alloc_gfp |= __GFP_HARDWALL;
		/*
		 * When we are in the interrupt context, it is irrelevant
		 * to the current task context. It means that any node ok.
		 */
		if (in_task() && !ac->nodemask)
			ac->nodemask = &cpuset_current_mems_allowed;
		else
			*alloc_flags |= ALLOC_CPUSET;
	}

	might_alloc(gfp_mask);

	/*
	 * Don't invoke should_fail logic, since it may call
	 * get_random_u32() and printk() which need to spin_lock.
	 */
	if (!(*alloc_flags & ALLOC_TRYLOCK) &&
	    should_fail_alloc_page(gfp_mask, order))
		return false;

	*alloc_flags = gfp_to_alloc_flags_cma(gfp_mask, *alloc_flags);

	/* Dirty zone balancing only done in the fast path */
	ac->spread_dirty_pages = (gfp_mask & __GFP_WRITE);

	/*
	 * The preferred zone is used for statistics but crucially it is
	 * also used as the starting point for the zonelist iterator. It
	 * may get reset for allocations that ignore memory policies.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);

	return true;
}

/*
 * __alloc_pages_bulk - Allocate a number of order-0 pages to an array
 * @gfp: GFP flags for the allocation
 * @preferred_nid: The preferred NUMA node ID to allocate from
 * @nodemask: Set of nodes to allocate from, may be NULL
 * @nr_pages: The number of pages desired in the array
 * @page_array: Array to store the pages
 *
 * This is a batched version of the page allocator that attempts to
 * allocate nr_pages quickly. Pages are added to the page_array.
 *
 * Note that only NULL elements are populated with pages and nr_pages
 * is the maximum number of pages that will be stored in the array.
 *
 * Returns the number of pages in the array.
 */
unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
			nodemask_t *nodemask, int nr_pages,
			struct page **page_array)
{
	struct page *page;
	unsigned long __maybe_unused UP_flags;
	struct zone *zone;
	struct zoneref *z;
	struct per_cpu_pages *pcp;
	struct list_head *pcp_list;
	struct alloc_context ac;
	gfp_t alloc_gfp;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	int nr_populated = 0, nr_account = 0;

	/*
	 * Skip populated array elements to determine if any pages need
	 * to be allocated before disabling IRQs.
	 */
	while (nr_populated < nr_pages && page_array[nr_populated])
		nr_populated++;

	/* No pages requested? */
	if (unlikely(nr_pages <= 0))
		goto out;

	/* Already populated array? */
	if (unlikely(nr_pages - nr_populated == 0))
		goto out;

	/* Bulk allocator does not support memcg accounting. */
	if (memcg_kmem_online() && (gfp & __GFP_ACCOUNT))
		goto failed;

	/* Use the single page allocator for one page. */
	if (nr_pages - nr_populated == 1)
		goto failed;

#ifdef CONFIG_PAGE_OWNER
	/*
	 * PAGE_OWNER may recurse into the allocator to allocate space to
	 * save the stack with pagesets.lock held. Releasing/reacquiring
	 * removes much of the performance benefit of bulk allocation so
	 * force the caller to allocate one page at a time as it'll have
	 * similar performance to added complexity to the bulk allocator.
	 */
	if (static_branch_unlikely(&page_owner_inited))
		goto failed;
#endif

	/* May set ALLOC_NOFRAGMENT, fragmentation will return 1 page. */
	gfp &= gfp_allowed_mask;
	alloc_gfp = gfp;
	if (!prepare_alloc_pages(gfp, 0, preferred_nid, nodemask, &ac, &alloc_gfp, &alloc_flags))
		goto out;
	gfp = alloc_gfp;

	/* Find an allowed local zone that meets the low watermark. */
	z = ac.preferred_zoneref;
	for_next_zone_zonelist_nodemask(zone, z, ac.highest_zoneidx, ac.nodemask) {
		unsigned long mark;

		if (cpusets_enabled() && (alloc_flags & ALLOC_CPUSET) &&
		    !__cpuset_zone_allowed(zone, gfp)) {
			continue;
		}

		if (nr_online_nodes > 1 && zone != zonelist_zone(ac.preferred_zoneref) &&
		    zone_to_nid(zone) != zonelist_node_idx(ac.preferred_zoneref)) {
			goto failed;
		}

		cond_accept_memory(zone, 0, alloc_flags);
retry_this_zone:
		mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK) + nr_pages;
		if (zone_watermark_fast(zone, 0,  mark,
				zonelist_zone_idx(ac.preferred_zoneref),
				alloc_flags, gfp)) {
			break;
		}

		if (cond_accept_memory(zone, 0, alloc_flags))
			goto retry_this_zone;

		/* Try again if zone has deferred pages */
		if (deferred_pages_enabled()) {
			if (_deferred_grow_zone(zone, 0))
				goto retry_this_zone;
		}
	}

	/*
	 * If there are no allowed local zones that meets the watermarks then
	 * try to allocate a single page and reclaim if necessary.
	 */
	if (unlikely(!zone))
		goto failed;

	/* spin_trylock may fail due to a parallel drain or IRQ reentrancy. */
	pcp_trylock_prepare(UP_flags);
	pcp = pcp_spin_trylock(zone->per_cpu_pageset);
	if (!pcp)
		goto failed_irq;

	/* Attempt the batch allocation */
	pcp_list = &pcp->lists[order_to_pindex(ac.migratetype, 0)];
	while (nr_populated < nr_pages) {

		/* Skip existing pages */
		if (page_array[nr_populated]) {
			nr_populated++;
			continue;
		}

		page = __rmqueue_pcplist(zone, 0, ac.migratetype, alloc_flags,
								pcp, pcp_list);
		if (unlikely(!page)) {
			/* Try and allocate at least one page */
			if (!nr_account) {
				pcp_spin_unlock(pcp);
				goto failed_irq;
			}
			break;
		}
		nr_account++;

		prep_new_page(page, 0, gfp, 0);
		set_page_refcounted(page);
		page_array[nr_populated++] = page;
	}

	pcp_spin_unlock(pcp);
	pcp_trylock_finish(UP_flags);

	__count_zid_vm_events(PGALLOC, zone_idx(zone), nr_account);
	zone_statistics(zonelist_zone(ac.preferred_zoneref), zone, nr_account);

out:
	return nr_populated;

failed_irq:
	pcp_trylock_finish(UP_flags);

failed:
	page = __alloc_pages_noprof(gfp, 0, preferred_nid, nodemask);
	if (page)
		page_array[nr_populated++] = page;
	goto out;
}
EXPORT_SYMBOL_GPL(alloc_pages_bulk_noprof);

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *__alloc_frozen_pages_noprof(gfp_t gfp, unsigned int order,
		int preferred_nid, nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_gfp; /* The gfp_t that was actually used for allocation */
	struct alloc_context ac = { };

	/*
	 * There are several places where we assume that the order value is sane
	 * so bail out early if the request is out of bound.
	 */
	if (WARN_ON_ONCE_GFP(order > MAX_PAGE_ORDER, gfp))
		return NULL;

	gfp &= gfp_allowed_mask;
	/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
	 * movable zones are not used during allocation.
	 */
	gfp = current_gfp_context(gfp);
	alloc_gfp = gfp;
	if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
			&alloc_gfp, &alloc_flags))
		return NULL;

	/*
	 * Forbid the first pass from falling back to types that fragment
	 * memory until all local zones are considered.
	 */
	alloc_flags |= alloc_flags_nofragment(zonelist_zone(ac.preferred_zoneref), gfp);

	/* First allocation attempt */
	page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	alloc_gfp = gfp;
	ac.spread_dirty_pages = false;

	/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */
	ac.nodemask = nodemask;

	page = __alloc_pages_slowpath(alloc_gfp, order, &ac);

out:
	if (memcg_kmem_online() && (gfp & __GFP_ACCOUNT) && page &&
	    unlikely(__memcg_kmem_charge_page(page, gfp, order) != 0)) {
		free_frozen_pages(page, order);
		page = NULL;
	}

	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
	kmsan_alloc_page(page, order, alloc_gfp);

	return page;
}
EXPORT_SYMBOL(__alloc_frozen_pages_noprof);

struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order,
		int preferred_nid, nodemask_t *nodemask)
{
	struct page *page;

	page = __alloc_frozen_pages_noprof(gfp, order, preferred_nid, nodemask);
	if (page)
		set_page_refcounted(page);
	return page;
}
EXPORT_SYMBOL(__alloc_pages_noprof);

struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
		nodemask_t *nodemask)
{
	struct page *page = __alloc_pages_noprof(gfp | __GFP_COMP, order,
					preferred_nid, nodemask);
	return page_rmappable_folio(page);
}
EXPORT_SYMBOL(__folio_alloc_noprof);

/*
 * Common helper functions. Never use with __GFP_HIGHMEM because the returned
 * address cannot represent highmem pages. Use alloc_pages and then kmap if
 * you need to access high mem.
 */
unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order)
{
	struct page *page;

	page = alloc_pages_noprof(gfp_mask & ~__GFP_HIGHMEM, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}
EXPORT_SYMBOL(get_free_pages_noprof);

unsigned long get_zeroed_page_noprof(gfp_t gfp_mask)
{
	return get_free_pages_noprof(gfp_mask | __GFP_ZERO, 0);
}
EXPORT_SYMBOL(get_zeroed_page_noprof);

static void ___free_pages(struct page *page, unsigned int order,
			  fpi_t fpi_flags)
{
	/* get PageHead before we drop reference */
	int head = PageHead(page);
	/* get alloc tag in case the page is released by others */
	struct alloc_tag *tag = pgalloc_tag_get(page);

	if (put_page_testzero(page))
		__free_frozen_pages(page, order, fpi_flags);
	else if (!head) {
		pgalloc_tag_sub_pages(tag, (1 << order) - 1);
		while (order-- > 0)
			__free_frozen_pages(page + (1 << order), order,
					    fpi_flags);
	}
}

/**
 * __free_pages - Free pages allocated with alloc_pages().
 * @page: The page pointer returned from alloc_pages().
 * @order: The order of the allocation.
 *
 * This function can free multi-page allocations that are not compound
 * pages.  It does not check that the @order passed in matches that of
 * the allocation, so it is easy to leak memory.  Freeing more memory
 * than was allocated will probably emit a warning.
 *
 * If the last reference to this page is speculative, it will be released
 * by put_page() which only frees the first page of a non-compound
 * allocation.  To prevent the remaining pages from being leaked, we free
 * the subsequent pages here.  If you want to use the page's reference
 * count to decide when to free the allocation, you should allocate a
 * compound page, and use put_page() instead of __free_pages().
 *
 * Context: May be called in interrupt context or while holding a normal
 * spinlock, but not in NMI context or while holding a raw spinlock.
 */
void __free_pages(struct page *page, unsigned int order)
{
	___free_pages(page, order, FPI_NONE);
}
EXPORT_SYMBOL(__free_pages);

/*
 * Can be called while holding raw_spin_lock or from IRQ and NMI for any
 * page type (not only those that came from alloc_pages_nolock)
 */
void free_pages_nolock(struct page *page, unsigned int order)
{
	___free_pages(page, order, FPI_TRYLOCK);
}

void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		VM_BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

static void *make_alloc_exact(unsigned long addr, unsigned int order,
		size_t size)
{
	if (addr) {
		unsigned long nr = DIV_ROUND_UP(size, PAGE_SIZE);
		struct page *page = virt_to_page((void *)addr);
		struct page *last = page + nr;

		split_page_owner(page, order, 0);
		pgalloc_tag_split(page_folio(page), order, 0);
		split_page_memcg(page, order);
		while (page < --last)
			set_page_refcounted(last);

		last = page + (1UL << order);
		for (page += nr; page < last; page++)
			__free_pages_ok(page, 0, FPI_TO_TAIL);
	}
	return (void *)addr;
}

/**
 * alloc_pages_exact - allocate an exact number physically-contiguous pages.
 * @size: the number of bytes to allocate
 * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
 *
 * This function is similar to alloc_pages(), except that it allocates the
 * minimum number of pages to satisfy the request.  alloc_pages() can only
 * allocate memory in power-of-two pages.
 *
 * This function is also limited by MAX_PAGE_ORDER.
 *
 * Memory allocated by this function must be released by free_pages_exact().
 *
 * Return: pointer to the allocated area or %NULL in case of error.
 */
void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask)
{
	unsigned int order = get_order(size);
	unsigned long addr;

	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);

	addr = get_free_pages_noprof(gfp_mask, order);
	return make_alloc_exact(addr, order, size);
}
EXPORT_SYMBOL(alloc_pages_exact_noprof);

/**
 * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
 *			   pages on a node.
 * @nid: the preferred node ID where memory should be allocated
 * @size: the number of bytes to allocate
 * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
 *
 * Like alloc_pages_exact(), but try to allocate on node nid first before falling
 * back.
 *
 * Return: pointer to the allocated area or %NULL in case of error.
 */
void * __meminit alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask)
{
	unsigned int order = get_order(size);
	struct page *p;

	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);

	p = alloc_pages_node_noprof(nid, gfp_mask, order);
	if (!p)
		return NULL;
	return make_alloc_exact((unsigned long)page_address(p), order, size);
}

/**
 * free_pages_exact - release memory allocated via alloc_pages_exact()
 * @virt: the value returned by alloc_pages_exact.
 * @size: size of allocation, same value as passed to alloc_pages_exact().
 *
 * Release the memory allocated by a previous call to alloc_pages_exact.
 */
void free_pages_exact(void *virt, size_t size)
{
	unsigned long addr = (unsigned long)virt;
	unsigned long end = addr + PAGE_ALIGN(size);

	while (addr < end) {
		free_page(addr);
		addr += PAGE_SIZE;
	}
}
EXPORT_SYMBOL(free_pages_exact);

/**
 * nr_free_zone_pages - count number of pages beyond high watermark
 * @offset: The zone index of the highest zone
 *
 * nr_free_zone_pages() counts the number of pages which are beyond the
 * high watermark within all zones at or below a given zone index.  For each
 * zone, the number of pages is calculated as:
 *
 *     nr_free_zone_pages = managed_pages - high_pages
 *
 * Return: number of pages beyond high watermark.
 */
static unsigned long nr_free_zone_pages(int offset)
{
	struct zoneref *z;
	struct zone *zone;

	/* Just pick one node, since fallback list is circular */
	unsigned long sum = 0;

	struct zonelist *zonelist = node_zonelist(numa_node_id(), GFP_KERNEL);

	for_each_zone_zonelist(zone, z, zonelist, offset) {
		unsigned long size = zone_managed_pages(zone);
		unsigned long high = high_wmark_pages(zone);
		if (size > high)
			sum += size - high;
	}

	return sum;
}

/**
 * nr_free_buffer_pages - count number of pages beyond high watermark
 *
 * nr_free_buffer_pages() counts the number of pages which are beyond the high
 * watermark within ZONE_DMA and ZONE_NORMAL.
 *
 * Return: number of pages beyond high watermark within ZONE_DMA and
 * ZONE_NORMAL.
 */
unsigned long nr_free_buffer_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_USER));
}
EXPORT_SYMBOL_GPL(nr_free_buffer_pages);

static void zoneref_set_zone(struct zone *zone, struct zoneref *zoneref)
{
	zoneref->zone = zone;
	zoneref->zone_idx = zone_idx(zone);
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 */
static int build_zonerefs_node(pg_data_t *pgdat, struct zoneref *zonerefs)
{
	struct zone *zone;
	enum zone_type zone_type = MAX_NR_ZONES;
	int nr_zones = 0;

	do {
		zone_type--;
		zone = pgdat->node_zones + zone_type;
		if (populated_zone(zone)) {
			zoneref_set_zone(zone, &zonerefs[nr_zones++]);
			check_highest_zone(zone_type);
		}
	} while (zone_type);

	return nr_zones;
}

#ifdef CONFIG_NUMA

static int __parse_numa_zonelist_order(char *s)
{
	/*
	 * We used to support different zonelists modes but they turned
	 * out to be just not useful. Let's keep the warning in place
	 * if somebody still use the cmd line parameter so that we do
	 * not fail it silently
	 */
	if (!(*s == 'd' || *s == 'D' || *s == 'n' || *s == 'N')) {
		pr_warn("Ignoring unsupported numa_zonelist_order value:  %s\n", s);
		return -EINVAL;
	}
	return 0;
}

static char numa_zonelist_order[] = "Node";
#define NUMA_ZONELIST_ORDER_LEN	16
/*
 * sysctl handler for numa_zonelist_order
 */
static int numa_zonelist_order_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	if (write)
		return __parse_numa_zonelist_order(buffer);
	return proc_dostring(table, write, buffer, length, ppos);
}

static int node_load[MAX_NUMNODES];

/**
 * find_next_best_node - find the next node that should appear in a given node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: nodemask_t of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 *
 * Return: node id of the found node or %NUMA_NO_NODE if no node is found.
 */
int find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	int best_node = NUMA_NO_NODE;

	/*
	 * Use the local node if we haven't already, but for memoryless local
	 * node, we should skip it and fall back to other nodes.
	 */
	if (!node_isset(node, *used_node_mask) && node_state(node, N_MEMORY)) {
		node_set(node, *used_node_mask);
		return node;
	}

	for_each_node_state(n, N_MEMORY) {

		/* Don't want a node to appear more than once */
		if (node_isset(n, *used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Penalize nodes under us ("prefer the next node") */
		val += (n < node);

		/* Give preference to headless and unused nodes */
		if (!cpumask_empty(cpumask_of_node(n)))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= MAX_NUMNODES;
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}


/*
 * Build zonelists ordered by node and zones within node.
 * This results in maximum locality--normal zone overflows into local
 * DMA zone, if any--but risks exhausting DMA zone.
 */
static void build_zonelists_in_node_order(pg_data_t *pgdat, int *node_order,
		unsigned nr_nodes)
{
	struct zoneref *zonerefs;
	int i;

	zonerefs = pgdat->node_zonelists[ZONELIST_FALLBACK]._zonerefs;

	for (i = 0; i < nr_nodes; i++) {
		int nr_zones;

		pg_data_t *node = NODE_DATA(node_order[i]);

		nr_zones = build_zonerefs_node(node, zonerefs);
		zonerefs += nr_zones;
	}
	zonerefs->zone = NULL;
	zonerefs->zone_idx = 0;
}

/*
 * Build __GFP_THISNODE zonelists
 */
static void build_thisnode_zonelists(pg_data_t *pgdat)
{
	struct zoneref *zonerefs;
	int nr_zones;

	zonerefs = pgdat->node_zonelists[ZONELIST_NOFALLBACK]._zonerefs;
	nr_zones = build_zonerefs_node(pgdat, zonerefs);
	zonerefs += nr_zones;
	zonerefs->zone = NULL;
	zonerefs->zone_idx = 0;
}

static void build_zonelists(pg_data_t *pgdat)
{
	static int node_order[MAX_NUMNODES];
	int node, nr_nodes = 0;
	nodemask_t used_mask = NODE_MASK_NONE;
	int local_node, prev_node;

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id;
	prev_node = local_node;

	memset(node_order, 0, sizeof(node_order));
	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local_node, node) !=
		    node_distance(local_node, prev_node))
			node_load[node] += 1;

		node_order[nr_nodes++] = node;
		prev_node = node;
	}

	build_zonelists_in_node_order(pgdat, node_order, nr_nodes);
	build_thisnode_zonelists(pgdat);
	pr_info("Fallback order for Node %d: ", local_node);
	for (node = 0; node < nr_nodes; node++)
		pr_cont("%d ", node_order[node]);
	pr_cont("\n");
}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
/*
 * Return node id of node used for "local" allocations.
 * I.e., first node id of first zone in arg node's generic zonelist.
 * Used for initializing percpu 'numa_mem', which is used primarily
 * for kernel allocations, so use GFP_KERNEL flags to locate zonelist.
 */
int local_memory_node(int node)
{
	struct zoneref *z;

	z = first_zones_zonelist(node_zonelist(node, GFP_KERNEL),
				   gfp_zone(GFP_KERNEL),
				   NULL);
	return zonelist_node_idx(z);
}
#endif

static void setup_min_unmapped_ratio(void);
static void setup_min_slab_ratio(void);
#else	/* CONFIG_NUMA */

static void build_zonelists(pg_data_t *pgdat)
{
	struct zoneref *zonerefs;
	int nr_zones;

	zonerefs = pgdat->node_zonelists[ZONELIST_FALLBACK]._zonerefs;
	nr_zones = build_zonerefs_node(pgdat, zonerefs);
	zonerefs += nr_zones;

	zonerefs->zone = NULL;
	zonerefs->zone_idx = 0;
}

#endif	/* CONFIG_NUMA */

/*
 * Boot pageset table. One per cpu which is going to be used for all
 * zones and all nodes. The parameters will be set in such a way
 * that an item put on a list will immediately be handed over to
 * the buddy list. This is safe since pageset manipulation is done
 * with interrupts disabled.
 *
 * The boot_pagesets must be kept even after bootup is complete for
 * unused processors and/or zones. They do play a role for bootstrapping
 * hotplugged processors.
 *
 * zoneinfo_show() and maybe other functions do
 * not check if the processor is online before following the pageset pointer.
 * Other parts of the kernel may not check if the zone is available.
 */
static void per_cpu_pages_init(struct per_cpu_pages *pcp, struct per_cpu_zonestat *pzstats);
/* These effectively disable the pcplists in the boot pageset completely */
#define BOOT_PAGESET_HIGH	0
#define BOOT_PAGESET_BATCH	1
static DEFINE_PER_CPU(struct per_cpu_pages, boot_pageset);
static DEFINE_PER_CPU(struct per_cpu_zonestat, boot_zonestats);

static void __build_all_zonelists(void *data)
{
	int nid;
	int __maybe_unused cpu;
	pg_data_t *self = data;
	unsigned long flags;

	/*
	 * The zonelist_update_seq must be acquired with irqsave because the
	 * reader can be invoked from IRQ with GFP_ATOMIC.
	 */
	write_seqlock_irqsave(&zonelist_update_seq, flags);
	/*
	 * Also disable synchronous printk() to prevent any printk() from
	 * trying to hold port->lock, for
	 * tty_insert_flip_string_and_push_buffer() on other CPU might be
	 * calling kmalloc(GFP_ATOMIC | __GFP_NOWARN) with port->lock held.
	 */
	printk_deferred_enter();

#ifdef CONFIG_NUMA
	memset(node_load, 0, sizeof(node_load));
#endif

	/*
	 * This node is hotadded and no memory is yet present.   So just
	 * building zonelists is fine - no need to touch other nodes.
	 */
	if (self && !node_online(self->node_id)) {
		build_zonelists(self);
	} else {
		/*
		 * All possible nodes have pgdat preallocated
		 * in free_area_init
		 */
		for_each_node(nid) {
			pg_data_t *pgdat = NODE_DATA(nid);

			build_zonelists(pgdat);
		}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
		/*
		 * We now know the "local memory node" for each node--
		 * i.e., the node of the first zone in the generic zonelist.
		 * Set up numa_mem percpu variable for on-line cpus.  During
		 * boot, only the boot cpu should be on-line;  we'll init the
		 * secondary cpus' numa_mem as they come on-line.  During
		 * node/memory hotplug, we'll fixup all on-line cpus.
		 */
		for_each_online_cpu(cpu)
			set_cpu_numa_mem(cpu, local_memory_node(cpu_to_node(cpu)));
#endif
	}

	printk_deferred_exit();
	write_sequnlock_irqrestore(&zonelist_update_seq, flags);
}

static noinline void __init
build_all_zonelists_init(void)
{
	int cpu;

	__build_all_zonelists(NULL);

	/*
	 * Initialize the boot_pagesets that are going to be used
	 * for bootstrapping processors. The real pagesets for
	 * each zone will be allocated later when the per cpu
	 * allocator is available.
	 *
	 * boot_pagesets are used also for bootstrapping offline
	 * cpus if the system is already booted because the pagesets
	 * are needed to initialize allocators on a specific cpu too.
	 * F.e. the percpu allocator needs the page allocator which
	 * needs the percpu allocator in order to allocate its pagesets
	 * (a chicken-egg dilemma).
	 */
	for_each_possible_cpu(cpu)
		per_cpu_pages_init(&per_cpu(boot_pageset, cpu), &per_cpu(boot_zonestats, cpu));

	mminit_verify_zonelist();
	cpuset_init_current_mems_allowed();
}

/*
 * unless system_state == SYSTEM_BOOTING.
 *
 * __ref due to call of __init annotated helper build_all_zonelists_init
 * [protected by SYSTEM_BOOTING].
 */
void __ref build_all_zonelists(pg_data_t *pgdat)
{
	unsigned long vm_total_pages;

	if (system_state == SYSTEM_BOOTING) {
		build_all_zonelists_init();
	} else {
		__build_all_zonelists(pgdat);
		/* cpuset refresh routine should be here */
	}
	/* Get the number of free pages beyond high watermark in all zones. */
	vm_total_pages = nr_free_zone_pages(gfp_zone(GFP_HIGHUSER_MOVABLE));
	/*
	 * Disable grouping by mobility if the number of pages in the
	 * system is too low to allow the mechanism to work. It would be
	 * more accurate, but expensive to check per-zone. This check is
	 * made on memory-hotadd so a system can start with mobility
	 * disabled and enable it later
	 */
	if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
		page_group_by_mobility_disabled = 1;
	else
		page_group_by_mobility_disabled = 0;

	pr_info("Built %u zonelists, mobility grouping %s.  Total pages: %ld\n",
		nr_online_nodes,
		str_off_on(page_group_by_mobility_disabled),
		vm_total_pages);
#ifdef CONFIG_NUMA
	pr_info("Policy zone: %s\n", zone_names[policy_zone]);
#endif
}

static int zone_batchsize(struct zone *zone)
{
#ifdef CONFIG_MMU
	int batch;

	/*
	 * The number of pages to batch allocate is either ~0.1%
	 * of the zone or 1MB, whichever is smaller. The batch
	 * size is striking a balance between allocation latency
	 * and zone lock contention.
	 */
	batch = min(zone_managed_pages(zone) >> 10, SZ_1M / PAGE_SIZE);
	batch /= 4;		/* We effectively *= 4 below */
	if (batch < 1)
		batch = 1;

	/*
	 * Clamp the batch to a 2^n - 1 value. Having a power
	 * of 2 value was found to be more likely to have
	 * suboptimal cache aliasing properties in some cases.
	 *
	 * For example if 2 tasks are alternately allocating
	 * batches of pages, one task can end up with a lot
	 * of pages of one half of the possible page colors
	 * and the other with pages of the other colors.
	 */
	batch = rounddown_pow_of_two(batch + batch/2) - 1;

	return batch;

#else
	/* The deferral and batching of frees should be suppressed under NOMMU
	 * conditions.
	 *
	 * The problem is that NOMMU needs to be able to allocate large chunks
	 * of contiguous memory as there's no hardware page translation to
	 * assemble apparent contiguous memory from discontiguous pages.
	 *
	 * Queueing large contiguous runs of pages for batching, however,
	 * causes the pages to actually be freed in smaller chunks.  As there
	 * can be a significant delay between the individual batches being
	 * recycled, this leads to the once large chunks of space being
	 * fragmented and becoming unavailable for high-order allocations.
	 */
	return 0;
#endif
}

static int percpu_pagelist_high_fraction;
static int zone_highsize(struct zone *zone, int batch, int cpu_online,
			 int high_fraction)
{
#ifdef CONFIG_MMU
	int high;
	int nr_split_cpus;
	unsigned long total_pages;

	if (!high_fraction) {
		/*
		 * By default, the high value of the pcp is based on the zone
		 * low watermark so that if they are full then background
		 * reclaim will not be started prematurely.
		 */
		total_pages = low_wmark_pages(zone);
	} else {
		/*
		 * If percpu_pagelist_high_fraction is configured, the high
		 * value is based on a fraction of the managed pages in the
		 * zone.
		 */
		total_pages = zone_managed_pages(zone) / high_fraction;
	}

	/*
	 * Split the high value across all online CPUs local to the zone. Note
	 * that early in boot that CPUs may not be online yet and that during
	 * CPU hotplug that the cpumask is not yet updated when a CPU is being
	 * onlined. For memory nodes that have no CPUs, split the high value
	 * across all online CPUs to mitigate the risk that reclaim is triggered
	 * prematurely due to pages stored on pcp lists.
	 */
	nr_split_cpus = cpumask_weight(cpumask_of_node(zone_to_nid(zone))) + cpu_online;
	if (!nr_split_cpus)
		nr_split_cpus = num_online_cpus();
	high = total_pages / nr_split_cpus;

	/*
	 * Ensure high is at least batch*4. The multiple is based on the
	 * historical relationship between high and batch.
	 */
	high = max(high, batch << 2);

	return high;
#else
	return 0;
#endif
}

/*
 * pcp->high and pcp->batch values are related and generally batch is lower
 * than high. They are also related to pcp->count such that count is lower
 * than high, and as soon as it reaches high, the pcplist is flushed.
 *
 * However, guaranteeing these relations at all times would require e.g. write
 * barriers here but also careful usage of read barriers at the read side, and
 * thus be prone to error and bad for performance. Thus the update only prevents
 * store tearing. Any new users of pcp->batch, pcp->high_min and pcp->high_max
 * should ensure they can cope with those fields changing asynchronously, and
 * fully trust only the pcp->count field on the local CPU with interrupts
 * disabled.
 *
 * mutex_is_locked(&pcp_batch_high_lock) required when calling this function
 * outside of boot time (or some other assurance that no concurrent updaters
 * exist).
 */
static void pageset_update(struct per_cpu_pages *pcp, unsigned long high_min,
			   unsigned long high_max, unsigned long batch)
{
	WRITE_ONCE(pcp->batch, batch);
	WRITE_ONCE(pcp->high_min, high_min);
	WRITE_ONCE(pcp->high_max, high_max);
}

static void per_cpu_pages_init(struct per_cpu_pages *pcp, struct per_cpu_zonestat *pzstats)
{
	int pindex;

	memset(pcp, 0, sizeof(*pcp));
	memset(pzstats, 0, sizeof(*pzstats));

	spin_lock_init(&pcp->lock);
	for (pindex = 0; pindex < NR_PCP_LISTS; pindex++)
		INIT_LIST_HEAD(&pcp->lists[pindex]);

	/*
	 * Set batch and high values safe for a boot pageset. A true percpu
	 * pageset's initialization will update them subsequently. Here we don't
	 * need to be as careful as pageset_update() as nobody can access the
	 * pageset yet.
	 */
	pcp->high_min = BOOT_PAGESET_HIGH;
	pcp->high_max = BOOT_PAGESET_HIGH;
	pcp->batch = BOOT_PAGESET_BATCH;
	pcp->free_count = 0;
}

static void __zone_set_pageset_high_and_batch(struct zone *zone, unsigned long high_min,
					      unsigned long high_max, unsigned long batch)
{
	struct per_cpu_pages *pcp;
	int cpu;

	for_each_possible_cpu(cpu) {
		pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
		pageset_update(pcp, high_min, high_max, batch);
	}
}

/*
 * Calculate and set new high and batch values for all per-cpu pagesets of a
 * zone based on the zone's size.
 */
static void zone_set_pageset_high_and_batch(struct zone *zone, int cpu_online)
{
	int new_high_min, new_high_max, new_batch;

	new_batch = max(1, zone_batchsize(zone));
	if (percpu_pagelist_high_fraction) {
		new_high_min = zone_highsize(zone, new_batch, cpu_online,
					     percpu_pagelist_high_fraction);
		/*
		 * PCP high is tuned manually, disable auto-tuning via
		 * setting high_min and high_max to the manual value.
		 */
		new_high_max = new_high_min;
	} else {
		new_high_min = zone_highsize(zone, new_batch, cpu_online, 0);
		new_high_max = zone_highsize(zone, new_batch, cpu_online,
					     MIN_PERCPU_PAGELIST_HIGH_FRACTION);
	}

	if (zone->pageset_high_min == new_high_min &&
	    zone->pageset_high_max == new_high_max &&
	    zone->pageset_batch == new_batch)
		return;

	zone->pageset_high_min = new_high_min;
	zone->pageset_high_max = new_high_max;
	zone->pageset_batch = new_batch;

	__zone_set_pageset_high_and_batch(zone, new_high_min, new_high_max,
					  new_batch);
}

void __meminit setup_zone_pageset(struct zone *zone)
{
	int cpu;

	/* Size may be 0 on !SMP && !NUMA */
	if (sizeof(struct per_cpu_zonestat) > 0)
		zone->per_cpu_zonestats = alloc_percpu(struct per_cpu_zonestat);

	zone->per_cpu_pageset = alloc_percpu(struct per_cpu_pages);
	for_each_possible_cpu(cpu) {
		struct per_cpu_pages *pcp;
		struct per_cpu_zonestat *pzstats;

		pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
		pzstats = per_cpu_ptr(zone->per_cpu_zonestats, cpu);
		per_cpu_pages_init(pcp, pzstats);
	}

	zone_set_pageset_high_and_batch(zone, 0);
}

/*
 * The zone indicated has a new number of managed_pages; batch sizes and percpu
 * page high values need to be recalculated.
 */
static void zone_pcp_update(struct zone *zone, int cpu_online)
{
	mutex_lock(&pcp_batch_high_lock);
	zone_set_pageset_high_and_batch(zone, cpu_online);
	mutex_unlock(&pcp_batch_high_lock);
}

static void zone_pcp_update_cacheinfo(struct zone *zone, unsigned int cpu)
{
	struct per_cpu_pages *pcp;
	struct cpu_cacheinfo *cci;

	pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
	cci = get_cpu_cacheinfo(cpu);
	/*
	 * If data cache slice of CPU is large enough, "pcp->batch"
	 * pages can be preserved in PCP before draining PCP for
	 * consecutive high-order pages freeing without allocation.
	 * This can reduce zone lock contention without hurting
	 * cache-hot pages sharing.
	 */
	spin_lock(&pcp->lock);
	if ((cci->per_cpu_data_slice_size >> PAGE_SHIFT) > 3 * pcp->batch)
		pcp->flags |= PCPF_FREE_HIGH_BATCH;
	else
		pcp->flags &= ~PCPF_FREE_HIGH_BATCH;
	spin_unlock(&pcp->lock);
}

void setup_pcp_cacheinfo(unsigned int cpu)
{
	struct zone *zone;

	for_each_populated_zone(zone)
		zone_pcp_update_cacheinfo(zone, cpu);
}

/*
 * Allocate per cpu pagesets and initialize them.
 * Before this call only boot pagesets were available.
 */
void __init setup_per_cpu_pageset(void)
{
	struct pglist_data *pgdat;
	struct zone *zone;
	int __maybe_unused cpu;

	for_each_populated_zone(zone)
		setup_zone_pageset(zone);

#ifdef CONFIG_NUMA
	/*
	 * Unpopulated zones continue using the boot pagesets.
	 * The numa stats for these pagesets need to be reset.
	 * Otherwise, they will end up skewing the stats of
	 * the nodes these zones are associated with.
	 */
	for_each_possible_cpu(cpu) {
		struct per_cpu_zonestat *pzstats = &per_cpu(boot_zonestats, cpu);
		memset(pzstats->vm_numa_event, 0,
		       sizeof(pzstats->vm_numa_event));
	}
#endif

	for_each_online_pgdat(pgdat)
		pgdat->per_cpu_nodestats =
			alloc_percpu(struct per_cpu_nodestat);
}

__meminit void zone_pcp_init(struct zone *zone)
{
	/*
	 * per cpu subsystem is not up at this point. The following code
	 * relies on the ability of the linker to provide the
	 * offset of a (static) per cpu variable into the per cpu area.
	 */
	zone->per_cpu_pageset = &boot_pageset;
	zone->per_cpu_zonestats = &boot_zonestats;
	zone->pageset_high_min = BOOT_PAGESET_HIGH;
	zone->pageset_high_max = BOOT_PAGESET_HIGH;
	zone->pageset_batch = BOOT_PAGESET_BATCH;

	if (populated_zone(zone))
		pr_debug("  %s zone: %lu pages, LIFO batch:%u\n", zone->name,
			 zone->present_pages, zone_batchsize(zone));
}

static void setup_per_zone_lowmem_reserve(void);

void adjust_managed_page_count(struct page *page, long count)
{
	atomic_long_add(count, &page_zone(page)->managed_pages);
	totalram_pages_add(count);
	setup_per_zone_lowmem_reserve();
}
EXPORT_SYMBOL(adjust_managed_page_count);

unsigned long free_reserved_area(void *start, void *end, int poison, const char *s)
{
	void *pos;
	unsigned long pages = 0;

	start = (void *)PAGE_ALIGN((unsigned long)start);
	end = (void *)((unsigned long)end & PAGE_MASK);
	for (pos = start; pos < end; pos += PAGE_SIZE, pages++) {
		struct page *page = virt_to_page(pos);
		void *direct_map_addr;

		/*
		 * 'direct_map_addr' might be different from 'pos'
		 * because some architectures' virt_to_page()
		 * work with aliases.  Getting the direct map
		 * address ensures that we get a _writeable_
		 * alias for the memset().
		 */
		direct_map_addr = page_address(page);
		/*
		 * Perform a kasan-unchecked memset() since this memory
		 * has not been initialized.
		 */
		direct_map_addr = kasan_reset_tag(direct_map_addr);
		if ((unsigned int)poison <= 0xFF)
			memset(direct_map_addr, poison, PAGE_SIZE);

		free_reserved_page(page);
	}

	if (pages && s)
		pr_info("Freeing %s memory: %ldK\n", s, K(pages));

	return pages;
}

void free_reserved_page(struct page *page)
{
	clear_page_tag_ref(page);
	ClearPageReserved(page);
	init_page_count(page);
	__free_page(page);
	adjust_managed_page_count(page, 1);
}
EXPORT_SYMBOL(free_reserved_page);

static int page_alloc_cpu_dead(unsigned int cpu)
{
	struct zone *zone;

	lru_add_drain_cpu(cpu);
	mlock_drain_remote(cpu);
	drain_pages(cpu);

	/*
	 * Spill the event counters of the dead processor
	 * into the current processors event counters.
	 * This artificially elevates the count of the current
	 * processor.
	 */
	vm_events_fold_cpu(cpu);

	/*
	 * Zero the differential counters of the dead processor
	 * so that the vm statistics are consistent.
	 *
	 * This is only okay since the processor is dead and cannot
	 * race with what we are doing.
	 */
	cpu_vm_stats_fold(cpu);

	for_each_populated_zone(zone)
		zone_pcp_update(zone, 0);

	return 0;
}

static int page_alloc_cpu_online(unsigned int cpu)
{
	struct zone *zone;

	for_each_populated_zone(zone)
		zone_pcp_update(zone, 1);
	return 0;
}

void __init page_alloc_init_cpuhp(void)
{
	int ret;

	ret = cpuhp_setup_state_nocalls(CPUHP_PAGE_ALLOC,
					"mm/page_alloc:pcp",
					page_alloc_cpu_online,
					page_alloc_cpu_dead);
	WARN_ON(ret < 0);
}

/*
 * calculate_totalreserve_pages - called when sysctl_lowmem_reserve_ratio
 *	or min_free_kbytes changes.
 */
static void calculate_totalreserve_pages(void)
{
	struct pglist_data *pgdat;
	unsigned long reserve_pages = 0;
	enum zone_type i, j;

	for_each_online_pgdat(pgdat) {

		pgdat->totalreserve_pages = 0;

		for (i = 0; i < MAX_NR_ZONES; i++) {
			struct zone *zone = pgdat->node_zones + i;
			long max = 0;
			unsigned long managed_pages = zone_managed_pages(zone);

			/* Find valid and maximum lowmem_reserve in the zone */
			for (j = i; j < MAX_NR_ZONES; j++) {
				if (zone->lowmem_reserve[j] > max)
					max = zone->lowmem_reserve[j];
			}

			/* we treat the high watermark as reserved pages. */
			max += high_wmark_pages(zone);

			if (max > managed_pages)
				max = managed_pages;

			pgdat->totalreserve_pages += max;

			reserve_pages += max;
		}
	}
	totalreserve_pages = reserve_pages;
	trace_mm_calculate_totalreserve_pages(totalreserve_pages);
}

/*
 * setup_per_zone_lowmem_reserve - called whenever
 *	sysctl_lowmem_reserve_ratio changes.  Ensures that each zone
 *	has a correct pages reserved value, so an adequate number of
 *	pages are left in the zone after a successful __alloc_pages().
 */
static void setup_per_zone_lowmem_reserve(void)
{
	struct pglist_data *pgdat;
	enum zone_type i, j;

	for_each_online_pgdat(pgdat) {
		for (i = 0; i < MAX_NR_ZONES - 1; i++) {
			struct zone *zone = &pgdat->node_zones[i];
			int ratio = sysctl_lowmem_reserve_ratio[i];
			bool clear = !ratio || !zone_managed_pages(zone);
			unsigned long managed_pages = 0;

			for (j = i + 1; j < MAX_NR_ZONES; j++) {
				struct zone *upper_zone = &pgdat->node_zones[j];

				managed_pages += zone_managed_pages(upper_zone);

				if (clear)
					zone->lowmem_reserve[j] = 0;
				else
					zone->lowmem_reserve[j] = managed_pages / ratio;
				trace_mm_setup_per_zone_lowmem_reserve(zone, upper_zone,
								       zone->lowmem_reserve[j]);
			}
		}
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

static void __setup_per_zone_wmarks(void)
{
	unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10);
	unsigned long lowmem_pages = 0;
	struct zone *zone;
	unsigned long flags;

	/* Calculate total number of !ZONE_HIGHMEM and !ZONE_MOVABLE pages */
	for_each_zone(zone) {
		if (!is_highmem(zone) && zone_idx(zone) != ZONE_MOVABLE)
			lowmem_pages += zone_managed_pages(zone);
	}

	for_each_zone(zone) {
		u64 tmp;

		spin_lock_irqsave(&zone->lock, flags);
		tmp = (u64)pages_min * zone_managed_pages(zone);
		tmp = div64_ul(tmp, lowmem_pages);
		if (is_highmem(zone) || zone_idx(zone) == ZONE_MOVABLE) {
			/*
			 * __GFP_HIGH and PF_MEMALLOC allocations usually don't
			 * need highmem and movable zones pages, so cap pages_min
			 * to a small  value here.
			 *
			 * The WMARK_HIGH-WMARK_LOW and (WMARK_LOW-WMARK_MIN)
			 * deltas control async page reclaim, and so should
			 * not be capped for highmem and movable zones.
			 */
			unsigned long min_pages;

			min_pages = zone_managed_pages(zone) / 1024;
			min_pages = clamp(min_pages, SWAP_CLUSTER_MAX, 128UL);
			zone->_watermark[WMARK_MIN] = min_pages;
		} else {
			/*
			 * If it's a lowmem zone, reserve a number of pages
			 * proportionate to the zone's size.
			 */
			zone->_watermark[WMARK_MIN] = tmp;
		}

		/*
		 * Set the kswapd watermarks distance according to the
		 * scale factor in proportion to available memory, but
		 * ensure a minimum size on small systems.
		 */
		tmp = max_t(u64, tmp >> 2,
			    mult_frac(zone_managed_pages(zone),
				      watermark_scale_factor, 10000));

		zone->watermark_boost = 0;
		zone->_watermark[WMARK_LOW]  = min_wmark_pages(zone) + tmp;
		zone->_watermark[WMARK_HIGH] = low_wmark_pages(zone) + tmp;
		zone->_watermark[WMARK_PROMO] = high_wmark_pages(zone) + tmp;
		trace_mm_setup_per_zone_wmarks(zone);

		spin_unlock_irqrestore(&zone->lock, flags);
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/**
 * setup_per_zone_wmarks - called when min_free_kbytes changes
 * or when memory is hot-{added|removed}
 *
 * Ensures that the watermark[min,low,high] values for each zone are set
 * correctly with respect to min_free_kbytes.
 */
void setup_per_zone_wmarks(void)
{
	struct zone *zone;
	static DEFINE_SPINLOCK(lock);

	spin_lock(&lock);
	__setup_per_zone_wmarks();
	spin_unlock(&lock);

	/*
	 * The watermark size have changed so update the pcpu batch
	 * and high limits or the limits may be inappropriate.
	 */
	for_each_zone(zone)
		zone_pcp_update(zone, 0);
}

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (256MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 *	min_free_kbytes = 4 * sqrt(lowmem_kbytes), for better accuracy:
 *	min_free_kbytes = sqrt(lowmem_kbytes * 16)
 *
 * which yields
 *
 * 16MB:	512k
 * 32MB:	724k
 * 64MB:	1024k
 * 128MB:	1448k
 * 256MB:	2048k
 * 512MB:	2896k
 * 1024MB:	4096k
 * 2048MB:	5792k
 * 4096MB:	8192k
 * 8192MB:	11584k
 * 16384MB:	16384k
 */
void calculate_min_free_kbytes(void)
{
	unsigned long lowmem_kbytes;
	int new_min_free_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);
	new_min_free_kbytes = int_sqrt(lowmem_kbytes * 16);

	if (new_min_free_kbytes > user_min_free_kbytes)
		min_free_kbytes = clamp(new_min_free_kbytes, 128, 262144);
	else
		pr_warn("min_free_kbytes is not updated to %d because user defined value %d is preferred\n",
				new_min_free_kbytes, user_min_free_kbytes);

}

int __meminit init_per_zone_wmark_min(void)
{
	calculate_min_free_kbytes();
	setup_per_zone_wmarks();
	refresh_zone_stat_thresholds();
	setup_per_zone_lowmem_reserve();

#ifdef CONFIG_NUMA
	setup_min_unmapped_ratio();
	setup_min_slab_ratio();
#endif

	khugepaged_min_free_kbytes_update();

	return 0;
}
postcore_initcall(init_per_zone_wmark_min)

/*
 * min_free_kbytes_sysctl_handler - just a wrapper around proc_dointvec() so
 *	that we can call two helper functions whenever min_free_kbytes
 *	changes.
 */
static int min_free_kbytes_sysctl_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
		user_min_free_kbytes = min_free_kbytes;
		setup_per_zone_wmarks();
	}
	return 0;
}

static int watermark_scale_factor_sysctl_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write)
		setup_per_zone_wmarks();

	return 0;
}

#ifdef CONFIG_NUMA
static void setup_min_unmapped_ratio(void)
{
	pg_data_t *pgdat;
	struct zone *zone;

	for_each_online_pgdat(pgdat)
		pgdat->min_unmapped_pages = 0;

	for_each_zone(zone)
		zone->zone_pgdat->min_unmapped_pages += (zone_managed_pages(zone) *
						         sysctl_min_unmapped_ratio) / 100;
}


static int sysctl_min_unmapped_ratio_sysctl_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	setup_min_unmapped_ratio();

	return 0;
}

static void setup_min_slab_ratio(void)
{
	pg_data_t *pgdat;
	struct zone *zone;

	for_each_online_pgdat(pgdat)
		pgdat->min_slab_pages = 0;

	for_each_zone(zone)
		zone->zone_pgdat->min_slab_pages += (zone_managed_pages(zone) *
						     sysctl_min_slab_ratio) / 100;
}

static int sysctl_min_slab_ratio_sysctl_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	setup_min_slab_ratio();

	return 0;
}
#endif

/*
 * lowmem_reserve_ratio_sysctl_handler - just a wrapper around
 *	proc_dointvec() so that we can call setup_per_zone_lowmem_reserve()
 *	whenever sysctl_lowmem_reserve_ratio changes.
 *
 * The reserve ratio obviously has absolutely no relation with the
 * minimum watermarks. The lowmem reserve ratio can only make sense
 * if in function of the boot time zone sizes.
 */
static int lowmem_reserve_ratio_sysctl_handler(const struct ctl_table *table,
		int write, void *buffer, size_t *length, loff_t *ppos)
{
	int i;

	proc_dointvec_minmax(table, write, buffer, length, ppos);

	for (i = 0; i < MAX_NR_ZONES; i++) {
		if (sysctl_lowmem_reserve_ratio[i] < 1)
			sysctl_lowmem_reserve_ratio[i] = 0;
	}

	setup_per_zone_lowmem_reserve();
	return 0;
}

/*
 * percpu_pagelist_high_fraction - changes the pcp->high for each zone on each
 * cpu. It is the fraction of total pages in each zone that a hot per cpu
 * pagelist can have before it gets flushed back to buddy allocator.
 */
static int percpu_pagelist_high_fraction_sysctl_handler(const struct ctl_table *table,
		int write, void *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int old_percpu_pagelist_high_fraction;
	int ret;

	mutex_lock(&pcp_batch_high_lock);
	old_percpu_pagelist_high_fraction = percpu_pagelist_high_fraction;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (!write || ret < 0)
		goto out;

	/* Sanity checking to avoid pcp imbalance */
	if (percpu_pagelist_high_fraction &&
	    percpu_pagelist_high_fraction < MIN_PERCPU_PAGELIST_HIGH_FRACTION) {
		percpu_pagelist_high_fraction = old_percpu_pagelist_high_fraction;
		ret = -EINVAL;
		goto out;
	}

	/* No change? */
	if (percpu_pagelist_high_fraction == old_percpu_pagelist_high_fraction)
		goto out;

	for_each_populated_zone(zone)
		zone_set_pageset_high_and_batch(zone, 0);
out:
	mutex_unlock(&pcp_batch_high_lock);
	return ret;
}

static const struct ctl_table page_alloc_sysctl_table[] = {
	{
		.procname	= "min_free_kbytes",
		.data		= &min_free_kbytes,
		.maxlen		= sizeof(min_free_kbytes),
		.mode		= 0644,
		.proc_handler	= min_free_kbytes_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "watermark_boost_factor",
		.data		= &watermark_boost_factor,
		.maxlen		= sizeof(watermark_boost_factor),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "watermark_scale_factor",
		.data		= &watermark_scale_factor,
		.maxlen		= sizeof(watermark_scale_factor),
		.mode		= 0644,
		.proc_handler	= watermark_scale_factor_sysctl_handler,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_THREE_THOUSAND,
	},
	{
		.procname	= "defrag_mode",
		.data		= &defrag_mode,
		.maxlen		= sizeof(defrag_mode),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "percpu_pagelist_high_fraction",
		.data		= &percpu_pagelist_high_fraction,
		.maxlen		= sizeof(percpu_pagelist_high_fraction),
		.mode		= 0644,
		.proc_handler	= percpu_pagelist_high_fraction_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "lowmem_reserve_ratio",
		.data		= &sysctl_lowmem_reserve_ratio,
		.maxlen		= sizeof(sysctl_lowmem_reserve_ratio),
		.mode		= 0644,
		.proc_handler	= lowmem_reserve_ratio_sysctl_handler,
	},
#ifdef CONFIG_NUMA
	{
		.procname	= "numa_zonelist_order",
		.data		= &numa_zonelist_order,
		.maxlen		= NUMA_ZONELIST_ORDER_LEN,
		.mode		= 0644,
		.proc_handler	= numa_zonelist_order_handler,
	},
	{
		.procname	= "min_unmapped_ratio",
		.data		= &sysctl_min_unmapped_ratio,
		.maxlen		= sizeof(sysctl_min_unmapped_ratio),
		.mode		= 0644,
		.proc_handler	= sysctl_min_unmapped_ratio_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "min_slab_ratio",
		.data		= &sysctl_min_slab_ratio,
		.maxlen		= sizeof(sysctl_min_slab_ratio),
		.mode		= 0644,
		.proc_handler	= sysctl_min_slab_ratio_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
#endif
};

void __init page_alloc_sysctl_init(void)
{
	register_sysctl_init("vm", page_alloc_sysctl_table);
}

#ifdef CONFIG_CONTIG_ALLOC
/* Usage: See admin-guide/dynamic-debug-howto.rst */
static void alloc_contig_dump_pages(struct list_head *page_list)
{
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, "migrate failure");

	if (DYNAMIC_DEBUG_BRANCH(descriptor)) {
		struct page *page;

		dump_stack();
		list_for_each_entry(page, page_list, lru)
			dump_page(page, "migration failure");
	}
}

/* [start, end) must belong to a single zone. */
static int __alloc_contig_migrate_range(struct compact_control *cc,
					unsigned long start, unsigned long end)
{
	/* This function is based on compact_zone() from compaction.c. */
	unsigned int nr_reclaimed;
	unsigned long pfn = start;
	unsigned int tries = 0;
	int ret = 0;
	struct migration_target_control mtc = {
		.nid = zone_to_nid(cc->zone),
		.gfp_mask = cc->gfp_mask,
		.reason = MR_CONTIG_RANGE,
	};

	lru_cache_disable();

	while (pfn < end || !list_empty(&cc->migratepages)) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (list_empty(&cc->migratepages)) {
			cc->nr_migratepages = 0;
			ret = isolate_migratepages_range(cc, pfn, end);
			if (ret && ret != -EAGAIN)
				break;
			pfn = cc->migrate_pfn;
			tries = 0;
		} else if (++tries == 5) {
			ret = -EBUSY;
			break;
		}

		nr_reclaimed = reclaim_clean_pages_from_list(cc->zone,
							&cc->migratepages);
		cc->nr_migratepages -= nr_reclaimed;

		ret = migrate_pages(&cc->migratepages, alloc_migration_target,
			NULL, (unsigned long)&mtc, cc->mode, MR_CONTIG_RANGE, NULL);

		/*
		 * On -ENOMEM, migrate_pages() bails out right away. It is pointless
		 * to retry again over this error, so do the same here.
		 */
		if (ret == -ENOMEM)
			break;
	}

	lru_cache_enable();
	if (ret < 0) {
		if (!(cc->gfp_mask & __GFP_NOWARN) && ret == -EBUSY)
			alloc_contig_dump_pages(&cc->migratepages);
		putback_movable_pages(&cc->migratepages);
	}

	return (ret < 0) ? ret : 0;
}

static void split_free_pages(struct list_head *list, gfp_t gfp_mask)
{
	int order;

	for (order = 0; order < NR_PAGE_ORDERS; order++) {
		struct page *page, *next;
		int nr_pages = 1 << order;

		list_for_each_entry_safe(page, next, &list[order], lru) {
			int i;

			post_alloc_hook(page, order, gfp_mask);
			set_page_refcounted(page);
			if (!order)
				continue;

			split_page(page, order);

			/* Add all subpages to the order-0 head, in sequence. */
			list_del(&page->lru);
			for (i = 0; i < nr_pages; i++)
				list_add_tail(&page[i].lru, &list[0]);
		}
	}
}

static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
{
	const gfp_t reclaim_mask = __GFP_IO | __GFP_FS | __GFP_RECLAIM;
	const gfp_t action_mask = __GFP_COMP | __GFP_RETRY_MAYFAIL | __GFP_NOWARN |
				  __GFP_ZERO | __GFP_ZEROTAGS | __GFP_SKIP_ZERO;
	const gfp_t cc_action_mask = __GFP_RETRY_MAYFAIL | __GFP_NOWARN;

	/*
	 * We are given the range to allocate; node, mobility and placement
	 * hints are irrelevant at this point. We'll simply ignore them.
	 */
	gfp_mask &= ~(GFP_ZONEMASK | __GFP_RECLAIMABLE | __GFP_WRITE |
		      __GFP_HARDWALL | __GFP_THISNODE | __GFP_MOVABLE);

	/*
	 * We only support most reclaim flags (but not NOFAIL/NORETRY), and
	 * selected action flags.
	 */
	if (gfp_mask & ~(reclaim_mask | action_mask))
		return -EINVAL;

	/*
	 * Flags to control page compaction/migration/reclaim, to free up our
	 * page range. Migratable pages are movable, __GFP_MOVABLE is implied
	 * for them.
	 *
	 * Traditionally we always had __GFP_RETRY_MAYFAIL set, keep doing that
	 * to not degrade callers.
	 */
	*gfp_cc_mask = (gfp_mask & (reclaim_mask | cc_action_mask)) |
			__GFP_MOVABLE | __GFP_RETRY_MAYFAIL;
	return 0;
}

/**
 * alloc_contig_range() -- tries to allocate given range of pages
 * @start:	start PFN to allocate
 * @end:	one-past-the-last PFN to allocate
 * @alloc_flags:	allocation information
 * @gfp_mask:	GFP mask. Node/zone/placement hints are ignored; only some
 *		action and reclaim modifiers are supported. Reclaim modifiers
 *		control allocation behavior during compaction/migration/reclaim.
 *
 * The PFN range does not have to be pageblock aligned. The PFN range must
 * belong to a single zone.
 *
 * The first thing this routine does is attempt to MIGRATE_ISOLATE all
 * pageblocks in the range.  Once isolated, the pageblocks should not
 * be modified by others.
 *
 * Return: zero on success or negative error code.  On success all
 * pages which PFN is in [start, end) are allocated for the caller and
 * need to be freed with free_contig_range().
 */
int alloc_contig_range_noprof(unsigned long start, unsigned long end,
			      acr_flags_t alloc_flags, gfp_t gfp_mask)
{
	unsigned long outer_start, outer_end;
	int ret = 0;

	struct compact_control cc = {
		.nr_migratepages = 0,
		.order = -1,
		.zone = page_zone(pfn_to_page(start)),
		.mode = MIGRATE_SYNC,
		.ignore_skip_hint = true,
		.no_set_skip_hint = true,
		.alloc_contig = true,
	};
	INIT_LIST_HEAD(&cc.migratepages);
	enum pb_isolate_mode mode = (alloc_flags & ACR_FLAGS_CMA) ?
					    PB_ISOLATE_MODE_CMA_ALLOC :
					    PB_ISOLATE_MODE_OTHER;

	gfp_mask = current_gfp_context(gfp_mask);
	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
		return -EINVAL;

	/*
	 * What we do here is we mark all pageblocks in range as
	 * MIGRATE_ISOLATE.  Because pageblock and max order pages may
	 * have different sizes, and due to the way page allocator
	 * work, start_isolate_page_range() has special handlings for this.
	 *
	 * Once the pageblocks are marked as MIGRATE_ISOLATE, we
	 * migrate the pages from an unaligned range (ie. pages that
	 * we are interested in). This will put all the pages in
	 * range back to page allocator as MIGRATE_ISOLATE.
	 *
	 * When this is done, we take the pages in range from page
	 * allocator removing them from the buddy system.  This way
	 * page allocator will never consider using them.
	 *
	 * This lets us mark the pageblocks back as
	 * MIGRATE_CMA/MIGRATE_MOVABLE so that free pages in the
	 * aligned range but not in the unaligned, original range are
	 * put back to page allocator so that buddy can use them.
	 */

	ret = start_isolate_page_range(start, end, mode);
	if (ret)
		goto done;

	drain_all_pages(cc.zone);

	/*
	 * In case of -EBUSY, we'd like to know which page causes problem.
	 * So, just fall through. test_pages_isolated() has a tracepoint
	 * which will report the busy page.
	 *
	 * It is possible that busy pages could become available before
	 * the call to test_pages_isolated, and the range will actually be
	 * allocated.  So, if we fall through be sure to clear ret so that
	 * -EBUSY is not accidentally used or returned to caller.
	 */
	ret = __alloc_contig_migrate_range(&cc, start, end);
	if (ret && ret != -EBUSY)
		goto done;

	/*
	 * When in-use hugetlb pages are migrated, they may simply be released
	 * back into the free hugepage pool instead of being returned to the
	 * buddy system.  After the migration of in-use huge pages is completed,
	 * we will invoke replace_free_hugepage_folios() to ensure that these
	 * hugepages are properly released to the buddy system.
	 */
	ret = replace_free_hugepage_folios(start, end);
	if (ret)
		goto done;

	/*
	 * Pages from [start, end) are within a pageblock_nr_pages
	 * aligned blocks that are marked as MIGRATE_ISOLATE.  What's
	 * more, all pages in [start, end) are free in page allocator.
	 * What we are going to do is to allocate all pages from
	 * [start, end) (that is remove them from page allocator).
	 *
	 * The only problem is that pages at the beginning and at the
	 * end of interesting range may be not aligned with pages that
	 * page allocator holds, ie. they can be part of higher order
	 * pages.  Because of this, we reserve the bigger range and
	 * once this is done free the pages we are not interested in.
	 *
	 * We don't have to hold zone->lock here because the pages are
	 * isolated thus they won't get removed from buddy.
	 */
	outer_start = find_large_buddy(start);

	/* Make sure the range is really isolated. */
	if (test_pages_isolated(outer_start, end, mode)) {
		ret = -EBUSY;
		goto done;
	}

	/* Grab isolated pages from freelists. */
	outer_end = isolate_freepages_range(&cc, outer_start, end);
	if (!outer_end) {
		ret = -EBUSY;
		goto done;
	}

	if (!(gfp_mask & __GFP_COMP)) {
		split_free_pages(cc.freepages, gfp_mask);

		/* Free head and tail (if any) */
		if (start != outer_start)
			free_contig_range(outer_start, start - outer_start);
		if (end != outer_end)
			free_contig_range(end, outer_end - end);
	} else if (start == outer_start && end == outer_end && is_power_of_2(end - start)) {
		struct page *head = pfn_to_page(start);
		int order = ilog2(end - start);

		check_new_pages(head, order);
		prep_new_page(head, order, gfp_mask, 0);
		set_page_refcounted(head);
	} else {
		ret = -EINVAL;
		WARN(true, "PFN range: requested [%lu, %lu), allocated [%lu, %lu)\n",
		     start, end, outer_start, outer_end);
	}
done:
	undo_isolate_page_range(start, end);
	return ret;
}
EXPORT_SYMBOL(alloc_contig_range_noprof);

static int __alloc_contig_pages(unsigned long start_pfn,
				unsigned long nr_pages, gfp_t gfp_mask)
{
	unsigned long end_pfn = start_pfn + nr_pages;

	return alloc_contig_range_noprof(start_pfn, end_pfn, ACR_FLAGS_NONE,
					 gfp_mask);
}

static bool pfn_range_valid_contig(struct zone *z, unsigned long start_pfn,
				   unsigned long nr_pages)
{
	unsigned long i, end_pfn = start_pfn + nr_pages;
	struct page *page;

	for (i = start_pfn; i < end_pfn; i++) {
		page = pfn_to_online_page(i);
		if (!page)
			return false;

		if (page_zone(page) != z)
			return false;

		if (PageReserved(page))
			return false;

		if (PageHuge(page))
			return false;
	}
	return true;
}

static bool zone_spans_last_pfn(const struct zone *zone,
				unsigned long start_pfn, unsigned long nr_pages)
{
	unsigned long last_pfn = start_pfn + nr_pages - 1;

	return zone_spans_pfn(zone, last_pfn);
}

/**
 * alloc_contig_pages() -- tries to find and allocate contiguous range of pages
 * @nr_pages:	Number of contiguous pages to allocate
 * @gfp_mask:	GFP mask. Node/zone/placement hints limit the search; only some
 *		action and reclaim modifiers are supported. Reclaim modifiers
 *		control allocation behavior during compaction/migration/reclaim.
 * @nid:	Target node
 * @nodemask:	Mask for other possible nodes
 *
 * This routine is a wrapper around alloc_contig_range(). It scans over zones
 * on an applicable zonelist to find a contiguous pfn range which can then be
 * tried for allocation with alloc_contig_range(). This routine is intended
 * for allocation requests which can not be fulfilled with the buddy allocator.
 *
 * The allocated memory is always aligned to a page boundary. If nr_pages is a
 * power of two, then allocated range is also guaranteed to be aligned to same
 * nr_pages (e.g. 1GB request would be aligned to 1GB).
 *
 * Allocated pages can be freed with free_contig_range() or by manually calling
 * __free_page() on each allocated page.
 *
 * Return: pointer to contiguous pages on success, or NULL if not successful.
 */
struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
				 int nid, nodemask_t *nodemask)
{
	unsigned long ret, pfn, flags;
	struct zonelist *zonelist;
	struct zone *zone;
	struct zoneref *z;

	zonelist = node_zonelist(nid, gfp_mask);
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(gfp_mask), nodemask) {
		spin_lock_irqsave(&zone->lock, flags);

		pfn = ALIGN(zone->zone_start_pfn, nr_pages);
		while (zone_spans_last_pfn(zone, pfn, nr_pages)) {
			if (pfn_range_valid_contig(zone, pfn, nr_pages)) {
				/*
				 * We release the zone lock here because
				 * alloc_contig_range() will also lock the zone
				 * at some point. If there's an allocation
				 * spinning on this lock, it may win the race
				 * and cause alloc_contig_range() to fail...
				 */
				spin_unlock_irqrestore(&zone->lock, flags);
				ret = __alloc_contig_pages(pfn, nr_pages,
							gfp_mask);
				if (!ret)
					return pfn_to_page(pfn);
				spin_lock_irqsave(&zone->lock, flags);
			}
			pfn += nr_pages;
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	}
	return NULL;
}
#endif /* CONFIG_CONTIG_ALLOC */

void free_contig_range(unsigned long pfn, unsigned long nr_pages)
{
	unsigned long count = 0;
	struct folio *folio = pfn_folio(pfn);

	if (folio_test_large(folio)) {
		int expected = folio_nr_pages(folio);

		if (nr_pages == expected)
			folio_put(folio);
		else
			WARN(true, "PFN %lu: nr_pages %lu != expected %d\n",
			     pfn, nr_pages, expected);
		return;
	}

	for (; nr_pages--; pfn++) {
		struct page *page = pfn_to_page(pfn);

		count += page_count(page) != 1;
		__free_page(page);
	}
	WARN(count != 0, "%lu pages are still in use!\n", count);
}
EXPORT_SYMBOL(free_contig_range);

/*
 * Effectively disable pcplists for the zone by setting the high limit to 0
 * and draining all cpus. A concurrent page freeing on another CPU that's about
 * to put the page on pcplist will either finish before the drain and the page
 * will be drained, or observe the new high limit and skip the pcplist.
 *
 * Must be paired with a call to zone_pcp_enable().
 */
void zone_pcp_disable(struct zone *zone)
{
	mutex_lock(&pcp_batch_high_lock);
	__zone_set_pageset_high_and_batch(zone, 0, 0, 1);
	__drain_all_pages(zone, true);
}

void zone_pcp_enable(struct zone *zone)
{
	__zone_set_pageset_high_and_batch(zone, zone->pageset_high_min,
		zone->pageset_high_max, zone->pageset_batch);
	mutex_unlock(&pcp_batch_high_lock);
}

void zone_pcp_reset(struct zone *zone)
{
	int cpu;
	struct per_cpu_zonestat *pzstats;

	if (zone->per_cpu_pageset != &boot_pageset) {
		for_each_online_cpu(cpu) {
			pzstats = per_cpu_ptr(zone->per_cpu_zonestats, cpu);
			drain_zonestat(zone, pzstats);
		}
		free_percpu(zone->per_cpu_pageset);
		zone->per_cpu_pageset = &boot_pageset;
		if (zone->per_cpu_zonestats != &boot_zonestats) {
			free_percpu(zone->per_cpu_zonestats);
			zone->per_cpu_zonestats = &boot_zonestats;
		}
	}
}

#ifdef CONFIG_MEMORY_HOTREMOVE
/*
 * All pages in the range must be in a single zone, must not contain holes,
 * must span full sections, and must be isolated before calling this function.
 *
 * Returns the number of managed (non-PageOffline()) pages in the range: the
 * number of pages for which memory offlining code must adjust managed page
 * counters using adjust_managed_page_count().
 */
unsigned long __offline_isolated_pages(unsigned long start_pfn,
		unsigned long end_pfn)
{
	unsigned long already_offline = 0, flags;
	unsigned long pfn = start_pfn;
	struct page *page;
	struct zone *zone;
	unsigned int order;

	offline_mem_sections(pfn, end_pfn);
	zone = page_zone(pfn_to_page(pfn));
	spin_lock_irqsave(&zone->lock, flags);
	while (pfn < end_pfn) {
		page = pfn_to_page(pfn);
		/*
		 * The HWPoisoned page may be not in buddy system, and
		 * page_count() is not 0.
		 */
		if (unlikely(!PageBuddy(page) && PageHWPoison(page))) {
			pfn++;
			continue;
		}
		/*
		 * At this point all remaining PageOffline() pages have a
		 * reference count of 0 and can simply be skipped.
		 */
		if (PageOffline(page)) {
			BUG_ON(page_count(page));
			BUG_ON(PageBuddy(page));
			already_offline++;
			pfn++;
			continue;
		}

		BUG_ON(page_count(page));
		BUG_ON(!PageBuddy(page));
		VM_WARN_ON(get_pageblock_migratetype(page) != MIGRATE_ISOLATE);
		order = buddy_order(page);
		del_page_from_free_list(page, zone, order, MIGRATE_ISOLATE);
		pfn += (1 << order);
	}
	spin_unlock_irqrestore(&zone->lock, flags);

	return end_pfn - start_pfn - already_offline;
}
#endif

/*
 * This function returns a stable result only if called under zone lock.
 */
bool is_free_buddy_page(const struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	unsigned int order;

	for (order = 0; order < NR_PAGE_ORDERS; order++) {
		const struct page *head = page - (pfn & ((1 << order) - 1));

		if (PageBuddy(head) &&
		    buddy_order_unsafe(head) >= order)
			break;
	}

	return order <= MAX_PAGE_ORDER;
}
EXPORT_SYMBOL(is_free_buddy_page);

#ifdef CONFIG_MEMORY_FAILURE
static inline void add_to_free_list(struct page *page, struct zone *zone,
				    unsigned int order, int migratetype,
				    bool tail)
{
	__add_to_free_list(page, zone, order, migratetype, tail);
	account_freepages(zone, 1 << order, migratetype);
}

/*
 * Break down a higher-order page in sub-pages, and keep our target out of
 * buddy allocator.
 */
static void break_down_buddy_pages(struct zone *zone, struct page *page,
				   struct page *target, int low, int high,
				   int migratetype)
{
	unsigned long size = 1 << high;
	struct page *current_buddy;

	while (high > low) {
		high--;
		size >>= 1;

		if (target >= &page[size]) {
			current_buddy = page;
			page = page + size;
		} else {
			current_buddy = page + size;
		}

		if (set_page_guard(zone, current_buddy, high))
			continue;

		add_to_free_list(current_buddy, zone, high, migratetype, false);
		set_buddy_order(current_buddy, high);
	}
}

/*
 * Take a page that will be marked as poisoned off the buddy allocator.
 */
bool take_page_off_buddy(struct page *page)
{
	struct zone *zone = page_zone(page);
	unsigned long pfn = page_to_pfn(page);
	unsigned long flags;
	unsigned int order;
	bool ret = false;

	spin_lock_irqsave(&zone->lock, flags);
	for (order = 0; order < NR_PAGE_ORDERS; order++) {
		struct page *page_head = page - (pfn & ((1 << order) - 1));
		int page_order = buddy_order(page_head);

		if (PageBuddy(page_head) && page_order >= order) {
			unsigned long pfn_head = page_to_pfn(page_head);
			int migratetype = get_pfnblock_migratetype(page_head,
								   pfn_head);

			del_page_from_free_list(page_head, zone, page_order,
						migratetype);
			break_down_buddy_pages(zone, page_head, page, 0,
						page_order, migratetype);
			SetPageHWPoisonTakenOff(page);
			ret = true;
			break;
		}
		if (page_count(page_head) > 0)
			break;
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	return ret;
}

/*
 * Cancel takeoff done by take_page_off_buddy().
 */
bool put_page_back_buddy(struct page *page)
{
	struct zone *zone = page_zone(page);
	unsigned long flags;
	bool ret = false;

	spin_lock_irqsave(&zone->lock, flags);
	if (put_page_testzero(page)) {
		unsigned long pfn = page_to_pfn(page);
		int migratetype = get_pfnblock_migratetype(page, pfn);

		ClearPageHWPoisonTakenOff(page);
		__free_one_page(page, pfn, zone, 0, migratetype, FPI_NONE);
		if (TestClearPageHWPoison(page)) {
			ret = true;
		}
	}
	spin_unlock_irqrestore(&zone->lock, flags);

	return ret;
}
#endif

#ifdef CONFIG_ZONE_DMA
bool has_managed_dma(void)
{
	struct pglist_data *pgdat;

	for_each_online_pgdat(pgdat) {
		struct zone *zone = &pgdat->node_zones[ZONE_DMA];

		if (managed_zone(zone))
			return true;
	}
	return false;
}
#endif /* CONFIG_ZONE_DMA */

#ifdef CONFIG_UNACCEPTED_MEMORY

static bool lazy_accept = true;

static int __init accept_memory_parse(char *p)
{
	if (!strcmp(p, "lazy")) {
		lazy_accept = true;
		return 0;
	} else if (!strcmp(p, "eager")) {
		lazy_accept = false;
		return 0;
	} else {
		return -EINVAL;
	}
}
early_param("accept_memory", accept_memory_parse);

static bool page_contains_unaccepted(struct page *page, unsigned int order)
{
	phys_addr_t start = page_to_phys(page);

	return range_contains_unaccepted_memory(start, PAGE_SIZE << order);
}

static void __accept_page(struct zone *zone, unsigned long *flags,
			  struct page *page)
{
	list_del(&page->lru);
	account_freepages(zone, -MAX_ORDER_NR_PAGES, MIGRATE_MOVABLE);
	__mod_zone_page_state(zone, NR_UNACCEPTED, -MAX_ORDER_NR_PAGES);
	__ClearPageUnaccepted(page);
	spin_unlock_irqrestore(&zone->lock, *flags);

	accept_memory(page_to_phys(page), PAGE_SIZE << MAX_PAGE_ORDER);

	__free_pages_ok(page, MAX_PAGE_ORDER, FPI_TO_TAIL);
}

void accept_page(struct page *page)
{
	struct zone *zone = page_zone(page);
	unsigned long flags;

	spin_lock_irqsave(&zone->lock, flags);
	if (!PageUnaccepted(page)) {
		spin_unlock_irqrestore(&zone->lock, flags);
		return;
	}

	/* Unlocks zone->lock */
	__accept_page(zone, &flags, page);
}

static bool try_to_accept_memory_one(struct zone *zone)
{
	unsigned long flags;
	struct page *page;

	spin_lock_irqsave(&zone->lock, flags);
	page = list_first_entry_or_null(&zone->unaccepted_pages,
					struct page, lru);
	if (!page) {
		spin_unlock_irqrestore(&zone->lock, flags);
		return false;
	}

	/* Unlocks zone->lock */
	__accept_page(zone, &flags, page);

	return true;
}

static bool cond_accept_memory(struct zone *zone, unsigned int order,
			       int alloc_flags)
{
	long to_accept, wmark;
	bool ret = false;

	if (list_empty(&zone->unaccepted_pages))
		return false;

	/* Bailout, since try_to_accept_memory_one() needs to take a lock */
	if (alloc_flags & ALLOC_TRYLOCK)
		return false;

	wmark = promo_wmark_pages(zone);

	/*
	 * Watermarks have not been initialized yet.
	 *
	 * Accepting one MAX_ORDER page to ensure progress.
	 */
	if (!wmark)
		return try_to_accept_memory_one(zone);

	/* How much to accept to get to promo watermark? */
	to_accept = wmark -
		    (zone_page_state(zone, NR_FREE_PAGES) -
		    __zone_watermark_unusable_free(zone, order, 0) -
		    zone_page_state(zone, NR_UNACCEPTED));

	while (to_accept > 0) {
		if (!try_to_accept_memory_one(zone))
			break;
		ret = true;
		to_accept -= MAX_ORDER_NR_PAGES;
	}

	return ret;
}

static bool __free_unaccepted(struct page *page)
{
	struct zone *zone = page_zone(page);
	unsigned long flags;

	if (!lazy_accept)
		return false;

	spin_lock_irqsave(&zone->lock, flags);
	list_add_tail(&page->lru, &zone->unaccepted_pages);
	account_freepages(zone, MAX_ORDER_NR_PAGES, MIGRATE_MOVABLE);
	__mod_zone_page_state(zone, NR_UNACCEPTED, MAX_ORDER_NR_PAGES);
	__SetPageUnaccepted(page);
	spin_unlock_irqrestore(&zone->lock, flags);

	return true;
}

#else

static bool page_contains_unaccepted(struct page *page, unsigned int order)
{
	return false;
}

static bool cond_accept_memory(struct zone *zone, unsigned int order,
			       int alloc_flags)
{
	return false;
}

static bool __free_unaccepted(struct page *page)
{
	BUILD_BUG();
	return false;
}

#endif /* CONFIG_UNACCEPTED_MEMORY */

/**
 * alloc_pages_nolock - opportunistic reentrant allocation from any context
 * @nid: node to allocate from
 * @order: allocation order size
 *
 * Allocates pages of a given order from the given node. This is safe to
 * call from any context (from atomic, NMI, and also reentrant
 * allocator -> tracepoint -> alloc_pages_nolock_noprof).
 * Allocation is best effort and to be expected to fail easily so nobody should
 * rely on the success. Failures are not reported via warn_alloc().
 * See always fail conditions below.
 *
 * Return: allocated page or NULL on failure. NULL does not mean EBUSY or EAGAIN.
 * It means ENOMEM. There is no reason to call it again and expect !NULL.
 */
struct page *alloc_pages_nolock_noprof(int nid, unsigned int order)
{
	/*
	 * Do not specify __GFP_DIRECT_RECLAIM, since direct claim is not allowed.
	 * Do not specify __GFP_KSWAPD_RECLAIM either, since wake up of kswapd
	 * is not safe in arbitrary context.
	 *
	 * These two are the conditions for gfpflags_allow_spinning() being true.
	 *
	 * Specify __GFP_NOWARN since failing alloc_pages_nolock() is not a reason
	 * to warn. Also warn would trigger printk() which is unsafe from
	 * various contexts. We cannot use printk_deferred_enter() to mitigate,
	 * since the running context is unknown.
	 *
	 * Specify __GFP_ZERO to make sure that call to kmsan_alloc_page() below
	 * is safe in any context. Also zeroing the page is mandatory for
	 * BPF use cases.
	 *
	 * Though __GFP_NOMEMALLOC is not checked in the code path below,
	 * specify it here to highlight that alloc_pages_nolock()
	 * doesn't want to deplete reserves.
	 */
	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_ZERO | __GFP_NOMEMALLOC
			| __GFP_ACCOUNT;
	unsigned int alloc_flags = ALLOC_TRYLOCK;
	struct alloc_context ac = { };
	struct page *page;

	/*
	 * In PREEMPT_RT spin_trylock() will call raw_spin_lock() which is
	 * unsafe in NMI. If spin_trylock() is called from hard IRQ the current
	 * task may be waiting for one rt_spin_lock, but rt_spin_trylock() will
	 * mark the task as the owner of another rt_spin_lock which will
	 * confuse PI logic, so return immediately if called form hard IRQ or
	 * NMI.
	 *
	 * Note, irqs_disabled() case is ok. This function can be called
	 * from raw_spin_lock_irqsave region.
	 */
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && (in_nmi() || in_hardirq()))
		return NULL;
	if (!pcp_allowed_order(order))
		return NULL;

	/* Bailout, since _deferred_grow_zone() needs to take a lock */
	if (deferred_pages_enabled())
		return NULL;

	if (nid == NUMA_NO_NODE)
		nid = numa_node_id();

	prepare_alloc_pages(alloc_gfp, order, nid, NULL, &ac,
			    &alloc_gfp, &alloc_flags);

	/*
	 * Best effort allocation from percpu free list.
	 * If it's empty attempt to spin_trylock zone->lock.
	 */
	page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);

	/* Unlike regular alloc_pages() there is no __alloc_pages_slowpath(). */

	if (page)
		set_page_refcounted(page);

	if (memcg_kmem_online() && page &&
	    unlikely(__memcg_kmem_charge_page(page, alloc_gfp, order) != 0)) {
		free_pages_nolock(page, order);
		page = NULL;
	}
	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
	kmsan_alloc_page(page, order, alloc_gfp);
	return page;
}
