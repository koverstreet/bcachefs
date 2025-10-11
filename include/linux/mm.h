/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/errno.h>
#include <linux/mmdebug.h>
#include <linux/gfp.h>
#include <linux/pgalloc_tag.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/rbtree.h>
#include <linux/atomic.h>
#include <linux/debug_locks.h>
#include <linux/compiler.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/range.h>
#include <linux/pfn.h>
#include <linux/percpu-refcount.h>
#include <linux/bit_spinlock.h>
#include <linux/shrinker.h>
#include <linux/resource.h>
#include <linux/page_ext.h>
#include <linux/err.h>
#include <linux/page-flags.h>
#include <linux/page_ref.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <linux/kasan.h>
#include <linux/memremap.h>
#include <linux/slab.h>
#include <linux/cacheinfo.h>
#include <linux/rcuwait.h>

struct mempolicy;
struct anon_vma;
struct anon_vma_chain;
struct user_struct;
struct pt_regs;
struct folio_batch;

void arch_mm_preinit(void);
void mm_core_init(void);
void init_mm_internals(void);

extern atomic_long_t _totalram_pages;
static inline unsigned long totalram_pages(void)
{
	return (unsigned long)atomic_long_read(&_totalram_pages);
}

static inline void totalram_pages_inc(void)
{
	atomic_long_inc(&_totalram_pages);
}

static inline void totalram_pages_dec(void)
{
	atomic_long_dec(&_totalram_pages);
}

static inline void totalram_pages_add(long count)
{
	atomic_long_add(count, &_totalram_pages);
}

extern void * high_memory;

#ifdef CONFIG_SYSCTL
extern int sysctl_legacy_va_layout;
#else
#define sysctl_legacy_va_layout 0
#endif

#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
extern const int mmap_rnd_bits_min;
extern int mmap_rnd_bits_max __ro_after_init;
extern int mmap_rnd_bits __read_mostly;
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
extern const int mmap_rnd_compat_bits_min;
extern const int mmap_rnd_compat_bits_max;
extern int mmap_rnd_compat_bits __read_mostly;
#endif

#ifndef DIRECT_MAP_PHYSMEM_END
# ifdef MAX_PHYSMEM_BITS
# define DIRECT_MAP_PHYSMEM_END	((1ULL << MAX_PHYSMEM_BITS) - 1)
# else
# define DIRECT_MAP_PHYSMEM_END	(((phys_addr_t)-1)&~(1ULL<<63))
# endif
#endif

#include <asm/page.h>
#include <asm/processor.h>

#ifndef __pa_symbol
#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#endif

#ifndef page_to_virt
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#endif

#ifndef lm_alias
#define lm_alias(x)	__va(__pa_symbol(x))
#endif

/*
 * To prevent common memory management code establishing
 * a zero page mapping on a read fault.
 * This macro should be defined within <asm/pgtable.h>.
 * s390 does this to prevent multiplexing of hardware bits
 * related to the physical page in case of virtualization.
 */
#ifndef mm_forbids_zeropage
#define mm_forbids_zeropage(X)	(0)
#endif

/*
 * On some architectures it is expensive to call memset() for small sizes.
 * If an architecture decides to implement their own version of
 * mm_zero_struct_page they should wrap the defines below in a #ifndef and
 * define their own version of this macro in <asm/pgtable.h>
 */
#if BITS_PER_LONG == 64
/* This function must be updated when the size of struct page grows above 96
 * or reduces below 56. The idea that compiler optimizes out switch()
 * statement, and only leaves move/store instructions. Also the compiler can
 * combine write statements if they are both assignments and can be reordered,
 * this can result in several of the writes here being dropped.
 */
#define	mm_zero_struct_page(pp) __mm_zero_struct_page(pp)
static inline void __mm_zero_struct_page(struct page *page)
{
	unsigned long *_pp = (void *)page;

	 /* Check that struct page is either 56, 64, 72, 80, 88 or 96 bytes */
	BUILD_BUG_ON(sizeof(struct page) & 7);
	BUILD_BUG_ON(sizeof(struct page) < 56);
	BUILD_BUG_ON(sizeof(struct page) > 96);

	switch (sizeof(struct page)) {
	case 96:
		_pp[11] = 0;
		fallthrough;
	case 88:
		_pp[10] = 0;
		fallthrough;
	case 80:
		_pp[9] = 0;
		fallthrough;
	case 72:
		_pp[8] = 0;
		fallthrough;
	case 64:
		_pp[7] = 0;
		fallthrough;
	case 56:
		_pp[6] = 0;
		_pp[5] = 0;
		_pp[4] = 0;
		_pp[3] = 0;
		_pp[2] = 0;
		_pp[1] = 0;
		_pp[0] = 0;
	}
}
#else
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#endif

/*
 * Default maximum number of active map areas, this limits the number of vmas
 * per mm struct. Users can overwrite this number by sysctl but there is a
 * problem.
 *
 * When a program's coredump is generated as ELF format, a section is created
 * per a vma. In ELF, the number of sections is represented in unsigned short.
 * This means the number of sections should be smaller than 65535 at coredump.
 * Because the kernel adds some informative sections to a image of program at
 * generating coredump, we need some margin. The number of extra sections is
 * 1-3 now and depends on arch. We use "5" as safe margin, here.
 *
 * ELF extended numbering allows more than 65535 sections, so 16-bit bound is
 * not a hard limit any more. Although some userspace tools can be surprised by
 * that.
 */
#define MAPCOUNT_ELF_CORE_MARGIN	(5)
#define DEFAULT_MAX_MAP_COUNT	(USHRT_MAX - MAPCOUNT_ELF_CORE_MARGIN)

extern int sysctl_max_map_count;

extern unsigned long sysctl_user_reserve_kbytes;
extern unsigned long sysctl_admin_reserve_kbytes;

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
#else
#define nth_page(page,n) ((page) + (n))
#define folio_page_idx(folio, p)	((p) - &(folio)->page)
#endif

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* to align the pointer to the (prev) page boundary */
#define PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, PAGE_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

static inline struct folio *lru_to_folio(struct list_head *head)
{
	return list_entry((head)->prev, struct folio, lru);
}

void setup_initial_init_mm(void *start_code, void *end_code,
			   void *end_data, void *brk);

/*
 * Linux kernel virtual memory manager primitives.
 * The idea being to have a "virtual" mm in the same way
 * we have a virtual fs - giving a cleaner interface to the
 * mm details, and allowing different kinds of memory mappings
 * (from shared memory to executable loading to arbitrary
 * mmap() functions).
 */

struct vm_area_struct *vm_area_alloc(struct mm_struct *);
struct vm_area_struct *vm_area_dup(struct vm_area_struct *);
void vm_area_free(struct vm_area_struct *);

#ifndef CONFIG_MMU
extern struct rb_root nommu_region_tree;
extern struct rw_semaphore nommu_region_sem;

extern unsigned int kobjsize(const void *objp);
#endif

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 */
#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#ifdef CONFIG_MMU
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#else /* CONFIG_MMU */
#define VM_MAYOVERLAY	0x00000200	/* nommu: R/O MAP_PRIVATE mapping that might overlay a file mapping */
#define VM_UFFD_MISSING	0
#endif /* CONFIG_MMU */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_UFFD_WP	0x00001000	/* wrprotect pages tracking */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_LOCKONFAULT	0x00080000	/* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_SYNC		0x00800000	/* Synchronous page faults */
#define VM_ARCH_1	0x01000000	/* Architecture-specific flag */
#define VM_WIPEONFORK	0x02000000	/* Wipe VMA contents in child. */
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */

#ifdef CONFIG_MEM_SOFT_DIRTY
# define VM_SOFTDIRTY	0x08000000	/* Not soft dirty clean area */
#else
# define VM_SOFTDIRTY	0
#endif

#define VM_MIXEDMAP	0x10000000	/* Can contain "struct page" and pure PFN pages */
#define VM_HUGEPAGE	0x20000000	/* MADV_HUGEPAGE marked this vma */
#define VM_NOHUGEPAGE	0x40000000	/* MADV_NOHUGEPAGE marked this vma */
#define VM_MERGEABLE	0x80000000	/* KSM may merge identical pages */

#ifdef CONFIG_ARCH_USES_HIGH_VMA_FLAGS
#define VM_HIGH_ARCH_BIT_0	32	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_1	33	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_2	34	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_3	35	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_4	36	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_5	37	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_BIT_6	38	/* bit only usable on 64-bit architectures */
#define VM_HIGH_ARCH_0	BIT(VM_HIGH_ARCH_BIT_0)
#define VM_HIGH_ARCH_1	BIT(VM_HIGH_ARCH_BIT_1)
#define VM_HIGH_ARCH_2	BIT(VM_HIGH_ARCH_BIT_2)
#define VM_HIGH_ARCH_3	BIT(VM_HIGH_ARCH_BIT_3)
#define VM_HIGH_ARCH_4	BIT(VM_HIGH_ARCH_BIT_4)
#define VM_HIGH_ARCH_5	BIT(VM_HIGH_ARCH_BIT_5)
#define VM_HIGH_ARCH_6	BIT(VM_HIGH_ARCH_BIT_6)
#endif /* CONFIG_ARCH_USES_HIGH_VMA_FLAGS */

#ifdef CONFIG_ARCH_HAS_PKEYS
# define VM_PKEY_SHIFT VM_HIGH_ARCH_BIT_0
# define VM_PKEY_BIT0  VM_HIGH_ARCH_0
# define VM_PKEY_BIT1  VM_HIGH_ARCH_1
# define VM_PKEY_BIT2  VM_HIGH_ARCH_2
#if CONFIG_ARCH_PKEY_BITS > 3
# define VM_PKEY_BIT3  VM_HIGH_ARCH_3
#else
# define VM_PKEY_BIT3  0
#endif
#if CONFIG_ARCH_PKEY_BITS > 4
# define VM_PKEY_BIT4  VM_HIGH_ARCH_4
#else
# define VM_PKEY_BIT4  0
#endif
#endif /* CONFIG_ARCH_HAS_PKEYS */

#ifdef CONFIG_X86_USER_SHADOW_STACK
/*
 * VM_SHADOW_STACK should not be set with VM_SHARED because of lack of
 * support core mm.
 *
 * These VMAs will get a single end guard page. This helps userspace protect
 * itself from attacks. A single page is enough for current shadow stack archs
 * (x86). See the comments near alloc_shstk() in arch/x86/kernel/shstk.c
 * for more details on the guard size.
 */
# define VM_SHADOW_STACK	VM_HIGH_ARCH_5
#endif

#if defined(CONFIG_ARM64_GCS)
/*
 * arm64's Guarded Control Stack implements similar functionality and
 * has similar constraints to shadow stacks.
 */
# define VM_SHADOW_STACK	VM_HIGH_ARCH_6
#endif

#ifndef VM_SHADOW_STACK
# define VM_SHADOW_STACK	VM_NONE
#endif

#if defined(CONFIG_PPC64)
# define VM_SAO		VM_ARCH_1	/* Strong Access Ordering (powerpc) */
#elif defined(CONFIG_PARISC)
# define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_SPARC64)
# define VM_SPARC_ADI	VM_ARCH_1	/* Uses ADI tag for access control */
# define VM_ARCH_CLEAR	VM_SPARC_ADI
#elif defined(CONFIG_ARM64)
# define VM_ARM64_BTI	VM_ARCH_1	/* BTI guarded page, a.k.a. GP bit */
# define VM_ARCH_CLEAR	VM_ARM64_BTI
#elif !defined(CONFIG_MMU)
# define VM_MAPPED_COPY	VM_ARCH_1	/* T if mapped copy of data (nommu mmap) */
#endif

#if defined(CONFIG_ARM64_MTE)
# define VM_MTE		VM_HIGH_ARCH_4	/* Use Tagged memory for access control */
# define VM_MTE_ALLOWED	VM_HIGH_ARCH_5	/* Tagged memory permitted */
#else
# define VM_MTE		VM_NONE
# define VM_MTE_ALLOWED	VM_NONE
#endif

#ifndef VM_GROWSUP
# define VM_GROWSUP	VM_NONE
#endif

#ifdef CONFIG_HAVE_ARCH_USERFAULTFD_MINOR
# define VM_UFFD_MINOR_BIT	41
# define VM_UFFD_MINOR		BIT(VM_UFFD_MINOR_BIT)	/* UFFD minor faults */
#else /* !CONFIG_HAVE_ARCH_USERFAULTFD_MINOR */
# define VM_UFFD_MINOR		VM_NONE
#endif /* CONFIG_HAVE_ARCH_USERFAULTFD_MINOR */

/*
 * This flag is used to connect VFIO to arch specific KVM code. It
 * indicates that the memory under this VMA is safe for use with any
 * non-cachable memory type inside KVM. Some VFIO devices, on some
 * platforms, are thought to be unsafe and can cause machine crashes
 * if KVM does not lock down the memory type.
 */
#ifdef CONFIG_64BIT
#define VM_ALLOW_ANY_UNCACHED_BIT	39
#define VM_ALLOW_ANY_UNCACHED		BIT(VM_ALLOW_ANY_UNCACHED_BIT)
#else
#define VM_ALLOW_ANY_UNCACHED		VM_NONE
#endif

#ifdef CONFIG_64BIT
#define VM_DROPPABLE_BIT	40
#define VM_DROPPABLE		BIT(VM_DROPPABLE_BIT)
#elif defined(CONFIG_PPC32)
#define VM_DROPPABLE		VM_ARCH_1
#else
#define VM_DROPPABLE		VM_NONE
#endif

#ifdef CONFIG_64BIT
#define VM_SEALED_BIT	42
#define VM_SEALED	BIT(VM_SEALED_BIT)
#else
#define VM_SEALED	VM_NONE
#endif

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP (VM_RAND_READ | VM_SEQ_READ | VM_STACK_EARLY)

#define TASK_EXEC ((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0)

/* Common data flag combinations */
#define VM_DATA_FLAGS_TSK_EXEC	(VM_READ | VM_WRITE | TASK_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#define VM_DATA_FLAGS_NON_EXEC	(VM_READ | VM_WRITE | VM_MAYREAD | \
				 VM_MAYWRITE | VM_MAYEXEC)
#define VM_DATA_FLAGS_EXEC	(VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#ifndef VM_DATA_DEFAULT_FLAGS		/* arch can override this */
#define VM_DATA_DEFAULT_FLAGS  VM_DATA_FLAGS_EXEC
#endif

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#define VM_STARTGAP_FLAGS (VM_GROWSDOWN | VM_SHADOW_STACK)

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK	VM_GROWSUP
#define VM_STACK_EARLY	VM_GROWSDOWN
#else
#define VM_STACK	VM_GROWSDOWN
#define VM_STACK_EARLY	0
#endif

#define VM_STACK_FLAGS	(VM_STACK | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)

/* VMA basic access permission flags */
#define VM_ACCESS_FLAGS (VM_READ | VM_WRITE | VM_EXEC)


/*
 * Special vmas that are non-mergable, non-mlock()able.
 */
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)

/* This mask prevents VMA from being scanned with khugepaged */
#define VM_NO_KHUGEPAGED (VM_SPECIAL | VM_HUGETLB)

/* This mask defines which mm->def_flags a process can inherit its parent */
#define VM_INIT_DEF_MASK	VM_NOHUGEPAGE

/* This mask represents all the VMA flag bits used by mlock */
#define VM_LOCKED_MASK	(VM_LOCKED | VM_LOCKONFAULT)

/* Arch-specific flags to clear when updating VM flags on protection change */
#ifndef VM_ARCH_CLEAR
# define VM_ARCH_CLEAR	VM_NONE
#endif
#define VM_FLAGS_CLEAR	(ARCH_VM_PKEY_FLAGS | VM_ARCH_CLEAR)

/*
 * mapping from the currently active vm_flags protection bits (the
 * low four bits) to a page protection mask..
 */

/*
 * The default fault flags that should be used by most of the
 * arch-specific page fault handlers.
 */
#define FAULT_FLAG_DEFAULT  (FAULT_FLAG_ALLOW_RETRY | \
			     FAULT_FLAG_KILLABLE | \
			     FAULT_FLAG_INTERRUPTIBLE)

/**
 * fault_flag_allow_retry_first - check ALLOW_RETRY the first time
 * @flags: Fault flags.
 *
 * This is mostly used for places where we want to try to avoid taking
 * the mmap_lock for too long a time when waiting for another condition
 * to change, in which case we can try to be polite to release the
 * mmap_lock in the first round to avoid potential starvation of other
 * processes that would also want the mmap_lock.
 *
 * Return: true if the page fault allows retry and this is the first
 * attempt of the fault handling; false otherwise.
 */
static inline bool fault_flag_allow_retry_first(enum fault_flag flags)
{
	return (flags & FAULT_FLAG_ALLOW_RETRY) &&
	    (!(flags & FAULT_FLAG_TRIED));
}

#define FAULT_FLAG_TRACE \
	{ FAULT_FLAG_WRITE,		"WRITE" }, \
	{ FAULT_FLAG_MKWRITE,		"MKWRITE" }, \
	{ FAULT_FLAG_ALLOW_RETRY,	"ALLOW_RETRY" }, \
	{ FAULT_FLAG_RETRY_NOWAIT,	"RETRY_NOWAIT" }, \
	{ FAULT_FLAG_KILLABLE,		"KILLABLE" }, \
	{ FAULT_FLAG_TRIED,		"TRIED" }, \
	{ FAULT_FLAG_USER,		"USER" }, \
	{ FAULT_FLAG_REMOTE,		"REMOTE" }, \
	{ FAULT_FLAG_INSTRUCTION,	"INSTRUCTION" }, \
	{ FAULT_FLAG_INTERRUPTIBLE,	"INTERRUPTIBLE" }, \
	{ FAULT_FLAG_VMA_LOCK,		"VMA_LOCK" }

/*
 * vm_fault is filled by the pagefault handler and passed to the vma's
 * ->fault function. The vma's ->fault is responsible for returning a bitmask
 * of VM_FAULT_xxx flags that give details about how the fault was handled.
 *
 * MM layer fills up gfp_mask for page allocations but fault handler might
 * alter it if its implementation requires a different allocation context.
 *
 * pgoff should be used in favour of virtual_address, if possible.
 */
struct vm_fault {
	const struct {
		struct vm_area_struct *vma;	/* Target VMA */
		gfp_t gfp_mask;			/* gfp mask to be used for allocations */
		pgoff_t pgoff;			/* Logical page offset based on vma */
		unsigned long address;		/* Faulting virtual address - masked */
		unsigned long real_address;	/* Faulting virtual address - unmasked */
	};
	enum fault_flag flags;		/* FAULT_FLAG_xxx flags
					 * XXX: should really be 'const' */
	pmd_t *pmd;			/* Pointer to pmd entry matching
					 * the 'address' */
	pud_t *pud;			/* Pointer to pud entry matching
					 * the 'address'
					 */
	union {
		pte_t orig_pte;		/* Value of PTE at the time of fault */
		pmd_t orig_pmd;		/* Value of PMD at the time of fault,
					 * used by PMD fault only.
					 */
	};

	struct page *cow_page;		/* Page handler may use for COW fault */
	struct page *page;		/* ->fault handlers should return a
					 * page here, unless VM_FAULT_NOPAGE
					 * is set (which is also implied by
					 * VM_FAULT_ERROR).
					 */
	/* These three entries are valid only while holding ptl lock */
	pte_t *pte;			/* Pointer to pte entry matching
					 * the 'address'. NULL if the page
					 * table hasn't been allocated.
					 */
	spinlock_t *ptl;		/* Page table lock.
					 * Protects pte page table if 'pte'
					 * is not NULL, otherwise pmd.
					 */
	pgtable_t prealloc_pte;		/* Pre-allocated pte page table.
					 * vm_ops->map_pages() sets up a page
					 * table from atomic context.
					 * do_fault_around() pre-allocates
					 * page table to avoid allocation from
					 * atomic context.
					 */
};

/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs.
 */
struct vm_operations_struct {
	void (*open)(struct vm_area_struct * area);
	/**
	 * @close: Called when the VMA is being removed from the MM.
	 * Context: User context.  May sleep.  Caller holds mmap_lock.
	 */
	void (*close)(struct vm_area_struct * area);
	/* Called any time before splitting to check if it's allowed */
	int (*may_split)(struct vm_area_struct *area, unsigned long addr);
	int (*mremap)(struct vm_area_struct *area);
	/*
	 * Called by mprotect() to make driver-specific permission
	 * checks before mprotect() is finalised.   The VMA must not
	 * be modified.  Returns 0 if mprotect() can proceed.
	 */
	int (*mprotect)(struct vm_area_struct *vma, unsigned long start,
			unsigned long end, unsigned long newflags);
	vm_fault_t (*fault)(struct vm_fault *vmf);
	vm_fault_t (*huge_fault)(struct vm_fault *vmf, unsigned int order);
	vm_fault_t (*map_pages)(struct vm_fault *vmf,
			pgoff_t start_pgoff, pgoff_t end_pgoff);
	unsigned long (*pagesize)(struct vm_area_struct * area);

	/* notification that a previously read-only page is about to become
	 * writable, if an error is returned it will cause a SIGBUS */
	vm_fault_t (*page_mkwrite)(struct vm_fault *vmf);

	/* same as page_mkwrite when using VM_PFNMAP|VM_MIXEDMAP */
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *vmf);

	/* called by access_process_vm when get_user_pages() fails, typically
	 * for use by special VMAs. See also generic_access_phys() for a generic
	 * implementation useful for any iomem mapping.
	 */
	int (*access)(struct vm_area_struct *vma, unsigned long addr,
		      void *buf, int len, int write);

	/* Called by the /proc/PID/maps code to ask the vma whether it
	 * has a special name.  Returning non-NULL will also cause this
	 * vma to be dumped unconditionally. */
	const char *(*name)(struct vm_area_struct *vma);

#ifdef CONFIG_NUMA
	/*
	 * set_policy() op must add a reference to any non-NULL @new mempolicy
	 * to hold the policy upon return.  Caller should pass NULL @new to
	 * remove a policy and fall back to surrounding context--i.e. do not
	 * install a MPOL_DEFAULT policy, nor the task or system default
	 * mempolicy.
	 */
	int (*set_policy)(struct vm_area_struct *vma, struct mempolicy *new);

	/*
	 * get_policy() op must add reference [mpol_get()] to any policy at
	 * (vma,addr) marked as MPOL_SHARED.  The shared policy infrastructure
	 * in mm/mempolicy.c will do this automatically.
	 * get_policy() must NOT add a ref if the policy at (vma,addr) is not
	 * marked as MPOL_SHARED. vma policies are protected by the mmap_lock.
	 * If no [shared/vma] mempolicy exists at the addr, get_policy() op
	 * must return NULL--i.e., do not "fallback" to task or system default
	 * policy.
	 */
	struct mempolicy *(*get_policy)(struct vm_area_struct *vma,
					unsigned long addr, pgoff_t *ilx);
#endif
	/*
	 * Called by vm_normal_page() for special PTEs to find the
	 * page for @addr.  This is useful if the default behavior
	 * (using pte_page()) would not find the correct page.
	 */
	struct page *(*find_special_page)(struct vm_area_struct *vma,
					  unsigned long addr);
};

#ifdef CONFIG_NUMA_BALANCING
static inline void vma_numab_state_init(struct vm_area_struct *vma)
{
	vma->numab_state = NULL;
}
static inline void vma_numab_state_free(struct vm_area_struct *vma)
{
	kfree(vma->numab_state);
}
#else
static inline void vma_numab_state_init(struct vm_area_struct *vma) {}
static inline void vma_numab_state_free(struct vm_area_struct *vma) {}
#endif /* CONFIG_NUMA_BALANCING */

/*
 * These must be here rather than mmap_lock.h as dependent on vm_fault type,
 * declared in this header.
 */
#ifdef CONFIG_PER_VMA_LOCK
static inline void release_fault_lock(struct vm_fault *vmf)
{
	if (vmf->flags & FAULT_FLAG_VMA_LOCK)
		vma_end_read(vmf->vma);
	else
		mmap_read_unlock(vmf->vma->vm_mm);
}

static inline void assert_fault_locked(struct vm_fault *vmf)
{
	if (vmf->flags & FAULT_FLAG_VMA_LOCK)
		vma_assert_locked(vmf->vma);
	else
		mmap_assert_locked(vmf->vma->vm_mm);
}
#else
static inline void release_fault_lock(struct vm_fault *vmf)
{
	mmap_read_unlock(vmf->vma->vm_mm);
}

static inline void assert_fault_locked(struct vm_fault *vmf)
{
	mmap_assert_locked(vmf->vma->vm_mm);
}
#endif /* CONFIG_PER_VMA_LOCK */

extern const struct vm_operations_struct vma_dummy_vm_ops;

static inline void vma_init(struct vm_area_struct *vma, struct mm_struct *mm)
{
	memset(vma, 0, sizeof(*vma));
	vma->vm_mm = mm;
	vma->vm_ops = &vma_dummy_vm_ops;
	INIT_LIST_HEAD(&vma->anon_vma_chain);
	vma_lock_init(vma, false);
}

/* Use when VMA is not part of the VMA tree and needs no locking */
static inline void vm_flags_init(struct vm_area_struct *vma,
				 vm_flags_t flags)
{
	ACCESS_PRIVATE(vma, __vm_flags) = flags;
}

/*
 * Use when VMA is part of the VMA tree and modifications need coordination
 * Note: vm_flags_reset and vm_flags_reset_once do not lock the vma and
 * it should be locked explicitly beforehand.
 */
static inline void vm_flags_reset(struct vm_area_struct *vma,
				  vm_flags_t flags)
{
	vma_assert_write_locked(vma);
	vm_flags_init(vma, flags);
}

static inline void vm_flags_reset_once(struct vm_area_struct *vma,
				       vm_flags_t flags)
{
	vma_assert_write_locked(vma);
	WRITE_ONCE(ACCESS_PRIVATE(vma, __vm_flags), flags);
}

static inline void vm_flags_set(struct vm_area_struct *vma,
				vm_flags_t flags)
{
	vma_start_write(vma);
	ACCESS_PRIVATE(vma, __vm_flags) |= flags;
}

static inline void vm_flags_clear(struct vm_area_struct *vma,
				  vm_flags_t flags)
{
	vma_start_write(vma);
	ACCESS_PRIVATE(vma, __vm_flags) &= ~flags;
}

/*
 * Use only if VMA is not part of the VMA tree or has no other users and
 * therefore needs no locking.
 */
static inline void __vm_flags_mod(struct vm_area_struct *vma,
				  vm_flags_t set, vm_flags_t clear)
{
	vm_flags_init(vma, (vma->vm_flags | set) & ~clear);
}

/*
 * Use only when the order of set/clear operations is unimportant, otherwise
 * use vm_flags_{set|clear} explicitly.
 */
static inline void vm_flags_mod(struct vm_area_struct *vma,
				vm_flags_t set, vm_flags_t clear)
{
	vma_start_write(vma);
	__vm_flags_mod(vma, set, clear);
}

static inline void vma_set_anonymous(struct vm_area_struct *vma)
{
	vma->vm_ops = NULL;
}

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
	return !vma->vm_ops;
}

/*
 * Indicate if the VMA is a heap for the given task; for
 * /proc/PID/maps that is the heap of the main task.
 */
static inline bool vma_is_initial_heap(const struct vm_area_struct *vma)
{
	return vma->vm_start < vma->vm_mm->brk &&
		vma->vm_end > vma->vm_mm->start_brk;
}

/*
 * Indicate if the VMA is a stack for the given task; for
 * /proc/PID/maps that is the stack of the main task.
 */
static inline bool vma_is_initial_stack(const struct vm_area_struct *vma)
{
	/*
	 * We make no effort to guess what a given thread considers to be
	 * its "stack".  It's not even well-defined for programs written
	 * languages like Go.
	 */
	return vma->vm_start <= vma->vm_mm->start_stack &&
		vma->vm_end >= vma->vm_mm->start_stack;
}

static inline bool vma_is_temporary_stack(struct vm_area_struct *vma)
{
	int maybe_stack = vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP);

	if (!maybe_stack)
		return false;

	if ((vma->vm_flags & VM_STACK_INCOMPLETE_SETUP) ==
						VM_STACK_INCOMPLETE_SETUP)
		return true;

	return false;
}

static inline bool vma_is_foreign(struct vm_area_struct *vma)
{
	if (!current->mm)
		return true;

	if (current->mm != vma->vm_mm)
		return true;

	return false;
}

static inline bool vma_is_accessible(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_ACCESS_FLAGS;
}

static inline bool is_shared_maywrite(vm_flags_t vm_flags)
{
	return (vm_flags & (VM_SHARED | VM_MAYWRITE)) ==
		(VM_SHARED | VM_MAYWRITE);
}

static inline bool vma_is_shared_maywrite(struct vm_area_struct *vma)
{
	return is_shared_maywrite(vma->vm_flags);
}

static inline
struct vm_area_struct *vma_find(struct vma_iterator *vmi, unsigned long max)
{
	return mas_find(&vmi->mas, max - 1);
}

static inline struct vm_area_struct *vma_next(struct vma_iterator *vmi)
{
	/*
	 * Uses mas_find() to get the first VMA when the iterator starts.
	 * Calling mas_next() could skip the first entry.
	 */
	return mas_find(&vmi->mas, ULONG_MAX);
}

static inline
struct vm_area_struct *vma_iter_next_range(struct vma_iterator *vmi)
{
	return mas_next_range(&vmi->mas, ULONG_MAX);
}


static inline struct vm_area_struct *vma_prev(struct vma_iterator *vmi)
{
	return mas_prev(&vmi->mas, 0);
}

static inline int vma_iter_clear_gfp(struct vma_iterator *vmi,
			unsigned long start, unsigned long end, gfp_t gfp)
{
	__mas_set_range(&vmi->mas, start, end - 1);
	mas_store_gfp(&vmi->mas, NULL, gfp);
	if (unlikely(mas_is_err(&vmi->mas)))
		return -ENOMEM;

	return 0;
}

/* Free any unused preallocations */
static inline void vma_iter_free(struct vma_iterator *vmi)
{
	mas_destroy(&vmi->mas);
}

static inline int vma_iter_bulk_store(struct vma_iterator *vmi,
				      struct vm_area_struct *vma)
{
	vmi->mas.index = vma->vm_start;
	vmi->mas.last = vma->vm_end - 1;
	mas_store(&vmi->mas, vma);
	if (unlikely(mas_is_err(&vmi->mas)))
		return -ENOMEM;

	vma_mark_attached(vma);
	return 0;
}

static inline void vma_iter_invalidate(struct vma_iterator *vmi)
{
	mas_pause(&vmi->mas);
}

static inline void vma_iter_set(struct vma_iterator *vmi, unsigned long addr)
{
	mas_set(&vmi->mas, addr);
}

#define for_each_vma(__vmi, __vma)					\
	while (((__vma) = vma_next(&(__vmi))) != NULL)

/* The MM code likes to work with exclusive end addresses */
#define for_each_vma_range(__vmi, __vma, __end)				\
	while (((__vma) = vma_find(&(__vmi), (__end))) != NULL)

#ifdef CONFIG_SHMEM
/*
 * The vma_is_shmem is not inline because it is used only by slow
 * paths in userfault.
 */
bool vma_is_shmem(struct vm_area_struct *vma);
bool vma_is_anon_shmem(struct vm_area_struct *vma);
#else
static inline bool vma_is_shmem(struct vm_area_struct *vma) { return false; }
static inline bool vma_is_anon_shmem(struct vm_area_struct *vma) { return false; }
#endif

int vma_is_stack_for_current(struct vm_area_struct *vma);

/* flush_tlb_range() takes a vma, not a mm, and can care about flags */
#define TLB_FLUSH_VMA(mm,flags) { .vm_mm = (mm), .vm_flags = (flags) }

struct mmu_gather;
struct inode;

extern void prep_compound_page(struct page *page, unsigned int order);

static inline unsigned int folio_large_order(const struct folio *folio)
{
	return folio->_flags_1 & 0xff;
}

#ifdef NR_PAGES_IN_LARGE_FOLIO
static inline long folio_large_nr_pages(const struct folio *folio)
{
	return folio->_nr_pages;
}
#else
static inline long folio_large_nr_pages(const struct folio *folio)
{
	return 1L << folio_large_order(folio);
}
#endif

/*
 * compound_order() can be called without holding a reference, which means
 * that niceties like page_folio() don't work.  These callers should be
 * prepared to handle wild return values.  For example, PG_head may be
 * set before the order is initialised, or this may be a tail page.
 * See compaction.c for some good examples.
 */
static inline unsigned int compound_order(struct page *page)
{
	struct folio *folio = (struct folio *)page;

	if (!test_bit(PG_head, &folio->flags))
		return 0;
	return folio_large_order(folio);
}

/**
 * folio_order - The allocation order of a folio.
 * @folio: The folio.
 *
 * A folio is composed of 2^order pages.  See get_order() for the definition
 * of order.
 *
 * Return: The order of the folio.
 */
static inline unsigned int folio_order(const struct folio *folio)
{
	if (!folio_test_large(folio))
		return 0;
	return folio_large_order(folio);
}

/**
 * folio_reset_order - Reset the folio order and derived _nr_pages
 * @folio: The folio.
 *
 * Reset the order and derived _nr_pages to 0. Must only be used in the
 * process of splitting large folios.
 */
static inline void folio_reset_order(struct folio *folio)
{
	if (WARN_ON_ONCE(!folio_test_large(folio)))
		return;
	folio->_flags_1 &= ~0xffUL;
#ifdef NR_PAGES_IN_LARGE_FOLIO
	folio->_nr_pages = 0;
#endif
}

#include <linux/huge_mm.h>

/*
 * Methods to modify the page usage count.
 *
 * What counts for a page usage:
 * - cache mapping   (page->mapping)
 * - private data    (page->private)
 * - page mapped in a task's page tables, each mapping
 *   is counted separately
 *
 * Also, many kernel routines increase the page count before a critical
 * routine so they can be sure the page doesn't go away from under them.
 */

/*
 * Drop a ref, return true if the refcount fell to zero (the page has no users)
 */
static inline int put_page_testzero(struct page *page)
{
	VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);
	return page_ref_dec_and_test(page);
}

static inline int folio_put_testzero(struct folio *folio)
{
	return put_page_testzero(&folio->page);
}

/*
 * Try to grab a ref unless the page has a refcount of zero, return false if
 * that is the case.
 * This can be called when MMU is off so it must not access
 * any of the virtual mappings.
 */
static inline bool get_page_unless_zero(struct page *page)
{
	return page_ref_add_unless(page, 1, 0);
}

static inline struct folio *folio_get_nontail_page(struct page *page)
{
	if (unlikely(!get_page_unless_zero(page)))
		return NULL;
	return (struct folio *)page;
}

extern int page_is_ram(unsigned long pfn);

enum {
	REGION_INTERSECTS,
	REGION_DISJOINT,
	REGION_MIXED,
};

int region_intersects(resource_size_t offset, size_t size, unsigned long flags,
		      unsigned long desc);

/* Support for virtually mapped pages */
struct page *vmalloc_to_page(const void *addr);
unsigned long vmalloc_to_pfn(const void *addr);

/*
 * Determine if an address is within the vmalloc range
 *
 * On nommu, vmalloc/vfree wrap through kmalloc/kfree directly, so there
 * is no special casing required.
 */
#ifdef CONFIG_MMU
static inline bool is_vmalloc_addr_inlined(const void *x)
{
	unsigned long addr = (unsigned long)kasan_reset_tag(x);

	return addr >= VMALLOC_START && addr < VMALLOC_END;
}

extern bool is_vmalloc_addr(const void *x);
extern int is_vmalloc_or_module_addr(const void *x);
#else
static inline bool is_vmalloc_addr(const void *x)
{
	return false;
}
static inline int is_vmalloc_or_module_addr(const void *x)
{
	return 0;
}
#endif

/*
 * How many times the entire folio is mapped as a single unit (eg by a
 * PMD or PUD entry).  This is probably not what you want, except for
 * debugging purposes or implementation of other core folio_*() primitives.
 */
static inline int folio_entire_mapcount(const struct folio *folio)
{
	VM_BUG_ON_FOLIO(!folio_test_large(folio), folio);
	if (!IS_ENABLED(CONFIG_64BIT) && unlikely(folio_large_order(folio) == 1))
		return 0;
	return atomic_read(&folio->_entire_mapcount) + 1;
}

static inline int folio_large_mapcount(const struct folio *folio)
{
	VM_WARN_ON_FOLIO(!folio_test_large(folio), folio);
	return atomic_read(&folio->_large_mapcount) + 1;
}

/**
 * folio_mapcount() - Number of mappings of this folio.
 * @folio: The folio.
 *
 * The folio mapcount corresponds to the number of present user page table
 * entries that reference any part of a folio. Each such present user page
 * table entry must be paired with exactly on folio reference.
 *
 * For ordindary folios, each user page table entry (PTE/PMD/PUD/...) counts
 * exactly once.
 *
 * For hugetlb folios, each abstracted "hugetlb" user page table entry that
 * references the entire folio counts exactly once, even when such special
 * page table entries are comprised of multiple ordinary page table entries.
 *
 * Will report 0 for pages which cannot be mapped into userspace, such as
 * slab, page tables and similar.
 *
 * Return: The number of times this folio is mapped.
 */
static inline int folio_mapcount(const struct folio *folio)
{
	int mapcount;

	if (likely(!folio_test_large(folio))) {
		mapcount = atomic_read(&folio->_mapcount) + 1;
		if (page_mapcount_is_type(mapcount))
			mapcount = 0;
		return mapcount;
	}
	return folio_large_mapcount(folio);
}

/**
 * folio_mapped - Is this folio mapped into userspace?
 * @folio: The folio.
 *
 * Return: True if any page in this folio is referenced by user page tables.
 */
static inline bool folio_mapped(const struct folio *folio)
{
	return folio_mapcount(folio) >= 1;
}

/*
 * Return true if this page is mapped into pagetables.
 * For compound page it returns true if any sub-page of compound page is mapped,
 * even if this particular sub-page is not itself mapped by any PTE or PMD.
 */
static inline bool page_mapped(const struct page *page)
{
	return folio_mapped(page_folio(page));
}

static inline struct page *virt_to_head_page(const void *x)
{
	struct page *page = virt_to_page(x);

	return compound_head(page);
}

static inline struct folio *virt_to_folio(const void *x)
{
	struct page *page = virt_to_page(x);

	return page_folio(page);
}

void __folio_put(struct folio *folio);

void split_page(struct page *page, unsigned int order);
void folio_copy(struct folio *dst, struct folio *src);
int folio_mc_copy(struct folio *dst, struct folio *src);

unsigned long nr_free_buffer_pages(void);

/* Returns the number of bytes in this potentially compound page. */
static inline unsigned long page_size(struct page *page)
{
	return PAGE_SIZE << compound_order(page);
}

/* Returns the number of bits needed for the number of bytes in a page */
static inline unsigned int page_shift(struct page *page)
{
	return PAGE_SHIFT + compound_order(page);
}

/**
 * thp_order - Order of a transparent huge page.
 * @page: Head page of a transparent huge page.
 */
static inline unsigned int thp_order(struct page *page)
{
	VM_BUG_ON_PGFLAGS(PageTail(page), page);
	return compound_order(page);
}

/**
 * thp_size - Size of a transparent huge page.
 * @page: Head page of a transparent huge page.
 *
 * Return: Number of bytes in this page.
 */
static inline unsigned long thp_size(struct page *page)
{
	return PAGE_SIZE << thp_order(page);
}

#ifdef CONFIG_MMU
/*
 * Do pte_mkwrite, but only if the vma says VM_WRITE.  We do this when
 * servicing faults for write access.  In the normal case, do always want
 * pte_mkwrite.  But get_user_pages can cause write faults for mappings
 * that do not have writing enabled, when used by access_process_vm.
 */
static inline pte_t maybe_mkwrite(pte_t pte, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pte = pte_mkwrite(pte, vma);
	return pte;
}

vm_fault_t do_set_pmd(struct vm_fault *vmf, struct folio *folio, struct page *page);
void set_pte_range(struct vm_fault *vmf, struct folio *folio,
		struct page *page, unsigned int nr, unsigned long addr);

vm_fault_t finish_fault(struct vm_fault *vmf);
#endif

/*
 * Multiple processes may "see" the same page. E.g. for untouched
 * mappings of /dev/null, all processes see the same page full of
 * zeroes, and text pages of executables and shared libraries have
 * only one copy in memory, at most, normally.
 *
 * For the non-reserved pages, page_count(page) denotes a reference count.
 *   page_count() == 0 means the page is free. page->lru is then used for
 *   freelist management in the buddy allocator.
 *   page_count() > 0  means the page has been allocated.
 *
 * Pages are allocated by the slab allocator in order to provide memory
 * to kmalloc and kmem_cache_alloc. In this case, the management of the
 * page, and the fields in 'struct page' are the responsibility of mm/slab.c
 * unless a particular usage is carefully commented. (the responsibility of
 * freeing the kmalloc memory is the caller's, of course).
 *
 * A page may be used by anyone else who does a __get_free_page().
 * In this case, page_count still tracks the references, and should only
 * be used through the normal accessor functions. The top bits of page->flags
 * and page->virtual store page management information, but all other fields
 * are unused and could be used privately, carefully. The management of this
 * page is the responsibility of the one who allocated it, and those who have
 * subsequently been given references to it.
 *
 * The other pages (we may call them "pagecache pages") are completely
 * managed by the Linux memory manager: I/O, buffers, swapping etc.
 * The following discussion applies only to them.
 *
 * A pagecache page contains an opaque `private' member, which belongs to the
 * page's address_space. Usually, this is the address of a circular list of
 * the page's disk buffers. PG_private must be set to tell the VM to call
 * into the filesystem to release these pages.
 *
 * A folio may belong to an inode's memory mapping. In this case,
 * folio->mapping points to the inode, and folio->index is the file
 * offset of the folio, in units of PAGE_SIZE.
 *
 * If pagecache pages are not associated with an inode, they are said to be
 * anonymous pages. These may become associated with the swapcache, and in that
 * case PG_swapcache is set, and page->private is an offset into the swapcache.
 *
 * In either case (swapcache or inode backed), the pagecache itself holds one
 * reference to the page. Setting PG_private should also increment the
 * refcount. The each user mapping also has a reference to the page.
 *
 * The pagecache pages are stored in a per-mapping radix tree, which is
 * rooted at mapping->i_pages, and indexed by offset.
 * Where 2.4 and early 2.6 kernels kept dirty/clean pages in per-address_space
 * lists, we instead now tag pages as dirty/writeback in the radix tree.
 *
 * All pagecache pages may be subject to I/O:
 * - inode pages may need to be read from disk,
 * - inode pages which have been modified and are MAP_SHARED may need
 *   to be written back to the inode on disk,
 * - anonymous pages (including MAP_PRIVATE file mappings) which have been
 *   modified may need to be swapped out to swap space and (later) to be read
 *   back into memory.
 */

/* 127: arbitrary random number, small enough to assemble well */
#define folio_ref_zero_or_close_to_overflow(folio) \
	((unsigned int) folio_ref_count(folio) + 127u <= 127u)

/**
 * folio_get - Increment the reference count on a folio.
 * @folio: The folio.
 *
 * Context: May be called in any context, as long as you know that
 * you have a refcount on the folio.  If you do not already have one,
 * folio_try_get() may be the right interface for you to use.
 */
static inline void folio_get(struct folio *folio)
{
	VM_BUG_ON_FOLIO(folio_ref_zero_or_close_to_overflow(folio), folio);
	folio_ref_inc(folio);
}

static inline void get_page(struct page *page)
{
	struct folio *folio = page_folio(page);
	if (WARN_ON_ONCE(folio_test_slab(folio)))
		return;
	if (WARN_ON_ONCE(folio_test_large_kmalloc(folio)))
		return;
	folio_get(folio);
}

static inline __must_check bool try_get_page(struct page *page)
{
	page = compound_head(page);
	if (WARN_ON_ONCE(page_ref_count(page) <= 0))
		return false;
	page_ref_inc(page);
	return true;
}

/**
 * folio_put - Decrement the reference count on a folio.
 * @folio: The folio.
 *
 * If the folio's reference count reaches zero, the memory will be
 * released back to the page allocator and may be used by another
 * allocation immediately.  Do not access the memory or the struct folio
 * after calling folio_put() unless you can be sure that it wasn't the
 * last reference.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
static inline void folio_put(struct folio *folio)
{
	if (folio_put_testzero(folio))
		__folio_put(folio);
}

/**
 * folio_put_refs - Reduce the reference count on a folio.
 * @folio: The folio.
 * @refs: The amount to subtract from the folio's reference count.
 *
 * If the folio's reference count reaches zero, the memory will be
 * released back to the page allocator and may be used by another
 * allocation immediately.  Do not access the memory or the struct folio
 * after calling folio_put_refs() unless you can be sure that these weren't
 * the last references.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
static inline void folio_put_refs(struct folio *folio, int refs)
{
	if (folio_ref_sub_and_test(folio, refs))
		__folio_put(folio);
}

void folios_put_refs(struct folio_batch *folios, unsigned int *refs);

/*
 * union release_pages_arg - an array of pages or folios
 *
 * release_pages() releases a simple array of multiple pages, and
 * accepts various different forms of said page array: either
 * a regular old boring array of pages, an array of folios, or
 * an array of encoded page pointers.
 *
 * The transparent union syntax for this kind of "any of these
 * argument types" is all kinds of ugly, so look away.
 */
typedef union {
	struct page **pages;
	struct folio **folios;
	struct encoded_page **encoded_pages;
} release_pages_arg __attribute__ ((__transparent_union__));

void release_pages(release_pages_arg, int nr);

/**
 * folios_put - Decrement the reference count on an array of folios.
 * @folios: The folios.
 *
 * Like folio_put(), but for a batch of folios.  This is more efficient
 * than writing the loop yourself as it will optimise the locks which need
 * to be taken if the folios are freed.  The folios batch is returned
 * empty and ready to be reused for another batch; there is no need to
 * reinitialise it.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
static inline void folios_put(struct folio_batch *folios)
{
	folios_put_refs(folios, NULL);
}

static inline void put_page(struct page *page)
{
	struct folio *folio = page_folio(page);

	if (folio_test_slab(folio) || folio_test_large_kmalloc(folio))
		return;

	folio_put(folio);
}

/*
 * GUP_PIN_COUNTING_BIAS, and the associated functions that use it, overload
 * the page's refcount so that two separate items are tracked: the original page
 * reference count, and also a new count of how many pin_user_pages() calls were
 * made against the page. ("gup-pinned" is another term for the latter).
 *
 * With this scheme, pin_user_pages() becomes special: such pages are marked as
 * distinct from normal pages. As such, the unpin_user_page() call (and its
 * variants) must be used in order to release gup-pinned pages.
 *
 * Choice of value:
 *
 * By making GUP_PIN_COUNTING_BIAS a power of two, debugging of page reference
 * counts with respect to pin_user_pages() and unpin_user_page() becomes
 * simpler, due to the fact that adding an even power of two to the page
 * refcount has the effect of using only the upper N bits, for the code that
 * counts up using the bias value. This means that the lower bits are left for
 * the exclusive use of the original code that increments and decrements by one
 * (or at least, by much smaller values than the bias value).
 *
 * Of course, once the lower bits overflow into the upper bits (and this is
 * OK, because subtraction recovers the original values), then visual inspection
 * no longer suffices to directly view the separate counts. However, for normal
 * applications that don't have huge page reference counts, this won't be an
 * issue.
 *
 * Locking: the lockless algorithm described in folio_try_get_rcu()
 * provides safe operation for get_user_pages(), folio_mkclean() and
 * other calls that race to set up page table entries.
 */
#define GUP_PIN_COUNTING_BIAS (1U << 10)

void unpin_user_page(struct page *page);
void unpin_folio(struct folio *folio);
void unpin_user_pages_dirty_lock(struct page **pages, unsigned long npages,
				 bool make_dirty);
void unpin_user_page_range_dirty_lock(struct page *page, unsigned long npages,
				      bool make_dirty);
void unpin_user_pages(struct page **pages, unsigned long npages);
void unpin_user_folio(struct folio *folio, unsigned long npages);
void unpin_folios(struct folio **folios, unsigned long nfolios);

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

#ifndef CONFIG_MMU
static inline bool is_nommu_shared_mapping(vm_flags_t flags)
{
	/*
	 * NOMMU shared mappings are ordinary MAP_SHARED mappings and selected
	 * R/O MAP_PRIVATE file mappings that are an effective R/O overlay of
	 * a file mapping. R/O MAP_PRIVATE mappings might still modify
	 * underlying memory if ptrace is active, so this is only possible if
	 * ptrace does not apply. Note that there is no mprotect() to upgrade
	 * write permissions later.
	 */
	return flags & (VM_MAYSHARE | VM_MAYOVERLAY);
}
#endif

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define SECTION_IN_PAGE_FLAGS
#endif

/*
 * The identification function is mainly used by the buddy allocator for
 * determining if two pages could be buddies. We are not really identifying
 * the zone since we could be using the section number id if we do not have
 * node id available in page flags.
 * We only guarantee that it will return the same value for two combinable
 * pages in a zone.
 */
static inline int page_zone_id(struct page *page)
{
	return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

#ifdef NODE_NOT_IN_PAGE_FLAGS
int page_to_nid(const struct page *page);
#else
static inline int page_to_nid(const struct page *page)
{
	return (PF_POISONED_CHECK(page)->flags >> NODES_PGSHIFT) & NODES_MASK;
}
#endif

static inline int folio_nid(const struct folio *folio)
{
	return page_to_nid(&folio->page);
}

#ifdef CONFIG_NUMA_BALANCING
/* page access time bits needs to hold at least 4 seconds */
#define PAGE_ACCESS_TIME_MIN_BITS	12
#if LAST_CPUPID_SHIFT < PAGE_ACCESS_TIME_MIN_BITS
#define PAGE_ACCESS_TIME_BUCKETS				\
	(PAGE_ACCESS_TIME_MIN_BITS - LAST_CPUPID_SHIFT)
#else
#define PAGE_ACCESS_TIME_BUCKETS	0
#endif

#define PAGE_ACCESS_TIME_MASK				\
	(LAST_CPUPID_MASK << PAGE_ACCESS_TIME_BUCKETS)

static inline int cpu_pid_to_cpupid(int cpu, int pid)
{
	return ((cpu & LAST__CPU_MASK) << LAST__PID_SHIFT) | (pid & LAST__PID_MASK);
}

static inline int cpupid_to_pid(int cpupid)
{
	return cpupid & LAST__PID_MASK;
}

static inline int cpupid_to_cpu(int cpupid)
{
	return (cpupid >> LAST__PID_SHIFT) & LAST__CPU_MASK;
}

static inline int cpupid_to_nid(int cpupid)
{
	return cpu_to_node(cpupid_to_cpu(cpupid));
}

static inline bool cpupid_pid_unset(int cpupid)
{
	return cpupid_to_pid(cpupid) == (-1 & LAST__PID_MASK);
}

static inline bool cpupid_cpu_unset(int cpupid)
{
	return cpupid_to_cpu(cpupid) == (-1 & LAST__CPU_MASK);
}

static inline bool __cpupid_match_pid(pid_t task_pid, int cpupid)
{
	return (task_pid & LAST__PID_MASK) == cpupid_to_pid(cpupid);
}

#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
static inline int folio_xchg_last_cpupid(struct folio *folio, int cpupid)
{
	return xchg(&folio->_last_cpupid, cpupid & LAST_CPUPID_MASK);
}

static inline int folio_last_cpupid(struct folio *folio)
{
	return folio->_last_cpupid;
}
static inline void page_cpupid_reset_last(struct page *page)
{
	page->_last_cpupid = -1 & LAST_CPUPID_MASK;
}
#else
static inline int folio_last_cpupid(struct folio *folio)
{
	return (folio->flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK;
}

int folio_xchg_last_cpupid(struct folio *folio, int cpupid);

static inline void page_cpupid_reset_last(struct page *page)
{
	page->flags |= LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT;
}
#endif /* LAST_CPUPID_NOT_IN_PAGE_FLAGS */

static inline int folio_xchg_access_time(struct folio *folio, int time)
{
	int last_time;

	last_time = folio_xchg_last_cpupid(folio,
					   time >> PAGE_ACCESS_TIME_BUCKETS);
	return last_time << PAGE_ACCESS_TIME_BUCKETS;
}

static inline void vma_set_access_pid_bit(struct vm_area_struct *vma)
{
	unsigned int pid_bit;

	pid_bit = hash_32(current->pid, ilog2(BITS_PER_LONG));
	if (vma->numab_state && !test_bit(pid_bit, &vma->numab_state->pids_active[1])) {
		__set_bit(pid_bit, &vma->numab_state->pids_active[1]);
	}
}

bool folio_use_access_time(struct folio *folio);
#else /* !CONFIG_NUMA_BALANCING */
static inline int folio_xchg_last_cpupid(struct folio *folio, int cpupid)
{
	return folio_nid(folio); /* XXX */
}

static inline int folio_xchg_access_time(struct folio *folio, int time)
{
	return 0;
}

static inline int folio_last_cpupid(struct folio *folio)
{
	return folio_nid(folio); /* XXX */
}

static inline int cpupid_to_nid(int cpupid)
{
	return -1;
}

static inline int cpupid_to_pid(int cpupid)
{
	return -1;
}

static inline int cpupid_to_cpu(int cpupid)
{
	return -1;
}

static inline int cpu_pid_to_cpupid(int nid, int pid)
{
	return -1;
}

static inline bool cpupid_pid_unset(int cpupid)
{
	return true;
}

static inline void page_cpupid_reset_last(struct page *page)
{
}

static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
{
	return false;
}

static inline void vma_set_access_pid_bit(struct vm_area_struct *vma)
{
}
static inline bool folio_use_access_time(struct folio *folio)
{
	return false;
}
#endif /* CONFIG_NUMA_BALANCING */

#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)

/*
 * KASAN per-page tags are stored xor'ed with 0xff. This allows to avoid
 * setting tags for all pages to native kernel tag value 0xff, as the default
 * value 0x00 maps to 0xff.
 */

static inline u8 page_kasan_tag(const struct page *page)
{
	u8 tag = KASAN_TAG_KERNEL;

	if (kasan_enabled()) {
		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
		tag ^= 0xff;
	}

	return tag;
}

static inline void page_kasan_tag_set(struct page *page, u8 tag)
{
	unsigned long old_flags, flags;

	if (!kasan_enabled())
		return;

	tag ^= 0xff;
	old_flags = READ_ONCE(page->flags);
	do {
		flags = old_flags;
		flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
		flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
	} while (unlikely(!try_cmpxchg(&page->flags, &old_flags, flags)));
}

static inline void page_kasan_tag_reset(struct page *page)
{
	if (kasan_enabled())
		page_kasan_tag_set(page, KASAN_TAG_KERNEL);
}

#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */

static inline u8 page_kasan_tag(const struct page *page)
{
	return 0xff;
}

static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
static inline void page_kasan_tag_reset(struct page *page) { }

#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */

static inline struct zone *page_zone(const struct page *page)
{
	return &NODE_DATA(page_to_nid(page))->node_zones[page_zonenum(page)];
}

static inline pg_data_t *page_pgdat(const struct page *page)
{
	return NODE_DATA(page_to_nid(page));
}

static inline struct zone *folio_zone(const struct folio *folio)
{
	return page_zone(&folio->page);
}

static inline pg_data_t *folio_pgdat(const struct folio *folio)
{
	return page_pgdat(&folio->page);
}

#ifdef SECTION_IN_PAGE_FLAGS
static inline void set_page_section(struct page *page, unsigned long section)
{
	page->flags &= ~(SECTIONS_MASK << SECTIONS_PGSHIFT);
	page->flags |= (section & SECTIONS_MASK) << SECTIONS_PGSHIFT;
}

static inline unsigned long page_to_section(const struct page *page)
{
	return (page->flags >> SECTIONS_PGSHIFT) & SECTIONS_MASK;
}
#endif

/**
 * folio_pfn - Return the Page Frame Number of a folio.
 * @folio: The folio.
 *
 * A folio may contain multiple pages.  The pages have consecutive
 * Page Frame Numbers.
 *
 * Return: The Page Frame Number of the first page in the folio.
 */
static inline unsigned long folio_pfn(const struct folio *folio)
{
	return page_to_pfn(&folio->page);
}

static inline struct folio *pfn_folio(unsigned long pfn)
{
	return page_folio(pfn_to_page(pfn));
}

#ifdef CONFIG_MMU
static inline pte_t mk_pte(struct page *page, pgprot_t pgprot)
{
	return pfn_pte(page_to_pfn(page), pgprot);
}

/**
 * folio_mk_pte - Create a PTE for this folio
 * @folio: The folio to create a PTE for
 * @pgprot: The page protection bits to use
 *
 * Create a page table entry for the first page of this folio.
 * This is suitable for passing to set_ptes().
 *
 * Return: A page table entry suitable for mapping this folio.
 */
static inline pte_t folio_mk_pte(struct folio *folio, pgprot_t pgprot)
{
	return pfn_pte(folio_pfn(folio), pgprot);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/**
 * folio_mk_pmd - Create a PMD for this folio
 * @folio: The folio to create a PMD for
 * @pgprot: The page protection bits to use
 *
 * Create a page table entry for the first page of this folio.
 * This is suitable for passing to set_pmd_at().
 *
 * Return: A page table entry suitable for mapping this folio.
 */
static inline pmd_t folio_mk_pmd(struct folio *folio, pgprot_t pgprot)
{
	return pmd_mkhuge(pfn_pmd(folio_pfn(folio), pgprot));
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
/**
 * folio_mk_pud - Create a PUD for this folio
 * @folio: The folio to create a PUD for
 * @pgprot: The page protection bits to use
 *
 * Create a page table entry for the first page of this folio.
 * This is suitable for passing to set_pud_at().
 *
 * Return: A page table entry suitable for mapping this folio.
 */
static inline pud_t folio_mk_pud(struct folio *folio, pgprot_t pgprot)
{
	return pud_mkhuge(pfn_pud(folio_pfn(folio), pgprot));
}
#endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
#endif /* CONFIG_MMU */

static inline bool folio_has_pincount(const struct folio *folio)
{
	if (IS_ENABLED(CONFIG_64BIT))
		return folio_test_large(folio);
	return folio_order(folio) > 1;
}

/**
 * folio_maybe_dma_pinned - Report if a folio may be pinned for DMA.
 * @folio: The folio.
 *
 * This function checks if a folio has been pinned via a call to
 * a function in the pin_user_pages() family.
 *
 * For small folios, the return value is partially fuzzy: false is not fuzzy,
 * because it means "definitely not pinned for DMA", but true means "probably
 * pinned for DMA, but possibly a false positive due to having at least
 * GUP_PIN_COUNTING_BIAS worth of normal folio references".
 *
 * False positives are OK, because: a) it's unlikely for a folio to
 * get that many refcounts, and b) all the callers of this routine are
 * expected to be able to deal gracefully with a false positive.
 *
 * For most large folios, the result will be exactly correct. That's because
 * we have more tracking data available: the _pincount field is used
 * instead of the GUP_PIN_COUNTING_BIAS scheme.
 *
 * For more information, please see Documentation/core-api/pin_user_pages.rst.
 *
 * Return: True, if it is likely that the folio has been "dma-pinned".
 * False, if the folio is definitely not dma-pinned.
 */
static inline bool folio_maybe_dma_pinned(struct folio *folio)
{
	if (folio_has_pincount(folio))
		return atomic_read(&folio->_pincount) > 0;

	/*
	 * folio_ref_count() is signed. If that refcount overflows, then
	 * folio_ref_count() returns a negative value, and callers will avoid
	 * further incrementing the refcount.
	 *
	 * Here, for that overflow case, use the sign bit to count a little
	 * bit higher via unsigned math, and thus still get an accurate result.
	 */
	return ((unsigned int)folio_ref_count(folio)) >=
		GUP_PIN_COUNTING_BIAS;
}

/*
 * This should most likely only be called during fork() to see whether we
 * should break the cow immediately for an anon page on the src mm.
 *
 * The caller has to hold the PT lock and the vma->vm_mm->->write_protect_seq.
 */
static inline bool folio_needs_cow_for_dma(struct vm_area_struct *vma,
					  struct folio *folio)
{
	VM_BUG_ON(!(raw_read_seqcount(&vma->vm_mm->write_protect_seq) & 1));

	if (!test_bit(MMF_HAS_PINNED, &vma->vm_mm->flags))
		return false;

	return folio_maybe_dma_pinned(folio);
}

/**
 * is_zero_page - Query if a page is a zero page
 * @page: The page to query
 *
 * This returns true if @page is one of the permanent zero pages.
 */
static inline bool is_zero_page(const struct page *page)
{
	return is_zero_pfn(page_to_pfn(page));
}

/**
 * is_zero_folio - Query if a folio is a zero page
 * @folio: The folio to query
 *
 * This returns true if @folio is one of the permanent zero pages.
 */
static inline bool is_zero_folio(const struct folio *folio)
{
	return is_zero_page(&folio->page);
}

/* MIGRATE_CMA and ZONE_MOVABLE do not allow pin folios */
#ifdef CONFIG_MIGRATION
static inline bool folio_is_longterm_pinnable(struct folio *folio)
{
#ifdef CONFIG_CMA
	int mt = folio_migratetype(folio);

	if (mt == MIGRATE_CMA || mt == MIGRATE_ISOLATE)
		return false;
#endif
	/* The zero page can be "pinned" but gets special handling. */
	if (is_zero_folio(folio))
		return true;

	/* Coherent device memory must always allow eviction. */
	if (folio_is_device_coherent(folio))
		return false;

	/*
	 * Filesystems can only tolerate transient delays to truncate and
	 * hole-punch operations
	 */
	if (folio_is_fsdax(folio))
		return false;

	/* Otherwise, non-movable zone folios can be pinned. */
	return !folio_is_zone_movable(folio);

}
#else
static inline bool folio_is_longterm_pinnable(struct folio *folio)
{
	return true;
}
#endif

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void set_page_links(struct page *page, enum zone_type zone,
	unsigned long node, unsigned long pfn)
{
	set_page_zone(page, zone);
	set_page_node(page, node);
#ifdef SECTION_IN_PAGE_FLAGS
	set_page_section(page, pfn_to_section_nr(pfn));
#endif
}

/**
 * folio_nr_pages - The number of pages in the folio.
 * @folio: The folio.
 *
 * Return: A positive power of two.
 */
static inline long folio_nr_pages(const struct folio *folio)
{
	if (!folio_test_large(folio))
		return 1;
	return folio_large_nr_pages(folio);
}

/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
#define MAX_FOLIO_NR_PAGES	(1UL << PUD_ORDER)
#else
#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
#endif

/*
 * compound_nr() returns the number of pages in this potentially compound
 * page.  compound_nr() can be called on a tail page, and is defined to
 * return 1 in that case.
 */
static inline long compound_nr(struct page *page)
{
	struct folio *folio = (struct folio *)page;

	if (!test_bit(PG_head, &folio->flags))
		return 1;
	return folio_large_nr_pages(folio);
}

/**
 * folio_next - Move to the next physical folio.
 * @folio: The folio we're currently operating on.
 *
 * If you have physically contiguous memory which may span more than
 * one folio (eg a &struct bio_vec), use this function to move from one
 * folio to the next.  Do not use it if the memory is only virtually
 * contiguous as the folios are almost certainly not adjacent to each
 * other.  This is the folio equivalent to writing ``page++``.
 *
 * Context: We assume that the folios are refcounted and/or locked at a
 * higher level and do not adjust the reference counts.
 * Return: The next struct folio.
 */
static inline struct folio *folio_next(struct folio *folio)
{
	return (struct folio *)folio_page(folio, folio_nr_pages(folio));
}

/**
 * folio_shift - The size of the memory described by this folio.
 * @folio: The folio.
 *
 * A folio represents a number of bytes which is a power-of-two in size.
 * This function tells you which power-of-two the folio is.  See also
 * folio_size() and folio_order().
 *
 * Context: The caller should have a reference on the folio to prevent
 * it from being split.  It is not necessary for the folio to be locked.
 * Return: The base-2 logarithm of the size of this folio.
 */
static inline unsigned int folio_shift(const struct folio *folio)
{
	return PAGE_SHIFT + folio_order(folio);
}

/**
 * folio_size - The number of bytes in a folio.
 * @folio: The folio.
 *
 * Context: The caller should have a reference on the folio to prevent
 * it from being split.  It is not necessary for the folio to be locked.
 * Return: The number of bytes in this folio.
 */
static inline size_t folio_size(const struct folio *folio)
{
	return PAGE_SIZE << folio_order(folio);
}

/**
 * folio_maybe_mapped_shared - Whether the folio is mapped into the page
 *			       tables of more than one MM
 * @folio: The folio.
 *
 * This function checks if the folio maybe currently mapped into more than one
 * MM ("maybe mapped shared"), or if the folio is certainly mapped into a single
 * MM ("mapped exclusively").
 *
 * For KSM folios, this function also returns "mapped shared" when a folio is
 * mapped multiple times into the same MM, because the individual page mappings
 * are independent.
 *
 * For small anonymous folios and anonymous hugetlb folios, the return
 * value will be exactly correct: non-KSM folios can only be mapped at most once
 * into an MM, and they cannot be partially mapped. KSM folios are
 * considered shared even if mapped multiple times into the same MM.
 *
 * For other folios, the result can be fuzzy:
 *    #. For partially-mappable large folios (THP), the return value can wrongly
 *       indicate "mapped shared" (false positive) if a folio was mapped by
 *       more than two MMs at one point in time.
 *    #. For pagecache folios (including hugetlb), the return value can wrongly
 *       indicate "mapped shared" (false positive) when two VMAs in the same MM
 *       cover the same file range.
 *
 * Further, this function only considers current page table mappings that
 * are tracked using the folio mapcount(s).
 *
 * This function does not consider:
 *    #. If the folio might get mapped in the (near) future (e.g., swapcache,
 *       pagecache, temporary unmapping for migration).
 *    #. If the folio is mapped differently (VM_PFNMAP).
 *    #. If hugetlb page table sharing applies. Callers might want to check
 *       hugetlb_pmd_shared().
 *
 * Return: Whether the folio is estimated to be mapped into more than one MM.
 */
static inline bool folio_maybe_mapped_shared(struct folio *folio)
{
	int mapcount = folio_mapcount(folio);

	/* Only partially-mappable folios require more care. */
	if (!folio_test_large(folio) || unlikely(folio_test_hugetlb(folio)))
		return mapcount > 1;

	/*
	 * vm_insert_page() without CONFIG_TRANSPARENT_HUGEPAGE ...
	 * simply assume "mapped shared", nobody should really care
	 * about this for arbitrary kernel allocations.
	 */
	if (!IS_ENABLED(CONFIG_MM_ID))
		return true;

	/*
	 * A single mapping implies "mapped exclusively", even if the
	 * folio flag says something different: it's easier to handle this
	 * case here instead of on the RMAP hot path.
	 */
	if (mapcount <= 1)
		return false;
	return test_bit(FOLIO_MM_IDS_SHARED_BITNUM, &folio->_mm_ids);
}

/**
 * folio_expected_ref_count - calculate the expected folio refcount
 * @folio: the folio
 *
 * Calculate the expected folio refcount, taking references from the pagecache,
 * swapcache, PG_private and page table mappings into account. Useful in
 * combination with folio_ref_count() to detect unexpected references (e.g.,
 * GUP or other temporary references).
 *
 * Does currently not consider references from the LRU cache. If the folio
 * was isolated from the LRU (which is the case during migration or split),
 * the LRU cache does not apply.
 *
 * Calling this function on an unmapped folio -- !folio_mapped() -- that is
 * locked will return a stable result.
 *
 * Calling this function on a mapped folio will not result in a stable result,
 * because nothing stops additional page table mappings from coming (e.g.,
 * fork()) or going (e.g., munmap()).
 *
 * Calling this function without the folio lock will also not result in a
 * stable result: for example, the folio might get dropped from the swapcache
 * concurrently.
 *
 * However, even when called without the folio lock or on a mapped folio,
 * this function can be used to detect unexpected references early (for example,
 * if it makes sense to even lock the folio and unmap it).
 *
 * The caller must add any reference (e.g., from folio_try_get()) it might be
 * holding itself to the result.
 *
 * Returns the expected folio refcount.
 */
static inline int folio_expected_ref_count(const struct folio *folio)
{
	const int order = folio_order(folio);
	int ref_count = 0;

	if (WARN_ON_ONCE(page_has_type(&folio->page) && !folio_test_hugetlb(folio)))
		return 0;

	if (folio_test_anon(folio)) {
		/* One reference per page from the swapcache. */
		ref_count += folio_test_swapcache(folio) << order;
	} else {
		/* One reference per page from the pagecache. */
		ref_count += !!folio->mapping << order;
		/* One reference from PG_private. */
		ref_count += folio_test_private(folio);
	}

	/* One reference per page table mapping. */
	return ref_count + folio_mapcount(folio);
}

#ifndef HAVE_ARCH_MAKE_FOLIO_ACCESSIBLE
static inline int arch_make_folio_accessible(struct folio *folio)
{
	return 0;
}
#endif

/*
 * Some inline functions in vmstat.h depend on page_zone()
 */
#include <linux/vmstat.h>

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
static inline void *page_address(const struct page *page)
{
	return page->virtual;
}
static inline void set_page_address(struct page *page, void *address)
{
	page->virtual = address;
}
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(const struct page *page);
void set_page_address(struct page *page, void *virtual);
void page_address_init(void);
#endif

static __always_inline void *lowmem_page_address(const struct page *page)
{
	return page_to_virt(page);
}

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif

static inline void *folio_address(const struct folio *folio)
{
	return page_address(&folio->page);
}

/*
 * Return true only if the page has been allocated with
 * ALLOC_NO_WATERMARKS and the low watermark was not
 * met implying that the system is under some pressure.
 */
static inline bool page_is_pfmemalloc(const struct page *page)
{
	/*
	 * lru.next has bit 1 set if the page is allocated from the
	 * pfmemalloc reserves.  Callers may simply overwrite it if
	 * they do not need to preserve that information.
	 */
	return (uintptr_t)page->lru.next & BIT(1);
}

/*
 * Return true only if the folio has been allocated with
 * ALLOC_NO_WATERMARKS and the low watermark was not
 * met implying that the system is under some pressure.
 */
static inline bool folio_is_pfmemalloc(const struct folio *folio)
{
	/*
	 * lru.next has bit 1 set if the page is allocated from the
	 * pfmemalloc reserves.  Callers may simply overwrite it if
	 * they do not need to preserve that information.
	 */
	return (uintptr_t)folio->lru.next & BIT(1);
}

/*
 * Only to be called by the page allocator on a freshly allocated
 * page.
 */
static inline void set_page_pfmemalloc(struct page *page)
{
	page->lru.next = (void *)BIT(1);
}

static inline void clear_page_pfmemalloc(struct page *page)
{
	page->lru.next = NULL;
}

/*
 * Can be called by the pagefault handler when it gets a VM_FAULT_OOM.
 */
extern void pagefault_out_of_memory(void);

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define offset_in_folio(folio, p) ((unsigned long)(p) & (folio_size(folio) - 1))

/*
 * Parameter block passed down to zap_pte_range in exceptional cases.
 */
struct zap_details {
	struct folio *single_folio;	/* Locked folio to be unmapped */
	bool even_cows;			/* Zap COWed private pages too? */
	bool reclaim_pt;		/* Need reclaim page tables? */
	zap_flags_t zap_flags;		/* Extra flags for zapping */
};

/*
 * Whether to drop the pte markers, for example, the uffd-wp information for
 * file-backed memory.  This should only be specified when we will completely
 * drop the page in the mm, either by truncation or unmapping of the vma.  By
 * default, the flag is not set.
 */
#define  ZAP_FLAG_DROP_MARKER        ((__force zap_flags_t) BIT(0))
/* Set in unmap_vmas() to indicate a final unmap call.  Only used by hugetlb */
#define  ZAP_FLAG_UNMAP              ((__force zap_flags_t) BIT(1))

#ifdef CONFIG_SCHED_MM_CID
void sched_mm_cid_before_execve(struct task_struct *t);
void sched_mm_cid_after_execve(struct task_struct *t);
void sched_mm_cid_fork(struct task_struct *t);
void sched_mm_cid_exit_signals(struct task_struct *t);
static inline int task_mm_cid(struct task_struct *t)
{
	return t->mm_cid;
}
#else
static inline void sched_mm_cid_before_execve(struct task_struct *t) { }
static inline void sched_mm_cid_after_execve(struct task_struct *t) { }
static inline void sched_mm_cid_fork(struct task_struct *t) { }
static inline void sched_mm_cid_exit_signals(struct task_struct *t) { }
static inline int task_mm_cid(struct task_struct *t)
{
	/*
	 * Use the processor id as a fall-back when the mm cid feature is
	 * disabled. This provides functional per-cpu data structure accesses
	 * in user-space, althrough it won't provide the memory usage benefits.
	 */
	return raw_smp_processor_id();
}
#endif

#ifdef CONFIG_MMU
extern bool can_do_mlock(void);
#else
static inline bool can_do_mlock(void) { return false; }
#endif
extern int user_shm_lock(size_t, struct ucounts *);
extern void user_shm_unlock(size_t, struct ucounts *);

struct folio *vm_normal_folio(struct vm_area_struct *vma, unsigned long addr,
			     pte_t pte);
struct page *vm_normal_page(struct vm_area_struct *vma, unsigned long addr,
			     pte_t pte);
struct folio *vm_normal_folio_pmd(struct vm_area_struct *vma,
				  unsigned long addr, pmd_t pmd);
struct page *vm_normal_page_pmd(struct vm_area_struct *vma, unsigned long addr,
				pmd_t pmd);

void zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
		  unsigned long size);
void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
			   unsigned long size, struct zap_details *details);
static inline void zap_vma_pages(struct vm_area_struct *vma)
{
	zap_page_range_single(vma, vma->vm_start,
			      vma->vm_end - vma->vm_start, NULL);
}
void unmap_vmas(struct mmu_gather *tlb, struct ma_state *mas,
		struct vm_area_struct *start_vma, unsigned long start,
		unsigned long end, unsigned long tree_end, bool mm_wr_locked);

struct mmu_notifier_range;

void free_pgd_range(struct mmu_gather *tlb, unsigned long addr,
		unsigned long end, unsigned long floor, unsigned long ceiling);
int
copy_page_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma);
int generic_access_phys(struct vm_area_struct *vma, unsigned long addr,
			void *buf, int len, int write);

struct follow_pfnmap_args {
	/**
	 * Inputs:
	 * @vma: Pointer to @vm_area_struct struct
	 * @address: the virtual address to walk
	 */
	struct vm_area_struct *vma;
	unsigned long address;
	/**
	 * Internals:
	 *
	 * The caller shouldn't touch any of these.
	 */
	spinlock_t *lock;
	pte_t *ptep;
	/**
	 * Outputs:
	 *
	 * @pfn: the PFN of the address
	 * @addr_mask: address mask covering pfn
	 * @pgprot: the pgprot_t of the mapping
	 * @writable: whether the mapping is writable
	 * @special: whether the mapping is a special mapping (real PFN maps)
	 */
	unsigned long pfn;
	unsigned long addr_mask;
	pgprot_t pgprot;
	bool writable;
	bool special;
};
int follow_pfnmap_start(struct follow_pfnmap_args *args);
void follow_pfnmap_end(struct follow_pfnmap_args *args);

extern void truncate_pagecache(struct inode *inode, loff_t new);
extern void truncate_setsize(struct inode *inode, loff_t newsize);
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to);
void truncate_pagecache_range(struct inode *inode, loff_t offset, loff_t end);
int generic_error_remove_folio(struct address_space *mapping,
		struct folio *folio);

struct vm_area_struct *lock_mm_and_find_vma(struct mm_struct *mm,
		unsigned long address, struct pt_regs *regs);

#ifdef CONFIG_MMU
extern vm_fault_t handle_mm_fault(struct vm_area_struct *vma,
				  unsigned long address, unsigned int flags,
				  struct pt_regs *regs);
extern int fixup_user_fault(struct mm_struct *mm,
			    unsigned long address, unsigned int fault_flags,
			    bool *unlocked);
void unmap_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t nr, bool even_cows);
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows);
#else
static inline vm_fault_t handle_mm_fault(struct vm_area_struct *vma,
					 unsigned long address, unsigned int flags,
					 struct pt_regs *regs)
{
	/* should never happen if there's no MMU */
	BUG();
	return VM_FAULT_SIGBUS;
}
static inline int fixup_user_fault(struct mm_struct *mm, unsigned long address,
		unsigned int fault_flags, bool *unlocked)
{
	/* should never happen if there's no MMU */
	BUG();
	return -EFAULT;
}
static inline void unmap_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t nr, bool even_cows) { }
static inline void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows) { }
#endif

static inline void unmap_shared_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen)
{
	unmap_mapping_range(mapping, holebegin, holelen, 0);
}

static inline struct vm_area_struct *vma_lookup(struct mm_struct *mm,
						unsigned long addr);

extern int access_process_vm(struct task_struct *tsk, unsigned long addr,
		void *buf, int len, unsigned int gup_flags);
extern int access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags);

#ifdef CONFIG_BPF_SYSCALL
extern int copy_remote_vm_str(struct task_struct *tsk, unsigned long addr,
			      void *buf, int len, unsigned int gup_flags);
#endif

long get_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked);
long pin_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked);

/*
 * Retrieves a single page alongside its VMA. Does not support FOLL_NOWAIT.
 */
static inline struct page *get_user_page_vma_remote(struct mm_struct *mm,
						    unsigned long addr,
						    int gup_flags,
						    struct vm_area_struct **vmap)
{
	struct page *page;
	struct vm_area_struct *vma;
	int got;

	if (WARN_ON_ONCE(unlikely(gup_flags & FOLL_NOWAIT)))
		return ERR_PTR(-EINVAL);

	got = get_user_pages_remote(mm, addr, 1, gup_flags, &page, NULL);

	if (got < 0)
		return ERR_PTR(got);

	vma = vma_lookup(mm, addr);
	if (WARN_ON_ONCE(!vma)) {
		put_page(page);
		return ERR_PTR(-EINVAL);
	}

	*vmap = vma;
	return page;
}

long get_user_pages(unsigned long start, unsigned long nr_pages,
		    unsigned int gup_flags, struct page **pages);
long pin_user_pages(unsigned long start, unsigned long nr_pages,
		    unsigned int gup_flags, struct page **pages);
long get_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
		    struct page **pages, unsigned int gup_flags);
long pin_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
		    struct page **pages, unsigned int gup_flags);
long memfd_pin_folios(struct file *memfd, loff_t start, loff_t end,
		      struct folio **folios, unsigned int max_folios,
		      pgoff_t *offset);
int folio_add_pins(struct folio *folio, unsigned int pins);

int get_user_pages_fast(unsigned long start, int nr_pages,
			unsigned int gup_flags, struct page **pages);
int pin_user_pages_fast(unsigned long start, int nr_pages,
			unsigned int gup_flags, struct page **pages);
void folio_add_pin(struct folio *folio);

int account_locked_vm(struct mm_struct *mm, unsigned long pages, bool inc);
int __account_locked_vm(struct mm_struct *mm, unsigned long pages, bool inc,
			struct task_struct *task, bool bypass_rlim);

struct kvec;
struct page *get_dump_page(unsigned long addr, int *locked);

bool folio_mark_dirty(struct folio *folio);
bool folio_mark_dirty_lock(struct folio *folio);
bool set_page_dirty(struct page *page);
int set_page_dirty_lock(struct page *page);

int get_cmdline(struct task_struct *task, char *buffer, int buflen);

/*
 * Flags used by change_protection().  For now we make it a bitmap so
 * that we can pass in multiple flags just like parameters.  However
 * for now all the callers are only use one of the flags at the same
 * time.
 */
/*
 * Whether we should manually check if we can map individual PTEs writable,
 * because something (e.g., COW, uffd-wp) blocks that from happening for all
 * PTEs automatically in a writable mapping.
 */
#define  MM_CP_TRY_CHANGE_WRITABLE	   (1UL << 0)
/* Whether this protection change is for NUMA hints */
#define  MM_CP_PROT_NUMA                   (1UL << 1)
/* Whether this change is for write protecting */
#define  MM_CP_UFFD_WP                     (1UL << 2) /* do wp */
#define  MM_CP_UFFD_WP_RESOLVE             (1UL << 3) /* Resolve wp */
#define  MM_CP_UFFD_WP_ALL                 (MM_CP_UFFD_WP | \
					    MM_CP_UFFD_WP_RESOLVE)

bool can_change_pte_writable(struct vm_area_struct *vma, unsigned long addr,
			     pte_t pte);
extern long change_protection(struct mmu_gather *tlb,
			      struct vm_area_struct *vma, unsigned long start,
			      unsigned long end, unsigned long cp_flags);
extern int mprotect_fixup(struct vma_iterator *vmi, struct mmu_gather *tlb,
	  struct vm_area_struct *vma, struct vm_area_struct **pprev,
	  unsigned long start, unsigned long end, vm_flags_t newflags);

/*
 * doesn't attempt to fault and will return short.
 */
int get_user_pages_fast_only(unsigned long start, int nr_pages,
			     unsigned int gup_flags, struct page **pages);

static inline bool get_user_page_fast_only(unsigned long addr,
			unsigned int gup_flags, struct page **pagep)
{
	return get_user_pages_fast_only(addr, 1, gup_flags, pagep) == 1;
}
/*
 * per-process(per-mm_struct) statistics.
 */
static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
{
	return percpu_counter_read_positive(&mm->rss_stat[member]);
}

static inline unsigned long get_mm_counter_sum(struct mm_struct *mm, int member)
{
	return percpu_counter_sum_positive(&mm->rss_stat[member]);
}

void mm_trace_rss_stat(struct mm_struct *mm, int member);

static inline void add_mm_counter(struct mm_struct *mm, int member, long value)
{
	percpu_counter_add(&mm->rss_stat[member], value);

	mm_trace_rss_stat(mm, member);
}

static inline void inc_mm_counter(struct mm_struct *mm, int member)
{
	percpu_counter_inc(&mm->rss_stat[member]);

	mm_trace_rss_stat(mm, member);
}

static inline void dec_mm_counter(struct mm_struct *mm, int member)
{
	percpu_counter_dec(&mm->rss_stat[member]);

	mm_trace_rss_stat(mm, member);
}

/* Optimized variant when folio is already known not to be anon */
static inline int mm_counter_file(struct folio *folio)
{
	if (folio_test_swapbacked(folio))
		return MM_SHMEMPAGES;
	return MM_FILEPAGES;
}

static inline int mm_counter(struct folio *folio)
{
	if (folio_test_anon(folio))
		return MM_ANONPAGES;
	return mm_counter_file(folio);
}

static inline unsigned long get_mm_rss(struct mm_struct *mm)
{
	return get_mm_counter(mm, MM_FILEPAGES) +
		get_mm_counter(mm, MM_ANONPAGES) +
		get_mm_counter(mm, MM_SHMEMPAGES);
}

static inline unsigned long get_mm_hiwater_rss(struct mm_struct *mm)
{
	return max(mm->hiwater_rss, get_mm_rss(mm));
}

static inline unsigned long get_mm_hiwater_vm(struct mm_struct *mm)
{
	return max(mm->hiwater_vm, mm->total_vm);
}

static inline void update_hiwater_rss(struct mm_struct *mm)
{
	unsigned long _rss = get_mm_rss(mm);

	if (data_race(mm->hiwater_rss) < _rss)
		(mm)->hiwater_rss = _rss;
}

static inline void update_hiwater_vm(struct mm_struct *mm)
{
	if (mm->hiwater_vm < mm->total_vm)
		mm->hiwater_vm = mm->total_vm;
}

static inline void reset_mm_hiwater_rss(struct mm_struct *mm)
{
	mm->hiwater_rss = get_mm_rss(mm);
}

static inline void setmax_mm_hiwater_rss(unsigned long *maxrss,
					 struct mm_struct *mm)
{
	unsigned long hiwater_rss = get_mm_hiwater_rss(mm);

	if (*maxrss < hiwater_rss)
		*maxrss = hiwater_rss;
}

#ifndef CONFIG_ARCH_HAS_PTE_SPECIAL
static inline int pte_special(pte_t pte)
{
	return 0;
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	return pte;
}
#endif

#ifndef CONFIG_ARCH_SUPPORTS_PMD_PFNMAP
static inline bool pmd_special(pmd_t pmd)
{
	return false;
}

static inline pmd_t pmd_mkspecial(pmd_t pmd)
{
	return pmd;
}
#endif	/* CONFIG_ARCH_SUPPORTS_PMD_PFNMAP */

#ifndef CONFIG_ARCH_SUPPORTS_PUD_PFNMAP
static inline bool pud_special(pud_t pud)
{
	return false;
}

static inline pud_t pud_mkspecial(pud_t pud)
{
	return pud;
}
#endif	/* CONFIG_ARCH_SUPPORTS_PUD_PFNMAP */

extern pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
			       spinlock_t **ptl);
static inline pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
				    spinlock_t **ptl)
{
	pte_t *ptep;
	__cond_lock(*ptl, ptep = __get_locked_pte(mm, addr, ptl));
	return ptep;
}

#ifdef __PAGETABLE_P4D_FOLDED
static inline int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
						unsigned long address)
{
	return 0;
}
#else
int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
#endif

#if defined(__PAGETABLE_PUD_FOLDED) || !defined(CONFIG_MMU)
static inline int __pud_alloc(struct mm_struct *mm, p4d_t *p4d,
						unsigned long address)
{
	return 0;
}
static inline void mm_inc_nr_puds(struct mm_struct *mm) {}
static inline void mm_dec_nr_puds(struct mm_struct *mm) {}

#else
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address);

static inline void mm_inc_nr_puds(struct mm_struct *mm)
{
	if (mm_pud_folded(mm))
		return;
	atomic_long_add(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_puds(struct mm_struct *mm)
{
	if (mm_pud_folded(mm))
		return;
	atomic_long_sub(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}
#endif

#if defined(__PAGETABLE_PMD_FOLDED) || !defined(CONFIG_MMU)
static inline int __pmd_alloc(struct mm_struct *mm, pud_t *pud,
						unsigned long address)
{
	return 0;
}

static inline void mm_inc_nr_pmds(struct mm_struct *mm) {}
static inline void mm_dec_nr_pmds(struct mm_struct *mm) {}

#else
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

static inline void mm_inc_nr_pmds(struct mm_struct *mm)
{
	if (mm_pmd_folded(mm))
		return;
	atomic_long_add(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_pmds(struct mm_struct *mm)
{
	if (mm_pmd_folded(mm))
		return;
	atomic_long_sub(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}
#endif

#ifdef CONFIG_MMU
static inline void mm_pgtables_bytes_init(struct mm_struct *mm)
{
	atomic_long_set(&mm->pgtables_bytes, 0);
}

static inline unsigned long mm_pgtables_bytes(const struct mm_struct *mm)
{
	return atomic_long_read(&mm->pgtables_bytes);
}

static inline void mm_inc_nr_ptes(struct mm_struct *mm)
{
	atomic_long_add(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_ptes(struct mm_struct *mm)
{
	atomic_long_sub(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}
#else

static inline void mm_pgtables_bytes_init(struct mm_struct *mm) {}
static inline unsigned long mm_pgtables_bytes(const struct mm_struct *mm)
{
	return 0;
}

static inline void mm_inc_nr_ptes(struct mm_struct *mm) {}
static inline void mm_dec_nr_ptes(struct mm_struct *mm) {}
#endif

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd);
int __pte_alloc_kernel(pmd_t *pmd);

#if defined(CONFIG_MMU)

static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

static inline pud_t *pud_alloc(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && __pud_alloc(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}

static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#endif /* CONFIG_MMU */

static inline struct ptdesc *virt_to_ptdesc(const void *x)
{
	return page_ptdesc(virt_to_page(x));
}

static inline void *ptdesc_to_virt(const struct ptdesc *pt)
{
	return page_to_virt(ptdesc_page(pt));
}

static inline void *ptdesc_address(const struct ptdesc *pt)
{
	return folio_address(ptdesc_folio(pt));
}

static inline bool pagetable_is_reserved(struct ptdesc *pt)
{
	return folio_test_reserved(ptdesc_folio(pt));
}

/**
 * pagetable_alloc - Allocate pagetables
 * @gfp:    GFP flags
 * @order:  desired pagetable order
 *
 * pagetable_alloc allocates memory for page tables as well as a page table
 * descriptor to describe that memory.
 *
 * Return: The ptdesc describing the allocated page tables.
 */
static inline struct ptdesc *pagetable_alloc_noprof(gfp_t gfp, unsigned int order)
{
	struct page *page = alloc_pages_noprof(gfp | __GFP_COMP, order);

	return page_ptdesc(page);
}
#define pagetable_alloc(...)	alloc_hooks(pagetable_alloc_noprof(__VA_ARGS__))

/**
 * pagetable_free - Free pagetables
 * @pt:	The page table descriptor
 *
 * pagetable_free frees the memory of all page tables described by a page
 * table descriptor and the memory for the descriptor itself.
 */
static inline void pagetable_free(struct ptdesc *pt)
{
	struct page *page = ptdesc_page(pt);

	__free_pages(page, compound_order(page));
}

#if defined(CONFIG_SPLIT_PTE_PTLOCKS)
#if ALLOC_SPLIT_PTLOCKS
void __init ptlock_cache_init(void);
bool ptlock_alloc(struct ptdesc *ptdesc);
void ptlock_free(struct ptdesc *ptdesc);

static inline spinlock_t *ptlock_ptr(struct ptdesc *ptdesc)
{
	return ptdesc->ptl;
}
#else /* ALLOC_SPLIT_PTLOCKS */
static inline void ptlock_cache_init(void)
{
}

static inline bool ptlock_alloc(struct ptdesc *ptdesc)
{
	return true;
}

static inline void ptlock_free(struct ptdesc *ptdesc)
{
}

static inline spinlock_t *ptlock_ptr(struct ptdesc *ptdesc)
{
	return &ptdesc->ptl;
}
#endif /* ALLOC_SPLIT_PTLOCKS */

static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(page_ptdesc(pmd_page(*pmd)));
}

static inline spinlock_t *ptep_lockptr(struct mm_struct *mm, pte_t *pte)
{
	BUILD_BUG_ON(IS_ENABLED(CONFIG_HIGHPTE));
	BUILD_BUG_ON(MAX_PTRS_PER_PTE * sizeof(pte_t) > PAGE_SIZE);
	return ptlock_ptr(virt_to_ptdesc(pte));
}

static inline bool ptlock_init(struct ptdesc *ptdesc)
{
	/*
	 * prep_new_page() initialize page->private (and therefore page->ptl)
	 * with 0. Make sure nobody took it in use in between.
	 *
	 * It can happen if arch try to use slab for page table allocation:
	 * slab code uses page->slab_cache, which share storage with page->ptl.
	 */
	VM_BUG_ON_PAGE(*(unsigned long *)&ptdesc->ptl, ptdesc_page(ptdesc));
	if (!ptlock_alloc(ptdesc))
		return false;
	spin_lock_init(ptlock_ptr(ptdesc));
	return true;
}

#else	/* !defined(CONFIG_SPLIT_PTE_PTLOCKS) */
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
static inline spinlock_t *ptep_lockptr(struct mm_struct *mm, pte_t *pte)
{
	return &mm->page_table_lock;
}
static inline void ptlock_cache_init(void) {}
static inline bool ptlock_init(struct ptdesc *ptdesc) { return true; }
static inline void ptlock_free(struct ptdesc *ptdesc) {}
#endif /* defined(CONFIG_SPLIT_PTE_PTLOCKS) */

static inline void __pagetable_ctor(struct ptdesc *ptdesc)
{
	struct folio *folio = ptdesc_folio(ptdesc);

	__folio_set_pgtable(folio);
	lruvec_stat_add_folio(folio, NR_PAGETABLE);
}

static inline void pagetable_dtor(struct ptdesc *ptdesc)
{
	struct folio *folio = ptdesc_folio(ptdesc);

	ptlock_free(ptdesc);
	__folio_clear_pgtable(folio);
	lruvec_stat_sub_folio(folio, NR_PAGETABLE);
}

static inline void pagetable_dtor_free(struct ptdesc *ptdesc)
{
	pagetable_dtor(ptdesc);
	pagetable_free(ptdesc);
}

static inline bool pagetable_pte_ctor(struct mm_struct *mm,
				      struct ptdesc *ptdesc)
{
	if (mm != &init_mm && !ptlock_init(ptdesc))
		return false;
	__pagetable_ctor(ptdesc);
	return true;
}

pte_t *___pte_offset_map(pmd_t *pmd, unsigned long addr, pmd_t *pmdvalp);
static inline pte_t *__pte_offset_map(pmd_t *pmd, unsigned long addr,
			pmd_t *pmdvalp)
{
	pte_t *pte;

	__cond_lock(RCU, pte = ___pte_offset_map(pmd, addr, pmdvalp));
	return pte;
}
static inline pte_t *pte_offset_map(pmd_t *pmd, unsigned long addr)
{
	return __pte_offset_map(pmd, addr, NULL);
}

pte_t *__pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, spinlock_t **ptlp);
static inline pte_t *pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, spinlock_t **ptlp)
{
	pte_t *pte;

	__cond_lock(RCU, __cond_lock(*ptlp,
			pte = __pte_offset_map_lock(mm, pmd, addr, ptlp)));
	return pte;
}

pte_t *pte_offset_map_ro_nolock(struct mm_struct *mm, pmd_t *pmd,
				unsigned long addr, spinlock_t **ptlp);
pte_t *pte_offset_map_rw_nolock(struct mm_struct *mm, pmd_t *pmd,
				unsigned long addr, pmd_t *pmdvalp,
				spinlock_t **ptlp);

#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)

#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd))

#define pte_alloc_map(mm, pmd, address)			\
	(pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))

#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	(pte_alloc(mm, pmd) ?			\
		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))

#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
		NULL: pte_offset_kernel(pmd, address))

#if defined(CONFIG_SPLIT_PMD_PTLOCKS)

static inline struct page *pmd_pgtable_page(pmd_t *pmd)
{
	unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
	return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline struct ptdesc *pmd_ptdesc(pmd_t *pmd)
{
	return page_ptdesc(pmd_pgtable_page(pmd));
}

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_ptdesc(pmd));
}

static inline bool pmd_ptlock_init(struct ptdesc *ptdesc)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	ptdesc->pmd_huge_pte = NULL;
#endif
	return ptlock_init(ptdesc);
}

#define pmd_huge_pte(mm, pmd) (pmd_ptdesc(pmd)->pmd_huge_pte)

#else

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}

static inline bool pmd_ptlock_init(struct ptdesc *ptdesc) { return true; }

#define pmd_huge_pte(mm, pmd) ((mm)->pmd_huge_pte)

#endif

static inline spinlock_t *pmd_lock(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl = pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	return ptl;
}

static inline bool pagetable_pmd_ctor(struct mm_struct *mm,
				      struct ptdesc *ptdesc)
{
	if (mm != &init_mm && !pmd_ptlock_init(ptdesc))
		return false;
	ptdesc_pmd_pts_init(ptdesc);
	__pagetable_ctor(ptdesc);
	return true;
}

/*
 * No scalability reason to split PUD locks yet, but follow the same pattern
 * as the PMD locks to make it easier if we decide to.  The VM should not be
 * considered ready to switch to split PUD locks yet; there may be places
 * which need to be converted from page_table_lock.
 */
static inline spinlock_t *pud_lockptr(struct mm_struct *mm, pud_t *pud)
{
	return &mm->page_table_lock;
}

static inline spinlock_t *pud_lock(struct mm_struct *mm, pud_t *pud)
{
	spinlock_t *ptl = pud_lockptr(mm, pud);

	spin_lock(ptl);
	return ptl;
}

static inline void pagetable_pud_ctor(struct ptdesc *ptdesc)
{
	__pagetable_ctor(ptdesc);
}

static inline void pagetable_p4d_ctor(struct ptdesc *ptdesc)
{
	__pagetable_ctor(ptdesc);
}

static inline void pagetable_pgd_ctor(struct ptdesc *ptdesc)
{
	__pagetable_ctor(ptdesc);
}

extern void __init pagecache_init(void);
extern void free_initmem(void);

/*
 * Free reserved pages within range [PAGE_ALIGN(start), end & PAGE_MASK)
 * into the buddy system. The freed pages will be poisoned with pattern
 * "poison" if it's within range [0, UCHAR_MAX].
 * Return pages freed into the buddy system.
 */
extern unsigned long free_reserved_area(void *start, void *end,
					int poison, const char *s);

extern void adjust_managed_page_count(struct page *page, long count);

extern void reserve_bootmem_region(phys_addr_t start,
				   phys_addr_t end, int nid);

/* Free the reserved page into the buddy system, so it gets managed. */
void free_reserved_page(struct page *page);

static inline void mark_page_reserved(struct page *page)
{
	SetPageReserved(page);
	adjust_managed_page_count(page, -1);
}

static inline void free_reserved_ptdesc(struct ptdesc *pt)
{
	free_reserved_page(ptdesc_page(pt));
}

/*
 * Default method to free all the __init memory into the buddy system.
 * The freed pages will be poisoned with pattern "poison" if it's within
 * range [0, UCHAR_MAX].
 * Return pages freed into the buddy system.
 */
static inline unsigned long free_initmem_default(int poison)
{
	extern char __init_begin[], __init_end[];

	return free_reserved_area(&__init_begin, &__init_end,
				  poison, "unused kernel image (initmem)");
}

static inline unsigned long get_num_physpages(void)
{
	int nid;
	unsigned long phys_pages = 0;

	for_each_online_node(nid)
		phys_pages += node_present_pages(nid);

	return phys_pages;
}

/*
 * Using memblock node mappings, an architecture may initialise its
 * zones, allocate the backing mem_map and account for memory holes in an
 * architecture independent manner.
 *
 * An architecture is expected to register range of page frames backed by
 * physical memory with memblock_add[_node]() before calling
 * free_area_init() passing in the PFN each zone ends at. At a basic
 * usage, an architecture is expected to do something like
 *
 * unsigned long max_zone_pfns[MAX_NR_ZONES] = {max_dma, max_normal_pfn,
 * 							 max_highmem_pfn};
 * for_each_valid_physical_page_range()
 *	memblock_add_node(base, size, nid, MEMBLOCK_NONE)
 * free_area_init(max_zone_pfns);
 */
void free_area_init(unsigned long *max_zone_pfn);
unsigned long node_map_pfn_alignment(void);
extern unsigned long absent_pages_in_range(unsigned long start_pfn,
						unsigned long end_pfn);
extern void get_pfn_range_for_nid(unsigned int nid,
			unsigned long *start_pfn, unsigned long *end_pfn);

#ifndef CONFIG_NUMA
static inline int early_pfn_to_nid(unsigned long pfn)
{
	return 0;
}
#else
/* please see mm/page_alloc.c */
extern int __meminit early_pfn_to_nid(unsigned long pfn);
#endif

extern void mem_init(void);
extern void __init mmap_init(void);

extern void __show_mem(unsigned int flags, nodemask_t *nodemask, int max_zone_idx);
static inline void show_mem(void)
{
	__show_mem(0, NULL, MAX_NR_ZONES - 1);
}
extern long si_mem_available(void);
extern void si_meminfo(struct sysinfo * val);
extern void si_meminfo_node(struct sysinfo *val, int nid);

extern __printf(3, 4)
void warn_alloc(gfp_t gfp_mask, nodemask_t *nodemask, const char *fmt, ...);

extern void setup_per_cpu_pageset(void);

/* nommu.c */
extern atomic_long_t mmap_pages_allocated;
extern int nommu_shrink_inode_mappings(struct inode *, size_t, size_t);

/* interval_tree.c */
void vma_interval_tree_insert(struct vm_area_struct *node,
			      struct rb_root_cached *root);
void vma_interval_tree_insert_after(struct vm_area_struct *node,
				    struct vm_area_struct *prev,
				    struct rb_root_cached *root);
void vma_interval_tree_remove(struct vm_area_struct *node,
			      struct rb_root_cached *root);
struct vm_area_struct *vma_interval_tree_iter_first(struct rb_root_cached *root,
				unsigned long start, unsigned long last);
struct vm_area_struct *vma_interval_tree_iter_next(struct vm_area_struct *node,
				unsigned long start, unsigned long last);

#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))

void anon_vma_interval_tree_insert(struct anon_vma_chain *node,
				   struct rb_root_cached *root);
void anon_vma_interval_tree_remove(struct anon_vma_chain *node,
				   struct rb_root_cached *root);
struct anon_vma_chain *
anon_vma_interval_tree_iter_first(struct rb_root_cached *root,
				  unsigned long start, unsigned long last);
struct anon_vma_chain *anon_vma_interval_tree_iter_next(
	struct anon_vma_chain *node, unsigned long start, unsigned long last);
#ifdef CONFIG_DEBUG_VM_RB
void anon_vma_interval_tree_verify(struct anon_vma_chain *node);
#endif

#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))

/* mmap.c */
extern int __vm_enough_memory(struct mm_struct *mm, long pages, int cap_sys_admin);
extern int insert_vm_struct(struct mm_struct *, struct vm_area_struct *);
extern void exit_mmap(struct mm_struct *);
bool mmap_read_lock_maybe_expand(struct mm_struct *mm, struct vm_area_struct *vma,
				 unsigned long addr, bool write);

static inline int check_data_rlimit(unsigned long rlim,
				    unsigned long new,
				    unsigned long start,
				    unsigned long end_data,
				    unsigned long start_data)
{
	if (rlim < RLIM_INFINITY) {
		if (((new - start) + (end_data - start_data)) > rlim)
			return -ENOSPC;
	}

	return 0;
}

extern int mm_take_all_locks(struct mm_struct *mm);
extern void mm_drop_all_locks(struct mm_struct *mm);

extern int set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file);
extern int replace_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file);
extern struct file *get_mm_exe_file(struct mm_struct *mm);
extern struct file *get_task_exe_file(struct task_struct *task);

extern bool may_expand_vm(struct mm_struct *, vm_flags_t, unsigned long npages);
extern void vm_stat_account(struct mm_struct *, vm_flags_t, long npages);

extern bool vma_is_special_mapping(const struct vm_area_struct *vma,
				   const struct vm_special_mapping *sm);
struct vm_area_struct *_install_special_mapping(struct mm_struct *mm,
				   unsigned long addr, unsigned long len,
				   vm_flags_t vm_flags,
				   const struct vm_special_mapping *spec);

unsigned long randomize_stack_top(unsigned long stack_top);
unsigned long randomize_page(unsigned long start, unsigned long range);

unsigned long
__get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		    unsigned long pgoff, unsigned long flags, vm_flags_t vm_flags);

static inline unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		  unsigned long pgoff, unsigned long flags)
{
	return __get_unmapped_area(file, addr, len, pgoff, flags, 0);
}

extern unsigned long do_mmap(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot, unsigned long flags,
	vm_flags_t vm_flags, unsigned long pgoff, unsigned long *populate,
	struct list_head *uf);
extern int do_vmi_munmap(struct vma_iterator *vmi, struct mm_struct *mm,
			 unsigned long start, size_t len, struct list_head *uf,
			 bool unlock);
int do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
		    struct mm_struct *mm, unsigned long start,
		    unsigned long end, struct list_head *uf, bool unlock);
extern int do_munmap(struct mm_struct *, unsigned long, size_t,
		     struct list_head *uf);
extern int do_madvise(struct mm_struct *mm, unsigned long start, size_t len_in, int behavior);

#ifdef CONFIG_MMU
extern int __mm_populate(unsigned long addr, unsigned long len,
			 int ignore_errors);
static inline void mm_populate(unsigned long addr, unsigned long len)
{
	/* Ignore errors */
	(void) __mm_populate(addr, len, 1);
}
#else
static inline void mm_populate(unsigned long addr, unsigned long len) {}
#endif

/* This takes the mm semaphore itself */
extern int __must_check vm_brk_flags(unsigned long, unsigned long, unsigned long);
extern int vm_munmap(unsigned long, size_t);
extern unsigned long __must_check vm_mmap(struct file *, unsigned long,
        unsigned long, unsigned long,
        unsigned long, unsigned long);

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
	unsigned long start_gap;
};

extern unsigned long vm_unmapped_area(struct vm_unmapped_area_info *info);

/* truncate.c */
extern void truncate_inode_pages(struct address_space *, loff_t);
extern void truncate_inode_pages_range(struct address_space *,
				       loff_t lstart, loff_t lend);
extern void truncate_inode_pages_final(struct address_space *);

/* generic vm_area_ops exported for stackable file systems */
extern vm_fault_t filemap_fault(struct vm_fault *vmf);
extern vm_fault_t filemap_map_pages(struct vm_fault *vmf,
		pgoff_t start_pgoff, pgoff_t end_pgoff);
extern vm_fault_t filemap_page_mkwrite(struct vm_fault *vmf);

extern unsigned long stack_guard_gap;
/* Generic expand stack which grows the stack according to GROWS{UP,DOWN} */
int expand_stack_locked(struct vm_area_struct *vma, unsigned long address);
struct vm_area_struct *expand_stack(struct mm_struct * mm, unsigned long addr);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
extern struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr);
extern struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
					     struct vm_area_struct **pprev);

/*
 * Look up the first VMA which intersects the interval [start_addr, end_addr)
 * NULL if none.  Assume start_addr < end_addr.
 */
struct vm_area_struct *find_vma_intersection(struct mm_struct *mm,
			unsigned long start_addr, unsigned long end_addr);

/**
 * vma_lookup() - Find a VMA at a specific address
 * @mm: The process address space.
 * @addr: The user address.
 *
 * Return: The vm_area_struct at the given address, %NULL otherwise.
 */
static inline
struct vm_area_struct *vma_lookup(struct mm_struct *mm, unsigned long addr)
{
	return mtree_load(&mm->mm_mt, addr);
}

static inline unsigned long stack_guard_start_gap(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_GROWSDOWN)
		return stack_guard_gap;

	/* See reasoning around the VM_SHADOW_STACK definition */
	if (vma->vm_flags & VM_SHADOW_STACK)
		return PAGE_SIZE;

	return 0;
}

static inline unsigned long vm_start_gap(struct vm_area_struct *vma)
{
	unsigned long gap = stack_guard_start_gap(vma);
	unsigned long vm_start = vma->vm_start;

	vm_start -= gap;
	if (vm_start > vma->vm_start)
		vm_start = 0;
	return vm_start;
}

static inline unsigned long vm_end_gap(struct vm_area_struct *vma)
{
	unsigned long vm_end = vma->vm_end;

	if (vma->vm_flags & VM_GROWSUP) {
		vm_end += stack_guard_gap;
		if (vm_end < vma->vm_end)
			vm_end = -PAGE_SIZE;
	}
	return vm_end;
}

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

/* Look up the first VMA which exactly match the interval vm_start ... vm_end */
static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
				unsigned long vm_start, unsigned long vm_end)
{
	struct vm_area_struct *vma = vma_lookup(mm, vm_start);

	if (vma && (vma->vm_start != vm_start || vma->vm_end != vm_end))
		vma = NULL;

	return vma;
}

static inline bool range_in_vma(struct vm_area_struct *vma,
				unsigned long start, unsigned long end)
{
	return (vma && vma->vm_start <= start && end <= vma->vm_end);
}

#ifdef CONFIG_MMU
pgprot_t vm_get_page_prot(vm_flags_t vm_flags);
void vma_set_page_prot(struct vm_area_struct *vma);
#else
static inline pgprot_t vm_get_page_prot(vm_flags_t vm_flags)
{
	return __pgprot(0);
}
static inline void vma_set_page_prot(struct vm_area_struct *vma)
{
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
}
#endif

void vma_set_file(struct vm_area_struct *vma, struct file *file);

#ifdef CONFIG_NUMA_BALANCING
unsigned long change_prot_numa(struct vm_area_struct *vma,
			unsigned long start, unsigned long end);
#endif

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *,
		unsigned long addr);
int remap_pfn_range(struct vm_area_struct *, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t);
int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
		unsigned long pfn, unsigned long size, pgprot_t prot);
int vm_insert_page(struct vm_area_struct *, unsigned long addr, struct page *);
int vm_insert_pages(struct vm_area_struct *vma, unsigned long addr,
			struct page **pages, unsigned long *num);
int vm_map_pages(struct vm_area_struct *vma, struct page **pages,
				unsigned long num);
int vm_map_pages_zero(struct vm_area_struct *vma, struct page **pages,
				unsigned long num);
vm_fault_t vmf_insert_page_mkwrite(struct vm_fault *vmf, struct page *page,
			bool write);
vm_fault_t vmf_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn);
vm_fault_t vmf_insert_pfn_prot(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t pgprot);
vm_fault_t vmf_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn);
vm_fault_t vmf_insert_mixed_mkwrite(struct vm_area_struct *vma,
		unsigned long addr, unsigned long pfn);
int vm_iomap_memory(struct vm_area_struct *vma, phys_addr_t start, unsigned long len);

static inline vm_fault_t vmf_insert_page(struct vm_area_struct *vma,
				unsigned long addr, struct page *page)
{
	int err = vm_insert_page(vma, addr, page);

	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	if (err < 0 && err != -EBUSY)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

#ifndef io_remap_pfn_range
static inline int io_remap_pfn_range(struct vm_area_struct *vma,
				     unsigned long addr, unsigned long pfn,
				     unsigned long size, pgprot_t prot)
{
	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
}
#endif

static inline vm_fault_t vmf_error(int err)
{
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	else if (err == -EHWPOISON)
		return VM_FAULT_HWPOISON;
	return VM_FAULT_SIGBUS;
}

/*
 * Convert errno to return value for ->page_mkwrite() calls.
 *
 * This should eventually be merged with vmf_error() above, but will need a
 * careful audit of all vmf_error() callers.
 */
static inline vm_fault_t vmf_fs_error(int err)
{
	if (err == 0)
		return VM_FAULT_LOCKED;
	if (err == -EFAULT || err == -EAGAIN)
		return VM_FAULT_NOPAGE;
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	/* -ENOSPC, -EDQUOT, -EIO ... */
	return VM_FAULT_SIGBUS;
}

static inline int vm_fault_to_errno(vm_fault_t vm_fault, int foll_flags)
{
	if (vm_fault & VM_FAULT_OOM)
		return -ENOMEM;
	if (vm_fault & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
		return (foll_flags & FOLL_HWPOISON) ? -EHWPOISON : -EFAULT;
	if (vm_fault & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
		return -EFAULT;
	return 0;
}

/*
 * Indicates whether GUP can follow a PROT_NONE mapped page, or whether
 * a (NUMA hinting) fault is required.
 */
static inline bool gup_can_follow_protnone(struct vm_area_struct *vma,
					   unsigned int flags)
{
	/*
	 * If callers don't want to honor NUMA hinting faults, no need to
	 * determine if we would actually have to trigger a NUMA hinting fault.
	 */
	if (!(flags & FOLL_HONOR_NUMA_FAULT))
		return true;

	/*
	 * NUMA hinting faults don't apply in inaccessible (PROT_NONE) VMAs.
	 *
	 * Requiring a fault here even for inaccessible VMAs would mean that
	 * FOLL_FORCE cannot make any progress, because handle_mm_fault()
	 * refuses to process NUMA hinting faults in inaccessible VMAs.
	 */
	return !vma_is_accessible(vma);
}

typedef int (*pte_fn_t)(pte_t *pte, unsigned long addr, void *data);
extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
			       unsigned long size, pte_fn_t fn, void *data);
extern int apply_to_existing_page_range(struct mm_struct *mm,
				   unsigned long address, unsigned long size,
				   pte_fn_t fn, void *data);

#ifdef CONFIG_PAGE_POISONING
extern void __kernel_poison_pages(struct page *page, int numpages);
extern void __kernel_unpoison_pages(struct page *page, int numpages);
extern bool _page_poisoning_enabled_early;
DECLARE_STATIC_KEY_FALSE(_page_poisoning_enabled);
static inline bool page_poisoning_enabled(void)
{
	return _page_poisoning_enabled_early;
}
/*
 * For use in fast paths after init_mem_debugging() has run, or when a
 * false negative result is not harmful when called too early.
 */
static inline bool page_poisoning_enabled_static(void)
{
	return static_branch_unlikely(&_page_poisoning_enabled);
}
static inline void kernel_poison_pages(struct page *page, int numpages)
{
	if (page_poisoning_enabled_static())
		__kernel_poison_pages(page, numpages);
}
static inline void kernel_unpoison_pages(struct page *page, int numpages)
{
	if (page_poisoning_enabled_static())
		__kernel_unpoison_pages(page, numpages);
}
#else
static inline bool page_poisoning_enabled(void) { return false; }
static inline bool page_poisoning_enabled_static(void) { return false; }
static inline void __kernel_poison_pages(struct page *page, int nunmpages) { }
static inline void kernel_poison_pages(struct page *page, int numpages) { }
static inline void kernel_unpoison_pages(struct page *page, int numpages) { }
#endif

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
static inline bool want_init_on_alloc(gfp_t flags)
{
	if (static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON,
				&init_on_alloc))
		return true;
	return flags & __GFP_ZERO;
}

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_FREE_DEFAULT_ON, init_on_free);
static inline bool want_init_on_free(void)
{
	return static_branch_maybe(CONFIG_INIT_ON_FREE_DEFAULT_ON,
				   &init_on_free);
}

extern bool _debug_pagealloc_enabled_early;
DECLARE_STATIC_KEY_FALSE(_debug_pagealloc_enabled);

static inline bool debug_pagealloc_enabled(void)
{
	return IS_ENABLED(CONFIG_DEBUG_PAGEALLOC) &&
		_debug_pagealloc_enabled_early;
}

/*
 * For use in fast paths after mem_debugging_and_hardening_init() has run,
 * or when a false negative result is not harmful when called too early.
 */
static inline bool debug_pagealloc_enabled_static(void)
{
	if (!IS_ENABLED(CONFIG_DEBUG_PAGEALLOC))
		return false;

	return static_branch_unlikely(&_debug_pagealloc_enabled);
}

/*
 * To support DEBUG_PAGEALLOC architecture must ensure that
 * __kernel_map_pages() never fails
 */
extern void __kernel_map_pages(struct page *page, int numpages, int enable);
#ifdef CONFIG_DEBUG_PAGEALLOC
static inline void debug_pagealloc_map_pages(struct page *page, int numpages)
{
	if (debug_pagealloc_enabled_static())
		__kernel_map_pages(page, numpages, 1);
}

static inline void debug_pagealloc_unmap_pages(struct page *page, int numpages)
{
	if (debug_pagealloc_enabled_static())
		__kernel_map_pages(page, numpages, 0);
}

extern unsigned int _debug_guardpage_minorder;
DECLARE_STATIC_KEY_FALSE(_debug_guardpage_enabled);

static inline unsigned int debug_guardpage_minorder(void)
{
	return _debug_guardpage_minorder;
}

static inline bool debug_guardpage_enabled(void)
{
	return static_branch_unlikely(&_debug_guardpage_enabled);
}

static inline bool page_is_guard(struct page *page)
{
	if (!debug_guardpage_enabled())
		return false;

	return PageGuard(page);
}

bool __set_page_guard(struct zone *zone, struct page *page, unsigned int order);
static inline bool set_page_guard(struct zone *zone, struct page *page,
				  unsigned int order)
{
	if (!debug_guardpage_enabled())
		return false;
	return __set_page_guard(zone, page, order);
}

void __clear_page_guard(struct zone *zone, struct page *page, unsigned int order);
static inline void clear_page_guard(struct zone *zone, struct page *page,
				    unsigned int order)
{
	if (!debug_guardpage_enabled())
		return;
	__clear_page_guard(zone, page, order);
}

#else	/* CONFIG_DEBUG_PAGEALLOC */
static inline void debug_pagealloc_map_pages(struct page *page, int numpages) {}
static inline void debug_pagealloc_unmap_pages(struct page *page, int numpages) {}
static inline unsigned int debug_guardpage_minorder(void) { return 0; }
static inline bool debug_guardpage_enabled(void) { return false; }
static inline bool page_is_guard(struct page *page) { return false; }
static inline bool set_page_guard(struct zone *zone, struct page *page,
			unsigned int order) { return false; }
static inline void clear_page_guard(struct zone *zone, struct page *page,
				unsigned int order) {}
#endif	/* CONFIG_DEBUG_PAGEALLOC */

#ifdef __HAVE_ARCH_GATE_AREA
extern struct vm_area_struct *get_gate_vma(struct mm_struct *mm);
extern int in_gate_area_no_mm(unsigned long addr);
extern int in_gate_area(struct mm_struct *mm, unsigned long addr);
#else
static inline struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
	return NULL;
}
static inline int in_gate_area_no_mm(unsigned long addr) { return 0; }
static inline int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	return 0;
}
#endif	/* __HAVE_ARCH_GATE_AREA */

extern bool process_shares_mm(struct task_struct *p, struct mm_struct *mm);

void drop_slab(void);

#ifndef CONFIG_MMU
#define randomize_va_space 0
#else
extern int randomize_va_space;
#endif

const char * arch_vma_name(struct vm_area_struct *vma);
#ifdef CONFIG_MMU
void print_vma_addr(char *prefix, unsigned long rip);
#else
static inline void print_vma_addr(char *prefix, unsigned long rip)
{
}
#endif

void *sparse_buffer_alloc(unsigned long size);
unsigned long section_map_size(void);
struct page * __populate_section_memmap(unsigned long pfn,
		unsigned long nr_pages, int nid, struct vmem_altmap *altmap,
		struct dev_pagemap *pgmap);
pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
p4d_t *vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node);
pud_t *vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node);
pmd_t *vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node);
pte_t *vmemmap_pte_populate(pmd_t *pmd, unsigned long addr, int node,
			    struct vmem_altmap *altmap, unsigned long ptpfn,
			    unsigned long flags);
void *vmemmap_alloc_block(unsigned long size, int node);
struct vmem_altmap;
void *vmemmap_alloc_block_buf(unsigned long size, int node,
			      struct vmem_altmap *altmap);
void vmemmap_verify(pte_t *, int, unsigned long, unsigned long);
void vmemmap_set_pmd(pmd_t *pmd, void *p, int node,
		     unsigned long addr, unsigned long next);
int vmemmap_check_pmd(pmd_t *pmd, int node,
		      unsigned long addr, unsigned long next);
int vmemmap_populate_basepages(unsigned long start, unsigned long end,
			       int node, struct vmem_altmap *altmap);
int vmemmap_populate_hugepages(unsigned long start, unsigned long end,
			       int node, struct vmem_altmap *altmap);
int vmemmap_populate(unsigned long start, unsigned long end, int node,
		struct vmem_altmap *altmap);
int vmemmap_populate_hvo(unsigned long start, unsigned long end, int node,
			 unsigned long headsize);
int vmemmap_undo_hvo(unsigned long start, unsigned long end, int node,
		     unsigned long headsize);
void vmemmap_wrprotect_hvo(unsigned long start, unsigned long end, int node,
			  unsigned long headsize);
void vmemmap_populate_print_last(void);
#ifdef CONFIG_MEMORY_HOTPLUG
void vmemmap_free(unsigned long start, unsigned long end,
		struct vmem_altmap *altmap);
#endif

#ifdef CONFIG_SPARSEMEM_VMEMMAP
static inline unsigned long vmem_altmap_offset(struct vmem_altmap *altmap)
{
	/* number of pfns from base where pfn_to_page() is valid */
	if (altmap)
		return altmap->reserve + altmap->free;
	return 0;
}

static inline void vmem_altmap_free(struct vmem_altmap *altmap,
				    unsigned long nr_pfns)
{
	altmap->alloc -= nr_pfns;
}
#else
static inline unsigned long vmem_altmap_offset(struct vmem_altmap *altmap)
{
	return 0;
}

static inline void vmem_altmap_free(struct vmem_altmap *altmap,
				    unsigned long nr_pfns)
{
}
#endif

#define VMEMMAP_RESERVE_NR	2
#ifdef CONFIG_ARCH_WANT_OPTIMIZE_DAX_VMEMMAP
static inline bool __vmemmap_can_optimize(struct vmem_altmap *altmap,
					  struct dev_pagemap *pgmap)
{
	unsigned long nr_pages;
	unsigned long nr_vmemmap_pages;

	if (!pgmap || !is_power_of_2(sizeof(struct page)))
		return false;

	nr_pages = pgmap_vmemmap_nr(pgmap);
	nr_vmemmap_pages = ((nr_pages * sizeof(struct page)) >> PAGE_SHIFT);
	/*
	 * For vmemmap optimization with DAX we need minimum 2 vmemmap
	 * pages. See layout diagram in Documentation/mm/vmemmap_dedup.rst
	 */
	return !altmap && (nr_vmemmap_pages > VMEMMAP_RESERVE_NR);
}
/*
 * If we don't have an architecture override, use the generic rule
 */
#ifndef vmemmap_can_optimize
#define vmemmap_can_optimize __vmemmap_can_optimize
#endif

#else
static inline bool vmemmap_can_optimize(struct vmem_altmap *altmap,
					   struct dev_pagemap *pgmap)
{
	return false;
}
#endif

enum mf_flags {
	MF_COUNT_INCREASED = 1 << 0,
	MF_ACTION_REQUIRED = 1 << 1,
	MF_MUST_KILL = 1 << 2,
	MF_SOFT_OFFLINE = 1 << 3,
	MF_UNPOISON = 1 << 4,
	MF_SW_SIMULATED = 1 << 5,
	MF_NO_RETRY = 1 << 6,
	MF_MEM_PRE_REMOVE = 1 << 7,
};
int mf_dax_kill_procs(struct address_space *mapping, pgoff_t index,
		      unsigned long count, int mf_flags);
extern int memory_failure(unsigned long pfn, int flags);
extern int unpoison_memory(unsigned long pfn);
extern atomic_long_t num_poisoned_pages __read_mostly;
extern int soft_offline_page(unsigned long pfn, int flags);
#ifdef CONFIG_MEMORY_FAILURE
/*
 * Sysfs entries for memory failure handling statistics.
 */
extern const struct attribute_group memory_failure_attr_group;
extern void memory_failure_queue(unsigned long pfn, int flags);
extern int __get_huge_page_for_hwpoison(unsigned long pfn, int flags,
					bool *migratable_cleared);
void num_poisoned_pages_inc(unsigned long pfn);
void num_poisoned_pages_sub(unsigned long pfn, long i);
#else
static inline void memory_failure_queue(unsigned long pfn, int flags)
{
}

static inline int __get_huge_page_for_hwpoison(unsigned long pfn, int flags,
					bool *migratable_cleared)
{
	return 0;
}

static inline void num_poisoned_pages_inc(unsigned long pfn)
{
}

static inline void num_poisoned_pages_sub(unsigned long pfn, long i)
{
}
#endif

#if defined(CONFIG_MEMORY_FAILURE) && defined(CONFIG_MEMORY_HOTPLUG)
extern void memblk_nr_poison_inc(unsigned long pfn);
extern void memblk_nr_poison_sub(unsigned long pfn, long i);
#else
static inline void memblk_nr_poison_inc(unsigned long pfn)
{
}

static inline void memblk_nr_poison_sub(unsigned long pfn, long i)
{
}
#endif

#ifndef arch_memory_failure
static inline int arch_memory_failure(unsigned long pfn, int flags)
{
	return -ENXIO;
}
#endif

#ifndef arch_is_platform_page
static inline bool arch_is_platform_page(u64 paddr)
{
	return false;
}
#endif

/*
 * Error handlers for various types of pages.
 */
enum mf_result {
	MF_IGNORED,	/* Error: cannot be handled */
	MF_FAILED,	/* Error: handling failed */
	MF_DELAYED,	/* Will be handled later */
	MF_RECOVERED,	/* Successfully recovered */
};

enum mf_action_page_type {
	MF_MSG_KERNEL,
	MF_MSG_KERNEL_HIGH_ORDER,
	MF_MSG_DIFFERENT_COMPOUND,
	MF_MSG_HUGE,
	MF_MSG_FREE_HUGE,
	MF_MSG_GET_HWPOISON,
	MF_MSG_UNMAP_FAILED,
	MF_MSG_DIRTY_SWAPCACHE,
	MF_MSG_CLEAN_SWAPCACHE,
	MF_MSG_DIRTY_MLOCKED_LRU,
	MF_MSG_CLEAN_MLOCKED_LRU,
	MF_MSG_DIRTY_UNEVICTABLE_LRU,
	MF_MSG_CLEAN_UNEVICTABLE_LRU,
	MF_MSG_DIRTY_LRU,
	MF_MSG_CLEAN_LRU,
	MF_MSG_TRUNCATED_LRU,
	MF_MSG_BUDDY,
	MF_MSG_DAX,
	MF_MSG_UNSPLIT_THP,
	MF_MSG_ALREADY_POISONED,
	MF_MSG_UNKNOWN,
};

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
void folio_zero_user(struct folio *folio, unsigned long addr_hint);
int copy_user_large_folio(struct folio *dst, struct folio *src,
			  unsigned long addr_hint,
			  struct vm_area_struct *vma);
long copy_folio_from_user(struct folio *dst_folio,
			   const void __user *usr_src,
			   bool allow_pagefault);

/**
 * vma_is_special_huge - Are transhuge page-table entries considered special?
 * @vma: Pointer to the struct vm_area_struct to consider
 *
 * Whether transhuge page-table entries are considered "special" following
 * the definition in vm_normal_page().
 *
 * Return: true if transhuge page-table entries should be considered special,
 * false otherwise.
 */
static inline bool vma_is_special_huge(const struct vm_area_struct *vma)
{
	return vma_is_dax(vma) || (vma->vm_file &&
				   (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)));
}

#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_HUGETLBFS */

#if MAX_NUMNODES > 1
void __init setup_nr_node_ids(void);
#else
static inline void setup_nr_node_ids(void) {}
#endif

extern int memcmp_pages(struct page *page1, struct page *page2);

static inline int pages_identical(struct page *page1, struct page *page2)
{
	return !memcmp_pages(page1, page2);
}

#ifdef CONFIG_MAPPING_DIRTY_HELPERS
unsigned long clean_record_shared_mapping_range(struct address_space *mapping,
						pgoff_t first_index, pgoff_t nr,
						pgoff_t bitmap_pgoff,
						unsigned long *bitmap,
						pgoff_t *start,
						pgoff_t *end);

unsigned long wp_shared_mapping_range(struct address_space *mapping,
				      pgoff_t first_index, pgoff_t nr);
#endif

#ifdef CONFIG_ANON_VMA_NAME
int set_anon_vma_name(unsigned long addr, unsigned long size,
		      const char __user *uname);
#else
static inline
int set_anon_vma_name(unsigned long addr, unsigned long size,
		      const char __user *uname)
{
	return -EINVAL;
}
#endif

#ifdef CONFIG_UNACCEPTED_MEMORY

bool range_contains_unaccepted_memory(phys_addr_t start, unsigned long size);
void accept_memory(phys_addr_t start, unsigned long size);

#else

static inline bool range_contains_unaccepted_memory(phys_addr_t start,
						    unsigned long size)
{
	return false;
}

static inline void accept_memory(phys_addr_t start, unsigned long size)
{
}

#endif

static inline bool pfn_is_unaccepted_memory(unsigned long pfn)
{
	return range_contains_unaccepted_memory(pfn << PAGE_SHIFT, PAGE_SIZE);
}

void vma_pgtable_walk_begin(struct vm_area_struct *vma);
void vma_pgtable_walk_end(struct vm_area_struct *vma);

int reserve_mem_find_by_name(const char *name, phys_addr_t *start, phys_addr_t *size);
int reserve_mem_release_by_name(const char *name);

#ifdef CONFIG_64BIT
int do_mseal(unsigned long start, size_t len_in, unsigned long flags);
#else
static inline int do_mseal(unsigned long start, size_t len_in, unsigned long flags)
{
	/* noop on 32 bit */
	return 0;
}
#endif

/*
 * user_alloc_needs_zeroing checks if a user folio from page allocator needs to
 * be zeroed or not.
 */
static inline bool user_alloc_needs_zeroing(void)
{
	/*
	 * for user folios, arch with cache aliasing requires cache flush and
	 * arc changes folio->flags to make icache coherent with dcache, so
	 * always return false to make caller use
	 * clear_user_page()/clear_user_highpage().
	 */
	return cpu_dcache_is_aliasing() || cpu_icache_is_aliasing() ||
	       !static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON,
				   &init_on_alloc);
}

int arch_get_shadow_stack_status(struct task_struct *t, unsigned long __user *status);
int arch_set_shadow_stack_status(struct task_struct *t, unsigned long status);
int arch_lock_shadow_stack_status(struct task_struct *t, unsigned long status);


/*
 * mseal of userspace process's system mappings.
 */
#ifdef CONFIG_MSEAL_SYSTEM_MAPPINGS
#define VM_SEALED_SYSMAP	VM_SEALED
#else
#define VM_SEALED_SYSMAP	VM_NONE
#endif

/*
 * DMA mapping IDs for page_pool
 *
 * When DMA-mapping a page, page_pool allocates an ID (from an xarray) and
 * stashes it in the upper bits of page->pp_magic. We always want to be able to
 * unambiguously identify page pool pages (using page_pool_page_is_pp()). Non-PP
 * pages can have arbitrary kernel pointers stored in the same field as pp_magic
 * (since it overlaps with page->lru.next), so we must ensure that we cannot
 * mistake a valid kernel pointer with any of the values we write into this
 * field.
 *
 * On architectures that set POISON_POINTER_DELTA, this is already ensured,
 * since this value becomes part of PP_SIGNATURE; meaning we can just use the
 * space between the PP_SIGNATURE value (without POISON_POINTER_DELTA), and the
 * lowest bits of POISON_POINTER_DELTA. On arches where POISON_POINTER_DELTA is
 * 0, we make sure that we leave the two topmost bits empty, as that guarantees
 * we won't mistake a valid kernel pointer for a value we set, regardless of the
 * VMSPLIT setting.
 *
 * Altogether, this means that the number of bits available is constrained by
 * the size of an unsigned long (at the upper end, subtracting two bits per the
 * above), and the definition of PP_SIGNATURE (with or without
 * POISON_POINTER_DELTA).
 */
#define PP_DMA_INDEX_SHIFT (1 + __fls(PP_SIGNATURE - POISON_POINTER_DELTA))
#if POISON_POINTER_DELTA > 0
/* PP_SIGNATURE includes POISON_POINTER_DELTA, so limit the size of the DMA
 * index to not overlap with that if set
 */
#define PP_DMA_INDEX_BITS MIN(32, __ffs(POISON_POINTER_DELTA) - PP_DMA_INDEX_SHIFT)
#else
/* Always leave out the topmost two; see above. */
#define PP_DMA_INDEX_BITS MIN(32, BITS_PER_LONG - PP_DMA_INDEX_SHIFT - 2)
#endif

#define PP_DMA_INDEX_MASK GENMASK(PP_DMA_INDEX_BITS + PP_DMA_INDEX_SHIFT - 1, \
				  PP_DMA_INDEX_SHIFT)

/* Mask used for checking in page_pool_page_is_pp() below. page->pp_magic is
 * OR'ed with PP_SIGNATURE after the allocation in order to preserve bit 0 for
 * the head page of compound page and bit 1 for pfmemalloc page, as well as the
 * bits used for the DMA index. page_is_pfmemalloc() is checked in
 * __page_pool_put_page() to avoid recycling the pfmemalloc page.
 */
#define PP_MAGIC_MASK ~(PP_DMA_INDEX_MASK | 0x3UL)

#ifdef CONFIG_PAGE_POOL
static inline bool page_pool_page_is_pp(const struct page *page)
{
	return (page->pp_magic & PP_MAGIC_MASK) == PP_SIGNATURE;
}
#else
static inline bool page_pool_page_is_pp(const struct page *page)
{
	return false;
}
#endif

#define PAGE_SNAPSHOT_FAITHFUL (1 << 0)
#define PAGE_SNAPSHOT_PG_BUDDY (1 << 1)
#define PAGE_SNAPSHOT_PG_IDLE  (1 << 2)

struct page_snapshot {
	struct folio folio_snapshot;
	struct page page_snapshot;
	unsigned long pfn;
	unsigned long idx;
	unsigned long flags;
};

static inline bool snapshot_page_is_faithful(const struct page_snapshot *ps)
{
	return ps->flags & PAGE_SNAPSHOT_FAITHFUL;
}

void snapshot_page(struct page_snapshot *ps, const struct page *page);

#endif /* _LINUX_MM_H */
