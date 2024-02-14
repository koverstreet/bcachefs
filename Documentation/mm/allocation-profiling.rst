.. SPDX-License-Identifier: GPL-2.0

===========================
MEMORY ALLOCATION PROFILING
===========================

Low overhead (suitable for production) accounting of all memory allocations,
tracked by file and line number.

Usage:
kconfig options:
 - CONFIG_MEM_ALLOC_PROFILING
 - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
 - CONFIG_MEM_ALLOC_PROFILING_DEBUG
   adds warnings for allocations that weren't accounted because of a
   missing annotation

sysctl:
  /proc/sys/vm/mem_profiling

Runtime info:
  /proc/allocinfo

Example output:
  root@moria-kvm:~# sort -h /proc/allocinfo|tail
   3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_inode
   3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_stack_node
   3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_ext
   4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_collapse_alloc_folio
   10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc_rqs
   14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_alloc_noprof
   26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_alloc_noprof
   64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_init
   98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio_alloc_noprof
    125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page


Theory of operation:

Memory allocation profiling builds off of code tagging, which is a library for
declaring static structs (that typcially describe a file and line number in
some way, hence code tagging) and then finding and operating on them at runtime
- i.e. iterating over them to print them in debugfs/procfs.

To add accounting for an allocation call, we replace it with a macro
invocation, alloc_hooks(), that
 - declares a code tag
 - stashes a pointer to it in task_struct
 - calls the real allocation function
 - and finally, restores the task_struct alloc tag pointer to its previous value.

This allows for alloc_hooks() calls to be nested, with the most recent one
taking effect. This is important for allocations internal to the mm/ code that
do not properly belong to the outer allocation context and should be counted
separately: for example, slab object extension vectors, or when the slab
allocates pages from the page allocator.

Thus, proper usage requires determining which function in an allocation call
stack should be tagged. There are many helper functions that essentially wrap
e.g. kmalloc() and do a little more work, then are called in multiple places;
we'll generally want the accounting to happen in the callers of these helpers,
not in the helpers themselves.

To fix up a given helper, for example foo(), do the following:
 - switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
 - rename it to foo_noprof()
 - define a macro version of foo() like so:
   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))
