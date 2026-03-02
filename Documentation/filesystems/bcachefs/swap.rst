.. SPDX-License-Identifier: GPL-2.0

==========================
bcachefs Swap File Support
==========================

Overview
========

bcachefs supports swap files using the ``SWP_FS_OPS`` path, keeping the
filesystem in the I/O loop for swap operations.  Unlike btrfs (which
disables COW, checksums, and compression for swap), bcachefs swap files
use the normal COW write path.  Swap data gets checksumming, encryption,
compression, replication, and multi-device support.

Usage::

    fallocate -l 4G /mnt/bcachefs/swapfile
    chmod 600 /mnt/bcachefs/swapfile
    mkswap /mnt/bcachefs/swapfile
    swapon /mnt/bcachefs/swapfile

A small raw swap partition or zram as a safety net is recommended for
extreme memory pressure.

The Reclaim Deadlock Problem
============================

Swap writes happen during memory reclaim — the kernel writes pages to
swap *because* it is out of memory.  A COW filesystem needs memory for
btree updates, journal entries, and block allocation.  If any allocation
in the swap write path tries to reclaim memory, reclaim tries to swap
more pages → filesystem re-entry → deadlock.

How Other Filesystems Handle This
---------------------------------

**ext4, XFS** (non-COW): the kernel writes directly to pre-mapped
physical blocks via ``iomap_swapfile_activate``.  The filesystem is not
involved after swapon.

**btrfs**: disables COW, checksums, compression, RAID, and snapshots
for swap files.  Effectively degrades to the ext4 model.

**NFS**: uses ``SWP_FS_OPS`` — the only path where the filesystem stays
in the I/O loop.  This is what we use.

**dm-thin**: the existence proof that COW + swap can work.  Uses
mempools for all critical allocations (1024-element pools that never
fail).

Our Approach
============

Five mechanisms work together to make COW swap safe under memory
pressure.

PF_MEMALLOC
-----------

``swap_rw`` sets ``PF_MEMALLOC`` (via ``memalloc_noreclaim_save``) for
both reads and writes.  This tells the page allocator to use emergency
reserves rather than entering direct reclaim.

Why reads too: swap-in happens during page faults.  If a read-path
allocation enters reclaim, reclaim may start swap writes that compete
for the same btree locks — deadlock.

Critical detail: the write index update runs in a kworker thread
(``bch2_write_point_do_index_updates``), which does **not** inherit
task flags from the caller.  The ``BCH_WRITE_swap`` flag on the write
op tells the worker to set ``PF_MEMALLOC`` for that op's duration.

Btree Node Pinning
------------------

At swapon, leaf nodes for the extents, inodes, and alloc btrees
covering the swap file's key range are marked ``noevict``.  This
prevents the btree cache shrinker from evicting them.

Interior btree nodes are not pinned — they are few, hot, and covered
by the btree cache pre-reserve.

Btree Cache Pre-reserve
-----------------------

16 MB of btree node buffers are pre-allocated on ``bc->freeable`` at
swapon.  ``bch2_btree_node_mem_alloc`` checks freeable first, stealing
a pre-allocated buffer instead of hitting the page allocator.

The allocation uses ``GFP_NORETRY`` to avoid OOM on small VMs (the
pre-reserve is best-effort; partial allocation is handled gracefully).

``bc->nr_reserve`` is bumped in parallel to reduce the shrinker's
``can_free`` budget, indirectly shielding the pre-allocated buffers
from being drained.

Disk Reservation
----------------

``swap_pages × PAGE_SECTORS`` sectors are reserved at swapon.  Each
COW write allocates a new physical block before freeing the old one.
The reservation reduces ``sectors_available``, causing normal writers
to ENOSPC sooner, preserving free buckets for swap.

Swap writes themselves skip the reservation gate entirely: for a 1:1
COW overwrite (same size, same replicas), ``disk_sectors_delta = 0``
and the ``bch2_disk_reservation_add`` check in ``bch2_extent_update``
is never reached.

If the filesystem lacks space for the reservation, swapon fails
immediately with ENOSPC — failing loudly at mount time rather than
silently during reclaim.

Bkey Buffer Pre-allocation
--------------------------

A 2048-byte buffer is allocated with ``GFP_NOWAIT`` before entering
``PF_MEMALLOC`` in the write index kworker.  This avoids
``__GFP_NOFAIL`` WARN loops when ``bch2_bkey_buf_realloc`` spills
from its 96-byte on-stack buffer.

``GFP_NOWAIT`` rather than ``GFP_KERNEL``: the kworker context can
amplify a pre-existing deadlock path where ``journal_write`` →
``kvmalloc`` → direct reclaim → btree cache shrinker → needs journal
→ deadlock.  ``GFP_NOWAIT`` avoids entering reclaim entirely.  If
the allocation fails, the existing ``__GFP_NOFAIL`` fallback under
``PF_MEMALLOC`` handles it (using emergency reserves).

What Didn't Work
================

Pre-fragmentation of Extents
-----------------------------

The idea: at swapon, split the swap file's extents to page granularity
so every COW swap write is a 1:1 extent replacement (same logical
range, different physical pointer) instead of a 1→3 split.  This would
eliminate btree growth during swap I/O.

**Why it fails**: ``bch2_trans_update_extent`` performs front/back
merging of adjacent extents with contiguous physical pointers.  Since
the swap file is allocated contiguously (via ``fallocate``), each
split extent is immediately re-merged with its neighbor.  The entire
65536-iteration prefrag loop is a no-op.

All tests pass without pre-fragmentation.  COW 1→3 splits at swap
write time work correctly via ``bch2_extent_trim_atomic``.

Pre-fragmentation could be made to work by suppressing extent merging
during the split loop (e.g. a ``BTREE_UPDATE_no_merge`` flag) or by
inserting non-contiguous extents.  Worth revisiting if profiling shows
the 1→3 splits are a bottleneck under sustained pressure.

GFP_NOIO / GFP_NOFS for Individual Allocation Sites
----------------------------------------------------

Instead of ``PF_MEMALLOC``, we tried marking individual allocations
as ``GFP_NOIO`` or ``GFP_NOFS``.  This is a game of whack-a-mole:
fixing one site (e.g. ``bch2_printbuf_make_room``) just moves the
deadlock to the next ``GFP_KERNEL`` allocation in the btree path.
``PF_MEMALLOC`` is the correct blanket fix — it prevents reclaim from
all allocations in the task.

GFP_NOWAIT for Printbuf
------------------------

Making ``bch2_printbuf_make_room`` use ``GFP_NOWAIT`` causes the
allocation to fail, which makes the btree transaction retry, which
hits the next allocation.  The retry loop burns CPU without progress.

memalloc_noreclaim in swap_rw Only
-----------------------------------

Setting ``PF_MEMALLOC`` only in the ``swap_rw`` caller doesn't help
because the write index update runs in a kworker thread that doesn't
inherit the caller's task flags.  The ``BCH_WRITE_swap`` flag was
added specifically to propagate the noreclaim context to the kworker.

GFP_KERNEL for Bkey Pre-allocation
------------------------------------

The initial bkey pre-alloc used ``GFP_KERNEL``.  This triggered direct
reclaim in the write index kworker, amplifying the ``journal_write`` →
reclaim → btree shrinker → journal deadlock.  Changing to
``GFP_NOWAIT`` eliminated the regression.

Adversarial Analysis
====================

Dead-key Accumulation
---------------------

A btree node has at most 3 bsets.  When a node is written to disk and
then dirtied, old keys become dead space in the written bset.  Worst
case: a node starts at 50% live keys, all are overwritten via swap →
50% dead + 50% new live = 100% full.

Natural throttle: journal pressure.  Each swap write creates a journal
entry.  When the journal fills, reclaim writes dirty btree nodes,
compacting dead keys and restoring headroom.  Heavy swap → journal
fills → reclaim → compaction → headroom restored.

Residual risk: if a burst of writes fills a node to 100% before
journal reclaim triggers, the insert fails.  The 80% fill monitoring
(``btree/commit.c``) provides early warning.

Shared Btree Nodes
------------------

The swap file's extent keys live in ``BTREE_ID_extents``, shared with
all other files.  Other files' operations could insert keys into nodes
containing swap keys, eating into headroom.

In practice, extent btree keys are ordered by ``(inode, offset,
snapshot)``.  Different inodes share a leaf only when numerically
adjacent.  The risk is confined to boundary nodes.

Future options: reserved inode bit for swap files (no format change),
or a dedicated ``BTREE_ID_swap_extents`` (format change, structurally
eliminates sharing).

ENOSPC During Swap Writes
--------------------------

Even with the disk reservation, free space may be in partially-used
buckets with zero completely-free buckets on a fragmented filesystem.
Copygc must consolidate, competing for I/O.  The large reservation
helps copygc stay healthy, but ENOSPC during reclaim is extremely
unlikely rather than structurally impossible.

Diagnostics
===========

- **80% fill monitoring**: rate-limited ``bch_info`` when extents btree
  leaves exceed 80% fill (early warning before the 67% split
  threshold).

- **Swap I/O stall detection**: WARN at 2 seconds, BUG at 10 seconds
  (debug builds only).  Produces a crash dump with symbolized stacks
  instead of a silent hang.

- **Ablation toggles**: ``bcachefs.swap_nopin`` and
  ``bcachefs.swap_noreclaim`` cmdline options disable individual
  protections for A/B testing.

Limitations and Future Work
============================

- ``PF_MEMALLOC`` uses emergency memory reserves.  Under extreme
  pressure these could be depleted.  A small raw swap or zram as a
  safety net is recommended.

- Btree node pinning pins all alloc btree leaf nodes, which is
  significant on large filesystems.  Lazy pinning (pin on first use,
  never unpin) is a future optimization.

- No deferred btree splits under memory pressure.

- No minimum free space check at swapon beyond the disk reservation
  (a warning when free space is barely sufficient for copygc would
  be useful).
