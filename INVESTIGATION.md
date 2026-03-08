# bcachefs SRCU lock held too long — crash investigation, audit, and patch series

## The crash (2026-02-27 ~19:29-19:32 +08:00)

Matthias' Arch Linux desktop machine (128 GB RAM, 32 cores, bcachefs root filesystem with
tiered SSD+HDD storage) became completely unresponsive and required a
hard reset.  The previous boot ran kernel 6.18.9-arch1-2.1 with bcachefs
as a DKMS out-of-tree module.

### Filesystem layout

```
/dev/sdd1:/dev/nvme0n1p3:/dev/sda:/dev/sdb:/dev/sdc on / type bcachefs
  foreground_target: ssd
  background_target: hdd
  promote_target:    ssd
  background_compression: zstd:15
  data_replicas: 2
  metadata_replicas: 2
```

Five devices: one NVMe (ssd label), four HDDs (hdd label).  Data is
written to the SSD tier and reconcile moves it to the HDD tier with zstd
compression in the background.

### Workload at the time

Heavy development workload (~27 concurrent IDE sessions totalling ~68 GB
of anonymous memory), plus ~16 GB of kernel slab (bcachefs metadata).

### Timeline (from `journalctl --boot=-1`)

| Time | Event |
|------|-------|
| 19:29:28 | First `warn_alloc` (1471 callbacks suppressed) |
| 19:29:32 | kswapd0: order-0 page allocation failure.  Free: ~76 MB.  slab_unreclaimable: 16.6 GB.  Anon: ~85 GB.  Swap 750 GB free / 869 GB total. |
| 19:31:51 | Second failure.  `warn_alloc: 17,143 callbacks suppressed`.  Anon: ~90 GB. |
| 19:32:10 | bcachefs `do_reconcile_phys_thread` page allocation failure (`bch2_bio_alloc_pages` -> `bch2_data_update_init` -> `bch2_move_extent`).  Free: ~45 MB.  zswap shrinker caught in catch-22: decompression needs a page, but none available. |
| 19:32:26 | mypy page fault failure.  Free: ~10 MB. |
| 19:32:32 | **`btree trans held srcu lock (delaying memory reclaim) for 13 seconds`** — two instances from `do_reconcile_phys_thread` on CPUs 10 and 13. |
| 19:32:52 | Last log entry.  System unresponsive.  Hard reset required. |

### Why the OOM killer didn't fire

No "Killed process" messages in the logs.  bcachefs's SRCU read lock
blocked SRCU grace period completion, preventing reclaim of old btree
node memory.  The system deadlocked in the reclaim path before OOM could
act.

### Why swap didn't help

Swap (869 GB on non-bcachefs partitions) was 85% free.  The bottleneck
was not "where to put evicted pages" but "the kernel can't execute the
eviction":

1. `slab_unreclaimable` (16.6 GB) is kernel memory, never eligible for
   swap.
2. Reclaim needs temporary pages (zswap decompression buffers) but none
   were available.
3. SRCU read lock prevented grace periods, blocking old btree node
   reclaim.

## Root cause analysis

### The SRCU lock's role

bcachefs uses an SRCU read lock to protect btree node memory from being
freed while transactions read it.  Two unlock functions exist:

- `bch2_trans_unlock(trans)` — releases btree node locks only
- `bch2_trans_unlock_long(trans)` — releases btree locks AND the SRCU
  read lock

When code calls `bch2_trans_unlock` before a blocking operation, the SRCU
lock is still held.  If that blocking operation triggers page reclaim,
and reclaim needs to free bcachefs btree nodes, it must wait for the SRCU
grace period — which can't complete because we're holding the read lock.
Deadlock.

### The specific crash path

In `bch2_data_update_init()` (fs/bcachefs/data/update.c:1357), after
btree lookups are done, `bch2_trans_unlock(trans)` is called before
`bch2_data_update_bios_init()`, which does:

- `kmalloc_array(nr_vecs, ..., GFP_KERNEL)` for bio vecs
- `bch2_bio_alloc_pages(..., GFP_KERNEL)` for the write bio

Under memory pressure, these block in the page allocator for seconds
while the SRCU lock is held.

## The fix

Single commit on branch `fix/drop-srcu-pr`, based on `origin/master`.
Reproducer and investigation notes on the stacked branch
`fix/drop-srcu-before-data-update-alloc`.

At each of the 25 sites below, `bch2_trans_unlock()` is changed to
`bch2_trans_unlock_long()`, or `drop_locks_do()` is changed to the new
`drop_locks_long_do()` macro (which also drops the SRCU read lock).

Also introduces the `drop_locks_long_do()` macro in btree/iter.h and
cleans up `bch2_fsck_ask_yn()` in init/error.c (Kent's deferred
`unlock_long_at` workaround is no longer needed since we drop SRCU
immediately).

### Summary: 25 sites fixed

| Area | Sites | Operations |
|------|-------|------------|
| btree/cache.c | 4 | GFP_KERNEL allocs, sync I/O, wait_on_bit_io |
| btree/commit.c | 3 | GFP_KERNEL alloc, journal reclaim wait, journal res get |
| btree/interior.c | 5 | mutex, closure_sync, wait_event, down_read |
| btree/locking.c | 1 | mutex_lock |
| btree/read.c | 1 | sync disk I/O |
| alloc/foreground.c | 1 | mutex_lock |
| data/update.c | 3 | GFP_KERNEL bio alloc, closure_sync (x2) |
| data/ec/io.c | 1 | kvmalloc + multi-device I/O |
| data/migrate.c | 1 | closure_wait_event for in-flight writes |
| data/write.c | 1 | nocow lock + GFP_KERNEL |
| vfs/buffered.c | 1 | filemap_alloc_folio + GFP_KERNEL |
| vfs/fs.c | 1 | __wait_on_freeing_inode |
| init/error.c | 1 | user input wait |
| debug/tests.c | 1 | journal flush |

## Related upstream issues

Surveyed 14 issues on koverstreet/bcachefs.  Our patch series directly
addresses the `bch2_data_update_init` bio allocation path and indirectly
helps many other paths.

### Issues our patches help

| Issue | Title | Status | Relevant path |
|-------|-------|--------|---------------|
| [#934](https://github.com/koverstreet/bcachefs/issues/934) | device evacuate: SRCU held 21s | Open | data_update_init + write buffer flush |
| [#636](https://github.com/koverstreet/bcachefs/issues/636) | SRCU held 48s during rebalance | Closed | data_update_init via do_rebalance |

**Foreground I/O Stalls (Tiered Storage / Writeback)**
These patches were also found to completely resolve severe, multi-minute foreground I/O stalls (`ls`, `stat`, etc.) that occur when the system is performing heavy background writes to a slow tier (e.g. `dd` sequentially bypassing an SSD tier and writing directly to HDDs). Previously, the background writeback/promotion threads would hold the SRCU read lock while blocking on slow HDD I/O, freezing all foreground VFS operations that needed btree locks. With `bch2_trans_unlock_long()`, foreground I/O remains instantly responsive (e.g. 2ms) even under maximum background write pressure.

### Issues with different root causes (not addressed by our patches)

The most common SRCU-held-too-long path across issues is
`bch2_btree_write_buffer_flush_locked`, called from `bch2_trans_begin`.
This is an architectural issue — the write buffer flush happens inside
the transaction after SRCU is re-acquired, and can take a long time when
it needs to synchronize with journal reclaim or flush large numbers of
buffered keys.

| Issue | Title | Status | Root cause |
|-------|-------|--------|------------|
| [#936](https://github.com/koverstreet/bcachefs/issues/936) | System freeze during snapshot remove | Open | write_buffer_flush mass-trigger |
| [#1021](https://github.com/koverstreet/bcachefs/issues/1021) | device remove: SRCU | Closed | reconcile write_buffer_flush |
| [#1028](https://github.com/koverstreet/bcachefs/issues/1028) | reclaim/reconcile both stuck | Closed | write_buffer_flush_seq mutex |
| [#1045](https://github.com/koverstreet/bcachefs/issues/1045) | Soft lockup during reconcile | Closed | sort in bp_scan |
| [#779](https://github.com/koverstreet/bcachefs/issues/779) | System lockup after NFS | Closed | rhashtable_insert_slow |
| [#605](https://github.com/koverstreet/bcachefs/issues/605) | SRCU held >10s (parent) | Closed | __bch2_create VFS path |
| [#811](https://github.com/koverstreet/bcachefs/issues/811) | Startup delays SRCU 19s | Closed | __bch2_create at boot |
| [#826](https://github.com/koverstreet/bcachefs/issues/826) | SRCU 13s interior update | Closed | btree_interior_update_work |
| [#807](https://github.com/koverstreet/bcachefs/issues/807) | OOM from fsck rhashtable | Closed | rhashtable growth in key cache |
| [#882](https://github.com/koverstreet/bcachefs/issues/882) | Excessive memory use | Open | btree_bounce_alloc |

### Prior fixes by Kent Overstreet

| Commit | Site |
|--------|------|
| 2ff6837f9be3 | btree/commit.c — journal reclaim wait timeout path |
| a727c2357464 | alloc/backpointers.c — bp scan sort |
| c4accde498dd | Early SRCU hold-time enforcement |

## VM test reproducer

### What the reproducer exercises

The test creates a 128 MB RAM VM with pre-populated tiered bcachefs,
then eats 200 MB of memory to force every page allocation through
reclaim.  The code paths exercised:

**Reconcile thread** (`do_reconcile_phys_thread`):
- `bch2_data_update_init` → `bch2_data_update_bios_init` (commit 1)
- Btree lookups → `bch2_btree_node_fill` / `bch2_btree_node_mem_alloc` (commit 2)
- If btree nodes split → `bch2_btree_update_start` allocator wait (commit 4)

**Btree commit path** (any transaction commit under pressure):
- Key cache insert → `btree_key_can_insert_cached_slowpath` (commit 3)
- Journal reclaim wait (commit 3)
- Journal reservation → `drop_locks_long_do` (commit 9)

**Readahead** (if reconcile/user reads trigger it):
- `readpage_bio_extend` folio allocation (commit 7)

**Not exercised** (would need different test setups):
- EC stripe reconstruction (no erasure coding configured)
- Device removal/migration
- `bch2_btree_write_buffer_flush_locked` (architectural, inside bch2_trans_begin)

### Setup

```bash
# Build kernel (tinyconfig + virtio + bcachefs + serial + swap)
make -j$(nproc)

# Prepare disk images (one-time, needs root for loopback mount)
sudo ./prepare-vm-disks.sh

# Build initramfs (static musl Rust binary, ~430 KB)
./build-initramfs.sh

# Run test
./run-vm-test.sh fixed arch/x86/boot/bzImage
```

### How it works

1. `prepare-vm-disks.sh` — formats bcachefs with tiered storage on the
   host, writes 60 MB of data to the SSD tier, saves pristine images
2. `build-initramfs.sh` — builds the static Rust init binary (musl),
   packs a minimal initramfs (~430 KB)
3. `run-vm-test.sh` — copies pristine images, boots 128 MB QEMU VM:
   - bcachefs disks throttled to 512 KB/s write (slows reconcile)
   - swap disk unthrottled (matches real crash: swap on non-bcachefs)
   - 300s timeout
4. VM init (`vm-init-rs/`) — mounts swap, mounts pre-populated bcachefs
   (reconcile starts immediately), forks a child that eats 200 MB,
   prints heartbeats every 5s for 120s.  If heartbeats stop, system hung.

### Expected results

- **Unfixed kernel**: SRCU warnings from multiple paths (btree cache
  allocations, journal reclaim waits, reconcile bio allocation).
  System may hang under sufficient pressure.
- **Fixed kernel**: no SRCU warnings, or warnings with much shorter
  hold times.  System remains responsive throughout.

## Remaining work

### Audit: sites NOT yet fixed

Low-risk direct `bch2_trans_unlock` sites (no blocking follows, or
immediately followed by `bch2_trans_put`/`bch2_trans_begin`):

- `btree/iter.c:3521` — `cond_resched()`, SRCU check follows immediately
- `btree/interior.c:878` — immediate `bch2_trans_begin` re-acquires SRCU
- `vfs/buffered.c:340` — `bch2_trans_put` releases SRCU right after
- `alloc/accounting.c:1145` — CPU-bound sort/fixup, no blocking

Medium-risk `drop_locks_do` sites (bounded waits, could be converted):

- `debug/debug.c:424` — `copy_to_user` (page fault possible)
- `btree/commit.c:960,1089` — `bch2_accounting_update_sb` (superblock I/O)
- `vfs/fs.c:489` — `__bch2_new_inode(GFP_NOFS)` (reclaim possible)
- `vfs/io.c:697,733` — pagecache operations
- `vfs/fiemap.c:144,265,276` — `copy_to_user` via fiemap

### Architectural: `bch2_btree_write_buffer_flush_locked`

The single most reported SRCU-held-too-long path (#934, #936, #1021,
#1028, #1045).  Called from `bch2_trans_begin` which re-acquires SRCU
at the start of each transaction iteration.  The flush can take a long
time when synchronizing with journal reclaim.  This is not fixable with
simple `_long` conversions — it needs structural changes to how the
write buffer flush interacts with SRCU.

### Cost analysis

Each `bch2_trans_unlock_long` → `bch2_trans_relock` round-trip costs two
atomic operations (SRCU unlock + re-lock).  Under normal conditions this
is negligible.  Under memory pressure it's the difference between a
responsive system and a deadlock.

## Files

### Kernel patches

All under `fs/bcachefs/`:

- `btree/iter.h` — `drop_locks_long_do()` macro
- `btree/cache.c` — 4 sites
- `btree/commit.c` — 3 sites
- `btree/interior.c` — 5 sites
- `btree/locking.c` — 1 site
- `btree/read.c` — 1 site
- `alloc/foreground.c` — 1 site
- `data/update.c` — 3 sites
- `data/ec/io.c` — 1 site
- `data/migrate.c` — 1 site
- `data/write.c` — 1 site
- `vfs/buffered.c` — 1 site
- `vfs/fs.c` — 1 site
- `init/error.c` — 1 site (+ cleanup of Kent's deferred workaround)
- `debug/tests.c` — 1 site

### Test infrastructure

- `INVESTIGATION.md` — this file
- `vm-init-rs/` — static Rust init binary for the VM test
- `vm-disks/` — pristine disk images (fast, slow, swap)
- `prepare-vm-disks.sh` — format + pre-populate disk images on the host
- `build-initramfs.sh` — build static musl initramfs
- `run-vm-test.sh` — run test VM, analyze results
