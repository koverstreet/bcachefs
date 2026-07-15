// SPDX-License-Identifier: GPL-2.0

/* DOC_LATEX(device-management)
 * bcachefs is a multi-device filesystem: a single filesystem can span any number
 * of block devices, each contributing storage capacity and IO bandwidth. Devices
 * need not be the same size or have the same performance characteristics---the
 * \hyperref[sec:write-points]{allocator} stripes across all available devices,
 * biasing toward devices with more free space so that all devices fill at the
 * same rate, and the read path
 * tracks per-device IO latency to direct reads to the fastest available replica.
 *
 * Devices can be added and removed at any time without unmounting.
 *
 * \subsubsection{Per-device metadata}
 *
 * Each device has a \texttt{bch\_member} entry in the
 * \hyperref[sec:superblock]{superblock} containing:
 *
 * \begin{itemize}
 * \item \textbf{Identity}: per-device UUID, device name, model string
 * \item \textbf{Geometry}: bucket count, bucket size, first usable bucket
 * \item \textbf{State}: rw, ro, evacuating, or spare (see below)
 * \item \textbf{Configuration}: durability, data-type restrictions
 *   (\texttt{data\_allowed}), discard (TRIM) support, rotational hint
 * \item \textbf{Diagnostics}: cumulative error counters (read, write,
 *   checksum), performance measurements (sequential and random IO rates),
 *   last mount timestamp
 * \end{itemize}
 *
 * \subsubsection{Device states}
 *
 * Each device has a persistent state stored in the superblock:
 *
 * \begin{description}
 * \item[\texttt{rw}] Read-write: fully operational, participates in allocation
 * \item[\texttt{ro}] Read-only: can be read from but receives no new writes
 * \item[\texttt{evacuating}] Being emptied of data prior to removal
 * \item[\texttt{spare}] Reserved, not currently participating in IO
 * \end{description}
 *
 * Device state is changed with \texttt{bcachefs device set-state}. Transitions
 * that would reduce write redundancy below the configured replication level
 * require the \texttt{-{}-force} flag.
 *
 * Separately from the persistent state, a device can be \emph{online} (kernel
 * has the device open) or \emph{offline} (device is listed in the superblock but
 * not currently accessible).
 *
 * \subsubsection{Durability}
 *
 * The \texttt{durability} setting controls how many replicas a copy on a given
 * device counts for. The default is 1. Setting \texttt{durability=2} on a
 * hardware RAID device tells bcachefs that data on that device already has
 * internal redundancy---it counts as two replicas, so the filesystem does not
 * need to keep an additional copy elsewhere. Setting \texttt{durability=0} means
 * copies on the device do not count toward replication requirements at all---the
 * device can only be used as a cache.
 *
 * \subsubsection{Caching}
 *
 * When an extent has multiple copies on different devices, some of those copies
 * may be marked as \emph{cached}. Cached copies are evicted in LRU order by the
 * allocator when the device needs space. Caching behavior is controlled through
 * the target options:
 *
 * \begin{description}
 * \item[Writeback caching] Set \texttt{foreground\_target} and
 *   \texttt{promote\_target} to the cache device, and
 *   \texttt{background\_target} to the backing device. Writes land on the fast
 *   device first and migrate to the backing device in the background.
 * \item[Writearound caching] Set \texttt{foreground\_target} to the backing
 *   device and \texttt{promote\_target} to the cache device. Writes go directly
 *   to the backing device; frequently-read data is promoted to the cache.
 * \end{description}
 *
 * The \texttt{durability=0} setting is essential for cache devices: it ensures
 * bcachefs does not count cached copies toward the replica count, so losing the
 * cache device never causes data loss.
 *
 * \subsubsection{Adding and removing devices}
 *
 * \begin{description}
 * \item[\texttt{bcachefs device add}] Adds a new device to a mounted
 *   filesystem. The device is formatted with bcachefs metadata and integrated
 *   immediately---new allocations can land on it right away. A label can be
 *   assigned at add time with \texttt{-l}. Other per-device options
 *   (\texttt{-{}-discard}, \texttt{-{}-durability}) can be set at add time.
 *
 *   The new device must have a block size and bucket size compatible with the
 *   existing filesystem. After the device is added, its UUID is published via
 *   uevent so that \texttt{/dev/disk/by-uuid} symlinks are updated, and the
 *   reconcile subsystem is notified to scan for any work on the new device.
 *
 * \item[\texttt{bcachefs device evacuate}] Migrates all data off a device,
 *   displaying progress as sectors are moved. Uses the reconcile subsystem
 *   internally; the device's state transitions to evacuating during the process.
 *   Requires metadata version $\geq$ \texttt{reconcile} (1.33).
 * \item[\texttt{bcachefs device remove}] Removes a fully evacuated device from
 *   the filesystem and erases its metadata. Force flags allow removal even if
 *   some data (\texttt{-f}) or metadata (\texttt{-F}) would be lost.
 *
 *   Two removal code paths exist: the legacy path walks the btree to find and
 *   relocate all references to the device, while the \texttt{fast\_device\_removal}
 *   path (default on newer metadata versions) uses
 *   \hyperref[sec:backpointers]{backpointers} to efficiently locate all data
 *   on the device without a full btree scan.
 *
 * \item[\texttt{bcachefs device online/offline}] Bring a device back online or
 *   take it offline without removing it. Offline devices retain their superblock
 *   membership and can be brought back later. Bringing a device online includes
 *   a splitbrain check against the running filesystem's sequence numbers;
 *   onlining also triggers a reconcile scan to detect any data that may need
 *   re-replication.
 *
 *   Offlining a device requires that the remaining online devices can still
 *   satisfy both read and write requirements---the kernel checks that at least
 *   one device can serve reads and at least one can accept writes for every
 *   replica group. If offlining would leave the filesystem unable to operate,
 *   the request is rejected unless forced.
 * \end{description}
 *
 * The typical device removal workflow: \texttt{bcachefs device evacuate /dev/sda}
 * (wait for completion, watching progress), then \texttt{bcachefs device remove
 * /dev/sda}.
 *
 * \subsubsection{Block layer hot-remove}
 *
 * When the block layer reports a device as dead (e.g., a USB drive is
 * unplugged, or a disk is removed from a hot-swap bay), bcachefs receives
 * a notification and attempts a graceful response. If the device can be
 * offlined without leaving the filesystem unable to operate, it is taken
 * offline automatically. Otherwise, the filesystem transitions to
 * emergency read-only mode to prevent data corruption from writes that
 * can no longer reach all required replicas.
 *
 * \subsubsection{Data-type restrictions}
 *
 * The \texttt{data\_allowed} member field restricts which data types a device
 * can hold: journal, btree, or user data. This allows dedicating fast devices to
 * metadata while slower devices hold only user data, or restricting a device to
 * journal-only for write-ahead log isolation. Restrictions are set at format
 * time or via \texttt{set-fs-option} and are enforced by the
 * \hyperref[sec:write-points]{allocator}.
 *
 * \subsubsection{Degraded mode}
 *
 * When a device is unavailable (failed, offline, or physically disconnected),
 * the filesystem can continue operating in degraded mode if sufficient
 * redundancy remains. The number of tolerable failures per replica group is
 * \texttt{nr\_devs - nr\_required}: with 3-way replication, one device can fail
 * without data loss.
 *
 * The \texttt{degraded} mount option controls behavior when devices are missing:
 *
 * \begin{description}
 * \item[\texttt{degraded=true}] Allow mounting with missing devices (read-only
 *   access to degraded data)
 * \item[\texttt{degraded=run}] Allow mounting and normal operation with missing
 *   devices
 * \item[\texttt{degraded=very}] Allow mounting even if writes cannot maintain
 *   the requested replica count (\textbf{dangerous}---creates splitbrain risk)
 * \end{description}
 *
 * While degraded, the filesystem has reduced safety margin---further device loss
 * may cause data unavailability. The reconcile subsystem will automatically
 * repair degraded data by re-replicating to available devices.
 *
 * \subsubsection{Resize}
 *
 * \texttt{bcachefs device resize} resizes a device to use more or less space.
 * If no size is specified, the device grows to
 * fill its underlying block device. Resize works online---no unmount required.
 * Resize is executed by a per-device kthread, which is restarted when a
 * newer request overwrites an in-progress resize, automatically cancelling the old resize.
 * Resizes are persisted as \texttt{target\_nbuckets} and will be automatically resumed across restarts.
 *
 * \subsubsubsection{Growing}
 * The new size is subject to a maximum bucket count
 * (\texttt{BCH\_MEMBER\_NBUCKETS\_MAX}); resize will fail if the requested size
 * would exceed this limit. After resize, the reconcile subsystem is notified to
 * account for the newly available space.
 *
 * \subsubsubsection{Shrinking}
 * Shrinking removes the tail region of a device and evacuates any data
 * located there. If this is not possible, the operation will fail with \texttt{-ENOSPC}.
 *
 * Once \texttt{target\_nbuckets < nbuckets} is persisted, the allocator
 * refuses new allocations in the tail, cached pointers past the cutoff are
 * treated as stale, and metadata allocation spills to non-shrinking devices
 * so shrink does not deadlock on its own journal or btree-rewrite needs.
 * Reconcile is then used to discover and evacuate the remaining data.
 *
 * Before draining the tail, the worker relocates any journal buckets in the truncating region explicitly
 * (\texttt{move\_journal\_past\_cutoff()}) so journal activity does not keep
 * reintroducing references into the region being evacuated.
 *
 * Once the tail is empty, the worker finalises under \texttt{state\_lock}:
 * it flushes journal pins, clears \texttt{NEED\_DISCARD} bookkeeping for
 * the removed buckets, drops superblock copies and alloc metadata past the
 * cutoff, then commits \texttt{nbuckets = target\_nbuckets} to the
 * superblock.
 *
 * \texttt{bcachefs device resize-journal} adjusts the per-device journal size
 * independently of the data area.
 *
 * \subsubsection{Device failure and error tracking}
 *
 * Each device tracks cumulative error counters (read, write, checksum) in the
 * superblock members section. These counters persist across mounts and help
 * identify failing hardware before catastrophic failure. The
 * \texttt{write\_error\_timeout} option (default 30 seconds) controls how long
 * sustained write errors must persist before the device is automatically set to
 * read-only.
 *
 * When a device is set to read-only due to errors, reads can still be served
 * from it. If reads also fail, the device should be taken offline entirely to
 * prevent \hyperref[sec:journal]{journal} stalls---the journal cannot reclaim
 * space if it cannot read back btree nodes from a failed device.
 *
 * \subsubsection{Consistency and self-healing}
 *
 * Device membership is tracked in the superblock and cross-validated against
 * on-disk data during recovery. The allocator checks freespace and alloc btrees
 * against each other before using a bucket. Backpointer walks verify that all
 * data on a device is accounted for. If a device is removed or fails, the
 * reconcile subsystem detects under-replicated data and re-replicates it to
 * remaining devices automatically.
 */

#include "alloc/buckets.h"
#include "asm-generic/bug.h"
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/replicas.h"
#include "alloc/foreground.h"

#include "bcachefs_format.h"
#include "btree/bkey_methods.h"
#include "btree/bkey_types.h"
#include "btree/interior.h"

#include "btree/iter.h"
#include "btree/update.h"
#include "btree/types.h"
#include "btree/write_buffer.h"
#include "data/ec/init.h"
#include "data/extents.h"
#include "data/migrate.h"
#include "data/reconcile/work.h"

#include "debug/sysfs.h"

#include "journal/init.h"
#include "journal/journal.h"
#include "journal/reclaim.h"

#include "init/dev.h"
#include "init/fs.h"

#include "linux/bitmap.h"
#include "linux/byteorder/generic.h"
#include "linux/kthread.h"
#include "linux/sched.h"
#include "linux/sched/signal.h"
#include "sb/io.h"
#include "sb/members.h"
#include "sb/members_format.h"
#include "util/util.h"

static void bch2_dev_resize_thread_stop(struct bch_dev *);

#define x(n)		#n,
const char * const bch2_dev_read_refs[] = {
	BCH_DEV_READ_REFS()
	NULL
};

const char * const bch2_dev_write_refs[] = {
	BCH_DEV_WRITE_REFS()
	NULL
};
#undef x

void bch2_devs_list_to_text(struct printbuf *out,
			    struct bch_fs *c,
			    struct bch_devs_list *d)
{
	bch2_printbuf_make_room(out, 1024);
	guard(rcu)();

	darray_for_each(*d, i) {
		if (i != d->data)
			prt_char(out, ' ');

		struct bch_dev *ca = bch2_dev_rcu_noerror(c, *i);
		if (ca)
			prt_str(out, ca->name);
		else
			prt_printf(out, "(invalid device %u)", *i);
	}
}

static int bch2_dev_may_add(struct bch_sb *sb, struct bch_fs *c)
{
	struct bch_member m = bch2_sb_member_get(sb, sb->dev_idx);

	if (le16_to_cpu(sb->block_size) != block_sectors(c))
		return bch_err_throw(c, mismatched_block_size);

	if (le16_to_cpu(m.bucket_size) <
	    BCH_SB_BTREE_NODE_SIZE(c->disk_sb.sb))
		return bch_err_throw(c, bucket_size_too_small);

	return 0;
}

struct bch_fs *bch2_dev_to_fs(dev_t dev)
{
	guard(mutex)(&bch2_fs_list_lock);
	guard(rcu)();

	struct bch_fs *c;
	list_for_each_entry(c, &bch2_fs_list, list)
		for_each_member_device_rcu(c, ca, NULL)
			if (ca->disk_sb.bdev && ca->disk_sb.bdev->bd_dev == dev) {
				closure_get(&c->cl);
				return c;
			}
	return NULL;
}

int bch2_dev_in_fs(struct bch_sb_handle *fs,
		   struct bch_sb_handle *sb,
		   struct bch_opts *opts)
{
	if (fs == sb)
		return 0;

	if (!uuid_equal(&fs->sb->uuid, &sb->sb->uuid))
		return -BCH_ERR_device_not_a_member_of_filesystem;

	if (!bch2_member_exists(fs->sb, sb->sb->dev_idx))
		return -BCH_ERR_device_has_been_removed;

	if (fs->sb->block_size != sb->sb->block_size)
		return -BCH_ERR_mismatched_block_size;

	if (le16_to_cpu(fs->sb->version) < bcachefs_metadata_version_member_seq ||
	    le16_to_cpu(sb->sb->version) < bcachefs_metadata_version_member_seq)
		return 0;

	if (fs->sb->seq == sb->sb->seq &&
	    fs->sb->write_time != sb->sb->write_time) {
		CLASS(printbuf, buf)();

		prt_str(&buf, "Split brain detected between ");
		prt_bdevname(&buf, sb->bdev);
		prt_str(&buf, " and ");
		prt_bdevname(&buf, fs->bdev);
		prt_char(&buf, ':');
		prt_newline(&buf);
		prt_printf(&buf, "seq=%llu but write_time different, got", le64_to_cpu(sb->sb->seq));
		prt_newline(&buf);

		prt_bdevname(&buf, fs->bdev);
		prt_char(&buf, ' ');
		bch2_prt_datetime(&buf, le64_to_cpu(fs->sb->write_time));
		prt_newline(&buf);

		prt_bdevname(&buf, sb->bdev);
		prt_char(&buf, ' ');
		bch2_prt_datetime(&buf, le64_to_cpu(sb->sb->write_time));
		prt_newline(&buf);

		if (!opts->no_splitbrain_check)
			prt_printf(&buf, "Not using older sb");

		pr_err("%s", buf.buf);

		if (!opts->no_splitbrain_check)
			return -BCH_ERR_device_splitbrain;
	}

	struct bch_member m = bch2_sb_member_get(fs->sb, sb->sb->dev_idx);
	u64 seq_from_fs		= le64_to_cpu(m.seq);
	u64 seq_from_member	= le64_to_cpu(sb->sb->seq);

	if (seq_from_fs && seq_from_fs < seq_from_member) {
		CLASS(printbuf, buf)();

		prt_str(&buf, "Split brain detected between ");
		prt_bdevname(&buf, sb->bdev);
		prt_str(&buf, " and ");
		prt_bdevname(&buf, fs->bdev);
		prt_char(&buf, ':');
		prt_newline(&buf);

		prt_bdevname(&buf, fs->bdev);
		prt_str(&buf, " believes seq of ");
		prt_bdevname(&buf, sb->bdev);
		prt_printf(&buf, " to be %llu, but ", seq_from_fs);
		prt_bdevname(&buf, sb->bdev);
		prt_printf(&buf, " has %llu\n", seq_from_member);

		if (!opts->no_splitbrain_check) {
			prt_str(&buf, "Not using ");
			prt_bdevname(&buf, sb->bdev);
		}

		pr_err("%s", buf.buf);

		if (!opts->no_splitbrain_check)
			return -BCH_ERR_device_splitbrain;
	}

	return 0;
}

/* Device startup/shutdown: */

void bch2_dev_io_ref_stop(struct bch_dev *ca, int rw)
{
	if (rw == READ)
		clear_bit(ca->dev_idx, ca->fs->devs_online.d);

	if (!enumerated_ref_is_zero(&ca->io_ref[rw]))
		enumerated_ref_stop(&ca->io_ref[rw],
				    rw == READ
				    ? bch2_dev_read_refs
				    : bch2_dev_write_refs);
}

static void __bch2_dev_read_only(struct bch_fs *c, struct bch_dev *ca)
{
	bch2_dev_io_ref_stop(ca, WRITE);

	/*
	 * The allocator thread itself allocates btree nodes, so stop it first:
	 */
	bch2_dev_allocator_remove(c, ca);
	bch2_recalc_capacity(c);
	bch2_dev_journal_stop(&c->journal, ca);
	bch2_do_discards_async(c);
}

static void __bch2_dev_read_write(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	BUG_ON(ca->mi.state != BCH_MEMBER_STATE_rw);

	bch2_dev_allocator_add(c, ca);
	bch2_recalc_capacity(c);

	if (enumerated_ref_is_zero(&ca->io_ref[WRITE]))
		enumerated_ref_start(&ca->io_ref[WRITE]);

	bch2_do_discards_async(c);
}

void bch2_dev_unlink(struct bch_dev *ca)
{
	struct kobject *b;

	/*
	 * This is racy w.r.t. the underlying block device being hot-removed,
	 * which removes it from sysfs.
	 *
	 * It'd be lovely if we had a way to handle this race, but the sysfs
	 * code doesn't appear to provide a good method and block/holder.c is
	 * susceptible as well:
	 */
	if (ca->kobj.state_in_sysfs &&
	    ca->disk_sb.bdev &&
	    (b = bdev_kobj(ca->disk_sb.bdev))->state_in_sysfs) {
		sysfs_remove_link(b, "bcachefs");
		sysfs_remove_link(&ca->kobj, "block");
	}
}

static void bch2_dev_release(struct kobject *kobj)
{
	struct bch_dev *ca = container_of(kobj, struct bch_dev, kobj);

	kfree(ca);
}

KTYPE(bch2_dev);

void bch2_dev_free(struct bch_dev *ca)
{
	WARN_ON(!enumerated_ref_is_zero(&ca->io_ref[WRITE]));
	WARN_ON(!enumerated_ref_is_zero(&ca->io_ref[READ]));

	bch2_dev_resize_thread_stop(ca);
	cancel_work_sync(&ca->io_error_work);

	bch2_dev_unlink(ca);

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	bch2_bucket_bitmap_free(&ca->bucket_backpointer_mismatch);
	bch2_bucket_bitmap_free(&ca->bucket_backpointer_empty);

	bch2_free_super(&ca->disk_sb);
	bch2_dev_discards_exit(ca);
	bch2_dev_journal_exit(ca);

	free_percpu(ca->io_done);
	bch2_dev_buckets_free(ca);
	kfree(ca->sb_read_scratch);

	bch2_time_stats_quantiles_exit(&ca->io_latency[WRITE]);
	bch2_time_stats_quantiles_exit(&ca->io_latency[READ]);

	enumerated_ref_exit(&ca->io_ref[WRITE]);
	enumerated_ref_exit(&ca->io_ref[READ]);
#ifndef CONFIG_BCACHEFS_DEBUG
	percpu_ref_exit(&ca->ref);
#endif
	kobject_put(&ca->kobj);
}

void __bch2_dev_offline(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	if (enumerated_ref_is_zero(&ca->io_ref[READ]))
		return;

	__bch2_dev_read_only(c, ca);

	bch2_dev_io_ref_stop(ca, READ);

	bch2_dev_unlink(ca);

	bch2_free_super(&ca->disk_sb);
	bch2_dev_journal_exit(ca);
}

#ifndef CONFIG_BCACHEFS_DEBUG
static void bch2_dev_ref_complete(struct percpu_ref *ref)
{
	struct bch_dev *ca = container_of(ref, struct bch_dev, ref);

	complete(&ca->ref_completion);
}
#endif

int bch2_dev_sysfs_online(struct bch_fs *c, struct bch_dev *ca)
{
	if (!c->kobj.state_in_sysfs)
		return 0;

	if (!ca->kobj.state_in_sysfs) {
		try(kobject_add(&ca->kobj, &c->kobj, "dev-%u", ca->dev_idx));
		try(bch2_opts_create_sysfs_files(&ca->kobj, OPT_DEVICE));
	}

	if (ca->disk_sb.bdev) {
		struct kobject *block = bdev_kobj(ca->disk_sb.bdev);

		try(sysfs_create_link(block, &ca->kobj, "bcachefs"));
		try(sysfs_create_link(&ca->kobj, block, "block"));
	}

	return 0;
}

static struct bch_dev *__bch2_dev_alloc(struct bch_fs *c,
					struct bch_member *member)
{
	struct bch_dev *ca;
	unsigned i;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return NULL;

	kobject_init(&ca->kobj, &bch2_dev_ktype);
	init_completion(&ca->ref_completion);
	spin_lock_init(&ca->resize_lock);
	init_waitqueue_head(&ca->resize_wait);
	ca->resize_status = 0;

	INIT_WORK(&ca->io_error_work, bch2_io_error_work);

	bch2_time_stats_quantiles_init(&ca->io_latency[READ]);
	bch2_time_stats_quantiles_init(&ca->io_latency[WRITE]);

	ca->mi = bch2_mi_to_cpu(member);
	ca->btree_allocated_bitmap_gc = le64_to_cpu(member->btree_allocated_bitmap);

	for (i = 0; i < ARRAY_SIZE(member->errors); i++)
		atomic64_set(&ca->errors[i], le64_to_cpu(member->errors[i]));

	ca->uuid = member->uuid;

	ca->nr_btree_reserve = DIV_ROUND_UP(BTREE_NODE_RESERVE,
			     ca->mi.bucket_size / btree_sectors(c));

#ifndef CONFIG_BCACHEFS_DEBUG
	if (percpu_ref_init(&ca->ref, bch2_dev_ref_complete, 0, GFP_KERNEL))
		goto err;
#else
	atomic_long_set(&ca->ref, 1);
#endif

	mutex_init(&ca->bucket_backpointer_mismatch.lock);
	mutex_init(&ca->bucket_backpointer_empty.lock);

	bch2_dev_journal_init_early(ca);

	if (enumerated_ref_init(&ca->io_ref[READ],  BCH_DEV_READ_REF_NR,  NULL) ||
	    enumerated_ref_init(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_NR, NULL) ||
	    !(ca->sb_read_scratch = kmalloc(BCH_SB_READ_SCRATCH_BUF_SIZE, GFP_KERNEL)) ||
	    bch2_dev_buckets_alloc(c, ca) ||
	    bch2_dev_discards_init(ca) ||
	    !(ca->io_done	= alloc_percpu(*ca->io_done)))
		goto err;

	return ca;
err:
	bch2_dev_free(ca);
	return NULL;
}

static void bch2_dev_attach(struct bch_fs *c, struct bch_dev *ca,
			    unsigned dev_idx)
{
	ca->dev_idx = dev_idx;
	__set_bit(ca->dev_idx, ca->self.d);

	if (!ca->name[0])
		scnprintf(ca->name, sizeof(ca->name), "dev-%u", dev_idx);

	ca->fs = c;
	rcu_assign_pointer(c->devs[ca->dev_idx], ca);

	if (bch2_dev_sysfs_online(c, ca))
		pr_warn("error creating sysfs objects");
}

int bch2_dev_alloc(struct bch_fs *c, unsigned dev_idx)
{
	struct bch_member member = bch2_sb_member_get(c->disk_sb.sb, dev_idx);
	struct bch_dev *ca = NULL;

	if (bch2_fs_init_fault("dev_alloc"))
		return bch_err_throw(c, ENOMEM_dev_alloc);

	ca = __bch2_dev_alloc(c, &member);
	if (!ca)
		return bch_err_throw(c, ENOMEM_dev_alloc);

	ca->fs = c;

	bch2_dev_attach(c, ca, dev_idx);
	return 0;
}

static int read_file_str(const char *path, darray_char *ret)
{
	/*
	 * TODO: unify this with read_file_str() in bcachefs-tools tools-util.c
	 *
	 * Unfortunately, we don't have openat() in kernel
	 */
#ifdef __KERNEL__
	struct file *file = errptr_try(filp_open(path, O_RDONLY, 0));

	loff_t pos = 0;
	ssize_t r = kernel_read(file, ret->data, ret->size, &pos);
	fput(file);
#else
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;

	ssize_t r = read(fd, ret->data, ret->size);
	close(fd);
#endif

	if (r > 0) {
		ret->nr = r;
		if (ret->data[r - 1]) {
			/* null terminate */
			if (ret->nr >= ret->size)
				ret->nr = ret->size -1;
			ret->data[ret->nr] = '\0';
		}
	}
	return r < 0 ? r : 0;
}

static int __bch2_dev_attach_bdev(struct bch_fs *c, struct bch_dev *ca,
				  struct bch_sb_handle *sb, struct printbuf *err)
{
	if (bch2_dev_is_online(ca)) {
		prt_printf(err, "Cannot attach %s: already have device %s online in slot %u\n",
			   sb->sb_name, ca->name, sb->sb->dev_idx);
		return bch_err_throw(ca->fs, device_already_online);
	}

	if (get_capacity(sb->bdev->bd_disk) <
	    ca->mi.bucket_size * ca->mi.nbuckets) {
		prt_printf(err, "Cannot online %s: device too small (capacity %llu filesystem size %llu nbuckets %llu)\n",
			   sb->sb_name,
			   get_capacity(sb->bdev->bd_disk),
			   ca->mi.bucket_size * ca->mi.nbuckets,
			   ca->mi.nbuckets);
		return bch_err_throw(ca->fs, device_size_too_small);
	}

	BUG_ON(!enumerated_ref_is_zero(&ca->io_ref[READ]));
	BUG_ON(!enumerated_ref_is_zero(&ca->io_ref[WRITE]));

	try(bch2_dev_journal_init(ca, sb->sb));

	CLASS(printbuf, name)();
	prt_bdevname(&name, sb->bdev);
	strscpy(ca->name, name.buf, sizeof(ca->name));

	CLASS(darray_char, model)();
	darray_make_room(&model, 128);

	CLASS(printbuf, model_path)();
	prt_printf(&model_path, "/sys/block/%s/device/model", name.buf);

	read_file_str(model_path.buf, &model);

	if (model.nr && model.data[model.nr - 1] == '\n')
		model.data[--model.nr] = '\0';

	CLASS(darray_char, serial)();
	darray_make_room(&serial, 128);

	CLASS(printbuf, serial_path)();
	prt_printf(&serial_path, "/sys/block/%s/device/serial", name.buf);

	read_file_str(serial_path.buf, &serial);

	if (serial.nr && serial.data[serial.nr - 1] == '\n')
		serial.data[--serial.nr] = '\0';

	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		strtomem_pad(m->device_name, name.buf, '\0');

		if (model.nr)
			strtomem_pad(m->device_model, model.data, '\0');

		if (serial.nr)
			strtomem_pad(m->device_serial, serial.data, '\0');
	}

	/* Commit: */
	ca->disk_sb = *sb;
	memset(sb, 0, sizeof(*sb));

	/*
	 * Stash pointer to the filesystem for blk_holder_ops - note that once
	 * attached to a filesystem, we will always close the block device
	 * before tearing down the filesystem object.
	 */
	ca->disk_sb.holder->c = ca->fs;

	ca->dev = ca->disk_sb.bdev->bd_dev;

	enumerated_ref_start(&ca->io_ref[READ]);

	return 0;
}

int bch2_dev_attach_bdev(struct bch_fs *c, struct bch_sb_handle *sb, struct printbuf *err)
{
	lockdep_assert_held(&c->state_lock);

	if (le64_to_cpu(sb->sb->seq) >
	    le64_to_cpu(c->disk_sb.sb->seq)) {
		/*
		 * rewind, we'll lose some updates but it's not safe to call
		 * bch2_sb_to_fs() after fs is started
		 */
		sb->sb->seq = c->disk_sb.sb->seq;
	}

	BUG_ON(!bch2_dev_exists(c, sb->sb->dev_idx));

	struct bch_dev *ca = bch2_dev_locked(c, sb->sb->dev_idx);

	try(__bch2_dev_attach_bdev(c, ca, sb, err));

	set_bit(ca->dev_idx, c->devs_online.d);

	bch2_dev_sysfs_online(c, ca);

	bch2_reconcile_wakeup(c);
	return 0;
}

/* Device management: */

/*
 * Note: this function is also used by the error paths - when a particular
 * device sees an error, we call it to determine whether we can just set the
 * device RO, or - if this function returns false - we'll set the whole
 * filesystem RO:
 *
 * XXX: maybe we should be more explicit about whether we're changing state
 * because we got an error or what have you?
 */
bool bch2_dev_state_allowed(struct bch_fs *c, struct bch_dev *ca,
			    enum bch_member_state new_state, int flags,
			    struct printbuf *err)
{
	lockdep_assert_held(&c->state_lock);

	if (ca->mi.state	== BCH_MEMBER_STATE_rw &&
	    new_state		!= BCH_MEMBER_STATE_rw) {
		struct bch_devs_mask new_rw_devs = c->allocator.rw_devs[0];
		__clear_bit(ca->dev_idx, new_rw_devs.d);

		return bch2_can_write_fs_with_devs(c, new_rw_devs, flags, err);
	}

	return true;
}

int __bch2_dev_set_state(struct bch_fs *c, struct bch_dev *ca,
			 enum bch_member_state new_state, int flags,
			 struct printbuf *err)
{
	bool do_reconcile_scan =
		new_state == BCH_MEMBER_STATE_rw ||
		new_state == BCH_MEMBER_STATE_evacuating;

	struct reconcile_scan s = new_state == BCH_MEMBER_STATE_rw
		? (struct reconcile_scan) { .type = RECONCILE_SCAN_pending }
		: (struct reconcile_scan) { .type = RECONCILE_SCAN_device, .dev = ca->dev_idx };

	if (ca->mi.state == new_state) {
		if (new_state == BCH_MEMBER_STATE_evacuating)
			return bch2_set_reconcile_needs_scan(c, s, true);
		return 0;
	}

	if (!bch2_dev_state_allowed(c, ca, new_state, flags, err))
		return bch_err_throw(c, device_state_not_allowed);

	if (new_state != BCH_MEMBER_STATE_rw)
		__bch2_dev_read_only(c, ca);

	bch_notice_dev(ca, "%s", bch2_member_states[new_state]);

	if (do_reconcile_scan)
		try(bch2_set_reconcile_needs_scan(c, s, false));

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
		SET_BCH_MEMBER_STATE(m, new_state);
		bch2_write_super(c);
	}

	if (new_state == BCH_MEMBER_STATE_rw && bch2_dev_is_online(ca))
		__bch2_dev_read_write(c, ca);

	if (do_reconcile_scan)
		try(bch2_set_reconcile_needs_scan(c, s, true));

	return 0;
}

int bch2_dev_set_state(struct bch_fs *c, struct bch_dev *ca,
		       enum bch_member_state new_state, int flags,
		       struct printbuf *err)
{
	guard(rwsem_write)(&c->state_lock);
	return __bch2_dev_set_state(c, ca, new_state, flags, err);
}

/* Device add/removal: */

int bch2_dev_remove(struct bch_fs *c, struct bch_dev *ca, int flags,
		    struct printbuf *err)
{
	unsigned dev_idx = ca->dev_idx, data;
	bool fast_device_removal = (c->sb.compat & BIT_ULL(BCH_COMPAT_no_stale_ptrs)) &&
		!bch2_request_incompat_feature(c,
					bcachefs_metadata_version_fast_device_removal);
	int ret;

	guard(rwsem_write)(&c->state_lock);

	/*
	 * We consume a reference to ca->ref, regardless of whether we succeed
	 * or fail:
	 */
	bch2_dev_put(ca);

	try(__bch2_dev_set_state(c, ca, BCH_MEMBER_STATE_evacuating, flags, err));

	ret = fast_device_removal
		? bch2_dev_data_drop_by_backpointers(c, ca, flags, err)
		: (bch2_dev_data_drop(c, ca->dev_idx, flags, err) ?:
		   bch2_dev_remove_stripes(c, ca->dev_idx, flags, err));
	if (ret)
		goto err;

	bch2_btree_interior_updates_flush(c);

	/* Check if device still has data before blowing away alloc info */
	struct bch_dev_usage usage = bch2_dev_usage_read(ca);
	for (unsigned i = 0; i < BCH_DATA_NR; i++)
		if (!data_type_is_empty(i) &&
		    !data_type_is_hidden(i) &&
		    usage.buckets[i]) {
			if (!ret) {
				prt_printf(err, "Remove failed: still has data\n");
				ret = -EBUSY;
			}
			prt_printf(err, "  %s: %llu buckets\n", bch2_data_type_str(i), usage.buckets[i]);
		}
	if (ret)
		goto err;

	/*
	 * Disallow reads before we remove alloc info, otherwise we'll get
	 * spurious stale pointer errors:
	 */
	__bch2_dev_offline(c, ca);

	ret = bch2_dev_remove_alloc(c, ca, 0);
	if (ret) {
		prt_printf(err, "bch2_dev_remove_alloc() error: %s\n", bch2_err_str(ret));
		goto err;
	}
	ret = bch2_dev_usage_remove(c, ca);
	if (ret) {
		prt_printf(err, "bch2_dev_usage_remove() error: %s\n", bch2_err_str(ret));
		goto err;
	}

	/*
	 * We need to flush the entire journal to get rid of keys that reference
	 * the device being removed before removing the superblock entry
	 */
	bch2_journal_flush_outstanding_pins(&c->journal);

	/*
	 * this is really just needed for the bch2_replicas_gc_(start|end)
	 * calls, and could be cleaned up:
	 */
	ret = bch2_journal_flush_device_pins(&c->journal, ca->dev_idx);
	if (ret) {
		prt_printf(err, "bch2_journal_flush_device_pins() error: %s\n", bch2_err_str(ret));
		goto err;
	}

	ret = bch2_journal_flush(&c->journal);
	if (ret) {
		prt_printf(err, "bch2_journal_flush() error: %s\n", bch2_err_str(ret));
		goto err;
	}

	ret = bch2_replicas_gc_accounted(c);
	if (ret) {
		prt_printf(err, "bch2_replicas_gc2() error: %s\n", bch2_err_str(ret));
		goto err;
	}
	/*
	 * flushing the journal should be sufficient, but it's the write buffer
	 * flush that kills superblock replicas entries after they've gone to 0
	 * so bch2_dev_has_data() returns the correct value:
	 */

	data = bch2_dev_has_data(c, ca);
	if (data) {
		prt_str(err, "Remove failed, still has data (");
		prt_bitflags(err, __bch2_data_types, data);
		prt_str(err, ")\n");
		ret = -EBUSY;
		goto err;
	}

	scoped_guard(mutex, &c->sb_lock)
		rcu_assign_pointer(c->devs[ca->dev_idx], NULL);

#ifndef CONFIG_BCACHEFS_DEBUG
	percpu_ref_kill(&ca->ref);
#else
	ca->dying = true;
	bch2_dev_put(ca);
#endif
	wait_for_completion(&ca->ref_completion);

	bch2_dev_free(ca);

	/*
	 * Free this device's slot in the bch_member array - all pointers to
	 * this device must be gone:
	 */
	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, dev_idx);

		if (fast_device_removal)
			m->uuid = BCH_SB_MEMBER_DELETED_UUID;
		else
			memset(&m->uuid, 0, sizeof(m->uuid));

		bch2_write_super(c);
	}

	return 0;
err:
	if (test_bit(BCH_FS_rw, &c->flags) &&
	    ca->mi.state == BCH_MEMBER_STATE_rw &&
	    !enumerated_ref_is_zero(&ca->io_ref[READ]))
		__bch2_dev_read_write(c, ca);
	return ret;
}

/* Add new device to running filesystem: */
int bch2_dev_add(struct bch_fs *c, const char *path, struct printbuf *err)
{
	struct bch_opts opts = bch2_opts_empty();
	struct bch_sb_handle sb __cleanup(bch2_free_super) = {};
	int ret = bch2_read_super(path, &opts, &sb);
	if (ret) {
		prt_printf(err, "error reading superblock: %s\n", bch2_err_str(ret));
		return ret;
	}

	struct bch_member dev_mi = bch2_sb_member_get(sb.sb, sb.sb->dev_idx);

	CLASS(printbuf, label)();
	if (BCH_MEMBER_GROUP(&dev_mi)) {
		bch2_disk_path_to_text_sb(&label, sb.sb, BCH_MEMBER_GROUP(&dev_mi) - 1);
		if (label.allocation_failure)
			return -ENOMEM;
	}

	if (list_empty(&c->list)) {
		scoped_guard(mutex, &bch2_fs_list_lock) {
			if (__bch2_uuid_to_fs(c->sb.uuid))
				ret = bch_err_throw(c, filesystem_uuid_already_open);
			else
				list_add(&c->list, &bch2_fs_list);
		}

		if (ret) {
			prt_printf(err, "cannot go multidevice: filesystem UUID already open\n");
			return ret;
		}
	}

	try(bch2_dev_may_add(sb.sb, c));

	struct bch_dev *ca = __bch2_dev_alloc(c, &dev_mi);
	if (!ca)
		return -ENOMEM;

	ret = __bch2_dev_attach_bdev(c, ca, &sb, err);
	if (ret)
		goto err;

	struct reconcile_scan s = { .type = RECONCILE_SCAN_pending };
	if (test_bit(BCH_FS_started, &c->flags)) {
		/*
		 * Technically incorrect, but 'bcachefs image update' is the
		 * only thing that adds a device to a not-started filesystem:
		 */
		try(bch2_set_reconcile_needs_scan(c, s, false));
	}

	scoped_guard(rwsem_write, &c->state_lock) {
		scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
			guard(mutex)(&c->sb_lock);
			SET_BCH_SB_MULTI_DEVICE(c->disk_sb.sb, true);

			ret = bch2_sb_from_fs(c, ca);
			if (ret) {
				prt_printf(err, "error setting up new superblock: %s\n", bch2_err_str(ret));
				goto err;
			}

			if (dynamic_fault("bcachefs:add:no_slot"))
				goto err;

			ret = bch2_sb_member_alloc(c);
			if (ret < 0) {
				prt_printf(err, "error allocating superblock member slot: %s\n", bch2_err_str(ret));
				goto err;
			}
			unsigned dev_idx = ret;
			ret = 0;

			/* success: */

			dev_mi.last_mount = cpu_to_le64(ktime_get_real_seconds());
			*bch2_members_v2_get_mut(c->disk_sb.sb, dev_idx) = dev_mi;

			ca->disk_sb.sb->dev_idx	= dev_idx;
			bch2_dev_attach(c, ca, dev_idx);

			set_bit(ca->dev_idx, c->devs_online.d);

			if (BCH_MEMBER_GROUP(&dev_mi)) {
				ret = __bch2_dev_group_set(c, ca, label.buf);
				prt_printf(err, "error creating new label: %s\n", bch2_err_str(ret));
				if (ret)
					goto err_late;
			}


			bool write_sb = false;
			__bch2_dev_mi_field_upgrades(c, ca, &write_sb);

			bch2_write_super(c);
		}

		ret = bch2_dev_usage_init(ca, false);
		if (ret)
			goto err_late;

		if (test_bit(BCH_FS_started, &c->flags)) {
			ret = bch2_trans_mark_dev_sb(c, ca, BTREE_TRIGGER_transactional);
			if (ret) {
				prt_printf(err, "error marking new superblock: %s\n", bch2_err_str(ret));
				goto err_late;
			}

			ret = bch2_fs_freespace_init(c);
			if (ret) {
				prt_printf(err, "error initializing free space: %s\n", bch2_err_str(ret));
				goto err_late;
			}

			if (ca->mi.state == BCH_MEMBER_STATE_rw)
				__bch2_dev_read_write(c, ca);

			ret = bch2_dev_journal_alloc(ca, false);
			if (ret) {
				prt_printf(err, "error allocating journal: %s\n", bch2_err_str(ret));
				goto err_late;
			}
		}

		/*
		 * We just changed the superblock UUID, invalidate cache and send a
		 * uevent to update /dev/disk/by-uuid
		 */
		invalidate_bdev(ca->disk_sb.bdev);

		char uuid_str[37];
		snprintf(uuid_str, sizeof(uuid_str), "UUID=%pUb", &c->sb.uuid);

		char *envp[] = {
			"CHANGE=uuid",
			uuid_str,
			NULL,
		};
		kobject_uevent_env(&ca->disk_sb.bdev->bd_device.kobj, KOBJ_CHANGE, envp);
	}

	if (test_bit(BCH_FS_started, &c->flags))
		try(bch2_set_reconcile_needs_scan(c, s, true));
out:
	bch_err_fn(c, ret);
	return ret;
err:
	if (ca)
		bch2_dev_free(ca);
	goto out;
err_late:
	ca = NULL;
	goto err;
}

/* Hot add existing device to running filesystem: */
int bch2_dev_online(struct bch_fs *c, const char *path, struct printbuf *err)
{
	struct bch_opts opts = bch2_opts_empty();
	struct bch_sb_handle sb __cleanup(bch2_free_super) = {};
	int ret;

	guard(rwsem_write)(&c->state_lock);

	ret = bch2_read_super(path, &opts, &sb);
	if (ret) {
		prt_printf(err, "error reading superblock: %s\n", bch2_err_str(ret));
		return ret;
	}

	unsigned dev_idx = sb.sb->dev_idx;

	ret = bch2_dev_in_fs(&c->disk_sb, &sb, &c->opts);
	if (ret) {
		prt_printf(err, "device not a member of fs: %s\n", bch2_err_str(ret));
		return ret;
	}

	try(bch2_dev_attach_bdev(c, &sb, err));

	struct bch_dev *ca = bch2_dev_locked(c, dev_idx);

	bch2_dev_mi_field_upgrades(ca);

	ret = bch2_trans_mark_dev_sb(c, ca, BTREE_TRIGGER_transactional);
	if (ret) {
		prt_printf(err, "bch2_trans_mark_dev_sb() error: %s\n", bch2_err_str(ret));
		return ret;
	}

	if (ca->mi.state == BCH_MEMBER_STATE_rw)
		__bch2_dev_read_write(c, ca);

	if (!ca->mi.freespace_initialized) {
		ret = bch2_dev_freespace_init(c, ca, 0, ca->mi.nbuckets);
		if (ret) {
			prt_printf(err, "bch2_dev_freespace_init() error: %s\n", bch2_err_str(ret));
			return ret;
		}
	}

	if (!ca->journal.nr) {
		ret = bch2_dev_journal_alloc(ca, false);
		if (ret) {
			prt_printf(err, "bch2_dev_journal_alloc() error: %s\n", bch2_err_str(ret));
			return ret;
		}
	}

	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx)->last_mount =
			cpu_to_le64(ktime_get_real_seconds());
		bch2_write_super(c);
	}

	/*
	 * We might have been unable to write because this device was offline:
	 *
	 * We'd like to limit reconcile pending scans, having them happen
	 * because a device is going offline and coming back sucks - but to do
	 * that right we need to at least note somewhere /which/ targets have
	 * extents on the pending list:
	 */
	try(bch2_set_reconcile_needs_scan(c,
		(struct reconcile_scan) { .type = RECONCILE_SCAN_pending}, true));

	return 0;
}

static int bch2_dev_may_offline(struct bch_fs *c, struct bch_dev *ca, int flags, struct printbuf *err)
{
	struct bch_devs_mask new_devs = c->devs_online;
	__clear_bit(ca->dev_idx, new_devs.d);

	struct bch_devs_mask new_rw_devs = c->allocator.rw_devs[0];
	__clear_bit(ca->dev_idx, new_devs.d);

	if (!bch2_can_read_fs_with_devs(c, &new_devs, flags, err) ||
	    (!c->opts.read_only &&
	     !bch2_can_write_fs_with_devs(c, new_rw_devs, flags, err))) {
		prt_printf(err, "Cannot offline required disk\n");
		return bch_err_throw(c, device_state_not_allowed);
	}

	return 0;
}

int bch2_dev_offline(struct bch_fs *c, struct bch_dev *ca, int flags, struct printbuf *err)
{
	guard(rwsem_write)(&c->state_lock);

	if (!bch2_dev_is_online(ca)) {
		prt_printf(err, "Already offline\n");
		return 0;
	}

	try(bch2_dev_may_offline(c, ca, flags, err));

	__bch2_dev_offline(c, ca);
	return 0;
}

static u64 bch2_dev_resize_seq(struct bch_dev *ca)
{
	scoped_guard(spinlock, &ca->resize_lock)
		return ca->resize_seq;
}

static bool bch2_dev_resize_wait_done(struct bch_dev *ca, u64 seq, int *status)
{
	scoped_guard(spinlock, &ca->resize_lock) {
		if (ca->resize_seq != seq) {
			*status = -ECANCELED;
			return true;
		}
		if (ca->resize_status != -EINPROGRESS) {
			*status = ca->resize_status;
			return true;
		}
	}

	return false;
}

static int bch2_dev_resize_wait(struct bch_dev *ca, u64 seq)
{
	int status = -EINPROGRESS;
	int ret = wait_event_killable(ca->resize_wait,
				      bch2_dev_resize_wait_done(ca, seq, &status));

	return ret ? -EINTR : status;
}

static bool bch2_dev_resize_finish(struct bch_dev *ca, u64 seq, int status)
{
	bool is_current;

	scoped_guard(spinlock, &ca->resize_lock) {
		is_current = ca->resize_seq == seq;
		if (is_current)
			ca->resize_status = status;
	}

	if (is_current) {
		wake_up_all(&ca->resize_wait);

		/* Discards are deferred during resize to avoid allocator/journal deadlocks, restart them now that we are done */
		bch2_do_discards_async(ca->fs);
	}

	return is_current;
}

/* checks for kthread interruption, and resize seq having changed */
static int bch2_dev_resize_restart_check(struct bch_dev *ca, u64 seq)
{
	if (kthread_should_stop())
		return -EINTR;

	return bch2_dev_resize_seq(ca) != seq ? -EAGAIN : 0;
}

static int bch2_dev_resize_thread(void *arg);

static int bch2_dev_resize_thread_start(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	lockdep_assert_held(&c->state_lock);

	if (ca->resize_thread)
		return 0;

	struct task_struct *p =
		kthread_create(bch2_dev_resize_thread, ca,
			       "bch-resize/%s:%u", c->name, ca->dev_idx);
	try(PTR_ERR_OR_ZERO(p));

	get_task_struct(p);
	ca->resize_thread = p;
	wake_up_process(p);
	return 0;
}

static void bch2_dev_resize_thread_stop(struct bch_dev *ca)
{
	scoped_guard(spinlock, &ca->resize_lock) {
		ca->resize_seq++;
		ca->resize_status = -EINTR;
	}

	if (ca->resize_thread) {
		kthread_stop(ca->resize_thread);
		put_task_struct(ca->resize_thread);
		ca->resize_thread = NULL;
	}

	wake_up_all(&ca->resize_wait);
}

void bch2_dev_resize_threads_stop(struct bch_fs *c)
{
	for_each_member_device(c, ca)
		bch2_dev_resize_thread_stop(ca);
}

static int bch2_dev_resize_update_target(struct bch_fs *c, struct bch_dev *ca,
					 u64 target_nbuckets, struct printbuf *err)
{
	lockdep_assert_held(&c->state_lock);

	/* validate target_nbuckets */
	u64 old_nbuckets = ca->mi.nbuckets;

	if (target_nbuckets > BCH_MEMBER_NBUCKETS_MAX) {
		prt_printf(err, "New device size too big (%llu greater than max %u)\n",
			   target_nbuckets, BCH_MEMBER_NBUCKETS_MAX);
		return bch_err_throw(c, device_size_too_big);
	}

	if (target_nbuckets &&
	    target_nbuckets < old_nbuckets &&
	    target_nbuckets < ca->mi.first_bucket + BCH_MIN_NR_NBUCKETS) {
		prt_printf(err, "New device size too small (%llu smaller than min %llu)\n",
			   target_nbuckets,
			   (u64) ca->mi.first_bucket + BCH_MIN_NR_NBUCKETS);
		return bch_err_throw(c, device_size_too_small);
	}

	if (target_nbuckets > old_nbuckets &&
	    bch2_dev_is_online(ca) &&
	    get_capacity(ca->disk_sb.bdev->bd_disk) <
	    ca->mi.bucket_size * target_nbuckets) {
		prt_printf(err, "New size %llu larger than device size %llu\n",
			   ca->mi.bucket_size * target_nbuckets,
			   get_capacity(ca->disk_sb.bdev->bd_disk));
		return bch_err_throw(c, device_size_too_small);
	}

	/* commit target_nbuckets */
	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		m->target_nbuckets = cpu_to_le64(target_nbuckets);
		try(bch2_write_super(c));
	}

	return 0;
}

static int __bch2_dev_grow(struct bch_fs *c, struct bch_dev *ca,
			   u64 new_nbuckets, struct printbuf *err)
{
	guard(rwsem_write)(&c->state_lock);

	int ret = 0;

	u64 old_nbuckets = ca->mi.nbuckets;

	if (new_nbuckets <= old_nbuckets) {
		return 0;
	}

	/* we have more space -> wake up pending */
	bool wakeup_reconcile_pending = new_nbuckets > old_nbuckets;
	struct reconcile_scan s = { .type = RECONCILE_SCAN_pending };
	if (wakeup_reconcile_pending)
		try(bch2_set_reconcile_needs_scan(c, s, false));

	if (new_nbuckets > BCH_MEMBER_NBUCKETS_MAX) {
		prt_printf(err, "New device size too big (%llu greater than max %u)\n",
			   new_nbuckets, BCH_MEMBER_NBUCKETS_MAX);
		return bch_err_throw(c, device_size_too_big);
	}

	if (bch2_dev_is_online(ca) &&
	    get_capacity(ca->disk_sb.bdev->bd_disk) <
	    ca->mi.bucket_size * new_nbuckets) {
		prt_printf(err, "New size %llu larger than device size %llu\n",
			   ca->mi.bucket_size * new_nbuckets,
			   get_capacity(ca->disk_sb.bdev->bd_disk));
		return bch_err_throw(c, device_size_too_small);
	}

	ret = bch2_dev_buckets_resize(c, ca, new_nbuckets);
	if (ret) {
		prt_printf(err, "bch2_dev_buckets_resize() error: %s\n", bch2_err_str(ret));
		return ret;
	}

	ret = bch2_trans_mark_dev_sb(c, ca, BTREE_TRIGGER_transactional);
	if (ret) {
		prt_printf(err, "bch2_trans_mark_dev_sb() error: %s\n", bch2_err_str(ret));
		return ret;
	}

	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
		m->nbuckets = cpu_to_le64(new_nbuckets);
		if (bch2_dev_resize_target(ca) == new_nbuckets)
			m->target_nbuckets = 0;

		bch2_write_super(c);
	}

	if (ca->mi.freespace_initialized) {
		ret = __bch2_dev_resize_alloc(ca, old_nbuckets, new_nbuckets);
		if (ret) {
			prt_printf(err, "__bch2_dev_resize_alloc() error: %s\n", bch2_err_str(ret));
			return ret;
		}
	}

	bch2_recalc_capacity(c);

	if (wakeup_reconcile_pending)
		try(bch2_set_reconcile_needs_scan(c, s, true));
	return 0;
}

static int drop_sbs_after_cutoff(struct bch_fs *c, struct bch_dev *ca, u64 cutoff) {
	u64 cutoff_sector = bucket_to_sector(ca, cutoff);

	guard(memalloc_flags)(PF_MEMALLOC_NOFS);
	guard(mutex)(&c->sb_lock);

	struct bch_sb_layout *layout = &ca->disk_sb.sb->layout;

	u64 max_sectors = 1 << layout->sb_max_size_bits;

	u8 i;
	/* offsets are sorted in ascending order, see validate_sb_layout() overlapping checks for evidence */
	for (i = 0; i < layout->nr_superblocks; i++) {
		u64 offset = le64_to_cpu(layout->sb_offset[i]);
		if (offset + max_sectors > cutoff_sector) {
			break;
		}
	}

	/* this should never happen, as we only call to this function after checking the cutoff against the minimum fs size,
	 * which includes at least the first sb copy */
	BUG_ON(i == 0);

	layout->nr_superblocks = i;

	return bch2_write_super(c);
}

static int move_journal_past_cutoff(struct bch_fs *c, struct bch_dev *ca,
				    u64 cutoff, struct printbuf *err)
{
	bool grew = false;

	while (true) {
		u64 bucket_to_delete = 0;
		unsigned nr = 0, nr_past_cutoff = 0;
		bool cur_bucket_past_cutoff = false;
		int ret;

		scoped_guard(spinlock, &c->journal.lock) {
			struct journal_device *ja = &ca->journal;

			nr = ja->nr;
			if (!nr)
				break;

			cur_bucket_past_cutoff = ja->buckets[ja->cur_idx] >= cutoff;

			for (unsigned i = 0; i < ja->nr; i++) {
				if (ja->buckets[i] < cutoff)
					continue;

				nr_past_cutoff++;
				if (i != ja->cur_idx && !bucket_to_delete)
					bucket_to_delete = ja->buckets[i];
			}
		}

		if (!nr_past_cutoff)
			return 0;

		if (!grew) {
			ret = bch2_set_nr_journal_buckets(c, ca, nr + nr_past_cutoff);
			if (ret) {
				prt_printf(err, "Failed to relocate journal buckets: %s\n",
					   bch2_err_str(ret));
				return ret;
			}
			grew = true;
			continue;
		}

		if (!bucket_to_delete && cur_bucket_past_cutoff) {
			scoped_guard(spinlock, &c->journal.lock) {
				struct journal_device *ja = &ca->journal;

				if (ja->nr &&
				    ja->buckets[ja->cur_idx] >= cutoff)
					ja->sectors_free = 0;
			}

			scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
				guard(mutex)(&c->sb_lock);
				ret = bch2_write_super(c);
			}
			if (ret) {
				prt_printf(err, "Failed to advance journal off shrink tail: %s\n",
					   bch2_err_str(ret));
				return ret;
			}

			ret = bch2_journal_flush(&c->journal);
			if (ret) {
				prt_printf(err, "Failed to flush relocated journal: %s\n",
					   bch2_err_str(ret));
				return ret;
			}
			continue;
		}

		ret = bch2_dev_journal_bucket_delete(ca, bucket_to_delete);
		if (ret) {
			prt_printf(err, "Failed to drop journal bucket %llu from shrink tail: %s\n",
				   bucket_to_delete, bch2_err_str(ret));
			return ret;
		}
	}
}

struct shrink_tail_head {
	struct bpos	bucket;
	struct bpos	first_bp;
	unsigned	nr_backpointers;
};

struct shrink_tail_progress {
	struct shrink_tail_head	head;
	u64			nr_backpointers;
};

static inline bool shrink_tail_head_empty(const struct shrink_tail_head *head)
{
	return bpos_eq(head->first_bp, SPOS_MAX);
}

static bool shrink_tail_head_progressed(const struct shrink_tail_head *old,
					const struct shrink_tail_head *new)
{
	if (shrink_tail_head_empty(new))
		return true;

	if (shrink_tail_head_empty(old))
		return false;

	if (!bpos_eq(new->bucket, old->bucket))
		return bpos_gt(new->bucket, old->bucket);

	if (!bpos_eq(new->first_bp, old->first_bp))
		return bpos_gt(new->first_bp, old->first_bp);

	return new->nr_backpointers < old->nr_backpointers;
}

static bool shrink_tail_progressed(const struct shrink_tail_progress *old,
				   const struct shrink_tail_progress *new)
{
	if (shrink_tail_head_empty(&new->head))
		return true;

	if (shrink_tail_head_empty(&old->head))
		return false;

	if (new->nr_backpointers < old->nr_backpointers)
		return true;

	return shrink_tail_head_progressed(&old->head, &new->head);
}

/*
 * Make sure everything is caught here: this snapshots backpointer-visible tail
 * data. Journal buckets and superblock copies in the shrink tail are handled by
 * move_journal_past_cutoff() and drop_sbs_after_cutoff().
 */
static int tail_head_snapshot(struct bch_fs *c, struct bch_dev *ca,
			      u64 new_nbuckets, struct shrink_tail_head *head)
{
	struct bpos bp_start = bucket_pos_to_bp_start(ca, POS(ca->dev_idx, new_nbuckets));
	struct bpos bp_end = bucket_pos_to_bp_start(ca, POS(ca->dev_idx, ca->mi.nbuckets));

	CLASS(btree_trans, trans)(c);
	CLASS(backpointer_scan_iter, iter)(BTREE_ID_backpointers, bp_start, NULL);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct bkey_s_c_backpointer bp = bch2_bp_scan_iter_peek(trans, &iter, bp_end, &last_flushed);

	try(bkey_err(bp));

	*head = (struct shrink_tail_head) {
		.bucket		= SPOS_MAX,
		.first_bp	= SPOS_MAX,
	};

	if (!bp.k)
		return 0;

	head->bucket = bp_pos_to_bucket(ca, bp.k->p);
	head->first_bp = bp.k->p;

	do {
		head->nr_backpointers++;
		bch2_bp_scan_iter_advance(&iter);
		bp = bch2_bp_scan_iter_peek(trans, &iter, bp_end, &last_flushed);
		try(bkey_err(bp));
	} while (bp.k && bpos_eq(bp_pos_to_bucket(ca, bp.k->p), head->bucket));

	return 0;
}

static int tail_progress_snapshot(struct bch_fs *c, struct bch_dev *ca,
				  u64 new_nbuckets,
				  struct shrink_tail_progress *progress)
{
	struct bpos bp_start = bucket_pos_to_bp_start(ca, POS(ca->dev_idx, new_nbuckets));
	struct bpos bp_end = bucket_pos_to_bp_start(ca, POS(ca->dev_idx, ca->mi.nbuckets));

	CLASS(btree_trans, trans)(c);
	CLASS(backpointer_scan_iter, iter)(BTREE_ID_backpointers, bp_start, NULL);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	*progress = (struct shrink_tail_progress) {
		.head.bucket	= SPOS_MAX,
		.head.first_bp	= SPOS_MAX,
	};

	while (true) {
		struct bkey_s_c_backpointer bp =
			bch2_bp_scan_iter_peek(trans, &iter, bp_end, &last_flushed);

		try(bkey_err(bp));
		if (!bp.k)
			return 0;

		if (shrink_tail_head_empty(&progress->head)) {
			progress->head.bucket = bp_pos_to_bucket(ca, bp.k->p);
			progress->head.first_bp = bp.k->p;
		}

		if (bpos_eq(bp_pos_to_bucket(ca, bp.k->p), progress->head.bucket))
			progress->head.nr_backpointers++;

		progress->nr_backpointers++;
		bch2_bp_scan_iter_advance(&iter);
	}
}

static int tail_is_empty(struct bch_fs *c, struct bch_dev *ca, u64 new_nbuckets,
			 bool *empty)
{
	struct shrink_tail_head head;

	try(tail_head_snapshot(c, ca, new_nbuckets, &head));
	*empty = shrink_tail_head_empty(&head);
	return 0;
}

static int bch2_dev_shrink_invalidate_bp(struct btree_trans *trans,
					 struct bch_dev *ca,
					 struct bkey_s_c_backpointer bp,
					 struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_backpointer_get_key(trans, bp, &iter, 0, last_flushed));
	if (!k.k)
		return 0;

	struct bkey_i *n = errptr_try(bch2_bkey_make_mut(trans, &iter, &k,
						BTREE_UPDATE_internal_snapshot_node));

	bch2_bkey_drop_device_noerror(c, bkey_i_to_s(n), ca->dev_idx);

	if (!bch2_bkey_can_read(c, bkey_i_to_s_c(n)))
		bch2_set_bkey_error(c, n, KEY_TYPE_ERROR_device_removed);

	return 0;
}

static int bch2_dev_shrink_invalidate_cached_bucket(struct btree_trans *trans,
						    struct bch_dev *ca,
						    struct bpos bucket,
						    u8 gen,
						    struct wb_maybe_flush *last_flushed)
{
	struct bpos bp_start = bucket_pos_to_bp_start(ca, bucket);
	struct bpos bp_end = bucket_pos_to_bp_end(ca, bucket);

	return for_each_btree_key_max_commit(trans, iter, BTREE_ID_backpointers,
				      bp_start, bp_end, 0, k,
				      NULL, NULL,
				      BCH_WATERMARK_btree|
				      BCH_TRANS_COMMIT_no_enospc, ({
		if (k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);

		if (bp.v->bucket_gen != gen)
			continue;

		try(bch2_dev_shrink_invalidate_bp(trans, ca, bp, last_flushed));
		0;
	}));
}

static int bch2_dev_shrink_invalidate_tail_cached(struct bch_fs *c, struct bch_dev *ca, u64 new_nbuckets)
{
	struct bpos start = POS(ca->dev_idx, new_nbuckets);
	struct bpos end = POS(ca->dev_idx, ca->mi.nbuckets - 1);
	CLASS(btree_trans, trans)(c);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	try(bch2_btree_write_buffer_flush_sync(trans));

	return for_each_btree_key_max_commit(trans, iter, BTREE_ID_alloc,
				start, end, BTREE_ITER_prefetch, k,
				NULL, NULL,
				BCH_WATERMARK_btree|
				BCH_TRANS_COMMIT_no_enospc, ({
		struct bch_alloc_v4 a_convert;
		const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);

		if (a->data_type != BCH_DATA_cached || !a->cached_sectors)
			continue;

		if (bch2_bucket_is_open_safe(c, k.k->p.inode, k.k->p.offset))
			continue;

		try(bch2_dev_shrink_invalidate_cached_bucket(trans, ca, k.k->p,
							     a->gen, &last_flushed));
		0;
	}));
}

static int bch2_dev_shrink_queue_reconcile(struct bch_fs *c, struct bch_dev *ca,
					   bool scan_device, u32 *kick,
					   struct printbuf *err)
{
	if (scan_device) {
		struct reconcile_scan s = {
			.type = RECONCILE_SCAN_device, // TODO(performance): make this range-based
			.dev = ca->dev_idx,
		};

		int ret = bch2_set_reconcile_needs_scan(c, s, false);
		if (ret) {
			prt_printf(err, "Failed to queue device reconcile scan: %s\n",
				   bch2_err_str(ret));
			return ret;
		}
	}

	/*
	 * Shrink waits for a completed reconcile pass, not just for the device
	 * scan cookie to disappear. Queue the pending phase alongside the scan
	 * so the same pass also retries any work that evacuation demoted to the
	 * pending list.
	 */
	int ret = bch2_set_reconcile_needs_scan(c,
		(struct reconcile_scan) { .type = RECONCILE_SCAN_pending }, false);
	if (ret) {
		prt_printf(err, "Failed to queue pending reconcile scan: %s\n",
			   bch2_err_str(ret));
		return ret;
	}

	*kick = bch2_reconcile_kick(c);
	return 0;
}

static int bch2_dev_shrink_wait_reconcile(struct bch_dev *ca, u64 new_nbuckets,
					  u64 seq, u32 kick,
					  const struct shrink_tail_head *head_before,
					  bool *kick_complete,
					  struct printbuf *err)
{
	struct bch_fs *c = ca->fs;

	while (true) {
		bool completed;
		try(bch2_dev_resize_restart_check(ca, seq));

		/*
		 * We only need reconcile to keep running until the shrink tail is
		 * actually empty. A kick can continue chewing through unrelated
		 * global reconcile work for minutes after the truncating region is
		 * already evacuated, especially with fragmented variable-bucket
		 * workloads. Poll the head of the shrink tail and bound each wait
		 * to a one-second slice so shrink can rescan its own state instead
		 * of sitting behind one long reconcile kick.
		 */
		struct shrink_tail_head head_after;

		try(tail_head_snapshot(c, ca, new_nbuckets, &head_after));
		completed = bch2_reconcile_completed_kick(c) >= kick;

		if (shrink_tail_head_empty(&head_after) ||
		    shrink_tail_head_progressed(head_before, &head_after) ||
		    completed) {
			*kick_complete = completed;
			return 0;
		}

		int ret = wait_event_killable_timeout(c->reconcile.wait,
			bch2_reconcile_completed_kick(c) >= kick ||
			bch2_dev_resize_seq(ca) != seq ||
			kthread_should_stop(),
			HZ);
		if (ret < 0)
			return -EINTR;
		if (!ret) {
			*kick_complete = false;
			return 0;
		}
	}
}

static int bch2_dev_shrink_clear_target(struct bch_fs *c, struct bch_dev *ca,
					u64 new_nbuckets, u64 seq,
					struct printbuf *err)
{
	scoped_guard(rwsem_write, &c->state_lock) {
		try(bch2_dev_resize_restart_check(ca, seq));

		if (bch2_dev_resize_target(ca) != new_nbuckets ||
		    !bch2_dev_is_shrinking(ca))
			return -EAGAIN;

		try(bch2_dev_resize_update_target(c, ca, 0, err));
	}

	/* allocations are now no longer blocked after the cutoff, so there may now be more usable space  */
	int ret = bch2_reconcile_pending_wakeup(c); // TODO: also do this when a user requests a shrink cancel (aka a resize to the current size)
	if (ret)
		bch_err_fn(c, ret);

	return 0;
}

static int bch2_dev_shrink_finalize(struct bch_fs *c, struct bch_dev *ca,
				  u64 old_nbuckets, u64 new_nbuckets,
				  u64 seq, struct printbuf *err)
{
	scoped_guard(rwsem_write, &c->state_lock) {
		bool empty = false;

		try(bch2_dev_resize_restart_check(ca, seq));

		if (bch2_dev_resize_target(ca) != new_nbuckets ||
		    !bch2_dev_is_shrinking(ca))
			return -EAGAIN;

		/* flush interior updates - mirroring dev remove path */
		bch2_btree_interior_updates_flush(c);

		/*
		 * Only flush pins that were already outstanding when shrink
		 * entered the final commit path. Reconcile can continue
		 * generating unrelated key-cache journal pins on newer
		 * sequences while the tail is already empty; waiting for every
		 * future pin here can turn shrink into an unbounded global
		 * journal drain.
		 */
		bch2_journal_flush_outstanding_pins(&c->journal);

		int ret = bch2_journal_flush_device_pins(&c->journal, ca->dev_idx);
		if (ret) {
			prt_printf(err, "bch2_journal_flush_device_pins() error: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		ret = bch2_journal_flush(&c->journal);
		if (ret) {
			prt_printf(err, "bch2_journal_flush() error: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		/* re-check that tail is really empty */
		try(tail_is_empty(c, ca, new_nbuckets, &empty));

		if (!empty) {
			prt_printf(err, "Shrink failed: still has data\n");
			return -EBUSY;
		}

		/* drop references to now-truncated superblock copies */
		ret = drop_sbs_after_cutoff(c, ca, new_nbuckets);
		if (ret) {
			prt_printf(err, "Error dropping superblocks after cutoff: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		/* update accounting info - has to happen before truncating alloc info */
		ret = bch2_dev_truncate_accounting(c, ca, old_nbuckets, new_nbuckets);
		if (ret) {
			prt_printf(err, "error updating accounting info: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		/* truncate alloc info */
		ret = bch2_dev_remove_alloc(c, ca, new_nbuckets);
		if (ret) {
			prt_printf(err, "error truncating alloc info: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		/*
		 * Commit the shrink only after the truncated tail has been
		 * removed from alloc metadata, so later transactions can't see
		 * stale tail buckets after the new size is visible.
		 */
		scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
			guard(mutex)(&c->sb_lock);
			struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
			m->nbuckets = cpu_to_le64(new_nbuckets);
			if (bch2_dev_resize_target(ca) == new_nbuckets)
				m->target_nbuckets = 0;

			try(bch2_write_super(c));
		}

		/* resize buckets */
		ret = bch2_dev_buckets_resize(c, ca, new_nbuckets);
		if (ret) {
			prt_printf(err, "bch2_dev_buckets_resize() error: %s\n",
				   bch2_err_str(ret));
			return ret;
		}

		bch2_recalc_capacity(c);
	}

	return 0;
}


static int __bch2_dev_shrink(struct bch_fs *c, struct bch_dev *ca,
			     u64 new_nbuckets, u64 seq, struct printbuf *err)
{
	u64 old_nbuckets = ca->mi.nbuckets;

	scoped_guard(rwsem_write, &c->state_lock) {
		/* validate shrink size */
		if (new_nbuckets >= old_nbuckets) {
			return -EAGAIN;
		}

		try(bch2_dev_resize_restart_check(ca, seq));

		if (bch2_dev_resize_target(ca) != new_nbuckets ||
		    !bch2_dev_is_shrinking(ca))
			return -EAGAIN;

		/* close open buckets in the to-be-shrunk region */
		bch2_open_buckets_stop(c, ca, false, new_nbuckets);
		bch2_reset_alloc_cursors(c); // avoid churn
	};

	try(bch2_dev_resize_restart_check(ca, seq));

	/*
	 * Shrink can start while a discard worker from earlier freespace
	 * churn is still in flight. Drain that work before we begin the
	 * evacuation/journal-flush path: once shrink has started, later
	 * discard passes skip the shrinking device, but an already-running
	 * discard can still race in and deadlock against resize/reconcile's
	 * allocator and btree rewrite work.
	 */
	flush_work(&c->discards.work);
	flush_work(&ca->discard_fast_work);

	try(bch2_dev_resize_restart_check(ca, seq));

	/*
	 * Move journal buckets out of the tail up front: otherwise the journal
	 * can keep reintroducing metadata references in the region we're trying
	 * to evacuate while reconcile is draining backpointers from it.
	 */
	try(move_journal_past_cutoff(c, ca, new_nbuckets, err));

	try(bch2_dev_resize_restart_check(ca, seq));


	/* optimized cached data invalidation - just drops instead of reconcile read + write + drop */
	int ret = bch2_dev_shrink_invalidate_tail_cached(c, ca, new_nbuckets);
	if (ret) {
		prt_printf(err, "Failed to invalidate cached shrink-tail data: %s\n",
			   bch2_err_str(ret));
		return ret;
	}

	try(bch2_dev_resize_restart_check(ca, seq));

	/* wait for to-be-shrunk region to be empty */
	const unsigned stalled_kicks_limit = 32;
	struct shrink_tail_progress best_progress = {
		.head.bucket	= SPOS_MAX,
		.head.first_bp	= SPOS_MAX,
	};
	bool scan_device = true;
	unsigned stalled_kicks = 0;

	for (unsigned pass = 0; ; pass++) {
		bool invalidated_cached = false;
		bool kick_complete;
		struct shrink_tail_head head;
		struct shrink_tail_progress progress;
		u32 kick;

		try(bch2_dev_resize_restart_check(ca, seq));

		try(tail_head_snapshot(c, ca, new_nbuckets, &head));

		/* do a definitive check */
		if (shrink_tail_head_empty(&head)) {
			{
				CLASS(btree_trans, trans)(c);
				try(bch2_btree_write_buffer_flush_sync(trans));
			}

			try(tail_head_snapshot(c, ca, new_nbuckets, &head));
			if (shrink_tail_head_empty(&head)) {
				break;
			}
		}

		/*
		 * Live foreground IO can require several shrink/reconcile passes
		 * before the leading tail bucket drains, and the head bucket can
		 * stay put while work elsewhere in the tail is still making
		 * space for it. Track both the leading bucket and the total tail
		 * backpointer count, but only count no-progress passes after a
		 * full device rescan on a journal-quiescent state; if the
		 * journal is still moving then foreground IO or reconcile is
		 * still mutating metadata and a no-progress pass is not evidence
		 * that the shrink tail is impossible to evacuate.
		 */
		try(tail_progress_snapshot(c, ca, new_nbuckets, &progress));

		if (shrink_tail_progressed(&best_progress, &progress)) {
			best_progress = progress;
			scan_device = false;
			stalled_kicks = 0;
		}

		/*
		 * A consumed scan cookie only means reconcile observed the scan
		 * request and queued downstream work. Wait until either the
		 * requested pass completes or the tail is already empty before we
		 * decide whether shrink needs another evacuation pass.
		 */
		bool did_scan = pass == 0 || scan_device;
		u64 journal_seq_before;

		try(bch2_dev_shrink_queue_reconcile(c, ca, did_scan, &kick, err));
		journal_seq_before = journal_cur_seq(&c->journal);

		try(bch2_dev_shrink_wait_reconcile(ca, new_nbuckets, seq, kick,
						     &head, &kick_complete, err));

		try(tail_progress_snapshot(c, ca, new_nbuckets, &progress));

		if (shrink_tail_head_empty(&progress.head))
			break;

		if (shrink_tail_progressed(&best_progress, &progress)) {
			best_progress = progress;
			scan_device = false;
			stalled_kicks = 0;
		} else if (kick_complete) {
			/*
			 * A no-progress pass only counts toward ENOSPC after a
			 * full device rescan on a quiescent journal state. If
			 * metadata is still being committed then the set of tail
			 * blockers is still moving, so rescan from the current
			 * tail instead of treating the shrink as impossible.
			 *
			 * This is intentionally conservative but the signal is
			 * filesystem-global: unrelated metadata-writing IO can
			 * advance the journal and keep the heuristic from ever
			 * counting a stalled pass. A later cleanup should narrow
			 * this to a shrink-local churn signal.
			 */
			if (journal_cur_seq(&c->journal) != journal_seq_before) {
				scan_device = true;
				stalled_kicks = 0;
			} else if (!did_scan) {
				scan_device = true;
			} else if (++stalled_kicks >= stalled_kicks_limit) {
				prt_printf(err,
					   "Shrink failed: evacuating all data from the shrink tail not possible\n");
				try(bch2_dev_shrink_clear_target(c, ca, new_nbuckets, seq, err));
				return -ENOSPC;
			}
		}
	}

	return bch2_dev_shrink_finalize(c, ca, old_nbuckets, new_nbuckets, seq, err);
}

static int bch2_dev_resize_thread(void *arg)
{
	struct bch_dev *ca = arg;
	struct bch_fs *c = ca->fs;
	u64 seen_seq = 0;

	set_freezable();

	while (!kthread_should_stop()) {
		kthread_wait_freezable(kthread_should_stop() ||
				       bch2_dev_resize_seq(ca) != seen_seq);
		if (kthread_should_stop())
			break;

		while (!kthread_should_stop()) {
			u64 seq = bch2_dev_resize_seq(ca);
			u64 target = bch2_dev_resize_target(ca);
			int ret;
			CLASS(printbuf, err)();

			if (target == ca->mi.nbuckets) {
				ret = 0;
			} else if (target > ca->mi.nbuckets) {
				ret = __bch2_dev_grow(c, ca, target, &err);
			} else {
				ret = __bch2_dev_shrink(c, ca, target, seq, &err);
			}

			if (ret == -EAGAIN)
				continue;

			if (ret && err.pos)
				bch_err_dev(ca, "%s", err.buf);
			else if (ret && ret != -EINTR)
				bch_err_fn_dev(ca, ret);

			seen_seq = bch2_dev_resize_seq(ca);
			if (ret == -EINTR)
				break;
			if (!bch2_dev_resize_finish(ca, seq, ret))
				continue;
			break;
		}
	}

	return 0;
}

static int bch2_dev_resize_kick(struct bch_dev *ca)
{
	u64 seq;

	scoped_guard(spinlock, &ca->resize_lock) {
		seq = ++ca->resize_seq;
		ca->resize_status = -EINPROGRESS;
	}

	wake_up_process(ca->resize_thread);
	return bch2_dev_resize_wait(ca, seq);
}

int bch2_dev_resize(struct bch_fs *c, struct bch_dev *ca, u64 new_nbuckets, struct printbuf *err)
{
	u64 target_nbuckets;

	scoped_guard(rwsem_write, &c->state_lock) {
		target_nbuckets = new_nbuckets == ca->mi.nbuckets
			? 0
			: new_nbuckets;

		try(bch2_dev_resize_thread_start(ca));

		try(bch2_dev_resize_update_target(c, ca, target_nbuckets, err));
	}

	int ret = bch2_dev_resize_kick(ca);
	if (ret == -ECANCELED)
		prt_printf(err, "Resize request superseded by a newer target\n");
	else if (ret && ret != -EINTR && !err->pos)
		prt_printf(err, "Resize worker failed; see kernel log for details\n");
	return ret;
}

int bch2_dev_resize_resume(struct bch_fs *c, struct bch_dev *ca,
			   struct printbuf *err)
{
	if (!bch2_dev_resize_pending(ca))
		return 0;

	scoped_guard(rwsem_write, &c->state_lock) {
		try(bch2_dev_resize_thread_start(ca));
	}

	int ret = bch2_dev_resize_kick(ca);
	if (ret && ret != -ECANCELED && ret != -EINTR && !err->pos)
		prt_printf(err, "Resize resume failed; see kernel log for details\n");
	return ret;
}

/* Resize on mount */

int __bch2_dev_resize_alloc(struct bch_dev *ca, u64 old_nbuckets, u64 new_nbuckets)
{
	struct bch_fs *c = ca->fs;
	s64 v[3] = { (s64) new_nbuckets - (s64) old_nbuckets, 0, 0 };

	return bch2_trans_commit_do(ca->fs, NULL, NULL, 0,
			bch2_disk_accounting_mod2(trans, false, v, dev_data_type,
						  .dev = ca->dev_idx,
						  .data_type = BCH_DATA_free)) ?:
		bch2_dev_freespace_init(c, ca, old_nbuckets, new_nbuckets);
}

/* return with ref on ca->ref: */
struct bch_dev *bch2_dev_lookup(struct bch_fs *c, const char *name)
{
	if (!strncmp(name, "/dev/", strlen("/dev/")))
		name += strlen("/dev/");

	for_each_member_device(c, ca)
		if (!strcmp(name, ca->name)) {
			bch2_dev_get(ca);
			return ca;
		}
	return ERR_PTR(-BCH_ERR_ENOENT_dev_not_found);
}

/* blk_holder_ops: */

static struct bch_fs *bdev_get_fs(struct block_device *bdev)
	__releases(&bdev->bd_holder_lock)
{
	struct bch_sb_handle_holder *holder = bdev->bd_holder;
	struct bch_fs *c = holder->c;

	if (c && !bch2_ro_ref_tryget(c))
		c = NULL;

	mutex_unlock(&bdev->bd_holder_lock);

	if (c)
		wait_event(c->ro_ref_wait, test_bit(BCH_FS_started, &c->flags));
	return c;
}

DEFINE_CLASS(bdev_get_fs, struct bch_fs *,
	     bch2_ro_ref_put(_T), bdev_get_fs(bdev),
	     struct block_device *bdev);

/* returns with ref on ca->ref */
static struct bch_dev *bdev_to_bch_dev(struct bch_fs *c, struct block_device *bdev)
{
	for_each_member_device(c, ca)
		if (ca->disk_sb.bdev == bdev) {
			bch2_dev_get(ca);
			return ca;
		}
	return NULL;
}

static void bch2_fs_bdev_mark_dead(struct block_device *bdev, bool surprise)
{
	CLASS(bdev_get_fs, c)(bdev);
	if (!c)
		return;

	struct super_block *sb = c->vfs_sb;
	if (sb) {
		/*
		 * Not necessary, c->ro_ref guards against the filesystem being
		 * unmounted - we only take this to avoid a warning in
		 * sync_filesystem:
		 */
		down_read(&sb->s_umount);
	}

	guard(rwsem_write)(&c->state_lock);

	struct bch_dev *ca = bdev_to_bch_dev(c, bdev);
	if (ca) {
		bool print = true;
		CLASS(printbuf, buf)();
		__bch2_log_msg_start(ca->name, &buf);
		prt_printf(&buf, "offline from block layer\n");

		bool dev = !bch2_dev_may_offline(c, ca, BCH_FORCE_IF_DEGRADED, &buf);
		if (!dev && sb) {
			if (!surprise)
				sync_filesystem(sb);
			shrink_dcache_sb(sb);
			evict_inodes(sb);
		}

		if (!dev) {
			bch2_journal_flush(&c->journal);
			print = bch2_fs_emergency_read_only(c, &buf);
		}

		__bch2_dev_offline(c, ca);

		if (print)
			bch2_print_str(c, KERN_ERR, buf.buf);

		bch2_dev_put(ca);
	}

	if (sb)
		up_read(&sb->s_umount);
}

static void bch2_fs_bdev_sync(struct block_device *bdev)
{
	CLASS(bdev_get_fs, c)(bdev);
	if (!c)
		return;

	struct super_block *sb = c->vfs_sb;
	if (sb) {
		/*
		 * Not necessary, c->ro_ref guards against the filesystem being
		 * unmounted - we only take this to avoid a warning in
		 * sync_filesystem:
		 */
		guard(rwsem_read)(&sb->s_umount);
		sync_filesystem(sb);
	}
}

const struct blk_holder_ops bch2_sb_handle_bdev_ops = {
	.mark_dead		= bch2_fs_bdev_mark_dead,
	.sync			= bch2_fs_bdev_sync,
};
