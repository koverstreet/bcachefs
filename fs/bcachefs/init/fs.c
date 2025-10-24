// SPDX-License-Identifier: GPL-2.0
/*
 * bcachefs setup/teardown code, and some metadata io - read a superblock and
 * figure out what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"

#include "alloc/backpointers.h"
#include "alloc/buckets_waiting_for_journal.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/replicas.h"

#include "btree/cache.h"
#include "btree/check.h"
#include "btree/journal_overlay.h"
#include "btree/interior.h"
#include "btree/key_cache.h"
#include "btree/node_scan.h"
#include "btree/read.h"
#include "btree/sort.h"
#include "btree/write.h"
#include "btree/write_buffer.h"

#include "data/checksum.h"
#include "data/compress.h"
#include "data/copygc.h"
#include "data/ec.h"
#include "data/move.h"
#include "data/nocow_locking.h"
#include "data/read.h"
#include "data/rebalance.h"
#include "data/write.h"

#include "debug/async_objs.h"
#include "debug/debug.h"
#include "debug/sysfs.h"

#include "fs/check.h"
#include "fs/inode.h"
#include "fs/quota.h"

#include "init/chardev.h"
#include "init/dev.h"
#include "init/error.h"
#include "init/recovery.h"
#include "init/passes.h"
#include "init/fs.h"

#include "journal/init.h"
#include "journal/journal.h"
#include "journal/reclaim.h"
#include "journal/seq_blacklist.h"

#include "sb/clean.h"
#include "sb/counters.h"
#include "sb/downgrade.h"
#include "sb/errors.h"
#include "sb/io.h"
#include "sb/members.h"

#include "snapshots/snapshot.h"
#include "snapshots/subvolume.h"

#include "vfs/fs.h"
#include "vfs/io.h"
#include "vfs/buffered.h"
#include "vfs/direct.h"

#include "util/clock.h"
#include "util/enumerated_ref.h"
#include "util/thread_with_file.h"

#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/sysfs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");
MODULE_DESCRIPTION("bcachefs filesystem");

typedef DARRAY(struct bch_sb_handle) bch_sb_handles;

#define x(n)		#n,
const char * const bch2_fs_flag_strs[] = {
	BCH_FS_FLAGS()
	NULL
};

const char * const bch2_write_refs[] = {
	BCH_WRITE_REFS()
	NULL
};
#undef x

static bool should_print_loglevel(struct bch_fs *c, const char *fmt)
{
	unsigned loglevel_opt = c->loglevel ?: c->opts.verbose ? 7: 6;

	bool have_soh = fmt[0] == KERN_SOH[0];
	bool have_loglevel = have_soh && fmt[1] >= '0' && fmt[1] <= '9';

	unsigned loglevel = have_loglevel
		? fmt[1] - '0'
		: c->prev_loglevel;

	if (have_loglevel)
		c->prev_loglevel = loglevel;

	return loglevel <= loglevel_opt;
}

void bch2_print_str(struct bch_fs *c, const char *prefix, const char *str)
{
	if (!should_print_loglevel(c, prefix))
		return;

#ifndef __KERNEL__
	prefix = "";
#endif

#ifdef __KERNEL__
	struct stdio_redirect *stdio = bch2_fs_stdio_redirect(c);

	if (unlikely(stdio)) {
		bch2_stdio_redirect_printf(stdio, true, "%s", str);
		return;
	}
#endif
	bch2_print_string_as_lines(prefix, str);
}

__printf(2, 0)
static void bch2_print_maybe_redirect(struct stdio_redirect *stdio, const char *fmt, va_list args)
{
#ifdef __KERNEL__
	if (unlikely(stdio)) {
		if (fmt[0] == KERN_SOH[0])
			fmt += 2;

		bch2_stdio_redirect_vprintf(stdio, true, fmt, args);
		return;
	}
#endif
	vprintk(fmt, args);
}

void bch2_print_opts(struct bch_opts *opts, const char *fmt, ...)
{
	struct stdio_redirect *stdio = (void *)(unsigned long)opts->stdio;

	va_list args;
	va_start(args, fmt);
	bch2_print_maybe_redirect(stdio, fmt, args);
	va_end(args);
}

void __bch2_print(struct bch_fs *c, const char *fmt, ...)
{
	if (!should_print_loglevel(c, fmt))
		return;

#ifndef __KERNEL__
	if (fmt[0] == KERN_SOH[0])
		fmt += 2;
#endif

	struct stdio_redirect *stdio = bch2_fs_stdio_redirect(c);

	va_list args;
	va_start(args, fmt);
	bch2_print_maybe_redirect(stdio, fmt, args);
	va_end(args);
}

static void bch2_fs_release(struct kobject *);
static void bch2_fs_counters_release(struct kobject *k)
{
}

static void bch2_fs_internal_release(struct kobject *k)
{
}

static void bch2_fs_opts_dir_release(struct kobject *k)
{
}

static void bch2_fs_time_stats_release(struct kobject *k)
{
}

KTYPE(bch2_fs);
KTYPE(bch2_fs_counters);
KTYPE(bch2_fs_internal);
KTYPE(bch2_fs_opts_dir);
KTYPE(bch2_fs_time_stats);

static struct kset *bcachefs_kset;

static DECLARE_WAIT_QUEUE_HEAD(bch2_read_only_wait);

LIST_HEAD(bch2_fs_list);
DEFINE_MUTEX(bch2_fs_list_lock);

static bool bch2_fs_will_resize_on_mount(struct bch_fs *);

struct bch_fs *__bch2_uuid_to_fs(__uuid_t uuid)
{
	struct bch_fs *c;

	lockdep_assert_held(&bch2_fs_list_lock);

	list_for_each_entry(c, &bch2_fs_list, list)
		if (!memcmp(&c->disk_sb.sb->uuid, &uuid, sizeof(uuid)))
			return c;

	return NULL;
}

struct bch_fs *bch2_uuid_to_fs(__uuid_t uuid)
{
	guard(mutex)(&bch2_fs_list_lock);

	struct bch_fs *c = __bch2_uuid_to_fs(uuid);
	if (c)
		closure_get(&c->cl);
	return c;
}

/* Filesystem RO/RW: */

/*
 * For startup/shutdown of RW stuff, the dependencies are:
 *
 * - foreground writes depend on copygc and rebalance (to free up space)
 *
 * - copygc and rebalance depend on mark and sweep gc (they actually probably
 *   don't because they either reserve ahead of time or don't block if
 *   allocations fail, but allocations can require mark and sweep gc to run
 *   because of generation number wraparound)
 *
 * - all of the above depends on the allocator threads
 *
 * - allocator depends on the journal (when it rewrites prios and gens)
 */

static void __bch2_fs_read_only(struct bch_fs *c)
{
	unsigned clean_passes = 0;
	u64 seq = 0;

	bch2_fs_ec_stop(c);
	bch2_open_buckets_stop(c, NULL, true);
	bch2_rebalance_stop(c);
	bch2_copygc_stop(c);
	bch2_fs_ec_flush(c);

	bch_verbose(c, "flushing journal and stopping allocators, journal seq %llu",
		    journal_cur_seq(&c->journal));

	do {
		clean_passes++;

		bch2_do_discards_going_ro(c);

		if (bch2_btree_interior_updates_flush(c) ||
		    bch2_btree_write_buffer_flush_going_ro(c) ||
		    bch2_journal_flush_all_pins(&c->journal) ||
		    bch2_btree_flush_all_writes(c) ||
		    seq != atomic64_read(&c->journal.seq)) {
			seq = atomic64_read(&c->journal.seq);
			clean_passes = 0;
		}
	} while (clean_passes < 2);

	bch_verbose(c, "flushing journal and stopping allocators complete, journal seq %llu",
		    journal_cur_seq(&c->journal));

	if (test_bit(JOURNAL_replay_done, &c->journal.flags) &&
	    !test_bit(BCH_FS_emergency_ro, &c->flags))
		set_bit(BCH_FS_clean_shutdown, &c->flags);

	bch2_fs_journal_stop(&c->journal);

	bch_info(c, "%sclean shutdown complete, journal seq %llu",
		 test_bit(BCH_FS_clean_shutdown, &c->flags) ? "" : "un",
		 c->journal.seq_ondisk);

	/*
	 * After stopping journal:
	 */
	for_each_member_device(c, ca) {
		bch2_dev_io_ref_stop(ca, WRITE);
		bch2_dev_allocator_remove(c, ca);
	}
}

static void bch2_writes_disabled(struct enumerated_ref *writes)
{
	struct bch_fs *c = container_of(writes, struct bch_fs, writes);

	set_bit(BCH_FS_write_disable_complete, &c->flags);
	wake_up(&bch2_read_only_wait);
}

void bch2_fs_read_only(struct bch_fs *c)
{
	if (!test_bit(BCH_FS_rw, &c->flags)) {
		bch2_journal_reclaim_stop(&c->journal);
		return;
	}

	BUG_ON(test_bit(BCH_FS_write_disable_complete, &c->flags));

	bch_verbose(c, "going read-only");

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 */
	set_bit(BCH_FS_going_ro, &c->flags);
	enumerated_ref_stop_async(&c->writes);

	/*
	 * If we're not doing an emergency shutdown, we want to wait on
	 * outstanding writes to complete so they don't see spurious errors due
	 * to shutting down the allocator:
	 *
	 * If we are doing an emergency shutdown outstanding writes may
	 * hang until we shutdown the allocator so we don't want to wait
	 * on outstanding writes before shutting everything down - but
	 * we do need to wait on them before returning and signalling
	 * that going RO is complete:
	 */
	wait_event(bch2_read_only_wait,
		   test_bit(BCH_FS_write_disable_complete, &c->flags) ||
		   test_bit(BCH_FS_emergency_ro, &c->flags));

	bool writes_disabled = test_bit(BCH_FS_write_disable_complete, &c->flags);
	if (writes_disabled)
		bch_verbose(c, "finished waiting for writes to stop");

	__bch2_fs_read_only(c);

	wait_event(bch2_read_only_wait,
		   test_bit(BCH_FS_write_disable_complete, &c->flags));

	if (!writes_disabled)
		bch_verbose(c, "finished waiting for writes to stop");

	clear_bit(BCH_FS_write_disable_complete, &c->flags);
	clear_bit(BCH_FS_going_ro, &c->flags);
	clear_bit(BCH_FS_rw, &c->flags);

	if (!bch2_journal_error(&c->journal) &&
	    !test_bit(BCH_FS_error, &c->flags) &&
	    !test_bit(BCH_FS_emergency_ro, &c->flags) &&
	    test_bit(BCH_FS_started, &c->flags) &&
	    test_bit(BCH_FS_clean_shutdown, &c->flags) &&
	    c->recovery.pass_done >= BCH_RECOVERY_PASS_journal_replay) {
		BUG_ON(c->journal.last_empty_seq != journal_cur_seq(&c->journal));
		BUG_ON(atomic_long_read(&c->btree_cache.nr_dirty));
		BUG_ON(atomic_long_read(&c->btree_key_cache.nr_dirty));
		BUG_ON(c->btree_write_buffer.inc.keys.nr);
		BUG_ON(c->btree_write_buffer.flushing.keys.nr);
		bch2_verify_accounting_clean(c);

		bch_verbose(c, "marking filesystem clean");
		bch2_fs_mark_clean(c);
	} else {
		/* Make sure error counts/counters are persisted */
		guard(mutex)(&c->sb_lock);
		bch2_write_super(c);

		bch_verbose(c, "done going read-only, filesystem not clean");
	}
}

static void bch2_fs_read_only_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, read_only_work);

	guard(rwsem_write)(&c->state_lock);
	bch2_fs_read_only(c);
}

static void bch2_fs_read_only_async(struct bch_fs *c)
{
	queue_work(system_long_wq, &c->read_only_work);
}

bool bch2_fs_emergency_read_only(struct bch_fs *c)
{
	bool ret = !test_and_set_bit(BCH_FS_emergency_ro, &c->flags);

	bch2_journal_halt(&c->journal);
	bch2_fs_read_only_async(c);

	wake_up(&bch2_read_only_wait);
	return ret;
}

static bool __bch2_fs_emergency_read_only2(struct bch_fs *c, struct printbuf *out,
					   bool locked)
{
	bool ret = !test_and_set_bit(BCH_FS_emergency_ro, &c->flags);

	if (!locked)
		bch2_journal_halt(&c->journal);
	else
		bch2_journal_halt_locked(&c->journal);
	bch2_fs_read_only_async(c);
	wake_up(&bch2_read_only_wait);

	if (ret) {
		prt_printf(out, "emergency read only at seq %llu\n",
			   journal_cur_seq(&c->journal));
		bch2_prt_task_backtrace(out, current, 2, out->atomic ? GFP_ATOMIC : GFP_KERNEL);
	}

	return ret;
}

bool bch2_fs_emergency_read_only2(struct bch_fs *c, struct printbuf *out)
{
	return __bch2_fs_emergency_read_only2(c, out, false);
}

bool bch2_fs_emergency_read_only_locked(struct bch_fs *c)
{
	bool ret = !test_and_set_bit(BCH_FS_emergency_ro, &c->flags);

	bch2_journal_halt_locked(&c->journal);
	bch2_fs_read_only_async(c);

	wake_up(&bch2_read_only_wait);
	return ret;
}

static int __bch2_fs_read_write(struct bch_fs *c, bool early)
{
	BUG_ON(!test_bit(BCH_FS_may_go_rw, &c->flags));

	if (WARN_ON(c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)))
		return bch_err_throw(c, erofs_no_alloc_info);

	if (test_bit(BCH_FS_initial_gc_unfixed, &c->flags)) {
		bch_err(c, "cannot go rw, unfixed btree errors");
		return bch_err_throw(c, erofs_unfixed_errors);
	}

	if (c->sb.features & BIT_ULL(BCH_FEATURE_small_image)) {
		bch_err(c, "cannot go rw, filesystem is an unresized image file");
		return bch_err_throw(c, erofs_filesystem_full);
	}

	if (test_bit(BCH_FS_rw, &c->flags))
		return 0;

	bch_info(c, "going read-write");

	try(bch2_fs_init_rw(c));
	try(bch2_sb_members_v2_init(c));
	try(bch2_fs_mark_dirty(c));

	clear_bit(BCH_FS_clean_shutdown, &c->flags);

	scoped_guard(rcu)
		for_each_online_member_rcu(c, ca)
			if (ca->mi.state == BCH_MEMBER_STATE_rw) {
				bch2_dev_allocator_add(c, ca);
				enumerated_ref_start(&ca->io_ref[WRITE]);
			}

	bch2_recalc_capacity(c);

	/*
	 * First journal write must be a flush write: after a clean shutdown we
	 * don't read the journal, so the first journal write may end up
	 * overwriting whatever was there previously, and there must always be
	 * at least one non-flush write in the journal or recovery will fail:
	 */
	scoped_guard(spinlock, &c->journal.lock) {
		set_bit(JOURNAL_need_flush_write, &c->journal.flags);
		set_bit(JOURNAL_running, &c->journal.flags);
		bch2_journal_space_available(&c->journal);
	}

	/*
	 * Don't jump to our error path, and call bch2_fs_read_only(), unless we
	 * successfully marked the filesystem dirty
	 */

	set_bit(BCH_FS_rw, &c->flags);
	set_bit(BCH_FS_was_rw, &c->flags);

	enumerated_ref_start(&c->writes);

	int ret = bch2_journal_reclaim_start(&c->journal) ?:
		  bch2_copygc_start(c) ?:
		  bch2_rebalance_start(c);
	if (ret) {
		bch2_fs_read_only(c);
		return ret;
	}

	bch2_do_discards(c);
	bch2_do_invalidates(c);
	bch2_do_stripe_deletes(c);
	bch2_do_pending_node_rewrites(c);
	return 0;
}

int bch2_fs_read_write(struct bch_fs *c)
{
	if (c->opts.recovery_pass_last &&
	    c->opts.recovery_pass_last < BCH_RECOVERY_PASS_journal_replay)
		return bch_err_throw(c, erofs_norecovery);

	if (c->opts.nochanges)
		return bch_err_throw(c, erofs_nochanges);

	if (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info))
		return bch_err_throw(c, erofs_no_alloc_info);

	return __bch2_fs_read_write(c, false);
}

int bch2_fs_read_write_early(struct bch_fs *c)
{
	guard(rwsem_write)(&c->state_lock);
	return __bch2_fs_read_write(c, true);
}

/* Filesystem startup/shutdown: */

static void __bch2_fs_free(struct bch_fs *c)
{
	for (unsigned i = 0; i < BCH_TIME_STAT_NR; i++)
		bch2_time_stats_exit(&c->times[i]);

#if IS_ENABLED(CONFIG_UNICODE)
	utf8_unload(c->cf_encoding);
#endif

	bch2_rebalance_stop(c);
	bch2_copygc_stop(c);
	bch2_find_btree_nodes_exit(&c->found_btree_nodes);
	bch2_free_pending_node_rewrites(c);
	bch2_free_fsck_errs(c);
	bch2_fs_vfs_exit(c);
	bch2_fs_snapshots_exit(c);
	bch2_fs_sb_errors_exit(c);
	bch2_fs_replicas_exit(c);
	bch2_fs_rebalance_exit(c);
	bch2_fs_quota_exit(c);
	bch2_fs_nocow_locking_exit(c);
	bch2_fs_journal_exit(&c->journal);
	bch2_fs_fs_io_direct_exit(c);
	bch2_fs_fs_io_buffered_exit(c);
	bch2_fs_fsio_exit(c);
	bch2_fs_io_write_exit(c);
	bch2_fs_io_read_exit(c);
	bch2_fs_encryption_exit(c);
	bch2_fs_ec_exit(c);
	bch2_fs_counters_exit(c);
	bch2_fs_compress_exit(c);
	bch2_io_clock_exit(&c->io_clock[WRITE]);
	bch2_io_clock_exit(&c->io_clock[READ]);
	bch2_fs_buckets_waiting_for_journal_exit(c);
	bch2_fs_btree_write_buffer_exit(c);
	bch2_fs_btree_key_cache_exit(&c->btree_key_cache);
	bch2_fs_btree_iter_exit(c);
	bch2_fs_btree_interior_update_exit(c);
	bch2_fs_btree_cache_exit(c);
	bch2_fs_accounting_exit(c);
	bch2_fs_async_obj_exit(c);
	bch2_journal_keys_put_initial(c);
	bch2_find_btree_nodes_exit(&c->found_btree_nodes);

	BUG_ON(atomic_read(&c->journal_keys.ref));
	percpu_free_rwsem(&c->mark_lock);
	if (c->online_reserved) {
		u64 v = percpu_u64_get(c->online_reserved);
		WARN(v, "online_reserved not 0 at shutdown: %lli", v);
		free_percpu(c->online_reserved);
	}

	darray_exit(&c->btree_roots_extra);
	free_percpu(c->pcpu);
	free_percpu(c->usage);
	mempool_exit(&c->btree_bounce_pool);
	bioset_exit(&c->btree_bio);
	mempool_exit(&c->fill_iter);
	enumerated_ref_exit(&c->writes);
	kfree(rcu_dereference_protected(c->disk_groups, 1));
	kfree(c->journal_seq_blacklist_table);

	if (c->write_ref_wq)
		destroy_workqueue(c->write_ref_wq);
	if (c->btree_write_submit_wq)
		destroy_workqueue(c->btree_write_submit_wq);
	if (c->btree_read_complete_wq)
		destroy_workqueue(c->btree_read_complete_wq);
	if (c->copygc_wq)
		destroy_workqueue(c->copygc_wq);
	if (c->btree_write_complete_wq)
		destroy_workqueue(c->btree_write_complete_wq);
	if (c->btree_update_wq)
		destroy_workqueue(c->btree_update_wq);

	bch2_free_super(&c->disk_sb);
	kvfree(c);
	module_put(THIS_MODULE);
}

static void bch2_fs_release(struct kobject *kobj)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	__bch2_fs_free(c);
}

void __bch2_fs_stop(struct bch_fs *c)
{
	bch_verbose(c, "shutting down");

	set_bit(BCH_FS_stopping, &c->flags);

	scoped_guard(rwsem_write, &c->state_lock)
		bch2_fs_read_only(c);

	for (unsigned i = 0; i < c->sb.nr_devices; i++) {
		struct bch_dev *ca = rcu_dereference_protected(c->devs[i], true);
		if (ca)
			bch2_dev_io_ref_stop(ca, READ);
	}

	for_each_member_device(c, ca)
		bch2_dev_unlink(ca);

	if (c->kobj.state_in_sysfs)
		kobject_del(&c->kobj);

	bch2_fs_debug_exit(c);
	bch2_fs_chardev_exit(c);

	bch2_ro_ref_put(c);
	wait_event(c->ro_ref_wait, !refcount_read(&c->ro_ref));

	kobject_put(&c->counters_kobj);
	kobject_put(&c->time_stats);
	kobject_put(&c->opts_dir);
	kobject_put(&c->internal);

	/* btree prefetch might have kicked off reads in the background: */
	bch2_btree_flush_all_reads(c);

	for_each_member_device(c, ca)
		cancel_work_sync(&ca->io_error_work);

	cancel_work_sync(&c->read_only_work);

	flush_work(&c->btree_interior_update_work);
}

void bch2_fs_free(struct bch_fs *c)
{
	scoped_guard(mutex, &bch2_fs_list_lock)
		list_del(&c->list);

	closure_sync(&c->cl);
	closure_debug_destroy(&c->cl);

	for (unsigned i = 0; i < c->sb.nr_devices; i++) {
		struct bch_dev *ca = rcu_dereference_protected(c->devs[i], true);

		if (ca) {
			EBUG_ON(atomic_long_read(&ca->ref) != 1);
			bch2_dev_io_ref_stop(ca, READ);
			bch2_free_super(&ca->disk_sb);
			bch2_dev_free(ca);
		}
	}

	bch_verbose(c, "shutdown complete");

	kobject_put(&c->kobj);
}

void bch2_fs_stop(struct bch_fs *c)
{
	__bch2_fs_stop(c);
	bch2_fs_free(c);
}

static int bch2_fs_online(struct bch_fs *c)
{
	int ret = 0;

	lockdep_assert_held(&bch2_fs_list_lock);

	if (c->sb.multi_device &&
	    __bch2_uuid_to_fs(c->sb.uuid)) {
		bch_err(c, "filesystem UUID already open");
		return bch_err_throw(c, filesystem_uuid_already_open);
	}

	ret = bch2_fs_chardev_init(c);
	if (ret) {
		bch_err(c, "error creating character device");
		return ret;
	}

	bch2_fs_debug_init(c);

	ret = (c->sb.multi_device
	       ? kobject_add(&c->kobj, NULL, "%pU", c->sb.user_uuid.b)
	       : kobject_add(&c->kobj, NULL, "%s", c->name)) ?:
	    kobject_add(&c->internal, &c->kobj, "internal") ?:
	    kobject_add(&c->opts_dir, &c->kobj, "options") ?:
#ifndef CONFIG_BCACHEFS_NO_LATENCY_ACCT
	    kobject_add(&c->time_stats, &c->kobj, "time_stats") ?:
#endif
	    kobject_add(&c->counters_kobj, &c->kobj, "counters") ?:
	    bch2_opts_create_sysfs_files(&c->opts_dir, OPT_FS);
	if (ret) {
		bch_err(c, "error creating sysfs objects");
		return ret;
	}

	guard(rwsem_write)(&c->state_lock);

	for_each_member_device(c, ca) {
		ret = bch2_dev_sysfs_online(c, ca);
		if (ret) {
			bch_err(c, "error creating sysfs objects");
			bch2_dev_put(ca);
			return ret;
		}
	}

	BUG_ON(!list_empty(&c->list));
	list_add(&c->list, &bch2_fs_list);
	return ret;
}

int bch2_fs_init_rw(struct bch_fs *c)
{
	if (test_bit(BCH_FS_rw_init_done, &c->flags))
		return 0;

	if (!(c->btree_update_wq = alloc_workqueue("bcachefs",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_UNBOUND, 512)) ||
	    !(c->btree_write_complete_wq = alloc_workqueue("bcachefs_btree_write_complete",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 1)) ||
	    !(c->copygc_wq = alloc_workqueue("bcachefs_copygc",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_CPU_INTENSIVE, 1)) ||
	    !(c->btree_write_submit_wq = alloc_workqueue("bcachefs_btree_write_sumit",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 1)) ||
	    !(c->write_ref_wq = alloc_workqueue("bcachefs_write_ref",
				WQ_FREEZABLE, 0)))
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	int ret = bch2_fs_btree_interior_update_init(c) ?:
		bch2_fs_btree_write_buffer_init(c) ?:
		bch2_fs_fs_io_buffered_init(c) ?:
		bch2_fs_io_write_init(c) ?:
		bch2_fs_journal_init(&c->journal) ?:
		bch2_journal_reclaim_start(&c->journal) ?:
		bch2_copygc_start(c) ?:
		bch2_rebalance_start(c);
	if (ret)
		return ret;

	set_bit(BCH_FS_rw_init_done, &c->flags);
	return 0;
}

static bool check_version_upgrade(struct bch_fs *c)
{
	unsigned latest_version	= bcachefs_metadata_version_current;
	unsigned latest_compatible = min(latest_version,
					 bch2_latest_compatible_version(c->sb.version));
	unsigned old_version = c->sb.version_upgrade_complete ?: c->sb.version;
	unsigned new_version = 0;
	bool ret = false;

	if (old_version < bcachefs_metadata_required_upgrade_below) {
		if (c->opts.version_upgrade == BCH_VERSION_UPGRADE_incompatible ||
		    latest_compatible < bcachefs_metadata_required_upgrade_below)
			new_version = latest_version;
		else
			new_version = latest_compatible;
	} else {
		switch (c->opts.version_upgrade) {
		case BCH_VERSION_UPGRADE_compatible:
			new_version = latest_compatible;
			break;
		case BCH_VERSION_UPGRADE_incompatible:
			new_version = latest_version;
			break;
		case BCH_VERSION_UPGRADE_none:
			new_version = min(old_version, latest_version);
			break;
		}
	}

	if (new_version > old_version) {
		CLASS(printbuf, buf)();

		if (old_version < bcachefs_metadata_required_upgrade_below)
			prt_str(&buf, "Version upgrade required:\n");

		if (old_version != c->sb.version) {
			prt_str(&buf, "Version upgrade from ");
			bch2_version_to_text(&buf, c->sb.version_upgrade_complete);
			prt_str(&buf, " to ");
			bch2_version_to_text(&buf, c->sb.version);
			prt_str(&buf, " incomplete\n");
		}

		prt_printf(&buf, "Doing %s version upgrade from ",
			   BCH_VERSION_MAJOR(old_version) != BCH_VERSION_MAJOR(new_version)
			   ? "incompatible" : "compatible");
		bch2_version_to_text(&buf, old_version);
		prt_str(&buf, " to ");
		bch2_version_to_text(&buf, new_version);
		prt_newline(&buf);

		struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);
		__le64 passes = ext->recovery_passes_required[0];
		bch2_sb_set_upgrade(c, old_version, new_version);
		passes = ext->recovery_passes_required[0] & ~passes;

		if (passes) {
			prt_str(&buf, "  running recovery passes: ");
			prt_bitflags(&buf, bch2_recovery_passes,
				     bch2_recovery_passes_from_stable(le64_to_cpu(passes)));
		}

		bch_notice(c, "%s", buf.buf);
		ret = true;
	}

	if (new_version > c->sb.version_incompat_allowed &&
	    c->opts.version_upgrade == BCH_VERSION_UPGRADE_incompatible) {
		CLASS(printbuf, buf)();

		prt_str(&buf, "Now allowing incompatible features up to ");
		bch2_version_to_text(&buf, new_version);
		prt_str(&buf, ", previously allowed up to ");
		bch2_version_to_text(&buf, c->sb.version_incompat_allowed);
		prt_newline(&buf);

		bch_notice(c, "%s", buf.buf);
		ret = true;
	}

	if (ret)
		bch2_sb_upgrade(c, new_version,
				c->opts.version_upgrade == BCH_VERSION_UPGRADE_incompatible);

	return ret;
}

noinline_for_stack
static int bch2_fs_opt_version_init(struct bch_fs *c)
{
	if (c->opts.norecovery) {
		c->opts.recovery_pass_last = c->opts.recovery_pass_last
			? min(c->opts.recovery_pass_last, BCH_RECOVERY_PASS_snapshots_read)
			: BCH_RECOVERY_PASS_snapshots_read;
		c->opts.nochanges = true;
	}

	if (c->opts.nochanges)
		c->opts.read_only = true;

	if (c->opts.journal_rewind)
		c->opts.fsck = true;

	bool may_upgrade_downgrade = !(c->sb.features & BIT_ULL(BCH_FEATURE_small_image)) ||
		bch2_fs_will_resize_on_mount(c);

	CLASS(printbuf, p)();
	bch2_log_msg_start(c, &p);

	prt_str(&p, "starting version ");
	bch2_version_to_text(&p, c->sb.version);

	bool first = true;
	for (enum bch_opt_id i = 0; i < bch2_opts_nr; i++) {
		const struct bch_option *opt = &bch2_opt_table[i];
		u64 v = bch2_opt_get_by_id(&c->opts, i);

		if (!(opt->flags & OPT_MOUNT))
			continue;

		if (v == bch2_opt_get_by_id(&bch2_opts_default, i))
			continue;

		prt_str(&p, first ? " opts=" : ",");
		first = false;
		bch2_opt_to_text(&p, c, c->disk_sb.sb, opt, v, OPT_SHOW_MOUNT_STYLE);
	}

	if (c->sb.version_incompat_allowed != c->sb.version) {
		prt_printf(&p, "\nallowing incompatible features above ");
		bch2_version_to_text(&p, c->sb.version_incompat_allowed);
	}

	if (c->opts.verbose) {
		prt_printf(&p, "\nfeatures: ");
		prt_bitflags(&p, bch2_sb_features, c->sb.features);
	}

	if (c->sb.multi_device) {
		prt_printf(&p, "\nwith devices");
		for_each_online_member(c, ca, BCH_DEV_READ_REF_bch2_online_devs) {
			prt_char(&p, ' ');
			prt_str(&p, ca->name);
		}
	}

	/* cf_encoding log message should be here, but it breaks xfstests - sigh */

	if (c->opts.journal_rewind)
		prt_printf(&p, "\nrewinding journal, fsck required");

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_sb_field_ext *ext = bch2_sb_field_get_minsize(&c->disk_sb, ext,
				sizeof(struct bch_sb_field_ext) / sizeof(u64));
		if (!ext)
			return bch_err_throw(c, ENOSPC_sb);

		try(bch2_sb_members_v2_init(c));

		__le64 now = cpu_to_le64(ktime_get_real_seconds());
		scoped_guard(rcu)
			for_each_online_member_rcu(c, ca)
				bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx)->last_mount = now;

		if (BCH_SB_HAS_TOPOLOGY_ERRORS(c->disk_sb.sb))
			ext->recovery_passes_required[0] |=
				cpu_to_le64(bch2_recovery_passes_to_stable(BIT_ULL(BCH_RECOVERY_PASS_check_topology)));

		u64 sb_passes = bch2_recovery_passes_from_stable(le64_to_cpu(ext->recovery_passes_required[0]));
		if (sb_passes) {
			prt_str(&p, "\nsuperblock requires following recovery passes to be run:\n  ");
			prt_bitflags(&p, bch2_recovery_passes, sb_passes);
		}

		u64 btrees_lost_data = le64_to_cpu(ext->btrees_lost_data);
		if (btrees_lost_data) {
			prt_str(&p, "\nsuperblock indicates damage to following btrees:\n  ");
			prt_bitflags(&p, __bch2_btree_ids, btrees_lost_data);
		}

		if (may_upgrade_downgrade) {
			if (bch2_check_version_downgrade(c)) {
				prt_str(&p, "\nVersion downgrade required:");

				__le64 passes = ext->recovery_passes_required[0];
				bch2_sb_set_downgrade(c,
						      BCH_VERSION_MINOR(bcachefs_metadata_version_current),
						      BCH_VERSION_MINOR(c->sb.version));
				passes = ext->recovery_passes_required[0] & ~passes;
				if (passes) {
					prt_str(&p, "\nrunning recovery passes: ");
					prt_bitflags(&p, bch2_recovery_passes,
						     bch2_recovery_passes_from_stable(le64_to_cpu(passes)));
				}
			}

			check_version_upgrade(c);
		}

		c->opts.recovery_passes |= bch2_recovery_passes_from_stable(le64_to_cpu(ext->recovery_passes_required[0]));

		if (c->sb.version_upgrade_complete < bcachefs_metadata_version_autofix_errors)
			SET_BCH_SB_ERROR_ACTION(c->disk_sb.sb, BCH_ON_ERROR_fix_safe);

		/* Don't write the superblock, defer that until we go rw */
	}

	if (c->sb.clean)
		set_bit(BCH_FS_clean_recovery, &c->flags);
	if (c->opts.fsck)
		set_bit(BCH_FS_in_fsck, &c->flags);
	set_bit(BCH_FS_in_recovery, &c->flags);

	bch2_print_str(c, KERN_INFO, p.buf);

	/* this really should be part of our one multi line mount message, but -
	 * xfstests... */
	if (c->cf_encoding)
		bch_info(c, "Using encoding defined by superblock: utf8-%u.%u.%u",
			   unicode_major(BCH_FS_DEFAULT_UTF8_ENCODING),
			   unicode_minor(BCH_FS_DEFAULT_UTF8_ENCODING),
			   unicode_rev(BCH_FS_DEFAULT_UTF8_ENCODING));

	if (BCH_SB_INITIALIZED(c->disk_sb.sb)) {
		if (!(c->sb.features & (1ULL << BCH_FEATURE_new_extent_overwrite))) {
			bch_err(c, "feature new_extent_overwrite not set, filesystem no longer supported");
			return -EINVAL;
		}

		if (!c->sb.clean &&
		    !(c->sb.features & (1ULL << BCH_FEATURE_extents_above_btree_updates))) {
			bch_err(c, "filesystem needs recovery from older version; run fsck from older bcachefs-tools to fix");
			return -EINVAL;
		}
	}

	return 0;
}

static struct bch_fs *bch2_fs_alloc(struct bch_sb *sb, struct bch_opts *opts,
				    bch_sb_handles *sbs)
{
	struct bch_fs *c;
	unsigned i, iter_size;
	CLASS(printbuf, name)();
	int ret = 0;

	c = kvmalloc(sizeof(struct bch_fs), GFP_KERNEL|__GFP_ZERO);
	if (!c) {
		c = ERR_PTR(-BCH_ERR_ENOMEM_fs_alloc);
		goto out;
	}

	c->stdio = (void *)(unsigned long) opts->stdio;

	__module_get(THIS_MODULE);

	closure_init(&c->cl, NULL);

	c->kobj.kset = bcachefs_kset;
	kobject_init(&c->kobj, &bch2_fs_ktype);
	kobject_init(&c->internal, &bch2_fs_internal_ktype);
	kobject_init(&c->opts_dir, &bch2_fs_opts_dir_ktype);
	kobject_init(&c->time_stats, &bch2_fs_time_stats_ktype);
	kobject_init(&c->counters_kobj, &bch2_fs_counters_ktype);

	c->minor		= -1;
	c->disk_sb.fs_sb	= true;

	init_rwsem(&c->state_lock);
	mutex_init(&c->sb_lock);
	mutex_init(&c->replicas_gc_lock);
	mutex_init(&c->btree_root_lock);
	INIT_WORK(&c->read_only_work, bch2_fs_read_only_work);

	refcount_set(&c->ro_ref, 1);
	init_waitqueue_head(&c->ro_ref_wait);

	for (i = 0; i < BCH_TIME_STAT_NR; i++)
		bch2_time_stats_init(&c->times[i]);

	bch2_fs_allocator_background_init(c);
	bch2_fs_allocator_foreground_init(c);
	bch2_fs_btree_cache_init_early(&c->btree_cache);
	bch2_fs_btree_gc_init_early(c);
	bch2_fs_btree_interior_update_init_early(c);
	bch2_fs_btree_iter_init_early(c);
	bch2_fs_btree_key_cache_init_early(&c->btree_key_cache);
	bch2_fs_btree_write_buffer_init_early(c);
	bch2_fs_copygc_init(c);
	bch2_fs_ec_init_early(c);
	bch2_fs_journal_init_early(&c->journal);
	bch2_fs_journal_keys_init(c);
	bch2_fs_move_init(c);
	bch2_fs_nocow_locking_init_early(c);
	bch2_fs_quota_init(c);
	bch2_fs_recovery_passes_init(c);
	bch2_fs_sb_errors_init_early(c);
	bch2_fs_snapshots_init_early(c);
	bch2_fs_subvolumes_init_early(c);

	INIT_LIST_HEAD(&c->list);

	mutex_init(&c->bio_bounce_pages_lock);
	mutex_init(&c->snapshot_table_lock);
	init_rwsem(&c->snapshot_create_lock);

	spin_lock_init(&c->btree_write_error_lock);

	INIT_LIST_HEAD(&c->journal_iters);

	INIT_LIST_HEAD(&c->fsck_error_msgs);
	mutex_init(&c->fsck_error_msgs_lock);

	seqcount_init(&c->usage_lock);

	sema_init(&c->io_in_flight, 128);

	INIT_LIST_HEAD(&c->vfs_inodes_list);
	mutex_init(&c->vfs_inodes_lock);

	c->journal.flush_write_time	= &c->times[BCH_TIME_journal_flush_write];
	c->journal.noflush_write_time	= &c->times[BCH_TIME_journal_noflush_write];
	c->journal.flush_seq_time	= &c->times[BCH_TIME_journal_flush_seq];

	mutex_init(&c->sectors_available_lock);

	ret = percpu_init_rwsem(&c->mark_lock);
	if (ret)
		goto err;

	scoped_guard(mutex, &c->sb_lock)
		ret = bch2_sb_to_fs(c, sb);

	if (ret)
		goto err;

	/* Compat: */
	if (le16_to_cpu(sb->version) <= bcachefs_metadata_version_inode_v2 &&
	    !BCH_SB_JOURNAL_FLUSH_DELAY(sb))
		SET_BCH_SB_JOURNAL_FLUSH_DELAY(sb, 1000);

	if (le16_to_cpu(sb->version) <= bcachefs_metadata_version_inode_v2 &&
	    !BCH_SB_JOURNAL_RECLAIM_DELAY(sb))
		SET_BCH_SB_JOURNAL_RECLAIM_DELAY(sb, 100);

	c->opts = bch2_opts_default;
	ret = bch2_opts_from_sb(&c->opts, sb);
	if (ret)
		goto err;

	bch2_opts_apply(&c->opts, *opts);

#ifdef __KERNEL__
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) &&
	    c->opts.block_size > PAGE_SIZE) {
		bch_err(c, "cannot mount bs > ps filesystem without CONFIG_TRANSPARENT_HUGEPAGE");
		ret = -EINVAL;
		goto err;
	}
#endif

	c->btree_key_cache_btrees |= 1U << BTREE_ID_alloc;
	if (c->opts.inodes_use_key_cache)
		c->btree_key_cache_btrees |= 1U << BTREE_ID_inodes;
	c->btree_key_cache_btrees |= 1U << BTREE_ID_logged_ops;

	c->block_bits		= ilog2(block_sectors(c));
	c->btree_foreground_merge_threshold = BTREE_FOREGROUND_MERGE_THRESHOLD(c);

	if (bch2_fs_init_fault("fs_alloc")) {
		bch_err(c, "fs_alloc fault injected");
		ret = -EFAULT;
		goto err;
	}

	if (c->sb.multi_device)
		pr_uuid(&name, c->sb.user_uuid.b);
	else
		prt_bdevname(&name, sbs->data[0].bdev);

	ret = name.allocation_failure ? -BCH_ERR_ENOMEM_fs_name_alloc : 0;
	if (ret)
		goto err;

	strscpy(c->name, name.buf, sizeof(c->name));

	iter_size = sizeof(struct sort_iter) +
		(btree_blocks(c) + 1) * 2 *
		sizeof(struct sort_iter_set);

	if (!(c->btree_read_complete_wq = alloc_workqueue("bcachefs_btree_read_complete",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 512)) ||
	    enumerated_ref_init(&c->writes, BCH_WRITE_REF_NR,
				bch2_writes_disabled) ||
	    mempool_init_kmalloc_pool(&c->fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree_bio, 1,
			max(offsetof(struct btree_read_bio, bio),
			    offsetof(struct btree_write_bio, wbio.bio)),
			BIOSET_NEED_BVECS) ||
	    !(c->pcpu = alloc_percpu(struct bch_fs_pcpu)) ||
	    !(c->usage = alloc_percpu(struct bch_fs_usage_base)) ||
	    !(c->online_reserved = alloc_percpu(u64)) ||
	    mempool_init_kvmalloc_pool(&c->btree_bounce_pool, 1,
				       c->opts.btree_node_size)) {
		ret = bch_err_throw(c, ENOMEM_fs_other_alloc);
		goto err;
	}

	ret =
	    bch2_fs_async_obj_init(c) ?:
	    bch2_blacklist_table_initialize(c) ?:
	    bch2_fs_btree_cache_init(c) ?:
	    bch2_fs_btree_iter_init(c) ?:
	    bch2_fs_btree_key_cache_init(&c->btree_key_cache) ?:
	    bch2_fs_buckets_waiting_for_journal_init(c) ?:
	    bch2_io_clock_init(&c->io_clock[READ]) ?:
	    bch2_io_clock_init(&c->io_clock[WRITE]) ?:
	    bch2_fs_compress_init(c) ?:
	    bch2_fs_counters_init(c) ?:
	    bch2_fs_ec_init(c) ?:
	    bch2_fs_encryption_init(c) ?:
	    bch2_fs_fsio_init(c) ?:
	    bch2_fs_fs_io_direct_init(c) ?:
	    bch2_fs_io_read_init(c) ?:
	    bch2_fs_rebalance_init(c) ?:
	    bch2_fs_sb_errors_init(c) ?:
	    bch2_fs_vfs_init(c);
	if (ret)
		goto err;

	/*
	 * just make sure this is always allocated if we might need it - mount
	 * failing due to kthread_create() failing is _very_ annoying
	 */
	if (!(c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)) ||
	    go_rw_in_recovery(c)) {
		/*
		 * start workqueues/kworkers early - kthread creation checks for
		 * pending signals, which is _very_ annoying
		 */
		ret = bch2_fs_init_rw(c);
		if (ret)
			goto err;
	}

#if IS_ENABLED(CONFIG_UNICODE)
	if (!bch2_fs_casefold_enabled(c)) {
		/* Default encoding until we can potentially have more as an option. */
		c->cf_encoding = utf8_load(BCH_FS_DEFAULT_UTF8_ENCODING);
		if (IS_ERR(c->cf_encoding)) {
			printk(KERN_ERR "Cannot load UTF-8 encoding for filesystem. Version: %u.%u.%u",
			       unicode_major(BCH_FS_DEFAULT_UTF8_ENCODING),
			       unicode_minor(BCH_FS_DEFAULT_UTF8_ENCODING),
			       unicode_rev(BCH_FS_DEFAULT_UTF8_ENCODING));
			ret = -EINVAL;
			goto err;
		}
	}
#else
	if (c->sb.features & BIT_ULL(BCH_FEATURE_casefolding)) {
		printk(KERN_ERR "Cannot mount a filesystem with casefolding on a kernel without CONFIG_UNICODE\n");
		ret = -EINVAL;
		goto err;
	}
#endif

	for (unsigned i = 0; i < c->sb.nr_devices; i++) {
		if (!bch2_member_exists(c->disk_sb.sb, i))
			continue;
		ret = bch2_dev_alloc(c, i);
		if (ret)
			goto err;
	}

	bch2_journal_entry_res_resize(&c->journal,
			&c->btree_root_journal_res,
			BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_BTREE_PTR_U64s_MAX));
	bch2_journal_entry_res_resize(&c->journal,
			&c->clock_journal_res,
			(sizeof(struct jset_entry_clock) / sizeof(u64)) * 2);

	scoped_guard(rwsem_write, &c->state_lock)
		darray_for_each(*sbs, sb) {
			CLASS(printbuf, err)();
			ret = bch2_dev_attach_bdev(c, sb, &err);
			if (ret) {
				bch_err(bch2_dev_locked(c, sb->sb->dev_idx), "%s", err.buf);
				goto err;
			}
		}

	ret = bch2_fs_opt_version_init(c);
	if (ret)
		goto err;

	/*
	 * start workqueues/kworkers early - kthread creation checks for pending
	 * signals, which is _very_ annoying
	 */
	if (go_rw_in_recovery(c)) {
		ret = bch2_fs_init_rw(c);
		if (ret)
			goto err;
	}

	scoped_guard(mutex, &bch2_fs_list_lock)
		ret = bch2_fs_online(c);

	if (ret)
		goto err;

	c->recovery_task = current;
out:
	return c;
err:
	bch2_fs_free(c);
	c = ERR_PTR(ret);
	goto out;
}

static bool bch2_fs_may_start(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned flags = 0;

	switch (c->opts.degraded) {
	case BCH_DEGRADED_very:
		flags |= BCH_FORCE_IF_DEGRADED|BCH_FORCE_IF_LOST;
		break;
	case BCH_DEGRADED_yes:
		flags |= BCH_FORCE_IF_DEGRADED;
		break;
	default: {
		guard(mutex)(&c->sb_lock);
		for (unsigned i = 0; i < c->disk_sb.sb->nr_devices; i++) {
			if (!bch2_member_exists(c->disk_sb.sb, i))
				continue;

			ca = bch2_dev_locked(c, i);

			if (!bch2_dev_is_online(ca) &&
			    (ca->mi.state == BCH_MEMBER_STATE_rw ||
			     ca->mi.state == BCH_MEMBER_STATE_ro))
				return false;
		}
		break;
	}
	}

	CLASS(printbuf, err)();
	bool ret = bch2_have_enough_devs(c, c->online_devs, flags, &err, !c->opts.read_only);
	if (!ret)
		bch2_print_str(c, KERN_ERR, err.buf);
	return ret;
}

int bch2_fs_start(struct bch_fs *c)
{
	int ret = 0;

	BUG_ON(test_bit(BCH_FS_started, &c->flags));

	if (!bch2_fs_may_start(c))
		return bch_err_throw(c, insufficient_devices_to_start);

	scoped_guard(rwsem_write, &c->state_lock) {
		scoped_guard(rcu)
			for_each_online_member_rcu(c, ca) {
				if (ca->mi.state == BCH_MEMBER_STATE_rw)
					bch2_dev_allocator_add(c, ca);
			}

		bch2_recalc_capacity(c);
	}

	ret = BCH_SB_INITIALIZED(c->disk_sb.sb)
		? bch2_fs_recovery(c)
		: bch2_fs_initialize(c);
	c->recovery_task = NULL;

	if (ret)
		goto err;

	ret = bch2_opts_hooks_pre_set(c);
	if (ret)
		goto err;

	if (bch2_fs_init_fault("fs_start")) {
		ret = bch_err_throw(c, injected_fs_start);
		goto err;
	}

	set_bit(BCH_FS_started, &c->flags);
	wake_up(&c->ro_ref_wait);

	scoped_guard(rwsem_write, &c->state_lock) {
		if (c->opts.read_only)
			bch2_fs_read_only(c);
		else if (!test_bit(BCH_FS_rw, &c->flags))
			ret = bch2_fs_read_write(c);
	}
err:
	if (ret)
		bch_err_msg(c, ret, "starting filesystem");
	else
		bch_verbose(c, "done starting filesystem");
	return ret;
}

static bool bch2_dev_will_resize_on_mount(struct bch_dev *ca)
{
	return ca->mi.resize_on_mount &&
		ca->mi.nbuckets < div64_u64(get_capacity(ca->disk_sb.bdev->bd_disk),
					    ca->mi.bucket_size);
}

static bool bch2_fs_will_resize_on_mount(struct bch_fs *c)
{
	bool ret = false;
	for_each_online_member(c, ca, BCH_DEV_READ_REF_fs_resize_on_mount)
		ret |= bch2_dev_will_resize_on_mount(ca);
	return ret;
}

int bch2_fs_resize_on_mount(struct bch_fs *c)
{
	for_each_online_member(c, ca, BCH_DEV_READ_REF_fs_resize_on_mount) {
		if (bch2_dev_will_resize_on_mount(ca)) {
			u64 old_nbuckets = ca->mi.nbuckets;
			u64 new_nbuckets = div64_u64(get_capacity(ca->disk_sb.bdev->bd_disk),
						     ca->mi.bucket_size);

			bch_info(ca, "resizing to size %llu", new_nbuckets * ca->mi.bucket_size);
			int ret = bch2_dev_buckets_resize(c, ca, new_nbuckets);
			bch_err_fn(ca, ret);
			if (ret) {
				enumerated_ref_put(&ca->io_ref[READ],
						   BCH_DEV_READ_REF_fs_resize_on_mount);
				return ret;
			}

			scoped_guard(mutex, &c->sb_lock) {
				struct bch_member *m =
					bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
				m->nbuckets = cpu_to_le64(new_nbuckets);
				SET_BCH_MEMBER_RESIZE_ON_MOUNT(m, false);

				c->disk_sb.sb->features[0] &= ~cpu_to_le64(BIT_ULL(BCH_FEATURE_small_image));
				bch2_write_super(c);
			}

			if (ca->mi.freespace_initialized) {
				ret = __bch2_dev_resize_alloc(ca, old_nbuckets, new_nbuckets);
				if (ret) {
					enumerated_ref_put(&ca->io_ref[READ],
							BCH_DEV_READ_REF_fs_resize_on_mount);
					return ret;
				}
			}
		}
	}
	return 0;
}

/* Filesystem open: */

static inline int sb_cmp(struct bch_sb *l, struct bch_sb *r)
{
	return  cmp_int(le64_to_cpu(l->seq), le64_to_cpu(r->seq)) ?:
		cmp_int(le64_to_cpu(l->write_time), le64_to_cpu(r->write_time));
}

struct bch_fs *bch2_fs_open(darray_const_str *devices,
			    struct bch_opts *opts)
{
	bch_sb_handles sbs = {};
	struct bch_fs *c = NULL;
	struct bch_sb_handle *best = NULL;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENODEV);

	if (!devices->nr) {
		ret = -EINVAL;
		goto err;
	}

	ret = darray_make_room(&sbs, devices->nr);
	if (ret)
		goto err;

	darray_for_each(*devices, i) {
		struct bch_sb_handle sb = { NULL };

		ret = bch2_read_super(*i, opts, &sb);
		if (ret)
			goto err;

		BUG_ON(darray_push(&sbs, sb));
	}

	darray_for_each(sbs, sb)
		if (!best || sb_cmp(sb->sb, best->sb) > 0)
			best = sb;

	darray_for_each_reverse(sbs, sb) {
		ret = bch2_dev_in_fs(best, sb, opts);

		if (ret == -BCH_ERR_device_has_been_removed ||
		    ret == -BCH_ERR_device_splitbrain) {
			bch2_free_super(sb);
			darray_remove_item(&sbs, sb);
			best -= best > sb;
			ret = 0;
			continue;
		}

		if (ret)
			goto err_print;
	}

	c = bch2_fs_alloc(best->sb, opts, &sbs);
	ret = PTR_ERR_OR_ZERO(c);
	if (ret)
		goto err;

	if (!c->opts.nostart) {
		ret = bch2_fs_start(c);
		if (ret)
			goto err;
	}
out:
	darray_for_each(sbs, sb)
		bch2_free_super(sb);
	darray_exit(&sbs);
	module_put(THIS_MODULE);
	return c;
err_print:
	pr_err("bch_fs_open err opening %s: %s",
	       devices->data[0], bch2_err_str(ret));
err:
	if (!IS_ERR_OR_NULL(c))
		bch2_fs_stop(c);
	c = ERR_PTR(ret);
	goto out;
}

/* Global interfaces/init */

static void bcachefs_exit(void)
{
	bch2_debug_exit();
	bch2_vfs_exit();
	bch2_chardev_exit();
	bch2_btree_key_cache_exit();
	if (bcachefs_kset)
		kset_unregister(bcachefs_kset);
}

static int __init bcachefs_init(void)
{
	bch2_bkey_pack_test();

	if (!(bcachefs_kset = kset_create_and_add("bcachefs", NULL, fs_kobj)) ||
	    bch2_btree_key_cache_init() ||
	    bch2_chardev_init() ||
	    bch2_vfs_init() ||
	    bch2_debug_init())
		goto err;

	return 0;
err:
	bcachefs_exit();
	return -ENOMEM;
}

#define BCH_DEBUG_PARAM(name, description) DEFINE_STATIC_KEY_FALSE(bch2_##name);
BCH_DEBUG_PARAMS_ALL()
#undef BCH_DEBUG_PARAM

static int bch2_param_set_static_key_t(const char *val, const struct kernel_param *kp)
{
	/* Match bool exactly, by re-using it. */
	struct static_key *key = kp->arg;
	struct kernel_param boolkp = *kp;
	bool v;
	int ret;

	boolkp.arg = &v;

	ret = param_set_bool(val, &boolkp);
	if (ret)
		return ret;
	if (v)
		static_key_enable(key);
	else
		static_key_disable(key);
	return 0;
}

static int bch2_param_get_static_key_t(char *buffer, const struct kernel_param *kp)
{
	struct static_key *key = kp->arg;
	return sprintf(buffer, "%c\n", static_key_enabled(key) ? 'N' : 'Y');
}

/* this is unused in userspace - silence the warning */
__maybe_unused
static const struct kernel_param_ops bch2_param_ops_static_key_t = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = bch2_param_set_static_key_t,
	.get = bch2_param_get_static_key_t,
};

#define BCH_DEBUG_PARAM(name, description)				\
	module_param_cb(name, &bch2_param_ops_static_key_t, &bch2_##name.key, 0644);\
	__MODULE_PARM_TYPE(name, "static_key_t");			\
	MODULE_PARM_DESC(name, description);
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

__maybe_unused
static unsigned bch2_metadata_version = bcachefs_metadata_version_current;
module_param_named(version, bch2_metadata_version, uint, 0444);

module_exit(bcachefs_exit);
module_init(bcachefs_init);
