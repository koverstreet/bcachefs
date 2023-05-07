// SPDX-License-Identifier: GPL-2.0
/*
 * bcachefs setup/teardown code, and some metadata io - read a superblock and
 * figure out what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "bkey_sort.h"
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_key_cache.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "btree_write_buffer.h"
#include "buckets_waiting_for_journal.h"
#include "chardev.h"
#include "checksum.h"
#include "clock.h"
#include "compress.h"
#include "counters.h"
#include "debug.h"
#include "disk_groups.h"
#include "ec.h"
#include "errcode.h"
#include "error.h"
#include "fs.h"
#include "fs-io.h"
#include "fsck.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "journal_seq_blacklist.h"
#include "move.h"
#include "migrate.h"
#include "movinggc.h"
#include "nocow_locking.h"
#include "quota.h"
#include "rebalance.h"
#include "recovery.h"
#include "replicas.h"
#include "subvolume.h"
#include "super.h"
#include "super-io.h"
#include "sysfs.h"
#include "trace.h"

#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/sysfs.h>
#include <crypto/hash.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

#define KTYPE(type)							\
static const struct attribute_group type ## _group = {			\
	.attrs = type ## _files						\
};									\
									\
static const struct attribute_group *type ## _groups[] = {		\
	&type ## _group,						\
	NULL								\
};									\
									\
static const struct kobj_type type ## _ktype = {			\
	.release	= type ## _release,				\
	.sysfs_ops	= &type ## _sysfs_ops,				\
	.default_groups = type ## _groups				\
}

static void bch2_fs_release(struct kobject *);
static void bch2_dev_release(struct kobject *);
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
KTYPE(bch2_dev);

static struct kset *bcachefs_kset;
static LIST_HEAD(bch_fs_list);
static DEFINE_MUTEX(bch_fs_list_lock);

DECLARE_WAIT_QUEUE_HEAD(bch2_read_only_wait);

static void bch2_dev_free(struct bch_dev *);
static int bch2_dev_alloc(struct bch_fs *, unsigned);
static int bch2_dev_sysfs_online(struct bch_fs *, struct bch_dev *);
static void __bch2_dev_read_only(struct bch_fs *, struct bch_dev *);

struct bch_fs *bch2_dev_to_fs(dev_t dev)
{
	struct bch_fs *c;
	struct bch_dev *ca;
	unsigned i;

	mutex_lock(&bch_fs_list_lock);
	rcu_read_lock();

	list_for_each_entry(c, &bch_fs_list, list)
		for_each_member_device_rcu(ca, c, i, NULL)
			if (ca->disk_sb.bdev && ca->disk_sb.bdev->bd_dev == dev) {
				closure_get(&c->cl);
				goto found;
			}
	c = NULL;
found:
	rcu_read_unlock();
	mutex_unlock(&bch_fs_list_lock);

	return c;
}

static struct bch_fs *__bch2_uuid_to_fs(uuid_le uuid)
{
	struct bch_fs *c;

	lockdep_assert_held(&bch_fs_list_lock);

	list_for_each_entry(c, &bch_fs_list, list)
		if (!memcmp(&c->disk_sb.sb->uuid, &uuid, sizeof(uuid_le)))
			return c;

	return NULL;
}

struct bch_fs *bch2_uuid_to_fs(uuid_le uuid)
{
	struct bch_fs *c;

	mutex_lock(&bch_fs_list_lock);
	c = __bch2_uuid_to_fs(uuid);
	if (c)
		closure_get(&c->cl);
	mutex_unlock(&bch_fs_list_lock);

	return c;
}

static void bch2_dev_usage_journal_reserve(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i, nr = 0, u64s =
		((sizeof(struct jset_entry_dev_usage) +
		  sizeof(struct jset_entry_dev_usage_type) * BCH_DATA_NR)) /
		sizeof(u64);

	rcu_read_lock();
	for_each_member_device_rcu(ca, c, i, NULL)
		nr++;
	rcu_read_unlock();

	bch2_journal_entry_res_resize(&c->journal,
			&c->dev_usage_journal_res, u64s * nr);
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
	struct bch_dev *ca;
	unsigned i, clean_passes = 0;
	u64 seq = 0;

	bch2_fs_ec_stop(c);
	bch2_open_buckets_stop(c, NULL, true);
	bch2_rebalance_stop(c);
	bch2_copygc_stop(c);
	bch2_gc_thread_stop(c);
	bch2_fs_ec_flush(c);

	bch_verbose(c, "flushing journal and stopping allocators, journal seq %llu",
		    journal_cur_seq(&c->journal));

	do {
		clean_passes++;

		if (bch2_btree_interior_updates_flush(c) ||
		    bch2_journal_flush_all_pins(&c->journal) ||
		    bch2_btree_flush_all_writes(c) ||
		    seq != atomic64_read(&c->journal.seq)) {
			seq = atomic64_read(&c->journal.seq);
			clean_passes = 0;
		}
	} while (clean_passes < 2);

	bch_verbose(c, "flushing journal and stopping allocators complete, journal seq %llu",
		    journal_cur_seq(&c->journal));

	if (test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags) &&
	    !test_bit(BCH_FS_EMERGENCY_RO, &c->flags))
		set_bit(BCH_FS_CLEAN_SHUTDOWN, &c->flags);
	bch2_fs_journal_stop(&c->journal);

	/*
	 * After stopping journal:
	 */
	for_each_member_device(ca, c, i)
		bch2_dev_allocator_remove(c, ca);
}

#ifndef BCH_WRITE_REF_DEBUG
static void bch2_writes_disabled(struct percpu_ref *writes)
{
	struct bch_fs *c = container_of(writes, struct bch_fs, writes);

	set_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags);
	wake_up(&bch2_read_only_wait);
}
#endif

void bch2_fs_read_only(struct bch_fs *c)
{
	if (!test_bit(BCH_FS_RW, &c->flags)) {
		bch2_journal_reclaim_stop(&c->journal);
		return;
	}

	BUG_ON(test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags));

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 */
	set_bit(BCH_FS_GOING_RO, &c->flags);
#ifndef BCH_WRITE_REF_DEBUG
	percpu_ref_kill(&c->writes);
#else
	for (unsigned i = 0; i < BCH_WRITE_REF_NR; i++)
		bch2_write_ref_put(c, i);
#endif

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
		   test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags) ||
		   test_bit(BCH_FS_EMERGENCY_RO, &c->flags));

	__bch2_fs_read_only(c);

	wait_event(bch2_read_only_wait,
		   test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags));

	clear_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags);
	clear_bit(BCH_FS_GOING_RO, &c->flags);

	if (!bch2_journal_error(&c->journal) &&
	    !test_bit(BCH_FS_ERROR, &c->flags) &&
	    !test_bit(BCH_FS_EMERGENCY_RO, &c->flags) &&
	    test_bit(BCH_FS_STARTED, &c->flags) &&
	    test_bit(BCH_FS_CLEAN_SHUTDOWN, &c->flags) &&
	    !c->opts.norecovery) {
		bch_verbose(c, "marking filesystem clean");
		bch2_fs_mark_clean(c);
	}

	clear_bit(BCH_FS_RW, &c->flags);
}

static void bch2_fs_read_only_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, read_only_work);

	down_write(&c->state_lock);
	bch2_fs_read_only(c);
	up_write(&c->state_lock);
}

static void bch2_fs_read_only_async(struct bch_fs *c)
{
	queue_work(system_long_wq, &c->read_only_work);
}

bool bch2_fs_emergency_read_only(struct bch_fs *c)
{
	bool ret = !test_and_set_bit(BCH_FS_EMERGENCY_RO, &c->flags);

	bch2_journal_halt(&c->journal);
	bch2_fs_read_only_async(c);

	wake_up(&bch2_read_only_wait);
	return ret;
}

static int bch2_fs_read_write_late(struct bch_fs *c)
{
	int ret;

	ret = bch2_rebalance_start(c);
	if (ret) {
		bch_err(c, "error starting rebalance thread");
		return ret;
	}

	return 0;
}

static int __bch2_fs_read_write(struct bch_fs *c, bool early)
{
	struct bch_dev *ca;
	unsigned i;
	int ret;

	if (test_bit(BCH_FS_INITIAL_GC_UNFIXED, &c->flags)) {
		bch_err(c, "cannot go rw, unfixed btree errors");
		return -EROFS;
	}

	if (test_bit(BCH_FS_RW, &c->flags))
		return 0;

	/*
	 * nochanges is used for fsck -n mode - we have to allow going rw
	 * during recovery for that to work:
	 */
	if (c->opts.norecovery ||
	    (c->opts.nochanges &&
	     (!early || c->opts.read_only)))
		return -EROFS;

	bch_info(c, "going read-write");

	ret = bch2_fs_mark_dirty(c);
	if (ret)
		goto err;

	clear_bit(BCH_FS_CLEAN_SHUTDOWN, &c->flags);

	/*
	 * First journal write must be a flush write: after a clean shutdown we
	 * don't read the journal, so the first journal write may end up
	 * overwriting whatever was there previously, and there must always be
	 * at least one non-flush write in the journal or recovery will fail:
	 */
	set_bit(JOURNAL_NEED_FLUSH_WRITE, &c->journal.flags);

	for_each_rw_member(ca, c, i)
		bch2_dev_allocator_add(c, ca);
	bch2_recalc_capacity(c);

	ret = bch2_gc_thread_start(c);
	if (ret) {
		bch_err(c, "error starting gc thread");
		return ret;
	}

	ret = bch2_copygc_start(c);
	if (ret) {
		bch_err(c, "error starting copygc thread");
		return ret;
	}

	if (!early) {
		ret = bch2_fs_read_write_late(c);
		if (ret)
			goto err;
	}

#ifndef BCH_WRITE_REF_DEBUG
	percpu_ref_reinit(&c->writes);
#else
	for (unsigned i = 0; i < BCH_WRITE_REF_NR; i++) {
		BUG_ON(atomic_long_read(&c->writes[i]));
		atomic_long_inc(&c->writes[i]);
	}
#endif
	set_bit(BCH_FS_RW, &c->flags);
	set_bit(BCH_FS_WAS_RW, &c->flags);

	bch2_do_discards(c);
	bch2_do_invalidates(c);
	bch2_do_stripe_deletes(c);
	bch2_do_pending_node_rewrites(c);
	return 0;
err:
	__bch2_fs_read_only(c);
	return ret;
}

int bch2_fs_read_write(struct bch_fs *c)
{
	return __bch2_fs_read_write(c, false);
}

int bch2_fs_read_write_early(struct bch_fs *c)
{
	lockdep_assert_held(&c->state_lock);

	return __bch2_fs_read_write(c, true);
}

/* Filesystem startup/shutdown: */

static void __bch2_fs_free(struct bch_fs *c)
{
	unsigned i;
	int cpu;

	for (i = 0; i < BCH_TIME_STAT_NR; i++)
		bch2_time_stats_exit(&c->times[i]);

	bch2_free_pending_node_rewrites(c);
	bch2_fs_counters_exit(c);
	bch2_fs_snapshots_exit(c);
	bch2_fs_quota_exit(c);
	bch2_fs_fsio_exit(c);
	bch2_fs_ec_exit(c);
	bch2_fs_encryption_exit(c);
	bch2_fs_io_exit(c);
	bch2_fs_buckets_waiting_for_journal_exit(c);
	bch2_fs_btree_interior_update_exit(c);
	bch2_fs_btree_iter_exit(c);
	bch2_fs_btree_key_cache_exit(&c->btree_key_cache);
	bch2_fs_btree_cache_exit(c);
	bch2_fs_replicas_exit(c);
	bch2_fs_journal_exit(&c->journal);
	bch2_io_clock_exit(&c->io_clock[WRITE]);
	bch2_io_clock_exit(&c->io_clock[READ]);
	bch2_fs_compress_exit(c);
	bch2_journal_keys_free(&c->journal_keys);
	bch2_journal_entries_free(c);
	bch2_fs_btree_write_buffer_exit(c);
	percpu_free_rwsem(&c->mark_lock);
	free_percpu(c->online_reserved);

	if (c->btree_paths_bufs)
		for_each_possible_cpu(cpu)
			kfree(per_cpu_ptr(c->btree_paths_bufs, cpu)->path);

	free_percpu(c->btree_paths_bufs);
	free_percpu(c->pcpu);
	mempool_exit(&c->large_bkey_pool);
	mempool_exit(&c->btree_bounce_pool);
	bioset_exit(&c->btree_bio);
	mempool_exit(&c->fill_iter);
#ifndef BCH_WRITE_REF_DEBUG
	percpu_ref_exit(&c->writes);
#endif
	kfree(rcu_dereference_protected(c->disk_groups, 1));
	kfree(c->journal_seq_blacklist_table);
	kfree(c->unused_inode_hints);

	if (c->write_ref_wq)
		destroy_workqueue(c->write_ref_wq);
	if (c->io_complete_wq)
		destroy_workqueue(c->io_complete_wq);
	if (c->copygc_wq)
		destroy_workqueue(c->copygc_wq);
	if (c->btree_io_complete_wq)
		destroy_workqueue(c->btree_io_complete_wq);
	if (c->btree_update_wq)
		destroy_workqueue(c->btree_update_wq);

	bch2_free_super(&c->disk_sb);
	kvpfree(c, sizeof(*c));
	module_put(THIS_MODULE);
}

static void bch2_fs_release(struct kobject *kobj)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	__bch2_fs_free(c);
}

void __bch2_fs_stop(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	bch_verbose(c, "shutting down");

	set_bit(BCH_FS_STOPPING, &c->flags);

	cancel_work_sync(&c->journal_seq_blacklist_gc_work);

	down_write(&c->state_lock);
	bch2_fs_read_only(c);
	up_write(&c->state_lock);

	for_each_member_device(ca, c, i)
		if (ca->kobj.state_in_sysfs &&
		    ca->disk_sb.bdev)
			sysfs_remove_link(bdev_kobj(ca->disk_sb.bdev), "bcachefs");

	if (c->kobj.state_in_sysfs)
		kobject_del(&c->kobj);

	bch2_fs_debug_exit(c);
	bch2_fs_chardev_exit(c);

	kobject_put(&c->counters_kobj);
	kobject_put(&c->time_stats);
	kobject_put(&c->opts_dir);
	kobject_put(&c->internal);

	/* btree prefetch might have kicked off reads in the background: */
	bch2_btree_flush_all_reads(c);

	for_each_member_device(ca, c, i)
		cancel_work_sync(&ca->io_error_work);

	cancel_work_sync(&c->read_only_work);

	for (i = 0; i < c->sb.nr_devices; i++)
		if (c->devs[i])
			bch2_free_super(&c->devs[i]->disk_sb);
}

void bch2_fs_free(struct bch_fs *c)
{
	unsigned i;

	mutex_lock(&bch_fs_list_lock);
	list_del(&c->list);
	mutex_unlock(&bch_fs_list_lock);

	closure_sync(&c->cl);
	closure_debug_destroy(&c->cl);

	for (i = 0; i < c->sb.nr_devices; i++)
		if (c->devs[i])
			bch2_dev_free(rcu_dereference_protected(c->devs[i], 1));

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
	struct bch_dev *ca;
	unsigned i;
	int ret = 0;

	lockdep_assert_held(&bch_fs_list_lock);

	if (__bch2_uuid_to_fs(c->sb.uuid)) {
		bch_err(c, "filesystem UUID already open");
		return -EINVAL;
	}

	ret = bch2_fs_chardev_init(c);
	if (ret) {
		bch_err(c, "error creating character device");
		return ret;
	}

	bch2_fs_debug_init(c);

	ret = kobject_add(&c->kobj, NULL, "%pU", c->sb.user_uuid.b) ?:
	    kobject_add(&c->internal, &c->kobj, "internal") ?:
	    kobject_add(&c->opts_dir, &c->kobj, "options") ?:
	    kobject_add(&c->time_stats, &c->kobj, "time_stats") ?:
	    kobject_add(&c->counters_kobj, &c->kobj, "counters") ?:
	    bch2_opts_create_sysfs_files(&c->opts_dir);
	if (ret) {
		bch_err(c, "error creating sysfs objects");
		return ret;
	}

	down_write(&c->state_lock);

	for_each_member_device(ca, c, i) {
		ret = bch2_dev_sysfs_online(c, ca);
		if (ret) {
			bch_err(c, "error creating sysfs objects");
			percpu_ref_put(&ca->ref);
			goto err;
		}
	}

	BUG_ON(!list_empty(&c->list));
	list_add(&c->list, &bch_fs_list);
err:
	up_write(&c->state_lock);
	return ret;
}

static struct bch_fs *bch2_fs_alloc(struct bch_sb *sb, struct bch_opts opts)
{
	struct bch_sb_field_members *mi;
	struct bch_fs *c;
	struct printbuf name = PRINTBUF;
	unsigned i, iter_size;
	int ret = 0;

	pr_verbose_init(opts, "");

	c = kvpmalloc(sizeof(struct bch_fs), GFP_KERNEL|__GFP_ZERO);
	if (!c) {
		c = ERR_PTR(-BCH_ERR_ENOMEM_fs_alloc);
		goto out;
	}

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

	init_rwsem(&c->gc_lock);
	mutex_init(&c->gc_gens_lock);

	for (i = 0; i < BCH_TIME_STAT_NR; i++)
		bch2_time_stats_init(&c->times[i]);

	bch2_fs_copygc_init(c);
	bch2_fs_btree_key_cache_init_early(&c->btree_key_cache);
	bch2_fs_allocator_background_init(c);
	bch2_fs_allocator_foreground_init(c);
	bch2_fs_rebalance_init(c);
	bch2_fs_quota_init(c);
	bch2_fs_ec_init_early(c);
	bch2_fs_move_init(c);

	INIT_LIST_HEAD(&c->list);

	mutex_init(&c->usage_scratch_lock);

	mutex_init(&c->bio_bounce_pages_lock);
	mutex_init(&c->snapshot_table_lock);

	spin_lock_init(&c->btree_write_error_lock);

	INIT_WORK(&c->journal_seq_blacklist_gc_work,
		  bch2_blacklist_entries_gc);

	INIT_LIST_HEAD(&c->journal_iters);

	INIT_LIST_HEAD(&c->fsck_errors);
	mutex_init(&c->fsck_error_lock);

	seqcount_init(&c->gc_pos_lock);

	seqcount_init(&c->usage_lock);

	sema_init(&c->io_in_flight, 128);

	INIT_LIST_HEAD(&c->vfs_inodes_list);
	mutex_init(&c->vfs_inodes_lock);

	c->copy_gc_enabled		= 1;
	c->rebalance.enabled		= 1;
	c->promote_whole_extents	= true;

	c->journal.flush_write_time	= &c->times[BCH_TIME_journal_flush_write];
	c->journal.noflush_write_time	= &c->times[BCH_TIME_journal_noflush_write];
	c->journal.blocked_time		= &c->times[BCH_TIME_blocked_journal];
	c->journal.flush_seq_time	= &c->times[BCH_TIME_journal_flush_seq];

	bch2_fs_btree_cache_init_early(&c->btree_cache);

	mutex_init(&c->sectors_available_lock);

	ret = percpu_init_rwsem(&c->mark_lock);
	if (ret)
		goto err;

	mutex_lock(&c->sb_lock);
	ret = bch2_sb_to_fs(c, sb);
	mutex_unlock(&c->sb_lock);

	if (ret)
		goto err;

	pr_uuid(&name, c->sb.user_uuid.b);
	strscpy(c->name, name.buf, sizeof(c->name));
	printbuf_exit(&name);

	ret = name.allocation_failure ? -BCH_ERR_ENOMEM_fs_name_alloc : 0;
	if (ret)
		goto err;

	/* Compat: */
	if (sb->version <= bcachefs_metadata_version_inode_v2 &&
	    !BCH_SB_JOURNAL_FLUSH_DELAY(sb))
		SET_BCH_SB_JOURNAL_FLUSH_DELAY(sb, 1000);

	if (sb->version <= bcachefs_metadata_version_inode_v2 &&
	    !BCH_SB_JOURNAL_RECLAIM_DELAY(sb))
		SET_BCH_SB_JOURNAL_RECLAIM_DELAY(sb, 100);

	c->opts = bch2_opts_default;
	ret = bch2_opts_from_sb(&c->opts, sb);
	if (ret)
		goto err;

	bch2_opts_apply(&c->opts, opts);

	c->btree_key_cache_btrees |= 1U << BTREE_ID_alloc;
	if (c->opts.inodes_use_key_cache)
		c->btree_key_cache_btrees |= 1U << BTREE_ID_inodes;

	c->block_bits		= ilog2(block_sectors(c));
	c->btree_foreground_merge_threshold = BTREE_FOREGROUND_MERGE_THRESHOLD(c);

	if (bch2_fs_init_fault("fs_alloc")) {
		bch_err(c, "fs_alloc fault injected");
		ret = -EFAULT;
		goto err;
	}

	iter_size = sizeof(struct sort_iter) +
		(btree_blocks(c) + 1) * 2 *
		sizeof(struct sort_iter_set);

	c->inode_shard_bits = ilog2(roundup_pow_of_two(num_possible_cpus()));

	if (!(c->btree_update_wq = alloc_workqueue("bcachefs",
				WQ_FREEZABLE|WQ_UNBOUND|WQ_MEM_RECLAIM, 512)) ||
	    !(c->btree_io_complete_wq = alloc_workqueue("bcachefs_btree_io",
				WQ_FREEZABLE|WQ_MEM_RECLAIM, 1)) ||
	    !(c->copygc_wq = alloc_workqueue("bcachefs_copygc",
				WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_CPU_INTENSIVE, 1)) ||
	    !(c->io_complete_wq = alloc_workqueue("bcachefs_io",
				WQ_FREEZABLE|WQ_HIGHPRI|WQ_MEM_RECLAIM, 1)) ||
	    !(c->write_ref_wq = alloc_workqueue("bcachefs_write_ref",
				WQ_FREEZABLE, 0)) ||
#ifndef BCH_WRITE_REF_DEBUG
	    percpu_ref_init(&c->writes, bch2_writes_disabled,
			    PERCPU_REF_INIT_DEAD, GFP_KERNEL) ||
#endif
	    mempool_init_kmalloc_pool(&c->fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree_bio, 1,
			max(offsetof(struct btree_read_bio, bio),
			    offsetof(struct btree_write_bio, wbio.bio)),
			BIOSET_NEED_BVECS) ||
	    !(c->pcpu = alloc_percpu(struct bch_fs_pcpu)) ||
	    !(c->online_reserved = alloc_percpu(u64)) ||
	    !(c->btree_paths_bufs = alloc_percpu(struct btree_path_buf)) ||
	    mempool_init_kvpmalloc_pool(&c->btree_bounce_pool, 1,
					btree_bytes(c)) ||
	    mempool_init_kmalloc_pool(&c->large_bkey_pool, 1, 2048) ||
	    !(c->unused_inode_hints = kcalloc(1U << c->inode_shard_bits,
					      sizeof(u64), GFP_KERNEL))) {
		ret = -BCH_ERR_ENOMEM_fs_other_alloc;
		goto err;
	}

	ret = bch2_fs_counters_init(c) ?:
	    bch2_io_clock_init(&c->io_clock[READ]) ?:
	    bch2_io_clock_init(&c->io_clock[WRITE]) ?:
	    bch2_fs_journal_init(&c->journal) ?:
	    bch2_fs_replicas_init(c) ?:
	    bch2_fs_btree_cache_init(c) ?:
	    bch2_fs_btree_key_cache_init(&c->btree_key_cache) ?:
	    bch2_fs_btree_iter_init(c) ?:
	    bch2_fs_btree_interior_update_init(c) ?:
	    bch2_fs_buckets_waiting_for_journal_init(c) ?:
	    bch2_fs_btree_write_buffer_init(c) ?:
	    bch2_fs_subvolumes_init(c) ?:
	    bch2_fs_io_init(c) ?:
	    bch2_fs_nocow_locking_init(c) ?:
	    bch2_fs_encryption_init(c) ?:
	    bch2_fs_compress_init(c) ?:
	    bch2_fs_ec_init(c) ?:
	    bch2_fs_fsio_init(c);
	if (ret)
		goto err;

	mi = bch2_sb_get_members(c->disk_sb.sb);
	for (i = 0; i < c->sb.nr_devices; i++)
		if (bch2_dev_exists(c->disk_sb.sb, mi, i) &&
		    bch2_dev_alloc(c, i)) {
			ret = -EEXIST;
			goto err;
		}

	bch2_journal_entry_res_resize(&c->journal,
			&c->btree_root_journal_res,
			BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_BTREE_PTR_U64s_MAX));
	bch2_dev_usage_journal_reserve(c);
	bch2_journal_entry_res_resize(&c->journal,
			&c->clock_journal_res,
			(sizeof(struct jset_entry_clock) / sizeof(u64)) * 2);

	mutex_lock(&bch_fs_list_lock);
	ret = bch2_fs_online(c);
	mutex_unlock(&bch_fs_list_lock);

	if (ret)
		goto err;
out:
	pr_verbose_init(opts, "ret %i", PTR_ERR_OR_ZERO(c));
	return c;
err:
	bch2_fs_free(c);
	c = ERR_PTR(ret);
	goto out;
}

noinline_for_stack
static void print_mount_opts(struct bch_fs *c)
{
	enum bch_opt_id i;
	struct printbuf p = PRINTBUF;
	bool first = true;

	prt_printf(&p, "mounted version=%s", bch2_metadata_versions[c->sb.version]);

	if (c->opts.read_only) {
		prt_str(&p, " opts=");
		first = false;
		prt_printf(&p, "ro");
	}

	for (i = 0; i < bch2_opts_nr; i++) {
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

	bch_info(c, "%s", p.buf);
	printbuf_exit(&p);
}

int bch2_fs_start(struct bch_fs *c)
{
	struct bch_sb_field_members *mi;
	struct bch_dev *ca;
	time64_t now = ktime_get_real_seconds();
	unsigned i;
	int ret;

	down_write(&c->state_lock);

	BUG_ON(test_bit(BCH_FS_STARTED, &c->flags));

	mutex_lock(&c->sb_lock);

	for_each_online_member(ca, c, i)
		bch2_sb_from_fs(c, ca);

	mi = bch2_sb_get_members(c->disk_sb.sb);
	for_each_online_member(ca, c, i)
		mi->members[ca->dev_idx].last_mount = cpu_to_le64(now);

	mutex_unlock(&c->sb_lock);

	for_each_rw_member(ca, c, i)
		bch2_dev_allocator_add(c, ca);
	bch2_recalc_capacity(c);

	for (i = 0; i < BCH_TRANSACTIONS_NR; i++) {
		mutex_lock(&c->btree_transaction_stats[i].lock);
		bch2_time_stats_init(&c->btree_transaction_stats[i].lock_hold_times);
		mutex_unlock(&c->btree_transaction_stats[i].lock);
	}

	ret = BCH_SB_INITIALIZED(c->disk_sb.sb)
		? bch2_fs_recovery(c)
		: bch2_fs_initialize(c);
	if (ret)
		goto err;

	ret = bch2_opts_check_may_set(c);
	if (ret)
		goto err;

	if (bch2_fs_init_fault("fs_start")) {
		bch_err(c, "fs_start fault injected");
		ret = -EINVAL;
		goto err;
	}

	set_bit(BCH_FS_STARTED, &c->flags);

	if (c->opts.read_only || c->opts.nochanges) {
		bch2_fs_read_only(c);
	} else {
		ret = !test_bit(BCH_FS_RW, &c->flags)
			? bch2_fs_read_write(c)
			: bch2_fs_read_write_late(c);
		if (ret)
			goto err;
	}

	print_mount_opts(c);
	ret = 0;
out:
	up_write(&c->state_lock);
	return ret;
err:
	bch_err(c, "error starting filesystem: %s", bch2_err_str(ret));
	goto out;
}

static int bch2_dev_may_add(struct bch_sb *sb, struct bch_fs *c)
{
	struct bch_sb_field_members *sb_mi;

	sb_mi = bch2_sb_get_members(sb);
	if (!sb_mi)
		return -BCH_ERR_member_info_missing;

	if (le16_to_cpu(sb->block_size) != block_sectors(c))
		return -BCH_ERR_mismatched_block_size;

	if (le16_to_cpu(sb_mi->members[sb->dev_idx].bucket_size) <
	    BCH_SB_BTREE_NODE_SIZE(c->disk_sb.sb))
		return -BCH_ERR_bucket_size_too_small;

	return 0;
}

static int bch2_dev_in_fs(struct bch_sb *fs, struct bch_sb *sb)
{
	struct bch_sb *newest =
		le64_to_cpu(fs->seq) > le64_to_cpu(sb->seq) ? fs : sb;
	struct bch_sb_field_members *mi = bch2_sb_get_members(newest);

	if (uuid_le_cmp(fs->uuid, sb->uuid))
		return -BCH_ERR_device_not_a_member_of_filesystem;

	if (!bch2_dev_exists(newest, mi, sb->dev_idx))
		return -BCH_ERR_device_has_been_removed;

	if (fs->block_size != sb->block_size)
		return -BCH_ERR_mismatched_block_size;

	return 0;
}

/* Device startup/shutdown: */

static void bch2_dev_release(struct kobject *kobj)
{
	struct bch_dev *ca = container_of(kobj, struct bch_dev, kobj);

	kfree(ca);
}

static void bch2_dev_free(struct bch_dev *ca)
{
	cancel_work_sync(&ca->io_error_work);

	if (ca->kobj.state_in_sysfs &&
	    ca->disk_sb.bdev)
		sysfs_remove_link(bdev_kobj(ca->disk_sb.bdev), "bcachefs");

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	bch2_free_super(&ca->disk_sb);
	bch2_dev_journal_exit(ca);

	free_percpu(ca->io_done);
	bioset_exit(&ca->replica_set);
	bch2_dev_buckets_free(ca);
	free_page((unsigned long) ca->sb_read_scratch);

	bch2_time_stats_exit(&ca->io_latency[WRITE]);
	bch2_time_stats_exit(&ca->io_latency[READ]);

	percpu_ref_exit(&ca->io_ref);
	percpu_ref_exit(&ca->ref);
	kobject_put(&ca->kobj);
}

static void __bch2_dev_offline(struct bch_fs *c, struct bch_dev *ca)
{

	lockdep_assert_held(&c->state_lock);

	if (percpu_ref_is_zero(&ca->io_ref))
		return;

	__bch2_dev_read_only(c, ca);

	reinit_completion(&ca->io_ref_completion);
	percpu_ref_kill(&ca->io_ref);
	wait_for_completion(&ca->io_ref_completion);

	if (ca->kobj.state_in_sysfs) {
		sysfs_remove_link(bdev_kobj(ca->disk_sb.bdev), "bcachefs");
		sysfs_remove_link(&ca->kobj, "block");
	}

	bch2_free_super(&ca->disk_sb);
	bch2_dev_journal_exit(ca);
}

static void bch2_dev_ref_complete(struct percpu_ref *ref)
{
	struct bch_dev *ca = container_of(ref, struct bch_dev, ref);

	complete(&ca->ref_completion);
}

static void bch2_dev_io_ref_complete(struct percpu_ref *ref)
{
	struct bch_dev *ca = container_of(ref, struct bch_dev, io_ref);

	complete(&ca->io_ref_completion);
}

static int bch2_dev_sysfs_online(struct bch_fs *c, struct bch_dev *ca)
{
	int ret;

	if (!c->kobj.state_in_sysfs)
		return 0;

	if (!ca->kobj.state_in_sysfs) {
		ret = kobject_add(&ca->kobj, &c->kobj,
				  "dev-%u", ca->dev_idx);
		if (ret)
			return ret;
	}

	if (ca->disk_sb.bdev) {
		struct kobject *block = bdev_kobj(ca->disk_sb.bdev);

		ret = sysfs_create_link(block, &ca->kobj, "bcachefs");
		if (ret)
			return ret;

		ret = sysfs_create_link(&ca->kobj, block, "block");
		if (ret)
			return ret;
	}

	return 0;
}

static struct bch_dev *__bch2_dev_alloc(struct bch_fs *c,
					struct bch_member *member)
{
	struct bch_dev *ca;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return NULL;

	kobject_init(&ca->kobj, &bch2_dev_ktype);
	init_completion(&ca->ref_completion);
	init_completion(&ca->io_ref_completion);

	init_rwsem(&ca->bucket_lock);

	INIT_WORK(&ca->io_error_work, bch2_io_error_work);

	bch2_time_stats_init(&ca->io_latency[READ]);
	bch2_time_stats_init(&ca->io_latency[WRITE]);

	ca->mi = bch2_mi_to_cpu(member);
	ca->uuid = member->uuid;

	ca->nr_btree_reserve = DIV_ROUND_UP(BTREE_NODE_RESERVE,
			     ca->mi.bucket_size / btree_sectors(c));

	if (percpu_ref_init(&ca->ref, bch2_dev_ref_complete,
			    0, GFP_KERNEL) ||
	    percpu_ref_init(&ca->io_ref, bch2_dev_io_ref_complete,
			    PERCPU_REF_INIT_DEAD, GFP_KERNEL) ||
	    !(ca->sb_read_scratch = (void *) __get_free_page(GFP_KERNEL)) ||
	    bch2_dev_buckets_alloc(c, ca) ||
	    bioset_init(&ca->replica_set, 4,
			offsetof(struct bch_write_bio, bio), 0) ||
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
	scnprintf(ca->name, sizeof(ca->name), "dev-%u", dev_idx);

	ca->fs = c;
	rcu_assign_pointer(c->devs[ca->dev_idx], ca);

	if (bch2_dev_sysfs_online(c, ca))
		pr_warn("error creating sysfs objects");
}

static int bch2_dev_alloc(struct bch_fs *c, unsigned dev_idx)
{
	struct bch_member *member =
		bch2_sb_get_members(c->disk_sb.sb)->members + dev_idx;
	struct bch_dev *ca = NULL;
	int ret = 0;

	pr_verbose_init(c->opts, "");

	if (bch2_fs_init_fault("dev_alloc"))
		goto err;

	ca = __bch2_dev_alloc(c, member);
	if (!ca)
		goto err;

	ca->fs = c;

	bch2_dev_attach(c, ca, dev_idx);
out:
	pr_verbose_init(c->opts, "ret %i", ret);
	return ret;
err:
	if (ca)
		bch2_dev_free(ca);
	ret = -BCH_ERR_ENOMEM_dev_alloc;
	goto out;
}

static int __bch2_dev_attach_bdev(struct bch_dev *ca, struct bch_sb_handle *sb)
{
	unsigned ret;

	if (bch2_dev_is_online(ca)) {
		bch_err(ca, "already have device online in slot %u",
			sb->sb->dev_idx);
		return -BCH_ERR_device_already_online;
	}

	if (get_capacity(sb->bdev->bd_disk) <
	    ca->mi.bucket_size * ca->mi.nbuckets) {
		bch_err(ca, "cannot online: device too small");
		return -BCH_ERR_device_size_too_small;
	}

	BUG_ON(!percpu_ref_is_zero(&ca->io_ref));

	ret = bch2_dev_journal_init(ca, sb->sb);
	if (ret)
		return ret;

	/* Commit: */
	ca->disk_sb = *sb;
	if (sb->mode & FMODE_EXCL)
		ca->disk_sb.bdev->bd_holder = ca;
	memset(sb, 0, sizeof(*sb));

	ca->dev = ca->disk_sb.bdev->bd_dev;

	percpu_ref_reinit(&ca->io_ref);

	return 0;
}

static int bch2_dev_attach_bdev(struct bch_fs *c, struct bch_sb_handle *sb)
{
	struct bch_dev *ca;
	int ret;

	lockdep_assert_held(&c->state_lock);

	if (le64_to_cpu(sb->sb->seq) >
	    le64_to_cpu(c->disk_sb.sb->seq))
		bch2_sb_to_fs(c, sb->sb);

	BUG_ON(sb->sb->dev_idx >= c->sb.nr_devices ||
	       !c->devs[sb->sb->dev_idx]);

	ca = bch_dev_locked(c, sb->sb->dev_idx);

	ret = __bch2_dev_attach_bdev(ca, sb);
	if (ret)
		return ret;

	bch2_dev_sysfs_online(c, ca);

	if (c->sb.nr_devices == 1)
		snprintf(c->name, sizeof(c->name), "%pg", ca->disk_sb.bdev);
	snprintf(ca->name, sizeof(ca->name), "%pg", ca->disk_sb.bdev);

	rebalance_wakeup(c);
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
			    enum bch_member_state new_state, int flags)
{
	struct bch_devs_mask new_online_devs;
	struct bch_dev *ca2;
	int i, nr_rw = 0, required;

	lockdep_assert_held(&c->state_lock);

	switch (new_state) {
	case BCH_MEMBER_STATE_rw:
		return true;
	case BCH_MEMBER_STATE_ro:
		if (ca->mi.state != BCH_MEMBER_STATE_rw)
			return true;

		/* do we have enough devices to write to?  */
		for_each_member_device(ca2, c, i)
			if (ca2 != ca)
				nr_rw += ca2->mi.state == BCH_MEMBER_STATE_rw;

		required = max(!(flags & BCH_FORCE_IF_METADATA_DEGRADED)
			       ? c->opts.metadata_replicas
			       : c->opts.metadata_replicas_required,
			       !(flags & BCH_FORCE_IF_DATA_DEGRADED)
			       ? c->opts.data_replicas
			       : c->opts.data_replicas_required);

		return nr_rw >= required;
	case BCH_MEMBER_STATE_failed:
	case BCH_MEMBER_STATE_spare:
		if (ca->mi.state != BCH_MEMBER_STATE_rw &&
		    ca->mi.state != BCH_MEMBER_STATE_ro)
			return true;

		/* do we have enough devices to read from?  */
		new_online_devs = bch2_online_devs(c);
		__clear_bit(ca->dev_idx, new_online_devs.d);

		return bch2_have_enough_devs(c, new_online_devs, flags, false);
	default:
		BUG();
	}
}

static bool bch2_fs_may_start(struct bch_fs *c)
{
	struct bch_sb_field_members *mi;
	struct bch_dev *ca;
	unsigned i, flags = 0;

	if (c->opts.very_degraded)
		flags |= BCH_FORCE_IF_DEGRADED|BCH_FORCE_IF_LOST;

	if (c->opts.degraded)
		flags |= BCH_FORCE_IF_DEGRADED;

	if (!c->opts.degraded &&
	    !c->opts.very_degraded) {
		mutex_lock(&c->sb_lock);
		mi = bch2_sb_get_members(c->disk_sb.sb);

		for (i = 0; i < c->disk_sb.sb->nr_devices; i++) {
			if (!bch2_dev_exists(c->disk_sb.sb, mi, i))
				continue;

			ca = bch_dev_locked(c, i);

			if (!bch2_dev_is_online(ca) &&
			    (ca->mi.state == BCH_MEMBER_STATE_rw ||
			     ca->mi.state == BCH_MEMBER_STATE_ro)) {
				mutex_unlock(&c->sb_lock);
				return false;
			}
		}
		mutex_unlock(&c->sb_lock);
	}

	return bch2_have_enough_devs(c, bch2_online_devs(c), flags, true);
}

static void __bch2_dev_read_only(struct bch_fs *c, struct bch_dev *ca)
{
	/*
	 * The allocator thread itself allocates btree nodes, so stop it first:
	 */
	bch2_dev_allocator_remove(c, ca);
	bch2_dev_journal_stop(&c->journal, ca);
}

static void __bch2_dev_read_write(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	BUG_ON(ca->mi.state != BCH_MEMBER_STATE_rw);

	bch2_dev_allocator_add(c, ca);
	bch2_recalc_capacity(c);
}

int __bch2_dev_set_state(struct bch_fs *c, struct bch_dev *ca,
			 enum bch_member_state new_state, int flags)
{
	struct bch_sb_field_members *mi;
	int ret = 0;

	if (ca->mi.state == new_state)
		return 0;

	if (!bch2_dev_state_allowed(c, ca, new_state, flags))
		return -BCH_ERR_device_state_not_allowed;

	if (new_state != BCH_MEMBER_STATE_rw)
		__bch2_dev_read_only(c, ca);

	bch_notice(ca, "%s", bch2_member_states[new_state]);

	mutex_lock(&c->sb_lock);
	mi = bch2_sb_get_members(c->disk_sb.sb);
	SET_BCH_MEMBER_STATE(&mi->members[ca->dev_idx], new_state);
	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	if (new_state == BCH_MEMBER_STATE_rw)
		__bch2_dev_read_write(c, ca);

	rebalance_wakeup(c);

	return ret;
}

int bch2_dev_set_state(struct bch_fs *c, struct bch_dev *ca,
		       enum bch_member_state new_state, int flags)
{
	int ret;

	down_write(&c->state_lock);
	ret = __bch2_dev_set_state(c, ca, new_state, flags);
	up_write(&c->state_lock);

	return ret;
}

/* Device add/removal: */

static int bch2_dev_remove_alloc(struct bch_fs *c, struct bch_dev *ca)
{
	struct bpos start	= POS(ca->dev_idx, 0);
	struct bpos end		= POS(ca->dev_idx, U64_MAX);
	int ret;

	/*
	 * We clear the LRU and need_discard btrees first so that we don't race
	 * with bch2_do_invalidates() and bch2_do_discards()
	 */
	ret =   bch2_btree_delete_range(c, BTREE_ID_lru, start, end,
					BTREE_TRIGGER_NORUN, NULL) ?:
		bch2_btree_delete_range(c, BTREE_ID_need_discard, start, end,
					BTREE_TRIGGER_NORUN, NULL) ?:
		bch2_btree_delete_range(c, BTREE_ID_freespace, start, end,
					BTREE_TRIGGER_NORUN, NULL) ?:
		bch2_btree_delete_range(c, BTREE_ID_backpointers, start, end,
					BTREE_TRIGGER_NORUN, NULL) ?:
		bch2_btree_delete_range(c, BTREE_ID_alloc, start, end,
					BTREE_TRIGGER_NORUN, NULL) ?:
		bch2_btree_delete_range(c, BTREE_ID_bucket_gens, start, end,
					BTREE_TRIGGER_NORUN, NULL);
	if (ret)
		bch_err(c, "error removing dev alloc info: %s", bch2_err_str(ret));

	return ret;
}

int bch2_dev_remove(struct bch_fs *c, struct bch_dev *ca, int flags)
{
	struct bch_sb_field_members *mi;
	unsigned dev_idx = ca->dev_idx, data;
	int ret;

	down_write(&c->state_lock);

	/*
	 * We consume a reference to ca->ref, regardless of whether we succeed
	 * or fail:
	 */
	percpu_ref_put(&ca->ref);

	if (!bch2_dev_state_allowed(c, ca, BCH_MEMBER_STATE_failed, flags)) {
		bch_err(ca, "Cannot remove without losing data");
		ret = -BCH_ERR_device_state_not_allowed;
		goto err;
	}

	__bch2_dev_read_only(c, ca);

	ret = bch2_dev_data_drop(c, ca->dev_idx, flags);
	if (ret) {
		bch_err(ca, "Remove failed: error dropping data: %s", bch2_err_str(ret));
		goto err;
	}

	ret = bch2_dev_remove_alloc(c, ca);
	if (ret) {
		bch_err(ca, "Remove failed, error deleting alloc info");
		goto err;
	}

	ret = bch2_journal_flush_device_pins(&c->journal, ca->dev_idx);
	if (ret) {
		bch_err(ca, "Remove failed: error flushing journal: %s", bch2_err_str(ret));
		goto err;
	}

	ret = bch2_journal_flush(&c->journal);
	if (ret) {
		bch_err(ca, "Remove failed, journal error");
		goto err;
	}

	ret = bch2_replicas_gc2(c);
	if (ret) {
		bch_err(ca, "Remove failed: error from replicas gc: %s", bch2_err_str(ret));
		goto err;
	}

	data = bch2_dev_has_data(c, ca);
	if (data) {
		struct printbuf data_has = PRINTBUF;

		prt_bitflags(&data_has, bch2_data_types, data);
		bch_err(ca, "Remove failed, still has data (%s)", data_has.buf);
		printbuf_exit(&data_has);
		ret = -EBUSY;
		goto err;
	}

	__bch2_dev_offline(c, ca);

	mutex_lock(&c->sb_lock);
	rcu_assign_pointer(c->devs[ca->dev_idx], NULL);
	mutex_unlock(&c->sb_lock);

	percpu_ref_kill(&ca->ref);
	wait_for_completion(&ca->ref_completion);

	bch2_dev_free(ca);

	/*
	 * Free this device's slot in the bch_member array - all pointers to
	 * this device must be gone:
	 */
	mutex_lock(&c->sb_lock);
	mi = bch2_sb_get_members(c->disk_sb.sb);
	memset(&mi->members[dev_idx].uuid, 0, sizeof(mi->members[dev_idx].uuid));

	bch2_write_super(c);

	mutex_unlock(&c->sb_lock);
	up_write(&c->state_lock);

	bch2_dev_usage_journal_reserve(c);
	return 0;
err:
	if (ca->mi.state == BCH_MEMBER_STATE_rw &&
	    !percpu_ref_is_zero(&ca->io_ref))
		__bch2_dev_read_write(c, ca);
	up_write(&c->state_lock);
	return ret;
}

/* Add new device to running filesystem: */
int bch2_dev_add(struct bch_fs *c, const char *path)
{
	struct bch_opts opts = bch2_opts_empty();
	struct bch_sb_handle sb;
	struct bch_dev *ca = NULL;
	struct bch_sb_field_members *mi;
	struct bch_member dev_mi;
	unsigned dev_idx, nr_devices, u64s;
	struct printbuf errbuf = PRINTBUF;
	struct printbuf label = PRINTBUF;
	int ret;

	ret = bch2_read_super(path, &opts, &sb);
	if (ret) {
		bch_err(c, "device add error: error reading super: %s", bch2_err_str(ret));
		goto err;
	}

	dev_mi = bch2_sb_get_members(sb.sb)->members[sb.sb->dev_idx];

	if (BCH_MEMBER_GROUP(&dev_mi)) {
		bch2_disk_path_to_text(&label, sb.sb, BCH_MEMBER_GROUP(&dev_mi) - 1);
		if (label.allocation_failure) {
			ret = -ENOMEM;
			goto err;
		}
	}

	ret = bch2_dev_may_add(sb.sb, c);
	if (ret) {
		bch_err(c, "device add error: %s", bch2_err_str(ret));
		goto err;
	}

	ca = __bch2_dev_alloc(c, &dev_mi);
	if (!ca) {
		bch2_free_super(&sb);
		ret = -ENOMEM;
		goto err;
	}

	bch2_dev_usage_init(ca);

	ret = __bch2_dev_attach_bdev(ca, &sb);
	if (ret) {
		bch2_dev_free(ca);
		goto err;
	}

	ret = bch2_dev_journal_alloc(ca);
	if (ret) {
		bch_err(c, "device add error: journal alloc failed");
		goto err;
	}

	down_write(&c->state_lock);
	mutex_lock(&c->sb_lock);

	ret = bch2_sb_from_fs(c, ca);
	if (ret) {
		bch_err(c, "device add error: new device superblock too small");
		goto err_unlock;
	}

	mi = bch2_sb_get_members(ca->disk_sb.sb);

	if (!bch2_sb_resize_members(&ca->disk_sb,
				le32_to_cpu(mi->field.u64s) +
				sizeof(dev_mi) / sizeof(u64))) {
		bch_err(c, "device add error: new device superblock too small");
		ret = -BCH_ERR_ENOSPC_sb_members;
		goto err_unlock;
	}

	if (dynamic_fault("bcachefs:add:no_slot"))
		goto no_slot;

	mi = bch2_sb_get_members(c->disk_sb.sb);
	for (dev_idx = 0; dev_idx < BCH_SB_MEMBERS_MAX; dev_idx++)
		if (!bch2_dev_exists(c->disk_sb.sb, mi, dev_idx))
			goto have_slot;
no_slot:
	bch_err(c, "device add error: already have maximum number of devices");
	ret = -BCH_ERR_ENOSPC_sb_members;
	goto err_unlock;

have_slot:
	nr_devices = max_t(unsigned, dev_idx + 1, c->sb.nr_devices);
	u64s = (sizeof(struct bch_sb_field_members) +
		sizeof(struct bch_member) * nr_devices) / sizeof(u64);

	mi = bch2_sb_resize_members(&c->disk_sb, u64s);
	if (!mi) {
		bch_err(c, "device add error: no room in superblock for member info");
		ret = -BCH_ERR_ENOSPC_sb_members;
		goto err_unlock;
	}

	/* success: */

	mi->members[dev_idx] = dev_mi;
	mi->members[dev_idx].last_mount = cpu_to_le64(ktime_get_real_seconds());
	c->disk_sb.sb->nr_devices	= nr_devices;

	ca->disk_sb.sb->dev_idx	= dev_idx;
	bch2_dev_attach(c, ca, dev_idx);

	if (BCH_MEMBER_GROUP(&dev_mi)) {
		ret = __bch2_dev_group_set(c, ca, label.buf);
		if (ret) {
			bch_err(c, "device add error: error setting label");
			goto err_unlock;
		}
	}

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	bch2_dev_usage_journal_reserve(c);

	ret = bch2_trans_mark_dev_sb(c, ca);
	if (ret) {
		bch_err(c, "device add error: error marking new superblock: %s", bch2_err_str(ret));
		goto err_late;
	}

	ret = bch2_fs_freespace_init(c);
	if (ret) {
		bch_err(c, "device add error: error initializing free space: %s", bch2_err_str(ret));
		goto err_late;
	}

	ca->new_fs_bucket_idx = 0;

	if (ca->mi.state == BCH_MEMBER_STATE_rw)
		__bch2_dev_read_write(c, ca);

	up_write(&c->state_lock);
	return 0;

err_unlock:
	mutex_unlock(&c->sb_lock);
	up_write(&c->state_lock);
err:
	if (ca)
		bch2_dev_free(ca);
	bch2_free_super(&sb);
	printbuf_exit(&label);
	printbuf_exit(&errbuf);
	return ret;
err_late:
	up_write(&c->state_lock);
	ca = NULL;
	goto err;
}

/* Hot add existing device to running filesystem: */
int bch2_dev_online(struct bch_fs *c, const char *path)
{
	struct bch_opts opts = bch2_opts_empty();
	struct bch_sb_handle sb = { NULL };
	struct bch_sb_field_members *mi;
	struct bch_dev *ca;
	unsigned dev_idx;
	int ret;

	down_write(&c->state_lock);

	ret = bch2_read_super(path, &opts, &sb);
	if (ret) {
		up_write(&c->state_lock);
		return ret;
	}

	dev_idx = sb.sb->dev_idx;

	ret = bch2_dev_in_fs(c->disk_sb.sb, sb.sb);
	if (ret) {
		bch_err(c, "error bringing %s online: %s", path, bch2_err_str(ret));
		goto err;
	}

	ret = bch2_dev_attach_bdev(c, &sb);
	if (ret)
		goto err;

	ca = bch_dev_locked(c, dev_idx);

	ret = bch2_trans_mark_dev_sb(c, ca);
	if (ret) {
		bch_err(c, "error bringing %s online: error from bch2_trans_mark_dev_sb: %s",
			path, bch2_err_str(ret));
		goto err;
	}

	if (ca->mi.state == BCH_MEMBER_STATE_rw)
		__bch2_dev_read_write(c, ca);

	mutex_lock(&c->sb_lock);
	mi = bch2_sb_get_members(c->disk_sb.sb);

	mi->members[ca->dev_idx].last_mount =
		cpu_to_le64(ktime_get_real_seconds());

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	ret = bch2_fs_freespace_init(c);
	if (ret)
		bch_err(c, "device add error: error initializing free space: %s", bch2_err_str(ret));

	up_write(&c->state_lock);
	return 0;
err:
	up_write(&c->state_lock);
	bch2_free_super(&sb);
	return ret;
}

int bch2_dev_offline(struct bch_fs *c, struct bch_dev *ca, int flags)
{
	down_write(&c->state_lock);

	if (!bch2_dev_is_online(ca)) {
		bch_err(ca, "Already offline");
		up_write(&c->state_lock);
		return 0;
	}

	if (!bch2_dev_state_allowed(c, ca, BCH_MEMBER_STATE_failed, flags)) {
		bch_err(ca, "Cannot offline required disk");
		up_write(&c->state_lock);
		return -BCH_ERR_device_state_not_allowed;
	}

	__bch2_dev_offline(c, ca);

	up_write(&c->state_lock);
	return 0;
}

int bch2_dev_resize(struct bch_fs *c, struct bch_dev *ca, u64 nbuckets)
{
	struct bch_member *mi;
	int ret = 0;

	down_write(&c->state_lock);

	if (nbuckets < ca->mi.nbuckets) {
		bch_err(ca, "Cannot shrink yet");
		ret = -EINVAL;
		goto err;
	}

	if (bch2_dev_is_online(ca) &&
	    get_capacity(ca->disk_sb.bdev->bd_disk) <
	    ca->mi.bucket_size * nbuckets) {
		bch_err(ca, "New size larger than device");
		ret = -BCH_ERR_device_size_too_small;
		goto err;
	}

	ret = bch2_dev_buckets_resize(c, ca, nbuckets);
	if (ret) {
		bch_err(ca, "Resize error: %s", bch2_err_str(ret));
		goto err;
	}

	ret = bch2_trans_mark_dev_sb(c, ca);
	if (ret)
		goto err;

	mutex_lock(&c->sb_lock);
	mi = &bch2_sb_get_members(c->disk_sb.sb)->members[ca->dev_idx];
	mi->nbuckets = cpu_to_le64(nbuckets);

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	bch2_recalc_capacity(c);
err:
	up_write(&c->state_lock);
	return ret;
}

/* return with ref on ca->ref: */
struct bch_dev *bch2_dev_lookup(struct bch_fs *c, const char *name)
{
	struct bch_dev *ca;
	unsigned i;

	rcu_read_lock();
	for_each_member_device_rcu(ca, c, i, NULL)
		if (!strcmp(name, ca->name))
			goto found;
	ca = ERR_PTR(-ENOENT);
found:
	rcu_read_unlock();

	return ca;
}

/* Filesystem open: */

struct bch_fs *bch2_fs_open(char * const *devices, unsigned nr_devices,
			    struct bch_opts opts)
{
	struct bch_sb_handle *sb = NULL;
	struct bch_fs *c = NULL;
	struct bch_sb_field_members *mi;
	unsigned i, best_sb = 0;
	struct printbuf errbuf = PRINTBUF;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENODEV);

	pr_verbose_init(opts, "");

	if (!nr_devices) {
		ret = -EINVAL;
		goto err;
	}

	sb = kcalloc(nr_devices, sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < nr_devices; i++) {
		ret = bch2_read_super(devices[i], &opts, &sb[i]);
		if (ret)
			goto err;

	}

	for (i = 1; i < nr_devices; i++)
		if (le64_to_cpu(sb[i].sb->seq) >
		    le64_to_cpu(sb[best_sb].sb->seq))
			best_sb = i;

	mi = bch2_sb_get_members(sb[best_sb].sb);

	i = 0;
	while (i < nr_devices) {
		if (i != best_sb &&
		    !bch2_dev_exists(sb[best_sb].sb, mi, sb[i].sb->dev_idx)) {
			pr_info("%pg has been removed, skipping", sb[i].bdev);
			bch2_free_super(&sb[i]);
			array_remove_item(sb, nr_devices, i);
			continue;
		}

		ret = bch2_dev_in_fs(sb[best_sb].sb, sb[i].sb);
		if (ret)
			goto err_print;
		i++;
	}

	c = bch2_fs_alloc(sb[best_sb].sb, opts);
	if (IS_ERR(c)) {
		ret = PTR_ERR(c);
		goto err;
	}

	down_write(&c->state_lock);
	for (i = 0; i < nr_devices; i++) {
		ret = bch2_dev_attach_bdev(c, &sb[i]);
		if (ret) {
			up_write(&c->state_lock);
			goto err;
		}
	}
	up_write(&c->state_lock);

	if (!bch2_fs_may_start(c)) {
		ret = -BCH_ERR_insufficient_devices_to_start;
		goto err_print;
	}

	if (!c->opts.nostart) {
		ret = bch2_fs_start(c);
		if (ret)
			goto err;
	}
out:
	kfree(sb);
	printbuf_exit(&errbuf);
	module_put(THIS_MODULE);
	pr_verbose_init(opts, "ret %s (%i)", bch2_err_str(PTR_ERR_OR_ZERO(c)),
			PTR_ERR_OR_ZERO(c));
	return c;
err_print:
	pr_err("bch_fs_open err opening %s: %s",
	       devices[0], bch2_err_str(ret));
err:
	if (!IS_ERR_OR_NULL(c))
		bch2_fs_stop(c);
	if (sb)
		for (i = 0; i < nr_devices; i++)
			bch2_free_super(&sb[i]);
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

#define BCH_DEBUG_PARAM(name, description)			\
	bool bch2_##name;					\
	module_param_named(name, bch2_##name, bool, 0644);	\
	MODULE_PARM_DESC(name, description);
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

unsigned bch2_metadata_version = bcachefs_metadata_version_current;
module_param_named(version, bch2_metadata_version, uint, 0400);

module_exit(bcachefs_exit);
module_init(bcachefs_init);
