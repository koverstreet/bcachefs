/*
 * bcache setup/teardown code, and some metadata io - read a superblock and
 * figure out what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "blockdev.h"
#include "alloc.h"
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_io.h"
#include "chardev.h"
#include "checksum.h"
#include "clock.h"
#include "compress.h"
#include "debug.h"
#include "error.h"
#include "fs.h"
#include "fs-gc.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "migrate.h"
#include "movinggc.h"
#include "notify.h"
#include "stats.h"
#include "super.h"
#include "super-io.h"
#include "tier.h"
#include "writeback.h"

#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/sysfs.h>
#include <crypto/hash.h>

#include <trace/events/bcachefs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

static const uuid_le invalid_uuid = {
	.b = {
		0xa0, 0x3e, 0xf8, 0xed, 0x3e, 0xe1, 0xb8, 0x78,
		0xc8, 0x50, 0xfc, 0x5e, 0xcb, 0x16, 0xcd, 0x99
	}
};

static struct kset *bcache_kset;
struct mutex bch_register_lock;
LIST_HEAD(bch_fs_list);

static DECLARE_WAIT_QUEUE_HEAD(bch_read_only_wait);
struct workqueue_struct *bcache_io_wq;
struct crypto_shash *bch_sha256;

static void bch_dev_stop(struct cache *);
static int bch_dev_online(struct cache *);

static int bch_congested_fn(void *data, int bdi_bits)
{
	struct backing_dev_info *bdi;
	struct cache_set *c = data;
	struct cache *ca;
	unsigned i;
	int ret = 0;

	rcu_read_lock();
	if (bdi_bits & (1 << WB_sync_congested)) {
		/* Reads - check all devices: */
		for_each_cache_rcu(ca, c, i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	} else {
		/* Writes prefer fastest tier: */
		struct bch_tier *tier = READ_ONCE(c->fastest_tier);
		struct cache_group *grp = tier ? &tier->devs : &c->cache_all;

		group_for_each_cache_rcu(ca, grp, i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

/* Cache set RO/RW: */

/*
 * For startup/shutdown of RW stuff, the dependencies are:
 *
 * - foreground writes depend on copygc and tiering (to free up space)
 *
 * - copygc and tiering depend on mark and sweep gc (they actually probably
 *   don't because they either reserve ahead of time or don't block if
 *   allocations fail, but allocations can require mark and sweep gc to run
 *   because of generation number wraparound)
 *
 * - all of the above depends on the allocator threads
 *
 * - allocator depends on the journal (when it rewrites prios and gens)
 */

static void __bch_fs_read_only(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	bch_tiering_stop(c);

	for_each_cache(ca, c, i)
		bch_moving_gc_stop(ca);

	bch_gc_thread_stop(c);

	bch_btree_flush(c);

	for_each_cache(ca, c, i)
		bch_dev_allocator_stop(ca);

	/*
	 * Write a journal entry after flushing the btree, so we don't end up
	 * replaying everything we just flushed:
	 */
	if (test_bit(JOURNAL_STARTED, &c->journal.flags)) {
		int ret;

		bch_journal_flush_pins(&c->journal);
		bch_journal_flush_async(&c->journal, NULL);

		ret = bch_journal_meta(&c->journal);
		BUG_ON(ret && !bch_journal_error(&c->journal));
	}

	cancel_delayed_work_sync(&c->journal.write_work);
	cancel_delayed_work_sync(&c->journal.reclaim_work);
}

static void bch_writes_disabled(struct percpu_ref *writes)
{
	struct cache_set *c = container_of(writes, struct cache_set, writes);

	set_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags);
	wake_up(&bch_read_only_wait);
}

static void bch_fs_read_only_work(struct work_struct *work)
{
	struct cache_set *c =
		container_of(work, struct cache_set, read_only_work);

	percpu_ref_put(&c->writes);

	del_timer(&c->foreground_write_wakeup);
	cancel_delayed_work(&c->pd_controllers_update);

	c->foreground_write_pd.rate.rate = UINT_MAX;
	bch_wake_delayed_writes((unsigned long) c);

	if (!test_bit(BCH_FS_EMERGENCY_RO, &c->flags)) {
		/*
		 * If we're not doing an emergency shutdown, we want to wait on
		 * outstanding writes to complete so they don't see spurious
		 * errors due to shutting down the allocator:
		 */
		wait_event(bch_read_only_wait,
			   test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags));

		__bch_fs_read_only(c);

		if (!bch_journal_error(&c->journal) &&
		    !test_bit(BCH_FS_ERROR, &c->flags)) {
			mutex_lock(&c->sb_lock);
			SET_BCH_SB_CLEAN(c->disk_sb, true);
			bch_write_super(c);
			mutex_unlock(&c->sb_lock);
		}
	} else {
		/*
		 * If we are doing an emergency shutdown outstanding writes may
		 * hang until we shutdown the allocator so we don't want to wait
		 * on outstanding writes before shutting everything down - but
		 * we do need to wait on them before returning and signalling
		 * that going RO is complete:
		 */
		__bch_fs_read_only(c);

		wait_event(bch_read_only_wait,
			   test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags));
	}

	bch_notify_fs_read_only(c);
	trace_fs_read_only_done(c);

	set_bit(BCH_FS_RO_COMPLETE, &c->flags);
	wake_up(&bch_read_only_wait);
}

bool bch_fs_read_only(struct cache_set *c)
{
	if (test_and_set_bit(BCH_FS_RO, &c->flags))
		return false;

	trace_fs_read_only(c);

	percpu_ref_get(&c->writes);

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 *
	 * (This is really blocking new _allocations_, writes to previously
	 * allocated space can still happen until stopping the allocator in
	 * bch_dev_allocator_stop()).
	 */
	percpu_ref_kill(&c->writes);

	queue_work(system_freezable_wq, &c->read_only_work);
	return true;
}

bool bch_fs_emergency_read_only(struct cache_set *c)
{
	bool ret = !test_and_set_bit(BCH_FS_EMERGENCY_RO, &c->flags);

	bch_fs_read_only(c);
	bch_journal_halt(&c->journal);

	wake_up(&bch_read_only_wait);
	return ret;
}

void bch_fs_read_only_sync(struct cache_set *c)
{
	/* so we don't race with bch_fs_read_write() */
	lockdep_assert_held(&bch_register_lock);

	bch_fs_read_only(c);

	wait_event(bch_read_only_wait,
		   test_bit(BCH_FS_RO_COMPLETE, &c->flags) &&
		   test_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags));
}

static const char *__bch_fs_read_write(struct cache_set *c)
{
	struct cache *ca;
	const char *err;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	err = "error starting allocator thread";
	for_each_cache(ca, c, i)
		if (ca->mi.state == BCH_MEMBER_STATE_ACTIVE &&
		    bch_dev_allocator_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}

	err = "error starting btree GC thread";
	if (bch_gc_thread_start(c))
		goto err;

	for_each_cache(ca, c, i) {
		if (ca->mi.state != BCH_MEMBER_STATE_ACTIVE)
			continue;

		err = "error starting moving GC thread";
		if (bch_moving_gc_thread_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}
	}

	err = "error starting tiering thread";
	if (bch_tiering_start(c))
		goto err;

	schedule_delayed_work(&c->pd_controllers_update, 5 * HZ);

	return NULL;
err:
	__bch_fs_read_only(c);
	return err;
}

const char *bch_fs_read_write(struct cache_set *c)
{
	const char *err;

	lockdep_assert_held(&bch_register_lock);

	if (!test_bit(BCH_FS_RO_COMPLETE, &c->flags))
		return NULL;

	err = __bch_fs_read_write(c);
	if (err)
		return err;

	percpu_ref_reinit(&c->writes);

	clear_bit(BCH_FS_WRITE_DISABLE_COMPLETE, &c->flags);
	clear_bit(BCH_FS_EMERGENCY_RO, &c->flags);
	clear_bit(BCH_FS_RO_COMPLETE, &c->flags);
	clear_bit(BCH_FS_RO, &c->flags);
	return NULL;
}

/* Cache set startup/shutdown: */

static void bch_fs_free(struct cache_set *c)
{
	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);
	cancel_work_sync(&c->read_only_work);
	cancel_work_sync(&c->bio_submit_work);
	cancel_work_sync(&c->read_retry_work);

	bch_fs_encryption_free(c);
	bch_btree_cache_free(c);
	bch_journal_free(&c->journal);
	bch_io_clock_exit(&c->io_clock[WRITE]);
	bch_io_clock_exit(&c->io_clock[READ]);
	bch_compress_free(c);
	bch_fs_blockdev_exit(c);
	bdi_destroy(&c->bdi);
	lg_lock_free(&c->bucket_stats_lock);
	free_percpu(c->bucket_stats_percpu);
	mempool_exit(&c->btree_bounce_pool);
	mempool_exit(&c->bio_bounce_pages);
	bioset_exit(&c->bio_write);
	bioset_exit(&c->bio_read_split);
	bioset_exit(&c->bio_read);
	bioset_exit(&c->btree_read_bio);
	mempool_exit(&c->btree_interior_update_pool);
	mempool_exit(&c->btree_reserve_pool);
	mempool_exit(&c->fill_iter);
	percpu_ref_exit(&c->writes);

	if (c->copygc_wq)
		destroy_workqueue(c->copygc_wq);
	if (c->wq)
		destroy_workqueue(c->wq);

	kfree_rcu(rcu_dereference_protected(c->members, 1), rcu); /* shutting down */
	free_pages((unsigned long) c->disk_sb, c->disk_sb_order);
	kfree(c);
	module_put(THIS_MODULE);
}

/*
 * should be __bch_fs_stop4 - block devices are closed, now we can finally
 * free it
 */
void bch_fs_release(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	struct completion *stop_completion = c->stop_completion;

	bch_notify_fs_stopped(c);
	bch_info(c, "stopped");

	bch_fs_free(c);

	if (stop_completion)
		complete(stop_completion);
}

/*
 * All activity on the cache_set should have stopped now - close devices:
 */
static void __bch_fs_stop3(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;
	unsigned i;

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_dev_stop(ca);

	list_del(&c->list);
	mutex_unlock(&bch_register_lock);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

/*
 * Openers (i.e. block devices) should have exited, shutdown all userspace
 * interfaces and wait for &c->cl to hit 0
 */
static void __bch_fs_stop2(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_debug_exit_cache_set(c);
	bch_fs_chardev_exit(c);

	if (c->kobj.state_in_sysfs)
		kobject_del(&c->kobj);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->time_stats);
	kobject_put(&c->opts_dir);
	kobject_put(&c->internal);

	mutex_lock(&bch_register_lock);
	bch_fs_read_only_sync(c);
	mutex_unlock(&bch_register_lock);

	closure_return(cl);
}

/*
 * First phase of the shutdown process that's kicked off by bch_fs_stop(); we
 * haven't waited for anything to stop yet, we're just punting to process
 * context to shut down block devices:
 */
static void __bch_fs_stop1(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_blockdevs_stop(c);

	continue_at(cl, __bch_fs_stop2, system_wq);
}

void bch_fs_stop(struct cache_set *c)
{
	if (!test_and_set_bit(BCH_FS_STOPPING, &c->flags))
		closure_queue(&c->caching);
}

void bch_fs_stop_sync(struct cache_set *c)
{
	DECLARE_COMPLETION_ONSTACK(complete);

	c->stop_completion = &complete;
	bch_fs_stop(c);
	closure_put(&c->cl);

	/* Killable? */
	wait_for_completion(&complete);
}

/* Stop, detaching from backing devices: */
void bch_fs_detach(struct cache_set *c)
{
	if (!test_and_set_bit(BCH_FS_DETACHING, &c->flags))
		bch_fs_stop(c);
}

static unsigned bch_fs_nr_devices(struct cache_set *c)
{
	struct bch_sb_field_members *mi;
	unsigned i, nr = 0;

	mutex_lock(&c->sb_lock);
	mi = bch_sb_get_members(c->disk_sb);

	for (i = 0; i < c->disk_sb->nr_devices; i++)
		if (!bch_is_zero(mi->members[i].uuid.b, sizeof(uuid_le)))
			nr++;

	mutex_unlock(&c->sb_lock);

	return nr;
}

static unsigned bch_fs_nr_online_devices(struct cache_set *c)
{
	unsigned i, nr = 0;

	for (i = 0; i < c->sb.nr_devices; i++)
		if (c->cache[i])
			nr++;

	return nr;
}

#define alloc_bucket_pages(gfp, ca)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(ca))))

static struct cache_set *bch_fs_alloc(struct bch_sb *sb, struct bch_opts opts)
{
	struct cache_set *c;
	unsigned iter_size, journal_entry_bytes;

	c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return NULL;

	__module_get(THIS_MODULE);

	c->minor		= -1;

	mutex_init(&c->sb_lock);
	INIT_RADIX_TREE(&c->devices, GFP_KERNEL);
	mutex_init(&c->btree_cache_lock);
	mutex_init(&c->bucket_lock);
	mutex_init(&c->btree_root_lock);
	INIT_WORK(&c->read_only_work, bch_fs_read_only_work);

	init_rwsem(&c->gc_lock);

#define BCH_TIME_STAT(name, frequency_units, duration_units)		\
	spin_lock_init(&c->name##_time.lock);
	BCH_TIME_STATS()
#undef BCH_TIME_STAT

	bch_fs_allocator_init(c);
	bch_fs_tiering_init(c);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);

	INIT_LIST_HEAD(&c->btree_interior_update_list);
	mutex_init(&c->btree_reserve_cache_lock);
	mutex_init(&c->btree_interior_update_lock);

	mutex_init(&c->bio_bounce_pages_lock);
	INIT_WORK(&c->bio_submit_work, bch_bio_submit_work);
	spin_lock_init(&c->bio_submit_lock);
	bio_list_init(&c->read_retry_list);
	spin_lock_init(&c->read_retry_lock);
	INIT_WORK(&c->read_retry_work, bch_read_retry_work);
	mutex_init(&c->zlib_workspace_lock);

	seqcount_init(&c->gc_pos_lock);

	c->prio_clock[READ].hand = 1;
	c->prio_clock[READ].min_prio = 0;
	c->prio_clock[WRITE].hand = 1;
	c->prio_clock[WRITE].min_prio = 0;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 16 << IO_ERROR_SHIFT;
	init_waitqueue_head(&c->writeback_wait);

	c->writeback_pages_max = (256 << 10) / PAGE_SIZE;

	c->copy_gc_enabled = 1;
	c->tiering_enabled = 1;
	c->tiering_percent = 10;

	c->foreground_target_percent = 20;

	c->journal.write_time	= &c->journal_write_time;
	c->journal.delay_time	= &c->journal_delay_time;
	c->journal.blocked_time	= &c->journal_blocked_time;
	c->journal.flush_seq_time = &c->journal_flush_seq_time;

	mutex_init(&c->uevent_lock);

	mutex_lock(&c->sb_lock);

	if (bch_sb_to_cache_set(c, sb)) {
		mutex_unlock(&c->sb_lock);
		goto err;
	}

	mutex_unlock(&c->sb_lock);

	scnprintf(c->name, sizeof(c->name), "%pU", &c->sb.user_uuid);

	bch_opts_apply(&c->opts, bch_sb_opts(sb));
	bch_opts_apply(&c->opts, opts);

	c->opts.nochanges	|= c->opts.noreplay;
	c->opts.read_only	|= c->opts.nochanges;

	c->block_bits		= ilog2(c->sb.block_size);

	if (bch_fs_init_fault("fs_alloc"))
		goto err;

	iter_size = (btree_blocks(c) + 1) * 2 *
		sizeof(struct btree_node_iter_set);

	journal_entry_bytes = 512U << BCH_SB_JOURNAL_ENTRY_SIZE(sb);

	if (!(c->wq = alloc_workqueue("bcache",
				WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_HIGHPRI, 1)) ||
	    !(c->copygc_wq = alloc_workqueue("bcache_copygc",
				WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_HIGHPRI, 1)) ||
	    percpu_ref_init(&c->writes, bch_writes_disabled, 0, GFP_KERNEL) ||
	    mempool_init_kmalloc_pool(&c->btree_reserve_pool, 1,
				      sizeof(struct btree_reserve)) ||
	    mempool_init_kmalloc_pool(&c->btree_interior_update_pool, 1,
				      sizeof(struct btree_interior_update)) ||
	    mempool_init_kmalloc_pool(&c->fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree_read_bio, 1, 0) ||
	    bioset_init(&c->bio_read, 1, offsetof(struct bch_read_bio, bio)) ||
	    bioset_init(&c->bio_read_split, 1, offsetof(struct bch_read_bio, bio)) ||
	    bioset_init(&c->bio_write, 1, offsetof(struct bch_write_bio, bio)) ||
	    mempool_init_page_pool(&c->bio_bounce_pages,
				   max_t(unsigned,
					 c->sb.btree_node_size,
					 BCH_ENCODED_EXTENT_MAX) /
				   PAGE_SECTORS, 0) ||
	    !(c->bucket_stats_percpu = alloc_percpu(struct bucket_stats_cache_set)) ||
	    lg_lock_init(&c->bucket_stats_lock) ||
	    mempool_init_page_pool(&c->btree_bounce_pool, 1,
				   ilog2(btree_pages(c))) ||
	    bdi_setup_and_register(&c->bdi, "bcache") ||
	    bch_fs_blockdev_init(c) ||
	    bch_io_clock_init(&c->io_clock[READ]) ||
	    bch_io_clock_init(&c->io_clock[WRITE]) ||
	    bch_journal_alloc(&c->journal, journal_entry_bytes) ||
	    bch_btree_cache_alloc(c) ||
	    bch_fs_encryption_init(c) ||
	    bch_compress_init(c) ||
	    bch_check_set_has_compressed_data(c, c->opts.compression))
		goto err;

	c->bdi.ra_pages		= VM_MAX_READAHEAD * 1024 / PAGE_SIZE;
	c->bdi.congested_fn	= bch_congested_fn;
	c->bdi.congested_data	= c;

	/*
	 * Now that all allocations have succeeded, init various refcounty
	 * things that let us shutdown:
	 */
	closure_init(&c->cl, NULL);

	c->kobj.kset = bcache_kset;
	kobject_init(&c->kobj, &bch_fs_ktype);
	kobject_init(&c->internal, &bch_fs_internal_ktype);
	kobject_init(&c->opts_dir, &bch_fs_opts_dir_ktype);
	kobject_init(&c->time_stats, &bch_fs_time_stats_ktype);

	bch_cache_accounting_init(&c->accounting, &c->cl);

	closure_init(&c->caching, &c->cl);
	set_closure_fn(&c->caching, __bch_fs_stop1, system_wq);

	continue_at_noreturn(&c->cl, __bch_fs_stop3, system_wq);
	return c;
err:
	bch_fs_free(c);
	return NULL;
}

static int bch_fs_online(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;
	int ret;

	lockdep_assert_held(&bch_register_lock);

	if (!list_empty(&c->list))
		return 0;

	list_add(&c->list, &bch_fs_list);

	ret = bch_fs_chardev_init(c);
	if (ret)
		return ret;

	if (kobject_add(&c->kobj, NULL, "%pU", c->sb.user_uuid.b) ||
	    kobject_add(&c->internal, &c->kobj, "internal") ||
	    kobject_add(&c->opts_dir, &c->kobj, "options") ||
	    kobject_add(&c->time_stats, &c->kobj, "time_stats") ||
	    bch_cache_accounting_add_kobjs(&c->accounting, &c->kobj))
		return -1;

	for_each_cache(ca, c, i)
		if (bch_dev_online(ca)) {
			percpu_ref_put(&ca->ref);
			return -1;
		}

	return 0;
}

const char *bch_fs_start(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct bch_sb_field_members *mi;
	struct cache *ca;
	unsigned i, id;
	time64_t now;
	LIST_HEAD(journal);
	struct jset *j;
	int ret = -EINVAL;

	lockdep_assert_held(&bch_register_lock);
	BUG_ON(test_bit(BCH_FS_RUNNING, &c->flags));

	/* We don't want bch_fatal_error() to free underneath us */
	closure_get(&c->caching);

	/*
	 * Make sure that each cache object's mi is up to date before
	 * we start testing it.
	 */
	for_each_cache(ca, c, i)
		bch_sb_from_cache_set(c, ca);

	if (BCH_SB_INITIALIZED(c->disk_sb)) {
		ret = bch_journal_read(c, &journal);
		if (ret)
			goto err;

		pr_debug("btree_journal_read() done");

		j = &list_entry(journal.prev, struct journal_replay, list)->j;

		err = "error reading priorities";
		for_each_cache(ca, c, i) {
			ret = bch_prio_read(ca);
			if (ret) {
				percpu_ref_put(&ca->ref);
				goto err;
			}
		}

		c->prio_clock[READ].hand = le16_to_cpu(j->read_clock);
		c->prio_clock[WRITE].hand = le16_to_cpu(j->write_clock);

		for_each_cache(ca, c, i) {
			bch_recalc_min_prio(ca, READ);
			bch_recalc_min_prio(ca, WRITE);
		}

		for (id = 0; id < BTREE_ID_NR; id++) {
			unsigned level;
			struct bkey_i *k;

			err = "bad btree root";
			k = bch_journal_find_btree_root(c, j, id, &level);
			if (!k && id == BTREE_ID_EXTENTS)
				goto err;
			if (!k) {
				pr_debug("missing btree root: %d", id);
				continue;
			}

			err = "error reading btree root";
			if (bch_btree_root_read(c, id, k, level))
				goto err;
		}

		bch_verbose(c, "starting mark and sweep:");

		err = "error in recovery";
		if (bch_initial_gc(c, &journal))
			goto err;

		if (c->opts.noreplay)
			goto recovery_done;

		bch_verbose(c, "mark and sweep done");

		/*
		 * bch_journal_start() can't happen sooner, or btree_gc_finish()
		 * will give spurious errors about oldest_gen > bucket_gen -
		 * this is a hack but oh well.
		 */
		bch_journal_start(c);

		err = "error starting allocator thread";
		for_each_cache(ca, c, i)
			if (ca->mi.state == BCH_MEMBER_STATE_ACTIVE &&
			    bch_dev_allocator_start(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_verbose(c, "starting journal replay:");

		err = "journal replay failed";
		ret = bch_journal_replay(c, &journal);
		if (ret)
			goto err;

		bch_verbose(c, "journal replay done");

		if (c->opts.norecovery)
			goto recovery_done;

		bch_verbose(c, "starting fsck:");
		err = "error in fsck";
		ret = bch_fsck(c, !c->opts.nofsck);
		if (ret)
			goto err;

		bch_verbose(c, "fsck done");
	} else {
		struct bch_inode_unpacked inode;
		struct bkey_inode_buf packed_inode;
		struct closure cl;

		closure_init_stack(&cl);

		bch_notice(c, "initializing new filesystem");

		bch_initial_gc(c, NULL);

		err = "error starting allocator thread";
		for_each_cache(ca, c, i)
			if (ca->mi.state == BCH_MEMBER_STATE_ACTIVE &&
			    bch_dev_allocator_start(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		err = "unable to allocate journal buckets";
		for_each_cache(ca, c, i)
			if (bch_dev_journal_alloc(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		/*
		 * journal_res_get() will crash if called before this has
		 * set up the journal.pin FIFO and journal.cur pointer:
		 */
		bch_journal_start(c);
		bch_journal_set_replay_done(&c->journal);

		err = "cannot allocate new btree root";
		for (id = 0; id < BTREE_ID_NR; id++)
			if (bch_btree_root_alloc(c, id, &cl)) {
				closure_sync(&cl);
				goto err;
			}

		/* Wait for new btree roots to be written: */
		closure_sync(&cl);

		bch_inode_init(c, &inode, 0, 0,
			       S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0);
		inode.inum = BCACHE_ROOT_INO;

		bch_inode_pack(&packed_inode, &inode);

		err = "error creating root directory";
		if (bch_btree_insert(c, BTREE_ID_INODES,
				     &packed_inode.inode.k_i,
				     NULL, NULL, NULL, 0))
			goto err;

		err = "error writing first journal entry";
		if (bch_journal_meta(&c->journal))
			goto err;
	}
recovery_done:
	if (c->opts.read_only) {
		bch_fs_read_only_sync(c);
	} else {
		err = __bch_fs_read_write(c);
		if (err)
			goto err;
	}

	mutex_lock(&c->sb_lock);
	mi = bch_sb_get_members(c->disk_sb);
	now = ktime_get_seconds();

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		mi->members[ca->dev_idx].last_mount = cpu_to_le64(now);
	rcu_read_unlock();

	SET_BCH_SB_INITIALIZED(c->disk_sb, true);
	SET_BCH_SB_CLEAN(c->disk_sb, false);
	c->disk_sb->version = BCACHE_SB_VERSION_CDEV;

	bch_write_super(c);
	mutex_unlock(&c->sb_lock);

	err = "dynamic fault";
	if (bch_fs_init_fault("fs_start"))
		goto err;

	err = "error creating kobject";
	if (bch_fs_online(c))
		goto err;

	err = "can't bring up blockdev volumes";
	if (bch_blockdev_volumes_start(c))
		goto err;

	bch_debug_init_cache_set(c);
	set_bit(BCH_FS_RUNNING, &c->flags);
	bch_attach_backing_devs(c);

	bch_notify_fs_read_write(c);
	err = NULL;
out:
	bch_journal_entries_free(&journal);
	closure_put(&c->caching);
	return err;
err:
	switch (ret) {
	case BCH_FSCK_ERRORS_NOT_FIXED:
		bch_err(c, "filesystem contains errors: please report this to the developers");
		pr_cont("mount with -o fix_errors to repair");
		err = "fsck error";
		break;
	case BCH_FSCK_REPAIR_UNIMPLEMENTED:
		bch_err(c, "filesystem contains errors: please report this to the developers");
		pr_cont("repair unimplemented: inform the developers so that it can be added");
		err = "fsck error";
		break;
	case BCH_FSCK_REPAIR_IMPOSSIBLE:
		bch_err(c, "filesystem contains errors, but repair impossible");
		err = "fsck error";
		break;
	case BCH_FSCK_UNKNOWN_VERSION:
		err = "unknown metadata version";;
		break;
	case -ENOMEM:
		err = "cannot allocate memory";
		break;
	case -EIO:
		err = "IO error";
		break;
	}

	BUG_ON(!err);
	set_bit(BCH_FS_ERROR, &c->flags);
	goto out;
}

static const char *bch_dev_may_add(struct bch_sb *sb, struct cache_set *c)
{
	struct bch_sb_field_members *sb_mi;

	sb_mi = bch_sb_get_members(sb);
	if (!sb_mi)
		return "Invalid superblock: member info area missing";

	if (le16_to_cpu(sb->block_size) != c->sb.block_size)
		return "mismatched block size";

	if (le16_to_cpu(sb_mi->members[sb->dev_idx].bucket_size) <
	    BCH_SB_BTREE_NODE_SIZE(c->disk_sb))
		return "new cache bucket_size is too small";

	return NULL;
}

static const char *bch_dev_in_fs(struct bch_sb *sb, struct cache_set *c)
{
	struct bch_sb_field_members *mi = bch_sb_get_members(c->disk_sb);
	struct bch_sb_field_members *dev_mi = bch_sb_get_members(sb);
	uuid_le dev_uuid = dev_mi->members[sb->dev_idx].uuid;
	const char *err;

	err = bch_dev_may_add(sb, c);
	if (err)
		return err;

	if (bch_is_zero(&dev_uuid, sizeof(dev_uuid)))
		return "device has been removed";

	/*
	 * When attaching an existing device, the cache set superblock must
	 * already contain member_info with a matching UUID
	 */
	if (sb->dev_idx >= c->disk_sb->nr_devices ||
	    memcmp(&mi->members[sb->dev_idx].uuid,
		   &dev_uuid, sizeof(uuid_le)))
		return "cache sb does not match set";

	return NULL;
}

/* Cache device */

bool bch_dev_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bch_sb_field_members *mi;
	char buf[BDEVNAME_SIZE];

	bdevname(ca->disk_sb.bdev, buf);

	lockdep_assert_held(&bch_register_lock);

	if (ca->mi.state != BCH_MEMBER_STATE_ACTIVE)
		return false;

	if (!bch_dev_may_remove(ca)) {
		bch_err(c, "required member %s going RO, forcing fs RO", buf);
		bch_fs_read_only_sync(c);
	}

	trace_bcache_cache_read_only(ca);

	bch_moving_gc_stop(ca);

	/*
	 * This stops new data writes (e.g. to existing open data
	 * buckets) and then waits for all existing writes to
	 * complete.
	 */
	bch_dev_allocator_stop(ca);

	bch_dev_group_remove(&c->journal.devs, ca);

	/*
	 * Device data write barrier -- no non-meta-data writes should
	 * occur after this point.  However, writes to btree buckets,
	 * journal buckets, and the superblock can still occur.
	 */
	trace_bcache_cache_read_only_done(ca);

	bch_notice(c, "%s read only", bdevname(ca->disk_sb.bdev, buf));
	bch_notify_dev_read_only(ca);

	mutex_lock(&c->sb_lock);
	mi = bch_sb_get_members(c->disk_sb);
	SET_BCH_MEMBER_STATE(&mi->members[ca->dev_idx],
			     BCH_MEMBER_STATE_RO);
	bch_write_super(c);
	mutex_unlock(&c->sb_lock);
	return true;
}

static const char *__bch_dev_read_write(struct cache_set *c, struct cache *ca)
{
	lockdep_assert_held(&bch_register_lock);

	if (ca->mi.state == BCH_MEMBER_STATE_ACTIVE)
		return NULL;

	if (test_bit(BCH_DEV_REMOVING, &ca->flags))
		return "removing";

	trace_bcache_cache_read_write(ca);

	if (bch_dev_allocator_start(ca))
		return "error starting allocator thread";

	if (bch_moving_gc_thread_start(ca))
		return "error starting moving GC thread";

	if (bch_tiering_start(c))
		return "error starting tiering thread";

	bch_notify_dev_read_write(ca);
	trace_bcache_cache_read_write_done(ca);

	return NULL;
}

const char *bch_dev_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bch_sb_field_members *mi;
	const char *err;

	err = __bch_dev_read_write(c, ca);
	if (err)
		return err;

	mutex_lock(&c->sb_lock);
	mi = bch_sb_get_members(c->disk_sb);
	SET_BCH_MEMBER_STATE(&mi->members[ca->dev_idx],
			     BCH_MEMBER_STATE_ACTIVE);
	bch_write_super(c);
	mutex_unlock(&c->sb_lock);

	return NULL;
}

/*
 * bch_dev_stop has already returned, so we no longer hold the register
 * lock at the point this is called.
 */

void bch_dev_release(struct kobject *kobj)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);

	percpu_ref_exit(&ca->ref);
	kfree(ca);
}

static void bch_dev_free_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, free_work);
	struct cache_set *c = ca->set;
	unsigned i;

	cancel_work_sync(&ca->io_error_work);

	if (c && c->kobj.state_in_sysfs) {
		char buf[12];

		sprintf(buf, "cache%u", ca->dev_idx);
		sysfs_remove_link(&c->kobj, buf);
	}

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	bch_free_super(&ca->disk_sb);

	/*
	 * bch_dev_stop can be called in the middle of initialization
	 * of the struct cache object.
	 * As such, not all the sub-structures may be initialized.
	 * However, they were zeroed when the object was allocated.
	 */

	bch_journal_free_cache(ca);
	free_percpu(ca->sectors_written);
	bioset_exit(&ca->replica_set);
	free_percpu(ca->bucket_stats_percpu);
	free_pages((unsigned long) ca->disk_buckets, ilog2(bucket_pages(ca)));
	kfree(ca->prio_buckets);
	kfree(ca->bio_prio);
	kfree(ca->journal.bio);
	vfree(ca->buckets);
	vfree(ca->oldest_gens);
	free_heap(&ca->heap);
	free_fifo(&ca->free_inc);

	for (i = 0; i < RESERVE_NR; i++)
		free_fifo(&ca->free[i]);

	kobject_put(&ca->kobj);

	if (c)
		kobject_put(&c->kobj);
}

static void bch_dev_percpu_ref_release(struct percpu_ref *ref)
{
	struct cache *ca = container_of(ref, struct cache, ref);

	schedule_work(&ca->free_work);
}

static void bch_dev_free_rcu(struct rcu_head *rcu)
{
	struct cache *ca = container_of(rcu, struct cache, free_rcu);

	/*
	 * This decrements the ref count to ca, and once the ref count
	 * is 0 (outstanding bios to the ca also incremented it and
	 * decrement it on completion/error), bch_dev_percpu_ref_release
	 * is called, and that eventually results in bch_dev_free_work
	 * being called, which in turn results in bch_dev_release being
	 * called.
	 *
	 * In particular, these functions won't be called until there are no
	 * bios outstanding (the per-cpu ref counts are all 0), so it
	 * is safe to remove the actual sysfs device at that point,
	 * and that can indicate success to the user.
	 */

	percpu_ref_kill(&ca->ref);
}

static void bch_dev_stop(struct cache *ca)
{
	struct cache_set *c = ca->set;

	lockdep_assert_held(&bch_register_lock);

	if (c) {
		BUG_ON(rcu_access_pointer(c->cache[ca->dev_idx]) != ca);
		rcu_assign_pointer(c->cache[ca->dev_idx], NULL);
	}

	call_rcu(&ca->free_rcu, bch_dev_free_rcu);
}

static void bch_dev_remove_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct bch_sb_field_members *mi;
	struct cache_set *c = ca->set;
	char name[BDEVNAME_SIZE];
	bool force = test_bit(BCH_DEV_FORCE_REMOVE, &ca->flags);
	unsigned dev_idx = ca->dev_idx;

	bdevname(ca->disk_sb.bdev, name);

	/*
	 * Device should already be RO, now migrate data off:
	 *
	 * XXX: locking is sketchy, bch_dev_read_write() has to check
	 * BCH_DEV_REMOVING bit
	 */
	if (!ca->mi.has_data) {
		/* Nothing to do: */
	} else if (!bch_move_data_off_device(ca)) {
		mutex_lock(&c->sb_lock);
		mi = bch_sb_get_members(c->disk_sb);
		SET_BCH_MEMBER_HAS_DATA(&mi->members[ca->dev_idx], false);

		bch_write_super(c);
		mutex_unlock(&c->sb_lock);
	} else if (force) {
		bch_flag_data_bad(ca);

		mutex_lock(&c->sb_lock);
		mi = bch_sb_get_members(c->disk_sb);
		SET_BCH_MEMBER_HAS_DATA(&mi->members[ca->dev_idx], false);

		bch_write_super(c);
		mutex_unlock(&c->sb_lock);
	} else {
		bch_err(c, "Remove of %s failed, unable to migrate data off",
			name);
		clear_bit(BCH_DEV_REMOVING, &ca->flags);
		return;
	}

	/* Now metadata: */

	if (!ca->mi.has_metadata) {
		/* Nothing to do: */
	} else if (!bch_move_meta_data_off_device(ca)) {
		mutex_lock(&c->sb_lock);
		mi = bch_sb_get_members(c->disk_sb);
		SET_BCH_MEMBER_HAS_METADATA(&mi->members[ca->dev_idx], false);

		bch_write_super(c);
		mutex_unlock(&c->sb_lock);
	} else {
		bch_err(c, "Remove of %s failed, unable to migrate metadata off",
			name);
		clear_bit(BCH_DEV_REMOVING, &ca->flags);
		return;
	}

	/*
	 * Ok, really doing the remove:
	 * Drop device's prio pointer before removing it from superblock:
	 */
	bch_notify_dev_removed(ca);

	spin_lock(&c->journal.lock);
	c->journal.prio_buckets[dev_idx] = 0;
	spin_unlock(&c->journal.lock);

	bch_journal_meta(&c->journal);

	/*
	 * Stop device before removing it from the cache set's list of devices -
	 * and get our own ref on cache set since ca is going away:
	 */
	closure_get(&c->cl);

	mutex_lock(&bch_register_lock);
	bch_dev_stop(ca);

	/*
	 * RCU barrier between dropping between c->cache and dropping from
	 * member info:
	 */
	synchronize_rcu();

	lockdep_assert_held(&bch_register_lock);

	/*
	 * Free this device's slot in the bch_member array - all pointers to
	 * this device must be gone:
	 */
	mutex_lock(&c->sb_lock);
	mi = bch_sb_get_members(c->disk_sb);
	memset(&mi->members[dev_idx].uuid, 0, sizeof(mi->members[dev_idx].uuid));

	bch_write_super(c);
	mutex_unlock(&c->sb_lock);

	mutex_unlock(&bch_register_lock);

	closure_put(&c->cl);
}

bool bch_dev_remove(struct cache *ca, bool force)
{
	mutex_lock(&bch_register_lock);

	if (test_bit(BCH_DEV_REMOVING, &ca->flags))
		return false;

	if (!bch_dev_may_remove(ca)) {
		bch_err(ca->set, "Can't remove last RW device");
		bch_notify_dev_remove_failed(ca);
		return false;
	}

	/* First, go RO before we try to migrate data off: */
	bch_dev_read_only(ca);

	if (force)
		set_bit(BCH_DEV_FORCE_REMOVE, &ca->flags);
	set_bit(BCH_DEV_REMOVING, &ca->flags);
	bch_notify_dev_removing(ca);

	mutex_unlock(&bch_register_lock);

	/* Migrate the data and finish removal asynchronously: */

	queue_work(system_long_wq, &ca->remove_work);
	return true;
}

static int bch_dev_online(struct cache *ca)
{
	char buf[12];

	lockdep_assert_held(&bch_register_lock);

	sprintf(buf, "cache%u", ca->dev_idx);

	if (kobject_add(&ca->kobj,
			&part_to_dev(ca->disk_sb.bdev->bd_part)->kobj,
			"bcache") ||
	    sysfs_create_link(&ca->kobj, &ca->set->kobj, "set") ||
	    sysfs_create_link(&ca->set->kobj, &ca->kobj, buf))
		return -1;

	return 0;
}

static const char *bch_dev_alloc(struct bcache_superblock *sb,
				 struct cache_set *c,
				 struct cache **ret)
{
	struct bch_member *member;
	size_t reserve_none, movinggc_reserve, free_inc_reserve, total_reserve;
	size_t heap_size;
	unsigned i;
	const char *err = "cannot allocate memory";
	struct cache *ca;

	if (c->sb.nr_devices == 1)
		bdevname(sb->bdev, c->name);

	if (bch_fs_init_fault("dev_alloc"))
		return err;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return err;

	if (percpu_ref_init(&ca->ref, bch_dev_percpu_ref_release,
			    0, GFP_KERNEL)) {
		kfree(ca);
		return err;
	}

	kobject_init(&ca->kobj, &bch_dev_ktype);

	spin_lock_init(&ca->self.lock);
	ca->self.nr = 1;
	rcu_assign_pointer(ca->self.d[0].dev, ca);
	ca->dev_idx = sb->sb->dev_idx;

	INIT_WORK(&ca->free_work, bch_dev_free_work);
	INIT_WORK(&ca->remove_work, bch_dev_remove_work);
	spin_lock_init(&ca->freelist_lock);
	spin_lock_init(&ca->prio_buckets_lock);
	mutex_init(&ca->heap_lock);
	bch_moving_init_cache(ca);

	ca->disk_sb = *sb;
	ca->disk_sb.bdev->bd_holder = ca;
	memset(sb, 0, sizeof(*sb));

	INIT_WORK(&ca->io_error_work, bch_nonfatal_io_error_work);

	err = "dynamic fault";
	if (bch_fs_init_fault("dev_alloc"))
		goto err;

	member = bch_sb_get_members(ca->disk_sb.sb)->members +
		ca->disk_sb.sb->dev_idx;

	ca->mi = cache_mi_to_cpu_mi(member);
	ca->uuid = member->uuid;
	ca->bucket_bits = ilog2(ca->mi.bucket_size);

	/* XXX: tune these */
	movinggc_reserve = max_t(size_t, 16, ca->mi.nbuckets >> 7);
	reserve_none = max_t(size_t, 4, ca->mi.nbuckets >> 9);
	/*
	 * free_inc must be smaller than the copygc reserve: if it was bigger,
	 * one copygc iteration might not make enough buckets available to fill
	 * up free_inc and allow the allocator to make forward progress
	 */
	free_inc_reserve = movinggc_reserve / 2;
	heap_size = movinggc_reserve * 8;

	if (!init_fifo(&ca->free[RESERVE_PRIO], prio_buckets(ca), GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_BTREE], BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC],
		       movinggc_reserve, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_NONE], reserve_none, GFP_KERNEL) ||
	    !init_fifo(&ca->free_inc,	free_inc_reserve, GFP_KERNEL) ||
	    !init_heap(&ca->heap,	heap_size, GFP_KERNEL) ||
	    !(ca->oldest_gens	= vzalloc(sizeof(u8) *
					  ca->mi.nbuckets)) ||
	    !(ca->buckets	= vzalloc(sizeof(struct bucket) *
					  ca->mi.nbuckets)) ||
	    !(ca->prio_buckets	= kzalloc(sizeof(uint64_t) * prio_buckets(ca) *
					  2, GFP_KERNEL)) ||
	    !(ca->disk_buckets	= alloc_bucket_pages(GFP_KERNEL, ca)) ||
	    !(ca->bucket_stats_percpu = alloc_percpu(struct bucket_stats_cache)) ||
	    !(ca->bio_prio = bio_kmalloc(GFP_NOIO, bucket_pages(ca))) ||
	    bioset_init(&ca->replica_set, 4,
			offsetof(struct bch_write_bio, bio)) ||
	    !(ca->sectors_written = alloc_percpu(*ca->sectors_written)) ||
	    bch_journal_init_cache(ca))
		goto err;

	ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

	total_reserve = ca->free_inc.size;
	for (i = 0; i < RESERVE_NR; i++)
		total_reserve += ca->free[i].size;
	pr_debug("%zu buckets reserved", total_reserve);

	ca->copygc_write_point.group = &ca->self;
	ca->tiering_write_point.group = &ca->self;

	/*
	 * Increase journal write timeout if flushes to this device are
	 * expensive:
	 */
	if (!blk_queue_nonrot(bdev_get_queue(ca->disk_sb.bdev)) &&
	    journal_flushes_device(ca))
		c->journal.write_delay_ms =
			max(c->journal.write_delay_ms, 1000U);

	kobject_get(&c->kobj);
	ca->set = c;

	kobject_get(&ca->kobj);
	rcu_assign_pointer(c->cache[ca->dev_idx], ca);

	mutex_lock(&c->sb_lock);

	if (le64_to_cpu(ca->disk_sb.sb->seq) > le64_to_cpu(c->disk_sb->seq))
		bch_sb_to_cache_set(c, ca->disk_sb.sb);

	mutex_unlock(&c->sb_lock);

	err = "error creating kobject";
	if (c->kobj.state_in_sysfs &&
	    bch_dev_online(ca))
		goto err;

	if (ret)
		*ret = ca;
	else
		kobject_put(&ca->kobj);
	return NULL;
err:
	bch_dev_stop(ca);
	return err;
}

static struct cache_set *bch_fs_lookup(uuid_le uuid)
{
	struct cache_set *c;

	lockdep_assert_held(&bch_register_lock);

	list_for_each_entry(c, &bch_fs_list, list)
		if (!memcmp(&c->disk_sb->uuid, &uuid, sizeof(uuid_le)))
			return c;

	return NULL;
}

int bch_dev_add(struct cache_set *c, const char *path)
{
	struct bcache_superblock sb;
	const char *err;
	struct cache *ca;
	struct bch_sb_field_members *mi, *dev_mi;
	struct bch_member saved_mi;
	unsigned dev_idx, nr_devices, u64s;
	int ret = -EINVAL;

	mutex_lock(&bch_register_lock);

	err = bch_read_super(&sb, c->opts, path);
	if (err)
		goto err_unlock_register;

	err = bch_validate_cache_super(&sb);
	if (err)
		goto err_unlock_register;

	mutex_lock(&c->sb_lock);

	err = bch_dev_may_add(sb.sb, c);
	if (err)
		goto err_unlock;

	/*
	 * Preserve the old cache member information (esp. tier)
	 * before we start bashing the disk stuff.
	 */
	dev_mi = bch_sb_get_members(sb.sb);
	saved_mi = dev_mi->members[sb.sb->dev_idx];
	saved_mi.last_mount = cpu_to_le64(ktime_get_seconds());

	down_read(&c->gc_lock);

	if (dynamic_fault("bcache:add:no_slot"))
		goto no_slot;

	if (test_bit(BCH_FS_GC_FAILURE, &c->flags))
		goto no_slot;

	mi = bch_sb_get_members(c->disk_sb);
	for (dev_idx = 0; dev_idx < BCH_SB_MEMBERS_MAX; dev_idx++)
		if (dev_idx >= c->sb.nr_devices ||
		    bch_is_zero(mi->members[dev_idx].uuid.b,
				 sizeof(uuid_le)))
			goto have_slot;
no_slot:
	up_read(&c->gc_lock);

	err = "no slots available in superblock";
	ret = -ENOSPC;
	goto err_unlock;

have_slot:
	up_read(&c->gc_lock);

	nr_devices = max_t(unsigned, dev_idx + 1, c->sb.nr_devices);
	u64s = (sizeof(struct bch_sb_field_members) +
		sizeof(struct bch_member) * nr_devices) / sizeof(u64);
	err = "no space in superblock for member info";

	mi = bch_fs_sb_resize_members(c, u64s);
	if (!mi)
		goto err_unlock;

	dev_mi = bch_sb_resize_members(&sb, u64s);
	if (!dev_mi)
		goto err_unlock;

	memcpy(dev_mi, mi, u64s * sizeof(u64));
	dev_mi->members[dev_idx] = saved_mi;

	sb.sb->dev_idx		= dev_idx;
	sb.sb->nr_devices	= nr_devices;

	if (bch_fs_mi_update(c, dev_mi->members, nr_devices)) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err_unlock;
	}

	/* commit new member info */
	memcpy(mi, dev_mi, u64s * sizeof(u64));
	c->disk_sb->nr_devices	= nr_devices;
	c->sb.nr_devices	= nr_devices;

	err = bch_dev_alloc(&sb, c, &ca);
	if (err)
		goto err_unlock;

	bch_write_super(c);

	err = "journal alloc failed";
	if (bch_dev_journal_alloc(ca))
		goto err_put;

	bch_notify_dev_added(ca);

	if (ca->mi.state == BCH_MEMBER_STATE_ACTIVE) {
		err = __bch_dev_read_write(c, ca);
		if (err)
			goto err_put;
	}

	kobject_put(&ca->kobj);
	mutex_unlock(&c->sb_lock);
	mutex_unlock(&bch_register_lock);
	return 0;
err_put:
	bch_dev_stop(ca);
err_unlock:
	mutex_unlock(&c->sb_lock);
err_unlock_register:
	mutex_unlock(&bch_register_lock);
	bch_free_super(&sb);

	bch_err(c, "Unable to add device: %s", err);
	return ret ?: -EINVAL;
}

const char *bch_fs_open(char * const *devices, unsigned nr_devices,
			struct bch_opts opts, struct cache_set **ret)
{
	const char *err;
	struct cache_set *c = NULL;
	struct bcache_superblock *sb;
	uuid_le uuid;
	unsigned i;

	memset(&uuid, 0, sizeof(uuid_le));

	if (!nr_devices)
		return "need at least one device";

	if (!try_module_get(THIS_MODULE))
		return "module unloading";

	err = "cannot allocate memory";
	sb = kcalloc(nr_devices, sizeof(*sb), GFP_KERNEL);
	if (!sb)
		goto err;

	/*
	 * bch_read_super() needs to happen under register_lock, so that the
	 * exclusive open is atomic with adding the new cache set to the list of
	 * cache sets:
	 */
	mutex_lock(&bch_register_lock);

	for (i = 0; i < nr_devices; i++) {
		err = bch_read_super(&sb[i], opts, devices[i]);
		if (err)
			goto err_unlock;

		err = "attempting to register backing device";
		if (__SB_IS_BDEV(le64_to_cpu(sb[i].sb->version)))
			goto err_unlock;

		err = bch_validate_cache_super(&sb[i]);
		if (err)
			goto err_unlock;
	}

	err = "cache set already registered";
	if (bch_fs_lookup(sb->sb->uuid))
		goto err_unlock;

	err = "cannot allocate memory";
	c = bch_fs_alloc(sb[0].sb, opts);
	if (!c)
		goto err_unlock;

	for (i = 0; i < nr_devices; i++) {
		err = bch_dev_alloc(&sb[i], c, NULL);
		if (err)
			goto err_unlock;
	}

	err = "insufficient devices";
	if (bch_fs_nr_online_devices(c) != bch_fs_nr_devices(c))
		goto err_unlock;

	if (!c->opts.nostart) {
		err = bch_fs_start(c);
		if (err)
			goto err_unlock;
	}

	err = "error creating kobject";
	if (bch_fs_online(c))
		goto err_unlock;

	if (ret) {
		closure_get(&c->cl);
		*ret = c;
	}

	mutex_unlock(&bch_register_lock);

	err = NULL;
out:
	kfree(sb);
	module_put(THIS_MODULE);
	if (err)
		c = NULL;
	return err;
err_unlock:
	if (c)
		bch_fs_stop(c);
	mutex_unlock(&bch_register_lock);
err:
	for (i = 0; i < nr_devices; i++)
		bch_free_super(&sb[i]);
	goto out;
}

static const char *__bch_fs_open_incremental(struct bcache_superblock *sb,
				  struct bch_opts opts)
{
	char name[BDEVNAME_SIZE];
	const char *err;
	struct cache_set *c;
	bool allocated_cache_set = false;

	err = bch_validate_cache_super(sb);
	if (err)
		return err;

	bdevname(sb->bdev, name);

	c = bch_fs_lookup(sb->sb->uuid);
	if (c) {
		err = bch_dev_in_fs(sb->sb, c);
		if (err)
			return err;
	} else {
		c = bch_fs_alloc(sb->sb, opts);
		if (!c)
			return "cannot allocate memory";

		allocated_cache_set = true;
	}

	err = bch_dev_alloc(sb, c, NULL);
	if (err)
		goto err;

	if (bch_fs_nr_online_devices(c) == bch_fs_nr_devices(c) &&
	    !c->opts.nostart) {
		err = bch_fs_start(c);
		if (err)
			goto err;
	} else {
		err = "error creating kobject";
		if (bch_fs_online(c))
			goto err;
	}

	bch_info(c, "started");
	return NULL;
err:
	if (allocated_cache_set)
		bch_fs_stop(c);
	return err;
}

const char *bch_fs_open_incremental(const char *path)
{
	struct bcache_superblock sb;
	struct bch_opts opts = bch_opts_empty();
	const char *err;

	mutex_lock(&bch_register_lock);

	err = bch_read_super(&sb, opts, path);
	if (err)
		goto err;

	if (__SB_IS_BDEV(le64_to_cpu(sb.sb->version)))
		err = bch_backing_dev_register(&sb);
	else
		err = __bch_fs_open_incremental(&sb, opts);

	bch_free_super(&sb);
err:
	mutex_unlock(&bch_register_lock);
	return err;
}

/* Global interfaces/init */

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

#define kobj_attribute_rw(n, show, store)				\
	static struct kobj_attribute ksysfs_##n =			\
		__ATTR(n, S_IWUSR|S_IRUSR, show, store)

static ssize_t register_bcache(struct kobject *, struct kobj_attribute *,
			       const char *, size_t);

kobj_attribute_write(register,		register_bcache);
kobj_attribute_write(register_quiet,	register_bcache);

static ssize_t register_bcache(struct kobject *k, struct kobj_attribute *attr,
			       const char *buffer, size_t size)
{
	ssize_t ret = -EINVAL;
	const char *err = "cannot allocate memory";
	char *path = NULL;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	if (!(path = kstrndup(skip_spaces(buffer), size, GFP_KERNEL)))
		goto err;

	err = bch_fs_open_incremental(strim(path));
	if (err)
		goto err;

	ret = size;
out:
	kfree(path);
	module_put(THIS_MODULE);
	return ret;
err:
	pr_err("error opening %s: %s", path, err);
	goto out;
}

static int bcache_reboot(struct notifier_block *n, unsigned long code, void *x)
{
	if (code == SYS_DOWN ||
	    code == SYS_HALT ||
	    code == SYS_POWER_OFF) {
		struct cache_set *c;

		mutex_lock(&bch_register_lock);

		if (!list_empty(&bch_fs_list))
			pr_info("Setting all devices read only:");

		list_for_each_entry(c, &bch_fs_list, list)
			bch_fs_read_only(c);

		list_for_each_entry(c, &bch_fs_list, list)
			bch_fs_read_only_sync(c);

		mutex_unlock(&bch_register_lock);
	}

	return NOTIFY_DONE;
}

static struct notifier_block reboot = {
	.notifier_call	= bcache_reboot,
	.priority	= INT_MAX, /* before any real devices */
};

static ssize_t reboot_test(struct kobject *k, struct kobj_attribute *attr,
			   const char *buffer, size_t size)
{
	bcache_reboot(NULL, SYS_DOWN, NULL);
	return size;
}

kobj_attribute_write(reboot,		reboot_test);

static void bcache_exit(void)
{
	bch_debug_exit();
	bch_fs_exit();
	bch_blockdev_exit();
	bch_chardev_exit();
	if (bcache_kset)
		kset_unregister(bcache_kset);
	if (bcache_io_wq)
		destroy_workqueue(bcache_io_wq);
	if (!IS_ERR_OR_NULL(bch_sha256))
		crypto_free_shash(bch_sha256);
	unregister_reboot_notifier(&reboot);
}

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		&ksysfs_reboot.attr,
		NULL
	};

	mutex_init(&bch_register_lock);
	register_reboot_notifier(&reboot);
	bkey_pack_test();

	bch_sha256 = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(bch_sha256))
		goto err;

	if (!(bcache_io_wq = create_freezable_workqueue("bcache_io")) ||
	    !(bcache_kset = kset_create_and_add("bcache", NULL, fs_kobj)) ||
	    sysfs_create_files(&bcache_kset->kobj, files) ||
	    bch_chardev_init() ||
	    bch_blockdev_init() ||
	    bch_fs_init() ||
	    bch_debug_init())
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

#define BCH_DEBUG_PARAM(name, description)			\
	bool bch_##name;					\
	module_param_named(name, bch_##name, bool, 0644);	\
	MODULE_PARM_DESC(name, description);
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

module_exit(bcache_exit);
module_init(bcache_init);
