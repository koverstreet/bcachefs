// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/check.h"
#include "alloc/replicas.h"

#include "btree/interior.h"

#include "data/ec.h"
#include "data/migrate.h"
#include "data/reconcile.h"

#include "debug/sysfs.h"

#include "journal/init.h"
#include "journal/reclaim.h"

#include "init/dev.h"
#include "init/fs.h"

#include "sb/members.h"

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
}

static void __bch2_dev_read_write(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	BUG_ON(ca->mi.state != BCH_MEMBER_STATE_rw);

	bch2_dev_allocator_add(c, ca);
	bch2_recalc_capacity(c);

	if (enumerated_ref_is_zero(&ca->io_ref[WRITE]))
		enumerated_ref_start(&ca->io_ref[WRITE]);

	bch2_dev_do_discards(ca);
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

	cancel_work_sync(&ca->io_error_work);

	bch2_dev_unlink(ca);

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	bch2_bucket_bitmap_free(&ca->bucket_backpointer_mismatch);
	bch2_bucket_bitmap_free(&ca->bucket_backpointer_empty);

	bch2_free_super(&ca->disk_sb);
	bch2_dev_allocator_background_exit(ca);
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

	bch2_dev_allocator_background_init(ca);

	if (enumerated_ref_init(&ca->io_ref[READ],  BCH_DEV_READ_REF_NR,  NULL) ||
	    enumerated_ref_init(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_NR, NULL) ||
	    !(ca->sb_read_scratch = kmalloc(BCH_SB_READ_SCRATCH_BUF_SIZE, GFP_KERNEL)) ||
	    bch2_dev_buckets_alloc(c, ca) ||
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

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		strtomem_pad(m->device_name, name.buf, '\0');

		if (model.nr)
			strtomem_pad(m->device_model, model.data, '\0');
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
	int ret = 0;

	if (ca->mi.state == new_state)
		return 0;

	if (!bch2_dev_state_allowed(c, ca, new_state, flags, err))
		return bch_err_throw(c, device_state_not_allowed);

	if (new_state != BCH_MEMBER_STATE_rw)
		__bch2_dev_read_only(c, ca);

	bch_notice_dev(ca, "%s", bch2_member_states[new_state]);

	bool do_reconcile_scan =
		new_state == BCH_MEMBER_STATE_rw ||
		new_state == BCH_MEMBER_STATE_evacuating;

	struct reconcile_scan s = new_state == BCH_MEMBER_STATE_rw
		? (struct reconcile_scan) { .type = RECONCILE_SCAN_pending }
		: (struct reconcile_scan) { .type = RECONCILE_SCAN_device, .dev = ca->dev_idx };

	if (do_reconcile_scan)
		try(bch2_set_reconcile_needs_scan(c, s, false));

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
		SET_BCH_MEMBER_STATE(m, new_state);
		bch2_write_super(c);
	}

	if (new_state == BCH_MEMBER_STATE_rw)
		__bch2_dev_read_write(c, ca);

	if (do_reconcile_scan)
		try(bch2_set_reconcile_needs_scan(c, s, true));

	return ret;
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
		? bch2_dev_data_drop_by_backpointers(c, ca->dev_idx, flags, err)
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
			prt_printf(err, "Remove failed: still has data (%s, %llu buckets)\n",
				   __bch2_data_types[i], usage.buckets[i]);
			ret = -EBUSY;
			goto err;
		}

	ret = bch2_dev_remove_alloc(c, ca);
	if (ret) {
		prt_printf(err, "bch2_dev_remove_alloc() error: %s\n", bch2_err_str(ret));
		goto err;
	}

	/*
	 * We need to flush the entire journal to get rid of keys that reference
	 * the device being removed before removing the superblock entry
	 */
	bch2_journal_flush_all_pins(&c->journal);

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

	__bch2_dev_offline(c, ca);

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
	scoped_guard(mutex, &c->sb_lock) {
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
	struct bch_dev *ca = NULL;
	CLASS(printbuf, label)();
	int ret = 0;

	ret = bch2_read_super(path, &opts, &sb);
	if (ret) {
		prt_printf(err, "error reading superblock: %s\n", bch2_err_str(ret));
		goto err;
	}

	struct bch_member dev_mi = bch2_sb_member_get(sb.sb, sb.sb->dev_idx);

	if (BCH_MEMBER_GROUP(&dev_mi)) {
		bch2_disk_path_to_text_sb(&label, sb.sb, BCH_MEMBER_GROUP(&dev_mi) - 1);
		if (label.allocation_failure) {
			ret = -ENOMEM;
			goto err;
		}
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
			goto err;
		}
	}

	ret = bch2_dev_may_add(sb.sb, c);
	if (ret)
		goto err;

	ca = __bch2_dev_alloc(c, &dev_mi);
	if (!ca) {
		ret = -ENOMEM;
		goto err;
	}

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
		scoped_guard(mutex, &c->sb_lock) {
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

	scoped_guard(mutex, &c->sb_lock) {
		bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx)->last_mount =
			cpu_to_le64(ktime_get_real_seconds());
		bch2_write_super(c);
	}

	return 0;
}

static int bch2_dev_may_offline(struct bch_fs *c, struct bch_dev *ca, int flags, struct printbuf *err)
{
	struct bch_devs_mask new_devs = c->devs_online;
	__clear_bit(ca->dev_idx, new_devs.d);

	struct bch_devs_mask new_rw_devs = c->allocator.rw_devs[0];
	__clear_bit(ca->dev_idx, new_devs.d);

	if (!bch2_can_read_fs_with_devs(c, new_devs, flags, err) ||
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

int bch2_dev_resize(struct bch_fs *c, struct bch_dev *ca, u64 nbuckets, struct printbuf *err)
{
	u64 old_nbuckets;
	int ret = 0;

	guard(rwsem_write)(&c->state_lock);
	old_nbuckets = ca->mi.nbuckets;

	if (nbuckets < ca->mi.nbuckets) {
		prt_printf(err, "Cannot shrink yet\n");
		return -EINVAL;
	}

	bool wakeup_reconcile_pending = nbuckets > ca->mi.nbuckets;
	struct reconcile_scan s = { .type = RECONCILE_SCAN_pending };
	if (wakeup_reconcile_pending)
		try(bch2_set_reconcile_needs_scan(c, s, false));

	if (nbuckets > BCH_MEMBER_NBUCKETS_MAX) {
		prt_printf(err, "New device size too big (%llu greater than max %u)\n",
			   nbuckets, BCH_MEMBER_NBUCKETS_MAX);
		return bch_err_throw(c, device_size_too_big);
	}

	if (bch2_dev_is_online(ca) &&
	    get_capacity(ca->disk_sb.bdev->bd_disk) <
	    ca->mi.bucket_size * nbuckets) {
		prt_printf(err, "New size %llu larger than device size %llu\n",
			   ca->mi.bucket_size * nbuckets,
			   get_capacity(ca->disk_sb.bdev->bd_disk));
		return bch_err_throw(c, device_size_too_small);
	}

	ret = bch2_dev_buckets_resize(c, ca, nbuckets);
	if (ret) {
		prt_printf(err, "bch2_dev_buckets_resize() error: %s\n", bch2_err_str(ret));
		return ret;
	}

	ret = bch2_trans_mark_dev_sb(c, ca, BTREE_TRIGGER_transactional);
	if (ret) {
		prt_printf(err, "bch2_trans_mark_dev_sb() error: %s\n", bch2_err_str(ret));
		return ret;
	}

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
		m->nbuckets = cpu_to_le64(nbuckets);

		bch2_write_super(c);
	}

	if (ca->mi.freespace_initialized) {
		ret = __bch2_dev_resize_alloc(ca, old_nbuckets, nbuckets);
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

/* Resize on mount */

int __bch2_dev_resize_alloc(struct bch_dev *ca, u64 old_nbuckets, u64 new_nbuckets)
{
	struct bch_fs *c = ca->fs;
	u64 v[3] = { new_nbuckets - old_nbuckets, 0, 0 };

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

		if (dev) {
			__bch2_dev_offline(c, ca);
		} else {
			bch2_journal_flush(&c->journal);
			print = bch2_fs_emergency_read_only(c, &buf);
		}

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
