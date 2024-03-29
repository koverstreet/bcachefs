// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_CHARDEV

#include "bcachefs.h"
#include "bcachefs_ioctl.h"
#include "buckets.h"
#include "chardev.h"
#include "journal.h"
#include "move.h"
#include "recovery_passes.h"
#include "replicas.h"
#include "super.h"
#include "super-io.h"
#include "thread_with_file.h"

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/major.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* returns with ref on ca->ref */
static struct bch_dev *bch2_device_lookup(struct bch_fs *c, u64 dev,
					  unsigned flags)
{
	struct bch_dev *ca;

	if (flags & BCH_BY_INDEX) {
		if (dev >= c->sb.nr_devices)
			return ERR_PTR(-EINVAL);

		rcu_read_lock();
		ca = rcu_dereference(c->devs[dev]);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca)
			return ERR_PTR(-EINVAL);
	} else {
		char *path;

		path = strndup_user((const char __user *)
				    (unsigned long) dev, PATH_MAX);
		if (IS_ERR(path))
			return ERR_CAST(path);

		ca = bch2_dev_lookup(c, path);
		kfree(path);
	}

	return ca;
}

#if 0
static long bch2_ioctl_assemble(struct bch_ioctl_assemble __user *user_arg)
{
	struct bch_ioctl_assemble arg;
	struct bch_fs *c;
	u64 *user_devs = NULL;
	char **devs = NULL;
	unsigned i;
	int ret = -EFAULT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	user_devs = kmalloc_array(arg.nr_devs, sizeof(u64), GFP_KERNEL);
	if (!user_devs)
		return -ENOMEM;

	devs = kcalloc(arg.nr_devs, sizeof(char *), GFP_KERNEL);

	if (copy_from_user(user_devs, user_arg->devs,
			   sizeof(u64) * arg.nr_devs))
		goto err;

	for (i = 0; i < arg.nr_devs; i++) {
		devs[i] = strndup_user((const char __user *)(unsigned long)
				       user_devs[i],
				       PATH_MAX);
		ret= PTR_ERR_OR_ZERO(devs[i]);
		if (ret)
			goto err;
	}

	c = bch2_fs_open(devs, arg.nr_devs, bch2_opts_empty());
	ret = PTR_ERR_OR_ZERO(c);
	if (!ret)
		closure_put(&c->cl);
err:
	if (devs)
		for (i = 0; i < arg.nr_devs; i++)
			kfree(devs[i]);
	kfree(devs);
	return ret;
}

static long bch2_ioctl_incremental(struct bch_ioctl_incremental __user *user_arg)
{
	struct bch_ioctl_incremental arg;
	const char *err;
	char *path;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	ret = PTR_ERR_OR_ZERO(path);
	if (ret)
		return ret;

	err = bch2_fs_open_incremental(path);
	kfree(path);

	if (err) {
		pr_err("Could not register bcachefs devices: %s", err);
		return -EINVAL;
	}

	return 0;
}
#endif

struct fsck_thread {
	struct thread_with_stdio thr;
	struct bch_fs		*c;
	char			**devs;
	size_t			nr_devs;
	struct bch_opts		opts;
};

static void bch2_fsck_thread_exit(struct thread_with_stdio *_thr)
{
	struct fsck_thread *thr = container_of(_thr, struct fsck_thread, thr);
	if (thr->devs)
		for (size_t i = 0; i < thr->nr_devs; i++)
			kfree(thr->devs[i]);
	kfree(thr->devs);
	kfree(thr);
}

static int bch2_fsck_offline_thread_fn(struct thread_with_stdio *stdio)
{
	struct fsck_thread *thr = container_of(stdio, struct fsck_thread, thr);
	struct bch_fs *c = bch2_fs_open(thr->devs, thr->nr_devs, thr->opts);

	if (IS_ERR(c))
		return PTR_ERR(c);

	int ret = 0;
	if (test_bit(BCH_FS_errors_fixed, &c->flags))
		ret |= 1;
	if (test_bit(BCH_FS_error, &c->flags))
		ret |= 4;

	bch2_fs_stop(c);

	if (ret & 1)
		bch2_stdio_redirect_printf(&stdio->stdio, false, "%s: errors fixed\n", c->name);
	if (ret & 4)
		bch2_stdio_redirect_printf(&stdio->stdio, false, "%s: still has errors\n", c->name);

	return ret;
}

static const struct thread_with_stdio_ops bch2_offline_fsck_ops = {
	.exit		= bch2_fsck_thread_exit,
	.fn		= bch2_fsck_offline_thread_fn,
};

static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_arg)
{
	struct bch_ioctl_fsck_offline arg;
	struct fsck_thread *thr = NULL;
	u64 *devs = NULL;
	long ret = 0;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!(devs = kcalloc(arg.nr_devs, sizeof(*devs), GFP_KERNEL)) ||
	    !(thr = kzalloc(sizeof(*thr), GFP_KERNEL)) ||
	    !(thr->devs = kcalloc(arg.nr_devs, sizeof(*thr->devs), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	thr->opts = bch2_opts_empty();
	thr->nr_devs = arg.nr_devs;

	if (copy_from_user(devs, &user_arg->devs[0],
			   array_size(sizeof(user_arg->devs[0]), arg.nr_devs))) {
		ret = -EINVAL;
		goto err;
	}

	for (size_t i = 0; i < arg.nr_devs; i++) {
		thr->devs[i] = strndup_user((char __user *)(unsigned long) devs[i], PATH_MAX);
		ret = PTR_ERR_OR_ZERO(thr->devs[i]);
		if (ret)
			goto err;
	}

	if (arg.opts) {
		char *optstr = strndup_user((char __user *)(unsigned long) arg.opts, 1 << 16);

		ret =   PTR_ERR_OR_ZERO(optstr) ?:
			bch2_parse_mount_opts(NULL, &thr->opts, optstr);
		kfree(optstr);

		if (ret)
			goto err;
	}

	opt_set(thr->opts, stdio, (u64)(unsigned long)&thr->thr.stdio);

	ret = bch2_run_thread_with_stdio(&thr->thr, &bch2_offline_fsck_ops);
err:
	if (ret < 0) {
		if (thr)
			bch2_fsck_thread_exit(&thr->thr);
		pr_err("ret %s", bch2_err_str(ret));
	}
	kfree(devs);
	return ret;
}

static long bch2_global_ioctl(unsigned cmd, void __user *arg)
{
	long ret;

	switch (cmd) {
#if 0
	case BCH_IOCTL_ASSEMBLE:
		return bch2_ioctl_assemble(arg);
	case BCH_IOCTL_INCREMENTAL:
		return bch2_ioctl_incremental(arg);
#endif
	case BCH_IOCTL_FSCK_OFFLINE: {
		ret = bch2_ioctl_fsck_offline(arg);
		break;
	}
	default:
		ret = -ENOTTY;
		break;
	}

	if (ret < 0)
		ret = bch2_err_class(ret);
	return ret;
}

static long bch2_ioctl_query_uuid(struct bch_fs *c,
			struct bch_ioctl_query_uuid __user *user_arg)
{
	return copy_to_user_errcode(&user_arg->uuid, &c->sb.user_uuid,
				    sizeof(c->sb.user_uuid));
}

#if 0
static long bch2_ioctl_start(struct bch_fs *c, struct bch_ioctl_start arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (arg.flags || arg.pad)
		return -EINVAL;

	return bch2_fs_start(c);
}

static long bch2_ioctl_stop(struct bch_fs *c)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	bch2_fs_stop(c);
	return 0;
}
#endif

static long bch2_ioctl_disk_add(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	char *path;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	ret = PTR_ERR_OR_ZERO(path);
	if (ret)
		return ret;

	ret = bch2_dev_add(c, path);
	kfree(path);

	return ret;
}

static long bch2_ioctl_disk_remove(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	struct bch_dev *ca;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	return bch2_dev_remove(c, ca, arg.flags);
}

static long bch2_ioctl_disk_online(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	char *path;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	ret = PTR_ERR_OR_ZERO(path);
	if (ret)
		return ret;

	ret = bch2_dev_online(c, path);
	kfree(path);
	return ret;
}

static long bch2_ioctl_disk_offline(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	struct bch_dev *ca;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_offline(c, ca, arg.flags);
	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch2_ioctl_disk_set_state(struct bch_fs *c,
			struct bch_ioctl_disk_set_state arg)
{
	struct bch_dev *ca;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad[0] || arg.pad[1] || arg.pad[2] ||
	    arg.new_state >= BCH_MEMBER_STATE_NR)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_set_state(c, ca, arg.new_state, arg.flags);
	if (ret)
		bch_err(c, "Error setting device state: %s", bch2_err_str(ret));

	percpu_ref_put(&ca->ref);
	return ret;
}

struct bch_data_ctx {
	struct thread_with_file		thr;

	struct bch_fs			*c;
	struct bch_ioctl_data		arg;
	struct bch_move_stats		stats;
};

static int bch2_data_thread(void *arg)
{
	struct bch_data_ctx *ctx = container_of(arg, struct bch_data_ctx, thr);

	ctx->thr.ret = bch2_data_job(ctx->c, &ctx->stats, ctx->arg);
	ctx->stats.data_type = U8_MAX;
	return 0;
}

static int bch2_data_job_release(struct inode *inode, struct file *file)
{
	struct bch_data_ctx *ctx = container_of(file->private_data, struct bch_data_ctx, thr);

	bch2_thread_with_file_exit(&ctx->thr);
	kfree(ctx);
	return 0;
}

static ssize_t bch2_data_job_read(struct file *file, char __user *buf,
				  size_t len, loff_t *ppos)
{
	struct bch_data_ctx *ctx = container_of(file->private_data, struct bch_data_ctx, thr);
	struct bch_fs *c = ctx->c;
	struct bch_ioctl_data_event e = {
		.type			= BCH_DATA_EVENT_PROGRESS,
		.p.data_type		= ctx->stats.data_type,
		.p.btree_id		= ctx->stats.pos.btree,
		.p.pos			= ctx->stats.pos.pos,
		.p.sectors_done		= atomic64_read(&ctx->stats.sectors_seen),
		.p.sectors_total	= bch2_fs_usage_read_short(c).used,
	};

	if (len < sizeof(e))
		return -EINVAL;

	return copy_to_user_errcode(buf, &e, sizeof(e)) ?: sizeof(e);
}

static const struct file_operations bcachefs_data_ops = {
	.release	= bch2_data_job_release,
	.read		= bch2_data_job_read,
	.llseek		= no_llseek,
};

static long bch2_ioctl_data(struct bch_fs *c,
			    struct bch_ioctl_data arg)
{
	struct bch_data_ctx *ctx;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (arg.op >= BCH_DATA_OP_NR || arg.flags)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->c = c;
	ctx->arg = arg;

	ret = bch2_run_thread_with_file(&ctx->thr,
			&bcachefs_data_ops,
			bch2_data_thread);
	if (ret < 0)
		kfree(ctx);
	return ret;
}

static long bch2_ioctl_fs_usage(struct bch_fs *c,
				struct bch_ioctl_fs_usage __user *user_arg)
{
	struct bch_ioctl_fs_usage *arg = NULL;
	struct bch_replicas_usage *dst_e, *dst_end;
	struct bch_fs_usage_online *src;
	u32 replica_entries_bytes;
	unsigned i;
	int ret = 0;

	if (!test_bit(BCH_FS_started, &c->flags))
		return -EINVAL;

	if (get_user(replica_entries_bytes, &user_arg->replica_entries_bytes))
		return -EFAULT;

	arg = kzalloc(size_add(sizeof(*arg), replica_entries_bytes), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	src = bch2_fs_usage_read(c);
	if (!src) {
		ret = -ENOMEM;
		goto err;
	}

	arg->capacity		= c->capacity;
	arg->used		= bch2_fs_sectors_used(c, src);
	arg->online_reserved	= src->online_reserved;

	for (i = 0; i < BCH_REPLICAS_MAX; i++)
		arg->persistent_reserved[i] = src->u.persistent_reserved[i];

	dst_e	= arg->replicas;
	dst_end = (void *) arg->replicas + replica_entries_bytes;

	for (i = 0; i < c->replicas.nr; i++) {
		struct bch_replicas_entry_v1 *src_e =
			cpu_replicas_entry(&c->replicas, i);

		/* check that we have enough space for one replicas entry */
		if (dst_e + 1 > dst_end) {
			ret = -ERANGE;
			break;
		}

		dst_e->sectors		= src->u.replicas[i];
		dst_e->r		= *src_e;

		/* recheck after setting nr_devs: */
		if (replicas_usage_next(dst_e) > dst_end) {
			ret = -ERANGE;
			break;
		}

		memcpy(dst_e->r.devs, src_e->devs, src_e->nr_devs);

		dst_e = replicas_usage_next(dst_e);
	}

	arg->replica_entries_bytes = (void *) dst_e - (void *) arg->replicas;

	percpu_up_read(&c->mark_lock);
	kfree(src);

	if (ret)
		goto err;

	ret = copy_to_user_errcode(user_arg, arg,
			sizeof(*arg) + arg->replica_entries_bytes);
err:
	kfree(arg);
	return ret;
}

/* obsolete, didn't allow for new data types: */
static long bch2_ioctl_dev_usage(struct bch_fs *c,
				 struct bch_ioctl_dev_usage __user *user_arg)
{
	struct bch_ioctl_dev_usage arg;
	struct bch_dev_usage src;
	struct bch_dev *ca;
	unsigned i;

	if (!test_bit(BCH_FS_started, &c->flags))
		return -EINVAL;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if ((arg.flags & ~BCH_BY_INDEX) ||
	    arg.pad[0] ||
	    arg.pad[1] ||
	    arg.pad[2])
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	src = bch2_dev_usage_read(ca);

	arg.state		= ca->mi.state;
	arg.bucket_size		= ca->mi.bucket_size;
	arg.nr_buckets		= ca->mi.nbuckets - ca->mi.first_bucket;

	for (i = 0; i < BCH_DATA_NR; i++) {
		arg.d[i].buckets	= src.d[i].buckets;
		arg.d[i].sectors	= src.d[i].sectors;
		arg.d[i].fragmented	= src.d[i].fragmented;
	}

	percpu_ref_put(&ca->ref);

	return copy_to_user_errcode(user_arg, &arg, sizeof(arg));
}

static long bch2_ioctl_dev_usage_v2(struct bch_fs *c,
				 struct bch_ioctl_dev_usage_v2 __user *user_arg)
{
	struct bch_ioctl_dev_usage_v2 arg;
	struct bch_dev_usage src;
	struct bch_dev *ca;
	int ret = 0;

	if (!test_bit(BCH_FS_started, &c->flags))
		return -EINVAL;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if ((arg.flags & ~BCH_BY_INDEX) ||
	    arg.pad[0] ||
	    arg.pad[1] ||
	    arg.pad[2])
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	src = bch2_dev_usage_read(ca);

	arg.state		= ca->mi.state;
	arg.bucket_size		= ca->mi.bucket_size;
	arg.nr_data_types	= min(arg.nr_data_types, BCH_DATA_NR);
	arg.nr_buckets		= ca->mi.nbuckets - ca->mi.first_bucket;

	ret = copy_to_user_errcode(user_arg, &arg, sizeof(arg));
	if (ret)
		goto err;

	for (unsigned i = 0; i < arg.nr_data_types; i++) {
		struct bch_ioctl_dev_usage_type t = {
			.buckets	= src.d[i].buckets,
			.sectors	= src.d[i].sectors,
			.fragmented	= src.d[i].fragmented,
		};

		ret = copy_to_user_errcode(&user_arg->d[i], &t, sizeof(t));
		if (ret)
			goto err;
	}
err:
	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch2_ioctl_read_super(struct bch_fs *c,
				  struct bch_ioctl_read_super arg)
{
	struct bch_dev *ca = NULL;
	struct bch_sb *sb;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~(BCH_BY_INDEX|BCH_READ_DEV)) ||
	    arg.pad)
		return -EINVAL;

	mutex_lock(&c->sb_lock);

	if (arg.flags & BCH_READ_DEV) {
		ca = bch2_device_lookup(c, arg.dev, arg.flags);

		if (IS_ERR(ca)) {
			ret = PTR_ERR(ca);
			goto err;
		}

		sb = ca->disk_sb.sb;
	} else {
		sb = c->disk_sb.sb;
	}

	if (vstruct_bytes(sb) > arg.size) {
		ret = -ERANGE;
		goto err;
	}

	ret = copy_to_user_errcode((void __user *)(unsigned long)arg.sb, sb,
				   vstruct_bytes(sb));
err:
	if (!IS_ERR_OR_NULL(ca))
		percpu_ref_put(&ca->ref);
	mutex_unlock(&c->sb_lock);
	return ret;
}

static long bch2_ioctl_disk_get_idx(struct bch_fs *c,
				    struct bch_ioctl_disk_get_idx arg)
{
	dev_t dev = huge_decode_dev(arg.dev);

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!dev)
		return -EINVAL;

	for_each_online_member(c, ca)
		if (ca->dev == dev) {
			percpu_ref_put(&ca->io_ref);
			return ca->dev_idx;
		}

	return -BCH_ERR_ENOENT_dev_idx_not_found;
}

static long bch2_ioctl_disk_resize(struct bch_fs *c,
				   struct bch_ioctl_disk_resize arg)
{
	struct bch_dev *ca;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~BCH_BY_INDEX) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_resize(c, ca, arg.nbuckets);

	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch2_ioctl_disk_resize_journal(struct bch_fs *c,
				   struct bch_ioctl_disk_resize_journal arg)
{
	struct bch_dev *ca;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if ((arg.flags & ~BCH_BY_INDEX) ||
	    arg.pad)
		return -EINVAL;

	if (arg.nbuckets > U32_MAX)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_set_nr_journal_buckets(c, ca, arg.nbuckets);

	percpu_ref_put(&ca->ref);
	return ret;
}

static int bch2_fsck_online_thread_fn(struct thread_with_stdio *stdio)
{
	struct fsck_thread *thr = container_of(stdio, struct fsck_thread, thr);
	struct bch_fs *c = thr->c;

	c->stdio_filter = current;
	c->stdio = &thr->thr.stdio;

	/*
	 * XXX: can we figure out a way to do this without mucking with c->opts?
	 */
	unsigned old_fix_errors = c->opts.fix_errors;
	if (opt_defined(thr->opts, fix_errors))
		c->opts.fix_errors = thr->opts.fix_errors;
	else
		c->opts.fix_errors = FSCK_FIX_ask;

	c->opts.fsck = true;
	set_bit(BCH_FS_fsck_running, &c->flags);

	c->curr_recovery_pass = BCH_RECOVERY_PASS_check_alloc_info;
	int ret = bch2_run_online_recovery_passes(c);

	clear_bit(BCH_FS_fsck_running, &c->flags);
	bch_err_fn(c, ret);

	c->stdio = NULL;
	c->stdio_filter = NULL;
	c->opts.fix_errors = old_fix_errors;

	up(&c->online_fsck_mutex);
	bch2_ro_ref_put(c);
	return ret;
}

static const struct thread_with_stdio_ops bch2_online_fsck_ops = {
	.exit		= bch2_fsck_thread_exit,
	.fn		= bch2_fsck_online_thread_fn,
};

static long bch2_ioctl_fsck_online(struct bch_fs *c,
				   struct bch_ioctl_fsck_online arg)
{
	struct fsck_thread *thr = NULL;
	long ret = 0;

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!bch2_ro_ref_tryget(c))
		return -EROFS;

	if (down_trylock(&c->online_fsck_mutex)) {
		bch2_ro_ref_put(c);
		return -EAGAIN;
	}

	thr = kzalloc(sizeof(*thr), GFP_KERNEL);
	if (!thr) {
		ret = -ENOMEM;
		goto err;
	}

	thr->c = c;
	thr->opts = bch2_opts_empty();

	if (arg.opts) {
		char *optstr = strndup_user((char __user *)(unsigned long) arg.opts, 1 << 16);

		ret =   PTR_ERR_OR_ZERO(optstr) ?:
			bch2_parse_mount_opts(c, &thr->opts, optstr);
		kfree(optstr);

		if (ret)
			goto err;
	}

	ret = bch2_run_thread_with_stdio(&thr->thr, &bch2_online_fsck_ops);
err:
	if (ret < 0) {
		bch_err_fn(c, ret);
		if (thr)
			bch2_fsck_thread_exit(&thr->thr);
		up(&c->online_fsck_mutex);
		bch2_ro_ref_put(c);
	}
	return ret;
}

#define BCH_IOCTL(_name, _argtype)					\
do {									\
	_argtype i;							\
									\
	if (copy_from_user(&i, arg, sizeof(i)))				\
		return -EFAULT;						\
	ret = bch2_ioctl_##_name(c, i);					\
	goto out;							\
} while (0)

long bch2_fs_ioctl(struct bch_fs *c, unsigned cmd, void __user *arg)
{
	long ret;

	switch (cmd) {
	case BCH_IOCTL_QUERY_UUID:
		return bch2_ioctl_query_uuid(c, arg);
	case BCH_IOCTL_FS_USAGE:
		return bch2_ioctl_fs_usage(c, arg);
	case BCH_IOCTL_DEV_USAGE:
		return bch2_ioctl_dev_usage(c, arg);
	case BCH_IOCTL_DEV_USAGE_V2:
		return bch2_ioctl_dev_usage_v2(c, arg);
#if 0
	case BCH_IOCTL_START:
		BCH_IOCTL(start, struct bch_ioctl_start);
	case BCH_IOCTL_STOP:
		return bch2_ioctl_stop(c);
#endif
	case BCH_IOCTL_READ_SUPER:
		BCH_IOCTL(read_super, struct bch_ioctl_read_super);
	case BCH_IOCTL_DISK_GET_IDX:
		BCH_IOCTL(disk_get_idx, struct bch_ioctl_disk_get_idx);
	}

	if (!test_bit(BCH_FS_started, &c->flags))
		return -EINVAL;

	switch (cmd) {
	case BCH_IOCTL_DISK_ADD:
		BCH_IOCTL(disk_add, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_REMOVE:
		BCH_IOCTL(disk_remove, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_ONLINE:
		BCH_IOCTL(disk_online, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_OFFLINE:
		BCH_IOCTL(disk_offline, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_SET_STATE:
		BCH_IOCTL(disk_set_state, struct bch_ioctl_disk_set_state);
	case BCH_IOCTL_DATA:
		BCH_IOCTL(data, struct bch_ioctl_data);
	case BCH_IOCTL_DISK_RESIZE:
		BCH_IOCTL(disk_resize, struct bch_ioctl_disk_resize);
	case BCH_IOCTL_DISK_RESIZE_JOURNAL:
		BCH_IOCTL(disk_resize_journal, struct bch_ioctl_disk_resize_journal);
	case BCH_IOCTL_FSCK_ONLINE:
		BCH_IOCTL(fsck_online, struct bch_ioctl_fsck_online);
	default:
		return -ENOTTY;
	}
out:
	if (ret < 0)
		ret = bch2_err_class(ret);
	return ret;
}

static DEFINE_IDR(bch_chardev_minor);

static long bch2_chardev_ioctl(struct file *filp, unsigned cmd, unsigned long v)
{
	unsigned minor = iminor(file_inode(filp));
	struct bch_fs *c = minor < U8_MAX ? idr_find(&bch_chardev_minor, minor) : NULL;
	void __user *arg = (void __user *) v;

	return c
		? bch2_fs_ioctl(c, cmd, arg)
		: bch2_global_ioctl(cmd, arg);
}

static const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch2_chardev_ioctl,
	.open		= nonseekable_open,
};

static int bch_chardev_major;
static struct class *bch_chardev_class;
static struct device *bch_chardev;

void bch2_fs_chardev_exit(struct bch_fs *c)
{
	if (!IS_ERR_OR_NULL(c->chardev))
		device_unregister(c->chardev);
	if (c->minor >= 0)
		idr_remove(&bch_chardev_minor, c->minor);
}

int bch2_fs_chardev_init(struct bch_fs *c)
{
	c->minor = idr_alloc(&bch_chardev_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	c->chardev = device_create(bch_chardev_class, NULL,
				   MKDEV(bch_chardev_major, c->minor), c,
				   "bcachefs%u-ctl", c->minor);
	if (IS_ERR(c->chardev))
		return PTR_ERR(c->chardev);

	return 0;
}

void bch2_chardev_exit(void)
{
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		device_destroy(bch_chardev_class,
			       MKDEV(bch_chardev_major, U8_MAX));
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		class_destroy(bch_chardev_class);
	if (bch_chardev_major > 0)
		unregister_chrdev(bch_chardev_major, "bcachefs");
}

int __init bch2_chardev_init(void)
{
	bch_chardev_major = register_chrdev(0, "bcachefs-ctl", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		return bch_chardev_major;

	bch_chardev_class = class_create("bcachefs");
	if (IS_ERR(bch_chardev_class))
		return PTR_ERR(bch_chardev_class);

	bch_chardev = device_create(bch_chardev_class, NULL,
				    MKDEV(bch_chardev_major, U8_MAX),
				    NULL, "bcachefs-ctl");
	if (IS_ERR(bch_chardev))
		return PTR_ERR(bch_chardev);

	return 0;
}

#endif /* NO_BCACHEFS_CHARDEV */
