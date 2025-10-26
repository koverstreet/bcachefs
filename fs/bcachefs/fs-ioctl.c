// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "chardev.h"
#include "dirent.h"
#include "fs.h"
#include "fs-ioctl.h"
#include "namei.h"
#include "quota.h"

#include <linux/compat.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/writeback.h>

#define FS_IOC_GOINGDOWN	     _IOR('X', 125, __u32)
#define FSOP_GOING_FLAGS_DEFAULT	0x0	/* going down */
#define FSOP_GOING_FLAGS_LOGFLUSH	0x1	/* flush log but not data */
#define FSOP_GOING_FLAGS_NOLOGFLUSH	0x2	/* don't flush log nor data */

static int bch2_reinherit_attrs_fn(struct btree_trans *trans,
				   struct bch_inode_info *inode,
				   struct bch_inode_unpacked *bi,
				   void *p)
{
	struct bch_inode_info *dir = p;

	return !bch2_reinherit_attrs(bi, &dir->ei_inode);
}

static int bch2_ioc_reinherit_attrs(struct bch_fs *c,
				    struct file *file,
				    struct bch_inode_info *src,
				    const char __user *name)
{
	struct bch_hash_info hash = bch2_hash_info_init(c, &src->ei_inode);
	struct bch_inode_info *dst;
	struct inode *vinode = NULL;
	char *kname = NULL;
	struct qstr qstr;
	int ret = 0;
	subvol_inum inum;

	kname = kmalloc(BCH_NAME_MAX, GFP_KERNEL);
	if (!kname)
		return -ENOMEM;

	ret = strncpy_from_user(kname, name, BCH_NAME_MAX);
	if (unlikely(ret < 0))
		goto err1;

	qstr.len	= ret;
	qstr.name	= kname;

	ret = bch2_dirent_lookup(c, inode_inum(src), &hash, &qstr, &inum);
	if (ret)
		goto err1;

	vinode = bch2_vfs_inode_get(c, inum);
	ret = PTR_ERR_OR_ZERO(vinode);
	if (ret)
		goto err1;

	dst = to_bch_ei(vinode);

	ret = mnt_want_write_file(file);
	if (ret)
		goto err2;

	bch2_lock_inodes(INODE_UPDATE_LOCK, src, dst);

	if (inode_attr_changing(src, dst, Inode_opt_project)) {
		ret = bch2_fs_quota_transfer(c, dst,
					     src->ei_qid,
					     1 << QTYP_PRJ,
					     KEY_TYPE_QUOTA_PREALLOC);
		if (ret)
			goto err3;
	}

	ret = bch2_write_inode(c, dst, bch2_reinherit_attrs_fn, src, 0);
err3:
	bch2_unlock_inodes(INODE_UPDATE_LOCK, src, dst);

	/* return true if we did work */
	if (ret >= 0)
		ret = !ret;

	mnt_drop_write_file(file);
err2:
	iput(vinode);
err1:
	kfree(kname);

	return ret;
}

static int bch2_ioc_getversion(struct bch_inode_info *inode, u32 __user *arg)
{
	return put_user(inode->v.i_generation, arg);
}

static int bch2_ioc_getlabel(struct bch_fs *c, char __user *user_label)
{
	int ret;
	size_t len;
	char label[BCH_SB_LABEL_SIZE];

	BUILD_BUG_ON(BCH_SB_LABEL_SIZE >= FSLABEL_MAX);

	scoped_guard(mutex, &c->sb_lock)
		memcpy(label, c->disk_sb.sb->label, BCH_SB_LABEL_SIZE);

	len = strnlen(label, BCH_SB_LABEL_SIZE);
	if (len == BCH_SB_LABEL_SIZE) {
		bch_warn(c,
			"label is too long, return the first %zu bytes",
			--len);
	}

	ret = copy_to_user(user_label, label, len);

	return ret ? -EFAULT : 0;
}

static int bch2_ioc_setlabel(struct bch_fs *c,
			     struct file *file,
			     struct bch_inode_info *inode,
			     const char __user *user_label)
{
	int ret;
	char label[BCH_SB_LABEL_SIZE];

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(label, user_label, sizeof(label)))
		return -EFAULT;

	if (strnlen(label, BCH_SB_LABEL_SIZE) == BCH_SB_LABEL_SIZE) {
		bch_err(c,
			"unable to set label with more than %d bytes",
			BCH_SB_LABEL_SIZE - 1);
		return -EINVAL;
	}

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	scoped_guard(mutex, &c->sb_lock) {
		strscpy(c->disk_sb.sb->label, label, BCH_SB_LABEL_SIZE);
		ret = bch2_write_super(c);
	}

	mnt_drop_write_file(file);
	return ret;
}

static int bch2_ioc_goingdown(struct bch_fs *c, u32 __user *arg)
{
	u32 flags;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, arg))
		return -EFAULT;

	CLASS(printbuf, buf)();
	bch2_log_msg_start(c, &buf);

	prt_printf(&buf, "shutdown by ioctl type %u", flags);

	switch (flags) {
	case FSOP_GOING_FLAGS_DEFAULT:
		ret = bdev_freeze(c->vfs_sb->s_bdev);
		if (ret)
			break;
		bch2_journal_flush(&c->journal);
		bch2_fs_emergency_read_only2(c, &buf);
		bdev_thaw(c->vfs_sb->s_bdev);
		break;
	case FSOP_GOING_FLAGS_LOGFLUSH:
		bch2_journal_flush(&c->journal);
		fallthrough;
	case FSOP_GOING_FLAGS_NOLOGFLUSH:
		bch2_fs_emergency_read_only2(c, &buf);
		break;
	default:
		return -EINVAL;
	}

	bch2_print_str(c, KERN_ERR, buf.buf);
	return ret;
}

static long __bch2_ioctl_subvolume_create(struct bch_fs *c, struct file *filp,
					  struct bch_ioctl_subvolume_v2 arg,
					  struct printbuf *err)
{
	struct inode *dir;
	struct bch_inode_info *inode;
	struct user_namespace *s_user_ns;
	struct dentry *dst_dentry;
	struct path src_path, dst_path;
	int how = LOOKUP_FOLLOW;
	int error;
	subvol_inum snapshot_src = { 0 };
	unsigned lookup_flags = 0;
	unsigned create_flags = BCH_CREATE_SUBVOL;

	if (arg.flags & ~(BCH_SUBVOL_SNAPSHOT_CREATE|
			  BCH_SUBVOL_SNAPSHOT_RO)) {
		prt_str(err, "invalid flasg");
		return -EINVAL;
	}

	if (!(arg.flags & BCH_SUBVOL_SNAPSHOT_CREATE) &&
	    (arg.src_ptr ||
	     (arg.flags & BCH_SUBVOL_SNAPSHOT_RO))) {
		prt_str(err, "invalid flasg");
		return -EINVAL;
	}

	if (arg.flags & BCH_SUBVOL_SNAPSHOT_CREATE)
		create_flags |= BCH_CREATE_SNAPSHOT;

	if (arg.flags & BCH_SUBVOL_SNAPSHOT_RO)
		create_flags |= BCH_CREATE_SNAPSHOT_RO;

	if (arg.flags & BCH_SUBVOL_SNAPSHOT_CREATE) {
		/* sync_inodes_sb enforce s_umount is locked */
		guard(rwsem_read)(&c->vfs_sb->s_umount);
		sync_inodes_sb(c->vfs_sb);
	}

	if (arg.src_ptr) {
		error = user_path_at(arg.dirfd,
				(const char __user *)(unsigned long)arg.src_ptr,
				how, &src_path);
		if (error)
			goto err1;

		if (src_path.dentry->d_sb->s_fs_info != c) {
			path_put(&src_path);
			prt_str(err, "src_path not on dst filesystem");
			error = -EXDEV;
			goto err1;
		}

		snapshot_src = inode_inum(to_bch_ei(src_path.dentry->d_inode));
	}

	dst_dentry = user_path_create(arg.dirfd,
			(const char __user *)(unsigned long)arg.dst_ptr,
			&dst_path, lookup_flags);
	error = PTR_ERR_OR_ZERO(dst_dentry);
	if (error)
		goto err2;

	if (dst_dentry->d_sb->s_fs_info != c) {
		prt_str(err, "dst_path not on dst filesystem");
		error = -EXDEV;
		goto err3;
	}

	if (dst_dentry->d_inode) {
		error = bch_err_throw(c, EEXIST_subvolume_create);
		goto err3;
	}

	dir = dst_path.dentry->d_inode;
	if (IS_DEADDIR(dir)) {
		error = bch_err_throw(c, ENOENT_directory_dead);
		goto err3;
	}

	s_user_ns = dir->i_sb->s_user_ns;
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) ||
	    !kgid_has_mapping(s_user_ns, current_fsgid())) {
		prt_str(err, "current uid/gid not mapped into fs namespace");
		error = -EOVERFLOW;
		goto err3;
	}

	error = inode_permission(file_mnt_idmap(filp),
				 dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto err3;

	if (!IS_POSIXACL(dir))
		arg.mode &= ~current_umask();

	error = security_path_mkdir(&dst_path, dst_dentry, arg.mode);
	if (error)
		goto err3;

	if ((arg.flags & BCH_SUBVOL_SNAPSHOT_CREATE) &&
	    !arg.src_ptr)
		snapshot_src.subvol = inode_inum(to_bch_ei(dir)).subvol;

	scoped_guard(rwsem_write, &c->snapshot_create_lock)
		inode = __bch2_create(file_mnt_idmap(filp), to_bch_ei(dir),
				      dst_dentry, arg.mode|S_IFDIR,
				      0, snapshot_src, create_flags);
	error = PTR_ERR_OR_ZERO(inode);
	if (error)
		goto err3;

	d_instantiate(dst_dentry, &inode->v);
	fsnotify_mkdir(dir, dst_dentry);
err3:
	done_path_create(&dst_path, dst_dentry);
err2:
	if (arg.src_ptr)
		path_put(&src_path);
err1:
	return error;
}

static long bch2_ioctl_subvolume_create(struct bch_fs *c, struct file *filp,
					struct bch_ioctl_subvolume arg)
{
	struct bch_ioctl_subvolume_v2 arg_v2 = {
		.flags		= arg.flags,
		.dirfd		= arg.dirfd,
		.mode		= arg.mode,
		.dst_ptr	= arg.dst_ptr,
		.src_ptr	= arg.src_ptr,
	};

	CLASS(printbuf, err)();
	long ret = __bch2_ioctl_subvolume_create(c, filp, arg_v2, &err);
	if (ret)
		bch_err_msg(c, ret, "%s", err.buf);
	return ret;
}

static long bch2_ioctl_subvolume_create_v2(struct bch_fs *c, struct file *filp,
					   struct bch_ioctl_subvolume_v2 arg)
{
	CLASS(printbuf, err)();
	long ret = __bch2_ioctl_subvolume_create(c, filp, arg, &err);
	return bch2_copy_ioctl_err_msg(&arg.err, &err, ret);
}

static long __bch2_ioctl_subvolume_destroy(struct bch_fs *c, struct file *filp,
					   struct bch_ioctl_subvolume_v2 arg,
					   struct printbuf *err)
{
	const char __user *name = (void __user *)(unsigned long)arg.dst_ptr;
	struct path path;
	struct inode *dir;
	struct dentry *victim;
	int ret = 0;

	if (arg.flags)
		return -EINVAL;

	victim = user_path_locked_at(arg.dirfd, name, &path);
	if (IS_ERR(victim))
		return PTR_ERR(victim);

	dir = d_inode(path.dentry);
	if (victim->d_sb->s_fs_info != c) {
		ret = -EXDEV;
		goto err;
	}

	ret =   inode_permission(file_mnt_idmap(filp), d_inode(victim), MAY_WRITE) ?:
		__bch2_unlink(dir, victim, true);
	if (!ret) {
		fsnotify_rmdir(dir, victim);
		d_invalidate(victim);
	}
err:
	inode_unlock(dir);
	dput(victim);
	path_put(&path);
	return ret;
}

static long bch2_ioctl_subvolume_destroy(struct bch_fs *c, struct file *filp,
					 struct bch_ioctl_subvolume arg)
{
	struct bch_ioctl_subvolume_v2 arg_v2 = {
		.flags		= arg.flags,
		.dirfd		= arg.dirfd,
		.mode		= arg.mode,
		.dst_ptr	= arg.dst_ptr,
		.src_ptr	= arg.src_ptr,
	};

	CLASS(printbuf, err)();
	long ret = __bch2_ioctl_subvolume_destroy(c, filp, arg_v2, &err);
	if (ret)
		bch_err_msg(c, ret, "%s", err.buf);
	return ret;
}

static long bch2_ioctl_subvolume_destroy_v2(struct bch_fs *c, struct file *filp,
					    struct bch_ioctl_subvolume_v2 arg)
{
	CLASS(printbuf, err)();
	long ret = __bch2_ioctl_subvolume_destroy(c, filp, arg, &err);
	return bch2_copy_ioctl_err_msg(&arg.err, &err, ret);
}

long bch2_fs_file_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	long ret;

	switch (cmd) {
	case BCHFS_IOC_REINHERIT_ATTRS:
		ret = bch2_ioc_reinherit_attrs(c, file, inode,
					       (void __user *) arg);
		break;

	case FS_IOC_GETVERSION:
		ret = bch2_ioc_getversion(inode, (u32 __user *) arg);
		break;

	case FS_IOC_SETVERSION:
		ret = -ENOTTY;
		break;

	case FS_IOC_GETFSLABEL:
		ret = bch2_ioc_getlabel(c, (void __user *) arg);
		break;

	case FS_IOC_SETFSLABEL:
		ret = bch2_ioc_setlabel(c, file, inode, (const void __user *) arg);
		break;

	case FS_IOC_GOINGDOWN:
		ret = bch2_ioc_goingdown(c, (u32 __user *) arg);
		break;

	case BCH_IOCTL_SUBVOLUME_CREATE: {
		struct bch_ioctl_subvolume i;

		ret = copy_from_user(&i, (void __user *) arg, sizeof(i))
			? -EFAULT
			: bch2_ioctl_subvolume_create(c, file, i);
		break;
	}

	case BCH_IOCTL_SUBVOLUME_CREATE_v2: {
		struct bch_ioctl_subvolume_v2 i;

		ret = copy_from_user(&i, (void __user *) arg, sizeof(i))
			? -EFAULT
			: bch2_ioctl_subvolume_create_v2(c, file, i);
		break;
	}

	case BCH_IOCTL_SUBVOLUME_DESTROY: {
		struct bch_ioctl_subvolume i;

		ret = copy_from_user(&i, (void __user *) arg, sizeof(i))
			? -EFAULT
			: bch2_ioctl_subvolume_destroy(c, file, i);
		break;
	}

	case BCH_IOCTL_SUBVOLUME_DESTROY_v2: {
		struct bch_ioctl_subvolume_v2 i;

		ret = copy_from_user(&i, (void __user *) arg, sizeof(i))
			? -EFAULT
			: bch2_ioctl_subvolume_destroy_v2(c, file, i);
		break;
	}

	default:
		ret = bch2_fs_ioctl(c, cmd, (void __user *) arg);
		break;
	}

	return bch2_err_class(ret);
}

#ifdef CONFIG_COMPAT
long bch2_compat_fs_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case FS_IOC_GETFSLABEL:
	case FS_IOC_SETFSLABEL:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return bch2_fs_file_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

#endif /* NO_BCACHEFS_FS */
