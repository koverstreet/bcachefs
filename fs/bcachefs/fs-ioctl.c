// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "chardev.h"
#include "dirent.h"
#include "fs.h"
#include "fs-ioctl.h"
#include "quota.h"

#include <linux/compat.h>
#include <linux/mount.h>

#define FS_IOC_GOINGDOWN	     _IOR('X', 125, __u32)

struct flags_set {
	unsigned		mask;
	unsigned		flags;

	unsigned		projid;
};

static int bch2_inode_flags_set(struct bch_inode_info *inode,
				struct bch_inode_unpacked *bi,
				void *p)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	/*
	 * We're relying on btree locking here for exclusion with other ioctl
	 * calls - use the flags in the btree (@bi), not inode->i_flags:
	 */
	struct flags_set *s = p;
	unsigned newflags = s->flags;
	unsigned oldflags = bi->bi_flags & s->mask;

	if (((newflags ^ oldflags) & (BCH_INODE_APPEND|BCH_INODE_IMMUTABLE)) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	if (!S_ISREG(bi->bi_mode) &&
	    !S_ISDIR(bi->bi_mode) &&
	    (newflags & (BCH_INODE_NODUMP|BCH_INODE_NOATIME)) != newflags)
		return -EINVAL;

	bi->bi_flags &= ~s->mask;
	bi->bi_flags |= newflags;

	bi->bi_ctime = timespec_to_bch2_time(c, current_time(&inode->v));
	return 0;
}

static int bch2_ioc_getflags(struct bch_inode_info *inode, int __user *arg)
{
	unsigned flags = map_flags(bch_flags_to_uflags, inode->ei_inode.bi_flags);

	return put_user(flags, arg);
}

static int bch2_ioc_setflags(struct bch_fs *c,
			     struct file *file,
			     struct bch_inode_info *inode,
			     void __user *arg)
{
	struct flags_set s = { .mask = map_defined(bch_flags_to_uflags) };
	unsigned uflags;
	int ret;

	if (get_user(uflags, (int __user *) arg))
		return -EFAULT;

	s.flags = map_flags_rev(bch_flags_to_uflags, uflags);
	if (uflags)
		return -EOPNOTSUPP;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	inode_lock(&inode->v);
	if (!inode_owner_or_capable(file_mnt_idmap(file), &inode->v)) {
		ret = -EACCES;
		goto setflags_out;
	}

	mutex_lock(&inode->ei_update_lock);
	ret = bch2_write_inode(c, inode, bch2_inode_flags_set, &s,
			       ATTR_CTIME);
	mutex_unlock(&inode->ei_update_lock);

setflags_out:
	inode_unlock(&inode->v);
	mnt_drop_write_file(file);
	return ret;
}

static int bch2_ioc_fsgetxattr(struct bch_inode_info *inode,
			       struct fsxattr __user *arg)
{
	struct fsxattr fa = { 0 };

	fa.fsx_xflags = map_flags(bch_flags_to_xflags, inode->ei_inode.bi_flags);
	fa.fsx_projid = inode->ei_qid.q[QTYP_PRJ];

	return copy_to_user(arg, &fa, sizeof(fa));
}

static int fssetxattr_inode_update_fn(struct bch_inode_info *inode,
				      struct bch_inode_unpacked *bi,
				      void *p)
{
	struct flags_set *s = p;

	if (s->projid != bi->bi_project) {
		bi->bi_fields_set |= 1U << Inode_opt_project;
		bi->bi_project = s->projid;
	}

	return bch2_inode_flags_set(inode, bi, p);
}

static int bch2_ioc_fssetxattr(struct bch_fs *c,
			       struct file *file,
			       struct bch_inode_info *inode,
			       struct fsxattr __user *arg)
{
	struct flags_set s = { .mask = map_defined(bch_flags_to_xflags) };
	struct fsxattr fa;
	int ret;

	if (copy_from_user(&fa, arg, sizeof(fa)))
		return -EFAULT;

	s.flags = map_flags_rev(bch_flags_to_xflags, fa.fsx_xflags);
	if (fa.fsx_xflags)
		return -EOPNOTSUPP;

	if (fa.fsx_projid >= U32_MAX)
		return -EINVAL;

	s.projid = fa.fsx_projid + 1;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	inode_lock(&inode->v);
	if (!inode_owner_or_capable(file_mnt_idmap(file), &inode->v)) {
		ret = -EACCES;
		goto err;
	}

	mutex_lock(&inode->ei_update_lock);
	ret = bch2_set_projid(c, inode, s.projid);
	if (ret)
		goto err_unlock;

	ret = bch2_write_inode(c, inode, fssetxattr_inode_update_fn, &s,
			       ATTR_CTIME);
err_unlock:
	mutex_unlock(&inode->ei_update_lock);
err:
	inode_unlock(&inode->v);
	mnt_drop_write_file(file);
	return ret;
}

static int bch2_ioc_reinherit_attrs(struct bch_fs *c,
				    struct file *file,
				    struct bch_inode_info *src,
				    const char __user *name)
{
	struct bch_inode_info *dst;
	struct inode *vinode = NULL;
	char *kname = NULL;
	struct qstr qstr;
	int ret = 0;
	u64 inum;

	kname = kmalloc(BCH_NAME_MAX + 1, GFP_KERNEL);
	if (!kname)
		return -ENOMEM;

	ret = strncpy_from_user(kname, name, BCH_NAME_MAX);
	if (unlikely(ret < 0))
		goto err1;

	qstr.hash_len	= ret;
	qstr.name	= kname;

	ret = -ENOENT;
	inum = bch2_dirent_lookup(c, src->v.i_ino,
				  &src->ei_str_hash,
				  &qstr);
	if (!inum)
		goto err1;

	vinode = bch2_vfs_inode_get(c, inum);
	ret = PTR_ERR_OR_ZERO(vinode);
	if (ret)
		goto err1;

	dst = to_bch_ei(vinode);

	ret = mnt_want_write_file(file);
	if (ret)
		goto err2;

	bch2_lock_inodes(src, dst);

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
	bch2_unlock_inodes(src, dst);

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

long bch2_fs_file_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct super_block *sb = inode->v.i_sb;
	struct bch_fs *c = sb->s_fs_info;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return bch2_ioc_getflags(inode, (int __user *) arg);

	case FS_IOC_SETFLAGS:
		return bch2_ioc_setflags(c, file, inode, (int __user *) arg);

	case FS_IOC_FSGETXATTR:
		return bch2_ioc_fsgetxattr(inode, (void __user *) arg);
	case FS_IOC_FSSETXATTR:
		return bch2_ioc_fssetxattr(c, file, inode,
					   (void __user *) arg);

	case BCHFS_IOC_REINHERIT_ATTRS:
		return bch2_ioc_reinherit_attrs(c, file, inode,
						(void __user *) arg);

	case FS_IOC_GETVERSION:
		return -ENOTTY;
	case FS_IOC_SETVERSION:
		return -ENOTTY;

	case FS_IOC_GOINGDOWN:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		down_write(&sb->s_umount);
		sb->s_flags |= SB_RDONLY;
		bch2_fs_emergency_read_only(c);
		up_write(&sb->s_umount);
		return 0;

	default:
		return bch2_fs_ioctl(c, cmd, (void __user *) arg);
	}
}

#ifdef CONFIG_COMPAT
long bch2_compat_fs_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case FS_IOC_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return bch2_fs_file_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

#endif /* NO_BCACHEFS_FS */
