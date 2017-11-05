#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "chardev.h"
#include "fs.h"
#include "fs-ioctl.h"

#include <linux/compat.h>
#include <linux/mount.h>

#define FS_IOC_GOINGDOWN	     _IOR('X', 125, __u32)

/* Inode flags: */

static const unsigned bch_inode_flags_to_vfs_flags_map[] = {
	[__BCH_INODE_SYNC]	= S_SYNC,
	[__BCH_INODE_IMMUTABLE]	= S_IMMUTABLE,
	[__BCH_INODE_APPEND]	= S_APPEND,
	[__BCH_INODE_NOATIME]	= S_NOATIME,
};

static const unsigned bch_inode_flags_to_user_flags_map[] = {
	[__BCH_INODE_SYNC]	= FS_SYNC_FL,
	[__BCH_INODE_IMMUTABLE]	= FS_IMMUTABLE_FL,
	[__BCH_INODE_APPEND]	= FS_APPEND_FL,
	[__BCH_INODE_NODUMP]	= FS_NODUMP_FL,
	[__BCH_INODE_NOATIME]	= FS_NOATIME_FL,
};

/* Set VFS inode flags from bcachefs inode: */
void bch2_inode_flags_to_vfs(struct bch_inode_info *inode)
{
	unsigned i, flags = inode->ei_flags;

	for (i = 0; i < ARRAY_SIZE(bch_inode_flags_to_vfs_flags_map); i++)
		if (flags & (1 << i))
			inode->v.i_flags |=  bch_inode_flags_to_vfs_flags_map[i];
		else
			inode->v.i_flags &= ~bch_inode_flags_to_vfs_flags_map[i];
}

/* Get FS_IOC_GETFLAGS flags from bcachefs inode: */
static unsigned bch2_inode_flags_to_user_flags(unsigned flags)
{
	unsigned i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(bch_inode_flags_to_user_flags_map); i++)
		if (flags & (1 << i))
			ret |= bch_inode_flags_to_user_flags_map[i];

	return ret;
}

static int bch2_inode_user_flags_set(struct bch_inode_info *inode,
				     struct bch_inode_unpacked *bi,
				     void *p)
{
	/*
	 * We're relying on btree locking here for exclusion with other ioctl
	 * calls - use the flags in the btree (@bi), not inode->i_flags:
	 */
	unsigned bch_flags = bi->bi_flags;
	unsigned oldflags = bch2_inode_flags_to_user_flags(bch_flags);
	unsigned newflags = *((unsigned *) p);
	unsigned i;

	if (((newflags ^ oldflags) & (FS_APPEND_FL|FS_IMMUTABLE_FL)) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	for (i = 0; i < ARRAY_SIZE(bch_inode_flags_to_user_flags_map); i++) {
		if (newflags & bch_inode_flags_to_user_flags_map[i])
			bch_flags |=  (1 << i);
		else
			bch_flags &= ~(1 << i);

		newflags &= ~bch_inode_flags_to_user_flags_map[i];
		oldflags &= ~bch_inode_flags_to_user_flags_map[i];
	}

	if (oldflags != newflags)
		return -EOPNOTSUPP;

	bi->bi_flags = bch_flags;
	inode->v.i_ctime = current_time(&inode->v);

	return 0;
}

long bch2_fs_file_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct super_block *sb = inode->v.i_sb;
	struct bch_fs *c = sb->s_fs_info;
	unsigned flags;
	int ret;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return put_user(bch2_inode_flags_to_user_flags(inode->ei_flags),
				(int __user *) arg);

	case FS_IOC_SETFLAGS: {
		ret = mnt_want_write_file(file);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(&inode->v)) {
			ret = -EACCES;
			goto setflags_out;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			goto setflags_out;
		}

		if (!S_ISREG(inode->v.i_mode) &&
		    !S_ISDIR(inode->v.i_mode) &&
		    (flags & (FS_NODUMP_FL|FS_NOATIME_FL)) != flags) {
			ret = -EINVAL;
			goto setflags_out;
		}

		inode_lock(&inode->v);

		mutex_lock(&inode->ei_update_lock);
		ret = __bch2_write_inode(c, inode, bch2_inode_user_flags_set, &flags);
		mutex_unlock(&inode->ei_update_lock);

		if (!ret)
			bch2_inode_flags_to_vfs(inode);

		inode_unlock(&inode->v);
setflags_out:
		mnt_drop_write_file(file);
		return ret;
	}

	case FS_IOC_GETVERSION:
		return -ENOTTY;
	case FS_IOC_SETVERSION:
		return -ENOTTY;

	case FS_IOC_GOINGDOWN:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		down_write(&sb->s_umount);
		sb->s_flags |= MS_RDONLY;
		bch2_fs_emergency_read_only(c);
		up_write(&sb->s_umount);
		return 0;

	default:
		return bch2_fs_ioctl(c, cmd, (void __user *) arg);
	}
}

#ifdef CONFIG_COMPAT
long bch2_compat_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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
