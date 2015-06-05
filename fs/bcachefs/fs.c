
#include "bcache.h"
#include "acl.h"
#include "btree.h"
#include "buckets.h"
#include "dirent.h"
#include "extents.h"
#include "fs.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "super.h"
#include "xattr.h"

#include <linux/aio.h>
#include <linux/compat.h>
#include <linux/migrate.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>
#include <linux/xattr.h>

/*
 * our page flags:
 *
 * allocated - page has space on disk reserved for it (-ENOSPC was checked then,
 * shouldn't be checked later)
 *
 * corresponds to c->sectors_reserved
 *
 * append - page is dirty from an append write, new i_size can't be written
 * until after page is written
 *
 * corresponds to ei->append_count
 */

#define PF_ANY(page, enforce)	page
PAGEFLAG(Allocated, private, PF_ANY)
TESTSCFLAG(Allocated, private, PF_ANY)

PAGEFLAG(Append, private_2, PF_ANY)
TESTSCFLAG(Append, private_2, PF_ANY)
#undef PF_ANY

static struct bio_set *bch_writepage_bioset;
static struct kmem_cache *bch_inode_cache;
static DECLARE_WAIT_QUEUE_HEAD(bch_append_wait);

static void bch_inode_init(struct bch_inode_info *);
static int bch_read_single_page(struct page *, struct address_space *);

#define SECTORS_CACHE	1024

static int reserve_sectors(struct cache_set *c, unsigned sectors)
{
	if (likely(atomic_long_sub_return(sectors,
					  &c->sectors_reserved_cache) >= 0))
		return 0;

	atomic_long_add(SECTORS_CACHE, &c->sectors_reserved);

	if (likely(!cache_set_full(c))) {
		atomic_long_add(SECTORS_CACHE, &c->sectors_reserved_cache);
		return 0;
	}

	atomic_long_sub_bug(SECTORS_CACHE, &c->sectors_reserved);
	atomic_long_add(sectors, &c->sectors_reserved_cache);
	return -ENOSPC;
}

static void bch_append_put(struct bch_inode_info *ei)
{
	if (atomic_long_dec_and_test(&ei->append_count))
		wake_up(&bch_append_wait);
}

static void bch_clear_page_bits(struct cache_set *c, struct bch_inode_info *ei,
				struct page *page)
{
	if (TestClearPageAllocated(page))
		atomic_long_sub_bug(PAGE_SECTORS, &c->sectors_reserved);

	if (TestClearPageAppend(page))
		bch_append_put(ei);
}

static int __bch_write_inode(struct inode *inode)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_inode *bi = &ei->inode.v;

	lockdep_assert_held(&ei->update_lock);
	BUG_ON(ei->inode.k.p.inode != inode->i_ino);
	BUG_ON(ei->inode.k.type != BCH_INODE_FS);

	if (!atomic_long_read(&ei->append_count)) {
		bi->i_flags	&= ~BCH_INODE_I_SIZE_DIRTY;
		bi->i_size	= inode->i_size;
	}

	bi->i_mode	= inode->i_mode;
	bi->i_uid	= i_uid_read(inode);
	bi->i_gid	= i_gid_read(inode);
	bi->i_nlink	= inode->i_nlink;
	bi->i_dev	= inode->i_rdev;
	bi->i_atime	= timespec_to_ns(&inode->i_atime);
	bi->i_mtime	= timespec_to_ns(&inode->i_mtime);
	bi->i_ctime	= timespec_to_ns(&inode->i_ctime);

	return bch_inode_update(c, &ei->inode.k_i, &ei->journal_seq);
}

static struct inode *bch_vfs_inode_get(struct super_block *sb, u64 inum)
{
	struct cache_set *c = sb->s_fs_info;
	struct bch_inode_info *ei;
	struct inode *inode;
	int ret;

	pr_debug("inum %llu", inum);

	inode = iget_locked(sb, inum);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = to_bch_ei(inode);

	ret = bch_inode_find_by_inum(c, inum, &ei->inode);
	if (unlikely(ret)) {
		iget_failed(inode);
		return ERR_PTR(ret);
	}

	bch_inode_init(ei);
	unlock_new_inode(inode);

	return inode;
}

static void bch_set_inode_flags(struct inode *inode)
{
	unsigned flags = to_bch_ei(inode)->inode.v.i_flags;

	inode->i_flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
}

static struct inode *bch_vfs_inode_create(struct cache_set *c,
					  struct inode *parent,
					  umode_t mode, dev_t rdev)
{
	struct inode *inode;
	struct bch_inode_info *ei;
	struct bch_inode *bi;
	struct timespec ts = CURRENT_TIME;
	s64 now = timespec_to_ns(&ts);
	int ret;

	inode = new_inode(parent->i_sb);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, parent, mode);

	ei = to_bch_ei(inode);

	bi = &bkey_inode_init(&ei->inode.k_i)->v;
	bi->i_uid	= i_uid_read(inode);
	bi->i_gid	= i_gid_read(inode);

	bi->i_mode	= inode->i_mode;
	bi->i_dev	= rdev;
	bi->i_atime	= now;
	bi->i_mtime	= now;
	bi->i_ctime	= now;
	bi->i_nlink	= S_ISDIR(mode) ? 2 : 1;

	ret = bch_inode_create(c, &ei->inode.k_i,
			       BLOCKDEV_INODE_MAX, 0,
			       &c->unused_inode_hint);
	if (unlikely(ret)) {
		/*
		 * indicate to bch_evict_inode that the inode was never actually
		 * created:
		 */
		bkey_init(&ei->inode.k);
		goto err;
	}

	bch_inode_init(ei);

	ret = bch_init_acl(inode, parent);
	if (unlikely(ret))
		goto err;

	insert_inode_hash(inode);
	atomic_long_inc(&c->nr_inodes);

	return inode;
err:
	clear_nlink(inode);
	iput(inode);
	return ERR_PTR(ret);
}

static int bch_vfs_dirent_create(struct cache_set *c, struct inode *dir,
				 u8 type, const struct qstr *name,
				 struct inode *dst)
{
	struct bch_inode_info *ei = to_bch_ei(dst);
	int ret;

	ret = bch_dirent_create(c, dir->i_ino, type, name,
				dst->i_ino, &ei->journal_seq);
	if (unlikely(ret))
		return ret;

	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty_sync(dir);
	return 0;
}

static int __bch_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	int ret;

	inode = bch_vfs_inode_create(c, dir, mode, rdev);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	ret = bch_vfs_dirent_create(c, dir, mode_to_type(mode),
				    &dentry->d_name, inode);
	if (unlikely(ret)) {
		clear_nlink(inode);
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	return 0;
}

/* methods */

static struct dentry *bch_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = NULL;
	u64 inum;

	inum = bch_dirent_lookup(c, dir->i_ino, &dentry->d_name);

	if (inum)
		inode = bch_vfs_inode_get(dir->i_sb, inum);

	return d_splice_alias(inode, dentry);
}

static int bch_create(struct inode *dir, struct dentry *dentry,
		      umode_t mode, bool excl)
{
	return __bch_create(dir, dentry, mode|S_IFREG, 0);
}

static int bch_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = old_dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	int ret;

	lockdep_assert_held(&inode->i_rwsem);

	mutex_lock(&ei->update_lock);
	inode->i_ctime = CURRENT_TIME;
	inc_nlink(inode);
	__bch_write_inode(inode);
	mutex_unlock(&ei->update_lock);

	ihold(inode);

	ret = bch_vfs_dirent_create(c, dir, mode_to_type(inode->i_mode),
				    &dentry->d_name, inode);
	if (unlikely(ret)) {
		inode_dec_link_count(inode);
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	return 0;
}

static int bch_unlink(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	int ret;

	lockdep_assert_held(&inode->i_rwsem);

	ret = bch_dirent_delete(c, dir->i_ino, &dentry->d_name);
	if (ret)
		return ret;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);

	return 0;
}

static int bch_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	int ret;

	inode = bch_vfs_inode_create(c, dir, S_IFLNK|S_IRWXUGO, 0);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	inode_lock(inode);
	ret = page_symlink(inode, symname, strlen(symname) + 1);
	inode_unlock(inode);

	if (unlikely(ret))
		goto err;

	ret = bch_vfs_dirent_create(c, dir, DT_LNK, &dentry->d_name, inode);
	if (unlikely(ret))
		goto err;

	d_instantiate(dentry, inode);
	return 0;
err:
	clear_nlink(inode);
	iput(inode);
	return ret;
}

static int bch_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int ret;

	lockdep_assert_held(&dir->i_rwsem);

	inode_inc_link_count(dir);
	mark_inode_dirty_sync(dir);

	ret = __bch_create(dir, dentry, mode|S_IFDIR, 0);
	if (unlikely(ret)) {
		inode_dec_link_count(dir);
		return ret;
	}

	return 0;
}

static int bch_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	int ret;

	lockdep_assert_held(&inode->i_rwsem);
	lockdep_assert_held(&dir->i_rwsem);

	if (bch_empty_dir(c, inode->i_ino))
		return -ENOTEMPTY;

	ret = bch_unlink(dir, dentry);
	if (unlikely(ret))
		return ret;

	inode_dec_link_count(inode);
	inode_dec_link_count(dir);

	return 0;
}

static int bch_mknod(struct inode *dir, struct dentry *dentry,
		     umode_t mode, dev_t rdev)
{
	return __bch_create(dir, dentry, mode, rdev);
}

static int bch_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry,
		      unsigned flags)
{
	struct cache_set *c = old_dir->i_sb->s_fs_info;
	struct inode *old_inode = old_dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(old_inode);
	struct inode *new_inode = new_dentry->d_inode;
	struct timespec now = CURRENT_TIME;
	int ret;

	if (flags)
		return -EINVAL;

	lockdep_assert_held(&old_dir->i_rwsem);
	lockdep_assert_held(&new_dir->i_rwsem);

	/*
	 * XXX: This isn't atomic w.r.t. unclean shutdowns, and we'd really like
	 * it to be
	 */

	if (new_inode && S_ISDIR(old_inode->i_mode)) {
		lockdep_assert_held(&new_inode->i_rwsem);

		if (!S_ISDIR(new_inode->i_mode))
			return -ENOTDIR;

		if (bch_empty_dir(c, new_inode->i_ino))
			return -ENOTEMPTY;

		ret = bch_dirent_update(c, new_dir->i_ino,
					&new_dentry->d_name,
					old_inode->i_ino,
					&ei->journal_seq);
		if (unlikely(ret))
			return ret;

		clear_nlink(new_inode);
		inode_dec_link_count(old_dir);
	} else if (new_inode) {
		lockdep_assert_held(&new_inode->i_rwsem);

		ret = bch_dirent_update(c, new_dir->i_ino,
					&new_dentry->d_name,
					old_inode->i_ino,
					&ei->journal_seq);
		if (unlikely(ret))
			return ret;

		new_inode->i_ctime = now;
		inode_dec_link_count(new_inode);
	} else if (S_ISDIR(old_inode->i_mode)) {
		ret = bch_vfs_dirent_create(c, new_dir,
					    mode_to_type(old_inode->i_mode),
					    &new_dentry->d_name,
					    old_inode);
		if (unlikely(ret))
			return ret;

		inode_inc_link_count(new_dir);
		inode_dec_link_count(old_dir);
	} else {
		ret = bch_vfs_dirent_create(c, new_dir,
					    mode_to_type(old_inode->i_mode),
					    &new_dentry->d_name,
					    old_inode);
		if (unlikely(ret))
			return ret;
	}

	old_dir->i_ctime = old_dir->i_mtime = now;
	new_dir->i_ctime = new_dir->i_mtime = now;
	mark_inode_dirty_sync(old_dir);
	mark_inode_dirty_sync(new_dir);

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */
	mutex_lock(&ei->update_lock);
	old_inode->i_ctime = now;
	if (new_inode)
		old_inode->i_mtime = now;
	__bch_write_inode(old_inode);
	mutex_unlock(&ei->update_lock);

	/* XXX: error handling */
	bch_dirent_delete(c, old_dir->i_ino, &old_dentry->d_name);

	return 0;
}

static int bch_truncate_page(struct address_space *mapping, loff_t from)
{
	unsigned offset = from & (PAGE_SIZE - 1);
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!offset)
		return 0;

	page = grab_cache_page(mapping, from >> PAGE_SHIFT);
	if (unlikely(!page)) {
		ret = -ENOMEM;
		goto out;
	}

	if (!PageUptodate(page))
		if (bch_read_single_page(page, mapping)) {
			ret = -EIO;
			goto unlock;
		}

	zero_user_segment(page, offset, PAGE_SIZE);
	set_page_dirty(page);
unlock:
	unlock_page(page);
	put_page(page);
out:
	return ret;
}

static int bch_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret = 0;

	lockdep_assert_held(&inode->i_rwsem);

	pr_debug("i_size was %llu update has %llu",
		 inode->i_size, iattr->ia_size);

	ret = setattr_prepare(dentry, iattr);
	if (ret)
		return ret;

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size) {
		inode_dio_wait(inode);

		/*
		 * __bch_write_inode() clears I_SIZE_DIRTY if append_count == 0:
		 */
		atomic_long_inc(&ei->append_count);

		/*
		 * I_SIZE_DIRTY indicates that there's extents past the end of
		 * i_size, and must be set atomically with setting the new
		 * i_size:
		 */
		mutex_lock(&ei->update_lock);
		i_size_write(inode, iattr->ia_size);
		ei->inode.v.i_flags |= BCH_INODE_I_SIZE_DIRTY;
		ei->inode.v.i_size = iattr->ia_size;
		__bch_write_inode(inode);
		mutex_unlock(&ei->update_lock);

		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (unlikely(ret))
			return ret;

		if (iattr->ia_size > inode->i_size)
			pagecache_isize_extended(inode, inode->i_size,
						 iattr->ia_size);
		truncate_pagecache(inode, iattr->ia_size);

		ret = bch_inode_truncate(c, inode->i_ino,
				round_up(iattr->ia_size, PAGE_SIZE) >> 9);
		if (unlikely(ret))
			return ret;

		/*
		 * Extents discarded, now clear I_SIZE_DIRTY (which write_inode
		 * does when append_count is 0
		 */
		bch_append_put(ei);
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	}

	mutex_lock(&ei->update_lock);
	setattr_copy(inode, iattr);
	__bch_write_inode(inode);
	mutex_unlock(&ei->update_lock);

	if (iattr->ia_valid & ATTR_MODE)
		ret = posix_acl_chmod(inode, inode->i_mode);

	return ret;
}

static int bch_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;

	/* XXX: i_nlink should be 0? */
	inode = bch_vfs_inode_create(c, dir, mode, 0);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	d_tmpfile(dentry, inode);
	return 0;
}

static int bch_fill_extent(struct fiemap_extent_info *info,
			   struct bkey_i *k, int flags)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr) {
		int ret = fiemap_fill_next_extent(info,
					      bkey_start_offset(e.k) << 9,
					      ptr->offset << 9,
					      e.k->size << 9, flags);
		if (ret)
			return ret;
	}

	return 0;
}

static int bch_fiemap(struct inode *inode, struct fiemap_extent_info *info,
		      u64 start, u64 len)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	BKEY_PADDED(k) tmp;
	bool have_extent = false;
	int ret = 0;

	if (start + len < start)
		return -EINVAL;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(inode->i_ino, start >> 9), k)
		if (bkey_extent_is_data(k.k)) {
			if (bkey_cmp(bkey_start_pos(k.k),
				     POS(inode->i_ino, (start + len) >> 9)) >= 0)
				break;

			if (have_extent) {
				ret = bch_fill_extent(info, &tmp.k, 0);
				if (ret)
					goto out;
			}

			bkey_reassemble(&tmp.k, k);
			have_extent = true;
		}

	if (have_extent)
		ret = bch_fill_extent(info, &tmp.k, FIEMAP_EXTENT_LAST);
out:
	bch_btree_iter_unlock(&iter);
	return ret < 0 ? ret : 0;
}

static int bch_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct closure cl;
	int ret;

	closure_init_stack(&cl);

	/*
	 * We really just want to sync all the PageAppend pages:
	 */
	start = 0;
	end = S64_MAX;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	inode_lock(inode);
	if (datasync && end <= ei->inode.v.i_size)
		goto out;

	/*
	 * redo after locking inode:
	 */
	filemap_write_and_wait_range(inode->i_mapping, start, end);

	wait_event(bch_append_wait,
		   !atomic_long_read(&ei->append_count));

	mutex_lock(&ei->update_lock);
	BUG_ON(atomic_long_read(&ei->append_count));
	ret = __bch_write_inode(inode);
	mutex_unlock(&ei->update_lock);
out:
	inode_unlock(inode);

	bch_journal_push_seq(&c->journal, ei->journal_seq, &cl);
	closure_sync(&cl);

	return ret;
}

/* Flags that are appropriate for non-directories/regular files. */
#define BCH_OTHER_FLMASK	(FS_NODUMP_FL | FS_NOATIME_FL)

static inline bool bch_flags_allowed(umode_t mode, u32 flags)
{
	if ((flags & BCH_FL_USER_FLAGS) != flags)
		return false;

	if (!S_ISREG(mode) &&
	    !S_ISDIR(mode) &&
	    (flags & BCH_OTHER_FLMASK) != flags)
		return false;

	return true;
}

static long bch_fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct bch_inode_info *ei = to_bch_ei(inode);
	unsigned flags;
	int ret;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = ei->inode.v.i_flags & BCH_FL_USER_FLAGS;
		return put_user(flags, (int __user *) arg);

	case FS_IOC_SETFLAGS: {
		unsigned oldflags;

		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			goto setflags_out;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			goto setflags_out;
		}

		if (!bch_flags_allowed(inode->i_mode, flags)) {
			ret = -EINVAL;
			goto setflags_out;
		}

		inode_lock(inode);
		oldflags = ei->inode.v.i_flags;

		if (((flags ^ oldflags) & (FS_APPEND_FL|FS_IMMUTABLE_FL)) &&
		    !capable(CAP_LINUX_IMMUTABLE)) {
			inode_unlock(inode);
			ret = -EPERM;
			goto setflags_out;
		}

		flags = flags & BCH_FL_USER_FLAGS;
		flags |= oldflags & ~BCH_FL_USER_FLAGS;
		ei->inode.v.i_flags = flags;

		inode->i_ctime = CURRENT_TIME_SEC;
		bch_set_inode_flags(inode);
		inode_unlock(inode);

		mark_inode_dirty(inode);
setflags_out:
		mnt_drop_write_file(filp);
		return ret;
	}
		return 0;
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long bch_compat_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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
	return bch_fs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

static loff_t bch_dir_llseek(struct file *file, loff_t offset, int whence)
{
	return generic_file_llseek_size(file, offset, whence,
					S64_MAX, S64_MAX);
}

static const struct file_operations bch_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.fsync		= bch_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,

	.unlocked_ioctl = bch_fs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bch_compat_fs_ioctl,
#endif
};

static const struct inode_operations bch_file_inode_operations = {
	.setattr	= bch_setattr,
	.fiemap		= bch_fiemap,
	.listxattr	= bch_xattr_list,
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
};

static const struct inode_operations bch_dir_inode_operations = {
	.lookup		= bch_lookup,
	.create		= bch_create,
	.link		= bch_link,
	.unlink		= bch_unlink,
	.symlink	= bch_symlink,
	.mkdir		= bch_mkdir,
	.rmdir		= bch_rmdir,
	.mknod		= bch_mknod,
	.rename		= bch_rename,
	.setattr	= bch_setattr,
	.tmpfile	= bch_tmpfile,
	.listxattr	= bch_xattr_list,
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
};

static const struct file_operations bch_dir_file_operations = {
	.llseek		= bch_dir_llseek,
	.read		= generic_read_dir,
	.iterate	= bch_readdir,
	.fsync		= bch_fsync,

	.unlocked_ioctl = bch_fs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bch_compat_fs_ioctl,
#endif
};

static const struct inode_operations bch_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= page_get_link,
	.setattr	= bch_setattr,

	.listxattr	= bch_xattr_list,
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
};

static const struct inode_operations bch_special_inode_operations = {
	.setattr	= bch_setattr,
	.listxattr	= bch_xattr_list,
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
};

static int bch_bio_add_page(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << (PAGE_SHIFT - 9);

	if (!bio->bi_vcnt) {
		bio->bi_iter.bi_sector = offset;
	} else if (bio_end_sector(bio) != offset ||
		   bio->bi_vcnt == bio->bi_max_vecs)
		return -1;

	bio->bi_io_vec[bio->bi_vcnt++] = (struct bio_vec) {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};

	bio->bi_iter.bi_size += PAGE_SIZE;

	return 0;
}

static void bch_readpages_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!bio->bi_error) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

static int bch_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = NULL;
	struct page *page;
	ssize_t ret;

	pr_debug("reading %u pages", nr_pages);

	while (nr_pages) {
		page = list_entry(pages->prev, struct page, lru);
		prefetchw(&page->flags);
		list_del(&page->lru);

		if (!add_to_page_cache_lru(page, mapping,
					   page->index, GFP_NOFS)) {
again:
			if (!bio) {
				bio = bio_alloc(GFP_NOFS,
						min_t(unsigned, nr_pages,
						      BIO_MAX_PAGES));

				bio->bi_end_io = bch_readpages_end_io;
			}

			if (bch_bio_add_page(bio, page)) {
				ret = bch_read(c, bio, inode->i_ino);
				bio_endio(bio);
				bio = NULL;

				if (ret < 0) {
					pr_debug("error %zi", ret);
					return ret;
				}
				goto again;
			}
		}

		nr_pages--;
		put_page(page);
	}

	if (bio) {
		ret = bch_read(c, bio, inode->i_ino);
		bio_endio(bio);

		if (ret < 0) {
			pr_debug("error %zi", ret);
			return ret;
		}
	}

	pr_debug("success");
	return 0;
}

static int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret;

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);

	ret = bch_read(c, bio, inode->i_ino);
	bio_endio(bio);

	return ret;
}

struct bch_writepage_io {
	struct closure		cl;
	struct bch_write_op	op;
	struct bch_write_bio	bio;
};

struct bch_writepage {
	struct cache_set	*c;
	u64			inum;
	struct bch_writepage_io	*io;
};

static void bch_writepage_io_free(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct cache_set *c = io->op.c;
	struct bio *bio = &io->bio.bio.bio;
	struct inode *inode = bio->bi_io_vec[0].bv_page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		BUG_ON(!PageWriteback(page));

		if (io->bio.bio.bio.bi_error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		bch_clear_page_bits(c, ei, page);
		end_page_writeback(page);
	}

	bio_put(bio);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	pr_debug("writing %u sectors to %llu:%llu",
		 bio_sectors(&io->bio.bio.bio),
		 io->op.insert_key.k.p.inode,
		 (u64) io->bio.bio.bio.bi_iter.bi_sector);

	closure_call(&io->op.cl, bch_write, NULL, &io->cl);
	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_writepage *w = data;
	struct bio *bio;
	unsigned offset;
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_SHIFT;

	/* Is the page fully inside i_size? */
	if (page->index < end_index)
		goto do_io;

	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_SIZE - 1);
	if (page->index > end_index || !offset) {
		unlock_page(page);
		return 0;
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, offset, PAGE_SIZE);
do_io:
	/* XXX: how we gonna make this synchronization efficient? */
	mutex_lock(&ei->update_lock);

	if (ei->inode.v.i_size < i_size &&
	    page->index >= (ei->inode.v.i_size >> PAGE_SHIFT) &&
	    !(ei->inode.v.i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		ei->inode.v.i_flags |= BCH_INODE_I_SIZE_DIRTY;
		__bch_write_inode(inode);
	}

	mutex_unlock(&ei->update_lock);

	if (!w->io) {
		bio = bio_alloc_bioset(GFP_NOFS, BIO_MAX_PAGES,
				       bch_writepage_bioset);
		w->io = container_of(bio, struct bch_writepage_io, bio.bio.bio);

		closure_init(&w->io->cl, NULL);
		bch_write_op_init(&w->io->op, w->c, &w->io->bio, NULL,
				  bkey_to_s_c(&KEY(w->inum, 0, 0)),
				  bkey_s_c_null,
				  &ei->journal_seq, 0);
	}

	if (bch_bio_add_page(&w->io->bio.bio.bio, page)) {
		bch_writepage_do_io(w->io);
		w->io = NULL;
		goto do_io;
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

static int bch_writepages(struct address_space *mapping,
			  struct writeback_control *wbc)
{
	int ret;
	struct bch_writepage w = {
		.c	= mapping->host->i_sb->s_fs_info,
		.inum	= mapping->host->i_ino,
		.io	= NULL,
	};

	ret = write_cache_pages(mapping, wbc, __bch_writepage, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

	return ret;
}

static int bch_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct bch_writepage w = {
		.c = inode->i_sb->s_fs_info,
		.inum = inode->i_ino,
		.io = NULL,
	};

	__bch_writepage(page, NULL, &w);
	bch_writepage_do_io(w.io);

	return 0;
}

static void bch_read_single_page_end_io(struct bio *bio)
{
	complete(bio->bi_private);
}

static int bch_read_single_page(struct page *page,
				struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(done);

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_private = &done;
	bio->bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(bio, page);

	ret = bch_read(c, bio, inode->i_ino);
	bio_endio(bio);
	wait_for_completion(&done);

	if (!ret)
		ret = bio->bi_error;
	bio_put(bio);

	if (ret < 0)
		return ret;

	SetPageUptodate(page);

	return 0;
}

static int bch_write_begin(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned flags,
			   struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *page;
	int ret = 0;

	BUG_ON(inode_unhashed(mapping->host));

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	if (!PageAllocated(page)) {
		if (reserve_sectors(c, PAGE_SECTORS)) {
			ret = -ENOSPC;
			goto err;
		}

		SetPageAllocated(page);
	}

	if (PageUptodate(page))
		goto out;

	/* If we're writing entire page, don't need to read it in first: */
	if (len == PAGE_SIZE)
		goto out;

	if (pos + len >= inode->i_size) {
		unsigned offset = pos & (PAGE_SIZE - 1);

		/*
		 * If the write extents past i_size, the top part of the page
		 * we're not writing to doesn't need to be read in, just zeroed:
		 */
		zero_user(page, offset + len, PAGE_SIZE - offset - len);
		flush_dcache_page(page);

		if (!offset)
			goto out;

		/*
		 * If the start of the page is past i_size, zero that part too:
		 */
		if ((index << PAGE_SHIFT) >> inode->i_size) {
			zero_user(page, 0, offset);
			flush_dcache_page(page);
			goto out;
		}
	}

	ret = bch_read_single_page(page, mapping);
	if (ret)
		goto err;
out:
	*pagep = page;
	return ret;
err:
	unlock_page(page);
	put_page(page);
	page = NULL;
	goto out;
}

static int bch_write_end(struct file *filp, struct address_space *mapping,
			 loff_t pos, unsigned len, unsigned copied,
			 struct page *page, void *fsdata)
{
	loff_t last_pos = pos + copied;
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);

	/*
	 * can't set a page dirty without i_rwsem, to avoid racing with truncate
	 */
	lockdep_assert_held(&inode->i_rwsem);

	if (unlikely(copied < len)) {
#if 0
		if (!PageUptodate(page)) {
			/* we skipped reading in the page before, read it now..  */
		}
#endif

		/*
		 * zero out the rest of the area
		 */
		unsigned from = pos & (PAGE_SIZE - 1);

		zero_user(page, from + copied, len - copied);
		flush_dcache_page(page);
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (!PageDirty(page))
		set_page_dirty(page);

	if (last_pos > inode->i_size) {
		mutex_lock(&ei->update_lock);

		if (!TestSetPageAppend(page))
			atomic_long_inc(&ei->append_count);

		i_size_write(inode, last_pos);
		mark_inode_dirty(inode);

		mutex_unlock(&ei->update_lock);
	}

	unlock_page(page);
	put_page(page);

	return copied;
}

static void bch_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (offset || length < PAGE_SIZE)
		return;

	bch_clear_page_bits(c, ei, page);
}

static int bch_releasepage(struct page *page, gfp_t gfp_mask)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	bch_clear_page_bits(c, ei, page);

	if (PageDirty(page)) {
		ClearPageDirty(page);
		cancel_dirty_page(page);
	}

	return 1;
}

/* O_DIRECT */

static struct bio_set *bch_dio_read_bioset;

struct dio_read {
	struct closure		cl;
	struct kiocb		*req;
	long			ret;
	struct bio		bio;
};

static void bch_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret, 0);
	bio_put(&dio->bio);
}

static void bch_direct_IO_read_endio(struct bio *bio)
{
	struct dio_read *dio = bio->bi_private;

	if (bio->bi_error)
		dio->ret = bio->bi_error;

	closure_put(&dio->cl);
	bio_check_pages_dirty(bio);	/* transfers ownership */
}

static int bch_direct_IO_read(struct cache_set *c, struct kiocb *req,
			      struct file *file, struct inode *inode,
			      struct iov_iter *iter, loff_t offset)
{
	struct dio_read *dio;
	struct bio *bio;
	unsigned long inum = inode->i_ino;
	ssize_t ret = 0;
	size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);
	loff_t i_size;

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_read_bioset);
	bio_get(bio);

	dio = container_of(bio, struct dio_read, bio);
	closure_init(&dio->cl, NULL);
	dio->req	= req;
	dio->ret	= iter->count;

	i_size = i_size_read(inode);
	if (offset + dio->ret > i_size) {
		dio->ret = max_t(loff_t, 0, i_size - offset);
		iter->count = round_up(dio->ret, PAGE_SIZE);
	}

	if (!dio->ret)
		goto out;

	goto start;
	while (iter->count && !ret) {
		pages = iov_iter_npages(iter, BIO_MAX_PAGES);
		bio = bio_alloc(GFP_KERNEL, pages);
start:
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_end_io		= bch_direct_IO_read_endio;
		bio->bi_private		= dio;

		ret = bio_get_user_pages(bio, iter, 1);
		if (ret < 0) {
			dio->ret = ret;
			bio_put(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;
		bio_set_pages_dirty(bio);

		closure_get(&dio->cl);
		ret = bch_read(c, bio, inum);
		if (ret)
			bio->bi_error = ret;
		bio_endio(bio);
	}
out:
	if (is_sync_kiocb(req)) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_put(&dio->bio);
		return ret;
	} else {
		closure_return_with_destructor_noreturn(&dio->cl,
						bch_dio_read_complete);
		return -EIOCBQUEUED;
	}
}

struct dio_write {
	struct closure		cl;
	struct kiocb		*req;
	long			ret;
	bool			append;
};

struct dio_write_bio {
	struct closure		cl;
	struct dio_write	*dio;
	struct bch_write_op	iop;
	struct bch_write_bio	bio;
};

static void __bch_dio_write_complete(struct dio_write *dio)
{
	struct bch_inode_info *ei = to_bch_ei(dio->req->ki_filp->f_inode);

	if (dio->append)
		bch_append_put(ei);
	inode_dio_end(dio->req->ki_filp->f_inode);
	kfree(dio);
}

static void bch_dio_write_complete(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);
	struct kiocb *req = dio->req;
	long ret = dio->ret;

	__bch_dio_write_complete(dio);
	req->ki_complete(req, ret, 0);
}

static void bch_direct_IO_write_done(struct closure *cl)
{
	struct dio_write_bio *op =
		container_of(cl, struct dio_write_bio, cl);
	struct bio_vec *bv;
	int i;

	if (op->iop.error)
		op->dio->ret = op->iop.error;
	closure_put(&op->dio->cl);

	bio_for_each_segment_all(bv, &op->bio.bio.bio, i)
		put_page(bv->bv_page);
	kfree(op);
}

static int bch_direct_IO_write(struct cache_set *c, struct kiocb *req,
			       struct file *file, struct inode *inode,
			       struct iov_iter *iter, loff_t offset)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct dio_write *dio;
	struct dio_write_bio *op;
	struct bio *bio;
	unsigned long inum = inode->i_ino;
	unsigned flags = BCH_WRITE_CHECK_ENOSPC;
	ssize_t ret = 0;

	lockdep_assert_held(&inode->i_rwsem);

	if (file->f_flags & O_DSYNC || IS_SYNC(file->f_mapping->host))
		flags |= BCH_WRITE_FLUSH;

	dio = kmalloc(sizeof(*dio), GFP_NOIO);
	if (!dio)
		return -ENOMEM;

	closure_init(&dio->cl, NULL);
	dio->req	= req;
	dio->ret	= iter->count;
	dio->append	= false;

	if (offset + iter->count > inode->i_size) {
		dio->append = true;
		atomic_long_inc(&ei->append_count);

		mutex_lock(&ei->update_lock);
		if (!(ei->inode.v.i_flags & BCH_INODE_I_SIZE_DIRTY)) {
			ei->inode.v.i_flags |= BCH_INODE_I_SIZE_DIRTY;
			__bch_write_inode(inode);
		}
		mutex_unlock(&ei->update_lock);
	}

	/* Decremented by inode_dio_done(): */
	atomic_inc(&inode->i_dio_count);

	while (iter->count) {
		size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);

		op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages,
			     GFP_NOIO);
		if (!op) {
			dio->ret = -ENOMEM;
			break;
		}

		bio = &op->bio.bio.bio;
		bio_init(bio);
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_max_vecs	= pages;
		bio->bi_io_vec		= bio->bi_inline_vecs;

		ret = bio_get_user_pages(bio, iter, 0);
		if (ret < 0) {
			dio->ret = ret;
			kfree(op);
			break;
		}

		offset += bio->bi_iter.bi_size;
		closure_get(&dio->cl);
		op->dio = dio;
		closure_init(&op->cl, NULL);

		bch_write_op_init(&op->iop, c, &op->bio, NULL,
				  bkey_to_s_c(&KEY(inum,
						   bio_end_sector(bio),
						   bio_sectors(bio))),
				  bkey_s_c_null,
				  &ei->journal_seq, flags);

		task_io_account_write(bio->bi_iter.bi_size);

		closure_call(&op->iop.cl, bch_write, NULL, &op->cl);
		closure_return_with_destructor_noreturn(&op->cl,
						bch_direct_IO_write_done);
	}

	if (is_sync_kiocb(req) || dio->append) {
		/*
		 * appends are sync in order to do the i_size update under
		 * i_rwsem, after we know the write has completed successfully
		 */
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;

		if (ret > 0 &&
		    offset > inode->i_size) {
			i_size_write(inode, offset);
			mark_inode_dirty(inode);
		}

		__bch_dio_write_complete(dio);
		return ret;
	} else {
		closure_return_with_destructor_noreturn(&dio->cl,
						bch_dio_write_complete);
		return -EIOCBQUEUED;
	}
}

static ssize_t bch_direct_IO(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct inode *inode = file->f_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;

	if ((req->ki_pos|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	return ((iov_iter_rw(iter) == WRITE)
		? bch_direct_IO_write
		: bch_direct_IO_read)(c, req, file, inode, iter, req->ki_pos);
}

#ifdef CONFIG_MIGRATION
static int bch_migrate_page(struct address_space *mapping,
			    struct page *newpage, struct page *page,
			    enum migrate_mode mode)
{
	int ret;

	ret = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);
	if (ret != MIGRATEPAGE_SUCCESS)
		return ret;

	if (PageAllocated(page)) {
		ClearPageAllocated(page);
		SetPageAllocated(newpage);
	}

	if (PageAppend(page)) {
		ClearPageAppend(page);
		SetPageAppend(newpage);
	}

	migrate_page_copy(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
#endif

static const struct address_space_operations bch_address_space_operations = {
	.writepage		= bch_writepage,
	.readpage		= bch_readpage,
	.writepages		= bch_writepages,
	.readpages		= bch_readpages,

	.set_page_dirty		= __set_page_dirty_nobuffers,

	.write_begin		= bch_write_begin,
	.write_end		= bch_write_end,
	.invalidatepage		= bch_invalidatepage,
	.releasepage		= bch_releasepage,

	.direct_IO		= bch_direct_IO,

#ifdef CONFIG_MIGRATION
	.migratepage		= bch_migrate_page,
#endif
	.error_remove_page	= generic_error_remove_page,
};

static void bch_inode_init(struct bch_inode_info *ei)
{
	struct inode *inode = &ei->vfs_inode;
	struct bch_inode *bi = &ei->inode.v;

	pr_debug("init inode %llu with mode %o",
		 ei->inode.k.p.inode, bi->i_mode);

	BUG_ON(atomic_long_read(&ei->append_count));

	inode->i_mode	= bi->i_mode;
	i_uid_write(inode, bi->i_uid);
	i_gid_write(inode, bi->i_gid);

	inode->i_ino	= ei->inode.k.p.inode;
	set_nlink(inode, bi->i_nlink);
	inode->i_rdev	= bi->i_dev;
	inode->i_size	= bi->i_size;
	inode->i_atime	= ns_to_timespec(bi->i_atime);
	inode->i_mtime	= ns_to_timespec(bi->i_mtime);
	inode->i_ctime	= ns_to_timespec(bi->i_ctime);
	bch_set_inode_flags(inode);

	inode->i_mapping->a_ops = &bch_address_space_operations;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &bch_file_inode_operations;
		inode->i_fop = &bch_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &bch_dir_inode_operations;
		inode->i_fop = &bch_dir_file_operations;
		break;
	case S_IFLNK:
		inode_nohighmem(inode);
		inode->i_op = &bch_symlink_inode_operations;
		break;
	default:
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		inode->i_op = &bch_special_inode_operations;
		break;
	}
}

static struct inode *bch_alloc_inode(struct super_block *sb)
{
	struct bch_inode_info *ei;

	ei = kmem_cache_alloc(bch_inode_cache, GFP_NOFS);
	if (!ei)
		return NULL;

	pr_debug("allocated %p", &ei->vfs_inode);

	inode_init_once(&ei->vfs_inode);
	mutex_init(&ei->update_lock);
	ei->journal_seq = 0;
	atomic_long_set(&ei->append_count, 0);

	return &ei->vfs_inode;
}

static void bch_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(bch_inode_cache, to_bch_ei(inode));
}

static void bch_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, bch_i_callback);
}

static int bch_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	int ret;

	mutex_lock(&ei->update_lock);
	ret = __bch_write_inode(inode);
	mutex_unlock(&ei->update_lock);

	if (!ret && wbc->sync_mode == WB_SYNC_ALL) {
		struct closure cl;

		closure_init_stack(&cl);
		bch_journal_push_seq(&c->journal, ei->journal_seq, &cl);
		closure_sync(&cl);
	}

	return ret;
}

static void bch_evict_inode(struct inode *inode)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);

	if (inode->i_nlink) {
		truncate_inode_pages_final(&inode->i_data);

		mutex_lock(&ei->update_lock);
		BUG_ON(atomic_long_read(&ei->append_count));

		if (!(inode->i_state & I_NEW) &&
		    (ei->inode.v.i_flags & BCH_INODE_I_SIZE_DIRTY ||
		     inode->i_size != ei->inode.v.i_size))
			__bch_write_inode(inode);
		mutex_unlock(&ei->update_lock);

		clear_inode(inode);
	} else if (!bkey_deleted(&ei->inode.k)) {
		atomic_long_inc(&ei->append_count);

		mutex_lock(&ei->update_lock);
		ei->inode.v.i_flags |= BCH_INODE_I_SIZE_DIRTY;
		ei->inode.v.i_size = 0;
		i_size_write(inode, 0);
		__bch_write_inode(inode);
		mutex_unlock(&ei->update_lock);

		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);

		/*
		 * write_inode() shouldn't be called again - this will cause it
		 * to BUG():
		 */
		ei->inode.k.type = KEY_TYPE_DELETED;
		atomic_long_dec_bug(&ei->append_count);

		bch_inode_rm(c, inode->i_ino);
		atomic_long_dec(&c->nr_inodes);
	} else {
		/* bch_inode_create() failed: */
		clear_inode(inode);
	}
}

static int bch_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct cache_set *c = sb->s_fs_info;

	buf->f_type	= BCACHE_STATFS_MAGIC;
	buf->f_bsize	= sb->s_blocksize;
	buf->f_blocks	= c->capacity >> (PAGE_SHIFT - 9);
	buf->f_bfree	= (c->capacity - cache_set_sectors_used(c)) >>
		(PAGE_SHIFT - 9);
	buf->f_bavail	= buf->f_bfree;
	buf->f_files	= atomic_long_read(&c->nr_inodes);
	buf->f_namelen	= NAME_MAX;

	return 0;
}

static int bch_sync_fs(struct super_block *sb, int wait)
{
	struct cache_set *c = sb->s_fs_info;
	struct closure cl;

	closure_init_stack(&cl);

	/* XXX: should only push a journal write if it's dirty */
	bch_journal_flush(&c->journal, wait ? &cl : NULL);
	closure_sync(&cl);
	return 0;
}

static struct cache_set *bch_open_as_blockdevs(const char *_dev_name,
					       struct cache_set_opts opts)
{
	size_t nr_devs = 0, i = 0;
	char *dev_name, *s, **devs;
	struct cache_set *c = NULL;
	const char *err;

	dev_name = kstrdup(_dev_name, GFP_KERNEL);
	if (!dev_name)
		return NULL;

	for (s = dev_name; s; s = strchr(s + 1, ':'))
		nr_devs++;

	devs = kcalloc(nr_devs, sizeof(const char *), GFP_KERNEL);
	if (!devs)
		goto out;

	for (i = 0, s = dev_name;
	     s;
	     (s = strchr(s, ':')) && (*s++ = '\0'))
		devs[i++] = s;

	err = bch_register_cache_set(devs, nr_devs, opts, &c);
	if (err) {
		pr_err("register_cache_set err %s", err);
		goto out;
	}

	set_bit(CACHE_SET_BDEV_MOUNTED, &c->flags);
out:
	kfree(devs);
	kfree(dev_name);

	return c;
}

enum {
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_user_xattr, Opt_nouser_xattr,
	Opt_acl, Opt_noacl,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_err, NULL}
};

static int parse_options(struct cache_set_opts *opts, int flags, char *options)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	*opts = cache_set_opts_empty();

	opts->read_only = (flags & MS_RDONLY) != 0;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_err_panic:
			opts->on_error_action = BCH_ON_ERROR_PANIC;
			break;
		case Opt_err_ro:
			opts->on_error_action = BCH_ON_ERROR_RO;
			break;
		case Opt_err_cont:
			opts->on_error_action = BCH_ON_ERROR_CONTINUE;
			break;
		case Opt_user_xattr:
		case Opt_nouser_xattr:
			break;
		case Opt_acl:
			opts->posix_acl = true;
			break;
		case Opt_noacl:
			opts->posix_acl = false;
			break;
		default:
			return 0;
		}
	}

	return 1;
}

static int bch_remount(struct super_block *sb, int *flags, char *data)
{
	struct cache_set *c = sb->s_fs_info;
	struct cache_set_opts opts;
	int ret = 0;

	if (!parse_options(&opts, *flags, data))
		return EINVAL;

	mutex_lock(&bch_register_lock);

	if (opts.read_only >= 0 &&
	    opts.read_only != c->opts.read_only) {
		const char *err = NULL;

		if (opts.read_only) {
			bch_cache_set_read_only(c);

			sb->s_flags |= MS_RDONLY;
		} else {
			err = bch_cache_set_read_write(c);
			if (err) {
				pr_info("error going rw");
				ret = -EINVAL;
				goto unlock;
			}

			sb->s_flags &= ~MS_RDONLY;
		}

		c->opts.read_only = opts.read_only;
	}

	if (opts.on_error_action >= 0)
		c->opts.on_error_action = opts.on_error_action;

unlock:
	mutex_unlock(&bch_register_lock);

	return ret;
}

static const struct super_operations bch_super_operations = {
	.alloc_inode	= bch_alloc_inode,
	.destroy_inode	= bch_destroy_inode,
	.write_inode	= bch_write_inode,
	.evict_inode	= bch_evict_inode,
	.sync_fs	= bch_sync_fs,
	.statfs		= bch_statfs,
	.show_options	= generic_show_options,
	.remount_fs	= bch_remount,
#if 0
	.put_super	= bch_put_super,
	.freeze_fs	= bch_freeze,
	.unfreeze_fs	= bch_unfreeze,
#endif
};

static struct dentry *bch_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	struct cache_set *c;
	struct super_block *sb;
	struct inode *inode;
	struct cache_set_opts opts;
	int ret;

	if (!parse_options(&opts, flags, data))
		return ERR_PTR(-EINVAL);

	c = bch_open_as_blockdevs(dev_name, opts);
	if (!c)
		return ERR_PTR(-ENOENT);

	sb = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(sb)) {
		ret = PTR_ERR(sb);
		goto err;
	}

	/* XXX: blocksize */
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_op		= &bch_super_operations;
	sb->s_xattr		= bch_xattr_handlers;
	sb->s_magic		= BCACHE_STATFS_MAGIC;
	sb->s_time_gran		= 1;
	sb->s_fs_info		= c;

	if (opts.posix_acl < 0)
		sb->s_flags	|= MS_POSIXACL;
	else
		sb->s_flags	|= opts.posix_acl ? MS_POSIXACL : 0;

	/* XXX: do we even need s_bdev? */
	sb->s_bdev		= c->cache[0]->disk_sb.bdev;
	sb->s_bdi		= &c->bdi;

	inode = bch_vfs_inode_get(sb, BCACHE_ROOT_INO);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto err_put_super;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_put_super;
	}

	sb->s_flags |= MS_ACTIVE;
	return dget(sb->s_root);

err_put_super:
	deactivate_locked_super(sb);
err:
	closure_put(&c->cl);
	return ERR_PTR(ret);
}

static void bch_kill_sb(struct super_block *sb)
{
	struct cache_set *c = sb->s_fs_info;

	generic_shutdown_super(sb);

	if (test_bit(CACHE_SET_BDEV_MOUNTED, &c->flags)) {
		DECLARE_COMPLETION_ONSTACK(complete);

		c->stop_completion = &complete;
		bch_cache_set_stop(c);
		closure_put(&c->cl);

		/* Killable? */
		wait_for_completion(&complete);
	} else
		closure_put(&c->cl);
}

static struct file_system_type bcache_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bcache",
	.mount		= bch_mount,
	.kill_sb	= bch_kill_sb,
};

MODULE_ALIAS_FS("bcache");

void bch_fs_exit(void)
{
	unregister_filesystem(&bcache_fs_type);
	if (bch_dio_read_bioset)
		bioset_free(bch_dio_read_bioset);
	if (bch_writepage_bioset)
		bioset_free(bch_writepage_bioset);
	if (bch_inode_cache)
		kmem_cache_destroy(bch_inode_cache);
}

int __init bch_fs_init(void)
{
	int ret = -ENOMEM;

	bch_inode_cache = KMEM_CACHE(bch_inode_info, 0);
	if (!bch_inode_cache)
		goto err;

	bch_writepage_bioset =
		bioset_create(4, offsetof(struct bch_writepage_io, bio.bio.bio));
	if (!bch_writepage_bioset)
		goto err;


	bch_dio_read_bioset = bioset_create(4, offsetof(struct dio_read, bio));
	if (!bch_dio_read_bioset)
		goto err;

	ret = register_filesystem(&bcache_fs_type);
	if (ret)
		goto err;

	return 0;
err:
	bch_fs_exit();
	return ret;
}
