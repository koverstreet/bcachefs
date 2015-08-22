
#include "bcache.h"
#include "acl.h"
#include "btree_update.h"
#include "buckets.h"
#include "dirent.h"
#include "extents.h"
#include "fs.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "super.h"
#include "xattr.h"

#include <linux/aio.h>
#include <linux/compat.h>
#include <linux/migrate.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>
#include <linux/xattr.h>

/*
 * our page flags:
 *
 * allocated - page has space on disk reserved for it (c->sectors_reserved) -
 * -ENOSPC was checked then, shouldn't be checked later
 *
 * append - page is dirty from an append write, new i_size can't be written
 * until after page is written; ref held on ei->i_size_dirty_count
 */

#define PF_ANY(page, enforce)	page
PAGEFLAG(Allocated, private, PF_ANY)
TESTSCFLAG(Allocated, private, PF_ANY)

PAGEFLAG(Append, private_2, PF_ANY)
TESTSCFLAG(Append, private_2, PF_ANY)
#undef PF_ANY

static struct bio_set *bch_writepage_bioset;
static struct kmem_cache *bch_inode_cache;

static void bch_inode_init(struct bch_inode_info *, struct bkey_s_c_inode);
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

static void i_size_dirty_put(struct bch_inode_info *ei)
{
	atomic_long_dec_bug(&ei->i_size_dirty_count);
}

static void i_size_dirty_get(struct bch_inode_info *ei)
{
	lockdep_assert_held(&ei->vfs_inode.i_rwsem);

	atomic_long_inc(&ei->i_size_dirty_count);
}

static void bch_clear_page_bits(struct cache_set *c, struct bch_inode_info *ei,
				struct page *page)
{
	if (TestClearPageAllocated(page))
		atomic_long_sub_bug(PAGE_SECTORS, &c->sectors_reserved);

	if (TestClearPageAppend(page))
		i_size_dirty_put(ei);
}

/* returns true if we want to do the update */
typedef int (*inode_set_fn)(struct bch_inode_info *, struct bch_inode *);

/*
 * I_SIZE_DIRTY requires special handling:
 *
 * To the recovery code, the flag means that there is stale data past i_size
 * that needs to be deleted; it's used for implementing atomic appends and
 * truncates.
 *
 * On append, we set I_SIZE_DIRTY before doing the write, then after the write
 * we clear I_SIZE_DIRTY atomically with updating i_size to the new larger size
 * that exposes the data we just wrote.
 *
 * On truncate, it's the reverse: We set I_SIZE_DIRTY atomically with setting
 * i_size to the new smaller size, then we delete the data that we just made
 * invisible, and then we clear I_SIZE_DIRTY.
 *
 * Because there can be multiple appends in flight at a time, we need a refcount
 * (i_size_dirty_count) instead of manipulating the flag directly. Nonzero
 * refcount means I_SIZE_DIRTY is set, zero means it's cleared.
 *
 * Because write_inode() can be called at any time, i_size_dirty_count means
 * something different to the runtime code - it means to write_inode() "don't
 * update i_size yet".
 *
 * We don't clear I_SIZE_DIRTY directly, we let write_inode() clear it when
 * i_size_dirty_count is zero - but the reverse is not true, I_SIZE_DIRTY must
 * be set explicitly.
 */

static int inode_maybe_clear_dirty(struct bch_inode_info *ei,
				    struct bch_inode *bi)
{
	lockdep_assert_held(&ei->update_lock);

	/* we kind of want i_size_dirty_count to be a rwlock */

	if (!atomic_long_read(&ei->i_size_dirty_count)) {
		bi->i_flags	&= ~BCH_INODE_I_SIZE_DIRTY;
		bi->i_size	= i_size_read(&ei->vfs_inode);
	}
	return 0;
}

static int inode_set_dirty(struct bch_inode_info *ei,
			   struct bch_inode *bi)
{
	if (bi->i_flags & BCH_INODE_I_SIZE_DIRTY)
		return 1;

	bi->i_flags |= BCH_INODE_I_SIZE_DIRTY;
	return 0;
}

static int __must_check __bch_write_inode(struct cache_set *c,
					  struct bch_inode_info *ei,
					  inode_set_fn set)
{
	struct btree_iter iter;
	struct inode *vfs_inode = &ei->vfs_inode;
	struct bkey_i_inode inode;
	struct bch_inode *bi;
	u64 inum = vfs_inode->i_ino;
	int ret;

	lockdep_assert_held(&ei->update_lock);

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(inum, 0));

	do {
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);

		if (WARN_ONCE(!k.k || k.k->type != BCH_INODE_FS,
			      "inode %llu not found when updating", inum)) {
			bch_btree_iter_unlock(&iter);
			return -ENOENT;
		}

		bkey_reassemble(&inode.k_i, k);
		bi = &inode.v;

		ret = set(ei, bi);
		if (ret)
			goto out;

		bi->i_mode	= vfs_inode->i_mode;
		bi->i_uid	= i_uid_read(vfs_inode);
		bi->i_gid	= i_gid_read(vfs_inode);
		bi->i_nlink	= vfs_inode->i_nlink;
		bi->i_dev	= vfs_inode->i_rdev;
		bi->i_atime	= timespec_to_ns(&vfs_inode->i_atime);
		bi->i_mtime	= timespec_to_ns(&vfs_inode->i_mtime);
		bi->i_ctime	= timespec_to_ns(&vfs_inode->i_ctime);

		ret = bch_btree_insert_at(&iter, &keylist_single(&inode.k_i),
					  NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
	} while (ret == -EINTR);

	if (!ret) {
		ei->i_size	= bi->i_size;
		ei->i_flags	= bi->i_flags;
	}
out:
	bch_btree_iter_unlock(&iter);

	return ret < 0 ? ret : 0;
}

static int __must_check bch_write_inode(struct cache_set *c,
					struct bch_inode_info *ei)
{
	return __bch_write_inode(c, ei, inode_maybe_clear_dirty);
}

static struct inode *bch_vfs_inode_get(struct super_block *sb, u64 inum)
{
	struct cache_set *c = sb->s_fs_info;
	struct inode *inode;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	pr_debug("inum %llu", inum);

	inode = iget_locked(sb, inum);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(inum, 0));
	k = bch_btree_iter_peek_with_holes(&iter);
	if (!k.k || k.k->type != BCH_INODE_FS) {
		ret = bch_btree_iter_unlock(&iter);
		iget_failed(inode);
		return ERR_PTR(ret ?: -ENOENT);
	}

	bch_inode_init(to_bch_ei(inode), bkey_s_c_to_inode(k));
	unlock_new_inode(inode);

	bch_btree_iter_unlock(&iter);

	return inode;
}

static void bch_set_inode_flags(struct inode *inode)
{
	unsigned flags = to_bch_ei(inode)->i_flags;

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
	struct bkey_i_inode bkey_inode;
	s64 now = timespec_to_ns(&ts);
	int ret;

	inode = new_inode(parent->i_sb);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, parent, mode);

	ei = to_bch_ei(inode);

	bi = &bkey_inode_init(&bkey_inode.k_i)->v;
	bi->i_uid	= i_uid_read(inode);
	bi->i_gid	= i_gid_read(inode);

	bi->i_mode	= inode->i_mode;
	bi->i_dev	= rdev;
	bi->i_atime	= now;
	bi->i_mtime	= now;
	bi->i_ctime	= now;
	bi->i_nlink	= S_ISDIR(mode) ? 2 : 1;

	ret = bch_inode_create(c, &bkey_inode.k_i,
			       BLOCKDEV_INODE_MAX, 0,
			       &c->unused_inode_hint);
	if (unlikely(ret)) {
		/*
		 * indicate to bch_evict_inode that the inode was never actually
		 * created:
		 */
		make_bad_inode(inode);
		goto err;
	}

	bch_inode_init(ei, inode_i_to_s_c(&bkey_inode));

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
	ret = bch_write_inode(c, ei);
	mutex_unlock(&ei->update_lock);

	if (ret)
		return ret;

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

		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, true);
		if (unlikely(ret))
			return ret;

		clear_nlink(new_inode);
		inode_dec_link_count(old_dir);
	} else if (new_inode) {
		lockdep_assert_held(&new_inode->i_rwsem);

		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, true);
		if (unlikely(ret))
			return ret;

		new_inode->i_ctime = now;
		inode_dec_link_count(new_inode);
	} else if (S_ISDIR(old_inode->i_mode)) {
		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, false);
		if (unlikely(ret))
			return ret;

		inode_inc_link_count(new_dir);
		inode_dec_link_count(old_dir);
	} else {
		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, false);
		if (unlikely(ret))
			return ret;
	}

	old_dir->i_ctime = old_dir->i_mtime = now;
	new_dir->i_ctime = new_dir->i_mtime = now;
	mark_inode_dirty_sync(old_dir);
	mark_inode_dirty_sync(new_dir);

	mutex_lock(&ei->update_lock);
	old_inode->i_ctime = now;
	if (new_inode)
		old_inode->i_mtime = now;
	ret = bch_write_inode(c, ei);
	mutex_unlock(&ei->update_lock);

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

	page = find_lock_page(mapping, from >> PAGE_SHIFT);
	if (!page) {
		struct inode *inode = mapping->host;
		struct cache_set *c = inode->i_sb->s_fs_info;
		struct btree_iter iter;
		struct bkey_s_c k;

		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino,
				       (from & PAGE_MASK) >> 9),
				   k)
			if (bkey_cmp(bkey_start_pos(k.k),
				     POS(inode->i_ino,
					 ((from + PAGE_SIZE) &
					  PAGE_MASK) >> 9)) < 0) {
				bch_btree_iter_unlock(&iter);
				goto grab;
			}
		bch_btree_iter_unlock(&iter);
		return 0;
grab:
		page = grab_cache_page(mapping, from >> PAGE_SHIFT);
		if (unlikely(!page)) {
			ret = -ENOMEM;
			goto out;
		}
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

/*
 * For truncate: We need to set I_SIZE_DIRTY atomically with setting the new
 * (truncated, smaller) size
 */
static int inode_set_size_and_dirty(struct bch_inode_info *ei,
				    struct bch_inode *bi)
{
	bi->i_flags |= BCH_INODE_I_SIZE_DIRTY;
	bi->i_size = ei->vfs_inode.i_size;
	return 0;
}

static int inode_set_size(struct bch_inode_info *ei,
			  struct bch_inode *bi)
{
	if (!atomic_long_read(&ei->i_size_dirty_count)) {
		bi->i_flags	&= ~BCH_INODE_I_SIZE_DIRTY;
		bi->i_size = ei->vfs_inode.i_size;
	} else if (ei->vfs_inode.i_size < ei->i_size) {
		bi->i_size = ei->vfs_inode.i_size;
	}
	return 0;
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
		 * I_SIZE_DIRTY indicates that there's extents past the end of
		 * i_size, and must be set atomically with setting the new
		 * i_size:
		 */

		/*
		 * XXX: do the i_size_write after the inode update succeeds, so
		 * we're not inconsistent on failure
		 */
		mutex_lock(&ei->update_lock);
		i_size_dirty_get(ei);
		i_size_write(inode, iattr->ia_size);
		ret = __bch_write_inode(c, ei, inode_set_size_and_dirty);
		mutex_unlock(&ei->update_lock);

		if (unlikely(ret))
			return ret;

		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (unlikely(ret))
			return ret;

		/*
		 * XXX: if we error, we leak i_size_dirty count - and we can't
		 * just put it, because it actually is still dirty
		 */

		if (iattr->ia_size > inode->i_size)
			pagecache_isize_extended(inode, inode->i_size,
						 iattr->ia_size);
		truncate_pagecache(inode, iattr->ia_size);

		ret = bch_inode_truncate(c, inode->i_ino,
				round_up(iattr->ia_size, PAGE_SIZE) >> 9,
				&ei->journal_seq);
		if (unlikely(ret))
			return ret;

		/*
		 * Extents discarded, now clear I_SIZE_DIRTY (which write_inode
		 * does when i_size_dirty_count is 0
		 */
		i_size_dirty_put(ei);
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;

		mutex_lock(&ei->update_lock);
		setattr_copy(inode, iattr);
		ret = __bch_write_inode(c, ei, inode_set_size);
		mutex_unlock(&ei->update_lock);
	} else {
		mutex_lock(&ei->update_lock);
		setattr_copy(inode, iattr);
		ret = bch_write_inode(c, ei);
		mutex_unlock(&ei->update_lock);

	}

	BUG_ON(inode->i_size < ei->i_size);

	if (unlikely(ret))
		return ret;

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
			   struct bkey_i *k, unsigned flags)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	const union bch_extent_crc *crc;
	int ret;

	extent_for_each_ptr_crc(e, ptr, crc) {
		int flags2 = 0;
		u64 offset = ptr->offset;

		if (crc_to_64(crc).compression_type)
			flags2 |= FIEMAP_EXTENT_ENCODED;
		else
			offset += crc_to_64(crc).offset;

		if ((offset & (PAGE_SECTORS - 1)) ||
		    (e.k->size & (PAGE_SECTORS - 1)))
			flags2 |= FIEMAP_EXTENT_NOT_ALIGNED;

		ret = fiemap_fill_next_extent(info,
					      bkey_start_offset(e.k) << 9,
					      offset << 9,
					      e.k->size << 9, flags|flags2);
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

static int bch_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct address_space *mapping = inode->i_mapping;
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);
	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(inode)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (!PageAllocated(page)) {
		if (reserve_sectors(c, PAGE_SECTORS)) {
			unlock_page(page);
			ret = VM_FAULT_SIGBUS;
			goto out;
		}

		SetPageAllocated(page);
	}

	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static const struct vm_operations_struct bch_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = bch_page_mkwrite,
};

static int bch_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);

	vma->vm_ops = &bch_vm_ops;
	return 0;
}

static int inode_set_partial_size(struct bch_inode_info *ei,
				  struct bch_inode *bi)
{
	bi->i_size = ei->i_size;
	return 0;
}

static int bch_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	inode_lock(inode);
	if (datasync && end <= ei->i_size)
		goto out;

	/*
	 * If i_size is dirty, and disk i_size < end < memory i_size, then -
	 * it's safe to write an i_size out that's intermediate, because... XXX
	 * explain
	 */

	mutex_lock(&ei->update_lock);

	if (inode->i_size == ei->i_size) {
		/* nothing to do */
	} else if (!atomic_long_read(&ei->i_size_dirty_count)) {
		ret = bch_write_inode(c, ei);
	} else if (inode->i_size > ei->i_size) {
		ei->i_size = min_t(u64, inode->i_size,
				   roundup(end, PAGE_SIZE));

		ret = __bch_write_inode(c, ei, inode_set_partial_size);
	} else {
		/* truncate.. */
		BUG();
	}

	mutex_unlock(&ei->update_lock);
out:
	inode_unlock(inode);

	if (ret)
		return ret;

	if (c->opts.journal_flush_disabled)
		return 0;

	return bch_journal_flush_seq(&c->journal, ei->journal_seq);
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

static int bch_inode_set_flags(struct bch_inode_info *ei, struct bch_inode *bi)
{
	unsigned oldflags = bi->i_flags;
	unsigned newflags = ei->newflags;

	if (((newflags ^ oldflags) & (FS_APPEND_FL|FS_IMMUTABLE_FL)) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	newflags = newflags & BCH_FL_USER_FLAGS;
	newflags |= oldflags & ~BCH_FL_USER_FLAGS;
	bi->i_flags = newflags;

	ei->vfs_inode.i_ctime = CURRENT_TIME_SEC;

	return 0;
}

#define FS_IOC_GOINGDOWN	     _IOR ('X', 125, __u32)

static long bch_fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct cache_set *c = sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	unsigned flags;
	int ret;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = ei->i_flags & BCH_FL_USER_FLAGS;
		return put_user(flags, (int __user *) arg);

	case FS_IOC_SETFLAGS: {
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

		mutex_lock(&ei->update_lock);
		ei->newflags = flags;
		ret = __bch_write_inode(c, ei, bch_inode_set_flags);
		mutex_unlock(&ei->update_lock);

		if (!ret)
			bch_set_inode_flags(inode);

		inode_unlock(inode);
setflags_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case FS_IOC_GOINGDOWN:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		down_write(&sb->s_umount);
		sb->s_flags |= MS_RDONLY;
		bch_cache_set_read_only(c);
		up_write(&sb->s_umount);
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
	.mmap		= bch_mmap,
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
				bch_read(c, bio, inode->i_ino);
				bio = NULL;
				goto again;
			}
		}

		nr_pages--;
		put_page(page);
	}

	if (bio)
		bch_read(c, bio, inode->i_ino);

	pr_debug("success");
	return 0;
}

static int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);
	bch_read(c, bio, inode->i_ino);

	return 0;
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
	struct cache_set *c = inode->i_sb->s_fs_info;
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
	if (PageAppend(page) &&
	    !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		int ret;

		mutex_lock(&ei->update_lock);
		ret = __bch_write_inode(c, ei, inode_set_dirty);
		mutex_unlock(&ei->update_lock);

		if (ret) {
			redirty_page_for_writepage(wbc, page);
			unlock_page(page);
			return 0;
		}
	}

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
	int ret;
	struct bch_writepage w = {
		.c = inode->i_sb->s_fs_info,
		.inum = inode->i_ino,
		.io = NULL,
	};

	ret = __bch_writepage(page, NULL, &w);
	if (ret)
		return ret;

	if (w.io)
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
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(done);

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_private = &done;
	bio->bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(bio, page);

	bch_read(c, bio, inode->i_ino);
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
		if (!TestSetPageAppend(page)) {
			mutex_lock(&ei->update_lock);
			i_size_dirty_get(ei);
			mutex_unlock(&ei->update_lock);
		}

		i_size_write(inode, last_pos);
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
		bch_read(c, bio, inum);
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
		i_size_dirty_put(ei);
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
	ssize_t ret;

	lockdep_assert_held(&inode->i_rwsem);

	if (file->f_flags & O_DSYNC || IS_SYNC(file->f_mapping->host))
		flags |= BCH_WRITE_FLUSH;

	dio = kmalloc(sizeof(*dio), GFP_NOIO);
	if (!dio)
		return -ENOMEM;

	dio->req	= req;
	dio->ret	= iter->count;
	dio->append	= false;

	if (offset + iter->count > inode->i_size) {
		dio->append = true;

		mutex_lock(&ei->update_lock);
		i_size_dirty_get(ei);
		ret = __bch_write_inode(c, ei, inode_set_dirty);
		mutex_unlock(&ei->update_lock);

		if (ret) {
			kfree(dio);
			return ret;
		}
	}

	closure_init(&dio->cl, NULL);

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
		    offset > inode->i_size)
			i_size_write(inode, offset);

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

static void bch_inode_init(struct bch_inode_info *ei,
			   struct bkey_s_c_inode bkey_inode)
{
	struct inode *inode = &ei->vfs_inode;
	const struct bch_inode *bi = bkey_inode.v;

	pr_debug("init inode %llu with mode %o",
		 bkey_inode.k->p.inode, bi->i_mode);

	ei->i_flags	= bi->i_flags;
	ei->i_size	= bi->i_size;

	inode->i_mode	= bi->i_mode;
	i_uid_write(inode, bi->i_uid);
	i_gid_write(inode, bi->i_gid);

	inode->i_ino	= bkey_inode.k->p.inode;
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
	atomic_long_set(&ei->i_size_dirty_count, 0);

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

static int bch_vfs_write_inode(struct inode *inode,
			       struct writeback_control *wbc)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	int ret;

	mutex_lock(&ei->update_lock);
	ret = bch_write_inode(c, ei);
	mutex_unlock(&ei->update_lock);

	if (c->opts.journal_flush_disabled)
		return ret;

	if (!ret && wbc->sync_mode == WB_SYNC_ALL)
		ret = bch_journal_flush_seq(&c->journal, ei->journal_seq);

	return ret;
}

static void bch_evict_inode(struct inode *inode)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);

	if (is_bad_inode(inode)) {
		/* bch_inode_create() failed: */
		clear_inode(inode);
	} else if (inode->i_nlink) {
		truncate_inode_pages_final(&inode->i_data);

		mutex_lock(&ei->update_lock);
		BUG_ON((inode->i_sb->s_flags & MS_ACTIVE) &&
		       atomic_long_read(&ei->i_size_dirty_count));

		if (!(inode->i_state & I_NEW) &&
		    (ei->i_flags & BCH_INODE_I_SIZE_DIRTY ||
		     inode->i_size != ei->i_size))
			WARN(bch_write_inode(c, ei) &&
			     (inode->i_sb->s_flags & MS_ACTIVE),
			     "failed to write inode before evicting\n");
		mutex_unlock(&ei->update_lock);

		clear_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);

		bch_inode_rm(c, inode->i_ino);
		atomic_long_dec(&c->nr_inodes);
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

	if (!wait) {
		bch_journal_flush_async(&c->journal, NULL);
		return 0;
	}

	return bch_journal_flush(&c->journal);
}

static struct cache_set *bdev_to_cache_set(struct block_device *bdev)
{
	struct cache_set *c;
	struct cache *ca;
	unsigned i;

	rcu_read_lock();

	list_for_each_entry(c, &bch_cache_sets, list)
		for_each_cache_rcu(ca, c, i)
			if (ca->disk_sb.bdev == bdev) {
				rcu_read_unlock();
				return c;
			}

	rcu_read_unlock();

	return NULL;
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
		goto err;

	for (i = 0, s = dev_name;
	     s;
	     (s = strchr(s, ':')) && (*s++ = '\0'))
		devs[i++] = s;

	err = bch_register_cache_set(devs, nr_devs, opts, &c);
	if (err) {
		/*
		 * Already open?
		 * Look up each block device, make sure they all belong to a
		 * cache set and they all belong to the _same_ cache set
		 */

		mutex_lock(&bch_register_lock);

		for (i = 0; i < nr_devs; i++) {
			struct block_device *bdev = lookup_bdev(devs[i]);
			struct cache_set *c2;

			if (IS_ERR(bdev))
				goto err_unlock;

			c2 = bdev_to_cache_set(bdev);
			bdput(bdev);

			if (!c)
				c = c2;

			if (c != c2)
				goto err_unlock;
		}

		if (!c)
			goto err_unlock;

		closure_get(&c->cl);
		mutex_unlock(&bch_register_lock);
	}

	set_bit(CACHE_SET_BDEV_MOUNTED, &c->flags);
err:
	kfree(devs);
	kfree(dev_name);

	return c;
err_unlock:
	mutex_unlock(&bch_register_lock);
	pr_err("register_cache_set err %s", err);
	goto err;
}

static int bch_remount(struct super_block *sb, int *flags, char *data)
{
	struct cache_set *c = sb->s_fs_info;
	struct cache_set_opts opts;
	int ret;

	ret = bch_parse_options(&opts, *flags, data);
	if (ret)
		return ret;

	mutex_lock(&bch_register_lock);

	if (opts.read_only >= 0 &&
	    opts.read_only != c->opts.read_only) {
		const char *err = NULL;

		if (opts.read_only) {
			bch_cache_set_read_only_sync(c);

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

	if (opts.errors >= 0)
		c->opts.errors = opts.errors;

unlock:
	mutex_unlock(&bch_register_lock);

	return ret;
}

static const struct super_operations bch_super_operations = {
	.alloc_inode	= bch_alloc_inode,
	.destroy_inode	= bch_destroy_inode,
	.write_inode	= bch_vfs_write_inode,
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

static int bch_test_super(struct super_block *s, void *data)
{
	return s->s_fs_info == data;
}

static int bch_set_super(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return 0;
}

static struct dentry *bch_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	struct cache_set *c;
	struct cache *ca;
	struct super_block *sb;
	struct inode *inode;
	struct cache_set_opts opts;
	unsigned i;
	int ret;

	ret = bch_parse_options(&opts, flags, data);
	if (ret)
		return ERR_PTR(ret);

	c = bch_open_as_blockdevs(dev_name, opts);
	if (!c)
		return ERR_PTR(-ENOENT);

	sb = sget(fs_type, bch_test_super, bch_set_super, flags|MS_NOSEC, c);
	if (IS_ERR(sb)) {
		closure_put(&c->cl);
		return ERR_CAST(sb);
	}

	BUG_ON(sb->s_fs_info != c);

	if (sb->s_root) {
		closure_put(&c->cl);

		if ((flags ^ sb->s_flags) & MS_RDONLY) {
			ret = -EBUSY;
			goto err_put_super;
		}
		goto out;
	}

	/* XXX: blocksize */
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_op		= &bch_super_operations;
	sb->s_xattr		= bch_xattr_handlers;
	sb->s_magic		= BCACHE_STATFS_MAGIC;
	sb->s_time_gran		= 1;
	c->vfs_sb		= sb;
	sb->s_bdi		= &c->bdi;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i) {
		struct block_device *bdev = ca->disk_sb.bdev;

		BUILD_BUG_ON(sizeof(sb->s_id) < BDEVNAME_SIZE);

		bdevname(bdev, sb->s_id);

		/* XXX: do we even need s_bdev? */
		sb->s_bdev	= bdev;
		sb->s_dev	= bdev->bd_dev;
		break;
	}
	rcu_read_unlock();

	if (opts.posix_acl < 0)
		sb->s_flags	|= MS_POSIXACL;
	else
		sb->s_flags	|= opts.posix_acl ? MS_POSIXACL : 0;

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
out:
	return dget(sb->s_root);

err_put_super:
	deactivate_locked_super(sb);
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
