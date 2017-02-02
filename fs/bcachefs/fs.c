
#include "bcache.h"
#include "acl.h"
#include "btree_update.h"
#include "buckets.h"
#include "chardev.h"
#include "dirent.h"
#include "extents.h"
#include "fs.h"
#include "fs-gc.h"
#include "fs-io.h"
#include "inode.h"
#include "journal.h"
#include "keylist.h"
#include "super.h"
#include "xattr.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

static struct kmem_cache *bch_inode_cache;

static void bch_vfs_inode_init(struct bch_inode_info *, struct bkey_s_c_inode);

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

int __must_check __bch_write_inode(struct cache_set *c,
				   struct bch_inode_info *ei,
				   inode_set_fn set,
				   void *p)
{
	struct btree_iter iter;
	struct inode *inode = &ei->vfs_inode;
	struct bkey_i_inode new_inode;
	struct bch_inode *bi;
	u64 inum = inode->i_ino;
	int ret;

	lockdep_assert_held(&ei->update_lock);

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(inum, 0));

	do {
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);

		if ((ret = btree_iter_err(k)))
			goto out;

		if (WARN_ONCE(k.k->type != BCH_INODE_FS,
			      "inode %llu not found when updating", inum)) {
			bch_btree_iter_unlock(&iter);
			return -ENOENT;
		}

		bkey_reassemble(&new_inode.k_i, k);
		bi = &new_inode.v;

		if (set) {
			ret = set(ei, bi, p);
			if (ret)
				goto out;
		}

		bi->i_mode	= cpu_to_le16(inode->i_mode);
		bi->i_uid	= cpu_to_le32(i_uid_read(inode));
		bi->i_gid	= cpu_to_le32(i_gid_read(inode));
		bi->i_nlink	= cpu_to_le32(inode->i_nlink);
		bi->i_dev	= cpu_to_le32(inode->i_rdev);
		bi->i_atime	= cpu_to_le64(timespec_to_ns(&inode->i_atime));
		bi->i_mtime	= cpu_to_le64(timespec_to_ns(&inode->i_mtime));
		bi->i_ctime	= cpu_to_le64(timespec_to_ns(&inode->i_ctime));

		ret = bch_btree_insert_at(c, NULL, NULL, &ei->journal_seq,
				BTREE_INSERT_ATOMIC|
				BTREE_INSERT_NOFAIL,
				BTREE_INSERT_ENTRY(&iter, &new_inode.k_i));
	} while (ret == -EINTR);

	if (!ret) {
		ei->i_size	= le64_to_cpu(bi->i_size);
		ei->i_flags	= le32_to_cpu(bi->i_flags);
	}
out:
	bch_btree_iter_unlock(&iter);

	return ret < 0 ? ret : 0;
}

int __must_check bch_write_inode(struct cache_set *c,
				 struct bch_inode_info *ei)
{
	return __bch_write_inode(c, ei, NULL, NULL);
}

int bch_inc_nlink(struct cache_set *c, struct bch_inode_info *ei)
{
	int ret;

	mutex_lock(&ei->update_lock);
	inc_nlink(&ei->vfs_inode);
	ret = bch_write_inode(c, ei);
	mutex_unlock(&ei->update_lock);

	return ret;
}

int bch_dec_nlink(struct cache_set *c, struct bch_inode_info *ei)
{
	int ret;

	mutex_lock(&ei->update_lock);
	drop_nlink(&ei->vfs_inode);
	ret = bch_write_inode(c, ei);
	mutex_unlock(&ei->update_lock);

	return ret;
}

static struct inode *bch_vfs_inode_get(struct super_block *sb, u64 inum)
{
	struct cache_set *c = sb->s_fs_info;
	struct inode *inode;
	struct bch_inode_info *ei;
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

	if ((ret = btree_iter_err(k)) || k.k->type != BCH_INODE_FS) {
		ret = bch_btree_iter_unlock(&iter);
		iget_failed(inode);
		return ERR_PTR(ret ?: -ENOENT);
	}

	ei = to_bch_ei(inode);
	bch_vfs_inode_init(ei, bkey_s_c_to_inode(k));

	ei->journal_seq = bch_inode_journal_seq(&c->journal, inum);

	unlock_new_inode(inode);

	bch_btree_iter_unlock(&iter);

	return inode;
}

static struct inode *bch_vfs_inode_create(struct cache_set *c,
					  struct inode *parent,
					  umode_t mode, dev_t rdev)
{
	struct inode *inode;
	struct posix_acl *default_acl = NULL, *acl = NULL;
	struct bch_inode_info *ei;
	struct bkey_i_inode bkey_inode;
	int ret;

	inode = new_inode(parent->i_sb);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, parent, mode);

	ret = posix_acl_create(parent, &inode->i_mode, &default_acl, &acl);
	if (ret) {
		make_bad_inode(inode);
		goto err;
	}

	ei = to_bch_ei(inode);

	bch_inode_init(c, &bkey_inode, i_uid_read(inode),
		       i_gid_read(inode), inode->i_mode, rdev);

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

	bch_vfs_inode_init(ei, inode_i_to_s_c(&bkey_inode));

	if (default_acl) {
		ret = bch_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		if (unlikely(ret))
			goto err;
	}

	if (acl) {
		ret = bch_set_acl(inode, acl, ACL_TYPE_ACCESS);
		if (unlikely(ret))
			goto err;
	}

	insert_inode_hash(inode);
	atomic_long_inc(&c->nr_inodes);
out:
	posix_acl_release(default_acl);
	posix_acl_release(acl);
	return inode;
err:
	clear_nlink(inode);
	iput(inode);
	inode = ERR_PTR(ret);
	goto out;
}

static int bch_vfs_dirent_create(struct cache_set *c, struct inode *dir,
				 u8 type, const struct qstr *name,
				 struct inode *dst)
{
	struct bch_inode_info *dir_ei = to_bch_ei(dir);
	int ret;

	ret = bch_dirent_create(c, dir->i_ino, &dir_ei->str_hash,
				type, name, dst->i_ino,
				&dir_ei->journal_seq,
				BCH_HASH_SET_MUST_CREATE);
	if (unlikely(ret))
		return ret;

	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty_sync(dir);
	return 0;
}

static int __bch_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct bch_inode_info *dir_ei = to_bch_ei(dir);
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	struct bch_inode_info *ei;
	int ret;

	inode = bch_vfs_inode_create(c, dir, mode, rdev);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	ei = to_bch_ei(inode);

	ret = bch_vfs_dirent_create(c, dir, mode_to_type(mode),
				    &dentry->d_name, inode);
	if (unlikely(ret)) {
		clear_nlink(inode);
		iput(inode);
		return ret;
	}

	if (dir_ei->journal_seq > ei->journal_seq)
		ei->journal_seq = dir_ei->journal_seq;

	d_instantiate(dentry, inode);
	return 0;
}

/* methods */

static struct dentry *bch_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *dir_ei = to_bch_ei(dir);
	struct inode *inode = NULL;
	u64 inum;

	inum = bch_dirent_lookup(c, dir->i_ino,
				 &dir_ei->str_hash,
				 &dentry->d_name);

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

	inode->i_ctime = CURRENT_TIME;

	ret = bch_inc_nlink(c, ei);
	if (ret)
		return ret;

	ihold(inode);

	ret = bch_vfs_dirent_create(c, dir, mode_to_type(inode->i_mode),
				    &dentry->d_name, inode);
	if (unlikely(ret)) {
		bch_dec_nlink(c, ei);
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	return 0;
}

static int bch_unlink(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *dir_ei = to_bch_ei(dir);
	struct inode *inode = dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	int ret;

	lockdep_assert_held(&inode->i_rwsem);

	ret = bch_dirent_delete(c, dir->i_ino, &dir_ei->str_hash,
				&dentry->d_name, &dir_ei->journal_seq);
	if (ret)
		return ret;

	if (dir_ei->journal_seq > ei->journal_seq)
		ei->journal_seq = dir_ei->journal_seq;

	inode->i_ctime = dir->i_ctime;

	if (S_ISDIR(inode->i_mode)) {
		bch_dec_nlink(c, dir_ei);
		drop_nlink(inode);
	}

	drop_nlink(inode);
	if (inode->i_nlink) {
		mutex_lock(&ei->update_lock);
		ret = bch_write_inode(c, ei);
		mutex_unlock(&ei->update_lock);
	}

	return 0;
}

static int bch_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	struct bch_inode_info *ei, *dir_ei = to_bch_ei(dir);
	int ret;

	inode = bch_vfs_inode_create(c, dir, S_IFLNK|S_IRWXUGO, 0);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	ei = to_bch_ei(inode);

	inode_lock(inode);
	ret = page_symlink(inode, symname, strlen(symname) + 1);
	inode_unlock(inode);

	if (unlikely(ret))
		goto err;

	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (unlikely(ret))
		goto err;

	/* XXX: racy */
	if (dir_ei->journal_seq < ei->journal_seq)
		dir_ei->journal_seq = ei->journal_seq;

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
	struct cache_set *c = dir->i_sb->s_fs_info;
	int ret;

	lockdep_assert_held(&dir->i_rwsem);

	ret = __bch_create(dir, dentry, mode|S_IFDIR, 0);
	if (unlikely(ret))
		return ret;

	bch_inc_nlink(c, to_bch_ei(dir));

	return 0;
}

static int bch_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;

	if (bch_empty_dir(c, inode->i_ino))
		return -ENOTEMPTY;

	return bch_unlink(dir, dentry);
}

static int bch_mknod(struct inode *dir, struct dentry *dentry,
		     umode_t mode, dev_t rdev)
{
	return __bch_create(dir, dentry, mode, rdev);
}

static int bch_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct cache_set *c = old_dir->i_sb->s_fs_info;
	struct inode *old_inode = old_dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(old_inode);
	struct inode *new_inode = new_dentry->d_inode;
	struct timespec now = CURRENT_TIME;
	int ret;

	lockdep_assert_held(&old_dir->i_rwsem);
	lockdep_assert_held(&new_dir->i_rwsem);

	if (new_inode)
		filemap_write_and_wait_range(old_inode->i_mapping,
					     0, LLONG_MAX);

	if (new_inode && S_ISDIR(old_inode->i_mode)) {
		lockdep_assert_held(&new_inode->i_rwsem);

		if (!S_ISDIR(new_inode->i_mode))
			return -ENOTDIR;

		if (bch_empty_dir(c, new_inode->i_ino))
			return -ENOTEMPTY;

		ret = bch_dirent_rename(c,
					old_dir, &old_dentry->d_name,
					new_dir, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		clear_nlink(new_inode);
		bch_dec_nlink(c, to_bch_ei(old_dir));
	} else if (new_inode) {
		lockdep_assert_held(&new_inode->i_rwsem);

		ret = bch_dirent_rename(c,
					old_dir, &old_dentry->d_name,
					new_dir, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		new_inode->i_ctime = now;
		bch_dec_nlink(c, to_bch_ei(new_inode));
	} else if (S_ISDIR(old_inode->i_mode)) {
		ret = bch_dirent_rename(c,
					old_dir, &old_dentry->d_name,
					new_dir, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME);
		if (unlikely(ret))
			return ret;

		bch_inc_nlink(c, to_bch_ei(new_dir));
		bch_dec_nlink(c, to_bch_ei(old_dir));
	} else {
		ret = bch_dirent_rename(c,
					old_dir, &old_dentry->d_name,
					new_dir, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME);
		if (unlikely(ret))
			return ret;
	}

	old_dir->i_ctime = old_dir->i_mtime = now;
	new_dir->i_ctime = new_dir->i_mtime = now;
	mark_inode_dirty_sync(old_dir);
	mark_inode_dirty_sync(new_dir);

	old_inode->i_ctime = now;
	mark_inode_dirty_sync(old_inode);

	return 0;
}

static int bch_rename_exchange(struct inode *old_dir, struct dentry *old_dentry,
			       struct inode *new_dir, struct dentry *new_dentry)
{
	struct cache_set *c = old_dir->i_sb->s_fs_info;
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(old_inode);
	struct timespec now = CURRENT_TIME;
	int ret;

	ret = bch_dirent_rename(c,
				old_dir, &old_dentry->d_name,
				new_dir, &new_dentry->d_name,
				&ei->journal_seq, BCH_RENAME_EXCHANGE);
	if (unlikely(ret))
		return ret;

	if (S_ISDIR(old_inode->i_mode) !=
	    S_ISDIR(new_inode->i_mode)) {
		if (S_ISDIR(old_inode->i_mode)) {
			bch_inc_nlink(c, to_bch_ei(new_dir));
			bch_dec_nlink(c, to_bch_ei(old_dir));
		} else {
			bch_dec_nlink(c, to_bch_ei(new_dir));
			bch_inc_nlink(c, to_bch_ei(old_dir));
		}
	}

	old_dir->i_ctime = old_dir->i_mtime = now;
	new_dir->i_ctime = new_dir->i_mtime = now;
	mark_inode_dirty_sync(old_dir);
	mark_inode_dirty_sync(new_dir);

	old_inode->i_ctime = now;
	new_inode->i_ctime = now;
	mark_inode_dirty_sync(old_inode);
	mark_inode_dirty_sync(new_inode);

	return 0;
}

static int bch_rename2(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned flags)
{
	if (flags & ~(RENAME_NOREPLACE|RENAME_EXCHANGE))
		return -EINVAL;

	if (flags & RENAME_EXCHANGE)
		return bch_rename_exchange(old_dir, old_dentry,
					   new_dir, new_dentry);

	return bch_rename(old_dir, old_dentry, new_dir, new_dentry);
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

	if (iattr->ia_valid & ATTR_SIZE) {
		ret = bch_truncate(inode, iattr);
	} else {
		mutex_lock(&ei->update_lock);
		setattr_copy(inode, iattr);
		ret = bch_write_inode(c, ei);
		mutex_unlock(&ei->update_lock);
	}

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
			   const struct bkey_i *k, unsigned flags)
{
	if (bkey_extent_is_data(&k->k)) {
		struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
		const struct bch_extent_ptr *ptr;
		const union bch_extent_crc *crc;
		int ret;

		extent_for_each_ptr_crc(e, ptr, crc) {
			int flags2 = 0;
			u64 offset = ptr->offset;

			if (crc_compression_type(crc))
				flags2 |= FIEMAP_EXTENT_ENCODED;
			else
				offset += crc_offset(crc);

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
	} else if (k->k.type == BCH_RESERVATION) {
		return fiemap_fill_next_extent(info,
					       bkey_start_offset(&k->k) << 9,
					       0, k->k.size << 9,
					       flags|
					       FIEMAP_EXTENT_DELALLOC|
					       FIEMAP_EXTENT_UNWRITTEN);
	} else {
		BUG();
	}
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
		if (bkey_extent_is_data(k.k) ||
		    k.k->type == BCH_RESERVATION) {
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

/* Set VFS inode flags from bcache inode: */
static void bch_inode_flags_to_vfs(struct inode *inode)
{
	unsigned i, flags = to_bch_ei(inode)->i_flags;

	for (i = 0; i < ARRAY_SIZE(bch_inode_flags_to_vfs_flags_map); i++)
		if (flags & (1 << i))
			inode->i_flags |=  bch_inode_flags_to_vfs_flags_map[i];
		else
			inode->i_flags &= ~bch_inode_flags_to_vfs_flags_map[i];
}

/* Get FS_IOC_GETFLAGS flags from bcache inode: */
static unsigned bch_inode_flags_to_user_flags(unsigned flags)
{
	unsigned i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(bch_inode_flags_to_user_flags_map); i++)
		if (flags & (1 << i))
			ret |= bch_inode_flags_to_user_flags_map[i];

	return ret;
}

static int bch_inode_user_flags_set(struct bch_inode_info *ei,
				    struct bch_inode *bi,
				    void *p)
{
	/*
	 * We're relying on btree locking here for exclusion with other ioctl
	 * calls - use the flags in the btree (@bi), not ei->i_flags:
	 */
	unsigned bch_flags = le32_to_cpu(bi->i_flags);
	unsigned oldflags = bch_inode_flags_to_user_flags(bch_flags);
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

	bi->i_flags = cpu_to_le32(bch_flags);
	ei->vfs_inode.i_ctime = CURRENT_TIME;

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
		return put_user(bch_inode_flags_to_user_flags(ei->i_flags),
				(int __user *) arg);

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

		if (!S_ISREG(inode->i_mode) &&
		    !S_ISDIR(inode->i_mode) &&
		    (flags & (FS_NODUMP_FL|FS_NOATIME_FL)) != flags) {
			ret = -EINVAL;
			goto setflags_out;
		}

		inode_lock(inode);

		mutex_lock(&ei->update_lock);
		ret = __bch_write_inode(c, ei, bch_inode_user_flags_set, &flags);
		mutex_unlock(&ei->update_lock);

		if (!ret)
			bch_inode_flags_to_vfs(inode);

		inode_unlock(inode);
setflags_out:
		mnt_drop_write_file(filp);
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
		bch_cache_set_emergency_read_only(c);
		up_write(&sb->s_umount);
		return 0;

	default:
		return bch_cache_set_ioctl(c, cmd, (void __user *) arg);
	}
}

#ifdef CONFIG_COMPAT
static long bch_compat_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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

/* Directories: */

static loff_t bch_dir_llseek(struct file *file, loff_t offset, int whence)
{
	return generic_file_llseek_size(file, offset, whence,
					S64_MAX, S64_MAX);
}

static int bch_vfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct cache_set *c = inode->i_sb->s_fs_info;

	return bch_readdir(c, file, ctx);
}

static const struct file_operations bch_file_operations = {
	.llseek		= bch_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= bch_write_iter,
	.mmap		= bch_mmap,
	.open		= generic_file_open,
	.fsync		= bch_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= bch_fallocate_dispatch,
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
	.rename		= bch_rename2,
	.setattr	= bch_setattr,
	.tmpfile	= bch_tmpfile,
	.listxattr	= bch_xattr_list,
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
};

static const struct file_operations bch_dir_file_operations = {
	.llseek		= bch_dir_llseek,
	.read		= generic_read_dir,
	.iterate	= bch_vfs_readdir,
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

static const struct address_space_operations bch_address_space_operations = {
	.writepage	= bch_writepage,
	.readpage	= bch_readpage,
	.writepages	= bch_writepages,
	.readpages	= bch_readpages,
	.set_page_dirty	= bch_set_page_dirty,
	.write_begin	= bch_write_begin,
	.write_end	= bch_write_end,
	.invalidatepage	= bch_invalidatepage,
	.releasepage	= bch_releasepage,
	.direct_IO	= bch_direct_IO,
#ifdef CONFIG_MIGRATION
	.migratepage	= bch_migrate_page,
#endif
	.error_remove_page = generic_error_remove_page,
};

static void bch_vfs_inode_init(struct bch_inode_info *ei,
			       struct bkey_s_c_inode bkey_inode)
{
	struct inode *inode = &ei->vfs_inode;
	const struct bch_inode *bi = bkey_inode.v;

	pr_debug("init inode %llu with mode %o",
		 bkey_inode.k->p.inode, bi->i_mode);

	ei->i_flags	= le32_to_cpu(bi->i_flags);
	ei->i_size	= le64_to_cpu(bi->i_size);

	inode->i_mode	= le16_to_cpu(bi->i_mode);
	i_uid_write(inode, le32_to_cpu(bi->i_uid));
	i_gid_write(inode, le32_to_cpu(bi->i_gid));

	atomic64_set(&ei->i_sectors, le64_to_cpu(bi->i_sectors));
	inode->i_blocks = atomic64_read(&ei->i_sectors);

	inode->i_ino	= bkey_inode.k->p.inode;
	set_nlink(inode, le32_to_cpu(bi->i_nlink));
	inode->i_rdev	= le32_to_cpu(bi->i_dev);
	inode->i_size	= le64_to_cpu(bi->i_size);
	inode->i_atime	= ns_to_timespec(le64_to_cpu(bi->i_atime));
	inode->i_mtime	= ns_to_timespec(le64_to_cpu(bi->i_mtime));
	inode->i_ctime	= ns_to_timespec(le64_to_cpu(bi->i_ctime));
	bch_inode_flags_to_vfs(inode);

	ei->str_hash = bch_hash_info_init(bi);

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
	atomic_long_set(&ei->i_sectors_dirty_count, 0);

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

	truncate_inode_pages_final(&inode->i_data);

	if (!bch_journal_error(&c->journal) && !is_bad_inode(inode)) {
		struct bch_inode_info *ei = to_bch_ei(inode);

		/* XXX - we want to check this stuff iff there weren't IO errors: */
		BUG_ON(atomic_long_read(&ei->i_sectors_dirty_count));
		BUG_ON(atomic64_read(&ei->i_sectors) != inode->i_blocks);
	}

	clear_inode(inode);

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		bch_inode_rm(c, inode->i_ino);
		atomic_long_dec(&c->nr_inodes);
	}
}

static int bch_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct cache_set *c = sb->s_fs_info;
	u64 fsid;

	buf->f_type	= BCACHE_STATFS_MAGIC;
	buf->f_bsize	= sb->s_blocksize;
	buf->f_blocks	= c->capacity >> PAGE_SECTOR_SHIFT;
	buf->f_bfree	= (c->capacity - cache_set_sectors_used(c)) >> PAGE_SECTOR_SHIFT;
	buf->f_bavail	= buf->f_bfree;
	buf->f_files	= atomic_long_read(&c->nr_inodes);
	buf->f_ffree	= U64_MAX;

	fsid = le64_to_cpup((void *) c->disk_sb.user_uuid.b) ^
	       le64_to_cpup((void *) c->disk_sb.user_uuid.b + sizeof(u64));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
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

		if (!test_bit(CACHE_SET_RUNNING, &c->flags)) {
			err = "incomplete cache set";
			c = NULL;
			goto err_unlock;
		}

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
				bch_err(c, "error going rw: %s", err);
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
	.fs_flags	= FS_REQUIRES_DEV,
};

MODULE_ALIAS_FS("bcache");

void bch_fs_exit(void)
{
	unregister_filesystem(&bcache_fs_type);
	if (bch_dio_write_bioset)
		bioset_free(bch_dio_write_bioset);
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
		bioset_create(4, offsetof(struct bch_writepage_io, bio.bio));
	if (!bch_writepage_bioset)
		goto err;

	bch_dio_read_bioset = bioset_create(4, offsetof(struct dio_read, rbio.bio));
	if (!bch_dio_read_bioset)
		goto err;

	bch_dio_write_bioset = bioset_create(4, offsetof(struct dio_write, bio.bio));
	if (!bch_dio_write_bioset)
		goto err;

	ret = register_filesystem(&bcache_fs_type);
	if (ret)
		goto err;

	return 0;
err:
	bch_fs_exit();
	return ret;
}
