
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
#include <linux/falloc.h>
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

static void i_size_update_put(struct cache_set *,
			      struct bch_inode_info *,
			      unsigned, unsigned long);

static void bch_clear_page_bits(struct cache_set *c, struct bch_inode_info *ei,
				struct page *page)
{
	EBUG_ON(!PageLocked(page));

	if (PageAllocated(page)) {
		atomic_long_sub_bug(PAGE_SECTORS, &c->sectors_reserved);
		ClearPageAllocated(page);
	}

	if (PageAppend(page)) {
		struct bch_page_state *s = (void *) &page->private;

		i_size_update_put(c, ei, s->idx, 1);
		ClearPageAppend(page);
	}
}

/*
 * In memory i_size should never be < on disk i_size:
 */
static void bch_i_size_write(struct inode *inode, loff_t new_i_size)
{
	struct bch_inode_info *ei = to_bch_ei(inode);

	EBUG_ON(new_i_size < ei->i_size);
	i_size_write(inode, new_i_size);
}

/* returns true if we want to do the update */
typedef int (*inode_set_fn)(struct bch_inode_info *,
			    struct bch_inode *, void *);

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

static void bch_write_inode_checks(struct cache_set *c,
				   struct bch_inode_info *ei)
{
	struct inode *inode = &ei->vfs_inode;

	/*
	 * ei->i_size is where we stash the i_size we're writing to disk (which
	 * is often different than the in memory i_size) - it never makes sense
	 * to be writing an i_size larger than the in memory i_size:
	 */
	BUG_ON(ei->i_size > inode->i_size);

	/*
	 * if i_size is not dirty, then there shouldn't be any extents past the
	 * i_size we're writing:
	 */
	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG) &&
	    !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		struct btree_iter iter;
		struct bkey_s_c k;

		for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino,
				       round_up(ei->i_size, PAGE_SIZE) >> 9), k) {
			if (k.k->p.inode != inode->i_ino)
				break;

			BUG_ON(bkey_extent_is_data(k.k));
		}

		bch_btree_iter_unlock(&iter);
	}
}

static int __must_check __bch_write_inode(struct cache_set *c,
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

		if (WARN_ONCE(!k.k || k.k->type != BCH_INODE_FS,
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

		bi->i_mode	= inode->i_mode;
		bi->i_uid	= i_uid_read(inode);
		bi->i_gid	= i_gid_read(inode);
		bi->i_nlink	= inode->i_nlink;
		bi->i_dev	= inode->i_rdev;
		bi->i_atime	= timespec_to_ns(&inode->i_atime);
		bi->i_mtime	= timespec_to_ns(&inode->i_mtime);
		bi->i_ctime	= timespec_to_ns(&inode->i_ctime);

		ret = bch_btree_insert_at(&iter,
					  &keylist_single(&new_inode.k_i),
					  NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
	} while (ret == -EINTR);

	if (!ret) {
		write_seqcount_begin(&ei->shadow_i_size_lock);
		ei->i_size	= bi->i_size;
		ei->i_flags	= bi->i_flags;
		write_seqcount_end(&ei->shadow_i_size_lock);

		bch_write_inode_checks(c, ei);
	}
out:
	bch_btree_iter_unlock(&iter);

	return ret < 0 ? ret : 0;
}

static int __must_check bch_write_inode(struct cache_set *c,
					struct bch_inode_info *ei)
{
	return __bch_write_inode(c, ei, NULL, NULL);
}

static int inode_set_size(struct bch_inode_info *ei, struct bch_inode *bi,
			  void *p)
{
	loff_t *new_i_size = p;

	lockdep_assert_held(&ei->update_lock);

	bi->i_size = *new_i_size;

	if (atomic_long_read(&ei->i_size_dirty_count))
		bi->i_flags |= BCH_INODE_I_SIZE_DIRTY;
	else
		bi->i_flags &= ~BCH_INODE_I_SIZE_DIRTY;

	return 0;
}

static int __must_check bch_write_inode_size(struct cache_set *c,
					     struct bch_inode_info *ei,
					     loff_t new_size)
{
	return __bch_write_inode(c, ei, inode_set_size, &new_size);
}

static int inode_set_dirty(struct bch_inode_info *ei,
			   struct bch_inode *bi, void *p)
{
	bi->i_flags |= BCH_INODE_I_SIZE_DIRTY;
	return 0;
}

static int check_make_i_size_dirty(struct bch_inode_info *ei,
				   loff_t offset)
{
	bool need_set_dirty;
	unsigned seq;
	int ret = 0;

	do {
		seq = read_seqcount_begin(&ei->shadow_i_size_lock);
		need_set_dirty = offset > ei->i_size &&
			!(ei->i_flags & BCH_INODE_I_SIZE_DIRTY);
	} while (read_seqcount_retry(&ei->shadow_i_size_lock, seq));

	if (!need_set_dirty)
		return 0;

	mutex_lock(&ei->update_lock);

	/* recheck under lock.. */

	if (offset > ei->i_size &&
	    !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		struct cache_set *c = ei->vfs_inode.i_sb->s_fs_info;

		ret = __bch_write_inode(c, ei, inode_set_dirty, NULL);
	}

	mutex_unlock(&ei->update_lock);

	return ret;
}

static void i_size_update_put(struct cache_set *c,
			      struct bch_inode_info *ei,
			      unsigned idx,
			      unsigned long count)
{
	struct i_size_update *u = &ei->i_size_updates.data[idx];
	loff_t new_i_size = -1;
	long r;

	if (!count)
		return;

	r = atomic_long_sub_return(count, &u->count);
	BUG_ON(r < 0);

	if (r)
		return;

	/*
	 * Flush i_size_updates entries in order - from the end of the fifo -
	 * if the entry at the end is finished (refcount has gone to 0):
	 */

	mutex_lock(&ei->update_lock);

	while (!fifo_empty(&ei->i_size_updates) &&
	       !atomic_long_read(&(u = &fifo_front(&ei->i_size_updates))->count)) {
		struct i_size_update t;

		i_size_dirty_put(ei);

		if (u->new_i_size != -1) {
			BUG_ON(u->new_i_size < ei->i_size);
			new_i_size = u->new_i_size;
		}

		fifo_pop(&ei->i_size_updates, t);
	}

	if (new_i_size != -1) {
		int ret = bch_write_inode_size(c, ei, new_i_size);
		/*
		 * XXX: need to pin the inode in memory if the inode update
		 * fails
		 */
		ret = ret;
	}

	mutex_unlock(&ei->update_lock);
}

static struct i_size_update *i_size_update_new(struct bch_inode_info *ei,
					       loff_t new_size)
{
	struct i_size_update *u;

	lockdep_assert_held(&ei->update_lock);

	if (fifo_empty(&ei->i_size_updates) ||
	    (test_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags) &&
	     !fifo_full(&ei->i_size_updates))) {
		clear_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
		fifo_push(&ei->i_size_updates,
			  (struct i_size_update) { 0 });

		u = &fifo_back(&ei->i_size_updates);
		atomic_long_set(&u->count, 0);
		i_size_dirty_get(ei);
	}

	u = &fifo_back(&ei->i_size_updates);
	u->new_i_size = new_size;

	return u;
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
	struct posix_acl *default_acl = NULL, *acl = NULL;
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

	ret = posix_acl_create(parent, &inode->i_mode, &default_acl, &acl);
	if (ret) {
		make_bad_inode(inode);
		goto err;
	}

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
	struct bch_inode_info *dir_ei = to_bch_ei(dir);
	struct inode *inode = dentry->d_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	int ret;

	lockdep_assert_held(&inode->i_rwsem);

	ret = bch_dirent_delete(c, dir->i_ino, &dentry->d_name,
				&dir_ei->journal_seq);
	if (ret)
		return ret;

	if (dir_ei->journal_seq > ei->journal_seq)
		ei->journal_seq = dir_ei->journal_seq;

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

	if (new_inode && S_ISDIR(old_inode->i_mode)) {
		lockdep_assert_held(&new_inode->i_rwsem);

		if (!S_ISDIR(new_inode->i_mode))
			return -ENOTDIR;

		if (bch_empty_dir(c, new_inode->i_ino))
			return -ENOTEMPTY;

		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		clear_nlink(new_inode);
		inode_dec_link_count(old_dir);
	} else if (new_inode) {
		lockdep_assert_held(&new_inode->i_rwsem);

		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		new_inode->i_ctime = now;
		inode_dec_link_count(new_inode);
	} else if (S_ISDIR(old_inode->i_mode)) {
		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
					&ei->journal_seq, BCH_RENAME);
		if (unlikely(ret))
			return ret;

		inode_inc_link_count(new_dir);
		inode_dec_link_count(old_dir);
	} else {
		ret = bch_dirent_rename(c,
					old_dir->i_ino, &old_dentry->d_name,
					new_dir->i_ino, &new_dentry->d_name,
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
				old_dir->i_ino, &old_dentry->d_name,
				new_dir->i_ino, &new_dentry->d_name,
				&ei->journal_seq, BCH_RENAME_EXCHANGE);
	if (unlikely(ret))
		return ret;

	if (S_ISDIR(old_inode->i_mode) !=
	    S_ISDIR(new_inode->i_mode)) {
		if (S_ISDIR(old_inode->i_mode)) {
			inode_inc_link_count(new_dir);
			inode_dec_link_count(old_dir);
		} else {
			inode_dec_link_count(new_dir);
			inode_inc_link_count(old_dir);
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

static int __bch_truncate_page(struct address_space *mapping,
			       pgoff_t index, loff_t start, loff_t end)
{
	unsigned start_offset = start & (PAGE_SIZE - 1);
	unsigned end_offset = ((end - 1) & (PAGE_SIZE - 1)) + 1;
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!((index == start >> PAGE_SHIFT && start_offset) ||
	      (index == end >> PAGE_SHIFT && end_offset != PAGE_SIZE)))
		return 0;

	page = find_lock_page(mapping, index);
	if (!page) {
		struct inode *inode = mapping->host;
		struct cache_set *c = inode->i_sb->s_fs_info;
		struct btree_iter iter;
		struct bkey_s_c k;

		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		bch_btree_iter_init(&iter, c, BTREE_ID_EXTENTS,
				    POS(inode->i_ino,
					index << (PAGE_SHIFT - 9)));
		k = bch_btree_iter_peek(&iter);
		bch_btree_iter_unlock(&iter);

		if (!k.k ||
		    bkey_cmp(bkey_start_pos(k.k),
			     POS(inode->i_ino,
				 (index + 1) << (PAGE_SHIFT - 9))) >= 0)
			return 0;

		page = find_or_create_page(mapping,
					   index,
					   GFP_KERNEL);
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

	if (index == start >> PAGE_SHIFT &&
	    index == end >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, end_offset);
	else if (index == start >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, PAGE_SIZE);
	else if (index == end >> PAGE_SHIFT)
		zero_user_segment(page, 0, end_offset);

	set_page_dirty(page);
unlock:
	unlock_page(page);
	put_page(page);
out:
	return ret;
}

static int bch_truncate_page(struct address_space *mapping, loff_t from)
{
	return __bch_truncate_page(mapping, from >> PAGE_SHIFT,
				   from, from + PAGE_SIZE);
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
		bool shrink = iattr->ia_size <= inode->i_size;
		struct i_size_update *u;
		unsigned idx;

		inode_dio_wait(inode);

		mutex_lock(&ei->update_lock);

		/*
		 * The new i_size could be bigger or smaller than the current on
		 * disk size (ei->i_size):
		 *
		 * If it's smaller (i.e. we actually are truncating), then in
		 * order to make the truncate appear atomic we have to write out
		 * the new i_size before discarding the data to be truncated.
		 *
		 * However, if the new i_size is bigger than the on disk i_size,
		 * then we _don't_ want to write the new i_size here - because
		 * if there are appends in flight, that would cause us to expose
		 * the range between the old and the new i_size before those
		 * appends have completed.
		 */

		/*
		 * First, cancel i_size_updates that extend past the new
		 * i_size, so the i_size we write here doesn't get
		 * stomped on:
		 */
		fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
			if (u->new_i_size > iattr->ia_size)
				u->new_i_size = -1;

		set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
		u = i_size_update_new(ei, iattr->ia_size);

		atomic_long_inc(&u->count);
		idx = u - ei->i_size_updates.data;

		if (iattr->ia_size < ei->i_size)
			ret = bch_write_inode_size(c, ei, iattr->ia_size);

		mutex_unlock(&ei->update_lock);

		/*
		 * XXX: if we error, we leak i_size_dirty count - and we can't
		 * just put it, because it actually is still dirty
		 */
		if (unlikely(ret))
			return ret;

		/*
		 * truncate_setsize() does the i_size_write(), can't use
		 * bch_i_size_write()
		 */
		EBUG_ON(iattr->ia_size < ei->i_size);
		truncate_setsize(inode, iattr->ia_size);

		/*
		 * There might be persistent reservations (from fallocate())
		 * above i_size, which bch_inode_truncate() will discard - we're
		 * only supposed to discard them if we're doing a real truncate
		 * here (new i_size < current i_size):
		 */
		if (shrink) {
			ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
			if (unlikely(ret))
				return ret;

			ret = bch_inode_truncate(c, inode->i_ino,
						 round_up(iattr->ia_size, PAGE_SIZE) >> 9,
						 &ei->journal_seq);
			if (unlikely(ret))
				return ret;
		}

		setattr_copy(inode, iattr);

		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		i_size_update_put(c, ei, idx, 1);
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

static long bch_fpunch(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	u64 ino = inode->i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(inode);
	ret = __bch_truncate_page(inode->i_mapping,
				  offset >> PAGE_SHIFT,
				  offset, offset + len);
	if (unlikely(ret))
		goto out;

	if (offset >> PAGE_SHIFT !=
	    (offset + len) >> PAGE_SHIFT) {
		ret = __bch_truncate_page(inode->i_mapping,
					  (offset + len) >> PAGE_SHIFT,
					  offset, offset + len);
		if (unlikely(ret))
			goto out;
	}

	truncate_pagecache_range(inode, offset, offset + len - 1);

	if (discard_start < discard_end)
		ret = bch_discard(c,
				  POS(ino, discard_start),
				  POS(ino, discard_end),
				  0, &ei->journal_seq);
out:
	inode_unlock(inode);

	return ret;
}

static long bch_fcollapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter src;
	struct btree_iter dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_size_update *u;
	loff_t new_size;
	unsigned idx;
	int ret;

	if ((offset | len) & (PAGE_SIZE - 1))
		return -EINVAL;

	bch_btree_iter_init_intent(&dst, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino, offset >> 9));
	/* position will be set from dst iter's position: */
	bch_btree_iter_init(&src, c, BTREE_ID_EXTENTS, POS_MIN);
	bch_btree_iter_link(&src, &dst);

	/*
	 * We need i_mutex to keep the page cache consistent with the extents
	 * btree, and the btree consistent with i_size - we don't need outside
	 * locking for the extents btree itself, because we're using linked
	 * iterators
	 *
	 * XXX: hmm, need to prevent reads adding things to the pagecache until
	 * we're done?
	 */
	inode_lock(inode);

	ret = -EINVAL;
	if (offset + len >= inode->i_size)
		goto err;

	if (inode->i_size < len)
		goto err;

	new_size = inode->i_size - len;

	inode_dio_wait(inode);

	do {
		ret = filemap_write_and_wait_range(inode->i_mapping,
						   offset, LLONG_MAX);
		if (ret)
			goto err;

		ret = invalidate_inode_pages2_range(inode->i_mapping,
					offset >> PAGE_SHIFT,
					ULONG_MAX);
	} while (ret == -EBUSY);

	if (ret)
		goto err;

	while (bkey_cmp(dst.pos,
			POS(inode->i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		bch_btree_iter_set_pos(&src,
			POS(dst.pos.inode, dst.pos.offset + (len >> 9)));

		/* Have to take intent locks before read locks: */
		ret = bch_btree_iter_traverse(&dst);
		if (ret)
			goto err_unwind;

		k = bch_btree_iter_peek_with_holes(&src);
		if (!k.k) {
			ret = -EIO;
			goto err_unwind;
		}

		bkey_reassemble(&copy.k, k);

		if (bkey_deleted(&copy.k.k))
			copy.k.k.type = KEY_TYPE_DISCARD;

		bch_cut_front(src.pos, &copy.k);
		copy.k.k.p.offset -= len >> 9;

		BUG_ON(bkey_cmp(dst.pos, bkey_start_pos(&copy.k.k)));

		ret = bch_btree_insert_at(&dst,
					  &keylist_single(&copy.k),
					  NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
		if (ret < 0 && ret != -EINTR)
			goto err_unwind;

		bch_btree_iter_unlock(&src);
	}

	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);

	ret = bch_inode_truncate(c, inode->i_ino,
				 round_up(new_size, PAGE_SIZE) >> 9,
				 &ei->journal_seq);
	if (ret)
		goto err_unwind;

	mutex_lock(&ei->update_lock);

	/*
	 * Cancel i_size updates > new_size:
	 *
	 * Note: we're also cancelling i_size updates for appends < new_size, and
	 * writing the new i_size before they finish - would be better to use an
	 * i_size_update here like truncate, so we can sequence our i_size
	 * updates with outstanding appends and not have to cancel them:
	 */
	fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
		u->new_i_size = -1;

	ret = bch_write_inode_size(c, ei, new_size);
	bch_i_size_write(inode, new_size);

	truncate_pagecache(inode, offset);

	mutex_unlock(&ei->update_lock);

	inode_unlock(inode);

	return ret;
err_unwind:
	BUG();
err:
	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);
	inode_unlock(inode);
	return ret;
}

static long bch_fallocate(struct file *file, int mode,
			  loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);

	if (mode == (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE))
		return bch_fpunch(inode, offset, len);

	if (mode == FALLOC_FL_COLLAPSE_RANGE)
		return bch_fcollapse(inode, offset, len);

	return -EOPNOTSUPP;
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

	/*
	 * i_mutex is required for synchronizing with fcollapse()...
	 */
	inode_lock(inode);

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
	inode_unlock(inode);
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
	 * If there's still outstanding appends, we may have not yet written an
	 * i_size that exposes the data we just fsynced - however, we can
	 * advance the i_size on disk up to the end of what we just explicitly
	 * wrote:
	 */

	mutex_lock(&ei->update_lock);

	if (end > ei->i_size &&
	    ei->i_size < inode->i_size) {
		struct i_size_update *u;
		unsigned idx;
		loff_t new_i_size = min_t(u64, inode->i_size,
					  roundup(end, PAGE_SIZE));

		BUG_ON(fifo_empty(&ei->i_size_updates));
		BUG_ON(new_i_size < ei->i_size);

		/*
		 * There can still be a pending i_size update < the size we're
		 * writing, because it may have been shared with pages > the
		 * size we fsynced to:
		 */
		fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
			if (u->new_i_size < new_i_size)
				u->new_i_size = -1;

		ret = bch_write_inode_size(c, ei, new_i_size);
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

static int bch_inode_set_flags(struct bch_inode_info *ei, struct bch_inode *bi,
			       void *p)
{
	unsigned oldflags = bi->i_flags;
	unsigned newflags = *((unsigned *) p);

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
		ret = __bch_write_inode(c, ei, bch_inode_set_flags, &flags);
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
	.fallocate	= bch_fallocate,

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

	struct bch_inode_info	*ei;
	unsigned long		i_size_update_count[I_SIZE_UPDATE_ENTRIES];
	unsigned long		sectors_reserved;

	struct bch_write_op	op;
	/* must come last: */
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
	struct bio *bio = &io->bio.bio.bio;

	bio_put(bio);
}

static void bch_writepage_io_done(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct cache_set *c = io->op.c;
	struct bio *bio = &io->bio.bio.bio;
	struct bch_inode_info *ei = io->ei;
	struct bio_vec *bvec;
	unsigned i;

	atomic_long_sub_bug(io->sectors_reserved, &c->sectors_reserved);

	for (i = 0; i < ARRAY_SIZE(io->i_size_update_count); i++)
		i_size_update_put(c, ei, i, io->i_size_update_count[i]);

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		BUG_ON(!PageWriteback(page));

		if (io->bio.bio.bio.bi_error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		end_page_writeback(page);
	}

	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	pr_debug("writing %u sectors to %llu:%llu",
		 bio_sectors(&io->bio.bio.bio),
		 io->op.insert_key.k.p.inode,
		 (u64) io->bio.bio.bio.bi_iter.bi_sector);

	closure_call(&io->op.cl, bch_write, NULL, &io->cl);
	continue_at(&io->cl, bch_writepage_io_done, io->op.c->wq);
}

/*
 * Get a bch_writepage_io and add @page to it - appending to an existing one if
 * possible, else allocating a new one:
 */
static void bch_writepage_io_alloc(struct bch_writepage *w,
				   struct bch_inode_info *ei,
				   struct page *page)
{
alloc_io:
	if (!w->io) {
		struct bio *bio = bio_alloc_bioset(GFP_NOFS, BIO_MAX_PAGES,
						   bch_writepage_bioset);
		w->io = container_of(bio, struct bch_writepage_io, bio.bio.bio);

		closure_init(&w->io->cl, NULL);
		w->io->ei		= ei;
		memset(w->io->i_size_update_count, 0,
		       sizeof(w->io->i_size_update_count));
		w->io->sectors_reserved	= 0;

		bch_write_op_init(&w->io->op, w->c, &w->io->bio, NULL,
				  bkey_to_s_c(&KEY(w->inum, 0, 0)),
				  bkey_s_c_null,
				  &ei->journal_seq, 0);
	}

	if (bch_bio_add_page(&w->io->bio.bio.bio, page)) {
		bch_writepage_do_io(w->io);
		w->io = NULL;
		goto alloc_io;
	}

	/*
	 * We shouldn't ever be handed pages for multiple inodes in a single
	 * pass - right?
	 */
	BUG_ON(ei != w->io->ei);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_writepage *w = data;
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
	if (check_make_i_size_dirty(ei, page_offset(page) + PAGE_SIZE)) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	bch_writepage_io_alloc(w, ei, page);

	/*
	 * Before unlocking the page, transfer refcounts to w->io:
	 */
	if (PageAppend(page)) {
		struct bch_page_state *s = (void *) &page->private;

		/*
		 * i_size won't get updated and this write's data made visible
		 * until the i_size_update this page points to completes - so
		 * tell the write path to start a new one:
		 */
		if (&ei->i_size_updates.data[s->idx] ==
		    &fifo_back(&ei->i_size_updates))
			set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);

		w->io->i_size_update_count[s->idx]++;
		ClearPageAppend(page);
	}

	if (PageAllocated(page)) {
		w->io->sectors_reserved += PAGE_SECTORS;
		ClearPageAllocated(page);
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
	unsigned offset = pos & (PAGE_SIZE - 1);
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

	if (!offset && pos + len >= inode->i_size) {
		zero_user_segment(page, len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}

	if (index > inode->i_size >> PAGE_SHIFT) {
		zero_user_segments(page, 0, offset, offset + len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
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
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	lockdep_assert_held(&inode->i_rwsem);

	if (unlikely(copied < len && !PageUptodate(page))) {
		/*
		 * The page needs to be read in, but that would destroy
		 * our partial write - simplest thing is to just force
		 * userspace to redo the write:
		 *
		 * userspace doesn't _have_ to redo the write, so clear
		 * PageAllocated:
		 */
		copied = 0;
		zero_user(page, 0, PAGE_SIZE);
		flush_dcache_page(page);
		bch_clear_page_bits(c, ei, page);
		goto out;
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (!PageDirty(page))
		set_page_dirty(page);

	if (pos + copied > inode->i_size) {
		struct i_size_update *u;

		/*
		 * if page already has a ref on a i_size_update, even if it's an
		 * older one, leave it - they have to be flushed in order so
		 * that's just as good as taking a ref on a newer one, if we're
		 * adding a newer one now
		 *
		 * - if there's no current i_size_update, or if we want to
		 *   create a new one and there's room for a new one, create it
		 *
		 * - set current i_size_update's i_size to new i_size
		 *
		 * - if !PageAppend, take a ref on the current i_size_update
		 */

		/* XXX: locking */
		mutex_lock(&ei->update_lock);
		u = i_size_update_new(ei, pos + copied);

		if (!PageAppend(page)) {
			struct bch_page_state *s = (void *) &page->private;

			s->idx = u - ei->i_size_updates.data;
			atomic_long_inc(&u->count);

			SetPageAppend(page);
		}

		bch_i_size_write(inode, pos + copied);
		mutex_unlock(&ei->update_lock);
	}
out:
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
	bool sync = is_sync_kiocb(req);
	loff_t i_size;

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_read_bioset);
	bio_get(bio);

	dio = container_of(bio, struct dio_read, bio);
	closure_init(&dio->cl, NULL);

	/*
	 * this is a _really_ horrible hack just to avoid an atomic sub at the
	 * end:
	 */
	if (!sync) {
		set_closure_fn(&dio->cl, bch_dio_read_complete, NULL);
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER -
			   CLOSURE_RUNNING +
			   CLOSURE_DESTRUCTOR);
	} else {
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER + 1);
	}

	dio->req	= req;
	dio->ret	= iter->count;

	i_size = i_size_read(inode);
	if (offset + dio->ret > i_size) {
		dio->ret = max_t(loff_t, 0, i_size - offset);
		iter->count = round_up(dio->ret, PAGE_SIZE);
	}

	if (!dio->ret) {
		closure_put(&dio->cl);
		goto out;
	}

	goto start;
	while (iter->count) {
		pages = iov_iter_npages(iter, BIO_MAX_PAGES);
		bio = bio_alloc(GFP_KERNEL, pages);
start:
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_end_io		= bch_direct_IO_read_endio;
		bio->bi_private		= dio;

		ret = bio_get_user_pages(bio, iter, 1);
		if (ret < 0) {
			/* XXX: fault inject this path */
			bio->bi_error = ret;
			bio_endio(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;
		bio_set_pages_dirty(bio);

		if (iter->count)
			closure_get(&dio->cl);

		bch_read(c, bio, inum);
	}
out:
	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_put(&dio->bio);
		return ret;
	} else {
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
	dio->ret	= 0;
	dio->append	= false;

	if (offset + iter->count > inode->i_size) {
		/*
		 * XXX: try and convert this to i_size_update_new(), and maybe
		 * make async O_DIRECT appends work
		 */

		dio->append = true;
		i_size_dirty_get(ei);
	}

	ret = check_make_i_size_dirty(ei, offset + iter->count);
	if (ret) {
		if (dio->append)
			i_size_dirty_put(ei);
		kfree(dio);
		return ret;
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
			if (!dio->ret)
				dio->ret = ret;
			kfree(op);
			break;
		}

		offset		+= bio->bi_iter.bi_size;
		dio->ret	+= bio->bi_iter.bi_size;

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

		/*
		 * XXX: if the bch_write call errors, we don't handle partial
		 * writes correctly
		 */

		if (dio->append) {
			int ret2 = 0;

			if (ret > 0 &&
			    offset > inode->i_size) {
				struct i_size_update *u;
				unsigned idx;

				mutex_lock(&ei->update_lock);

				bch_i_size_write(inode, offset);
				i_size_dirty_put(ei);

				fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
					if (u->new_i_size < offset)
						u->new_i_size = -1;

				ret2 = bch_write_inode_size(c, ei, offset);

				mutex_unlock(&ei->update_lock);
			} else {
				i_size_dirty_put(ei);
			}
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

static void bch_inode_init(struct bch_inode_info *ei,
			   struct bkey_s_c_inode bkey_inode)
{
	struct inode *inode = &ei->vfs_inode;
	const struct bch_inode *bi = bkey_inode.v;

	BUG_ON(!fifo_empty(&ei->i_size_updates));

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

	ei->i_size_updates.front	= 0;
	ei->i_size_updates.back		= 0;
	ei->i_size_updates.size		= ARRAY_SIZE(ei->i_size_updates.data) - 1;
	ei->i_size_updates.mask		= ARRAY_SIZE(ei->i_size_updates.data) - 1;
	ei->flags			= 0;

	seqcount_init(&ei->shadow_i_size_lock);

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

		BUG_ON(!fifo_empty(&ei->i_size_updates));
		clear_inode(inode);
	} else if (inode->i_nlink) {
		truncate_inode_pages_final(&inode->i_data);

		BUG_ON(!fifo_empty(&ei->i_size_updates));
		clear_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);

		BUG_ON(!fifo_empty(&ei->i_size_updates));
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
	buf->f_ffree	= U64_MAX;
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
