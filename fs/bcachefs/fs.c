#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "acl.h"
#include "btree_update.h"
#include "buckets.h"
#include "chardev.h"
#include "dirent.h"
#include "extents.h"
#include "fs.h"
#include "fs-io.h"
#include "fs-ioctl.h"
#include "fsck.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "quota.h"
#include "super.h"
#include "xattr.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/exportfs.h>
#include <linux/module.h>
#include <linux/posix_acl.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

static struct kmem_cache *bch2_inode_cache;

static void bch2_vfs_inode_init(struct bch_fs *,
				struct bch_inode_info *,
				struct bch_inode_unpacked *);

static void journal_seq_copy(struct bch_inode_info *dst,
			     u64 journal_seq)
{
	u64 old, v = READ_ONCE(dst->ei_journal_seq);

	do {
		old = v;

		if (old >= journal_seq)
			break;
	} while ((v = cmpxchg(&dst->ei_journal_seq, old, journal_seq)) != old);
}

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

void bch2_inode_update_after_write(struct bch_fs *c,
				   struct bch_inode_info *inode,
				   struct bch_inode_unpacked *bi,
				   unsigned fields)
{
	set_nlink(&inode->v, bi->bi_flags & BCH_INODE_UNLINKED
		  ? 0
		  : bi->bi_nlink + nlink_bias(inode->v.i_mode));

	if (fields & ATTR_ATIME)
		inode->v.i_atime = bch2_time_to_timespec(c, bi->bi_atime);
	if (fields & ATTR_MTIME)
		inode->v.i_mtime = bch2_time_to_timespec(c, bi->bi_mtime);
	if (fields & ATTR_CTIME)
		inode->v.i_ctime = bch2_time_to_timespec(c, bi->bi_ctime);

	inode->ei_inode		= *bi;
	inode->ei_qid		= bch_qid(bi);
}

int __must_check bch2_write_inode_trans(struct btree_trans *trans,
				struct bch_inode_info *inode,
				struct bch_inode_unpacked *inode_u,
				inode_set_fn set,
				void *p)
{
	struct bch_fs *c = trans->c;
	struct btree_iter *iter;
	struct bkey_inode_buf *inode_p;
	struct bkey_s_c k;
	u64 inum = inode->v.i_ino;
	int ret;

	lockdep_assert_held(&inode->ei_update_lock);

	iter = bch2_trans_get_iter(trans, BTREE_ID_INODES, POS(inum, 0),
				   BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	k = bch2_btree_iter_peek_slot(iter);
	if ((ret = btree_iter_err(k)))
		return ret;

	if (WARN_ONCE(k.k->type != BCH_INODE_FS,
		      "inode %llu not found when updating", inum))
		return -ENOENT;

	ret = bch2_inode_unpack(bkey_s_c_to_inode(k), inode_u);
	if (WARN_ONCE(ret,
		      "error %i unpacking inode %llu", ret, inum))
		return -ENOENT;

	BUG_ON(inode_u->bi_size != inode->ei_inode.bi_size);

	BUG_ON(inode_u->bi_size != inode->ei_inode.bi_size &&
	       !(inode_u->bi_flags & BCH_INODE_I_SIZE_DIRTY) &&
	       inode_u->bi_size > i_size_read(&inode->v));

	inode_u->bi_mode	= inode->v.i_mode;
	inode_u->bi_uid		= i_uid_read(&inode->v);
	inode_u->bi_gid		= i_gid_read(&inode->v);
	inode_u->bi_project	= inode->ei_qid.q[QTYP_PRJ];
	inode_u->bi_dev		= inode->v.i_rdev;
	inode_u->bi_atime	= timespec_to_bch2_time(c, inode->v.i_atime);
	inode_u->bi_mtime	= timespec_to_bch2_time(c, inode->v.i_mtime);
	inode_u->bi_ctime	= timespec_to_bch2_time(c, inode->v.i_ctime);

	if (set) {
		ret = set(inode, inode_u, p);
		if (ret)
			return ret;
	}

	inode_p = bch2_trans_kmalloc(trans, sizeof(*inode_p));
	if (IS_ERR(inode_p))
		return PTR_ERR(inode_p);

	bch2_inode_pack(inode_p, inode_u);
	bch2_trans_update(trans, iter, &inode_p->inode.k_i, 0);
	return 0;
}

int __must_check __bch2_write_inode(struct bch_fs *c,
				    struct bch_inode_info *inode,
				    inode_set_fn set,
				    void *p, unsigned fields)
{
	struct btree_trans trans;
	struct bch_inode_unpacked inode_u;
	int ret;

	bch2_trans_init(&trans, c);
retry:
	bch2_trans_begin(&trans);

	ret = bch2_write_inode_trans(&trans, inode, &inode_u, set, p) ?:
		bch2_trans_commit(&trans, NULL, NULL,
				  &inode->ei_journal_seq,
				  BTREE_INSERT_ATOMIC|
				  BTREE_INSERT_NOUNLOCK|
				  BTREE_INSERT_NOFAIL);
	if (ret == -EINTR)
		goto retry;

	/*
	 * the btree node lock protects inode->ei_inode, not ei_update_lock;
	 * this is important for inode updates via bchfs_write_index_update
	 */
	if (!ret)
		bch2_inode_update_after_write(c, inode, &inode_u, fields);

	bch2_trans_exit(&trans);
	return ret < 0 ? ret : 0;
}

int __must_check bch2_write_inode(struct bch_fs *c,
				  struct bch_inode_info *inode)
{
	return __bch2_write_inode(c, inode, NULL, NULL, 0);
}

static int inode_mod_nlink_fn(struct bch_inode_info *inode,
				  struct bch_inode_unpacked *bi, void *p)
{
	bi->bi_nlink += (long) p;
	return 0;
}

static int bch2_mod_nlink(struct bch_fs *c, struct bch_inode_info *inode,
			  int count)
{
	int ret;

	mutex_lock(&inode->ei_update_lock);
	ret = __bch2_write_inode(c, inode, inode_mod_nlink_fn,
				 (void *)(long) count, 0);
	mutex_unlock(&inode->ei_update_lock);

	return ret;
}

static int bch2_inc_nlink(struct bch_fs *c, struct bch_inode_info *inode)
{
	return bch2_mod_nlink(c, inode, 1);
}

static int bch2_dec_nlink(struct bch_fs *c, struct bch_inode_info *inode)
{
	return bch2_mod_nlink(c, inode, -1);
}

static struct inode *bch2_vfs_inode_get(struct bch_fs *c, u64 inum)
{
	struct bch_inode_unpacked inode_u;
	struct bch_inode_info *inode;
	int ret;

	inode = to_bch_ei(iget_locked(c->vfs_sb, inum));
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->v.i_state & I_NEW))
		return &inode->v;

	ret = bch2_inode_find_by_inum(c, inum, &inode_u);
	if (ret) {
		iget_failed(&inode->v);
		return ERR_PTR(ret);
	}

	bch2_vfs_inode_init(c, inode, &inode_u);

	inode->ei_journal_seq = bch2_inode_journal_seq(&c->journal, inum);

	unlock_new_inode(&inode->v);

	return &inode->v;
}

static void bch2_inode_init_owner(struct bch_inode_unpacked *inode_u,
				  const struct inode *dir, umode_t mode)
{
	kuid_t uid = current_fsuid();
	kgid_t gid;

	if (dir && dir->i_mode & S_ISGID) {
		gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else
		gid = current_fsgid();

	inode_u->bi_uid		= from_kuid(dir->i_sb->s_user_ns, uid);
	inode_u->bi_gid		= from_kgid(dir->i_sb->s_user_ns, gid);
	inode_u->bi_mode	= mode;
}

static struct bch_inode_info *bch2_vfs_inode_create(struct bch_fs *c,
						    struct bch_inode_info *dir,
						    umode_t mode, dev_t rdev)
{
	struct posix_acl *default_acl = NULL, *acl = NULL;
	struct bch_inode_info *inode;
	struct bch_inode_unpacked inode_u;
	int ret;

	inode = to_bch_ei(new_inode(c->vfs_sb));
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);

	inode_init_owner(&inode->v, &dir->v, mode);

#ifdef CONFIG_BCACHEFS_POSIX_ACL
	ret = posix_acl_create(&dir->v, &inode->v.i_mode, &default_acl, &acl);
	if (ret)
		goto err_make_bad;
#endif

	bch2_inode_init(c, &inode_u,
			i_uid_read(&inode->v),
			i_gid_read(&inode->v),
			inode->v.i_mode, rdev,
			&dir->ei_inode);

	inode_u.bi_project = dir->ei_qid.q[QTYP_PRJ];

	ret = bch2_quota_acct(c, bch_qid(&inode_u), Q_INO, 1, BCH_QUOTA_PREALLOC);
	if (ret)
		goto err_make_bad;

	ret = bch2_inode_create(c, &inode_u,
				BLOCKDEV_INODE_MAX, 0,
				&c->unused_inode_hint);
	if (unlikely(ret))
		goto err_acct_quota;

	bch2_vfs_inode_init(c, inode, &inode_u);
	atomic_long_inc(&c->nr_inodes);

	if (default_acl) {
		ret = __bch2_set_acl(&inode->v, default_acl, ACL_TYPE_DEFAULT);
		if (unlikely(ret))
			goto err;
	}

	if (acl) {
		ret = __bch2_set_acl(&inode->v, acl, ACL_TYPE_ACCESS);
		if (unlikely(ret))
			goto err;
	}

	insert_inode_hash(&inode->v);
out:
	posix_acl_release(default_acl);
	posix_acl_release(acl);
	return inode;
err_acct_quota:
	bch2_quota_acct(c, bch_qid(&inode_u), Q_INO, -1, BCH_QUOTA_WARN);
err_make_bad:
	/*
	 * indicate to bch_evict_inode that the inode was never actually
	 * created:
	 */
	make_bad_inode(&inode->v);
err:
	clear_nlink(&inode->v);
	iput(&inode->v);
	inode = ERR_PTR(ret);
	goto out;
}

static int bch2_vfs_dirent_create(struct bch_fs *c,
				  struct bch_inode_info *dir,
				  u8 type, const struct qstr *name,
				  u64 dst)
{
	int ret;

	ret = bch2_dirent_create(c, dir->v.i_ino, &dir->ei_str_hash,
				type, name, dst,
				&dir->ei_journal_seq,
				BCH_HASH_SET_MUST_CREATE);
	if (unlikely(ret))
		return ret;

	dir->v.i_mtime = dir->v.i_ctime = current_time(&dir->v);
	mark_inode_dirty_sync(&dir->v);
	return 0;
}

static int inode_update_for_create_fn(struct bch_inode_info *inode,
				      struct bch_inode_unpacked *bi,
				      void *p)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_inode_unpacked *new_inode = p;
	struct timespec64 now = current_time(&inode->v);

	bi->bi_mtime = bi->bi_ctime = timespec_to_bch2_time(c, now);

	if (S_ISDIR(new_inode->bi_mode))
		bi->bi_nlink++;

	return 0;
}

static int __bch2_create(struct bch_inode_info *dir, struct dentry *dentry,
			 umode_t mode, dev_t rdev, bool tmpfile)
{
	struct bch_fs *c = dir->v.i_sb->s_fs_info;
	struct btree_trans trans;
	struct bch_inode_unpacked dir_u;
	struct bch_inode_info *inode, *old;
	struct bch_inode_unpacked inode_u;
	struct bch_hash_info hash_info;
	struct posix_acl *default_acl = NULL, *acl = NULL;
	int ret;

	bch2_inode_init(c, &inode_u, 0, 0, 0, rdev, &dir->ei_inode);
	bch2_inode_init_owner(&inode_u, &dir->v, mode);

	inode_u.bi_project = dir->ei_qid.q[QTYP_PRJ];

	hash_info = bch2_hash_info_init(c, &inode_u);

	if (tmpfile)
		inode_u.bi_flags |= BCH_INODE_UNLINKED;

	ret = bch2_quota_acct(c, bch_qid(&inode_u), Q_INO, 1, BCH_QUOTA_PREALLOC);
	if (ret)
		return ret;

#ifdef CONFIG_BCACHEFS_POSIX_ACL
	ret = posix_acl_create(&dir->v, &inode_u.bi_mode, &default_acl, &acl);
	if (ret)
		goto err;
#endif

	/*
	 * preallocate vfs inode before btree transaction, so that nothing can
	 * fail after the transaction succeeds:
	 */
	inode = to_bch_ei(new_inode(c->vfs_sb));
	if (unlikely(!inode)) {
		ret = -ENOMEM;
		goto err;
	}

	bch2_trans_init(&trans, c);
retry:
	bch2_trans_begin(&trans);

	ret   = __bch2_inode_create(&trans, &inode_u,
				    BLOCKDEV_INODE_MAX, 0,
				    &c->unused_inode_hint) ?:
		(default_acl
		 ? bch2_set_acl_trans(&trans, &inode_u, &hash_info,
				      default_acl, ACL_TYPE_DEFAULT)
		 : 0) ?:
		(acl
		 ? bch2_set_acl_trans(&trans, &inode_u, &hash_info,
				      acl, ACL_TYPE_ACCESS)
		 : 0) ?:
		(!tmpfile
		 ? __bch2_dirent_create(&trans, dir->v.i_ino,
					&dir->ei_str_hash,
					mode_to_type(mode),
					&dentry->d_name,
					inode_u.bi_inum,
					BCH_HASH_SET_MUST_CREATE)
		: 0) ?:
		(!tmpfile
		 ? bch2_write_inode_trans(&trans, dir, &dir_u,
					  inode_update_for_create_fn,
					  &inode_u)
		 : 0) ?:
		bch2_trans_commit(&trans, NULL, NULL,
				  &inode->ei_journal_seq,
				  BTREE_INSERT_ATOMIC|
				  BTREE_INSERT_NOUNLOCK);
	if (ret == -EINTR)
		goto retry;
	if (unlikely(ret))
		goto err_trans;

	atomic_long_inc(&c->nr_inodes);

	if (!tmpfile) {
		bch2_inode_update_after_write(c, dir, &dir_u,
					      ATTR_MTIME|ATTR_CTIME);
		journal_seq_copy(dir, inode->ei_journal_seq);
	}

	bch2_vfs_inode_init(c, inode, &inode_u);

	set_cached_acl(&inode->v, ACL_TYPE_ACCESS, acl);
	set_cached_acl(&inode->v, ACL_TYPE_DEFAULT, default_acl);

	/*
	 * we must insert the new inode into the inode cache before calling
	 * bch2_trans_exit() and dropping locks, else we could race with another
	 * thread pulling the inode in and modifying it:
	 */

	old = to_bch_ei(insert_inode_locked2(&inode->v));
	if (unlikely(old)) {
		/*
		 * We raced, another process pulled the new inode into cache
		 * before us:
		 */
		old->ei_journal_seq = inode->ei_journal_seq;
		make_bad_inode(&inode->v);
		iput(&inode->v);

		inode = old;
	} else {
		/*
		 * we really don't want insert_inode_locked2() to be setting
		 * I_NEW...
		 */
		unlock_new_inode(&inode->v);
	}

	bch2_trans_exit(&trans);

	if (tmpfile)
		d_mark_tmpfile(dentry, &inode->v);
	d_instantiate(dentry, &inode->v);
out:
	posix_acl_release(default_acl);
	posix_acl_release(acl);
	return ret;
err_trans:
	bch2_trans_exit(&trans);
	make_bad_inode(&inode->v);
	iput(&inode->v);
err:
	bch2_quota_acct(c, bch_qid(&inode_u), Q_INO, -1, BCH_QUOTA_WARN);
	goto out;
}

/* methods */

static struct dentry *bch2_lookup(struct inode *vdir, struct dentry *dentry,
				  unsigned int flags)
{
	struct bch_fs *c = vdir->i_sb->s_fs_info;
	struct bch_inode_info *dir = to_bch_ei(vdir);
	struct inode *vinode = NULL;
	u64 inum;

	inum = bch2_dirent_lookup(c, dir->v.i_ino,
				  &dir->ei_str_hash,
				  &dentry->d_name);

	if (inum)
		vinode = bch2_vfs_inode_get(c, inum);

	return d_splice_alias(vinode, dentry);
}

static int bch2_create(struct inode *vdir, struct dentry *dentry,
		       umode_t mode, bool excl)
{
	return __bch2_create(to_bch_ei(vdir), dentry, mode|S_IFREG, 0, false);
}

static int bch2_link(struct dentry *old_dentry, struct inode *vdir,
		     struct dentry *dentry)
{
	struct bch_fs *c = vdir->i_sb->s_fs_info;
	struct bch_inode_info *dir = to_bch_ei(vdir);
	struct bch_inode_info *inode = to_bch_ei(old_dentry->d_inode);
	int ret;

	lockdep_assert_held(&inode->v.i_rwsem);

	inode->v.i_ctime = current_time(&dir->v);

	ret = bch2_inc_nlink(c, inode);
	if (ret)
		return ret;

	ihold(&inode->v);

	ret = bch2_vfs_dirent_create(c, dir, mode_to_type(inode->v.i_mode),
				     &dentry->d_name, inode->v.i_ino);
	if (unlikely(ret)) {
		bch2_dec_nlink(c, inode);
		iput(&inode->v);
		return ret;
	}

	d_instantiate(dentry, &inode->v);
	return 0;
}

static int bch2_unlink(struct inode *vdir, struct dentry *dentry)
{
	struct bch_fs *c = vdir->i_sb->s_fs_info;
	struct bch_inode_info *dir = to_bch_ei(vdir);
	struct bch_inode_info *inode = to_bch_ei(dentry->d_inode);
	int ret;

	lockdep_assert_held(&inode->v.i_rwsem);

	ret = bch2_dirent_delete(c, dir->v.i_ino, &dir->ei_str_hash,
				 &dentry->d_name, &dir->ei_journal_seq);
	if (ret)
		return ret;

	if (dir->ei_journal_seq > inode->ei_journal_seq)
		inode->ei_journal_seq = dir->ei_journal_seq;

	inode->v.i_ctime = dir->v.i_ctime;

	if (S_ISDIR(inode->v.i_mode)) {
		bch2_dec_nlink(c, dir);
		drop_nlink(&inode->v);
	}

	bch2_dec_nlink(c, inode);

	return 0;
}

static int bch2_symlink(struct inode *vdir, struct dentry *dentry,
			const char *symname)
{
	struct bch_fs *c = vdir->i_sb->s_fs_info;
	struct bch_inode_info *dir = to_bch_ei(vdir), *inode;
	int ret;

	inode = bch2_vfs_inode_create(c, dir, S_IFLNK|S_IRWXUGO, 0);
	if (unlikely(IS_ERR(inode)))
		return PTR_ERR(inode);

	inode_lock(&inode->v);
	ret = page_symlink(&inode->v, symname, strlen(symname) + 1);
	inode_unlock(&inode->v);

	if (unlikely(ret))
		goto err;

	ret = filemap_write_and_wait_range(inode->v.i_mapping, 0, LLONG_MAX);
	if (unlikely(ret))
		goto err;

	journal_seq_copy(dir, inode->ei_journal_seq);

	ret = bch2_vfs_dirent_create(c, dir, DT_LNK, &dentry->d_name,
				     inode->v.i_ino);
	if (unlikely(ret))
		goto err;

	d_instantiate(dentry, &inode->v);
	return 0;
err:
	clear_nlink(&inode->v);
	iput(&inode->v);
	return ret;
}

static int bch2_mkdir(struct inode *vdir, struct dentry *dentry, umode_t mode)
{
	return __bch2_create(to_bch_ei(vdir), dentry, mode|S_IFDIR, 0, false);
}

static int bch2_rmdir(struct inode *vdir, struct dentry *dentry)
{
	struct bch_fs *c = vdir->i_sb->s_fs_info;

	if (bch2_empty_dir(c, dentry->d_inode->i_ino))
		return -ENOTEMPTY;

	return bch2_unlink(vdir, dentry);
}

static int bch2_mknod(struct inode *vdir, struct dentry *dentry,
		      umode_t mode, dev_t rdev)
{
	return __bch2_create(to_bch_ei(vdir), dentry, mode, rdev, false);
}

static int bch2_rename(struct bch_fs *c,
		       struct bch_inode_info *old_dir,
		       struct dentry *old_dentry,
		       struct bch_inode_info *new_dir,
		       struct dentry *new_dentry)
{
	struct bch_inode_info *old_inode = to_bch_ei(old_dentry->d_inode);
	struct bch_inode_info *new_inode = to_bch_ei(new_dentry->d_inode);
	struct timespec64 now = current_time(&old_dir->v);
	int ret;

	lockdep_assert_held(&old_dir->v.i_rwsem);
	lockdep_assert_held(&new_dir->v.i_rwsem);

	if (new_inode)
		filemap_write_and_wait_range(old_inode->v.i_mapping,
					     0, LLONG_MAX);

	if (new_inode && S_ISDIR(old_inode->v.i_mode)) {
		lockdep_assert_held(&new_inode->v.i_rwsem);

		if (!S_ISDIR(new_inode->v.i_mode))
			return -ENOTDIR;

		if (bch2_empty_dir(c, new_inode->v.i_ino))
			return -ENOTEMPTY;

		ret = bch2_dirent_rename(c,
				old_dir, &old_dentry->d_name,
				new_dir, &new_dentry->d_name,
				&old_inode->ei_journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		clear_nlink(&new_inode->v);
		bch2_dec_nlink(c, old_dir);
	} else if (new_inode) {
		lockdep_assert_held(&new_inode->v.i_rwsem);

		ret = bch2_dirent_rename(c,
				old_dir, &old_dentry->d_name,
				new_dir, &new_dentry->d_name,
				&old_inode->ei_journal_seq, BCH_RENAME_OVERWRITE);
		if (unlikely(ret))
			return ret;

		new_inode->v.i_ctime = now;
		bch2_dec_nlink(c, new_inode);
	} else if (S_ISDIR(old_inode->v.i_mode)) {
		ret = bch2_dirent_rename(c,
				old_dir, &old_dentry->d_name,
				new_dir, &new_dentry->d_name,
				&old_inode->ei_journal_seq, BCH_RENAME);
		if (unlikely(ret))
			return ret;

		bch2_inc_nlink(c, new_dir);
		bch2_dec_nlink(c, old_dir);
	} else {
		ret = bch2_dirent_rename(c,
				old_dir, &old_dentry->d_name,
				new_dir, &new_dentry->d_name,
				&old_inode->ei_journal_seq, BCH_RENAME);
		if (unlikely(ret))
			return ret;
	}

	old_dir->v.i_ctime = old_dir->v.i_mtime = now;
	new_dir->v.i_ctime = new_dir->v.i_mtime = now;
	mark_inode_dirty_sync(&old_dir->v);
	mark_inode_dirty_sync(&new_dir->v);

	old_inode->v.i_ctime = now;
	mark_inode_dirty_sync(&old_inode->v);

	return 0;
}

static int bch2_rename_exchange(struct bch_fs *c,
				struct bch_inode_info *old_dir,
				struct dentry *old_dentry,
				struct bch_inode_info *new_dir,
				struct dentry *new_dentry)
{
	struct bch_inode_info *old_inode = to_bch_ei(old_dentry->d_inode);
	struct bch_inode_info *new_inode = to_bch_ei(new_dentry->d_inode);
	struct timespec64 now = current_time(&old_dir->v);
	int ret;

	ret = bch2_dirent_rename(c,
				 old_dir, &old_dentry->d_name,
				 new_dir, &new_dentry->d_name,
				 &old_inode->ei_journal_seq, BCH_RENAME_EXCHANGE);
	if (unlikely(ret))
		return ret;

	if (S_ISDIR(old_inode->v.i_mode) !=
	    S_ISDIR(new_inode->v.i_mode)) {
		if (S_ISDIR(old_inode->v.i_mode)) {
			bch2_inc_nlink(c, new_dir);
			bch2_dec_nlink(c, old_dir);
		} else {
			bch2_dec_nlink(c, new_dir);
			bch2_inc_nlink(c, old_dir);
		}
	}

	old_dir->v.i_ctime = old_dir->v.i_mtime = now;
	new_dir->v.i_ctime = new_dir->v.i_mtime = now;
	mark_inode_dirty_sync(&old_dir->v);
	mark_inode_dirty_sync(&new_dir->v);

	old_inode->v.i_ctime = now;
	new_inode->v.i_ctime = now;
	mark_inode_dirty_sync(&old_inode->v);
	mark_inode_dirty_sync(&new_inode->v);

	return 0;
}

static int bch2_rename2(struct inode *old_vdir, struct dentry *old_dentry,
			struct inode *new_vdir, struct dentry *new_dentry,
			unsigned flags)
{
	struct bch_fs *c = old_vdir->i_sb->s_fs_info;
	struct bch_inode_info *old_dir = to_bch_ei(old_vdir);
	struct bch_inode_info *new_dir = to_bch_ei(new_vdir);

	if (flags & ~(RENAME_NOREPLACE|RENAME_EXCHANGE))
		return -EINVAL;

	if (flags & RENAME_EXCHANGE)
		return bch2_rename_exchange(c, old_dir, old_dentry,
					    new_dir, new_dentry);

	return bch2_rename(c, old_dir, old_dentry, new_dir, new_dentry);
}

static int bch2_setattr_nonsize(struct bch_inode_info *inode, struct iattr *iattr)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_qid qid = inode->ei_qid;
	unsigned qtypes = 0;
	int ret;

	mutex_lock(&inode->ei_update_lock);

	if (c->opts.usrquota &&
	    (iattr->ia_valid & ATTR_UID) &&
	    !uid_eq(iattr->ia_uid, inode->v.i_uid)) {
		qid.q[QTYP_USR] = from_kuid(&init_user_ns, iattr->ia_uid),
		qtypes |= 1 << QTYP_USR;
	}

	if (c->opts.grpquota &&
	    (iattr->ia_valid & ATTR_GID) &&
	    !gid_eq(iattr->ia_gid, inode->v.i_gid)) {
		qid.q[QTYP_GRP] = from_kgid(&init_user_ns, iattr->ia_gid);
		qtypes |= 1 << QTYP_GRP;
	}

	if (qtypes) {
		ret = bch2_quota_transfer(c, qtypes, qid, inode->ei_qid,
					  inode->v.i_blocks +
					  inode->ei_quota_reserved);
		if (ret)
			goto out_unlock;
	}

	setattr_copy(&inode->v, iattr);

	ret = bch2_write_inode(c, inode);
out_unlock:
	mutex_unlock(&inode->ei_update_lock);

	if (!ret &&
	    iattr->ia_valid & ATTR_MODE)
		ret = posix_acl_chmod(&inode->v, inode->v.i_mode);

	return ret;
}

static int bch2_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned query_flags)
{
	struct bch_inode_info *inode = to_bch_ei(d_inode(path->dentry));
	struct bch_fs *c = inode->v.i_sb->s_fs_info;

	stat->dev	= inode->v.i_sb->s_dev;
	stat->ino	= inode->v.i_ino;
	stat->mode	= inode->v.i_mode;
	stat->nlink	= inode->v.i_nlink;
	stat->uid	= inode->v.i_uid;
	stat->gid	= inode->v.i_gid;
	stat->rdev	= inode->v.i_rdev;
	stat->size	= i_size_read(&inode->v);
	stat->atime	= inode->v.i_atime;
	stat->mtime	= inode->v.i_mtime;
	stat->ctime	= inode->v.i_ctime;
	stat->blksize	= block_bytes(c);
	stat->blocks	= inode->v.i_blocks;

	if (request_mask & STATX_BTIME) {
		stat->result_mask |= STATX_BTIME;
		stat->btime = bch2_time_to_timespec(c, inode->ei_inode.bi_otime);
	}

	if (inode->ei_inode.bi_flags & BCH_INODE_IMMUTABLE)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (inode->ei_inode.bi_flags & BCH_INODE_APPEND)
		stat->attributes |= STATX_ATTR_APPEND;
	if (inode->ei_inode.bi_flags & BCH_INODE_NODUMP)
		stat->attributes |= STATX_ATTR_NODUMP;

	return 0;
}

static int bch2_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct bch_inode_info *inode = to_bch_ei(dentry->d_inode);
	int ret;

	lockdep_assert_held(&inode->v.i_rwsem);

	ret = setattr_prepare(dentry, iattr);
	if (ret)
		return ret;

	return iattr->ia_valid & ATTR_SIZE
		? bch2_truncate(inode, iattr)
		: bch2_setattr_nonsize(inode, iattr);
}

static int bch2_tmpfile(struct inode *vdir, struct dentry *dentry, umode_t mode)
{
	return __bch2_create(to_bch_ei(vdir), dentry, mode, 0, true);
}

static int bch2_fill_extent(struct fiemap_extent_info *info,
			    const struct bkey_i *k, unsigned flags)
{
	if (bkey_extent_is_data(&k->k)) {
		struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
		const struct bch_extent_ptr *ptr;
		struct bch_extent_crc_unpacked crc;
		int ret;

		extent_for_each_ptr_crc(e, ptr, crc) {
			int flags2 = 0;
			u64 offset = ptr->offset;

			if (crc.compression_type)
				flags2 |= FIEMAP_EXTENT_ENCODED;
			else
				offset += crc.offset;

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

static int bch2_fiemap(struct inode *vinode, struct fiemap_extent_info *info,
		       u64 start, u64 len)
{
	struct bch_fs *c = vinode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(vinode);
	struct btree_iter iter;
	struct bkey_s_c k;
	BKEY_PADDED(k) tmp;
	bool have_extent = false;
	int ret = 0;

	if (start + len < start)
		return -EINVAL;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(ei->v.i_ino, start >> 9), 0, k)
		if (bkey_extent_is_data(k.k) ||
		    k.k->type == BCH_RESERVATION) {
			if (bkey_cmp(bkey_start_pos(k.k),
				     POS(ei->v.i_ino, (start + len) >> 9)) >= 0)
				break;

			if (have_extent) {
				ret = bch2_fill_extent(info, &tmp.k, 0);
				if (ret)
					goto out;
			}

			bkey_reassemble(&tmp.k, k);
			have_extent = true;
		}

	if (have_extent)
		ret = bch2_fill_extent(info, &tmp.k, FIEMAP_EXTENT_LAST);
out:
	bch2_btree_iter_unlock(&iter);
	return ret < 0 ? ret : 0;
}

static const struct vm_operations_struct bch_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = bch2_page_mkwrite,
};

static int bch2_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);

	vma->vm_ops = &bch_vm_ops;
	return 0;
}

/* Directories: */

static loff_t bch2_dir_llseek(struct file *file, loff_t offset, int whence)
{
	return generic_file_llseek_size(file, offset, whence,
					S64_MAX, S64_MAX);
}

static int bch2_vfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct bch_fs *c = file_inode(file)->i_sb->s_fs_info;

	return bch2_readdir(c, file, ctx);
}

static const struct file_operations bch_file_operations = {
	.llseek		= bch2_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= bch2_write_iter,
	.mmap		= bch2_mmap,
	.open		= generic_file_open,
	.fsync		= bch2_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= bch2_fallocate_dispatch,
	.unlocked_ioctl = bch2_fs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bch2_compat_fs_ioctl,
#endif
};

static const struct inode_operations bch_file_inode_operations = {
	.getattr	= bch2_getattr,
	.setattr	= bch2_setattr,
	.fiemap		= bch2_fiemap,
	.listxattr	= bch2_xattr_list,
#ifdef CONFIG_BCACHEFS_POSIX_ACL
	.get_acl	= bch2_get_acl,
	.set_acl	= bch2_set_acl,
#endif
};

static const struct inode_operations bch_dir_inode_operations = {
	.lookup		= bch2_lookup,
	.create		= bch2_create,
	.link		= bch2_link,
	.unlink		= bch2_unlink,
	.symlink	= bch2_symlink,
	.mkdir		= bch2_mkdir,
	.rmdir		= bch2_rmdir,
	.mknod		= bch2_mknod,
	.rename		= bch2_rename2,
	.getattr	= bch2_getattr,
	.setattr	= bch2_setattr,
	.tmpfile	= bch2_tmpfile,
	.listxattr	= bch2_xattr_list,
#ifdef CONFIG_BCACHEFS_POSIX_ACL
	.get_acl	= bch2_get_acl,
	.set_acl	= bch2_set_acl,
#endif
};

static const struct file_operations bch_dir_file_operations = {
	.llseek		= bch2_dir_llseek,
	.read		= generic_read_dir,
	.iterate	= bch2_vfs_readdir,
	.fsync		= bch2_fsync,
	.unlocked_ioctl = bch2_fs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bch2_compat_fs_ioctl,
#endif
};

static const struct inode_operations bch_symlink_inode_operations = {
	.get_link	= page_get_link,
	.getattr	= bch2_getattr,
	.setattr	= bch2_setattr,
	.listxattr	= bch2_xattr_list,
#ifdef CONFIG_BCACHEFS_POSIX_ACL
	.get_acl	= bch2_get_acl,
	.set_acl	= bch2_set_acl,
#endif
};

static const struct inode_operations bch_special_inode_operations = {
	.getattr	= bch2_getattr,
	.setattr	= bch2_setattr,
	.listxattr	= bch2_xattr_list,
#ifdef CONFIG_BCACHEFS_POSIX_ACL
	.get_acl	= bch2_get_acl,
	.set_acl	= bch2_set_acl,
#endif
};

static const struct address_space_operations bch_address_space_operations = {
	.writepage	= bch2_writepage,
	.readpage	= bch2_readpage,
	.writepages	= bch2_writepages,
	.readpages	= bch2_readpages,
	.set_page_dirty	= bch2_set_page_dirty,
	.write_begin	= bch2_write_begin,
	.write_end	= bch2_write_end,
	.invalidatepage	= bch2_invalidatepage,
	.releasepage	= bch2_releasepage,
	.direct_IO	= bch2_direct_IO,
#ifdef CONFIG_MIGRATION
	.migratepage	= bch2_migrate_page,
#endif
	.error_remove_page = generic_error_remove_page,
};

static struct inode *bch2_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct bch_fs *c = sb->s_fs_info;
	struct inode *vinode;

	if (ino < BCACHEFS_ROOT_INO)
		return ERR_PTR(-ESTALE);

	vinode = bch2_vfs_inode_get(c, ino);
	if (IS_ERR(vinode))
		return ERR_CAST(vinode);
	if (generation && vinode->i_generation != generation) {
		/* we didn't find the right inode.. */
		iput(vinode);
		return ERR_PTR(-ESTALE);
	}
	return vinode;
}

static struct dentry *bch2_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    bch2_nfs_get_inode);
}

static struct dentry *bch2_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    bch2_nfs_get_inode);
}

static const struct export_operations bch_export_ops = {
	.fh_to_dentry	= bch2_fh_to_dentry,
	.fh_to_parent	= bch2_fh_to_parent,
	//.get_parent	= bch2_get_parent,
};

static void bch2_vfs_inode_init(struct bch_fs *c,
				struct bch_inode_info *inode,
				struct bch_inode_unpacked *bi)
{
	bch2_inode_update_after_write(c, inode, bi, ~0);

	inode->v.i_mode		= bi->bi_mode;
	i_uid_write(&inode->v, bi->bi_uid);
	i_gid_write(&inode->v, bi->bi_gid);
	inode->v.i_blocks	= bi->bi_sectors;
	inode->v.i_ino		= bi->bi_inum;
	inode->v.i_rdev		= bi->bi_dev;
	inode->v.i_generation	= bi->bi_generation;
	inode->v.i_size		= bi->bi_size;

	inode->ei_journal_seq	= 0;
	inode->ei_quota_reserved = 0;
	inode->ei_str_hash	= bch2_hash_info_init(c, bi);

	bch2_inode_flags_to_vfs(inode);

	inode->v.i_mapping->a_ops = &bch_address_space_operations;

	switch (inode->v.i_mode & S_IFMT) {
	case S_IFREG:
		inode->v.i_op	= &bch_file_inode_operations;
		inode->v.i_fop	= &bch_file_operations;
		break;
	case S_IFDIR:
		inode->v.i_op	= &bch_dir_inode_operations;
		inode->v.i_fop	= &bch_dir_file_operations;
		break;
	case S_IFLNK:
		inode_nohighmem(&inode->v);
		inode->v.i_op	= &bch_symlink_inode_operations;
		break;
	default:
		init_special_inode(&inode->v, inode->v.i_mode, inode->v.i_rdev);
		inode->v.i_op	= &bch_special_inode_operations;
		break;
	}
}

static struct inode *bch2_alloc_inode(struct super_block *sb)
{
	struct bch_inode_info *inode;

	inode = kmem_cache_alloc(bch2_inode_cache, GFP_NOFS);
	if (!inode)
		return NULL;

	inode_init_once(&inode->v);
	mutex_init(&inode->ei_update_lock);
	mutex_init(&inode->ei_quota_lock);
	inode->ei_journal_seq = 0;

	return &inode->v;
}

static void bch2_i_callback(struct rcu_head *head)
{
	struct inode *vinode = container_of(head, struct inode, i_rcu);
	struct bch_inode_info *inode = to_bch_ei(vinode);

	kmem_cache_free(bch2_inode_cache, inode);
}

static void bch2_destroy_inode(struct inode *vinode)
{
	call_rcu(&vinode->i_rcu, bch2_i_callback);
}

static int inode_update_times_fn(struct bch_inode_info *inode,
				 struct bch_inode_unpacked *bi,
				 void *p)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;

	bi->bi_atime	= timespec_to_bch2_time(c, inode->v.i_atime);
	bi->bi_mtime	= timespec_to_bch2_time(c, inode->v.i_mtime);
	bi->bi_ctime	= timespec_to_bch2_time(c, inode->v.i_ctime);

	return 0;
}

static int bch2_vfs_write_inode(struct inode *vinode,
				struct writeback_control *wbc)
{
	struct bch_fs *c = vinode->i_sb->s_fs_info;
	struct bch_inode_info *inode = to_bch_ei(vinode);
	int ret;

	mutex_lock(&inode->ei_update_lock);
	ret = __bch2_write_inode(c, inode, inode_update_times_fn, NULL,
				 ATTR_ATIME|ATTR_MTIME|ATTR_CTIME);
	mutex_unlock(&inode->ei_update_lock);

	if (c->opts.journal_flush_disabled)
		return ret;

	if (!ret && wbc->sync_mode == WB_SYNC_ALL)
		ret = bch2_journal_flush_seq(&c->journal, inode->ei_journal_seq);

	return ret;
}

static void bch2_evict_inode(struct inode *vinode)
{
	struct bch_fs *c = vinode->i_sb->s_fs_info;
	struct bch_inode_info *inode = to_bch_ei(vinode);

	truncate_inode_pages_final(&inode->v.i_data);

	clear_inode(&inode->v);

	BUG_ON(!is_bad_inode(&inode->v) && inode->ei_quota_reserved);

	if (!inode->v.i_nlink && !is_bad_inode(&inode->v)) {
		bch2_quota_acct(c, inode->ei_qid, Q_SPC, -((s64) inode->v.i_blocks),
				BCH_QUOTA_WARN);
		bch2_quota_acct(c, inode->ei_qid, Q_INO, -1,
				BCH_QUOTA_WARN);
		bch2_inode_rm(c, inode->v.i_ino);

		WARN_ONCE(atomic_long_dec_return(&c->nr_inodes) < 0,
			  "nr_inodes < 0");
	}
}

static int bch2_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct bch_fs *c = sb->s_fs_info;
	u64 fsid;

	buf->f_type	= BCACHEFS_STATFS_MAGIC;
	buf->f_bsize	= sb->s_blocksize;
	buf->f_blocks	= c->capacity >> PAGE_SECTOR_SHIFT;
	buf->f_bfree	= bch2_fs_sectors_free(c, bch2_fs_usage_read(c)) >>
			   PAGE_SECTOR_SHIFT;
	buf->f_bavail	= buf->f_bfree;
	buf->f_files	= atomic_long_read(&c->nr_inodes);
	buf->f_ffree	= U64_MAX;

	fsid = le64_to_cpup((void *) c->sb.user_uuid.b) ^
	       le64_to_cpup((void *) c->sb.user_uuid.b + sizeof(u64));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
	buf->f_namelen	= BCH_NAME_MAX;

	return 0;
}

static int bch2_sync_fs(struct super_block *sb, int wait)
{
	struct bch_fs *c = sb->s_fs_info;

	if (!wait) {
		bch2_journal_flush_async(&c->journal, NULL);
		return 0;
	}

	return bch2_journal_flush(&c->journal);
}

static struct bch_fs *bch2_path_to_fs(const char *dev)
{
	struct bch_fs *c;
	struct block_device *bdev = lookup_bdev(dev);

	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	c = bch2_bdev_to_fs(bdev);
	bdput(bdev);
	return c ?: ERR_PTR(-ENOENT);
}

static struct bch_fs *__bch2_open_as_blockdevs(const char *dev_name, char * const *devs,
					       unsigned nr_devs, struct bch_opts opts)
{
	struct bch_fs *c, *c1, *c2;
	size_t i;

	if (!nr_devs)
		return ERR_PTR(-EINVAL);

	c = bch2_fs_open(devs, nr_devs, opts);

	if (IS_ERR(c) && PTR_ERR(c) == -EBUSY) {
		/*
		 * Already open?
		 * Look up each block device, make sure they all belong to a
		 * filesystem and they all belong to the _same_ filesystem
		 */

		c1 = bch2_path_to_fs(devs[0]);
		if (!c1)
			return c;

		for (i = 1; i < nr_devs; i++) {
			c2 = bch2_path_to_fs(devs[i]);
			if (!IS_ERR(c2))
				closure_put(&c2->cl);

			if (c1 != c2) {
				closure_put(&c1->cl);
				return c;
			}
		}

		c = c1;
	}

	if (IS_ERR(c))
		return c;

	mutex_lock(&c->state_lock);

	if (!bch2_fs_running(c)) {
		mutex_unlock(&c->state_lock);
		closure_put(&c->cl);
		pr_err("err mounting %s: incomplete filesystem", dev_name);
		return ERR_PTR(-EINVAL);
	}

	mutex_unlock(&c->state_lock);

	set_bit(BCH_FS_BDEV_MOUNTED, &c->flags);
	return c;
}

static struct bch_fs *bch2_open_as_blockdevs(const char *_dev_name,
					     struct bch_opts opts)
{
	char *dev_name = NULL, **devs = NULL, *s;
	struct bch_fs *c = ERR_PTR(-ENOMEM);
	size_t i, nr_devs = 0;

	dev_name = kstrdup(_dev_name, GFP_KERNEL);
	if (!dev_name)
		goto err;

	for (s = dev_name; s; s = strchr(s + 1, ':'))
		nr_devs++;

	devs = kcalloc(nr_devs, sizeof(const char *), GFP_KERNEL);
	if (!devs)
		goto err;

	for (i = 0, s = dev_name;
	     s;
	     (s = strchr(s, ':')) && (*s++ = '\0'))
		devs[i++] = s;

	c = __bch2_open_as_blockdevs(_dev_name, devs, nr_devs, opts);
err:
	kfree(devs);
	kfree(dev_name);
	return c;
}

static int bch2_remount(struct super_block *sb, int *flags, char *data)
{
	struct bch_fs *c = sb->s_fs_info;
	struct bch_opts opts = bch2_opts_empty();
	int ret;

	opt_set(opts, read_only, (*flags & SB_RDONLY) != 0);

	ret = bch2_parse_mount_opts(&opts, data);
	if (ret)
		return ret;

	if (opts.read_only != c->opts.read_only) {
		const char *err = NULL;

		mutex_lock(&c->state_lock);

		if (opts.read_only) {
			bch2_fs_read_only(c);

			sb->s_flags |= SB_RDONLY;
		} else {
			err = bch2_fs_read_write(c);
			if (err) {
				bch_err(c, "error going rw: %s", err);
				return -EINVAL;
			}

			sb->s_flags &= ~SB_RDONLY;
		}

		c->opts.read_only = opts.read_only;

		mutex_unlock(&c->state_lock);
	}

	if (opts.errors >= 0)
		c->opts.errors = opts.errors;

	return ret;
}

static int bch2_show_options(struct seq_file *seq, struct dentry *root)
{
	struct bch_fs *c = root->d_sb->s_fs_info;
	enum bch_opt_id i;
	char buf[512];

	for (i = 0; i < bch2_opts_nr; i++) {
		const struct bch_option *opt = &bch2_opt_table[i];
		u64 v = bch2_opt_get_by_id(&c->opts, i);

		if (opt->mode < OPT_MOUNT)
			continue;

		if (v == bch2_opt_get_by_id(&bch2_opts_default, i))
			continue;

		bch2_opt_to_text(c, buf, sizeof(buf), opt, v,
				 OPT_SHOW_MOUNT_STYLE);
		seq_putc(seq, ',');
		seq_puts(seq, buf);
	}

	return 0;

}

static const struct super_operations bch_super_operations = {
	.alloc_inode	= bch2_alloc_inode,
	.destroy_inode	= bch2_destroy_inode,
	.write_inode	= bch2_vfs_write_inode,
	.evict_inode	= bch2_evict_inode,
	.sync_fs	= bch2_sync_fs,
	.statfs		= bch2_statfs,
	.show_options	= bch2_show_options,
	.remount_fs	= bch2_remount,
#if 0
	.put_super	= bch2_put_super,
	.freeze_fs	= bch2_freeze,
	.unfreeze_fs	= bch2_unfreeze,
#endif
};

static int bch2_test_super(struct super_block *s, void *data)
{
	return s->s_fs_info == data;
}

static int bch2_set_super(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return 0;
}

static struct dentry *bch2_mount(struct file_system_type *fs_type,
				 int flags, const char *dev_name, void *data)
{
	struct bch_fs *c;
	struct bch_dev *ca;
	struct super_block *sb;
	struct inode *vinode;
	struct bch_opts opts = bch2_opts_empty();
	unsigned i;
	int ret;

	opt_set(opts, read_only, (flags & SB_RDONLY) != 0);

	ret = bch2_parse_mount_opts(&opts, data);
	if (ret)
		return ERR_PTR(ret);

	c = bch2_open_as_blockdevs(dev_name, opts);
	if (IS_ERR(c))
		return ERR_CAST(c);

	sb = sget(fs_type, bch2_test_super, bch2_set_super, flags|SB_NOSEC, c);
	if (IS_ERR(sb)) {
		closure_put(&c->cl);
		return ERR_CAST(sb);
	}

	BUG_ON(sb->s_fs_info != c);

	if (sb->s_root) {
		closure_put(&c->cl);

		if ((flags ^ sb->s_flags) & SB_RDONLY) {
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
	sb->s_export_op		= &bch_export_ops;
#ifdef CONFIG_BCACHEFS_QUOTA
	sb->s_qcop		= &bch2_quotactl_operations;
	sb->s_quota_types	= QTYPE_MASK_USR|QTYPE_MASK_GRP|QTYPE_MASK_PRJ;
#endif
	sb->s_xattr		= bch2_xattr_handlers;
	sb->s_magic		= BCACHEFS_STATFS_MAGIC;
	sb->s_time_gran		= c->sb.time_precision;
	c->vfs_sb		= sb;
	strlcpy(sb->s_id, c->name, sizeof(sb->s_id));

	ret = super_setup_bdi(sb);
	if (ret)
		goto err_put_super;

	sb->s_bdi->congested_fn		= bch2_congested;
	sb->s_bdi->congested_data	= c;
	sb->s_bdi->ra_pages		= VM_MAX_READAHEAD * 1024 / PAGE_SIZE;

	for_each_online_member(ca, c, i) {
		struct block_device *bdev = ca->disk_sb.bdev;

		/* XXX: create an anonymous device for multi device filesystems */
		sb->s_bdev	= bdev;
		sb->s_dev	= bdev->bd_dev;
		percpu_ref_put(&ca->io_ref);
		break;
	}

#ifdef CONFIG_BCACHEFS_POSIX_ACL
	if (c->opts.acl)
		sb->s_flags	|= SB_POSIXACL;
#endif

	vinode = bch2_vfs_inode_get(c, BCACHEFS_ROOT_INO);
	if (IS_ERR(vinode)) {
		ret = PTR_ERR(vinode);
		goto err_put_super;
	}

	sb->s_root = d_make_root(vinode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_put_super;
	}

	sb->s_flags |= SB_ACTIVE;
out:
	return dget(sb->s_root);

err_put_super:
	deactivate_locked_super(sb);
	return ERR_PTR(ret);
}

static void bch2_kill_sb(struct super_block *sb)
{
	struct bch_fs *c = sb->s_fs_info;

	generic_shutdown_super(sb);

	if (test_bit(BCH_FS_BDEV_MOUNTED, &c->flags))
		bch2_fs_stop(c);
	else
		closure_put(&c->cl);
}

static struct file_system_type bcache_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bcachefs",
	.mount		= bch2_mount,
	.kill_sb	= bch2_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};

MODULE_ALIAS_FS("bcachefs");

void bch2_vfs_exit(void)
{
	unregister_filesystem(&bcache_fs_type);
	if (bch2_inode_cache)
		kmem_cache_destroy(bch2_inode_cache);
}

int __init bch2_vfs_init(void)
{
	int ret = -ENOMEM;

	bch2_inode_cache = KMEM_CACHE(bch_inode_info, 0);
	if (!bch2_inode_cache)
		goto err;

	ret = register_filesystem(&bcache_fs_type);
	if (ret)
		goto err;

	return 0;
err:
	bch2_vfs_exit();
	return ret;
}

#endif /* NO_BCACHEFS_FS */
