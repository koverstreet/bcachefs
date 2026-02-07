// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"

#include "fs/dirent.h"
#include "fs/inode.h"
#include "fs/namei.h"
#include "fs/quota.h"

#include "snapshots/snapshot.h"
#include "snapshots/subvolume.h"

#include "alloc/accounting.h"
#include "btree/write_buffer.h"

#include "init/chardev.h"
#include "init/fs.h"

#include "vfs/fs.h"
#include "vfs/ioctl.h"

#include <linux/compat.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/security.h>
#include <linux/writeback.h>

#define FS_IOC_GOINGDOWN	     _IOR('X', 125, __u32)
#define FSOP_GOING_FLAGS_DEFAULT	0x0	/* going down */
#define FSOP_GOING_FLAGS_LOGFLUSH	0x1	/* flush log but not data */
#define FSOP_GOING_FLAGS_NOLOGFLUSH	0x2	/* don't flush log nor data */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0)
#define start_creating_user_path	user_path_create
#define end_creating_path		done_path_create
#define start_removing_user_path_at	user_path_locked_at
#endif

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
	struct bch_inode_info *dst;
	struct inode *vinode = NULL;
	char *kname = NULL;
	struct qstr qstr;
	int ret = 0;
	subvol_inum inum;

	struct bch_hash_info hash;
	try(bch2_hash_info_init(c, &src->ei_inode, &hash));

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

	vinode = bch2_vfs_inode_get(c, inum, __func__);
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
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	char label[BCH_SB_LABEL_SIZE];
	if (copy_from_user(label, user_label, sizeof(label)))
		return -EFAULT;

	if (strnlen(label, BCH_SB_LABEL_SIZE) == BCH_SB_LABEL_SIZE) {
		bch_err(c,
			"unable to set label with more than %d bytes",
			BCH_SB_LABEL_SIZE - 1);
		return -EINVAL;
	}

	try(mnt_want_write_file(file));

	int ret;
	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&c->sb_lock);
		strscpy(c->disk_sb.sb->label, label, BCH_SB_LABEL_SIZE);
		ret = bch2_write_super(c);
	}

	mnt_drop_write_file(file);
	return ret;
}

static int bch2_ioc_goingdown(struct bch_fs *c, u32 __user *arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	u32 flags;
	try(get_user(flags, arg));

	CLASS(bch_log_msg, msg)(c);
	msg.m.suppress = true; /* cleared by ERO */

	prt_printf(&msg.m, "shutdown by ioctl type %u", flags);

	switch (flags) {
	case FSOP_GOING_FLAGS_DEFAULT:
		try(bdev_freeze(c->vfs_sb->s_bdev));

		bch2_journal_flush(&c->journal);
		bch2_fs_emergency_read_only(c, &msg.m);

		bdev_thaw(c->vfs_sb->s_bdev);
		return 0;
	case FSOP_GOING_FLAGS_LOGFLUSH:
		bch2_journal_flush(&c->journal);
		fallthrough;
	case FSOP_GOING_FLAGS_NOLOGFLUSH:
		bch2_fs_emergency_read_only(c, &msg.m);
		return 0;
	default:
		return -EINVAL;
	}
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

	dst_dentry = start_creating_user_path(arg.dirfd,
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

	scoped_guard(rwsem_write, &c->snapshots.create_lock)
		inode = __bch2_create(file_mnt_idmap(filp), to_bch_ei(dir),
				      dst_dentry, arg.mode|S_IFDIR,
				      0, snapshot_src, create_flags);
	error = PTR_ERR_OR_ZERO(inode);
	if (error)
		goto err3;

	d_instantiate(dst_dentry, &inode->v);
	fsnotify_mkdir(dir, dst_dentry);
err3:
	end_creating_path(&dst_path, dst_dentry);
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

	victim = start_removing_user_path_at(arg.dirfd, name, &path);
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
	if (ret && err.buf)
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

/*
 * Check if the current user can traverse from a child subvolume root
 * up to the parent subvolume, checking MAY_EXEC on each intermediate
 * directory using the full VFS permission stack (including POSIX ACLs
 * and LSM hooks).
 *
 * Returns 0 if accessible, 1 to skip (permission denied or path doesn't
 * connect to parent), or negative on error.
 */
static inline void bch2_iput(struct bch_inode_info *inode) { iput(&inode->v); }
DEFINE_DARRAY_NAMED_FREE_ITEM(darray_inode, struct bch_inode_info *, bch2_iput);

static int bch2_check_path_accessible(struct btree_trans *trans,
				      struct mnt_idmap *idmap,
				      struct bch_subvolume *child,
				      u32 child_subvol, u32 parent_subvol)
{
	struct bch_inode_info *inode = bch2_vfs_inode_get_trans(trans,
			(subvol_inum) { child_subvol, le64_to_cpu(child->inode) },
			__func__);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	u32 parent_sv = inode->ei_inode.bi_parent_subvol;
	u64 dir_inum = inode->ei_inode.bi_dir;
	iput(&inode->v);

	if (!parent_sv)
		return -EIO;

	CLASS(darray_inode, check_inodes)();

	while (dir_inum) {
		inode = bch2_vfs_inode_get_trans(trans,
				(subvol_inum) { parent_sv, dir_inum }, __func__);
		if (IS_ERR(inode))
			return PTR_ERR(inode);

		int ret = darray_push(&check_inodes, inode);
		if (ret) {
			iput(&inode->v);
			return ret;
		}

		if (inode->ei_inode.bi_subvol == parent_subvol)
			goto check_perms;

		dir_inum = inode->ei_inode.bi_dir;
	}

	return 1;
check_perms:
	/*
	 * Unlock the transaction before calling inode_permission(),
	 * which may trigger bch2_get_acl() needing its own transaction.
	 */
	bch2_trans_unlock(trans);

	darray_for_each(check_inodes, i) {
		int ret = inode_permission(idmap, &(*i)->v, MAY_EXEC);
		if (ret)
			return 1;
	}

	return bch2_trans_relock(trans);
}

static int bch2_subvol_readdir_emit(struct btree_trans *trans,
				    struct mnt_idmap *idmap,
				    u32 parent, u32 child_subvol,
				    char __user *buf, u32 buf_size,
				    u32 *used, u32 *pos)
{
	struct bch_subvolume child;
	try(bch2_subvolume_get(trans, child_subvol, true, &child));

	int ret = bch2_check_path_accessible(trans, idmap, &child, child_subvol, parent);
	if (ret) {
		if (ret > 0) {
			*pos = child_subvol + 1;
			ret = 0;
		}
		return ret;
	}

	CLASS(printbuf, path)();
	ret = bch2_inum_to_path_in_subvol(trans,
		(subvol_inum) { child_subvol, le64_to_cpu(child.inode) },
		parent, INUM_TO_PATH_FAIL_ON_ERR, &path);
	if (ret) {
		if (!bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			*pos = child_subvol + 1;
			ret = 0;
		}
		return ret;
	}

	/* Strip leading '/' — paths are relative to the readdir directory */
	char *p = path.buf;
	u32 len = path.pos;
	while (len && *p == '/') { p++; len--; }

	u32 path_bytes = len + 1;
	u32 reclen = ALIGN(offsetof(struct bch_ioctl_subvol_dirent, path) +
			   path_bytes, 8);

	if (*used + reclen > buf_size)
		return 1;

	struct timespec64 otime = bch2_time_to_timespec(trans->c,
						le64_to_cpu(child.otime.lo));

	struct bch_ioctl_subvol_dirent ent = {
		.reclen		= reclen,
		.subvolid	= child_subvol,
		.flags		= le32_to_cpu(child.flags),
		.snapshot_parent = le32_to_cpu(child.creation_parent),
		.otime_sec	= otime.tv_sec,
		.otime_nsec	= otime.tv_nsec,
	};

	try(copy_to_user_errcode(buf + *used, &ent, sizeof(ent)));
	try(copy_to_user_errcode(buf + *used + sizeof(ent), p, path_bytes));

	/* Zero-fill alignment padding between NUL terminator and next entry */
	u32 written = sizeof(ent) + path_bytes;
	if (written < reclen &&
	    clear_user(buf + *used + written, reclen - written))
		return -EFAULT;

	*used += reclen;
	*pos = child_subvol + 1;
	return 0;
}

static long bch2_ioctl_subvolume_list(struct bch_fs *c, struct file *filp,
				      struct bch_ioctl_subvol_readdir __user *user_arg)
{
	struct bch_ioctl_subvol_readdir arg;
	try(copy_from_user_errcode(&arg, user_arg, sizeof(arg)));

	if (arg.pad)
		return -EINVAL;

	u32 parent = inode_inum(file_bch_inode(filp)).subvol;
	struct mnt_idmap *idmap = file_mnt_idmap(filp);

	char __user *buf = (char __user *)(unsigned long)arg.buf;
	u32 used = 0;
	u32 pos = arg.pos;

	CLASS(btree_trans, trans)(c);

	int ret = for_each_btree_key(trans, iter,
			BTREE_ID_subvolume_children,
			POS(parent, arg.pos),
			BTREE_ITER_prefetch, k, ({
		if (k.k->p.inode != parent)
			break;

		int ret2 = bch2_subvol_readdir_emit(trans, idmap,
						    parent, k.k->p.offset,
						    buf, arg.buf_size,
						    &used, &pos);
		if (ret2 > 0)
			break;
		ret2;
	}));

	if (ret)
		return ret;

	try(put_user(pos, &user_arg->pos));
	try(put_user(used, &user_arg->used));

	return 0;
}

static long bch2_ioctl_subvolume_to_path(struct bch_fs *c, struct file *filp,
					 struct bch_ioctl_subvol_to_path __user *user_arg)
{
	struct bch_ioctl_subvol_to_path arg;
	try(copy_from_user_errcode(&arg, user_arg, sizeof(arg)));

	if (!arg.buf_size)
		return -EINVAL;

	CLASS(btree_trans, trans)(c);
	CLASS(printbuf, path)();

	struct bch_subvolume subvol;
	int ret = lockrestart_do(trans, ({
		printbuf_reset(&path);
		bch2_subvolume_get(trans, arg.subvolid, false, &subvol) ?:
		bch2_inum_to_path(trans,
			(subvol_inum) { arg.subvolid, le64_to_cpu(subvol.inode) },
			&path);
	}));
	if (ret)
		return ret;

	/* Strip leading '/' — return path relative to mountpoint */
	char *p = path.buf;
	u32 len = path.pos;
	while (len && *p == '/') { p++; len--; }

	u32 path_bytes = len + 1; /* include NUL */
	if (path_bytes > arg.buf_size)
		return -ERANGE;

	char __user *ubuf = (char __user *)(unsigned long)arg.buf;
	try(copy_to_user_errcode(ubuf, p, path_bytes));

	return 0;
}

static int bch2_ioctl_snapshot_tree_resolve(struct btree_trans *trans,
					    struct file *filp, u32 arg_tree_id,
					    u32 *tree_id, struct bch_snapshot_tree *st)
{
	*tree_id = arg_tree_id;

	if (!*tree_id) {
		u32 subvolid = inode_inum(file_bch_inode(filp)).subvol;

		struct bch_subvolume subvol;
		try(bch2_subvolume_get(trans, subvolid, false, &subvol));

		*tree_id = bch2_snapshot_tree(trans->c, le32_to_cpu(subvol.snapshot));
		if (!*tree_id)
			return -ENOENT;
	}

	return bch2_snapshot_tree_lookup(trans, *tree_id, st);
}

static long bch2_ioctl_snapshot_tree(struct bch_fs *c, struct file *filp,
					   struct bch_ioctl_snapshot_tree_query __user *user_arg)
{
	struct bch_ioctl_snapshot_tree_query arg;
	try(copy_from_user_errcode(&arg, user_arg, sizeof(arg)));

	if (arg.pad)
		return -EINVAL;

	/* Querying a specific tree by ID requires CAP_SYS_ADMIN */
	if (arg.tree_id && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	u32 tree_id = arg.tree_id;
	struct bch_snapshot_tree st;
	{
		CLASS(btree_trans, trans)(c);

		int ret = lockrestart_do(trans,
			bch2_ioctl_snapshot_tree_resolve(trans, filp, arg.tree_id, &tree_id, &st));
		if (ret)
			return ret;
	}

	u32 size = arg.nr;
	u32 nr = 0;
	u32 total = 0;

	CLASS(btree_trans, trans)(c);

	/* Flush write buffer so accounting keys are visible in the btree */
	try(bch2_btree_write_buffer_flush_sync(trans));

	int ret = for_each_btree_key(trans, iter,
			BTREE_ID_snapshots, POS_MIN,
			BTREE_ITER_prefetch, k, ({
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		struct bkey_s_c_snapshot snap = bkey_s_c_to_snapshot(k);
		if (le32_to_cpu(snap.v->tree) != tree_id)
			continue;
		if (BCH_SNAPSHOT_DELETED(snap.v))
			continue;

		u64 sectors[1] = {};
		int _ret = bch2_fs_accounting_read_key2(trans, sectors,
				snapshot, .id = k.k->p.offset);
		if (!_ret) {
			total++;

			if (nr < size) {
				struct bch_ioctl_snapshot_node node = {
					.id		= k.k->p.offset,
					.parent		= le32_to_cpu(snap.v->parent),
					.children	= {
						le32_to_cpu(snap.v->children[0]),
						le32_to_cpu(snap.v->children[1]),
					},
					.subvol		= le32_to_cpu(snap.v->subvol),
					.flags		= le32_to_cpu(snap.v->flags),
					.sectors	= sectors[0],
				};

				_ret = copy_to_user_errcode(&user_arg->nodes[nr], &node,
							    sizeof(node));
				if (!_ret)
					nr++;
			}
		}
		_ret;
	}));

	if (ret)
		return ret;

	try(put_user(le32_to_cpu(st.master_subvol), &user_arg->master_subvol));
	try(put_user(le32_to_cpu(st.root_snapshot), &user_arg->root_snapshot));
	try(put_user(nr, &user_arg->nr));
	try(put_user(total, &user_arg->total));

	if (size && size < total)
		return -ERANGE;

	return 0;
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

	case BCH_IOCTL_SUBVOLUME_LIST:
		ret = bch2_ioctl_subvolume_list(c, file,
				(struct bch_ioctl_subvol_readdir __user *) arg);
		break;

	case BCH_IOCTL_SUBVOLUME_TO_PATH:
		ret = bch2_ioctl_subvolume_to_path(c, file,
				(struct bch_ioctl_subvol_to_path __user *) arg);
		break;

	case BCH_IOCTL_SNAPSHOT_TREE:
		ret = bch2_ioctl_snapshot_tree(c, file,
				(struct bch_ioctl_snapshot_tree_query __user *) arg);
		break;

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
