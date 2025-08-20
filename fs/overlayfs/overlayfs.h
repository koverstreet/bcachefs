/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * Copyright (C) 2011 Novell Inc.
 */

#include <linux/kernel.h>
#include <linux/uuid.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/namei.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include "ovl_entry.h"

#undef pr_fmt
#define pr_fmt(fmt) "overlayfs: " fmt

enum ovl_path_type {
	__OVL_PATH_UPPER	= (1 << 0),
	__OVL_PATH_MERGE	= (1 << 1),
	__OVL_PATH_ORIGIN	= (1 << 2),
};

#define OVL_TYPE_UPPER(type)	((type) & __OVL_PATH_UPPER)
#define OVL_TYPE_MERGE(type)	((type) & __OVL_PATH_MERGE)
#define OVL_TYPE_ORIGIN(type)	((type) & __OVL_PATH_ORIGIN)

#define OVL_XATTR_NAMESPACE "overlay."
#define OVL_XATTR_TRUSTED_PREFIX XATTR_TRUSTED_PREFIX OVL_XATTR_NAMESPACE
#define OVL_XATTR_TRUSTED_PREFIX_LEN (sizeof(OVL_XATTR_TRUSTED_PREFIX) - 1)
#define OVL_XATTR_USER_PREFIX XATTR_USER_PREFIX OVL_XATTR_NAMESPACE
#define OVL_XATTR_USER_PREFIX_LEN (sizeof(OVL_XATTR_USER_PREFIX) - 1)

#define OVL_XATTR_ESCAPE_PREFIX OVL_XATTR_NAMESPACE
#define OVL_XATTR_ESCAPE_PREFIX_LEN (sizeof(OVL_XATTR_ESCAPE_PREFIX) - 1)
#define OVL_XATTR_ESCAPE_TRUSTED_PREFIX OVL_XATTR_TRUSTED_PREFIX OVL_XATTR_ESCAPE_PREFIX
#define OVL_XATTR_ESCAPE_TRUSTED_PREFIX_LEN (sizeof(OVL_XATTR_ESCAPE_TRUSTED_PREFIX) - 1)
#define OVL_XATTR_ESCAPE_USER_PREFIX OVL_XATTR_USER_PREFIX OVL_XATTR_ESCAPE_PREFIX
#define OVL_XATTR_ESCAPE_USER_PREFIX_LEN (sizeof(OVL_XATTR_ESCAPE_USER_PREFIX) - 1)

enum ovl_xattr {
	OVL_XATTR_OPAQUE,
	OVL_XATTR_REDIRECT,
	OVL_XATTR_ORIGIN,
	OVL_XATTR_IMPURE,
	OVL_XATTR_NLINK,
	OVL_XATTR_UPPER,
	OVL_XATTR_UUID,
	OVL_XATTR_METACOPY,
	OVL_XATTR_PROTATTR,
	OVL_XATTR_XWHITEOUT,
};

enum ovl_inode_flag {
	/* Pure upper dir that may contain non pure upper entries */
	OVL_IMPURE,
	/* Non-merge dir that may contain whiteout entries */
	OVL_WHITEOUTS,
	OVL_INDEX,
	OVL_UPPERDATA,
	/* Inode number will remain constant over copy up. */
	OVL_CONST_INO,
	OVL_HAS_DIGEST,
	OVL_VERIFIED_DIGEST,
};

enum ovl_entry_flag {
	OVL_E_UPPER_ALIAS,
	OVL_E_OPAQUE,
	OVL_E_CONNECTED,
	/* Lower stack may contain xwhiteout entries */
	OVL_E_XWHITEOUTS,
};

enum {
	OVL_REDIRECT_OFF,	/* "off" mode is never used. In effect	*/
	OVL_REDIRECT_FOLLOW,	/* ...it translates to either "follow"	*/
	OVL_REDIRECT_NOFOLLOW,	/* ...or "nofollow".			*/
	OVL_REDIRECT_ON,
};

enum {
	OVL_UUID_OFF,
	OVL_UUID_NULL,
	OVL_UUID_AUTO,
	OVL_UUID_ON,
};

enum {
	OVL_XINO_OFF,
	OVL_XINO_AUTO,
	OVL_XINO_ON,
};

enum {
	OVL_VERITY_OFF,
	OVL_VERITY_ON,
	OVL_VERITY_REQUIRE,
};

/*
 * The tuple (fh,uuid) is a universal unique identifier for a copy up origin,
 * where:
 * origin.fh	- exported file handle of the lower file
 * origin.uuid	- uuid of the lower filesystem
 */
#define OVL_FH_VERSION	0
#define OVL_FH_MAGIC	0xfb

/* CPU byte order required for fid decoding:  */
#define OVL_FH_FLAG_BIG_ENDIAN	(1 << 0)
#define OVL_FH_FLAG_ANY_ENDIAN	(1 << 1)
/* Is the real inode encoded in fid an upper inode? */
#define OVL_FH_FLAG_PATH_UPPER	(1 << 2)

#define OVL_FH_FLAG_ALL (OVL_FH_FLAG_BIG_ENDIAN | OVL_FH_FLAG_ANY_ENDIAN | \
			 OVL_FH_FLAG_PATH_UPPER)

#if defined(__LITTLE_ENDIAN)
#define OVL_FH_FLAG_CPU_ENDIAN 0
#elif defined(__BIG_ENDIAN)
#define OVL_FH_FLAG_CPU_ENDIAN OVL_FH_FLAG_BIG_ENDIAN
#else
#error Endianness not defined
#endif

/* The type used to be returned by overlay exportfs for misaligned fid */
#define OVL_FILEID_V0	0xfb
/* The type returned by overlay exportfs for 32bit aligned fid */
#define OVL_FILEID_V1	0xf8

/* On-disk format for "origin" file handle */
struct ovl_fb {
	u8 version;	/* 0 */
	u8 magic;	/* 0xfb */
	u8 len;		/* size of this header + size of fid */
	u8 flags;	/* OVL_FH_FLAG_* */
	u8 type;	/* fid_type of fid */
	uuid_t uuid;	/* uuid of filesystem */
	u32 fid[];	/* file identifier should be 32bit aligned in-memory */
} __packed;

/* In-memory and on-wire format for overlay file handle */
struct ovl_fh {
	u8 padding[3];	/* make sure fb.fid is 32bit aligned */
	union {
		struct ovl_fb fb;
		DECLARE_FLEX_ARRAY(u8, buf);
	};
} __packed;

#define OVL_FH_WIRE_OFFSET	offsetof(struct ovl_fh, fb)
#define OVL_FH_LEN(fh)		(OVL_FH_WIRE_OFFSET + (fh)->fb.len)
#define OVL_FH_FID_OFFSET	(OVL_FH_WIRE_OFFSET + \
				 offsetof(struct ovl_fb, fid))

/* On-disk format for "metacopy" xattr (if non-zero size) */
struct ovl_metacopy {
	u8 version;	/* 0 */
	u8 len;         /* size of this header + used digest bytes */
	u8 flags;
	u8 digest_algo;	/* FS_VERITY_HASH_ALG_* constant, 0 for no digest */
	u8 digest[FS_VERITY_MAX_DIGEST_SIZE];  /* Only the used part on disk */
} __packed;

#define OVL_METACOPY_MAX_SIZE (sizeof(struct ovl_metacopy))
#define OVL_METACOPY_MIN_SIZE (OVL_METACOPY_MAX_SIZE - FS_VERITY_MAX_DIGEST_SIZE)
#define OVL_METACOPY_INIT { 0, OVL_METACOPY_MIN_SIZE }

static inline int ovl_metadata_digest_size(const struct ovl_metacopy *metacopy)
{
	if (metacopy->len < OVL_METACOPY_MIN_SIZE)
		return 0;
	return (int)metacopy->len - OVL_METACOPY_MIN_SIZE;
}

/* No atime modification on underlying */
#define OVL_OPEN_FLAGS (O_NOATIME)

extern const char *const ovl_xattr_table[][2];
static inline const char *ovl_xattr(struct ovl_fs *ofs, enum ovl_xattr ox)
{
	return ovl_xattr_table[ox][ofs->config.userxattr];
}

/*
 * When changing ownership of an upper object map the intended ownership
 * according to the upper layer's idmapping. When an upper mount idmaps files
 * that are stored on-disk as owned by id 1001 to id 1000 this means stat on
 * this object will report it as being owned by id 1000 when calling stat via
 * the upper mount.
 * In order to change ownership of an object so stat reports id 1000 when
 * called on an idmapped upper mount the value written to disk - i.e., the
 * value stored in ia_*id - must 1001. The mount mapping helper will thus take
 * care to map 1000 to 1001.
 * The mnt idmapping helpers are nops if the upper layer isn't idmapped.
 */
static inline int ovl_do_notify_change(struct ovl_fs *ofs,
				       struct dentry *upperdentry,
				       struct iattr *attr)
{
	return notify_change(ovl_upper_mnt_idmap(ofs), upperdentry, attr, NULL);
}

static inline int ovl_do_rmdir(struct ovl_fs *ofs,
			       struct inode *dir, struct dentry *dentry)
{
	int err = vfs_rmdir(ovl_upper_mnt_idmap(ofs), dir, dentry);

	pr_debug("rmdir(%pd2) = %i\n", dentry, err);
	return err;
}

static inline int ovl_do_unlink(struct ovl_fs *ofs, struct inode *dir,
				struct dentry *dentry)
{
	int err = vfs_unlink(ovl_upper_mnt_idmap(ofs), dir, dentry, NULL);

	pr_debug("unlink(%pd2) = %i\n", dentry, err);
	return err;
}

static inline int ovl_do_link(struct ovl_fs *ofs, struct dentry *old_dentry,
			      struct inode *dir, struct dentry *new_dentry)
{
	int err = vfs_link(old_dentry, ovl_upper_mnt_idmap(ofs), dir,
			   new_dentry, NULL);

	pr_debug("link(%pd2, %pd2) = %i\n", old_dentry, new_dentry, err);
	return err;
}

static inline int ovl_do_create(struct ovl_fs *ofs,
				struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	int err = vfs_create(ovl_upper_mnt_idmap(ofs), dir, dentry, mode, true);

	pr_debug("create(%pd2, 0%o) = %i\n", dentry, mode, err);
	return err;
}

static inline struct dentry *ovl_do_mkdir(struct ovl_fs *ofs,
					  struct inode *dir,
					  struct dentry *dentry,
					  umode_t mode)
{
	struct dentry *ret;

	ret = vfs_mkdir(ovl_upper_mnt_idmap(ofs), dir, dentry, mode);
	pr_debug("mkdir(%pd2, 0%o) = %i\n", dentry, mode, PTR_ERR_OR_ZERO(ret));
	return ret;
}

static inline int ovl_do_mknod(struct ovl_fs *ofs,
			       struct inode *dir, struct dentry *dentry,
			       umode_t mode, dev_t dev)
{
	int err = vfs_mknod(ovl_upper_mnt_idmap(ofs), dir, dentry, mode, dev);

	pr_debug("mknod(%pd2, 0%o, 0%o) = %i\n", dentry, mode, dev, err);
	return err;
}

static inline int ovl_do_symlink(struct ovl_fs *ofs,
				 struct inode *dir, struct dentry *dentry,
				 const char *oldname)
{
	int err = vfs_symlink(ovl_upper_mnt_idmap(ofs), dir, dentry, oldname);

	pr_debug("symlink(\"%s\", %pd2) = %i\n", oldname, dentry, err);
	return err;
}

static inline ssize_t ovl_do_getxattr(const struct path *path, const char *name,
				      void *value, size_t size)
{
	int err, len;

	WARN_ON(path->dentry->d_sb != path->mnt->mnt_sb);

	err = vfs_getxattr(mnt_idmap(path->mnt), path->dentry,
			       name, value, size);
	len = (value && err > 0) ? err : 0;

	pr_debug("getxattr(%pd2, \"%s\", \"%*pE\", %zu, 0) = %i\n",
		 path->dentry, name, min(len, 48), value, size, err);
	return err;
}

static inline ssize_t ovl_getxattr_upper(struct ovl_fs *ofs,
					 struct dentry *upperdentry,
					 enum ovl_xattr ox, void *value,
					 size_t size)
{
	struct path upperpath = {
		.dentry = upperdentry,
		.mnt = ovl_upper_mnt(ofs),
	};

	return ovl_do_getxattr(&upperpath, ovl_xattr(ofs, ox), value, size);
}

static inline ssize_t ovl_path_getxattr(struct ovl_fs *ofs,
					 const struct path *path,
					 enum ovl_xattr ox, void *value,
					 size_t size)
{
	return ovl_do_getxattr(path, ovl_xattr(ofs, ox), value, size);
}

static inline int ovl_do_setxattr(struct ovl_fs *ofs, struct dentry *dentry,
				  const char *name, const void *value,
				  size_t size, int flags)
{
	int err = vfs_setxattr(ovl_upper_mnt_idmap(ofs), dentry, name,
			       value, size, flags);

	pr_debug("setxattr(%pd2, \"%s\", \"%*pE\", %zu, %d) = %i\n",
		 dentry, name, min((int)size, 48), value, size, flags, err);
	return err;
}

static inline int ovl_setxattr(struct ovl_fs *ofs, struct dentry *dentry,
			       enum ovl_xattr ox, const void *value,
			       size_t size)
{
	return ovl_do_setxattr(ofs, dentry, ovl_xattr(ofs, ox), value, size, 0);
}

static inline int ovl_do_removexattr(struct ovl_fs *ofs, struct dentry *dentry,
				     const char *name)
{
	int err = vfs_removexattr(ovl_upper_mnt_idmap(ofs), dentry, name);
	pr_debug("removexattr(%pd2, \"%s\") = %i\n", dentry, name, err);
	return err;
}

static inline int ovl_removexattr(struct ovl_fs *ofs, struct dentry *dentry,
				  enum ovl_xattr ox)
{
	return ovl_do_removexattr(ofs, dentry, ovl_xattr(ofs, ox));
}

static inline int ovl_do_set_acl(struct ovl_fs *ofs, struct dentry *dentry,
				 const char *acl_name, struct posix_acl *acl)
{
	return vfs_set_acl(ovl_upper_mnt_idmap(ofs), dentry, acl_name, acl);
}

static inline int ovl_do_remove_acl(struct ovl_fs *ofs, struct dentry *dentry,
				    const char *acl_name)
{
	return vfs_remove_acl(ovl_upper_mnt_idmap(ofs), dentry, acl_name);
}

static inline int ovl_do_rename(struct ovl_fs *ofs, struct inode *olddir,
				struct dentry *olddentry, struct inode *newdir,
				struct dentry *newdentry, unsigned int flags)
{
	int err;
	struct renamedata rd = {
		.old_mnt_idmap	= ovl_upper_mnt_idmap(ofs),
		.old_dir 	= olddir,
		.old_dentry 	= olddentry,
		.new_mnt_idmap	= ovl_upper_mnt_idmap(ofs),
		.new_dir 	= newdir,
		.new_dentry 	= newdentry,
		.flags 		= flags,
	};

	pr_debug("rename(%pd2, %pd2, 0x%x)\n", olddentry, newdentry, flags);
	err = vfs_rename(&rd);
	if (err) {
		pr_debug("...rename(%pd2, %pd2, ...) = %i\n",
			 olddentry, newdentry, err);
	}
	return err;
}

static inline int ovl_do_whiteout(struct ovl_fs *ofs,
				  struct inode *dir, struct dentry *dentry)
{
	int err = vfs_whiteout(ovl_upper_mnt_idmap(ofs), dir, dentry);
	pr_debug("whiteout(%pd2) = %i\n", dentry, err);
	return err;
}

static inline struct file *ovl_do_tmpfile(struct ovl_fs *ofs,
					  struct dentry *dentry, umode_t mode)
{
	struct path path = { .mnt = ovl_upper_mnt(ofs), .dentry = dentry };
	struct file *file = kernel_tmpfile_open(ovl_upper_mnt_idmap(ofs), &path,
						mode, O_LARGEFILE | O_WRONLY,
						current_cred());
	int err = PTR_ERR_OR_ZERO(file);

	pr_debug("tmpfile(%pd2, 0%o) = %i\n", dentry, mode, err);
	return file;
}

static inline struct dentry *ovl_lookup_upper(struct ovl_fs *ofs,
					      const char *name,
					      struct dentry *base, int len)
{
	return lookup_one(ovl_upper_mnt_idmap(ofs), &QSTR_LEN(name, len), base);
}

static inline bool ovl_open_flags_need_copy_up(int flags)
{
	if (!flags)
		return false;

	return ((OPEN_FMODE(flags) & FMODE_WRITE) || (flags & O_TRUNC));
}

/* util.c */
int ovl_get_write_access(struct dentry *dentry);
void ovl_put_write_access(struct dentry *dentry);
void ovl_start_write(struct dentry *dentry);
void ovl_end_write(struct dentry *dentry);
int ovl_want_write(struct dentry *dentry);
void ovl_drop_write(struct dentry *dentry);
struct dentry *ovl_workdir(struct dentry *dentry);
const struct cred *ovl_override_creds(struct super_block *sb);
void ovl_revert_creds(const struct cred *old_cred);

static inline const struct cred *ovl_creds(struct super_block *sb)
{
	return OVL_FS(sb)->creator_cred;
}

int ovl_can_decode_fh(struct super_block *sb);
struct dentry *ovl_indexdir(struct super_block *sb);
bool ovl_index_all(struct super_block *sb);
bool ovl_verify_lower(struct super_block *sb);
struct ovl_path *ovl_stack_alloc(unsigned int n);
void ovl_stack_cpy(struct ovl_path *dst, struct ovl_path *src, unsigned int n);
void ovl_stack_put(struct ovl_path *stack, unsigned int n);
void ovl_stack_free(struct ovl_path *stack, unsigned int n);
struct ovl_entry *ovl_alloc_entry(unsigned int numlower);
void ovl_free_entry(struct ovl_entry *oe);
bool ovl_dentry_remote(struct dentry *dentry);
void ovl_dentry_update_reval(struct dentry *dentry, struct dentry *realdentry);
void ovl_dentry_init_reval(struct dentry *dentry, struct dentry *upperdentry,
			   struct ovl_entry *oe);
void ovl_dentry_init_flags(struct dentry *dentry, struct dentry *upperdentry,
			   struct ovl_entry *oe, unsigned int mask);
bool ovl_dentry_weird(struct dentry *dentry);

static inline bool ovl_dentry_casefolded(struct dentry *dentry)
{
	return sb_has_encoding(dentry->d_sb) && IS_CASEFOLDED(d_inode(dentry));
}

enum ovl_path_type ovl_path_type(struct dentry *dentry);
void ovl_path_upper(struct dentry *dentry, struct path *path);
void ovl_path_lower(struct dentry *dentry, struct path *path);
void ovl_path_lowerdata(struct dentry *dentry, struct path *path);
struct inode *ovl_i_path_real(struct inode *inode, struct path *path);
enum ovl_path_type ovl_path_real(struct dentry *dentry, struct path *path);
enum ovl_path_type ovl_path_realdata(struct dentry *dentry, struct path *path);
struct dentry *ovl_dentry_upper(struct dentry *dentry);
struct dentry *ovl_dentry_lower(struct dentry *dentry);
struct dentry *ovl_dentry_lowerdata(struct dentry *dentry);
int ovl_dentry_set_lowerdata(struct dentry *dentry, struct ovl_path *datapath);
const struct ovl_layer *ovl_i_layer_lower(struct inode *inode);
const struct ovl_layer *ovl_layer_lower(struct dentry *dentry);
struct dentry *ovl_dentry_real(struct dentry *dentry);
struct dentry *ovl_i_dentry_upper(struct inode *inode);
struct inode *ovl_inode_upper(struct inode *inode);
struct inode *ovl_inode_lower(struct inode *inode);
struct inode *ovl_inode_lowerdata(struct inode *inode);
struct inode *ovl_inode_real(struct inode *inode);
struct inode *ovl_inode_realdata(struct inode *inode);
const char *ovl_lowerdata_redirect(struct inode *inode);
struct ovl_dir_cache *ovl_dir_cache(struct inode *inode);
void ovl_set_dir_cache(struct inode *inode, struct ovl_dir_cache *cache);
void ovl_dentry_set_flag(unsigned long flag, struct dentry *dentry);
void ovl_dentry_clear_flag(unsigned long flag, struct dentry *dentry);
bool ovl_dentry_test_flag(unsigned long flag, struct dentry *dentry);
bool ovl_dentry_is_opaque(struct dentry *dentry);
bool ovl_dentry_is_whiteout(struct dentry *dentry);
void ovl_dentry_set_opaque(struct dentry *dentry);
bool ovl_dentry_has_xwhiteouts(struct dentry *dentry);
void ovl_dentry_set_xwhiteouts(struct dentry *dentry);
void ovl_layer_set_xwhiteouts(struct ovl_fs *ofs,
			      const struct ovl_layer *layer);
bool ovl_dentry_has_upper_alias(struct dentry *dentry);
void ovl_dentry_set_upper_alias(struct dentry *dentry);
bool ovl_dentry_needs_data_copy_up(struct dentry *dentry, int flags);
bool ovl_dentry_needs_data_copy_up_locked(struct dentry *dentry, int flags);
bool ovl_has_upperdata(struct inode *inode);
void ovl_set_upperdata(struct inode *inode);
const char *ovl_dentry_get_redirect(struct dentry *dentry);
void ovl_dentry_set_redirect(struct dentry *dentry, const char *redirect);
void ovl_inode_update(struct inode *inode, struct dentry *upperdentry);
void ovl_dir_modified(struct dentry *dentry, bool impurity);
u64 ovl_inode_version_get(struct inode *inode);
bool ovl_is_whiteout(struct dentry *dentry);
bool ovl_path_is_whiteout(struct ovl_fs *ofs, const struct path *path);
struct file *ovl_path_open(const struct path *path, int flags);
int ovl_copy_up_start(struct dentry *dentry, int flags);
void ovl_copy_up_end(struct dentry *dentry);
bool ovl_already_copied_up(struct dentry *dentry, int flags);
char ovl_get_dir_xattr_val(struct ovl_fs *ofs, const struct path *path,
			   enum ovl_xattr ox);
bool ovl_path_check_origin_xattr(struct ovl_fs *ofs, const struct path *path);
bool ovl_path_check_xwhiteout_xattr(struct ovl_fs *ofs, const struct path *path);
bool ovl_init_uuid_xattr(struct super_block *sb, struct ovl_fs *ofs,
			 const struct path *upperpath);

static inline bool ovl_upper_is_whiteout(struct ovl_fs *ofs,
					 struct dentry *upperdentry)
{
	struct path upperpath = {
		.dentry = upperdentry,
		.mnt = ovl_upper_mnt(ofs),
	};
	return ovl_path_is_whiteout(ofs, &upperpath);
}

static inline bool ovl_check_origin_xattr(struct ovl_fs *ofs,
					  struct dentry *upperdentry)
{
	struct path upperpath = {
		.dentry = upperdentry,
		.mnt = ovl_upper_mnt(ofs),
	};
	return ovl_path_check_origin_xattr(ofs, &upperpath);
}

int ovl_check_setxattr(struct ovl_fs *ofs, struct dentry *upperdentry,
		       enum ovl_xattr ox, const void *value, size_t size,
		       int xerr);
int ovl_set_impure(struct dentry *dentry, struct dentry *upperdentry);
bool ovl_inuse_trylock(struct dentry *dentry);
void ovl_inuse_unlock(struct dentry *dentry);
bool ovl_is_inuse(struct dentry *dentry);
bool ovl_need_index(struct dentry *dentry);
int ovl_nlink_start(struct dentry *dentry);
void ovl_nlink_end(struct dentry *dentry);
int ovl_lock_rename_workdir(struct dentry *workdir, struct dentry *upperdir);
int ovl_check_metacopy_xattr(struct ovl_fs *ofs, const struct path *path,
			     struct ovl_metacopy *data);
int ovl_set_metacopy_xattr(struct ovl_fs *ofs, struct dentry *d,
			   struct ovl_metacopy *metacopy);
bool ovl_is_metacopy_dentry(struct dentry *dentry);
char *ovl_get_redirect_xattr(struct ovl_fs *ofs, const struct path *path, int padding);
int ovl_ensure_verity_loaded(struct path *path);
int ovl_validate_verity(struct ovl_fs *ofs,
			struct path *metapath,
			struct path *datapath);
int ovl_get_verity_digest(struct ovl_fs *ofs, struct path *src,
			  struct ovl_metacopy *metacopy);
int ovl_sync_status(struct ovl_fs *ofs);

static inline void ovl_set_flag(unsigned long flag, struct inode *inode)
{
	set_bit(flag, &OVL_I(inode)->flags);
}

static inline void ovl_clear_flag(unsigned long flag, struct inode *inode)
{
	clear_bit(flag, &OVL_I(inode)->flags);
}

static inline bool ovl_test_flag(unsigned long flag, struct inode *inode)
{
	return test_bit(flag, &OVL_I(inode)->flags);
}

static inline bool ovl_is_impuredir(struct super_block *sb,
				    struct dentry *upperdentry)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	struct path upperpath = {
		.dentry = upperdentry,
		.mnt = ovl_upper_mnt(ofs),
	};

	return ovl_get_dir_xattr_val(ofs, &upperpath, OVL_XATTR_IMPURE) == 'y';
}

static inline char ovl_get_opaquedir_val(struct ovl_fs *ofs,
					 const struct path *path)
{
	return ovl_get_dir_xattr_val(ofs, path, OVL_XATTR_OPAQUE);
}

static inline bool ovl_redirect_follow(struct ovl_fs *ofs)
{
	return ofs->config.redirect_mode != OVL_REDIRECT_NOFOLLOW;
}

static inline bool ovl_redirect_dir(struct ovl_fs *ofs)
{
	return ofs->config.redirect_mode == OVL_REDIRECT_ON;
}

static inline bool ovl_origin_uuid(struct ovl_fs *ofs)
{
	return ofs->config.uuid != OVL_UUID_OFF;
}

static inline bool ovl_has_fsid(struct ovl_fs *ofs)
{
	return ofs->config.uuid == OVL_UUID_ON ||
	       ofs->config.uuid == OVL_UUID_AUTO;
}

/*
 * With xino=auto, we do best effort to keep all inodes on same st_dev and
 * d_ino consistent with st_ino.
 * With xino=on, we do the same effort but we warn if we failed.
 */
static inline bool ovl_xino_warn(struct ovl_fs *ofs)
{
	return ofs->config.xino == OVL_XINO_ON;
}

/*
 * To avoid regressions in existing setups with overlay lower offline changes,
 * we allow lower changes only if none of the new features are used.
 */
static inline bool ovl_allow_offline_changes(struct ovl_fs *ofs)
{
	return (!ofs->config.index && !ofs->config.metacopy &&
		!ovl_redirect_dir(ofs) && !ovl_xino_warn(ofs));
}

/* All layers on same fs? */
static inline bool ovl_same_fs(struct ovl_fs *ofs)
{
	return ofs->xino_mode == 0;
}

/* All overlay inodes have same st_dev? */
static inline bool ovl_same_dev(struct ovl_fs *ofs)
{
	return ofs->xino_mode >= 0;
}

static inline unsigned int ovl_xino_bits(struct ovl_fs *ofs)
{
	return ovl_same_dev(ofs) ? ofs->xino_mode : 0;
}

static inline void ovl_inode_lock(struct inode *inode)
{
	mutex_lock(&OVL_I(inode)->lock);
}

static inline int ovl_inode_lock_interruptible(struct inode *inode)
{
	return mutex_lock_interruptible(&OVL_I(inode)->lock);
}

static inline void ovl_inode_unlock(struct inode *inode)
{
	mutex_unlock(&OVL_I(inode)->lock);
}


/* namei.c */
int ovl_check_fb_len(struct ovl_fb *fb, int fb_len);

static inline int ovl_check_fh_len(struct ovl_fh *fh, int fh_len)
{
	if (fh_len < sizeof(struct ovl_fh))
		return -EINVAL;

	return ovl_check_fb_len(&fh->fb, fh_len - OVL_FH_WIRE_OFFSET);
}

struct dentry *ovl_decode_real_fh(struct ovl_fs *ofs, struct ovl_fh *fh,
				  struct vfsmount *mnt, bool connected);
int ovl_check_origin_fh(struct ovl_fs *ofs, struct ovl_fh *fh, bool connected,
			struct dentry *upperdentry, struct ovl_path **stackp);
int ovl_verify_set_fh(struct ovl_fs *ofs, struct dentry *dentry,
		      enum ovl_xattr ox, const struct ovl_fh *fh,
		      bool is_upper, bool set);
int ovl_verify_origin_xattr(struct ovl_fs *ofs, struct dentry *dentry,
			    enum ovl_xattr ox, struct dentry *real,
			    bool is_upper, bool set);
struct dentry *ovl_index_upper(struct ovl_fs *ofs, struct dentry *index,
			       bool connected);
int ovl_verify_index(struct ovl_fs *ofs, struct dentry *index);
int ovl_get_index_name_fh(const struct ovl_fh *fh, struct qstr *name);
int ovl_get_index_name(struct ovl_fs *ofs, struct dentry *origin,
		       struct qstr *name);
struct dentry *ovl_get_index_fh(struct ovl_fs *ofs, struct ovl_fh *fh);
struct dentry *ovl_lookup_index(struct ovl_fs *ofs, struct dentry *upper,
				struct dentry *origin, bool verify);
int ovl_path_next(int idx, struct dentry *dentry, struct path *path,
		  const struct ovl_layer **layer);
int ovl_verify_lowerdata(struct dentry *dentry);
struct dentry *ovl_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags);
bool ovl_lower_positive(struct dentry *dentry);

static inline int ovl_verify_origin_fh(struct ovl_fs *ofs, struct dentry *upper,
				       const struct ovl_fh *fh, bool set)
{
	return ovl_verify_set_fh(ofs, upper, OVL_XATTR_ORIGIN, fh, false, set);
}

static inline int ovl_verify_origin(struct ovl_fs *ofs, struct dentry *upper,
				    struct dentry *origin, bool set)
{
	return ovl_verify_origin_xattr(ofs, upper, OVL_XATTR_ORIGIN, origin,
				       false, set);
}

static inline int ovl_verify_upper(struct ovl_fs *ofs, struct dentry *index,
				   struct dentry *upper, bool set)
{
	return ovl_verify_origin_xattr(ofs, index, OVL_XATTR_UPPER, upper,
				       true, set);
}

/* readdir.c */
extern const struct file_operations ovl_dir_operations;
struct file *ovl_dir_real_file(const struct file *file, bool want_upper);
int ovl_check_empty_dir(struct dentry *dentry, struct list_head *list);
void ovl_cleanup_whiteouts(struct ovl_fs *ofs, struct dentry *upper,
			   struct list_head *list);
void ovl_cache_free(struct list_head *list);
void ovl_dir_cache_free(struct inode *inode);
int ovl_check_d_type_supported(const struct path *realpath);
int ovl_workdir_cleanup(struct ovl_fs *ofs, struct inode *dir,
			struct vfsmount *mnt, struct dentry *dentry, int level);
int ovl_indexdir_cleanup(struct ovl_fs *ofs);

/*
 * Can we iterate real dir directly?
 *
 * Non-merge dir may contain whiteouts from a time it was a merge upper, before
 * lower dir was removed under it and possibly before it was rotated from upper
 * to lower layer.
 */
static inline bool ovl_dir_is_real(struct inode *dir)
{
	return !ovl_test_flag(OVL_WHITEOUTS, dir);
}

/* inode.c */
int ovl_set_nlink_upper(struct dentry *dentry);
int ovl_set_nlink_lower(struct dentry *dentry);
unsigned int ovl_get_nlink(struct ovl_fs *ofs, struct dentry *lowerdentry,
			   struct dentry *upperdentry,
			   unsigned int fallback);
int ovl_permission(struct mnt_idmap *idmap, struct inode *inode,
		   int mask);

#ifdef CONFIG_FS_POSIX_ACL
struct posix_acl *do_ovl_get_acl(struct mnt_idmap *idmap,
				 struct inode *inode, int type,
				 bool rcu, bool noperm);
static inline struct posix_acl *ovl_get_inode_acl(struct inode *inode, int type,
						  bool rcu)
{
	return do_ovl_get_acl(&nop_mnt_idmap, inode, type, rcu, true);
}
static inline struct posix_acl *ovl_get_acl(struct mnt_idmap *idmap,
					    struct dentry *dentry, int type)
{
	return do_ovl_get_acl(idmap, d_inode(dentry), type, false, false);
}
int ovl_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		struct posix_acl *acl, int type);
struct posix_acl *ovl_get_acl_path(const struct path *path,
				   const char *acl_name, bool noperm);
#else
#define ovl_get_inode_acl	NULL
#define ovl_get_acl		NULL
#define ovl_set_acl		NULL
static inline struct posix_acl *ovl_get_acl_path(const struct path *path,
						 const char *acl_name,
						 bool noperm)
{
	return NULL;
}
#endif

int ovl_update_time(struct inode *inode, int flags);
bool ovl_is_private_xattr(struct super_block *sb, const char *name);

struct ovl_inode_params {
	struct inode *newinode;
	struct dentry *upperdentry;
	struct ovl_entry *oe;
	bool index;
	char *redirect;
	char *lowerdata_redirect;
};
void ovl_inode_init(struct inode *inode, struct ovl_inode_params *oip,
		    unsigned long ino, int fsid);
struct inode *ovl_new_inode(struct super_block *sb, umode_t mode, dev_t rdev);
struct inode *ovl_lookup_inode(struct super_block *sb, struct dentry *real,
			       bool is_upper);
bool ovl_lookup_trap_inode(struct super_block *sb, struct dentry *dir);
struct inode *ovl_get_trap_inode(struct super_block *sb, struct dentry *dir);
struct inode *ovl_get_inode(struct super_block *sb,
			    struct ovl_inode_params *oip);
void ovl_copyattr(struct inode *to);

/* vfs inode flags copied from real to ovl inode */
#define OVL_COPY_I_FLAGS_MASK	(S_SYNC | S_NOATIME | S_APPEND | S_IMMUTABLE)
/* vfs inode flags read from overlay.protattr xattr to ovl inode */
#define OVL_PROT_I_FLAGS_MASK	(S_APPEND | S_IMMUTABLE)

/*
 * fileattr flags copied from lower to upper inode on copy up.
 * We cannot copy up immutable/append-only flags, because that would prevent
 * linking temp inode to upper dir, so we store them in xattr instead.
 */
#define OVL_COPY_FS_FLAGS_MASK	(FS_SYNC_FL | FS_NOATIME_FL)
#define OVL_COPY_FSX_FLAGS_MASK	(FS_XFLAG_SYNC | FS_XFLAG_NOATIME)
#define OVL_PROT_FS_FLAGS_MASK  (FS_APPEND_FL | FS_IMMUTABLE_FL)
#define OVL_PROT_FSX_FLAGS_MASK (FS_XFLAG_APPEND | FS_XFLAG_IMMUTABLE)

void ovl_check_protattr(struct inode *inode, struct dentry *upper);
int ovl_set_protattr(struct inode *inode, struct dentry *upper,
		      struct fileattr *fa);

static inline void ovl_copyflags(struct inode *from, struct inode *to)
{
	unsigned int mask = OVL_COPY_I_FLAGS_MASK;

	inode_set_flags(to, from->i_flags & mask, mask);
}

/* dir.c */
extern const struct inode_operations ovl_dir_inode_operations;
int ovl_cleanup_and_whiteout(struct ovl_fs *ofs, struct inode *dir,
			     struct dentry *dentry);
struct ovl_cattr {
	dev_t rdev;
	umode_t mode;
	const char *link;
	struct dentry *hardlink;
};

#define OVL_CATTR(m) (&(struct ovl_cattr) { .mode = (m) })

struct dentry *ovl_create_real(struct ovl_fs *ofs,
			       struct inode *dir, struct dentry *newdentry,
			       struct ovl_cattr *attr);
int ovl_cleanup(struct ovl_fs *ofs, struct inode *dir, struct dentry *dentry);
struct dentry *ovl_lookup_temp(struct ovl_fs *ofs, struct dentry *workdir);
struct dentry *ovl_create_temp(struct ovl_fs *ofs, struct dentry *workdir,
			       struct ovl_cattr *attr);

/* file.c */
extern const struct file_operations ovl_file_operations;
int ovl_real_fileattr_get(const struct path *realpath, struct fileattr *fa);
int ovl_real_fileattr_set(const struct path *realpath, struct fileattr *fa);
int ovl_fileattr_get(struct dentry *dentry, struct fileattr *fa);
int ovl_fileattr_set(struct mnt_idmap *idmap,
		     struct dentry *dentry, struct fileattr *fa);
struct ovl_file;
struct ovl_file *ovl_file_alloc(struct file *realfile);
void ovl_file_free(struct ovl_file *of);

/* copy_up.c */
int ovl_copy_up(struct dentry *dentry);
int ovl_copy_up_with_data(struct dentry *dentry);
int ovl_maybe_copy_up(struct dentry *dentry, int flags);
int ovl_copy_xattr(struct super_block *sb, const struct path *path, struct dentry *new);
int ovl_set_attr(struct ovl_fs *ofs, struct dentry *upper, struct kstat *stat);
struct ovl_fh *ovl_encode_real_fh(struct ovl_fs *ofs, struct inode *realinode,
				  bool is_upper);
struct ovl_fh *ovl_get_origin_fh(struct ovl_fs *ofs, struct dentry *origin);
int ovl_set_origin_fh(struct ovl_fs *ofs, const struct ovl_fh *fh,
		      struct dentry *upper);

/* export.c */
extern const struct export_operations ovl_export_operations;
extern const struct export_operations ovl_export_fid_operations;

/* super.c */
int ovl_fill_super(struct super_block *sb, struct fs_context *fc);

/* Will this overlay be forced to mount/remount ro? */
static inline bool ovl_force_readonly(struct ovl_fs *ofs)
{
	return (!ovl_upper_mnt(ofs) || !ofs->workdir);
}

/* xattr.c */

const struct xattr_handler * const *ovl_xattr_handlers(struct ovl_fs *ofs);
int ovl_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
		struct iattr *attr);
int ovl_getattr(struct mnt_idmap *idmap, const struct path *path,
		struct kstat *stat, u32 request_mask, unsigned int flags);
ssize_t ovl_listxattr(struct dentry *dentry, char *list, size_t size);
