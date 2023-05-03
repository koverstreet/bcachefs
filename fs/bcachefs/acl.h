/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ACL_H
#define _BCACHEFS_ACL_H

struct bch_inode_unpacked;
struct bch_hash_info;
struct bch_inode_info;
struct posix_acl;

#ifdef CONFIG_BCACHEFS_POSIX_ACL

#define BCH_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} bch_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} bch_acl_entry_short;

typedef struct {
	__le32		a_version;
} bch_acl_header;

struct posix_acl *bch2_get_acl(struct mnt_idmap *, struct dentry *, int);

int bch2_set_acl_trans(struct btree_trans *,
		       struct bch_inode_unpacked *,
		       const struct bch_hash_info *,
		       struct posix_acl *, int);
int bch2_set_acl(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
int bch2_acl_chmod(struct btree_trans *, struct bch_inode_unpacked *,
		   umode_t, struct posix_acl **);

#else

static inline int bch2_set_acl_trans(struct btree_trans *trans,
				     struct bch_inode_unpacked *inode_u,
				     const struct bch_hash_info *hash_info,
				     struct posix_acl *acl, int type)
{
	return 0;
}

static inline int bch2_acl_chmod(struct btree_trans *trans,
				 struct bch_inode_unpacked *inode,
				 umode_t mode,
				 struct posix_acl **new_acl)
{
	return 0;
}

#endif /* CONFIG_BCACHEFS_POSIX_ACL */

#endif /* _BCACHEFS_ACL_H */
