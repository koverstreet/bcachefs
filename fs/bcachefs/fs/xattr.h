/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_XATTR_H
#define _BCACHEFS_XATTR_H

#include "str_hash.h"
#include "snapshots/types.h"
#include <linux/slab.h>

extern const struct bch_hash_desc bch2_xattr_hash_desc;

int bch2_xattr_validate(struct bch_fs *, struct bkey_s_c,
			struct bkey_validate_context);
void bch2_xattr_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_xattr ((struct bkey_ops) {	\
	.key_validate	= bch2_xattr_validate,		\
	.val_to_text	= bch2_xattr_to_text,		\
	.min_val_size	= 8,				\
})

static inline unsigned xattr_val_u64s(unsigned name_len, unsigned val_len)
{
	return DIV_ROUND_UP(offsetof(struct bch_xattr, x_name_and_value) +
			    name_len + val_len, sizeof(u64));
}

#define xattr_val(_xattr)					\
	((void *) (_xattr)->x_name_and_value + (_xattr)->x_name_len)

struct xattr_search_key {
	u8		type;
	struct qstr	name;
};

#define X_SEARCH(_type, _name, _len) ((struct xattr_search_key)	\
	{ .type = _type, .name = QSTR_INIT(_name, _len) })

struct dentry;
struct xattr_handler;
struct bch_hash_info;
struct bch_inode_info;

/* Exported for cmd_migrate.c in tools: */
int bch2_xattr_set(struct btree_trans *, subvol_inum,
		   struct bch_inode_unpacked *,
		   const char *, const void *, size_t, int, int);

ssize_t bch2_xattr_list(struct dentry *, char *, size_t);

extern const struct xattr_handler * const bch2_xattr_handlers[];

struct bch_security_xattrs {
	struct bkey_i_xattr** xattrs;
};

int bch2_init_security_xattrs(struct bch_security_xattrs *sec_xattrs,
			struct inode *inode, struct inode *dir,
			const struct qstr *name);
int bch2_apply_security_xattrs_trans(struct bch_security_xattrs sec_xattrs,
				struct bch_fs *c,
				struct btree_trans *trans, subvol_inum subvol_inum,
				struct bch_inode_unpacked *inode_u);
static inline void bch2_free_security_xattrs(struct bch_security_xattrs sec_xattrs) {
	if (!sec_xattrs.xattrs) return;
	for (struct bkey_i_xattr **i=sec_xattrs.xattrs; (*i) != NULL; i++) {
		kfree(*i);
	}
	kfree(sec_xattrs.xattrs);
}
#endif /* _BCACHEFS_XATTR_H */
