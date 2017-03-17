#ifndef _BCACHEFS_XATTR_H
#define _BCACHEFS_XATTR_H

#include "str_hash.h"

extern const struct bch_hash_desc bch2_xattr_hash_desc;

const char *bch2_xattr_invalid(const struct bch_fs *, struct bkey_s_c);
void bch2_xattr_to_text(struct bch_fs *, char *, size_t, struct bkey_s_c);

#define bch2_bkey_xattr_ops (struct bkey_ops) {		\
	.key_invalid	= bch2_xattr_invalid,		\
	.val_to_text	= bch2_xattr_to_text,		\
}

struct dentry;
struct xattr_handler;
struct bch_hash_info;
struct bch_inode_info;

int bch2_xattr_get(struct bch_fs *, struct bch_inode_info *,
		  const char *, void *, size_t, int);
int __bch2_xattr_set(struct bch_fs *, u64, const struct bch_hash_info *,
		  const char *, const void *, size_t, int, int, u64 *);
int bch2_xattr_set(struct bch_fs *, struct bch_inode_info *,
		  const char *, const void *, size_t, int, int);
ssize_t bch2_xattr_list(struct dentry *, char *, size_t);

extern const struct xattr_handler *bch2_xattr_handlers[];

#endif /* _BCACHEFS_XATTR_H */
