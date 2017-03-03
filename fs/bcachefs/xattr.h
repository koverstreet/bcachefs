#ifndef _BCACHE_XATTR_H
#define _BCACHE_XATTR_H

extern const struct bkey_ops bch_bkey_xattr_ops;

struct dentry;
struct xattr_handler;
struct bch_hash_info;

int bch_xattr_get(struct cache_set *, struct inode *,
		  const char *, void *, size_t, int);
int __bch_xattr_set(struct cache_set *, u64, const struct bch_hash_info *,
		  const char *, const void *, size_t, int, int, u64 *);
int bch_xattr_set(struct cache_set *, struct inode *,
		  const char *, const void *, size_t, int, int);
ssize_t bch_xattr_list(struct dentry *, char *, size_t);

extern const struct xattr_handler *bch_xattr_handlers[];

#endif /* _BCACHE_XATTR_H */
