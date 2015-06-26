#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

extern const struct btree_keys_ops bch_inode_ops;
extern const struct bkey_ops bch_bkey_inode_ops;

ssize_t bch_inode_status(char *, size_t, const struct bkey *);

int bch_inode_create(struct cache_set *, struct bkey_i *, u64, u64, u64 *);
int bch_inode_truncate(struct cache_set *, u64, u64, u64 *);
int bch_inode_rm(struct cache_set *, u64);
int bch_inode_update(struct cache_set *, struct bkey_i *, u64 *);

int bch_inode_find_by_inum(struct cache_set *, u64, struct bkey_i_inode *);
int bch_cached_dev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				      struct bkey_i_inode_blockdev *);

#endif
