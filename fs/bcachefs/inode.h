#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

extern const struct btree_keys_ops bch_inode_ops;

ssize_t bch_inode_status(char *, size_t, const struct bkey *);
bool bch_inode_invalid(const struct bkey *);

int bch_inode_create(struct cache_set *, struct bkey *, u64, u64, u64 *);
int bch_inode_update(struct cache_set *, struct bkey *);
int bch_inode_truncate(struct cache_set *, u64, u64);
int bch_inode_rm(struct cache_set *, u64);

int bch_blockdev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				    struct bkey_i_inode_blockdev *);

#endif
