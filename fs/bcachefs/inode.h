#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

extern const struct btree_keys_ops bch_inode_ops;

int bch_inode_create(struct cache_set *, struct bch_inode *, u64, u64, u64 *);
int bch_inode_update(struct cache_set *, struct bch_inode *);
int bch_inode_rm(struct cache_set *c, u64 inode_nr);

int bch_blockdev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				    struct bch_inode_blockdev *);

#endif
