#ifndef _BCACHE_FS_H
#define _BCACHE_FS_H

#include "str_hash.h"

#include <linux/seqlock.h>

struct bch_inode_info {
	struct inode		vfs_inode;

	struct mutex		update_lock;
	u64			journal_seq;

	atomic_long_t		i_size_dirty_count;

	/*
	 * these are updated whenever we update the inode in the btree - for
	 * e.g. fsync
	 */
	u64			i_size;
	u32			i_flags;

	atomic_long_t		i_sectors_dirty_count;
	atomic64_t		i_sectors;

	struct bch_hash_info	str_hash;
};

#define to_bch_ei(_inode)					\
	container_of(_inode, struct bch_inode_info, vfs_inode)

static inline u8 mode_to_type(umode_t mode)
{
	return (mode >> 12) & 15;
}

static inline unsigned nlink_bias(umode_t mode)
{
	return S_ISDIR(mode) ? 2 : 1;
}

struct bch_inode_unpacked;

/* returns 0 if we want to do the update, or error is passed up */
typedef int (*inode_set_fn)(struct bch_inode_info *,
			    struct bch_inode_unpacked *, void *);

int __must_check __bch_write_inode(struct cache_set *, struct bch_inode_info *,
				   inode_set_fn, void *);
int __must_check bch_write_inode(struct cache_set *,
				 struct bch_inode_info *);

void bch_fs_exit(void);
int bch_fs_init(void);

#endif /* _BCACHE_FS_H */
