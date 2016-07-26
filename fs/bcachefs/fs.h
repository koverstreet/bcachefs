#ifndef _BCACHE_FS_H
#define _BCACHE_FS_H

struct bch_inode_info {
	struct bkey_i_inode	inode;
	struct inode		vfs_inode;
	struct mutex		update_lock;
	u64			journal_seq;
	atomic_long_t		append_count;
};

#define to_bch_ei(_inode)					\
	container_of(_inode, struct bch_inode_info, vfs_inode)

static inline u8 mode_to_type(umode_t mode)
{
	return (mode >> 12) & 15;
}

#endif /* _BCACHE_FS_H */
