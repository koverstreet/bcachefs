#ifndef _BCACHE_FS_H
#define _BCACHE_FS_H

struct bch_inode_info {
	struct inode		vfs_inode;

	struct mutex		update_lock;
	u64			journal_seq;

	/*
	 * Append_count corresponds to the I_SIZE_DIRTY flag in bch_inode:
	 *
	 * XXX: we need a seqlock or something that covers both
	 * i_size_dirty_count and i_size
	 */
	atomic_long_t		i_size_dirty_count;

	/*
	 * these are updated whenever we update the inode in the btree - for
	 * e.g. fsync
	 */
	u64			i_size;
	u32			i_flags;

	/*
	 * hack for FS_IOC_SETFLAGS - need a place to stash the new flags for
	 * __bch_write_inode since we can't use nested functions in the kernel
	 *
	 * protected by update_lock
	 */
	u32			newflags;
};

#define to_bch_ei(_inode)					\
	container_of(_inode, struct bch_inode_info, vfs_inode)

static inline u8 mode_to_type(umode_t mode)
{
	return (mode >> 12) & 15;
}

#endif /* _BCACHE_FS_H */
