#ifndef _BCACHE_FS_H
#define _BCACHE_FS_H

struct i_size_update {
	/* value of -1 means cancelled (i.e. truncated): */
	loff_t			new_i_size;
	atomic_long_t		count;
};

#define I_SIZE_UPDATE_ENTRIES	4

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

	struct {
		u8		front;
		u8		back;
		u8		size;
		u8		mask;
		struct i_size_update data[I_SIZE_UPDATE_ENTRIES];
	} i_size_updates;

	unsigned long		flags;

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

enum {
	BCH_INODE_WANT_NEW_APPEND,
};

/* stored in page->private: */
struct bch_page_state {
	u8			idx;
};

#define to_bch_ei(_inode)					\
	container_of(_inode, struct bch_inode_info, vfs_inode)

static inline u8 mode_to_type(umode_t mode)
{
	return (mode >> 12) & 15;
}

#endif /* _BCACHE_FS_H */
