#ifndef _BCACHE_FS_H
#define _BCACHE_FS_H

#include <linux/seqlock.h>

struct i_size_update {
	/* value of -1 means cancelled (i.e. truncated): */
	loff_t			new_i_size;
	atomic_long_t		count;
};

#define I_SIZE_UPDATE_ENTRIES_BITS	2
#define I_SIZE_UPDATE_ENTRIES		(1 << I_SIZE_UPDATE_ENTRIES_BITS)

struct bch_inode_info {
	struct inode		vfs_inode;

	struct mutex		update_lock;
	u64			journal_seq;

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
	seqcount_t		shadow_i_size_lock;

	atomic_long_t		i_sectors_dirty_count;
	atomic64_t		i_sectors;

	u64			str_hash_seed;
	u8			str_hash_type;
};

enum {
	BCH_INODE_WANT_NEW_APPEND,
};

#define to_bch_ei(_inode)					\
	container_of(_inode, struct bch_inode_info, vfs_inode)

static inline u8 mode_to_type(umode_t mode)
{
	return (mode >> 12) & 15;
}

/* returns 0 if we want to do the update, or error is passed up */
typedef int (*inode_set_fn)(struct bch_inode_info *,
			    struct bch_inode *, void *);

int __must_check __bch_write_inode(struct cache_set *, struct bch_inode_info *,
				   inode_set_fn, void *);
int __must_check bch_write_inode(struct cache_set *,
				 struct bch_inode_info *);

#endif /* _BCACHE_FS_H */
