/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FS_IOCTL_H
#define _BCACHEFS_FS_IOCTL_H

/* Inode flags: */

/* bcachefs inode flags -> vfs inode flags: */
static const unsigned bch_flags_to_vfs[] = {
	[__BCH_INODE_SYNC]	= S_SYNC,
	[__BCH_INODE_IMMUTABLE]	= S_IMMUTABLE,
	[__BCH_INODE_APPEND]	= S_APPEND,
	[__BCH_INODE_NOATIME]	= S_NOATIME,
};

/* bcachefs inode flags -> FS_IOC_GETFLAGS: */
static const unsigned bch_flags_to_uflags[] = {
	[__BCH_INODE_SYNC]	= FS_SYNC_FL,
	[__BCH_INODE_IMMUTABLE]	= FS_IMMUTABLE_FL,
	[__BCH_INODE_APPEND]	= FS_APPEND_FL,
	[__BCH_INODE_NODUMP]	= FS_NODUMP_FL,
	[__BCH_INODE_NOATIME]	= FS_NOATIME_FL,
};

/* bcachefs inode flags -> FS_IOC_FSGETXATTR: */
static const unsigned bch_flags_to_xflags[] = {
	[__BCH_INODE_SYNC]	= FS_XFLAG_SYNC,
	[__BCH_INODE_IMMUTABLE]	= FS_XFLAG_IMMUTABLE,
	[__BCH_INODE_APPEND]	= FS_XFLAG_APPEND,
	[__BCH_INODE_NODUMP]	= FS_XFLAG_NODUMP,
	[__BCH_INODE_NOATIME]	= FS_XFLAG_NOATIME,
	//[__BCH_INODE_PROJINHERIT] = FS_XFLAG_PROJINHERIT;
};

#define set_flags(_map, _in, _out)					\
do {									\
	unsigned _i;							\
									\
	for (_i = 0; _i < ARRAY_SIZE(_map); _i++)			\
		if ((_in) & (1 << _i))					\
			(_out) |= _map[_i];				\
		else							\
			(_out) &= ~_map[_i];				\
} while (0)

#define map_flags(_map, _in)						\
({									\
	unsigned _out = 0;						\
									\
	set_flags(_map, _in, _out);					\
	_out;								\
})

#define map_flags_rev(_map, _in)					\
({									\
	unsigned _i, _out = 0;						\
									\
	for (_i = 0; _i < ARRAY_SIZE(_map); _i++)			\
		if ((_in) & _map[_i]) {					\
			(_out) |= 1 << _i;				\
			(_in) &= ~_map[_i];				\
		}							\
	(_out);								\
})

#define map_defined(_map)						\
({									\
	unsigned _in = ~0;						\
									\
	map_flags_rev(_map, _in);					\
})

/* Set VFS inode flags from bcachefs inode: */
static inline void bch2_inode_flags_to_vfs(struct bch_inode_info *inode)
{
	set_flags(bch_flags_to_vfs, inode->ei_inode.bi_flags, inode->v.i_flags);
}

long bch2_fs_file_ioctl(struct file *, unsigned, unsigned long);
long bch2_compat_fs_ioctl(struct file *, unsigned, unsigned long);

#endif /* _BCACHEFS_FS_IOCTL_H */
