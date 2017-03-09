#ifndef _BCACHE_FS_GC_H
#define _BCACHE_FS_GC_H

s64 bch_count_inode_sectors(struct bch_fs *, u64);
int bch_fsck(struct bch_fs *, bool);

#endif /* _BCACHE_FS_GC_H */
