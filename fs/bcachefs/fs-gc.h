#ifndef _BCACHE_FS_GC_H
#define _BCACHE_FS_GC_H

enum {
	BCH_FSCK_OK			= 0,
	BCH_FSCK_ERRORS_NOT_FIXED	= 1,
	BCH_FSCK_REPAIR_UNIMPLEMENTED	= 2,
};

s64 bch_count_inode_sectors(struct cache_set *, u64);
int bch_gc_inode_nlinks(struct cache_set *);
int bch_fsck(struct cache_set *);

#endif /* _BCACHE_FS_GC_H */
