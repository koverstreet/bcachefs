#ifndef _BCACHE_FS_GC_H
#define _BCACHE_FS_GC_H

s64 bch_count_inode_sectors(struct cache_set *, u64);
int bch_gc_inode_nlinks(struct cache_set *);

#endif /* _BCACHE_FS_GC_H */
