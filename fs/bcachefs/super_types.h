#ifndef _BCACHE_SUPER_TYPES_H
#define _BCACHE_SUPER_TYPES_H

struct bcache_superblock {
	struct cache_sb		*sb;
	struct block_device	*bdev;
	struct bio		*bio;
	unsigned		page_order;
};

#endif /* _BCACHE_SUPER_TYPES_H */
