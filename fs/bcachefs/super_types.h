#ifndef _BCACHE_SUPER_TYPES_H
#define _BCACHE_SUPER_TYPES_H

struct bcache_superblock {
	struct bio		*bio;
	struct cache_sb		*sb;
	unsigned		page_order;
};

#endif /* _BCACHE_SUPER_TYPES_H */
