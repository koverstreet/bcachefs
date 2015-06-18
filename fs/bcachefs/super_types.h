#ifndef _BCACHE_SUPER_TYPES_H
#define _BCACHE_SUPER_TYPES_H

struct bcache_superblock {
	struct cache_sb		*sb;
	struct block_device	*bdev;
	struct bio		*bio;
	unsigned		page_order;
};

struct cache_set_opts {
	/* For each opt, -1 = undefined */

	int		read_only:2;
	int		on_error_action:3;

	/* filesystem options: */
	int		posix_acl:2;
	int		verbose_recovery:2;
};

#endif /* _BCACHE_SUPER_TYPES_H */
