#ifndef _BCACHEFS_SUPER_TYPES_H
#define _BCACHEFS_SUPER_TYPES_H

struct bch_sb_handle {
	struct bch_sb		*sb;
	struct block_device	*bdev;
	struct bio		*bio;
	unsigned		page_order;
	fmode_t			mode;
};

struct bch_devs_mask {
	unsigned long d[BITS_TO_LONGS(BCH_SB_MEMBERS_MAX)];
};

#endif /* _BCACHEFS_SUPER_TYPES_H */
