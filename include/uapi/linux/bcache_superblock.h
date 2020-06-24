/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_BCACHE_SUPERBLOCK_H
#define _LINUX_BCACHE_SUPERBLOCK_H

#include <linux/types.h>

#define BITMASK(name, type, field, offset, size)		\
static inline __u64 name(const type *k)				\
{ return (k->field >> offset) & ~(~0ULL << size); }		\
								\
static inline void SET_##name(type *k, __u64 v)			\
{								\
	k->field &= ~(~(~0ULL << size) << offset);		\
	k->field |= (v & ~(~0ULL << size)) << offset;		\
}

/* Version 0: Cache device
 * Version 1: Backing device
 * Version 2: Seed pointer into btree node checksum
 * Version 3: Cache device with new UUID format
 * Version 4: Backing device with data offset
 */
#define BCACHE_SB_VERSION_CDEV		0
#define BCACHE_SB_VERSION_BDEV		1
#define BCACHE_SB_VERSION_CDEV_WITH_UUID 3
#define BCACHE_SB_VERSION_BDEV_WITH_OFFSET 4
#define BCACHE_SB_MAX_VERSION		4

#define SB_SECTOR			8
#define SB_OFFSET			(SB_SECTOR << SECTOR_SHIFT)
#define SB_SIZE				4096
#define SB_LABEL_SIZE			32
#define SB_JOURNAL_BUCKETS		256U
/* SB_JOURNAL_BUCKETS must be divisible by BITS_PER_LONG */
#define MAX_CACHES_PER_SET		8

#define BDEV_DATA_START_DEFAULT		16	/* sectors */

struct cache_sb_disk {
	__le64			csum;
	__le64			offset;	/* sector where this sb was written */
	__le64			version;

	__u8			magic[16];

	__u8			uuid[16];
	union {
		__u8		set_uuid[16];
		__le64		set_magic;
	};
	__u8			label[SB_LABEL_SIZE];

	__le64			flags;
	__le64			seq;
	__le64			pad[8];

	union {
	struct {
		/* Cache devices */
		__le64		nbuckets;	/* device size */

		__le16		block_size;	/* sectors */
		__le16		bucket_size;	/* sectors */

		__le16		nr_in_set;
		__le16		nr_this_dev;
	};
	struct {
		/* Backing devices */
		__le64		data_offset;

		/*
		 * block_size from the cache device section is still used by
		 * backing devices, so don't add anything here until we fix
		 * things to not need it for backing devices anymore
		 */
	};
	};

	__le32			last_mount;	/* time overflow in y2106 */

	__le16			first_bucket;
	union {
		__le16		njournal_buckets;
		__le16		keys;
	};
	__le64			d[SB_JOURNAL_BUCKETS];	/* journal buckets */
};

struct cache_sb {
	__u64			csum;
	__u64			offset;	/* sector where this sb was written */
	__u64			version;

	__u8			magic[16];

	__u8			uuid[16];
	union {
		__u8		set_uuid[16];
		__u64		set_magic;
	};
	__u8			label[SB_LABEL_SIZE];

	__u64			flags;
	__u64			seq;
	__u64			pad[8];

	union {
	struct {
		/* Cache devices */
		__u64		nbuckets;	/* device size */

		__u16		block_size;	/* sectors */
		__u16		bucket_size;	/* sectors */

		__u16		nr_in_set;
		__u16		nr_this_dev;
	};
	struct {
		/* Backing devices */
		__u64		data_offset;

		/*
		 * block_size from the cache device section is still used by
		 * backing devices, so don't add anything here until we fix
		 * things to not need it for backing devices anymore
		 */
	};
	};

	__u32			last_mount;	/* time overflow in y2106 */

	__u16			first_bucket;
	union {
		__u16		njournal_buckets;
		__u16		keys;
	};
	__u64			d[SB_JOURNAL_BUCKETS];	/* journal buckets */
};

static inline _Bool SB_IS_BDEV(const struct cache_sb *sb)
{
	return sb->version == BCACHE_SB_VERSION_BDEV
		|| sb->version == BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
}

BITMASK(CACHE_SYNC,			struct cache_sb, flags, 0, 1);
BITMASK(CACHE_DISCARD,			struct cache_sb, flags, 1, 1);
BITMASK(CACHE_REPLACEMENT,		struct cache_sb, flags, 2, 3);
#define CACHE_REPLACEMENT_LRU		0U
#define CACHE_REPLACEMENT_FIFO		1U
#define CACHE_REPLACEMENT_RANDOM	2U
#define CACHE_REPLACEMENT_NR		3U

BITMASK(BDEV_CACHE_MODE,		struct cache_sb, flags, 0, 4);
#define CACHE_MODE_WRITETHROUGH		0U
#define CACHE_MODE_WRITEBACK		1U
#define CACHE_MODE_WRITEAROUND		2U
#define CACHE_MODE_NONE			3U
BITMASK(BDEV_STATE,			struct cache_sb, flags, 61, 2);
#define BDEV_STATE_NONE			0U
#define BDEV_STATE_CLEAN		1U
#define BDEV_STATE_DIRTY		2U
#define BDEV_STATE_STALE		3U

/*
 * Magic numbers
 *
 * The various other data structures have their own magic numbers, which are
 * xored with the first part of the cache set's UUID
 */

#define JSET_MAGIC			0x245235c1a3625032ULL
#define PSET_MAGIC			0x6750e15f87337f91ULL
#define BSET_MAGIC			0x90135c78b99e07f5ULL

#endif /* _LINUX_BCACHE_SUPERBLOCK_H */
