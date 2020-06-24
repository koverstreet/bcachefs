/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_BCACHE_H
#define _LINUX_BCACHE_H

/*
 * Bcache on disk data structures
 */

#include <linux/bcache_superblock.h>

/* Btree keys - all units are in sectors */

struct bkey {
	__u64	high;
	__u64	low;
	__u64	ptr[];
};

#define KEY_FIELD(name, field, offset, size)				\
	BITMASK(name, struct bkey, field, offset, size)

#define PTR_FIELD(name, offset, size)					\
static inline __u64 name(const struct bkey *k, unsigned int i)		\
{ return (k->ptr[i] >> offset) & ~(~0ULL << size); }			\
									\
static inline void SET_##name(struct bkey *k, unsigned int i, __u64 v)	\
{									\
	k->ptr[i] &= ~(~(~0ULL << size) << offset);			\
	k->ptr[i] |= (v & ~(~0ULL << size)) << offset;			\
}

#define KEY_SIZE_BITS		16
#define KEY_MAX_U64S		8

KEY_FIELD(KEY_PTRS,	high, 60, 3)
KEY_FIELD(HEADER_SIZE,	high, 58, 2)
KEY_FIELD(KEY_CSUM,	high, 56, 2)
KEY_FIELD(KEY_PINNED,	high, 55, 1)
KEY_FIELD(KEY_DIRTY,	high, 36, 1)

KEY_FIELD(KEY_SIZE,	high, 20, KEY_SIZE_BITS)
KEY_FIELD(KEY_INODE,	high, 0,  20)

/* Next time I change the on disk format, KEY_OFFSET() won't be 64 bits */

static inline __u64 KEY_OFFSET(const struct bkey *k)
{
	return k->low;
}

static inline void SET_KEY_OFFSET(struct bkey *k, __u64 v)
{
	k->low = v;
}

/*
 * The high bit being set is a relic from when we used it to do binary
 * searches - it told you where a key started. It's not used anymore,
 * and can probably be safely dropped.
 */
#define KEY(inode, offset, size)					\
((struct bkey) {							\
	.high = (1ULL << 63) | ((__u64) (size) << 20) | (inode),	\
	.low = (offset)							\
})

#define ZERO_KEY			KEY(0, 0, 0)

#define MAX_KEY_INODE			(~(~0 << 20))
#define MAX_KEY_OFFSET			(~0ULL >> 1)
#define MAX_KEY				KEY(MAX_KEY_INODE, MAX_KEY_OFFSET, 0)

#define KEY_START(k)			(KEY_OFFSET(k) - KEY_SIZE(k))
#define START_KEY(k)			KEY(KEY_INODE(k), KEY_START(k), 0)

#define PTR_DEV_BITS			12

PTR_FIELD(PTR_DEV,			51, PTR_DEV_BITS)
PTR_FIELD(PTR_OFFSET,			8,  43)
PTR_FIELD(PTR_GEN,			0,  8)

#define PTR_CHECK_DEV			((1 << PTR_DEV_BITS) - 1)

#define MAKE_PTR(gen, offset, dev)					\
	((((__u64) dev) << 51) | ((__u64) offset) << 8 | gen)

/* Bkey utility code */

static inline unsigned long bkey_u64s(const struct bkey *k)
{
	return (sizeof(struct bkey) / sizeof(__u64)) + KEY_PTRS(k);
}

static inline unsigned long bkey_bytes(const struct bkey *k)
{
	return bkey_u64s(k) * sizeof(__u64);
}

#define bkey_copy(_dest, _src)	memcpy(_dest, _src, bkey_bytes(_src))

static inline void bkey_copy_key(struct bkey *dest, const struct bkey *src)
{
	SET_KEY_INODE(dest, KEY_INODE(src));
	SET_KEY_OFFSET(dest, KEY_OFFSET(src));
}

static inline struct bkey *bkey_next(const struct bkey *k)
{
	__u64 *d = (void *) k;

	return (struct bkey *) (d + bkey_u64s(k));
}

static inline struct bkey *bkey_idx(const struct bkey *k, unsigned int nr_keys)
{
	__u64 *d = (void *) k;

	return (struct bkey *) (d + nr_keys);
}
/* Enough for a key with 6 pointers */
#define BKEY_PAD		8

#define BKEY_PADDED(key)					\
	union { struct bkey key; __u64 key ## _pad[BKEY_PAD]; }

/* Superblock */

static inline __u64 jset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ JSET_MAGIC;
}

static inline __u64 pset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ PSET_MAGIC;
}

static inline __u64 bset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ BSET_MAGIC;
}

/*
 * Journal
 *
 * On disk format for a journal entry:
 * seq is monotonically increasing; every journal entry has its own unique
 * sequence number.
 *
 * last_seq is the oldest journal entry that still has keys the btree hasn't
 * flushed to disk yet.
 *
 * version is for on disk format changes.
 */

#define BCACHE_JSET_VERSION_UUIDv1	1
#define BCACHE_JSET_VERSION_UUID	1	/* Always latest UUID format */
#define BCACHE_JSET_VERSION		1

struct jset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys;

	__u64			last_seq;

	BKEY_PADDED(uuid_bucket);
	BKEY_PADDED(btree_root);
	__u16			btree_level;
	__u16			pad[3];

	__u64			prio_bucket[MAX_CACHES_PER_SET];

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

/* Bucket prios/gens */

struct prio_set {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			pad;

	__u64			next_bucket;

	struct bucket_disk {
		__u16		prio;
		__u8		gen;
	} __attribute((packed)) data[];
};

/* UUIDS - per backing device/flash only volume metadata */

struct uuid_entry {
	union {
		struct {
			__u8	uuid[16];
			__u8	label[32];
			__u32	first_reg; /* time overflow in y2106 */
			__u32	last_reg;
			__u32	invalidated;

			__u32	flags;
			/* Size of flash only volumes */
			__u64	sectors;
		};

		__u8		pad[128];
	};
};

BITMASK(UUID_FLASH_ONLY,	struct uuid_entry, flags, 0, 1);

/* Btree nodes */

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_CSUM		1
#define BCACHE_BSET_VERSION		1

/*
 * Btree nodes
 *
 * On disk a btree node is a list/log of these; within each set the keys are
 * sorted
 */
struct bset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys;

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

/* OBSOLETE */

/* UUIDS - per backing device/flash only volume metadata */

struct uuid_entry_v0 {
	__u8		uuid[16];
	__u8		label[32];
	__u32		first_reg;
	__u32		last_reg;
	__u32		invalidated;
	__u32		pad;
};

#endif /* _LINUX_BCACHE_H */
