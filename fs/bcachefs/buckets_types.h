#ifndef _BUCKETS_TYPES_H
#define _BUCKETS_TYPES_H

#include "util.h"

/* kill, switch to bch_data_type */
enum bucket_data_type {
	BUCKET_DATA	= 0,
	BUCKET_BTREE,
	BUCKET_JOURNAL,
	BUCKET_SB,
};

struct bucket_mark {
	union {
	struct {
		u64		counter;
	};

	struct {
		u8		gen;
		u8		data_type:3,
				gen_valid:1,
				owned_by_allocator:1,
				nouse:1,
				journal_seq_valid:1,
				touched_this_mount:1;
		u16		dirty_sectors;
		u16		cached_sectors;

		/*
		 * low bits of journal sequence number when this bucket was most
		 * recently modified: if journal_seq_valid is set, this bucket
		 * can't be reused until the journal sequence number written to
		 * disk is >= the bucket's journal sequence number:
		 */
		u16		journal_seq;
	};
	};
};

struct bucket {
	u16				prio[2];

	union {
		struct bucket_mark	_mark;
		const struct bucket_mark mark;
	};
};

/* kill, switch to bucket_data_type */
enum s_alloc {
	S_META,
	S_DIRTY,
	S_ALLOC_NR,
};

struct bch_dev_usage {
	u64			buckets[S_ALLOC_NR];
	u64			buckets_cached;
	u64			buckets_alloc;

	/* _compressed_ sectors: */
	u64			sectors[S_ALLOC_NR];
	u64			sectors_cached;
};

struct bch_fs_usage {
	/* all fields are in units of 512 byte sectors: */

	/* _uncompressed_ sectors: */

	struct {
		u64		data[S_ALLOC_NR];
		u64		persistent_reserved;
	}			s[BCH_REPLICAS_MAX];

	u64			online_reserved;
	u64			available_cache;
};

struct bucket_heap_entry {
	size_t			bucket;
	struct bucket_mark	mark;
};

typedef HEAP(struct bucket_heap_entry) bucket_heap;

/*
 * A reservation for space on disk:
 */
struct disk_reservation {
	u64		sectors;
	u32		gen;
	unsigned	nr_replicas;
};

#endif /* _BUCKETS_TYPES_H */
