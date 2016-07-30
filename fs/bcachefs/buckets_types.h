#ifndef _BUCKETS_TYPES_H
#define _BUCKETS_TYPES_H

struct bucket_mark {
	union {
	struct {
		u32		counter;
	};

	struct {
		unsigned	owned_by_allocator:1;
		unsigned	cached_sectors:15;
		unsigned	is_metadata:1;
		unsigned	dirty_sectors:15;
	};
	};
};

struct bucket {
	union {
		struct {
			u16	read_prio;
			u16	write_prio;
		};
		u16		prio[2];
	};
	struct bucket_mark	mark;
	/* Most out of date gen in the btree */
	u8			oldest_gen;

	/* generation copygc is going to move this bucket into */
	u8			copygc_gen;
};

struct bucket_stats_cache {
	u64			buckets_dirty;
	u64			buckets_cached;
	u64			buckets_meta;
	u64			buckets_alloc;

	u64			sectors_dirty;
	u64			sectors_cached;
	u64			sectors_meta;
};

enum s_alloc {
	S_META,
	S_DIRTY,
	S_CACHED,
	S_ALLOC_NR,
};

enum s_compressed {
	S_COMPRESSED,
	S_UNCOMPRESSED,
	S_COMPRESSED_NR,
};

struct bucket_stats_cache_set {
	/* all fields are in units of 512 byte sectors: */
	u64			s[S_COMPRESSED_NR][S_ALLOC_NR];
	u64			persistent_reserved;
	u64			online_reserved;
	u64			available_cache;
};

struct bucket_heap_entry {
	struct bucket *g;
	unsigned long val;
};

/*
 * A reservation for space on disk:
 */
struct disk_reservation {
	u32		sectors;
	u32		gen;
};

#endif /* _BUCKETS_TYPES_H */
