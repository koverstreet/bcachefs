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

struct bucket_stats {
	u64			buckets_dirty;
	u64			buckets_cached;
	u64			buckets_meta;
	u64			buckets_alloc;

	u64			sectors_dirty;
	u64			sectors_cached;
};

struct bucket_heap_entry {
	struct bucket *g;
	unsigned long val;
};

#endif /* _BUCKETS_TYPES_H */
