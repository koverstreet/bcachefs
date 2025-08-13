/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_JOURNAL_ITER_TYPES_H
#define _BCACHEFS_BTREE_JOURNAL_ITER_TYPES_H

struct journal_ptr {
	bool		csum_good;
	struct bch_csum	csum;
	u8		dev;
	u32		bucket;
	u32		bucket_offset;
	u64		sector;
};

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	DARRAY_PREALLOCATED(struct journal_ptr, 8) ptrs;

	bool			csum_good;
	bool			ignore_blacklisted;
	bool			ignore_not_dirty;
	/* must be last: */
	struct jset		j;
};

struct journal_key_range_overwritten {
	size_t			start, end;
};

struct journal_key {
	union {
		u64		journal_seq;
		struct bkey_i	*allocated_k;
	};
	u32			journal_offset;
	enum btree_id		btree_id:8;
	unsigned		level:8;
	bool			allocated:1;
	bool			overwritten:1;
	bool			rewind:1;
	struct journal_key_range_overwritten __rcu *
				overwritten_range;
};

struct journal_keys {
	/* must match layout in darray_types.h */
	size_t			nr, size;
	struct journal_key	*data;
	/*
	 * Gap buffer: instead of all the empty space in the array being at the
	 * end of the buffer - from @nr to @size - the empty space is at @gap.
	 * This means that sequential insertions are O(n) instead of O(n^2).
	 */
	size_t			gap;
	atomic_t		ref;
	bool			initial_ref_held;
	struct mutex		overwrite_lock;
};

#endif /* _BCACHEFS_BTREE_JOURNAL_ITER_TYPES_H */
