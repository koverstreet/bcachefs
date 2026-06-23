/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_BACKGROUND_FORMAT_H
#define _BCACHEFS_ALLOC_BACKGROUND_FORMAT_H

struct bch_alloc {
	struct bch_val		v;
	__u8			fields;
	__u8			gen;
	__u8			data[];
} __packed __aligned(8);

#define BCH_ALLOC_FIELDS_V1()			\
	x(read_time,		16)		\
	x(write_time,		16)		\
	x(data_type,		8)		\
	x(dirty_sectors,	16)		\
	x(cached_sectors,	16)		\
	x(oldest_gen,		8)		\
	x(stripe,		32)		\
	x(stripe_redundancy,	8)

enum {
#define x(name, _bits) BCH_ALLOC_FIELD_V1_##name,
	BCH_ALLOC_FIELDS_V1()
#undef x
};

struct bch_alloc_v2 {
	struct bch_val		v;
	__u8			nr_fields;
	__u8			gen;
	__u8			oldest_gen;
	__u8			data_type;
	__u8			data[];
} __packed __aligned(8);

#define BCH_ALLOC_FIELDS_V2()			\
	x(read_time,		64)		\
	x(write_time,		64)		\
	x(dirty_sectors,	32)		\
	x(cached_sectors,	32)		\
	x(stripe,		32)		\
	x(stripe_redundancy,	8)

struct bch_alloc_v3 {
	struct bch_val		v;
	__le64			journal_seq;
	__le32			flags;
	__u8			nr_fields;
	__u8			gen;
	__u8			oldest_gen;
	__u8			data_type;
	__u8			data[];
} __packed __aligned(8);

LE32_BITMASK(BCH_ALLOC_V3_NEED_DISCARD,struct bch_alloc_v3, flags,  0,  1)
LE32_BITMASK(BCH_ALLOC_V3_NEED_INC_GEN,struct bch_alloc_v3, flags,  1,  2)

/*
 * Per-bucket allocation state, stored in the alloc btree (cached).
 *
 * data_type is the bucket's state. For non-empty buckets, alloc_data_type()
 * derives it from sector counts and stripe_refcount. The empty-state
 * transitions are decided explicitly:
 *   stripe_refcount > 0	→ BCH_DATA_stripe/parity
 *   dirty_sectors > 0		→ data type from bucket contents
 *   cached_sectors > 0		→ BCH_DATA_cached
 *   nonempty → empty		→ BCH_DATA_need_discard (set in bch2_trigger_alloc)
 *   need_discard → empty	→ BCH_DATA_free (set in bch2_discard_one_bucket)
 *   gc_gen >= MAX, free	→ BCH_DATA_need_gc_gens (in alloc_data_type)
 *
 * NEED_DISCARD flag is no longer read by alloc_data_type(); it's still
 * written for forward/back compatibility with kernels that do read it.
 *
 * journal_seq_nonempty/journal_seq_empty track bucket state transitions for
 * the noflush optimization and discard path:
 *   journal_seq_nonempty: set on empty→nonempty transition
 *   journal_seq_empty:    set on nonempty→empty transition;
 *     bucket can't be reused until this seq is flushed to disk.
 *     0 means no journal delay needed (noflush/fast discard path).
 */
struct bch_alloc_v4 {
	struct bch_val		v;
	__u64			journal_seq_nonempty;
	__u32			flags;
	__u8			gen;
	__u8			oldest_gen;
	__u8			data_type;
	__u8			stripe_redundancy_obsolete;
	__u32			dirty_sectors;
	__u32			cached_sectors;
	__u64			io_time[2];
	__u32			stripe_refcount;
	__u32			nr_external_backpointers;
	/* end of fields in original version of alloc_v4 */
	__u64			journal_seq_empty;
	__u32			stripe_sectors;
	__u32			pad;
} __packed __aligned(8);

#define BCH_ALLOC_V4_U64s_V0	6
#define BCH_ALLOC_V4_U64s	(sizeof(struct bch_alloc_v4) / sizeof(__u64))

BITMASK(BCH_ALLOC_V4_NEED_DISCARD,	struct bch_alloc_v4, flags,  0,  1)
BITMASK(BCH_ALLOC_V4_NEED_INC_GEN,	struct bch_alloc_v4, flags,  1,  2)
BITMASK(BCH_ALLOC_V4_BACKPOINTERS_START,struct bch_alloc_v4, flags,  2,  8)
BITMASK(BCH_ALLOC_V4_NR_BACKPOINTERS,	struct bch_alloc_v4, flags,  8,  14)

#define KEY_TYPE_BUCKET_GENS_BITS	8
#define KEY_TYPE_BUCKET_GENS_NR		(1U << KEY_TYPE_BUCKET_GENS_BITS)
#define KEY_TYPE_BUCKET_GENS_MASK	(KEY_TYPE_BUCKET_GENS_NR - 1)

struct bch_bucket_gens {
	struct bch_val		v;
	u8			gens[KEY_TYPE_BUCKET_GENS_NR];
} __packed __aligned(8);

#endif /* _BCACHEFS_ALLOC_BACKGROUND_FORMAT_H */
