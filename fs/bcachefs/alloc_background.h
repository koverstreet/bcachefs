/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_BACKGROUND_H
#define _BCACHEFS_ALLOC_BACKGROUND_H

#include "bcachefs.h"
#include "alloc_types.h"
#include "buckets.h"
#include "debug.h"
#include "super.h"

struct bkey_alloc_unpacked {
	u64		journal_seq;
	u64		bucket;
	u8		dev;
	u8		gen;
	u8		oldest_gen;
	u8		data_type;
	bool		need_discard:1;
	bool		need_inc_gen:1;
#define x(_name, _bits)	u##_bits _name;
	BCH_ALLOC_FIELDS_V2()
#undef  x
};

/* How out of date a pointer gen is allowed to be: */
#define BUCKET_GC_GEN_MAX	96U

static inline u8 alloc_gc_gen(struct bkey_alloc_unpacked a)
{
	return a.gen - a.oldest_gen;
}

enum bucket_state {
	BUCKET_free,
	BUCKET_need_gc_gens,
	BUCKET_need_discard,
	BUCKET_cached,
	BUCKET_dirty,
};

extern const char * const bch2_bucket_states[];

static inline enum bucket_state bucket_state(struct bkey_alloc_unpacked a)
{
	if (a.dirty_sectors || a.stripe)
		return BUCKET_dirty;
	if (a.cached_sectors)
		return BUCKET_cached;
	BUG_ON(a.data_type);
	if (a.need_discard)
		return BUCKET_need_discard;
	if (alloc_gc_gen(a) >= BUCKET_GC_GEN_MAX)
		return BUCKET_need_gc_gens;
	return BUCKET_free;
}

static inline u64 alloc_lru_idx(struct bkey_alloc_unpacked a)
{
	return bucket_state(a) == BUCKET_cached ? a.read_time : 0;
}

static inline u64 alloc_freespace_genbits(struct bkey_alloc_unpacked a)
{
	return ((u64) alloc_gc_gen(a) >> 4) << 56;
}

static inline struct bpos alloc_freespace_pos(struct bkey_alloc_unpacked a)
{
	return POS(a.dev, a.bucket | alloc_freespace_genbits(a));
}

/* returns true if not equal */
static inline bool bkey_alloc_unpacked_cmp(struct bkey_alloc_unpacked l,
					   struct bkey_alloc_unpacked r)
{
	return  l.gen != r.gen			||
		l.oldest_gen != r.oldest_gen	||
		l.data_type != r.data_type
#define x(_name, ...)	|| l._name != r._name
	BCH_ALLOC_FIELDS_V2()
#undef  x
	;
}

struct bkey_alloc_buf {
	struct bkey_i	k;
	struct bch_alloc_v3 v;

#define x(_name,  _bits)		+ _bits / 8
	u8		_pad[0 + BCH_ALLOC_FIELDS_V2()];
#undef  x
} __attribute__((packed, aligned(8)));

struct bkey_alloc_unpacked bch2_alloc_unpack(struct bkey_s_c);
struct bkey_alloc_buf *bch2_alloc_pack(struct btree_trans *,
				       const struct bkey_alloc_unpacked);
int bch2_alloc_write(struct btree_trans *, struct btree_iter *,
		     struct bkey_alloc_unpacked *, unsigned);

int bch2_bucket_io_time_reset(struct btree_trans *, unsigned, size_t, int);

#define ALLOC_SCAN_BATCH(ca)		max_t(size_t, 1, (ca)->mi.nbuckets >> 9)

const char *bch2_alloc_v1_invalid(const struct bch_fs *, struct bkey_s_c);
const char *bch2_alloc_v2_invalid(const struct bch_fs *, struct bkey_s_c);
const char *bch2_alloc_v3_invalid(const struct bch_fs *, struct bkey_s_c);
void bch2_alloc_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_alloc (struct bkey_ops) {		\
	.key_invalid	= bch2_alloc_v1_invalid,	\
	.val_to_text	= bch2_alloc_to_text,		\
	.trans_trigger	= bch2_trans_mark_alloc,	\
	.atomic_trigger	= bch2_mark_alloc,		\
}

#define bch2_bkey_ops_alloc_v2 (struct bkey_ops) {	\
	.key_invalid	= bch2_alloc_v2_invalid,	\
	.val_to_text	= bch2_alloc_to_text,		\
	.trans_trigger	= bch2_trans_mark_alloc,	\
	.atomic_trigger	= bch2_mark_alloc,		\
}

#define bch2_bkey_ops_alloc_v3 (struct bkey_ops) {	\
	.key_invalid	= bch2_alloc_v3_invalid,	\
	.val_to_text	= bch2_alloc_to_text,		\
	.trans_trigger	= bch2_trans_mark_alloc,	\
	.atomic_trigger	= bch2_mark_alloc,		\
}

static inline bool bkey_is_alloc(const struct bkey *k)
{
	return  k->type == KEY_TYPE_alloc ||
		k->type == KEY_TYPE_alloc_v2 ||
		k->type == KEY_TYPE_alloc_v3;
}

int bch2_alloc_read(struct bch_fs *);

int bch2_trans_mark_alloc(struct btree_trans *, struct bkey_s_c,
			  struct bkey_i *, unsigned);
int bch2_check_alloc_info(struct bch_fs *, bool);
void bch2_do_discards(struct bch_fs *);

static inline bool should_invalidate_buckets(struct bch_dev *ca)
{
	struct bch_dev_usage u = bch2_dev_usage_read(ca);

	return u.d[BCH_DATA_cached].buckets &&
		u.buckets_unavailable + u.d[BCH_DATA_cached].buckets <
		ca->mi.nbuckets >> 7;
}

void bch2_do_invalidates(struct bch_fs *);

int bch2_fs_freespace_init(struct bch_fs *);

void bch2_recalc_capacity(struct bch_fs *);

void bch2_dev_allocator_remove(struct bch_fs *, struct bch_dev *);
void bch2_dev_allocator_add(struct bch_fs *, struct bch_dev *);

void bch2_fs_allocator_background_init(struct bch_fs *);

#endif /* _BCACHEFS_ALLOC_BACKGROUND_H */
