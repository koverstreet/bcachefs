/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EC_H
#define _BCACHEFS_EC_H

#include "ec_types.h"
#include "buckets_types.h"
#include "extents_types.h"

enum bch_validate_flags;

int bch2_stripe_validate(struct bch_fs *, struct bkey_s_c, enum bch_validate_flags);
void bch2_stripe_to_text(struct printbuf *, struct bch_fs *,
			 struct bkey_s_c);
int bch2_trigger_stripe(struct btree_trans *, enum btree_id, unsigned,
			struct bkey_s_c, struct bkey_s,
			enum btree_iter_update_trigger_flags);

#define bch2_bkey_ops_stripe ((struct bkey_ops) {	\
	.key_validate	= bch2_stripe_validate,		\
	.val_to_text	= bch2_stripe_to_text,		\
	.swab		= bch2_ptr_swab,		\
	.trigger	= bch2_trigger_stripe,		\
	.min_val_size	= 8,				\
})

static inline unsigned stripe_csums_per_device(const struct bch_stripe *s)
{
	return DIV_ROUND_UP(le16_to_cpu(s->sectors),
			    1 << s->csum_granularity_bits);
}

static inline unsigned stripe_csum_offset(const struct bch_stripe *s,
					  unsigned dev, unsigned csum_idx)
{
	EBUG_ON(s->csum_type >= BCH_CSUM_NR);

	unsigned csum_bytes = bch_crc_bytes[s->csum_type];

	return sizeof(struct bch_stripe) +
		sizeof(struct bch_extent_ptr) * s->nr_blocks +
		(dev * stripe_csums_per_device(s) + csum_idx) * csum_bytes;
}

static inline unsigned stripe_blockcount_offset(const struct bch_stripe *s,
						unsigned idx)
{
	return stripe_csum_offset(s, s->nr_blocks, 0) +
		sizeof(u16) * idx;
}

static inline unsigned stripe_blockcount_get(const struct bch_stripe *s,
					     unsigned idx)
{
	return le16_to_cpup((void *) s + stripe_blockcount_offset(s, idx));
}

static inline void stripe_blockcount_set(struct bch_stripe *s,
					 unsigned idx, unsigned v)
{
	__le16 *p = (void *) s + stripe_blockcount_offset(s, idx);

	*p = cpu_to_le16(v);
}

static inline unsigned stripe_val_u64s(const struct bch_stripe *s)
{
	return DIV_ROUND_UP(stripe_blockcount_offset(s, s->nr_blocks),
			    sizeof(u64));
}

static inline void *stripe_csum(struct bch_stripe *s,
				unsigned block, unsigned csum_idx)
{
	EBUG_ON(block >= s->nr_blocks);
	EBUG_ON(csum_idx >= stripe_csums_per_device(s));

	return (void *) s + stripe_csum_offset(s, block, csum_idx);
}

static inline struct bch_csum stripe_csum_get(struct bch_stripe *s,
				   unsigned block, unsigned csum_idx)
{
	struct bch_csum csum = { 0 };

	memcpy(&csum, stripe_csum(s, block, csum_idx), bch_crc_bytes[s->csum_type]);
	return csum;
}

static inline void stripe_csum_set(struct bch_stripe *s,
				   unsigned block, unsigned csum_idx,
				   struct bch_csum csum)
{
	memcpy(stripe_csum(s, block, csum_idx), &csum, bch_crc_bytes[s->csum_type]);
}

static inline bool __bch2_ptr_matches_stripe(const struct bch_extent_ptr *stripe_ptr,
					     const struct bch_extent_ptr *data_ptr,
					     unsigned sectors)
{
	return  (data_ptr->dev    == stripe_ptr->dev ||
		 data_ptr->dev    == BCH_SB_MEMBER_INVALID ||
		 stripe_ptr->dev  == BCH_SB_MEMBER_INVALID) &&
		data_ptr->gen    == stripe_ptr->gen &&
		data_ptr->offset >= stripe_ptr->offset &&
		data_ptr->offset  < stripe_ptr->offset + sectors;
}

static inline bool bch2_ptr_matches_stripe(const struct bch_stripe *s,
					   struct extent_ptr_decoded p)
{
	unsigned nr_data = s->nr_blocks - s->nr_redundant;

	BUG_ON(!p.has_ec);

	if (p.ec.block >= nr_data)
		return false;

	return __bch2_ptr_matches_stripe(&s->ptrs[p.ec.block], &p.ptr,
					 le16_to_cpu(s->sectors));
}

static inline bool bch2_ptr_matches_stripe_m(const struct gc_stripe *m,
					     struct extent_ptr_decoded p)
{
	unsigned nr_data = m->nr_blocks - m->nr_redundant;

	BUG_ON(!p.has_ec);

	if (p.ec.block >= nr_data)
		return false;

	return __bch2_ptr_matches_stripe(&m->ptrs[p.ec.block], &p.ptr,
					 m->sectors);
}

struct bch_read_bio;

struct ec_stripe_buf {
	/* might not be buffering the entire stripe: */
	unsigned		offset;
	unsigned		size;
	unsigned long		valid[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];

	void			*data[BCH_BKEY_PTRS_MAX];

	__BKEY_PADDED(key, 255);
};

struct ec_stripe_head;

enum ec_stripe_ref {
	STRIPE_REF_io,
	STRIPE_REF_stripe,
	STRIPE_REF_NR
};

struct ec_stripe_new {
	struct bch_fs		*c;
	struct ec_stripe_head	*h;
	struct mutex		lock;
	struct list_head	list;

	struct hlist_node	hash;
	u64			idx;

	struct closure		iodone;

	atomic_t		ref[STRIPE_REF_NR];

	int			err;

	u8			nr_data;
	u8			nr_parity;
	bool			allocated;
	bool			pending;
	bool			have_existing_stripe;

	unsigned long		blocks_gotten[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];
	unsigned long		blocks_allocated[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];
	open_bucket_idx_t	blocks[BCH_BKEY_PTRS_MAX];
	struct disk_reservation	res;

	struct ec_stripe_buf	new_stripe;
	struct ec_stripe_buf	existing_stripe;
};

struct ec_stripe_head {
	struct list_head	list;
	struct mutex		lock;

	unsigned		disk_label;
	unsigned		algo;
	unsigned		redundancy;
	enum bch_watermark	watermark;
	bool			insufficient_devs;

	unsigned long		rw_devs_change_count;

	u64			nr_created;

	struct bch_devs_mask	devs;
	unsigned		nr_active_devs;

	unsigned		blocksize;

	struct dev_stripe_state	block_stripe;
	struct dev_stripe_state	parity_stripe;

	struct ec_stripe_new	*s;
};

int bch2_ec_read_extent(struct btree_trans *, struct bch_read_bio *, struct bkey_s_c);

void *bch2_writepoint_ec_buf(struct bch_fs *, struct write_point *);

void bch2_ec_bucket_cancel(struct bch_fs *, struct open_bucket *);

int bch2_ec_stripe_new_alloc(struct bch_fs *, struct ec_stripe_head *);

void bch2_ec_stripe_head_put(struct bch_fs *, struct ec_stripe_head *);
struct ec_stripe_head *bch2_ec_stripe_head_get(struct btree_trans *,
			unsigned, unsigned, unsigned,
			enum bch_watermark, struct closure *);

void bch2_stripes_heap_update(struct bch_fs *, struct stripe *, size_t);
void bch2_stripes_heap_del(struct bch_fs *, struct stripe *, size_t);
void bch2_stripes_heap_insert(struct bch_fs *, struct stripe *, size_t);

void bch2_do_stripe_deletes(struct bch_fs *);
void bch2_ec_do_stripe_creates(struct bch_fs *);
void bch2_ec_stripe_new_free(struct bch_fs *, struct ec_stripe_new *);

static inline void ec_stripe_new_get(struct ec_stripe_new *s,
				     enum ec_stripe_ref ref)
{
	atomic_inc(&s->ref[ref]);
}

static inline void ec_stripe_new_put(struct bch_fs *c, struct ec_stripe_new *s,
				     enum ec_stripe_ref ref)
{
	BUG_ON(atomic_read(&s->ref[ref]) <= 0);

	if (atomic_dec_and_test(&s->ref[ref]))
		switch (ref) {
		case STRIPE_REF_stripe:
			bch2_ec_stripe_new_free(c, s);
			break;
		case STRIPE_REF_io:
			bch2_ec_do_stripe_creates(c);
			break;
		default:
			BUG();
		}
}

int bch2_dev_remove_stripes(struct bch_fs *, unsigned);

void bch2_ec_stop_dev(struct bch_fs *, struct bch_dev *);
void bch2_fs_ec_stop(struct bch_fs *);
void bch2_fs_ec_flush(struct bch_fs *);

int bch2_stripes_read(struct bch_fs *);

void bch2_stripes_heap_to_text(struct printbuf *, struct bch_fs *);
void bch2_new_stripes_to_text(struct printbuf *, struct bch_fs *);

void bch2_fs_ec_exit(struct bch_fs *);
void bch2_fs_ec_init_early(struct bch_fs *);
int bch2_fs_ec_init(struct bch_fs *);

#endif /* _BCACHEFS_EC_H */
