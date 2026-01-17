/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_EC_TRIGGER_H
#define _BCACHEFS_DATA_EC_TRIGGER_H

int bch2_stripe_validate(struct bch_fs *, struct bkey_s_c,
			 struct bkey_validate_context);
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

#define STRIPE_LRU_POS_EMPTY	1

static inline u64 stripe_lru_pos(const struct bch_stripe *s)
{
	if (!s)
		return 0;

	unsigned nr_data = s->nr_blocks - s->nr_redundant, blocks_empty = 0;

	for (unsigned i = 0; i < nr_data; i++)
		blocks_empty += !stripe_blockcount_get(s, i);

	/* Will be picked up by the stripe_delete worker */
	if (blocks_empty == nr_data)
		return STRIPE_LRU_POS_EMPTY;

	if (!blocks_empty)
		return 0;

	/* invert: more blocks empty = reuse first */
	return LRU_TIME_MAX - blocks_empty;
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

static inline void gc_stripe_unlock(struct gc_stripe *s)
{
	BUILD_BUG_ON(!((union ulong_byte_assert) { .ulong = 1UL << BUCKET_LOCK_BITNR }).byte);

	clear_bit_unlock(BUCKET_LOCK_BITNR, (void *) &s->lock);
	smp_mb__after_atomic();
	wake_up_bit((void *) &s->lock, BUCKET_LOCK_BITNR);
}

static inline void gc_stripe_lock(struct gc_stripe *s)
{
	wait_on_bit_lock((void *) &s->lock, BUCKET_LOCK_BITNR,
			 TASK_UNINTERRUPTIBLE);
}

int bch2_ec_stripe_mem_alloc(struct btree_trans *, struct btree_iter *);

bool bch2_bucket_has_new_stripe(struct bch_fs *, u64);

void bch2_stripe_new_buckets_add(struct bch_fs *c, struct ec_stripe_new *s);
void bch2_stripe_new_buckets_del(struct bch_fs *, struct ec_stripe_new *);

bool bch2_stripe_is_open(struct bch_fs *, u64);

struct ec_stripe_handle;
bool bch2_stripe_handle_tryget(struct bch_fs *, struct ec_stripe_handle *, u64);
void bch2_stripe_handle_put(struct bch_fs *, struct ec_stripe_handle *);

#endif /* _BCACHEFS_DATA_EC_TRIGGER_H */

