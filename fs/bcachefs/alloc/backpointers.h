/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BACKPOINTERS_H
#define _BCACHEFS_BACKPOINTERS_H

#include "alloc/buckets.h"
#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/update.h"
#include "init/error.h"

static inline u64 swab40(u64 x)
{
	return (((x & 0x00000000ffULL) << 32)|
		((x & 0x000000ff00ULL) << 16)|
		((x & 0x0000ff0000ULL) >>  0)|
		((x & 0x00ff000000ULL) >> 16)|
		((x & 0xff00000000ULL) >> 32));
}

int bch2_backpointer_validate(struct bch_fs *, struct bkey_s_c k,
			      struct bkey_validate_context);
void bch2_backpointer_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
void bch2_backpointer_swab(struct bkey_s);

#define bch2_bkey_ops_backpointer ((struct bkey_ops) {	\
	.key_validate	= bch2_backpointer_validate,	\
	.val_to_text	= bch2_backpointer_to_text,	\
	.swab		= bch2_backpointer_swab,	\
	.min_val_size	= 32,				\
})

#define MAX_EXTENT_COMPRESS_RATIO_SHIFT		10

/*
 * Convert from pos in backpointer btree to pos of corresponding bucket in alloc
 * btree:
 */
static inline struct bpos bp_pos_to_bucket(const struct bch_dev *ca, struct bpos bp_pos)
{
	u64 bucket_sector = bp_pos.offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT;

	return POS(bp_pos.inode, sector_to_bucket(ca, bucket_sector));
}

static inline struct bpos bp_pos_to_bucket_and_offset(const struct bch_dev *ca, struct bpos bp_pos,
						      u32 *bucket_offset)
{
	u64 bucket_sector = bp_pos.offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT;

	return POS(bp_pos.inode, sector_to_bucket_and_offset(ca, bucket_sector, bucket_offset));
}

static inline bool bp_pos_to_bucket_nodev_noerror(struct bch_fs *c, struct bpos bp_pos, struct bpos *bucket)
{
	guard(rcu)();
	struct bch_dev *ca = bch2_dev_rcu_noerror(c, bp_pos.inode);
	if (ca)
		*bucket = bp_pos_to_bucket(ca, bp_pos);
	return ca != NULL;
}

static inline struct bpos bucket_pos_to_bp_noerror(const struct bch_dev *ca,
						   struct bpos bucket,
						   u64 bucket_offset)
{
	return POS(bucket.inode,
		   (bucket_to_sector(ca, bucket.offset) <<
		    MAX_EXTENT_COMPRESS_RATIO_SHIFT) + bucket_offset);
}

/*
 * Convert from pos in alloc btree + bucket offset to pos in backpointer btree:
 */
static inline struct bpos bucket_pos_to_bp(const struct bch_dev *ca,
					   struct bpos bucket,
					   u64 bucket_offset)
{
	struct bpos ret = bucket_pos_to_bp_noerror(ca, bucket, bucket_offset);
	EBUG_ON(!bkey_eq(bucket, bp_pos_to_bucket(ca, ret)));
	return ret;
}

static inline struct bpos bucket_pos_to_bp_start(const struct bch_dev *ca, struct bpos bucket)
{
	return bucket_pos_to_bp(ca, bucket, 0);
}

static inline struct bpos bucket_pos_to_bp_end(const struct bch_dev *ca, struct bpos bucket)
{
	return bpos_nosnap_predecessor(bucket_pos_to_bp(ca, bpos_nosnap_successor(bucket), 0));
}

int bch2_bucket_backpointer_mod_nowritebuffer(struct btree_trans *,
				struct bkey_s_c,
				struct bkey_i_backpointer *,
				bool);

static inline int bch2_bucket_backpointer_mod(struct btree_trans *trans,
				struct bkey_s_c orig_k,
				struct bkey_i_backpointer *bp,
				bool insert)
{
	if (static_branch_unlikely(&bch2_backpointers_no_use_write_buffer))
		return bch2_bucket_backpointer_mod_nowritebuffer(trans, orig_k, bp, insert);

	if (!insert) {
		bp->k.type = KEY_TYPE_deleted;
		set_bkey_val_u64s(&bp->k, 0);
	}

	return bch2_trans_update_buffered(trans, BTREE_ID_backpointers, &bp->k_i);
}

static inline enum bch_data_type bch2_bkey_ptr_data_type(struct bkey_s_c k,
							 struct extent_ptr_decoded p,
							 const union bch_extent_entry *entry)
{
	switch (k.k->type) {
	case KEY_TYPE_btree_ptr:
	case KEY_TYPE_btree_ptr_v2:
		return BCH_DATA_btree;
	case KEY_TYPE_extent:
	case KEY_TYPE_reflink_v:
		if (p.has_ec)
			return BCH_DATA_stripe;
		if (p.ptr.cached)
			return BCH_DATA_cached;
		else
			return BCH_DATA_user;
	case KEY_TYPE_stripe: {
		const struct bch_extent_ptr *ptr = &entry->ptr;
		struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);

		BUG_ON(ptr < s.v->ptrs ||
		       ptr >= s.v->ptrs + s.v->nr_blocks);

		return ptr >= s.v->ptrs + s.v->nr_blocks - s.v->nr_redundant
			? BCH_DATA_parity
			: BCH_DATA_user;
	}
	default:
		BUG();
	}
}

static inline void bch2_extent_ptr_to_bp(struct bch_fs *c,
			   enum btree_id btree_id, unsigned level,
			   struct bkey_s_c k, struct extent_ptr_decoded p,
			   const union bch_extent_entry *entry,
			   struct bkey_i_backpointer *bp)
{
	bkey_backpointer_init(&bp->k_i);
	bp->k.p.inode = p.ptr.dev;

	if (k.k->type != KEY_TYPE_stripe)
		bp->k.p.offset = ((u64) p.ptr.offset << MAX_EXTENT_COMPRESS_RATIO_SHIFT) + p.crc.offset;
	else {
		/*
		 * Put stripe backpointers where they won't collide with the
		 * extent backpointers within the stripe:
		 */
		struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);
		bp->k.p.offset = ((u64) (p.ptr.offset + le16_to_cpu(s.v->sectors)) <<
				  MAX_EXTENT_COMPRESS_RATIO_SHIFT) - 1;
	}

	bp->v	= (struct bch_backpointer) {
		.btree_id	= btree_id,
		.level		= level,
		.data_type	= bch2_bkey_ptr_data_type(k, p, entry),
		.bucket_gen	= p.ptr.gen,
		.bucket_len	= ptr_disk_sectors(level ? btree_sectors(c) : k.k->size, p),
		.pos		= k.k->p,
	};
}

struct wb_maybe_flush;
struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *, struct bkey_s_c_backpointer,
					 struct btree_iter *, unsigned, struct wb_maybe_flush *);
struct btree *bch2_backpointer_get_node(struct btree_trans *, struct bkey_s_c_backpointer,
					struct btree_iter *, struct wb_maybe_flush *);

int bch2_check_bucket_backpointer_mismatch(struct btree_trans *, struct bch_dev *, u64,
					   bool, struct wb_maybe_flush *);

int bch2_check_btree_backpointers(struct bch_fs *);
int bch2_check_extents_to_backpointers(struct bch_fs *);
int bch2_check_backpointers_to_extents(struct bch_fs *);

static inline bool bch2_bucket_bitmap_test(struct bucket_bitmap *b, u64 i)
{
	unsigned long *bitmap = READ_ONCE(b->buckets);
	return bitmap && test_bit(i, bitmap);
}

int bch2_bucket_bitmap_resize(struct bch_dev *, struct bucket_bitmap *, u64, u64);
void bch2_bucket_bitmap_free(struct bucket_bitmap *);

#endif /* _BCACHEFS_BACKPOINTERS_BACKGROUND_H */
