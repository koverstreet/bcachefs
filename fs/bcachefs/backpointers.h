/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BACKPOINTERS_BACKGROUND_H
#define _BCACHEFS_BACKPOINTERS_BACKGROUND_H

#include "buckets.h"
#include "super.h"

int bch2_backpointer_invalid(const struct bch_fs *, struct bkey_s_c k,
			     int, struct printbuf *);
void bch2_backpointer_to_text(struct printbuf *, const struct bch_backpointer *);
void bch2_backpointer_k_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
void bch2_backpointer_swab(struct bkey_s);

#define bch2_bkey_ops_backpointer ((struct bkey_ops) {	\
	.key_invalid	= bch2_backpointer_invalid,	\
	.val_to_text	= bch2_backpointer_k_to_text,	\
	.swab		= bch2_backpointer_swab,	\
})

#define MAX_EXTENT_COMPRESS_RATIO_SHIFT		10

static inline void bch2_extent_ptr_to_bp(struct bch_fs *c,
			   enum btree_id btree_id, unsigned level,
			   struct bkey_s_c k, struct extent_ptr_decoded p,
			   struct bpos *bucket_pos, struct bch_backpointer *bp)
{
	enum bch_data_type data_type = level ? BCH_DATA_btree : BCH_DATA_user;
	s64 sectors = level ? btree_sectors(c) : k.k->size;
	u32 bucket_offset;

	*bucket_pos = PTR_BUCKET_POS_OFFSET(c, &p.ptr, &bucket_offset);
	*bp = (struct bch_backpointer) {
		.btree_id	= btree_id,
		.level		= level,
		.data_type	= data_type,
		.bucket_offset	= ((u64) bucket_offset << MAX_EXTENT_COMPRESS_RATIO_SHIFT) +
			p.crc.offset,
		.bucket_len	= ptr_disk_sectors(sectors, p),
		.pos		= k.k->p,
	};
}

int bch2_bucket_backpointer_del(struct btree_trans *, struct bkey_i_alloc_v4 *,
				struct bch_backpointer, struct bkey_s_c);
int bch2_bucket_backpointer_add(struct btree_trans *, struct bkey_i_alloc_v4 *,
				struct bch_backpointer, struct bkey_s_c);
int bch2_get_next_backpointer(struct btree_trans *, struct bpos, int,
			      u64 *, struct bch_backpointer *, unsigned);
struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *, struct btree_iter *,
					 struct bpos, u64, struct bch_backpointer);
struct btree *bch2_backpointer_get_node(struct btree_trans *, struct btree_iter *,
					struct bpos, u64, struct bch_backpointer);

int bch2_check_btree_backpointers(struct bch_fs *);
int bch2_check_extents_to_backpointers(struct bch_fs *);
int bch2_check_backpointers_to_extents(struct bch_fs *);

#endif /* _BCACHEFS_BACKPOINTERS_BACKGROUND_H */
