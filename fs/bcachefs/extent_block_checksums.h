/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EXTENT_BLOCK_CHECKSUS_H
#define _BCACHEFS_EXTENT_BLOCK_CHECKSUS_H

#include "bkey.h"

static inline unsigned extent_block_checksums_nr_crcs(struct bkey_s_c_extent_block_checksums e)
{
	return (e.k->size + e.v->front_pad + e.v->back_pad) >> e.v->csum_blocksize_bits;
}

static inline unsigned extent_block_checksums_crc_bytes(struct bkey_s_c_extent_block_checksums e)
{
	return round_up(extent_block_checksums_nr_crcs(e) * bch_crc_bytes[e.v->csum_type], sizeof(u64));
}

static inline unsigned extent_block_checksums_crc_u64s(struct bkey_s_c_extent_block_checksums e)
{
	return extent_block_checksums_crc_bytes(e) / sizeof(u64);
}

static inline unsigned extent_block_checksums_val_bytes(struct bkey_s_c_extent_block_checksums e)
{
	return sizeof(*e.v) + sizeof(e.v->ptrs[0]) * e.v->nr_ptrs + extent_block_checksums_crc_bytes(e);
}

static inline unsigned extent_block_checksums_val_u64s(struct bkey_s_c_extent_block_checksums e)
{
	return extent_block_checksums_val_bytes(e) / sizeof(u64);
}

int bch2_extent_block_checksums_invalid(struct bch_fs *, struct bkey_s_c,
					enum bkey_invalid_flags, struct printbuf *);
bool bch2_extent_block_checksums_merge(struct bch_fs *, struct bkey_s, struct bkey_s_c);
void bch2_extent_block_checksums_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_extent_block_checksums ((struct bkey_ops) {	\
	.key_invalid	= bch2_bkey_ptrs_invalid,			\
	.val_to_text	= bch2_extent_block_checksums_to_text,		\
	.swab		= bch2_ptr_swab,				\
	.key_normalize	= bch2_extent_normalize,			\
	.key_merge	= bch2_extent_block_checksums_merge,		\
	.trans_trigger	= bch2_trans_mark_extent,			\
	.atomic_trigger	= bch2_mark_extent,				\
	.min_val_size	= 8,						\
})

#endif /* _BCACHEFS_EXTENT_BLOCK_CHECKSUS_H */

