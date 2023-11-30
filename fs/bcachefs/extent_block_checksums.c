// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "checksum.h"
#include "error.h"
#include "extent_block_checksums.h"

int bch2_extent_block_checksums_invalid(struct bch_fs *c, struct bkey_s_c k,
					enum bkey_invalid_flags flags, struct printbuf *err)
{
	struct bkey_s_c_extent_block_checksums e = bkey_s_c_to_extent_block_checksums(k);
	unsigned csum_blocksize = 1U << e.v->csum_blocksize_bits;
	int ret = 0;

	bkey_fsck_err_on(!e.v->csum_type ||
			 !bch2_checksum_type_valid(c, e.v->csum_type), c, err,
			 extent_block_checksums_csum_type_unknown,
			 "invalid checksum type %u", e.v->csum_type);

	bkey_fsck_err_on(e.v->front_pad >= csum_blocksize, c, err,
			 extent_block_checksums_front_pad_bad,
			 "front_pad %u > csum_blocksize %u",
			 e.v->front_pad, csum_blocksize);

	bkey_fsck_err_on(e.v->back_pad >= csum_blocksize, c, err,
			 extent_block_checksums_back_pad_bad,
			 "back_pad %u > csum_blocksize %u",
			 e.v->back_pad, csum_blocksize);

	bkey_fsck_err_on((e.v->front_pad + e.k->size + e.v->back_pad) & (csum_blocksize - 1), c, err,
			 extent_block_checksums_misaligned,
			 "misaligned");

	bkey_fsck_err_on(bkey_val_u64s(e.k) != extent_block_checksums_val_u64s(e), c, err,
			 extent_block_checksums_val_size_bad,
			 "incorrect value size (%zu != %u)",
			 bkey_val_u64s(k.k), extent_block_checksums_val_u64s(e));

	ret = bch2_bkey_ptrs_invalid(c, k, flags, err);
fsck_err:
	return ret;
}

bool bch2_extent_block_checksums_merge(struct bch_fs *c, struct bkey_s l, struct bkey_s_c r)
{
	/* this is going to need a much bigger key, look at how it's allocated
	 * */
#if 0
	struct bkey_s_xtent_block_checksums le = bkey_s_o_extent_block_checksums(l);
	struct bkey_s_c_extent_block_checksums re = bkey_s_c_to_extent_block_checksums(r);

#endif
	return false;
}

void bch2_extent_block_checksums_to_text(struct printbuf *out, struct bch_fs *c,
					 struct bkey_s_c k)
{
	struct bkey_s_c_extent_block_checksums e = bkey_s_c_to_extent_block_checksums(k);

	prt_printf(out, "csum type %s ", bch2_csum_types[e.v->csum_type]);
	prt_printf(out, "csum blocksize %u ", 1U << e.v->csum_blocksize_bits);

	bch2_bkey_ptrs_to_text(out, c, k);
}
