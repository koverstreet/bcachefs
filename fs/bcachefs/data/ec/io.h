/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_EC_IO_H
#define _BCACHEFS_DATA_EC_IO_H

struct ec_bio {
	struct bch_dev		*ca;
	struct ec_stripe_buf	*buf;
	size_t			idx;
	int			rw;
	u64			submit_time;
	struct bio		bio;
};

struct ec_stripe_buf {
	struct closure		io;

	/* might not be buffering the entire stripe: */
	unsigned		offset;
	unsigned		size;
	s16			err[BCH_BKEY_PTRS_MAX];
	void			*data[BCH_BKEY_PTRS_MAX];

	/* Stale when we read the stripe key, i.e. alloc inconsistency */
	unsigned long		stale[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];

	struct bch_csum		csum_good[BCH_BKEY_PTRS_MAX];
	struct bch_csum		csum_bad[BCH_BKEY_PTRS_MAX];

	__BKEY_PADDED(key, 255);
};

static inline unsigned ec_nr_failed(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;

	unsigned nr_failed = 0;
	for (unsigned i = 0; i < v->nr_blocks; i++)
		nr_failed += buf->err[i] != 0;
	return nr_failed;
}

void bch2_ec_stripe_buf_exit(struct ec_stripe_buf *);
int __bch2_ec_stripe_buf_init(struct bch_fs *, struct ec_stripe_buf *, unsigned, unsigned);

static inline int bch2_ec_stripe_buf_init(struct bch_fs *c,
			      struct ec_stripe_buf *buf,
			      unsigned offset, unsigned size)
{
	closure_init(&buf->io, NULL);
	return __bch2_ec_stripe_buf_init(c, buf, offset, size);
}

DEFINE_FREE(ec_stripe_buf_free, struct ec_stripe_buf *, bch2_ec_stripe_buf_exit(_T); kfree(_T));

void bch2_ec_generate_ec(struct ec_stripe_buf *);
void bch2_ec_generate_checksums(struct ec_stripe_buf *);

int bch2_stripe_buf_validate(struct bch_fs *, struct ec_stripe_buf *, bool);

void bch2_ec_block_io(struct bch_fs *, struct ec_stripe_buf *, blk_opf_t, unsigned);
void bch2_stripe_buf_read(struct bch_fs *, struct ec_stripe_buf *);

struct bch_read_bio;
int bch2_ec_read_extent(struct btree_trans *, struct bch_read_bio *, struct bkey_s_c);

#endif /* _BCACHEFS_DATA_EC_IO_H */

