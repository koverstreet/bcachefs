// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/iter.h"

#include "data/checksum.h"
#include "data/ec/io.h"
#include "data/ec/trigger.h"
#include "data/read.h"

#include "init/error.h"

#include <linux/string_choices.h>

#ifdef __KERNEL__

#include <linux/raid/pq.h>
#include <linux/raid/xor.h>

static void raid5_recov(unsigned disks, unsigned failed_idx,
			size_t size, void **data)
{
	unsigned i = 2, nr;

	BUG_ON(failed_idx >= disks);

	swap(data[0], data[failed_idx]);
	memcpy(data[0], data[1], size);

	while (i < disks) {
		nr = min_t(unsigned, disks - i, MAX_XOR_BLOCKS);
		xor_blocks(nr, size, data[0], data + i);
		i += nr;
	}

	swap(data[0], data[failed_idx]);
}

static void raid_gen(int nd, int np, size_t size, void **v)
{
	if (np >= 1)
		raid5_recov(nd + np, nd, size, v);
	if (np >= 2)
		raid6_call.gen_syndrome(nd + np, size, v);
	BUG_ON(np > 2);
}

static void raid_rec(int nr, int *ir, int nd, int np, size_t size, void **v)
{
	switch (nr) {
	case 0:
		break;
	case 1:
		if (ir[0] < nd + 1)
			raid5_recov(nd + 1, ir[0], size, v);
		else
			raid6_call.gen_syndrome(nd + np, size, v);
		break;
	case 2:
		if (ir[1] < nd) {
			/* data+data failure. */
			raid6_2data_recov(nd + np, size, ir[0], ir[1], v);
		} else if (ir[0] < nd) {
			/* data + p/q failure */

			if (ir[1] == nd) /* data + p failure */
				raid6_datap_recov(nd + np, size, ir[0], v);
			else { /* data + q failure */
				raid5_recov(nd + 1, ir[0], size, v);
				raid6_call.gen_syndrome(nd + np, size, v);
			}
		} else {
			raid_gen(nd, np, size, v);
		}
		break;
	default:
		BUG();
	}
}

#else

#include <raid/raid.h>

#endif

void bch2_ec_stripe_buf_exit(struct ec_stripe_buf *buf)
{
	if (buf->key.k.type == KEY_TYPE_stripe) {
		struct bkey_i_stripe *s = bkey_i_to_stripe(&buf->key);
		unsigned i;

		for (i = 0; i < s->v.nr_blocks; i++) {
			kvfree(buf->data[i]);
			buf->data[i] = NULL;
		}
	}
}

/* XXX: this is a non-mempoolified memory allocation: */
int bch2_ec_stripe_buf_init(struct bch_fs *c,
			    struct ec_stripe_buf *buf,
			    unsigned offset, unsigned size)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned csum_granularity = 1U << v->csum_granularity_bits;
	unsigned end = offset + size;
	unsigned i;

	BUG_ON(end > le16_to_cpu(v->sectors));

	offset	= round_down(offset, csum_granularity);
	end	= min_t(unsigned, le16_to_cpu(v->sectors),
			round_up(end, csum_granularity));

	buf->offset	= offset;
	buf->size	= end - offset;

	memset(buf->valid, 0xFF, sizeof(buf->valid));

	for (i = 0; i < v->nr_blocks; i++) {
		buf->data[i] = kvmalloc(buf->size << 9, GFP_KERNEL);
		if (!buf->data[i]) {
			bch2_ec_stripe_buf_exit(buf);
			return bch_err_throw(c, ENOMEM_stripe_buf);
		}
	}

	return 0;
}

void bch2_ec_generate_ec(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned bytes = le16_to_cpu(v->sectors) << 9;

	raid_gen(nr_data, v->nr_redundant, bytes, buf->data);
}

int bch2_ec_do_recov(struct bch_fs *c, struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned i, failed[BCH_BKEY_PTRS_MAX], nr_failed = 0;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned bytes = buf->size << 9;

	if (ec_nr_failed(buf) > v->nr_redundant) {
		bch_err_ratelimited(c,
			"error doing reconstruct read: unable to read enough blocks");
		return -1;
	}

	for (i = 0; i < nr_data; i++)
		if (!test_bit(i, buf->valid))
			failed[nr_failed++] = i;

	raid_rec(nr_failed, failed, nr_data, v->nr_redundant, bytes, buf->data);
	return 0;
}

/* Checksumming: */

static struct bch_csum ec_block_checksum(struct ec_stripe_buf *buf,
					 unsigned block, unsigned offset)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned csum_granularity = 1 << v->csum_granularity_bits;
	unsigned end = buf->offset + buf->size;
	unsigned len = min(csum_granularity, end - offset);

	BUG_ON(offset >= end);
	BUG_ON(offset <  buf->offset);
	BUG_ON(offset & (csum_granularity - 1));
	BUG_ON(offset + len != le16_to_cpu(v->sectors) &&
	       (len & (csum_granularity - 1)));

	return bch2_checksum(NULL, v->csum_type,
			     null_nonce(),
			     buf->data[block] + ((offset - buf->offset) << 9),
			     len << 9);
}

void bch2_ec_generate_checksums(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned i, j, csums_per_device = stripe_csums_per_device(v);

	if (!v->csum_type)
		return;

	BUG_ON(buf->offset);
	BUG_ON(buf->size != le16_to_cpu(v->sectors));

	for (i = 0; i < v->nr_blocks; i++)
		for (j = 0; j < csums_per_device; j++)
			stripe_csum_set(v, i, j,
				ec_block_checksum(buf, i, j << v->csum_granularity_bits));
}

void bch2_ec_validate_checksums(struct bch_fs *c, struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned csum_granularity = 1 << v->csum_granularity_bits;
	unsigned i;

	if (!v->csum_type)
		return;

	for (i = 0; i < v->nr_blocks; i++) {
		unsigned offset = buf->offset;
		unsigned end = buf->offset + buf->size;

		if (!test_bit(i, buf->valid))
			continue;

		while (offset < end) {
			unsigned j = offset >> v->csum_granularity_bits;
			unsigned len = min(csum_granularity, end - offset);
			struct bch_csum want = stripe_csum_get(v, i, j);
			struct bch_csum got = ec_block_checksum(buf, i, offset);

			if (bch2_crc_cmp(want, got)) {
				CLASS(bch2_dev_bkey_tryget, ca)(c, bkey_i_to_s_c(&buf->key),
								v->ptrs[i].dev);
				if (ca) {
					CLASS(printbuf, err)();

					prt_str(&err, "stripe ");
					bch2_csum_err_msg(&err, v->csum_type, want, got);
					prt_printf(&err, "  for %ps at %u of\n  ", (void *) _RET_IP_, i);
					bch2_bkey_val_to_text(&err, c, bkey_i_to_s_c(&buf->key));
					bch_err_dev_ratelimited(ca, "%s", err.buf);

					bch2_io_error(ca, BCH_MEMBER_ERROR_checksum);
				}

				clear_bit(i, buf->valid);
				break;
			}

			offset += len;
		}
	}
}

/* IO: */

static void ec_block_endio(struct bio *bio)
{
	struct ec_bio *ec_bio = container_of(bio, struct ec_bio, bio);
	struct bch_stripe *v = &bkey_i_to_stripe(&ec_bio->buf->key)->v;
	struct bch_extent_ptr *ptr = &v->ptrs[ec_bio->idx];
	struct bch_dev *ca = ec_bio->ca;
	struct closure *cl = bio->bi_private;
	int rw = ec_bio->rw;
	unsigned ref = rw == READ
		? (unsigned) BCH_DEV_READ_REF_ec_block
		: (unsigned) BCH_DEV_WRITE_REF_ec_block;

	bch2_account_io_completion(ca, bio_data_dir(bio),
				   ec_bio->submit_time, !bio->bi_status);

	if (bio->bi_status) {
		bch_err_dev_ratelimited(ca, "erasure coding %s error: %s",
			       str_write_read(bio_data_dir(bio)),
			       bch2_blk_status_to_str(bio->bi_status));
		clear_bit(ec_bio->idx, ec_bio->buf->valid);
	}

	int stale = dev_ptr_stale(ca, ptr);
	if (stale) {
		bch_err_ratelimited(ca->fs,
				    "error %s stripe: stale/invalid pointer (%i) after io",
				    bio_data_dir(bio) == READ ? "reading from" : "writing to",
				    stale);
		clear_bit(ec_bio->idx, ec_bio->buf->valid);
	}

	bio_put(&ec_bio->bio);
	enumerated_ref_put(&ca->io_ref[rw], ref);
	closure_put(cl);
}

void bch2_ec_block_io(struct bch_fs *c, struct ec_stripe_buf *buf,
		      blk_opf_t opf, unsigned idx, struct closure *cl)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned offset = 0, bytes = buf->size << 9;
	struct bch_extent_ptr *ptr = &v->ptrs[idx];
	enum bch_data_type data_type = idx < v->nr_blocks - v->nr_redundant
		? BCH_DATA_user
		: BCH_DATA_parity;
	int rw = op_is_write(opf);
	unsigned ref = rw == READ
		? (unsigned) BCH_DEV_READ_REF_ec_block
		: (unsigned) BCH_DEV_WRITE_REF_ec_block;

	struct bch_dev *ca = bch2_dev_get_ioref(c, ptr->dev, rw, ref);
	if (!ca) {
		clear_bit(idx, buf->valid);
		return;
	}

	int stale = dev_ptr_stale(ca, ptr);
	if (stale) {
		bch_err_ratelimited(c,
				    "error %s stripe: stale pointer (%i)",
				    rw == READ ? "reading from" : "writing to",
				    stale);
		clear_bit(idx, buf->valid);
		return;
	}


	this_cpu_add(ca->io_done->sectors[rw][data_type], buf->size);

	while (offset < bytes) {
		unsigned nr_iovecs = min_t(size_t, BIO_MAX_VECS,
					   DIV_ROUND_UP(bytes, PAGE_SIZE));
		unsigned b = min_t(size_t, bytes - offset,
				   nr_iovecs << PAGE_SHIFT);
		struct ec_bio *ec_bio;

		ec_bio = container_of(bio_alloc_bioset(ca->disk_sb.bdev,
						       nr_iovecs,
						       opf,
						       GFP_KERNEL,
						       &c->ec.block_bioset),
				      struct ec_bio, bio);

		ec_bio->ca			= ca;
		ec_bio->buf			= buf;
		ec_bio->idx			= idx;
		ec_bio->rw			= rw;
		ec_bio->submit_time		= local_clock();

		ec_bio->bio.bi_iter.bi_sector	= ptr->offset + buf->offset + (offset >> 9);
		ec_bio->bio.bi_end_io		= ec_block_endio;
		ec_bio->bio.bi_private		= cl;

		bch2_bio_map(&ec_bio->bio, buf->data[idx] + offset, b);

		closure_get(cl);
		enumerated_ref_get(&ca->io_ref[rw], ref);

		submit_bio(&ec_bio->bio);

		offset += b;
	}

	enumerated_ref_put(&ca->io_ref[rw], ref);
}

static int get_stripe_key_trans(struct btree_trans *trans, u64 idx,
				struct ec_stripe_buf *stripe)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, idx), BTREE_ITER_slots);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));
	if (k.k->type != KEY_TYPE_stripe)
		return -ENOENT;
	bkey_reassemble(&stripe->key, k);
	return 0;
}

static int stripe_reconstruct_err(struct bch_fs *c, struct bkey_s_c orig_k, const char *msg)
{
	CLASS(printbuf, msgbuf)();
	bch2_bkey_val_to_text(&msgbuf, c, orig_k);
	bch_err_ratelimited(c, "error doing reconstruct read: %s\n  %s", msg, msgbuf.buf);
	return bch_err_throw(c, stripe_reconstruct);
}

/* recovery read path: */
int bch2_ec_read_extent(struct btree_trans *trans, struct bch_read_bio *rbio,
			struct bkey_s_c orig_k)
{
	struct bch_fs *c = trans->c;

	BUG_ON(!rbio->pick.has_ec);

	struct ec_stripe_buf *buf __free(ec_stripe_buf_free) = kzalloc(sizeof(*buf), GFP_NOFS);
	if (!buf)
		return bch_err_throw(c, ENOMEM_ec_read_extent);

	int ret = lockrestart_do(trans, get_stripe_key_trans(trans, rbio->pick.ec.idx, buf));
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "stripe not found");

	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	if (!bch2_ptr_matches_stripe(v, rbio->pick))
		return stripe_reconstruct_err(c, orig_k, "pointer doesn't match stripe");

	unsigned offset = rbio->bio.bi_iter.bi_sector - v->ptrs[rbio->pick.ec.block].offset;
	if (offset + bio_sectors(&rbio->bio) > le16_to_cpu(v->sectors))
		return stripe_reconstruct_err(c, orig_k, "read is bigger than stripe");

	ret = bch2_ec_stripe_buf_init(c, buf, offset, bio_sectors(&rbio->bio));
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "-ENOMEM");

	CLASS(closure_stack, cl)();

	for (unsigned i = 0; i < v->nr_blocks; i++)
		bch2_ec_block_io(c, buf, REQ_OP_READ, i, &cl);

	closure_sync(&cl);

	if (ec_nr_failed(buf) > v->nr_redundant)
		return stripe_reconstruct_err(c, orig_k, "unable to read enough blocks");

	bch2_ec_validate_checksums(c, buf);

	ret = bch2_ec_do_recov(c, buf);
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "unable to read enough blocks");

	memcpy_to_bio(&rbio->bio, rbio->bio.bi_iter,
		      buf->data[rbio->pick.ec.block] + ((offset - buf->offset) << 9));
	return 0;
}
