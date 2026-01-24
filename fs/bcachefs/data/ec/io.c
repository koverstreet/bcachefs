// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/iter.h"

#include "data/checksum.h"
#include "data/ec/io.h"
#include "data/ec/trigger.h"
#include "data/read.h"

#include "init/error.h"
#include "init/passes.h"

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

		for (unsigned i = 0; i < s->v.nr_blocks; i++) {
			kvfree(buf->data[i]);
			buf->data[i] = NULL;
		}
	}

	closure_sync(&buf->io);
	closure_debug_destroy(&buf->io);
}

/* XXX: this is a non-mempoolified memory allocation: */
int __bch2_ec_stripe_buf_init(struct bch_fs *c,
			      struct ec_stripe_buf *buf,
			      unsigned offset, unsigned size)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned csum_granularity = 1U << v->csum_granularity_bits;
	unsigned end = offset + size;

	BUG_ON(end > le16_to_cpu(v->sectors));

	offset	= round_down(offset, csum_granularity);
	end	= min_t(unsigned, le16_to_cpu(v->sectors),
			round_up(end, csum_granularity));

	buf->offset	= offset;
	buf->size	= end - offset;

	for (unsigned i = 0; i < v->nr_blocks; i++) {
		buf->data[i] = kvmalloc(buf->size << 9, GFP_KERNEL);
		if (!buf->data[i]) {
			bch2_ec_stripe_buf_exit(buf);
			return bch_err_throw(c, ENOMEM_stripe_buf);
		}
	}

	closure_init(&buf->io, NULL);

	return 0;
}

void bch2_ec_generate_ec(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned bytes = le16_to_cpu(v->sectors) << 9;

	raid_gen(nr_data, v->nr_redundant, bytes, buf->data);
}

static int bch2_ec_do_recov(struct bch_fs *c, struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned failed[BCH_BKEY_PTRS_MAX], nr_failed = 0;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned bytes = buf->size << 9;

	if (ec_nr_failed(buf) > v->nr_redundant)
		return bch_err_throw(c, stripe_reconstruct_insufficient_blocks);

	for (unsigned i = 0; i < nr_data; i++)
		if (buf->err[i])
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

static void bch2_ec_validate_checksums(struct bch_fs *c, struct ec_stripe_buf *buf,
				       bool data_only)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned csum_granularity = 1 << v->csum_granularity_bits;

	if (!v->csum_type)
		return;

	for (unsigned i = 0; i < (data_only ? nr_data : v->nr_blocks); i++) {
		unsigned offset = buf->offset;
		unsigned end = buf->offset + buf->size;

		if (buf->err[i])
			continue;

		while (offset < end) {
			unsigned j = offset >> v->csum_granularity_bits;
			unsigned len = min(csum_granularity, end - offset);
			struct bch_csum want = stripe_csum_get(v, i, j);
			struct bch_csum got = ec_block_checksum(buf, i, offset);

			if (bch2_crc_cmp(want, got)) {
				buf->err[i] = bch_err_throw(c, stripe_read_csum_err);
				buf->csum_good[i] = want;
				buf->csum_bad[i] = got;

				/*
				 * Can't error on invalid device, we no longer
				 * have the bkey locked
				 */
				CLASS(bch2_dev_tryget_noerror, ca)(c, v->ptrs[i].dev);
				if (ca)
					bch2_io_error(ca, BCH_MEMBER_ERROR_checksum);
				break;
			}

			offset += len;
		}
	}
}

static void stripe_buf_errs_to_text(struct printbuf *out, struct bch_fs *c, struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;

	for (unsigned i = 0; i < v->nr_blocks; i++)
		if (buf->err[i]) {
			CLASS(bch2_dev_tryget_noerror, ca)(c, v->ptrs[i].dev);
			prt_printf(out, "block %u %s: %s",
				   i,
				   ca ? ca->name : "(invalid device)",
				   bch2_err_str(buf->err[i]));

			if (buf->err[i] == -BCH_ERR_stripe_read_csum_err) {
				prt_str(out, " expected ");
				bch2_csum_to_text(out, v->csum_type, buf->csum_good[i]);
				prt_str(out, " got ");
				bch2_csum_to_text(out, v->csum_type, buf->csum_bad[i]);
			}

			prt_newline(out);
		}
}

int bch2_stripe_buf_validate(struct bch_fs *c, struct ec_stripe_buf *buf, bool is_open)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;

	closure_sync(&buf->io);

	bch2_ec_validate_checksums(c, buf, false);

	if (!ec_nr_failed(buf))
		return 0;

	bool errors_silent = true;
	bool have_stale_race = false;
	for (unsigned i = 0; i < v->nr_blocks; i++) {
		bool stale_race = buf->err[i] == -BCH_ERR_stripe_read_ptr_stale &&
			!test_bit(i, buf->stale) &&
			!is_open;
		have_stale_race |= stale_race;

		if (buf->err[i] &&
		    buf->err[i] != -BCH_ERR_stripe_read_device_offline &&
		    !stale_race)
			errors_silent = false;
	}

	CLASS(bch_log_msg, msg)(c);

	prt_printf(&msg.m, "%ps(): error reading stripe:\n", (void *) _RET_IP_);
	bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&buf->key));
	prt_newline(&msg.m);

	stripe_buf_errs_to_text(&msg.m, c, buf);

	int ret = bch2_ec_do_recov(c, buf);
	if (ret) {
		prt_printf(&msg.m, "error: %s\n", bch2_err_str(ret));
		/* Separate ratelimit state for hard errors */
		msg.m.suppress = !is_open && have_stale_race ? true : bch2_ratelimit(c);
		return ret;
	}

	memset(buf->err, 0, sizeof(buf->err));
	bch2_ec_validate_checksums(c, buf, true);

	if (ec_nr_failed(buf)) {
		prt_printf(&msg.m, "checksum error after reconstruct:\n");
		stripe_buf_errs_to_text(&msg.m, c, buf);
		return -BCH_ERR_stripe_read_csum_err;
	}

	prt_printf(&msg.m, "successful reconstruct\n");
	msg.m.suppress = errors_silent ? true : bch2_ratelimit(c);
	return 0;
}

/* IO: */

static void ec_block_endio(struct bio *bio)
{
	struct ec_bio *ec_bio = container_of(bio, struct ec_bio, bio);
	struct bch_stripe *v = &bkey_i_to_stripe(&ec_bio->buf->key)->v;
	struct bch_extent_ptr *ptr = &v->ptrs[ec_bio->idx];
	struct bch_dev *ca = ec_bio->ca;
	int rw = ec_bio->rw;
	unsigned ref = rw == READ
		? (unsigned) BCH_DEV_READ_REF_ec_block
		: (unsigned) BCH_DEV_WRITE_REF_ec_block;

	bch2_account_io_completion(ca, bio_data_dir(bio),
				   ec_bio->submit_time, !bio->bi_status);

	if (bio->bi_status)
		ec_bio->buf->err[ec_bio->idx] = -blk_status_to_bch_err(bio->bi_status);
	else if (dev_ptr_stale(ca, ptr))
		ec_bio->buf->err[ec_bio->idx] = bch_err_throw(ca->fs, stripe_read_ptr_stale);

	bio_put(&ec_bio->bio);
	enumerated_ref_put(&ca->io_ref[rw], ref);
	closure_put(&ec_bio->buf->io);
}

void bch2_ec_block_io(struct bch_fs *c, struct ec_stripe_buf *buf,
		      blk_opf_t opf, unsigned idx)
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
		buf->err[idx] = bch_err_throw(c, stripe_read_device_offline);
		return;
	}

	int stale = dev_ptr_stale(ca, ptr);
	if (stale) {
		buf->err[idx] = bch_err_throw(c, stripe_read_ptr_stale);
		enumerated_ref_put(&ca->io_ref[rw], ref);
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

		bch2_bio_map(&ec_bio->bio, buf->data[idx] + offset, b);

		closure_get(&buf->io);
		enumerated_ref_get(&ca->io_ref[rw], ref);

		submit_bio(&ec_bio->bio);

		offset += b;
	}

	enumerated_ref_put(&ca->io_ref[rw], ref);
}

void bch2_stripe_buf_read(struct bch_fs *c, struct ec_stripe_buf *buf)
{
	struct bkey_i_stripe *s = bkey_i_to_stripe(&buf->key);

	for (unsigned i = 0; i < s->v.nr_blocks; i++)
		bch2_ec_block_io(c, buf, REQ_OP_READ, i);
}

/* recovery read path: */

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

int bch2_ec_read_extent(struct btree_trans *trans, struct bch_read_bio *rbio,
			struct bkey_s_c orig_k)
{
	/*
	 * We need the original extent to read to still be locked when we check
	 * for non-spurious stale stripe pointers
	 */
	try(bch2_trans_relock(trans));

	struct bch_fs *c = trans->c;

	BUG_ON(!rbio->pick.has_ec);

	struct ec_stripe_buf *buf __free(ec_stripe_buf_free) = kzalloc(sizeof(*buf), GFP_KERNEL);
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

	/* Check for stale pointers while we still have btree locks held */
	bool have_stale = false;
	scoped_guard(rcu) {
		for (unsigned i = 0; i < v->nr_blocks; i++) {
			struct bch_dev *ca = bch2_dev_rcu_noerror(c, v->ptrs[i].dev);
			if (ca && dev_ptr_stale(ca, &v->ptrs[i])) {
				__set_bit(i, buf->stale);
				have_stale = true;
			}
		}
	}

	if (have_stale) {
		CLASS(bch_log_msg_ratelimited, msg)(c);
		prt_printf(&msg.m, "Stripe with stale pointer(s):\n");
		bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&buf->key));

		bch2_count_fsck_err(c, stale_dirty_ptr, &msg.m);
		bch2_run_explicit_recovery_pass(c, &msg.m, BCH_RECOVERY_PASS_check_allocations, 0);
	}

	/* Don't hold btree locks for stripe buffer allocations, or IO */
	bch2_trans_unlock(trans);

	ret = bch2_ec_stripe_buf_init(c, buf, offset, bio_sectors(&rbio->bio));
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "-ENOMEM");

	bch2_stripe_buf_read(c, buf);

	ret = bch2_stripe_buf_validate(c, buf, false);
	if (ret) {
		for (unsigned i = 0; i < v->nr_blocks; i++)
			if (buf->err[i] == -BCH_ERR_stripe_read_ptr_stale &&
			    !test_bit(i, buf->stale))
				ret = bch_err_throw(c, data_read_ptr_stale_race);
		if (ret != -BCH_ERR_data_read_ptr_stale_race)
			bch_err_fn(c, ret);
		return ret;
	}

	memcpy_to_bio(&rbio->bio, rbio->bio.bi_iter,
		      buf->data[rbio->pick.ec.block] + ((offset - buf->offset) << 9));
	return 0;
}
