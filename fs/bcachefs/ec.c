// SPDX-License-Identifier: GPL-2.0

/* erasure coding */

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "backpointers.h"
#include "bkey_buf.h"
#include "bset.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "checksum.h"
#include "disk_accounting.h"
#include "disk_groups.h"
#include "ec.h"
#include "enumerated_ref.h"
#include "error.h"
#include "io_read.h"
#include "io_write.h"
#include "keylist.h"
#include "lru.h"
#include "recovery.h"
#include "replicas.h"
#include "super-io.h"
#include "util.h"

#include <linux/sort.h>
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

struct ec_bio {
	struct bch_dev		*ca;
	struct ec_stripe_buf	*buf;
	size_t			idx;
	int			rw;
	u64			submit_time;
	struct bio		bio;
};

/* Stripes btree keys: */

int bch2_stripe_validate(struct bch_fs *c, struct bkey_s_c k,
			 struct bkey_validate_context from)
{
	const struct bch_stripe *s = bkey_s_c_to_stripe(k).v;
	int ret = 0;

	bkey_fsck_err_on(bkey_eq(k.k->p, POS_MIN) ||
			 bpos_gt(k.k->p, POS(0, U32_MAX)),
			 c, stripe_pos_bad,
			 "stripe at bad pos");

	bkey_fsck_err_on(bkey_val_u64s(k.k) < stripe_val_u64s(s),
			 c, stripe_val_size_bad,
			 "incorrect value size (%zu < %u)",
			 bkey_val_u64s(k.k), stripe_val_u64s(s));

	bkey_fsck_err_on(s->csum_granularity_bits >= 64,
			 c, stripe_csum_granularity_bad,
			 "invalid csum granularity (%u >= 64)",
			 s->csum_granularity_bits);

	ret = bch2_bkey_ptrs_validate(c, k, from);
fsck_err:
	return ret;
}

void bch2_stripe_to_text(struct printbuf *out, struct bch_fs *c,
			 struct bkey_s_c k)
{
	const struct bch_stripe *sp = bkey_s_c_to_stripe(k).v;
	struct bch_stripe s = {};

	memcpy(&s, sp, min(sizeof(s), bkey_val_bytes(k.k)));

	unsigned nr_data = s.nr_blocks - s.nr_redundant;

	prt_printf(out, "algo %u sectors %u blocks %u:%u csum ",
		   s.algorithm,
		   le16_to_cpu(s.sectors),
		   nr_data,
		   s.nr_redundant);
	bch2_prt_csum_type(out, s.csum_type);
	prt_str(out, " gran ");
	if (s.csum_granularity_bits < 64)
		prt_printf(out, "%llu", 1ULL << s.csum_granularity_bits);
	else
		prt_printf(out, "(invalid shift %u)", s.csum_granularity_bits);

	if (s.disk_label) {
		prt_str(out, " label");
		bch2_disk_path_to_text(out, c, s.disk_label - 1);
	}

	for (unsigned i = 0; i < s.nr_blocks; i++) {
		const struct bch_extent_ptr *ptr = sp->ptrs + i;

		if ((void *) ptr >= bkey_val_end(k))
			break;

		prt_char(out, ' ');
		bch2_extent_ptr_to_text(out, c, ptr);

		if (s.csum_type < BCH_CSUM_NR &&
		    i < nr_data &&
		    stripe_blockcount_offset(&s, i) < bkey_val_bytes(k.k))
			prt_printf(out,  "#%u", stripe_blockcount_get(sp, i));
	}
}

/* Triggers: */

static int __mark_stripe_bucket(struct btree_trans *trans,
				struct bch_dev *ca,
				struct bkey_s_c_stripe s,
				unsigned ptr_idx, bool deleting,
				struct bpos bucket,
				struct bch_alloc_v4 *a,
				enum btree_iter_update_trigger_flags flags)
{
	const struct bch_extent_ptr *ptr = s.v->ptrs + ptr_idx;
	unsigned nr_data = s.v->nr_blocks - s.v->nr_redundant;
	bool parity = ptr_idx >= nr_data;
	enum bch_data_type data_type = parity ? BCH_DATA_parity : BCH_DATA_stripe;
	s64 sectors = parity ? le16_to_cpu(s.v->sectors) : 0;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	struct bch_fs *c = trans->c;
	if (deleting)
		sectors = -sectors;

	if (!deleting) {
		if (bch2_trans_inconsistent_on(a->stripe ||
					       a->stripe_redundancy, trans,
				"bucket %llu:%llu gen %u data type %s dirty_sectors %u: multiple stripes using same bucket (%u, %llu)\n%s",
				bucket.inode, bucket.offset, a->gen,
				bch2_data_type_str(a->data_type),
				a->dirty_sectors,
				a->stripe, s.k->p.offset,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}

		if (bch2_trans_inconsistent_on(parity && bch2_bucket_sectors_total(*a), trans,
				"bucket %llu:%llu gen %u data type %s dirty_sectors %u cached_sectors %u: data already in parity bucket\n%s",
				bucket.inode, bucket.offset, a->gen,
				bch2_data_type_str(a->data_type),
				a->dirty_sectors,
				a->cached_sectors,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}
	} else {
		if (bch2_trans_inconsistent_on(a->stripe != s.k->p.offset ||
					       a->stripe_redundancy != s.v->nr_redundant, trans,
				"bucket %llu:%llu gen %u: not marked as stripe when deleting stripe (got %u)\n%s",
				bucket.inode, bucket.offset, a->gen,
				a->stripe,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}

		if (bch2_trans_inconsistent_on(a->data_type != data_type, trans,
				"bucket %llu:%llu gen %u data type %s: wrong data type when stripe, should be %s\n%s",
				bucket.inode, bucket.offset, a->gen,
				bch2_data_type_str(a->data_type),
				bch2_data_type_str(data_type),
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}

		if (bch2_trans_inconsistent_on(parity &&
					       (a->dirty_sectors != -sectors ||
						a->cached_sectors), trans,
				"bucket %llu:%llu gen %u dirty_sectors %u cached_sectors %u: wrong sectors when deleting parity block of stripe\n%s",
				bucket.inode, bucket.offset, a->gen,
				a->dirty_sectors,
				a->cached_sectors,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}
	}

	if (sectors) {
		ret = bch2_bucket_ref_update(trans, ca, s.s_c, ptr, sectors, data_type,
					     a->gen, a->data_type, &a->dirty_sectors);
		if (ret)
			goto err;
	}

	if (!deleting) {
		a->stripe		= s.k->p.offset;
		a->stripe_redundancy	= s.v->nr_redundant;
		alloc_data_type_set(a, data_type);
	} else {
		a->stripe		= 0;
		a->stripe_redundancy	= 0;
		alloc_data_type_set(a, BCH_DATA_user);
	}
err:
	printbuf_exit(&buf);
	return ret;
}

static int mark_stripe_bucket(struct btree_trans *trans,
			      struct bkey_s_c_stripe s,
			      unsigned ptr_idx, bool deleting,
			      enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	const struct bch_extent_ptr *ptr = s.v->ptrs + ptr_idx;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	struct bch_dev *ca = bch2_dev_tryget(c, ptr->dev);
	if (unlikely(!ca)) {
		if (ptr->dev != BCH_SB_MEMBER_INVALID && !(flags & BTREE_TRIGGER_overwrite))
			ret = bch_err_throw(c, mark_stripe);
		goto err;
	}

	struct bpos bucket = PTR_BUCKET_POS(ca, ptr);

	if (flags & BTREE_TRIGGER_transactional) {
		struct extent_ptr_decoded p = {
			.ptr = *ptr,
			.crc = bch2_extent_crc_unpack(s.k, NULL),
		};
		struct bkey_i_backpointer bp;
		bch2_extent_ptr_to_bp(c, BTREE_ID_stripes, 0, s.s_c, p,
				      (const union bch_extent_entry *) ptr, &bp);

		struct bkey_i_alloc_v4 *a =
			bch2_trans_start_alloc_update(trans, bucket, 0);
		ret   = PTR_ERR_OR_ZERO(a) ?:
			__mark_stripe_bucket(trans, ca, s, ptr_idx, deleting, bucket, &a->v, flags) ?:
			bch2_bucket_backpointer_mod(trans, s.s_c, &bp,
						    !(flags & BTREE_TRIGGER_overwrite));
		if (ret)
			goto err;
	}

	if (flags & BTREE_TRIGGER_gc) {
		struct bucket *g = gc_bucket(ca, bucket.offset);
		if (bch2_fs_inconsistent_on(!g, c, "reference to invalid bucket on device %u\n%s",
					    ptr->dev,
					    (bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf))) {
			ret = bch_err_throw(c, mark_stripe);
			goto err;
		}

		bucket_lock(g);
		struct bch_alloc_v4 old = bucket_m_to_alloc(*g), new = old;
		ret = __mark_stripe_bucket(trans, ca, s, ptr_idx, deleting, bucket, &new, flags);
		alloc_to_bucket(g, new);
		bucket_unlock(g);

		if (!ret)
			ret = bch2_alloc_key_to_dev_counters(trans, ca, &old, &new, flags);
	}
err:
	bch2_dev_put(ca);
	printbuf_exit(&buf);
	return ret;
}

static int mark_stripe_buckets(struct btree_trans *trans,
			       struct bkey_s_c old, struct bkey_s_c new,
			       enum btree_iter_update_trigger_flags flags)
{
	const struct bch_stripe *old_s = old.k->type == KEY_TYPE_stripe
		? bkey_s_c_to_stripe(old).v : NULL;
	const struct bch_stripe *new_s = new.k->type == KEY_TYPE_stripe
		? bkey_s_c_to_stripe(new).v : NULL;

	BUG_ON(old_s && new_s && old_s->nr_blocks != new_s->nr_blocks);

	unsigned nr_blocks = new_s ? new_s->nr_blocks : old_s->nr_blocks;

	for (unsigned i = 0; i < nr_blocks; i++) {
		if (new_s && old_s &&
		    !memcmp(&new_s->ptrs[i],
			    &old_s->ptrs[i],
			    sizeof(new_s->ptrs[i])))
			continue;

		if (new_s) {
			int ret = mark_stripe_bucket(trans,
					bkey_s_c_to_stripe(new), i, false, flags);
			if (ret)
				return ret;
		}

		if (old_s) {
			int ret = mark_stripe_bucket(trans,
					bkey_s_c_to_stripe(old), i, true, flags);
			if (ret)
				return ret;
		}
	}

	return 0;
}

int bch2_trigger_stripe(struct btree_trans *trans,
			enum btree_id btree, unsigned level,
			struct bkey_s_c old, struct bkey_s _new,
			enum btree_iter_update_trigger_flags flags)
{
	struct bkey_s_c new = _new.s_c;
	struct bch_fs *c = trans->c;
	u64 idx = new.k->p.offset;
	const struct bch_stripe *old_s = old.k->type == KEY_TYPE_stripe
		? bkey_s_c_to_stripe(old).v : NULL;
	const struct bch_stripe *new_s = new.k->type == KEY_TYPE_stripe
		? bkey_s_c_to_stripe(new).v : NULL;

	if (unlikely(flags & BTREE_TRIGGER_check_repair))
		return bch2_check_fix_ptrs(trans, btree, level, _new.s_c, flags);

	BUG_ON(new_s && old_s &&
	       (new_s->nr_blocks	!= old_s->nr_blocks ||
		new_s->nr_redundant	!= old_s->nr_redundant));

	if (flags & BTREE_TRIGGER_transactional) {
		int ret = bch2_lru_change(trans,
					  BCH_LRU_STRIPE_FRAGMENTATION,
					  idx,
					  stripe_lru_pos(old_s),
					  stripe_lru_pos(new_s));
		if (ret)
			return ret;
	}

	if (flags & (BTREE_TRIGGER_transactional|BTREE_TRIGGER_gc)) {
		/*
		 * If the pointers aren't changing, we don't need to do anything:
		 */
		if (new_s && old_s &&
		    new_s->nr_blocks	== old_s->nr_blocks &&
		    new_s->nr_redundant	== old_s->nr_redundant &&
		    !memcmp(old_s->ptrs, new_s->ptrs,
			    new_s->nr_blocks * sizeof(struct bch_extent_ptr)))
			return 0;

		struct gc_stripe *gc = NULL;
		if (flags & BTREE_TRIGGER_gc) {
			gc = genradix_ptr_alloc(&c->gc_stripes, idx, GFP_KERNEL);
			if (!gc) {
				bch_err(c, "error allocating memory for gc_stripes, idx %llu", idx);
				return bch_err_throw(c, ENOMEM_mark_stripe);
			}

			/*
			 * This will be wrong when we bring back runtime gc: we should
			 * be unmarking the old key and then marking the new key
			 *
			 * Also: when we bring back runtime gc, locking
			 */
			gc->alive	= true;
			gc->sectors	= le16_to_cpu(new_s->sectors);
			gc->nr_blocks	= new_s->nr_blocks;
			gc->nr_redundant	= new_s->nr_redundant;

			for (unsigned i = 0; i < new_s->nr_blocks; i++)
				gc->ptrs[i] = new_s->ptrs[i];

			/*
			 * gc recalculates this field from stripe ptr
			 * references:
			 */
			memset(gc->block_sectors, 0, sizeof(gc->block_sectors));
		}

		if (new_s) {
			s64 sectors = (u64) le16_to_cpu(new_s->sectors) * new_s->nr_redundant;

			struct disk_accounting_pos acc;
			memset(&acc, 0, sizeof(acc));
			acc.type = BCH_DISK_ACCOUNTING_replicas;
			bch2_bkey_to_replicas(&acc.replicas, new);
			int ret = bch2_disk_accounting_mod(trans, &acc, &sectors, 1, gc);
			if (ret)
				return ret;

			if (gc)
				unsafe_memcpy(&gc->r.e, &acc.replicas,
					      replicas_entry_bytes(&acc.replicas), "VLA");
		}

		if (old_s) {
			s64 sectors = -((s64) le16_to_cpu(old_s->sectors)) * old_s->nr_redundant;

			struct disk_accounting_pos acc;
			memset(&acc, 0, sizeof(acc));
			acc.type = BCH_DISK_ACCOUNTING_replicas;
			bch2_bkey_to_replicas(&acc.replicas, old);
			int ret = bch2_disk_accounting_mod(trans, &acc, &sectors, 1, gc);
			if (ret)
				return ret;
		}

		int ret = mark_stripe_buckets(trans, old, new, flags);
		if (ret)
			return ret;
	}

	return 0;
}

/* returns blocknr in stripe that we matched: */
static const struct bch_extent_ptr *bkey_matches_stripe(struct bch_stripe *s,
						struct bkey_s_c k, unsigned *block)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned i, nr_data = s->nr_blocks - s->nr_redundant;

	bkey_for_each_ptr(ptrs, ptr)
		for (i = 0; i < nr_data; i++)
			if (__bch2_ptr_matches_stripe(&s->ptrs[i], ptr,
						      le16_to_cpu(s->sectors))) {
				*block = i;
				return ptr;
			}

	return NULL;
}

static bool extent_has_stripe_ptr(struct bkey_s_c k, u64 idx)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) ==
		    BCH_EXTENT_ENTRY_stripe_ptr &&
		    entry->stripe_ptr.idx == idx)
			return true;

	return false;
}

/* Stripe bufs: */

static void ec_stripe_buf_exit(struct ec_stripe_buf *buf)
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
static int ec_stripe_buf_init(struct bch_fs *c,
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
		if (!buf->data[i])
			goto err;
	}

	return 0;
err:
	ec_stripe_buf_exit(buf);
	return bch_err_throw(c, ENOMEM_stripe_buf);
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

static void ec_generate_checksums(struct ec_stripe_buf *buf)
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

static void ec_validate_checksums(struct bch_fs *c, struct ec_stripe_buf *buf)
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
				struct bch_dev *ca = bch2_dev_tryget(c, v->ptrs[i].dev);
				if (ca) {
					struct printbuf err = PRINTBUF;

					prt_str(&err, "stripe ");
					bch2_csum_err_msg(&err, v->csum_type, want, got);
					prt_printf(&err, "  for %ps at %u of\n  ", (void *) _RET_IP_, i);
					bch2_bkey_val_to_text(&err, c, bkey_i_to_s_c(&buf->key));
					bch_err_ratelimited(ca, "%s", err.buf);
					printbuf_exit(&err);

					bch2_io_error(ca, BCH_MEMBER_ERROR_checksum);
				}

				clear_bit(i, buf->valid);
				break;
			}

			offset += len;
		}
	}
}

/* Erasure coding: */

static void ec_generate_ec(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;
	unsigned bytes = le16_to_cpu(v->sectors) << 9;

	raid_gen(nr_data, v->nr_redundant, bytes, buf->data);
}

static unsigned ec_nr_failed(struct ec_stripe_buf *buf)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&buf->key)->v;

	return v->nr_blocks - bitmap_weight(buf->valid, v->nr_blocks);
}

static int ec_do_recov(struct bch_fs *c, struct ec_stripe_buf *buf)
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
		? BCH_DEV_READ_REF_ec_block
		: BCH_DEV_WRITE_REF_ec_block;

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

static void ec_block_io(struct bch_fs *c, struct ec_stripe_buf *buf,
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
		? BCH_DEV_READ_REF_ec_block
		: BCH_DEV_WRITE_REF_ec_block;

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
						       &c->ec_bioset),
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
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_stripes,
			       POS(0, idx), BTREE_ITER_slots);
	ret = bkey_err(k);
	if (ret)
		goto err;
	if (k.k->type != KEY_TYPE_stripe) {
		ret = -ENOENT;
		goto err;
	}
	bkey_reassemble(&stripe->key, k);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/* recovery read path: */
int bch2_ec_read_extent(struct btree_trans *trans, struct bch_read_bio *rbio,
			struct bkey_s_c orig_k)
{
	struct bch_fs *c = trans->c;
	struct ec_stripe_buf *buf = NULL;
	struct closure cl;
	struct bch_stripe *v;
	unsigned i, offset;
	const char *msg = NULL;
	struct printbuf msgbuf = PRINTBUF;
	int ret = 0;

	closure_init_stack(&cl);

	BUG_ON(!rbio->pick.has_ec);

	buf = kzalloc(sizeof(*buf), GFP_NOFS);
	if (!buf)
		return bch_err_throw(c, ENOMEM_ec_read_extent);

	ret = lockrestart_do(trans, get_stripe_key_trans(trans, rbio->pick.ec.idx, buf));
	if (ret) {
		msg = "stripe not found";
		goto err;
	}

	v = &bkey_i_to_stripe(&buf->key)->v;

	if (!bch2_ptr_matches_stripe(v, rbio->pick)) {
		msg = "pointer doesn't match stripe";
		goto err;
	}

	offset = rbio->bio.bi_iter.bi_sector - v->ptrs[rbio->pick.ec.block].offset;
	if (offset + bio_sectors(&rbio->bio) > le16_to_cpu(v->sectors)) {
		msg = "read is bigger than stripe";
		goto err;
	}

	ret = ec_stripe_buf_init(c, buf, offset, bio_sectors(&rbio->bio));
	if (ret) {
		msg = "-ENOMEM";
		goto err;
	}

	for (i = 0; i < v->nr_blocks; i++)
		ec_block_io(c, buf, REQ_OP_READ, i, &cl);

	closure_sync(&cl);

	if (ec_nr_failed(buf) > v->nr_redundant) {
		msg = "unable to read enough blocks";
		goto err;
	}

	ec_validate_checksums(c, buf);

	ret = ec_do_recov(c, buf);
	if (ret)
		goto err;

	memcpy_to_bio(&rbio->bio, rbio->bio.bi_iter,
		      buf->data[rbio->pick.ec.block] + ((offset - buf->offset) << 9));
out:
	ec_stripe_buf_exit(buf);
	kfree(buf);
	return ret;
err:
	bch2_bkey_val_to_text(&msgbuf, c, orig_k);
	bch_err_ratelimited(c,
			    "error doing reconstruct read: %s\n  %s", msg, msgbuf.buf);
	printbuf_exit(&msgbuf);
	ret = bch_err_throw(c, stripe_reconstruct);
	goto out;
}

/* stripe bucket accounting: */

static int __ec_stripe_mem_alloc(struct bch_fs *c, size_t idx, gfp_t gfp)
{
	if (c->gc_pos.phase != GC_PHASE_not_running &&
	    !genradix_ptr_alloc(&c->gc_stripes, idx, gfp))
		return bch_err_throw(c, ENOMEM_ec_stripe_mem_alloc);

	return 0;
}

static int ec_stripe_mem_alloc(struct btree_trans *trans,
			       struct btree_iter *iter)
{
	return allocate_dropping_locks_errcode(trans,
			__ec_stripe_mem_alloc(trans->c, iter->pos.offset, _gfp));
}

/*
 * Hash table of open stripes:
 * Stripes that are being created or modified are kept in a hash table, so that
 * stripe deletion can skip them.
 */

static bool __bch2_stripe_is_open(struct bch_fs *c, u64 idx)
{
	unsigned hash = hash_64(idx, ilog2(ARRAY_SIZE(c->ec_stripes_new)));
	struct ec_stripe_new *s;

	hlist_for_each_entry(s, &c->ec_stripes_new[hash], hash)
		if (s->idx == idx)
			return true;
	return false;
}

static bool bch2_stripe_is_open(struct bch_fs *c, u64 idx)
{
	bool ret = false;

	spin_lock(&c->ec_stripes_new_lock);
	ret = __bch2_stripe_is_open(c, idx);
	spin_unlock(&c->ec_stripes_new_lock);

	return ret;
}

static bool bch2_try_open_stripe(struct bch_fs *c,
				 struct ec_stripe_new *s,
				 u64 idx)
{
	bool ret;

	spin_lock(&c->ec_stripes_new_lock);
	ret = !__bch2_stripe_is_open(c, idx);
	if (ret) {
		unsigned hash = hash_64(idx, ilog2(ARRAY_SIZE(c->ec_stripes_new)));

		s->idx = idx;
		hlist_add_head(&s->hash, &c->ec_stripes_new[hash]);
	}
	spin_unlock(&c->ec_stripes_new_lock);

	return ret;
}

static void bch2_stripe_close(struct bch_fs *c, struct ec_stripe_new *s)
{
	BUG_ON(!s->idx);

	spin_lock(&c->ec_stripes_new_lock);
	hlist_del_init(&s->hash);
	spin_unlock(&c->ec_stripes_new_lock);

	s->idx = 0;
}

/* stripe deletion */

static int ec_stripe_delete(struct btree_trans *trans, u64 idx)
{
	struct btree_iter iter;
	struct bkey_s_c k = bch2_bkey_get_iter(trans, &iter,
					       BTREE_ID_stripes, POS(0, idx),
					       BTREE_ITER_intent);
	int ret = bkey_err(k);
	if (ret)
		goto err;

	/*
	 * We expect write buffer races here
	 * Important: check stripe_is_open with stripe key locked:
	 */
	if (k.k->type == KEY_TYPE_stripe &&
	    !bch2_stripe_is_open(trans->c, idx) &&
	    stripe_lru_pos(bkey_s_c_to_stripe(k).v) == 1)
		ret = bch2_btree_delete_at(trans, &iter, 0);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/*
 * XXX
 * can we kill this and delete stripes from the trigger?
 */
static void ec_stripe_delete_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, ec_stripe_delete_work);

	bch2_trans_run(c,
		bch2_btree_write_buffer_tryflush(trans) ?:
		for_each_btree_key_max_commit(trans, lru_iter, BTREE_ID_lru,
				lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 1, 0),
				lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 1, LRU_TIME_MAX),
				0, lru_k,
				NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc, ({
			ec_stripe_delete(trans, lru_k.k->p.offset);
		})));
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_delete);
}

void bch2_do_stripe_deletes(struct bch_fs *c)
{
	if (enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_stripe_delete) &&
	    !queue_work(c->write_ref_wq, &c->ec_stripe_delete_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_delete);
}

/* stripe creation: */

static int ec_stripe_key_update(struct btree_trans *trans,
				struct bkey_i_stripe *old,
				struct bkey_i_stripe *new)
{
	struct bch_fs *c = trans->c;
	bool create = !old;

	struct btree_iter iter;
	struct bkey_s_c k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_stripes,
					       new->k.p, BTREE_ITER_intent);
	int ret = bkey_err(k);
	if (ret)
		goto err;

	if (bch2_fs_inconsistent_on(k.k->type != (create ? KEY_TYPE_deleted : KEY_TYPE_stripe),
				    c, "error %s stripe: got existing key type %s",
				    create ? "creating" : "updating",
				    bch2_bkey_types[k.k->type])) {
		ret = -EINVAL;
		goto err;
	}

	if (k.k->type == KEY_TYPE_stripe) {
		const struct bch_stripe *v = bkey_s_c_to_stripe(k).v;

		BUG_ON(old->v.nr_blocks != new->v.nr_blocks);
		BUG_ON(old->v.nr_blocks != v->nr_blocks);

		for (unsigned i = 0; i < new->v.nr_blocks; i++) {
			unsigned sectors = stripe_blockcount_get(v, i);

			if (!bch2_extent_ptr_eq(old->v.ptrs[i], new->v.ptrs[i]) && sectors) {
				struct printbuf buf = PRINTBUF;

				prt_printf(&buf, "stripe changed nonempty block %u", i);
				prt_str(&buf, "\nold: ");
				bch2_bkey_val_to_text(&buf, c, k);
				prt_str(&buf, "\nnew: ");
				bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new->k_i));
				bch2_fs_inconsistent(c, "%s", buf.buf);
				printbuf_exit(&buf);
				ret = -EINVAL;
				goto err;
			}

			/*
			 * If the stripe ptr changed underneath us, it must have
			 * been dev_remove_stripes() -> * invalidate_stripe_to_dev()
			 */
			if (!bch2_extent_ptr_eq(old->v.ptrs[i], v->ptrs[i])) {
				BUG_ON(v->ptrs[i].dev != BCH_SB_MEMBER_INVALID);

				if (bch2_extent_ptr_eq(old->v.ptrs[i], new->v.ptrs[i]))
					new->v.ptrs[i].dev = BCH_SB_MEMBER_INVALID;
			}

			stripe_blockcount_set(&new->v, i, sectors);
		}
	}

	ret = bch2_trans_update(trans, &iter, &new->k_i, 0);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int ec_stripe_update_extent(struct btree_trans *trans,
				   struct bch_dev *ca,
				   struct bpos bucket, u8 gen,
				   struct ec_stripe_buf *s,
				   struct bkey_s_c_backpointer bp,
				   struct bkey_buf *last_flushed)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&s->key)->v;
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	const struct bch_extent_ptr *ptr_c;
	struct bch_extent_ptr *ec_ptr = NULL;
	struct bch_extent_stripe_ptr stripe_ptr;
	struct bkey_i *n;
	int ret, dev, block;

	if (bp.v->level) {
		struct printbuf buf = PRINTBUF;
		struct btree_iter node_iter;
		struct btree *b;

		b = bch2_backpointer_get_node(trans, bp, &node_iter, last_flushed);
		bch2_trans_iter_exit(trans, &node_iter);

		if (!b)
			return 0;

		prt_printf(&buf, "found btree node in erasure coded bucket: b=%px\n", b);
		bch2_bkey_val_to_text(&buf, c, bp.s_c);

		bch2_fs_inconsistent(c, "%s", buf.buf);
		printbuf_exit(&buf);
		return bch_err_throw(c, erasure_coding_found_btree_node);
	}

	k = bch2_backpointer_get_key(trans, bp, &iter, BTREE_ITER_intent, last_flushed);
	ret = bkey_err(k);
	if (ret)
		return ret;
	if (!k.k) {
		/*
		 * extent no longer exists - we could flush the btree
		 * write buffer and retry to verify, but no need:
		 */
		return 0;
	}

	if (extent_has_stripe_ptr(k, s->key.k.p.offset))
		goto out;

	ptr_c = bkey_matches_stripe(v, k, &block);
	/*
	 * It doesn't generally make sense to erasure code cached ptrs:
	 * XXX: should we be incrementing a counter?
	 */
	if (!ptr_c || ptr_c->cached)
		goto out;

	dev = v->ptrs[block].dev;

	n = bch2_trans_kmalloc(trans, bkey_bytes(k.k) + sizeof(stripe_ptr));
	ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		goto out;

	bkey_reassemble(n, k);

	bch2_bkey_drop_ptrs_noerror(bkey_i_to_s(n), ptr, ptr->dev != dev);
	ec_ptr = bch2_bkey_has_device(bkey_i_to_s(n), dev);
	BUG_ON(!ec_ptr);

	stripe_ptr = (struct bch_extent_stripe_ptr) {
		.type = 1 << BCH_EXTENT_ENTRY_stripe_ptr,
		.block		= block,
		.redundancy	= v->nr_redundant,
		.idx		= s->key.k.p.offset,
	};

	__extent_entry_insert(n,
			(union bch_extent_entry *) ec_ptr,
			(union bch_extent_entry *) &stripe_ptr);

	ret = bch2_trans_update(trans, &iter, n, 0);
out:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int ec_stripe_update_bucket(struct btree_trans *trans, struct ec_stripe_buf *s,
				   unsigned block)
{
	struct bch_fs *c = trans->c;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->key)->v;
	struct bch_extent_ptr ptr = v->ptrs[block];
	int ret = 0;

	struct bch_dev *ca = bch2_dev_tryget(c, ptr.dev);
	if (!ca)
		return bch_err_throw(c, ENOENT_dev_not_found);

	struct bpos bucket_pos = PTR_BUCKET_POS(ca, &ptr);

	struct bkey_buf last_flushed;
	bch2_bkey_buf_init(&last_flushed);
	bkey_init(&last_flushed.k->k);

	ret = for_each_btree_key_max_commit(trans, bp_iter, BTREE_ID_backpointers,
			bucket_pos_to_bp_start(ca, bucket_pos),
			bucket_pos_to_bp_end(ca, bucket_pos), 0, bp_k,
			NULL, NULL,
			BCH_TRANS_COMMIT_no_check_rw|
			BCH_TRANS_COMMIT_no_enospc, ({
		if (bkey_ge(bp_k.k->p, bucket_pos_to_bp(ca, bpos_nosnap_successor(bucket_pos), 0)))
			break;

		if (bp_k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(bp_k);
		if (bp.v->btree_id == BTREE_ID_stripes)
			continue;

		ec_stripe_update_extent(trans, ca, bucket_pos, ptr.gen, s,
					bp, &last_flushed);
	}));

	bch2_bkey_buf_exit(&last_flushed, c);
	bch2_dev_put(ca);
	return ret;
}

static int ec_stripe_update_extents(struct bch_fs *c, struct ec_stripe_buf *s)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct bch_stripe *v = &bkey_i_to_stripe(&s->key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	int ret = bch2_btree_write_buffer_flush_sync(trans);
	if (ret)
		goto err;

	for (unsigned i = 0; i < nr_data; i++) {
		ret = ec_stripe_update_bucket(trans, s, i);
		if (ret)
			break;
	}
err:
	bch2_trans_put(trans);
	return ret;
}

static void zero_out_rest_of_ec_bucket(struct bch_fs *c,
				       struct ec_stripe_new *s,
				       unsigned block,
				       struct open_bucket *ob)
{
	struct bch_dev *ca = bch2_dev_get_ioref(c, ob->dev, WRITE,
				BCH_DEV_WRITE_REF_ec_bucket_zero);
	if (!ca) {
		s->err = bch_err_throw(c, erofs_no_writes);
		return;
	}

	unsigned offset = ca->mi.bucket_size - ob->sectors_free;
	memset(s->new_stripe.data[block] + (offset << 9),
	       0,
	       ob->sectors_free << 9);

	int ret = blkdev_issue_zeroout(ca->disk_sb.bdev,
			ob->bucket * ca->mi.bucket_size + offset,
			ob->sectors_free,
			GFP_KERNEL, 0);

	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_ec_bucket_zero);

	if (ret)
		s->err = ret;
}

void bch2_ec_stripe_new_free(struct bch_fs *c, struct ec_stripe_new *s)
{
	if (s->idx)
		bch2_stripe_close(c, s);
	kfree(s);
}

/*
 * data buckets of new stripe all written: create the stripe
 */
static void ec_stripe_create(struct ec_stripe_new *s)
{
	struct bch_fs *c = s->c;
	struct open_bucket *ob;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned i, nr_data = v->nr_blocks - v->nr_redundant;
	int ret;

	BUG_ON(s->h->s == s);

	closure_sync(&s->iodone);

	if (!s->err) {
		for (i = 0; i < nr_data; i++)
			if (s->blocks[i]) {
				ob = c->open_buckets + s->blocks[i];

				if (ob->sectors_free)
					zero_out_rest_of_ec_bucket(c, s, i, ob);
			}
	}

	if (s->err) {
		if (!bch2_err_matches(s->err, EROFS))
			bch_err(c, "error creating stripe: error writing data buckets");
		ret = s->err;
		goto err;
	}

	if (s->have_existing_stripe) {
		ec_validate_checksums(c, &s->existing_stripe);

		if (ec_do_recov(c, &s->existing_stripe)) {
			bch_err(c, "error creating stripe: error reading existing stripe");
			ret = bch_err_throw(c, ec_block_read);
			goto err;
		}

		for (i = 0; i < nr_data; i++)
			if (stripe_blockcount_get(&bkey_i_to_stripe(&s->existing_stripe.key)->v, i))
				swap(s->new_stripe.data[i],
				     s->existing_stripe.data[i]);

		ec_stripe_buf_exit(&s->existing_stripe);
	}

	BUG_ON(!s->allocated);
	BUG_ON(!s->idx);

	ec_generate_ec(&s->new_stripe);

	ec_generate_checksums(&s->new_stripe);

	/* write p/q: */
	for (i = nr_data; i < v->nr_blocks; i++)
		ec_block_io(c, &s->new_stripe, REQ_OP_WRITE, i, &s->iodone);
	closure_sync(&s->iodone);

	if (ec_nr_failed(&s->new_stripe)) {
		bch_err(c, "error creating stripe: error writing redundancy buckets");
		ret = bch_err_throw(c, ec_block_write);
		goto err;
	}

	ret = bch2_trans_commit_do(c, &s->res, NULL,
		BCH_TRANS_COMMIT_no_check_rw|
		BCH_TRANS_COMMIT_no_enospc,
		ec_stripe_key_update(trans,
				     s->have_existing_stripe
				     ? bkey_i_to_stripe(&s->existing_stripe.key)
				     : NULL,
				     bkey_i_to_stripe(&s->new_stripe.key)));
	bch_err_msg(c, ret, "creating stripe key");
	if (ret) {
		goto err;
	}

	ret = ec_stripe_update_extents(c, &s->new_stripe);
	bch_err_msg(c, ret, "error updating extents");
	if (ret)
		goto err;
err:
	trace_stripe_create(c, s->idx, ret);

	bch2_disk_reservation_put(c, &s->res);

	for (i = 0; i < v->nr_blocks; i++)
		if (s->blocks[i]) {
			ob = c->open_buckets + s->blocks[i];

			if (i < nr_data) {
				ob->ec = NULL;
				__bch2_open_bucket_put(c, ob);
			} else {
				bch2_open_bucket_put(c, ob);
			}
		}

	mutex_lock(&c->ec_stripe_new_lock);
	list_del(&s->list);
	mutex_unlock(&c->ec_stripe_new_lock);
	wake_up(&c->ec_stripe_new_wait);

	ec_stripe_buf_exit(&s->existing_stripe);
	ec_stripe_buf_exit(&s->new_stripe);
	closure_debug_destroy(&s->iodone);

	ec_stripe_new_put(c, s, STRIPE_REF_stripe);
}

static struct ec_stripe_new *get_pending_stripe(struct bch_fs *c)
{
	struct ec_stripe_new *s;

	mutex_lock(&c->ec_stripe_new_lock);
	list_for_each_entry(s, &c->ec_stripe_new_list, list)
		if (!atomic_read(&s->ref[STRIPE_REF_io]))
			goto out;
	s = NULL;
out:
	mutex_unlock(&c->ec_stripe_new_lock);

	return s;
}

static void ec_stripe_create_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work,
		struct bch_fs, ec_stripe_create_work);
	struct ec_stripe_new *s;

	while ((s = get_pending_stripe(c)))
		ec_stripe_create(s);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_create);
}

void bch2_ec_do_stripe_creates(struct bch_fs *c)
{
	enumerated_ref_get(&c->writes, BCH_WRITE_REF_stripe_create);

	if (!queue_work(system_long_wq, &c->ec_stripe_create_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_create);
}

static void ec_stripe_new_set_pending(struct bch_fs *c, struct ec_stripe_head *h)
{
	struct ec_stripe_new *s = h->s;

	lockdep_assert_held(&h->lock);

	BUG_ON(!s->allocated && !s->err);

	h->s		= NULL;
	s->pending	= true;

	mutex_lock(&c->ec_stripe_new_lock);
	list_add(&s->list, &c->ec_stripe_new_list);
	mutex_unlock(&c->ec_stripe_new_lock);

	ec_stripe_new_put(c, s, STRIPE_REF_io);
}

static void ec_stripe_new_cancel(struct bch_fs *c, struct ec_stripe_head *h, int err)
{
	h->s->err = err;
	ec_stripe_new_set_pending(c, h);
}

void bch2_ec_bucket_cancel(struct bch_fs *c, struct open_bucket *ob, int err)
{
	struct ec_stripe_new *s = ob->ec;

	s->err = err;
}

void *bch2_writepoint_ec_buf(struct bch_fs *c, struct write_point *wp)
{
	struct open_bucket *ob = ec_open_bucket(c, &wp->ptrs);
	if (!ob)
		return NULL;

	BUG_ON(!ob->ec->new_stripe.data[ob->ec_idx]);

	struct bch_dev *ca	= ob_dev(c, ob);
	unsigned offset		= ca->mi.bucket_size - ob->sectors_free;

	return ob->ec->new_stripe.data[ob->ec_idx] + (offset << 9);
}

static int unsigned_cmp(const void *_l, const void *_r)
{
	unsigned l = *((const unsigned *) _l);
	unsigned r = *((const unsigned *) _r);

	return cmp_int(l, r);
}

/* pick most common bucket size: */
static unsigned pick_blocksize(struct bch_fs *c,
			       struct bch_devs_mask *devs)
{
	unsigned nr = 0, sizes[BCH_SB_MEMBERS_MAX];
	struct {
		unsigned nr, size;
	} cur = { 0, 0 }, best = { 0, 0 };

	for_each_member_device_rcu(c, ca, devs)
		sizes[nr++] = ca->mi.bucket_size;

	sort(sizes, nr, sizeof(unsigned), unsigned_cmp, NULL);

	for (unsigned i = 0; i < nr; i++) {
		if (sizes[i] != cur.size) {
			if (cur.nr > best.nr)
				best = cur;

			cur.nr = 0;
			cur.size = sizes[i];
		}

		cur.nr++;
	}

	if (cur.nr > best.nr)
		best = cur;

	return best.size;
}

static bool may_create_new_stripe(struct bch_fs *c)
{
	return false;
}

static void ec_stripe_key_init(struct bch_fs *c,
			       struct bkey_i *k,
			       unsigned nr_data,
			       unsigned nr_parity,
			       unsigned stripe_size,
			       unsigned disk_label)
{
	struct bkey_i_stripe *s = bkey_stripe_init(k);
	unsigned u64s;

	s->v.sectors			= cpu_to_le16(stripe_size);
	s->v.algorithm			= 0;
	s->v.nr_blocks			= nr_data + nr_parity;
	s->v.nr_redundant		= nr_parity;
	s->v.csum_granularity_bits	= ilog2(c->opts.encoded_extent_max >> 9);
	s->v.csum_type			= BCH_CSUM_crc32c;
	s->v.disk_label			= disk_label;

	while ((u64s = stripe_val_u64s(&s->v)) > BKEY_VAL_U64s_MAX) {
		BUG_ON(1 << s->v.csum_granularity_bits >=
		       le16_to_cpu(s->v.sectors) ||
		       s->v.csum_granularity_bits == U8_MAX);
		s->v.csum_granularity_bits++;
	}

	set_bkey_val_u64s(&s->k, u64s);
}

static struct ec_stripe_new *ec_new_stripe_alloc(struct bch_fs *c, struct ec_stripe_head *h)
{
	struct ec_stripe_new *s;

	lockdep_assert_held(&h->lock);

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;

	mutex_init(&s->lock);
	closure_init(&s->iodone, NULL);
	atomic_set(&s->ref[STRIPE_REF_stripe], 1);
	atomic_set(&s->ref[STRIPE_REF_io], 1);
	s->c		= c;
	s->h		= h;
	s->nr_data	= min_t(unsigned, h->nr_active_devs,
				BCH_BKEY_PTRS_MAX) - h->redundancy;
	s->nr_parity	= h->redundancy;

	ec_stripe_key_init(c, &s->new_stripe.key,
			   s->nr_data, s->nr_parity,
			   h->blocksize, h->disk_label);
	return s;
}

static void ec_stripe_head_devs_update(struct bch_fs *c, struct ec_stripe_head *h)
{
	struct bch_devs_mask devs = h->devs;
	unsigned nr_devs, nr_devs_with_durability;

	scoped_guard(rcu) {
		h->devs = target_rw_devs(c, BCH_DATA_user, h->disk_label
					 ? group_to_target(h->disk_label - 1)
					 : 0);
		nr_devs = dev_mask_nr(&h->devs);

		for_each_member_device_rcu(c, ca, &h->devs)
			if (!ca->mi.durability)
				__clear_bit(ca->dev_idx, h->devs.d);
		nr_devs_with_durability = dev_mask_nr(&h->devs);

		h->blocksize = pick_blocksize(c, &h->devs);

		h->nr_active_devs = 0;
		for_each_member_device_rcu(c, ca, &h->devs)
			if (ca->mi.bucket_size == h->blocksize)
				h->nr_active_devs++;
	}

	/*
	 * If we only have redundancy + 1 devices, we're better off with just
	 * replication:
	 */
	h->insufficient_devs = h->nr_active_devs < h->redundancy + 2;

	if (h->insufficient_devs) {
		const char *err;

		if (nr_devs < h->redundancy + 2)
			err = NULL;
		else if (nr_devs_with_durability < h->redundancy + 2)
			err = "cannot use durability=0 devices";
		else
			err = "mismatched bucket sizes";

		if (err)
			bch_err(c, "insufficient devices available to create stripe (have %u, need %u): %s",
				h->nr_active_devs, h->redundancy + 2, err);
	}

	struct bch_devs_mask devs_leaving;
	bitmap_andnot(devs_leaving.d, devs.d, h->devs.d, BCH_SB_MEMBERS_MAX);

	if (h->s && !h->s->allocated && dev_mask_nr(&devs_leaving))
		ec_stripe_new_cancel(c, h, -EINTR);

	h->rw_devs_change_count = c->rw_devs_change_count;
}

static struct ec_stripe_head *
ec_new_stripe_head_alloc(struct bch_fs *c, unsigned disk_label,
			 unsigned algo, unsigned redundancy,
			 enum bch_watermark watermark)
{
	struct ec_stripe_head *h;

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return NULL;

	mutex_init(&h->lock);
	BUG_ON(!mutex_trylock(&h->lock));

	h->disk_label	= disk_label;
	h->algo		= algo;
	h->redundancy	= redundancy;
	h->watermark	= watermark;

	list_add(&h->list, &c->ec_stripe_head_list);
	return h;
}

void bch2_ec_stripe_head_put(struct bch_fs *c, struct ec_stripe_head *h)
{
	if (h->s &&
	    h->s->allocated &&
	    bitmap_weight(h->s->blocks_allocated,
			  h->s->nr_data) == h->s->nr_data)
		ec_stripe_new_set_pending(c, h);

	mutex_unlock(&h->lock);
}

static struct ec_stripe_head *
__bch2_ec_stripe_head_get(struct btree_trans *trans,
			  unsigned disk_label,
			  unsigned algo,
			  unsigned redundancy,
			  enum bch_watermark watermark)
{
	struct bch_fs *c = trans->c;
	struct ec_stripe_head *h;
	int ret;

	if (!redundancy)
		return NULL;

	ret = bch2_trans_mutex_lock(trans, &c->ec_stripe_head_lock);
	if (ret)
		return ERR_PTR(ret);

	if (test_bit(BCH_FS_going_ro, &c->flags)) {
		h = ERR_PTR(bch_err_throw(c, erofs_no_writes));
		goto err;
	}

	list_for_each_entry(h, &c->ec_stripe_head_list, list)
		if (h->disk_label	== disk_label &&
		    h->algo		== algo &&
		    h->redundancy	== redundancy &&
		    h->watermark	== watermark) {
			ret = bch2_trans_mutex_lock(trans, &h->lock);
			if (ret) {
				h = ERR_PTR(ret);
				goto err;
			}
			goto found;
		}

	h = ec_new_stripe_head_alloc(c, disk_label, algo, redundancy, watermark);
	if (!h) {
		h = ERR_PTR(bch_err_throw(c, ENOMEM_stripe_head_alloc));
		goto err;
	}
found:
	if (h->rw_devs_change_count != c->rw_devs_change_count)
		ec_stripe_head_devs_update(c, h);

	if (h->insufficient_devs) {
		mutex_unlock(&h->lock);
		h = NULL;
	}
err:
	mutex_unlock(&c->ec_stripe_head_lock);
	return h;
}

static int new_stripe_alloc_buckets(struct btree_trans *trans,
				    struct alloc_request *req,
				    struct ec_stripe_head *h, struct ec_stripe_new *s,
				    struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned i, j, nr_have_parity = 0, nr_have_data = 0;
	int ret = 0;

	req->scratch_data_type		= req->data_type;
	req->scratch_ptrs		= req->ptrs;
	req->scratch_nr_replicas	= req->nr_replicas;
	req->scratch_nr_effective	= req->nr_effective;
	req->scratch_have_cache		= req->have_cache;
	req->scratch_devs_may_alloc	= req->devs_may_alloc;

	req->devs_may_alloc	= h->devs;
	req->have_cache		= true;

	BUG_ON(v->nr_blocks	!= s->nr_data + s->nr_parity);
	BUG_ON(v->nr_redundant	!= s->nr_parity);

	/* * We bypass the sector allocator which normally does this: */
	bitmap_and(req->devs_may_alloc.d, req->devs_may_alloc.d,
		   c->rw_devs[BCH_DATA_user].d, BCH_SB_MEMBERS_MAX);

	for_each_set_bit(i, s->blocks_gotten, v->nr_blocks) {
		/*
		 * Note: we don't yet repair invalid blocks (failed/removed
		 * devices) when reusing stripes - we still need a codepath to
		 * walk backpointers and update all extents that point to that
		 * block when updating the stripe
		 */
		if (v->ptrs[i].dev != BCH_SB_MEMBER_INVALID)
			__clear_bit(v->ptrs[i].dev, req->devs_may_alloc.d);

		if (i < s->nr_data)
			nr_have_data++;
		else
			nr_have_parity++;
	}

	BUG_ON(nr_have_data	> s->nr_data);
	BUG_ON(nr_have_parity	> s->nr_parity);

	req->ptrs.nr = 0;
	if (nr_have_parity < s->nr_parity) {
		req->nr_replicas	= s->nr_parity;
		req->nr_effective	= nr_have_parity;
		req->data_type		= BCH_DATA_parity;

		ret = bch2_bucket_alloc_set_trans(trans, req, &h->parity_stripe, cl);

		open_bucket_for_each(c, &req->ptrs, ob, i) {
			j = find_next_zero_bit(s->blocks_gotten,
					       s->nr_data + s->nr_parity,
					       s->nr_data);
			BUG_ON(j >= s->nr_data + s->nr_parity);

			s->blocks[j] = req->ptrs.v[i];
			v->ptrs[j] = bch2_ob_ptr(c, ob);
			__set_bit(j, s->blocks_gotten);
		}

		if (ret)
			goto err;
	}

	req->ptrs.nr = 0;
	if (nr_have_data < s->nr_data) {
		req->nr_replicas	= s->nr_data;
		req->nr_effective	= nr_have_data;
		req->data_type		= BCH_DATA_user;

		ret = bch2_bucket_alloc_set_trans(trans, req, &h->block_stripe, cl);

		open_bucket_for_each(c, &req->ptrs, ob, i) {
			j = find_next_zero_bit(s->blocks_gotten,
					       s->nr_data, 0);
			BUG_ON(j >= s->nr_data);

			s->blocks[j] = req->ptrs.v[i];
			v->ptrs[j] = bch2_ob_ptr(c, ob);
			__set_bit(j, s->blocks_gotten);
		}

		if (ret)
			goto err;
	}
err:
	req->data_type		= req->scratch_data_type;
	req->ptrs		= req->scratch_ptrs;
	req->nr_replicas	= req->scratch_nr_replicas;
	req->nr_effective	= req->scratch_nr_effective;
	req->have_cache		= req->scratch_have_cache;
	req->devs_may_alloc	= req->scratch_devs_may_alloc;
	return ret;
}

static int __get_existing_stripe(struct btree_trans *trans,
				 struct ec_stripe_head *head,
				 struct ec_stripe_buf *stripe,
				 u64 idx)
{
	struct bch_fs *c = trans->c;

	struct btree_iter iter;
	struct bkey_s_c k = bch2_bkey_get_iter(trans, &iter,
					  BTREE_ID_stripes, POS(0, idx), 0);
	int ret = bkey_err(k);
	if (ret)
		goto err;

	/* We expect write buffer races here */
	if (k.k->type != KEY_TYPE_stripe)
		goto out;

	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);
	if (stripe_lru_pos(s.v) <= 1)
		goto out;

	if (s.v->disk_label		== head->disk_label &&
	    s.v->algorithm		== head->algo &&
	    s.v->nr_redundant		== head->redundancy &&
	    le16_to_cpu(s.v->sectors)	== head->blocksize &&
	    bch2_try_open_stripe(c, head->s, idx)) {
		bkey_reassemble(&stripe->key, k);
		ret = 1;
	}
out:
	bch2_set_btree_iter_dontneed(trans, &iter);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int init_new_stripe_from_existing(struct bch_fs *c, struct ec_stripe_new *s)
{
	struct bch_stripe *new_v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	struct bch_stripe *existing_v = &bkey_i_to_stripe(&s->existing_stripe.key)->v;
	unsigned i;

	BUG_ON(existing_v->nr_redundant != s->nr_parity);
	s->nr_data = existing_v->nr_blocks -
		existing_v->nr_redundant;

	int ret = ec_stripe_buf_init(c, &s->existing_stripe, 0, le16_to_cpu(existing_v->sectors));
	if (ret) {
		bch2_stripe_close(c, s);
		return ret;
	}

	BUG_ON(s->existing_stripe.size != le16_to_cpu(existing_v->sectors));

	/*
	 * Free buckets we initially allocated - they might conflict with
	 * blocks from the stripe we're reusing:
	 */
	for_each_set_bit(i, s->blocks_gotten, new_v->nr_blocks) {
		bch2_open_bucket_put(c, c->open_buckets + s->blocks[i]);
		s->blocks[i] = 0;
	}
	memset(s->blocks_gotten, 0, sizeof(s->blocks_gotten));
	memset(s->blocks_allocated, 0, sizeof(s->blocks_allocated));

	for (unsigned i = 0; i < existing_v->nr_blocks; i++) {
		if (stripe_blockcount_get(existing_v, i)) {
			__set_bit(i, s->blocks_gotten);
			__set_bit(i, s->blocks_allocated);
		}

		ec_block_io(c, &s->existing_stripe, READ, i, &s->iodone);
	}

	bkey_copy(&s->new_stripe.key, &s->existing_stripe.key);
	s->have_existing_stripe = true;

	return 0;
}

static int __bch2_ec_stripe_head_reuse(struct btree_trans *trans, struct ec_stripe_head *h,
				       struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;

	/*
	 * If we can't allocate a new stripe, and there's no stripes with empty
	 * blocks for us to reuse, that means we have to wait on copygc:
	 */
	if (may_create_new_stripe(c))
		return -1;

	struct btree_iter lru_iter;
	struct bkey_s_c lru_k;
	int ret = 0;

	for_each_btree_key_max_norestart(trans, lru_iter, BTREE_ID_lru,
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, 0),
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, LRU_TIME_MAX),
			0, lru_k, ret) {
		ret = __get_existing_stripe(trans, h, &s->existing_stripe, lru_k.k->p.offset);
		if (ret)
			break;
	}
	bch2_trans_iter_exit(trans, &lru_iter);
	if (!ret)
		ret = bch_err_throw(c, stripe_alloc_blocked);
	if (ret == 1)
		ret = 0;
	if (ret)
		return ret;

	return init_new_stripe_from_existing(c, s);
}

static int __bch2_ec_stripe_head_reserve(struct btree_trans *trans, struct ec_stripe_head *h,
					 struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bpos min_pos = POS(0, 1);
	struct bpos start_pos = bpos_max(min_pos, POS(0, c->ec_stripe_hint));
	int ret;

	if (!s->res.sectors) {
		ret = bch2_disk_reservation_get(c, &s->res,
					h->blocksize,
					s->nr_parity,
					BCH_DISK_RESERVATION_NOFAIL);
		if (ret)
			return ret;
	}

	/*
	 * Allocate stripe slot
	 * XXX: we're going to need a bitrange btree of free stripes
	 */
	for_each_btree_key_norestart(trans, iter, BTREE_ID_stripes, start_pos,
			   BTREE_ITER_slots|BTREE_ITER_intent, k, ret) {
		if (bkey_gt(k.k->p, POS(0, U32_MAX))) {
			if (start_pos.offset) {
				start_pos = min_pos;
				bch2_btree_iter_set_pos(trans, &iter, start_pos);
				continue;
			}

			ret = bch_err_throw(c, ENOSPC_stripe_create);
			break;
		}

		if (bkey_deleted(k.k) &&
		    bch2_try_open_stripe(c, s, k.k->p.offset))
			break;
	}

	c->ec_stripe_hint = iter.pos.offset;

	if (ret)
		goto err;

	ret = ec_stripe_mem_alloc(trans, &iter);
	if (ret) {
		bch2_stripe_close(c, s);
		goto err;
	}

	s->new_stripe.key.k.p = iter.pos;
out:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
err:
	bch2_disk_reservation_put(c, &s->res);
	goto out;
}

struct ec_stripe_head *bch2_ec_stripe_head_get(struct btree_trans *trans,
					       struct alloc_request *req,
					       unsigned algo,
					       struct closure *cl)
{
	struct bch_fs *c = trans->c;
	unsigned redundancy = req->nr_replicas - 1;
	unsigned disk_label = 0;
	struct target t = target_decode(req->target);
	bool waiting = false;
	int ret;

	if (t.type == TARGET_GROUP) {
		if (t.group > U8_MAX) {
			bch_err(c, "cannot create a stripe when disk_label > U8_MAX");
			return NULL;
		}
		disk_label = t.group + 1; /* 0 == no label */
	}

	struct ec_stripe_head *h =
		__bch2_ec_stripe_head_get(trans, disk_label, algo,
					  redundancy, req->watermark);
	if (IS_ERR_OR_NULL(h))
		return h;

	if (!h->s) {
		h->s = ec_new_stripe_alloc(c, h);
		if (!h->s) {
			ret = bch_err_throw(c, ENOMEM_ec_new_stripe_alloc);
			bch_err(c, "failed to allocate new stripe");
			goto err;
		}

		h->nr_created++;
	}

	struct ec_stripe_new *s = h->s;

	if (s->allocated)
		goto allocated;

	if (s->have_existing_stripe)
		goto alloc_existing;

	/* First, try to allocate a full stripe: */
	enum bch_watermark saved_watermark = BCH_WATERMARK_stripe;
	swap(req->watermark, saved_watermark);
	ret =   new_stripe_alloc_buckets(trans, req, h, s, NULL) ?:
		__bch2_ec_stripe_head_reserve(trans, h, s);
	swap(req->watermark, saved_watermark);

	if (!ret)
		goto allocate_buf;
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
	    bch2_err_matches(ret, ENOMEM))
		goto err;

	/*
	 * Not enough buckets available for a full stripe: we must reuse an
	 * existing stripe:
	 */
	while (1) {
		ret = __bch2_ec_stripe_head_reuse(trans, h, s);
		if (!ret)
			break;
		if (waiting || !cl || ret != -BCH_ERR_stripe_alloc_blocked)
			goto err;

		if (req->watermark == BCH_WATERMARK_copygc) {
			ret =   new_stripe_alloc_buckets(trans, req, h, s, NULL) ?:
				__bch2_ec_stripe_head_reserve(trans, h, s);
			if (ret)
				goto err;
			goto allocate_buf;
		}

		/* XXX freelist_wait? */
		closure_wait(&c->freelist_wait, cl);
		waiting = true;
	}

	if (waiting)
		closure_wake_up(&c->freelist_wait);
alloc_existing:
	/*
	 * Retry allocating buckets, with the watermark for this
	 * particular write:
	 */
	ret = new_stripe_alloc_buckets(trans, req, h, s, cl);
	if (ret)
		goto err;

allocate_buf:
	ret = ec_stripe_buf_init(c, &s->new_stripe, 0, h->blocksize);
	if (ret)
		goto err;

	s->allocated = true;
allocated:
	BUG_ON(!s->idx);
	BUG_ON(!s->new_stripe.data[0]);
	BUG_ON(trans->restarted);
	return h;
err:
	bch2_ec_stripe_head_put(c, h);
	return ERR_PTR(ret);
}

/* device removal */

int bch2_invalidate_stripe_to_dev(struct btree_trans *trans,
				  struct btree_iter *iter,
				  struct bkey_s_c k,
				  unsigned dev_idx,
				  unsigned flags)
{
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_i_stripe *s =
		bch2_bkey_make_mut_typed(trans, iter, &k, 0, stripe);
	int ret = PTR_ERR_OR_ZERO(s);
	if (ret)
		return ret;

	struct disk_accounting_pos acc;

	s64 sectors = 0;
	for (unsigned i = 0; i < s->v.nr_blocks; i++)
		sectors -= stripe_blockcount_get(&s->v, i);

	memset(&acc, 0, sizeof(acc));
	acc.type = BCH_DISK_ACCOUNTING_replicas;
	bch2_bkey_to_replicas(&acc.replicas, bkey_i_to_s_c(&s->k_i));
	acc.replicas.data_type = BCH_DATA_user;
	ret = bch2_disk_accounting_mod(trans, &acc, &sectors, 1, false);
	if (ret)
		return ret;

	struct bkey_ptrs ptrs = bch2_bkey_ptrs(bkey_i_to_s(&s->k_i));

	/* XXX: how much redundancy do we still have? check degraded flags */

	unsigned nr_good = 0;

	scoped_guard(rcu)
		bkey_for_each_ptr(ptrs, ptr) {
			if (ptr->dev == dev_idx)
				ptr->dev = BCH_SB_MEMBER_INVALID;

			struct bch_dev *ca = bch2_dev_rcu(c, ptr->dev);
			nr_good += ca && ca->mi.state != BCH_MEMBER_STATE_failed;
		}

	if (nr_good < s->v.nr_blocks && !(flags & BCH_FORCE_IF_DATA_DEGRADED))
		return bch_err_throw(c, remove_would_lose_data);

	unsigned nr_data = s->v.nr_blocks - s->v.nr_redundant;

	if (nr_good < nr_data && !(flags & BCH_FORCE_IF_DATA_LOST))
		return bch_err_throw(c, remove_would_lose_data);

	sectors = -sectors;

	memset(&acc, 0, sizeof(acc));
	acc.type = BCH_DISK_ACCOUNTING_replicas;
	bch2_bkey_to_replicas(&acc.replicas, bkey_i_to_s_c(&s->k_i));
	acc.replicas.data_type = BCH_DATA_user;
	return bch2_disk_accounting_mod(trans, &acc, &sectors, 1, false);
}

static int bch2_invalidate_stripe_to_dev_from_alloc(struct btree_trans *trans, struct bkey_s_c k_a,
						    unsigned flags)
{
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k_a, &a_convert);

	if (!a->stripe)
		return 0;

	if (a->stripe_sectors) {
		struct bch_fs *c = trans->c;
		bch_err(c, "trying to invalidate device in stripe when bucket has stripe data");
		return bch_err_throw(c, invalidate_stripe_to_dev);
	}

	struct btree_iter iter;
	struct bkey_s_c_stripe s =
		bch2_bkey_get_iter_typed(trans, &iter, BTREE_ID_stripes, POS(0, a->stripe),
					 BTREE_ITER_slots, stripe);
	int ret = bkey_err(s);
	if (ret)
		return ret;

	ret = bch2_invalidate_stripe_to_dev(trans, &iter, s.s_c, k_a.k->p.inode, flags);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_dev_remove_stripes(struct bch_fs *c, unsigned dev_idx, unsigned flags)
{
	int ret = bch2_trans_run(c,
		for_each_btree_key_max_commit(trans, iter,
				  BTREE_ID_alloc, POS(dev_idx, 0), POS(dev_idx, U64_MAX),
				  BTREE_ITER_intent, k,
				  NULL, NULL, 0, ({
			bch2_invalidate_stripe_to_dev_from_alloc(trans, k, flags);
	})));
	bch_err_fn(c, ret);
	return ret;
}

/* startup/shutdown */

static void __bch2_ec_stop(struct bch_fs *c, struct bch_dev *ca)
{
	struct ec_stripe_head *h;
	struct open_bucket *ob;
	unsigned i;

	mutex_lock(&c->ec_stripe_head_lock);
	list_for_each_entry(h, &c->ec_stripe_head_list, list) {
		mutex_lock(&h->lock);
		if (!h->s)
			goto unlock;

		if (!ca)
			goto found;

		for (i = 0; i < bkey_i_to_stripe(&h->s->new_stripe.key)->v.nr_blocks; i++) {
			if (!h->s->blocks[i])
				continue;

			ob = c->open_buckets + h->s->blocks[i];
			if (ob->dev == ca->dev_idx)
				goto found;
		}
		goto unlock;
found:
		ec_stripe_new_cancel(c, h, -BCH_ERR_erofs_no_writes);
unlock:
		mutex_unlock(&h->lock);
	}
	mutex_unlock(&c->ec_stripe_head_lock);
}

void bch2_ec_stop_dev(struct bch_fs *c, struct bch_dev *ca)
{
	__bch2_ec_stop(c, ca);
}

void bch2_fs_ec_stop(struct bch_fs *c)
{
	__bch2_ec_stop(c, NULL);
}

static bool bch2_fs_ec_flush_done(struct bch_fs *c)
{
	sched_annotate_sleep();

	mutex_lock(&c->ec_stripe_new_lock);
	bool ret = list_empty(&c->ec_stripe_new_list);
	mutex_unlock(&c->ec_stripe_new_lock);

	return ret;
}

void bch2_fs_ec_flush(struct bch_fs *c)
{
	wait_event(c->ec_stripe_new_wait, bch2_fs_ec_flush_done(c));
}

int bch2_stripes_read(struct bch_fs *c)
{
	return 0;
}

static void bch2_new_stripe_to_text(struct printbuf *out, struct bch_fs *c,
				    struct ec_stripe_new *s)
{
	prt_printf(out, "\tidx %llu blocks %u+%u allocated %u ref %u %u %s obs",
		   s->idx, s->nr_data, s->nr_parity,
		   bitmap_weight(s->blocks_allocated, s->nr_data),
		   atomic_read(&s->ref[STRIPE_REF_io]),
		   atomic_read(&s->ref[STRIPE_REF_stripe]),
		   bch2_watermarks[s->h->watermark]);

	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned i;
	for_each_set_bit(i, s->blocks_gotten, v->nr_blocks)
		prt_printf(out, " %u", s->blocks[i]);
	prt_newline(out);
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&s->new_stripe.key));
	prt_newline(out);
}

void bch2_new_stripes_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct ec_stripe_head *h;
	struct ec_stripe_new *s;

	mutex_lock(&c->ec_stripe_head_lock);
	list_for_each_entry(h, &c->ec_stripe_head_list, list) {
		prt_printf(out, "disk label %u algo %u redundancy %u %s nr created %llu:\n",
		       h->disk_label, h->algo, h->redundancy,
		       bch2_watermarks[h->watermark],
		       h->nr_created);

		if (h->s)
			bch2_new_stripe_to_text(out, c, h->s);
	}
	mutex_unlock(&c->ec_stripe_head_lock);

	prt_printf(out, "in flight:\n");

	mutex_lock(&c->ec_stripe_new_lock);
	list_for_each_entry(s, &c->ec_stripe_new_list, list)
		bch2_new_stripe_to_text(out, c, s);
	mutex_unlock(&c->ec_stripe_new_lock);
}

void bch2_fs_ec_exit(struct bch_fs *c)
{
	struct ec_stripe_head *h;
	unsigned i;

	while (1) {
		mutex_lock(&c->ec_stripe_head_lock);
		h = list_pop_entry(&c->ec_stripe_head_list, struct ec_stripe_head, list);
		mutex_unlock(&c->ec_stripe_head_lock);

		if (!h)
			break;

		if (h->s) {
			for (i = 0; i < bkey_i_to_stripe(&h->s->new_stripe.key)->v.nr_blocks; i++)
				BUG_ON(h->s->blocks[i]);

			kfree(h->s);
		}
		kfree(h);
	}

	BUG_ON(!list_empty(&c->ec_stripe_new_list));

	bioset_exit(&c->ec_bioset);
}

void bch2_fs_ec_init_early(struct bch_fs *c)
{
	spin_lock_init(&c->ec_stripes_new_lock);

	INIT_LIST_HEAD(&c->ec_stripe_head_list);
	mutex_init(&c->ec_stripe_head_lock);

	INIT_LIST_HEAD(&c->ec_stripe_new_list);
	mutex_init(&c->ec_stripe_new_lock);
	init_waitqueue_head(&c->ec_stripe_new_wait);

	INIT_WORK(&c->ec_stripe_create_work, ec_stripe_create_work);
	INIT_WORK(&c->ec_stripe_delete_work, ec_stripe_delete_work);
}

int bch2_fs_ec_init(struct bch_fs *c)
{
	return bioset_init(&c->ec_bioset, 1, offsetof(struct ec_bio, bio),
			   BIOSET_NEED_BVECS);
}

static int bch2_check_stripe_to_lru_ref(struct btree_trans *trans,
					struct bkey_s_c k,
					struct bkey_buf *last_flushed)
{
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);

	u64 lru_idx = stripe_lru_pos(s.v);
	if (lru_idx) {
		int ret = bch2_lru_check_set(trans, BCH_LRU_STRIPE_FRAGMENTATION,
					     k.k->p.offset, lru_idx, k, last_flushed);
		if (ret)
			return ret;
	}
	return 0;
}

int bch2_check_stripe_to_lru_refs(struct bch_fs *c)
{
	struct bkey_buf last_flushed;

	bch2_bkey_buf_init(&last_flushed);
	bkey_init(&last_flushed.k->k);

	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter, BTREE_ID_stripes,
				POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_check_stripe_to_lru_ref(trans, k, &last_flushed)));

	bch2_bkey_buf_exit(&last_flushed, c);
	bch_err_fn(c, ret);
	return ret;
}
