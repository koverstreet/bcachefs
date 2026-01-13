// SPDX-License-Identifier: GPL-2.0

/* erasure coding */

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"
#include "alloc/replicas.h"

#include "btree/bkey_buf.h"
#include "btree/bset.h"
#include "btree/check.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/checksum.h"
#include "data/ec.h"
#include "data/read.h"
#include "data/write.h"
#include "data/keylist.h"
#include "data/reconcile.h"

#include "init/error.h"
#include "init/passes.h"
#include "init/recovery.h"

#include "sb/counters.h"
#include "sb/io.h"

#include "util/enumerated_ref.h"
#include "util/util.h"

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

	bkey_fsck_err_on(!s->sectors,
			 c, stripe_sectors_zero,
			 "invalid sectors zero");

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

	guard(printbuf_indent)(out);
	guard(printbuf_atomic)(out);
	guard(rcu)();

	for (unsigned i = 0; i < s.nr_blocks; i++) {
		const struct bch_extent_ptr *ptr = sp->ptrs + i;

		if ((void *) ptr >= bkey_val_end(k))
			break;

		prt_newline(out);
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
	CLASS(printbuf, buf)();

	struct bch_fs *c = trans->c;
	if (deleting)
		sectors = -sectors;

	if (!deleting) {
		if (bch2_trans_inconsistent_on(parity && bch2_bucket_sectors_total(*a), trans,
				"bucket %llu:%llu gen %u data type %s dirty_sectors %u cached_sectors %u: data already in parity bucket\n%s",
				bucket.inode, bucket.offset, a->gen,
				bch2_data_type_str(a->data_type),
				a->dirty_sectors,
				a->cached_sectors,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf)))
			return bch_err_throw(c, mark_stripe);
	} else {
		if (bch2_trans_inconsistent_on(!a->stripe_refcount, trans,
				"bucket %llu:%llu gen %u: not marked as stripe when deleting stripe\n%s",
				bucket.inode, bucket.offset, a->gen,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf)))
			return bch_err_throw(c, mark_stripe);

		if (bch2_trans_inconsistent_on(a->data_type != data_type, trans,
				"bucket %llu:%llu gen %u data type %s: wrong data type when stripe, should be %s\n%s",
				bucket.inode, bucket.offset, a->gen,
				bch2_data_type_str(a->data_type),
				bch2_data_type_str(data_type),
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf)))
			return bch_err_throw(c, mark_stripe);

		if (bch2_trans_inconsistent_on(parity &&
					       (a->dirty_sectors != -sectors ||
						a->cached_sectors), trans,
				"bucket %llu:%llu gen %u dirty_sectors %u cached_sectors %u: wrong sectors when deleting parity block of stripe\n%s",
				bucket.inode, bucket.offset, a->gen,
				a->dirty_sectors,
				a->cached_sectors,
				(bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf)))
			return bch_err_throw(c, mark_stripe);
	}

	if (sectors)
		try(bch2_bucket_ref_update(trans, ca, s.s_c, ptr, sectors, data_type,
					   a->gen, a->data_type, &a->dirty_sectors));

	if (flags & BTREE_TRIGGER_transactional)
		try(bch2_btree_bit_mod(trans, BTREE_ID_bucket_to_stripe,
				       POS(bucket_to_u64(bucket), s.k->p.offset), !deleting));

	if (!deleting)
		a->stripe_refcount++;
	else
		--a->stripe_refcount;

	if (data_type == BCH_DATA_parity &&
	    !a->stripe_refcount != !a->dirty_sectors) {
		int ret = bch2_bucket_nr_stripes(trans, bucket);
		if (ret < 0)
			return ret;

		unsigned nr_stripes = ret;
		ret = 0;

		if (ret_fsck_err_on(a->stripe_refcount != nr_stripes,
				trans, alloc_key_stripe_refcount_wrong,
				"bucket %llu:%llu with incorrect stripe_refcount, should be %u",
				bucket.inode, bucket.offset, nr_stripes))
			a->stripe_refcount = nr_stripes;

		if (!a->stripe_refcount != !a->dirty_sectors) {
			CLASS(bch_log_msg, msg)(c);
			prt_printf(&msg.m, "Parity bucket with dirty_sectors/stripe_refcount inconsistency at %llu:%llu\n",
				   bucket.inode, bucket.offset);
			prt_printf(&msg.m, "stripe_refcount %u but dirty_sectors %u\n", a->stripe_refcount, a->dirty_sectors);

			bch2_run_explicit_recovery_pass(c, &msg.m,
						BCH_RECOVERY_PASS_check_allocations, 0);
			bch2_run_explicit_recovery_pass(c, &msg.m,
						BCH_RECOVERY_PASS_check_alloc_info, 0);

			/* Ensure the bucket isn't reused until we run proper repair: */
			a->stripe_refcount	= max(a->stripe_refcount, 1);
			a->dirty_sectors	= max(a->dirty_sectors, 1);
		}
	}


	alloc_data_type_set(a, a->stripe_refcount ? data_type : BCH_DATA_user);

	return 0;
}

static int mark_stripe_bucket(struct btree_trans *trans,
			      struct bkey_s_c_stripe s,
			      unsigned ptr_idx, bool deleting,
			      enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	const struct bch_extent_ptr *ptr = s.v->ptrs + ptr_idx;
	CLASS(printbuf, buf)();

	CLASS(bch2_dev_tryget, ca)(c, ptr->dev);
	if (unlikely(!ca)) {
		if (ptr->dev != BCH_SB_MEMBER_INVALID && !(flags & BTREE_TRIGGER_overwrite))
			return bch_err_throw(c, mark_stripe);
		return 0;
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
			errptr_try(bch2_trans_start_alloc_update(trans, bucket, 0));

		try(__mark_stripe_bucket(trans, ca, s, ptr_idx, deleting, bucket, &a->v, flags));
		try(bch2_bucket_backpointer_mod(trans, s.s_c, &bp, !(flags & BTREE_TRIGGER_overwrite)));
	}

	if (flags & BTREE_TRIGGER_gc) {
		struct bucket *g = gc_bucket(ca, bucket.offset);
		if (bch2_fs_inconsistent_on(!g, c, "reference to invalid bucket on device %u\n%s",
					    ptr->dev,
					    (bch2_bkey_val_to_text(&buf, c, s.s_c), buf.buf)))
			return bch_err_throw(c, mark_stripe);

		struct bch_alloc_v4 old, new;

		scoped_guard(bucket_lock, g) {
			old = new = bucket_m_to_alloc(*g);

			try(__mark_stripe_bucket(trans, ca, s, ptr_idx, deleting, bucket, &new, flags));
			alloc_to_bucket(g, new);
		}

		try(bch2_alloc_key_to_dev_counters(trans, ca, &old, &new, flags));
	}

	return 0;
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

		if (new_s)
			try(mark_stripe_bucket(trans, bkey_s_c_to_stripe(new), i, false, flags));

		if (old_s)
			try(mark_stripe_bucket(trans, bkey_s_c_to_stripe(old), i, true, flags));
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

	if (flags & BTREE_TRIGGER_transactional)
		try(bch2_lru_change(trans,
				    BCH_LRU_STRIPE_FRAGMENTATION,
				    idx,
				    stripe_lru_pos(old_s),
				    stripe_lru_pos(new_s)));

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
			gc = genradix_ptr_alloc(&c->ec.gc_stripes, idx, GFP_KERNEL);
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
			bch2_bkey_to_replicas(c, &acc.replicas, new);
			try(bch2_disk_accounting_mod(trans, &acc, &sectors, 1, gc));

			if (gc)
				unsafe_memcpy(&gc->r.e, &acc.replicas,
					      replicas_entry_bytes(&acc.replicas), "VLA");
		}

		if (old_s) {
			s64 sectors = -((s64) le16_to_cpu(old_s->sectors)) * old_s->nr_redundant;

			struct disk_accounting_pos acc;
			memset(&acc, 0, sizeof(acc));
			acc.type = BCH_DISK_ACCOUNTING_replicas;
			bch2_bkey_to_replicas(c, &acc.replicas, old);
			try(bch2_disk_accounting_mod(trans, &acc, &sectors, 1, gc));
		}

		try(mark_stripe_buckets(trans, old, new, flags));
	}

	if ((flags & (BTREE_TRIGGER_atomic|BTREE_TRIGGER_gc)) == BTREE_TRIGGER_atomic) {
		if (new_s && stripe_lru_pos(new_s) == 1)
			bch2_do_stripe_deletes(c);
	}

	return 0;
}

/* returns blocknr in stripe that we matched: */
static const struct bch_extent_ptr *bkey_matches_stripe(const struct bch_fs *c,
							struct bch_stripe *s,
						struct bkey_s_c k, unsigned *block)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned i, nr_data = s->nr_blocks - s->nr_redundant;

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == BCH_SB_MEMBER_INVALID)
			continue;

		for (i = 0; i < nr_data; i++)
			if (s->ptrs[i].dev != BCH_SB_MEMBER_INVALID &&
			    __bch2_ptr_matches_stripe(&s->ptrs[i], ptr,
						      le16_to_cpu(s->sectors))) {
				*block = i;
				return ptr;
			}
	}

	return NULL;
}

static bool extent_has_stripe_ptr(const struct bch_fs *c, struct bkey_s_c k, u64 idx)
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

DEFINE_FREE(ec_stripe_buf_free, struct ec_stripe_buf *, ec_stripe_buf_exit(_T); kfree(_T));

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
		if (!buf->data[i]) {
			ec_stripe_buf_exit(buf);
			return bch_err_throw(c, ENOMEM_stripe_buf);
		}
	}

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
				CLASS(bch2_dev_tryget, ca)(c, v->ptrs[i].dev);
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

	ret = ec_stripe_buf_init(c, buf, offset, bio_sectors(&rbio->bio));
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "-ENOMEM");

	CLASS(closure_stack, cl)();

	for (unsigned i = 0; i < v->nr_blocks; i++)
		ec_block_io(c, buf, REQ_OP_READ, i, &cl);

	closure_sync(&cl);

	if (ec_nr_failed(buf) > v->nr_redundant)
		return stripe_reconstruct_err(c, orig_k, "unable to read enough blocks");

	ec_validate_checksums(c, buf);

	ret = ec_do_recov(c, buf);
	if (ret)
		return stripe_reconstruct_err(c, orig_k, "unable to read enough blocks");

	memcpy_to_bio(&rbio->bio, rbio->bio.bi_iter,
		      buf->data[rbio->pick.ec.block] + ((offset - buf->offset) << 9));
	return 0;
}

/* stripe bucket accounting: */

static int __ec_stripe_mem_alloc(struct bch_fs *c, size_t idx, gfp_t gfp)
{
	if (c->gc.pos.phase != GC_PHASE_not_running &&
	    !genradix_ptr_alloc(&c->ec.gc_stripes, idx, gfp))
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
 *
 * Additionally, we have a hash table for buckets that have stripes being
 * created, to avoid racing with rebalance:
 */

static bool __bch2_bucket_has_new_stripe(struct bch_fs *c, u64 dev_bucket)
{
	unsigned hash = hash_64(dev_bucket, ilog2(ARRAY_SIZE(c->ec.stripes_new_buckets)));
	struct ec_stripe_new_bucket *s;

	hlist_for_each_entry(s, &c->ec.stripes_new_buckets[hash], hash)
		if (s->dev_bucket == dev_bucket)
			return true;
	return false;
}

bool bch2_bucket_has_new_stripe(struct bch_fs *c, u64 dev_bucket)
{
	guard(spinlock)(&c->ec.stripes_new_lock);
	return __bch2_bucket_has_new_stripe(c, dev_bucket);
}

static void stripe_new_bucket_add(struct bch_fs *c, struct ec_stripe_new_bucket *s, u64 dev_bucket)
{
	s->dev_bucket = dev_bucket;

	unsigned hash = hash_64(dev_bucket, ilog2(ARRAY_SIZE(c->ec.stripes_new_buckets)));
	hlist_add_head(&s->hash, &c->ec.stripes_new_buckets[hash]);
}

static void stripe_new_buckets_add(struct bch_fs *c, struct ec_stripe_new *s)
{
	unsigned nr_blocks = s->nr_data + s->nr_parity;

	guard(spinlock)(&c->ec.stripes_new_lock);
	for (unsigned i = 0; i < nr_blocks; i++) {
		if (!s->blocks[i])
			continue;

		struct open_bucket *ob = c->allocator.open_buckets + s->blocks[i];
		struct bpos bucket = POS(ob->dev, ob->bucket);

		stripe_new_bucket_add(c, &s->buckets[i], bucket_to_u64(bucket));
	}
}

static void stripe_new_buckets_del(struct bch_fs *c, struct ec_stripe_new *s)
{
	guard(spinlock)(&c->ec.stripes_new_lock);

	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	for (unsigned i = 0; i < v->nr_blocks; i++)
		hlist_del_init(&s->buckets[i].hash);
}

static struct ec_stripe_handle *bch2_open_stripe_find(struct bch_fs *c, u64 idx)
{
	unsigned hash = hash_64(idx, ilog2(ARRAY_SIZE(c->ec.stripes_new)));
	struct ec_stripe_handle *s;

	hlist_for_each_entry(s, &c->ec.stripes_new[hash], hash)
		if (s->idx == idx)
			return s;
	return NULL;
}

static bool bch2_stripe_is_open(struct bch_fs *c, u64 idx)
{
	guard(spinlock)(&c->ec.stripes_new_lock);
	return bch2_open_stripe_find(c, idx) != NULL;
}

static bool bch2_stripe_handle_tryget(struct bch_fs *c,
				      struct ec_stripe_handle *s,
				      u64 idx)
{
	BUG_ON(s->idx);
	BUG_ON(!idx);

	guard(spinlock)(&c->ec.stripes_new_lock);
	bool ret = !bch2_open_stripe_find(c, idx);
	if (ret) {
		unsigned hash = hash_64(idx, ilog2(ARRAY_SIZE(c->ec.stripes_new)));

		s->idx = idx;
		hlist_add_head(&s->hash, &c->ec.stripes_new[hash]);
	}
	return ret;
}

static void bch2_stripe_handle_put(struct bch_fs *c, struct ec_stripe_handle *s)
{
	if (!s->idx)
		return;

	guard(spinlock)(&c->ec.stripes_new_lock);
	BUG_ON(bch2_open_stripe_find(c, s->idx) != s);
	hlist_del_init(&s->hash);

	s->idx = 0;
}

/* stripe deletion */

static int ec_stripe_delete(struct btree_trans *trans, u64 idx, bool warn)
{
	struct bch_fs *c = trans->c;
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, idx), BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (bch2_stripe_is_open(c, idx))
		return 0;

	/*
	 * We expect write buffer races here
	 * Important: check stripe_is_open with stripe key locked:
	 */
	if (k.k->type != KEY_TYPE_stripe ||
	    stripe_lru_pos(bkey_s_c_to_stripe(k).v) != 1) {
		CLASS(printbuf, buf)();
		bch2_fs_inconsistent_on(warn,
					c, "error deleting stripe: got non or nonempty stripe\n%s",
					(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		return 0;
	}

	return bch2_btree_delete_at(trans, &iter, 0);
}

/*
 * XXX
 * can we kill this and delete stripes from the trigger?
 */
static void ec_stripe_delete_work(struct work_struct *work)
{
	struct bch_fs *c =
		container_of(work, struct bch_fs, ec.stripe_delete_work);

	bch2_trans_run(c,
		bch2_btree_write_buffer_tryflush(trans) ?:
		for_each_btree_key_max_commit(trans, lru_iter, BTREE_ID_lru,
				lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 1, 0),
				lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 1, LRU_TIME_MAX),
				0, lru_k,
				NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc, ({
			ec_stripe_delete(trans, lru_k.k->p.offset, false);
		})));
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_delete);
}

void bch2_do_stripe_deletes(struct bch_fs *c)
{
	if (enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_stripe_delete) &&
	    !queue_work(c->write_ref_wq, &c->ec.stripe_delete_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_delete);
}

/* stripe creation: */

static int ec_stripe_key_update(struct btree_trans *trans,
				struct bkey_i_stripe *new)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, new->k.p, BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	CLASS(printbuf, buf)();
	if (bch2_fs_inconsistent_on(k.k->type,
				    c, "error creating stripe: got existing key\n%s",
				    (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
		return -EINVAL;

	return bch2_trans_update(trans, &iter, &new->k_i, 0);
}

struct stripe_update_bucket_stats {
	u32			nr_bp_to_deleted;
	u32			nr_no_match;
	u32			nr_cached;
	u32			nr_done;

	u32			sectors_bp_to_deleted;
	u32			sectors_no_match;
	u32			sectors_cached;
	u32			sectors_done;
};

static void bch2_bkey_drop_stripe_ptr(const struct bch_fs *c, struct bkey_s k, u64 idx)
{
	struct bkey_ptrs ptrs = bch2_bkey_ptrs(k);
	union bch_extent_entry *entry;

	bkey_extent_entry_for_each(ptrs, entry)
		if (extent_entry_type(entry) == BCH_EXTENT_ENTRY_stripe_ptr &&
		    entry->stripe_ptr.idx == idx) {
			extent_entry_drop(c, k, entry);
			return;
		}
}

static int ec_stripe_update_extent(struct btree_trans *trans,
				   struct bch_dev *ca,
				   struct bpos bucket, u8 gen,
				   struct ec_stripe_new *s,
				   struct bkey_s_c_backpointer bp,
				   struct stripe_update_bucket_stats *stats,
				   struct disk_reservation *res,
				   struct wb_maybe_flush *last_flushed)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	struct bch_fs *c = trans->c;

	if (bp.v->level) {
		CLASS(btree_iter_uninit, iter)(trans);
		struct btree *b = errptr_try(bch2_backpointer_get_node(trans, bp, &iter, last_flushed));

		CLASS(printbuf, buf)();
		prt_printf(&buf, "found btree node in erasure coded bucket:\n");
		if (b)
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
		else
			prt_str(&buf, "(not found)");

		bch2_fs_inconsistent(c, "%s", buf.buf);
		return bch_err_throw(c, erasure_coding_found_btree_node);
	}

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k =
		bkey_try(bch2_backpointer_get_key(trans, bp, &iter, BTREE_ITER_intent, last_flushed));
	if (!k.k) {
		/*
		 * extent no longer exists - we could flush the btree
		 * write buffer and retry to verify, but no need:
		 */
		stats->nr_bp_to_deleted++;
		stats->sectors_bp_to_deleted += bp.v->bucket_len;
		event_inc_trace(c, stripe_update_extent, buf, ({
			prt_str(&buf, "backpointer race\n");
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}

	if (extent_has_stripe_ptr(c, k, s->new_stripe.key.k.p.offset))
		return 0;

	unsigned block;
	const struct bch_extent_ptr *ptr_c = bkey_matches_stripe(c, v, k, &block);
	/*
	 * It doesn't generally make sense to erasure code cached ptrs:
	 * XXX: should we be incrementing a counter?
	 */
	if (!ptr_c) {
		stats->nr_no_match++;
		stats->sectors_no_match += bp.v->bucket_len;
		event_inc_trace(c, stripe_update_extent, buf, ({
			prt_str(&buf, "no matching pointer found\n");
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}
	if (ptr_c->cached) {
		stats->nr_cached++;
		stats->sectors_cached += bp.v->bucket_len;
		event_inc_trace(c, stripe_update_extent, buf, ({
			prt_str(&buf, "cached pointer\n");
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}

	unsigned dev = v->ptrs[block].dev;

	struct bch_extent_stripe_ptr stripe_ptr = (struct bch_extent_stripe_ptr) {
		.type = 1 << BCH_EXTENT_ENTRY_stripe_ptr,
		.block		= block,
		.redundancy	= v->nr_redundant,
		.idx		= s->new_stripe.key.k.p.offset,
	};

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, BKEY_EXTENT_U64s_MAX * sizeof(u64)));
	bkey_reassemble(n, k);

	if (s->have_old_stripe)
		bch2_bkey_drop_stripe_ptr(c, bkey_i_to_s(n), s->old_stripe.key.k.p.offset);

	bch2_bkey_drop_ptrs_noerror(bkey_i_to_s(n), p, entry, p.ptr.dev != dev);

	struct bch_extent_ptr *ec_ptr = bch2_bkey_has_device(c, bkey_i_to_s(n), dev);
	if (!ec_ptr) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "dev %u not found (%u)\n", dev, ca->dev_idx);
		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(n));
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		prt_newline(&buf);
		WARN(true, "%s", buf.buf);
		return 0;
	}

	__extent_entry_insert(c, n,
			(union bch_extent_entry *) ec_ptr,
			(union bch_extent_entry *) &stripe_ptr);

	struct bch_inode_opts opts;

	try(bch2_bkey_get_io_opts(trans, NULL, bkey_i_to_s_c(n), &opts));
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, n, SET_NEEDS_REBALANCE_other, 0));
	try(bch2_trans_update(trans, &iter, n, 0));
	try(bch2_trans_commit(trans, res, NULL,
			BCH_TRANS_COMMIT_no_check_rw|
			BCH_TRANS_COMMIT_no_enospc));

	stats->nr_done++;
	stats->sectors_done += bp.v->bucket_len;

	event_inc_trace(c, stripe_update_extent, buf,
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(n)));

	return 0;
}

static int ec_stripe_update_bucket(struct btree_trans *trans, struct ec_stripe_new *s,
				   unsigned block)
{
	struct bch_fs *c = trans->c;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	struct bch_extent_ptr ptr = v->ptrs[block];

	CLASS(bch2_dev_tryget, ca)(c, ptr.dev);
	if (!ca) /* BCH_SB_MEMBER_INVALID */
		return 0;

	struct bpos bucket_pos = PTR_BUCKET_POS(ca, &ptr);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct stripe_update_bucket_stats stats = {};

	CLASS(disk_reservation, res)(c);

	try(for_each_btree_key_max(trans, bp_iter, BTREE_ID_backpointers,
			bucket_pos_to_bp_start(ca, bucket_pos),
			bucket_pos_to_bp_end(ca, bucket_pos), 0, bp_k, ({
		if (bkey_ge(bp_k.k->p, bucket_pos_to_bp(ca, bpos_nosnap_successor(bucket_pos), 0)))
			break;

		if (bp_k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(bp_k);
		if (bp.v->btree_id == BTREE_ID_stripes)
			continue;

		wb_maybe_flush_inc(&last_flushed);
		ec_stripe_update_extent(trans, ca, bucket_pos, ptr.gen, s, bp,
					&stats, &res.r, &last_flushed);
	})));

	event_inc_trace(c, stripe_update_bucket, buf, ({
		prt_printf(&buf, "bp_to_deleted:\t%u %u\n",
			   stats.nr_bp_to_deleted, stats.sectors_bp_to_deleted);
		prt_printf(&buf, "no_match:\t%u %u\n",
			   stats.nr_no_match, stats.sectors_no_match);
		prt_printf(&buf, "cached:\t%u %u\n",
			   stats.nr_cached, stats.sectors_cached);
		prt_printf(&buf, "done:\t%u %u\n",
			   stats.nr_done, stats.sectors_done);
	}));

	return 0;
}

static int ec_stripe_update_extents(struct bch_fs *c, struct ec_stripe_new *s)
{
	CLASS(btree_trans, trans)(c);
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	try(bch2_btree_write_buffer_flush_sync(trans));

	for (unsigned i = 0; i < nr_data; i++)
		try(ec_stripe_update_bucket(trans, s, i));

	return 0;
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
	stripe_new_buckets_del(c, s);
	bch2_stripe_handle_put(c, &s->new_stripe_handle);
	bch2_stripe_handle_put(c, &s->old_stripe_handle);
	kfree(s);
}

static int __ec_stripe_create(struct ec_stripe_new *s)
{
	struct bch_fs *c = s->c;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	if (s->err) {
		if (!bch2_err_matches(s->err, EROFS))
			bch_err(c, "error creating stripe: error writing data buckets");
		return s->err;
	}

	for (unsigned i = 0; i < nr_data; i++)
		if (s->blocks[i]) {
			struct open_bucket *ob = c->allocator.open_buckets + s->blocks[i];

			if (ob->sectors_free)
				zero_out_rest_of_ec_bucket(c, s, i, ob);
		}

	if (s->have_old_stripe) {
		ec_validate_checksums(c, &s->old_stripe);

		if (ec_do_recov(c, &s->old_stripe)) {
			bch_err(c, "error creating stripe: error reading old stripe");
			return bch_err_throw(c, ec_block_read);
		}

		for (unsigned i = 0; i < s->old_blocks_nr; i++)
			swap(s->new_stripe.data[i],
			     s->old_stripe.data[s->old_block_map[i]]);

		ec_stripe_buf_exit(&s->old_stripe);
	}

	BUG_ON(!s->allocated);

	ec_generate_ec(&s->new_stripe);
	ec_generate_checksums(&s->new_stripe);

	/* write p/q: */
	for (unsigned i = nr_data; i < v->nr_blocks; i++)
		ec_block_io(c, &s->new_stripe, REQ_OP_WRITE, i, &s->iodone);
	closure_sync(&s->iodone);

	if (ec_nr_failed(&s->new_stripe)) {
		bch_err(c, "error creating stripe: error writing redundancy buckets");
		return bch_err_throw(c, ec_block_write);
	}

	try(bch2_trans_commit_do(c, &s->res, NULL,
		BCH_TRANS_COMMIT_no_check_rw|
		BCH_TRANS_COMMIT_no_enospc,
		ec_stripe_key_update(trans,
				     bkey_i_to_stripe(&s->new_stripe.key))));
	try(ec_stripe_update_extents(c, s));

	if (s->have_old_stripe)
		try(bch2_trans_commit_do(c, NULL, NULL,
				BCH_TRANS_COMMIT_no_check_rw|
				BCH_TRANS_COMMIT_no_enospc,
			ec_stripe_delete(trans, s->old_stripe.key.k.p.offset, true)));

	return 0;
}

static void stripe_put_iorefs(struct bch_fs *c, struct bch_stripe *s)
{
	for (unsigned i = 0; i < s->nr_blocks; i++) {
		struct bch_dev *ca = bch2_dev_have_ref(c, s->ptrs[i].dev);
		enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_stripe_update_extents);
	}
}

/*
 * Guard against racing with device removal by ensuring devices are writeable
 * while we create stripes and references to devices:
 */
static int stripe_get_iorefs(struct bch_fs *c, struct bch_stripe *s)
{
	for (unsigned i = 0; i < s->nr_blocks; i++) {
		unsigned dev = s->ptrs[i].dev;
		if (!bch2_dev_get_ioref(c, dev, WRITE, BCH_DEV_WRITE_REF_stripe_update_extents)) {
			while (i--) {
				struct bch_dev *ca = bch2_dev_have_ref(c, s->ptrs[i].dev);
				enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_stripe_update_extents);
			}
			return bch_err_throw(c, stripe_create_device_offline);
		}
	}

	return 0;
}

/*
 * data buckets of new stripe all written: create the stripe
 */
static void ec_stripe_create(struct ec_stripe_new *s)
{
	struct bch_fs *c = s->c;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	BUG_ON(s->h->s == s);

	closure_sync(&s->iodone);

	int ret = stripe_get_iorefs(c, v);
	if (!ret) {
		ret = __ec_stripe_create(s);
		stripe_put_iorefs(c, v);
	}
	if (ret && !s->err)
		s->err = ret;

	if (!ret)
		event_inc_trace(c, stripe_create, buf,
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key)));
	else
		event_inc_trace(c, stripe_create_fail, buf, ({
			prt_printf(&buf, "error %s\n", bch2_err_str(ret));
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));

	bch2_disk_reservation_put(c, &s->res);

	for (unsigned i = 0; i < v->nr_blocks; i++)
		if (s->blocks[i]) {
			struct open_bucket *ob = c->allocator.open_buckets + s->blocks[i];

			if (i < nr_data) {
				ob->ec = NULL;
				__bch2_open_bucket_put(c, ob);
			} else {
				bch2_open_bucket_put(c, ob);
			}
		}

	scoped_guard(mutex, &c->ec.stripe_new_lock)
		list_del(&s->list);
	wake_up(&c->ec.stripe_new_wait);

	ec_stripe_buf_exit(&s->old_stripe);
	ec_stripe_buf_exit(&s->new_stripe);
	closure_debug_destroy(&s->iodone);

	ec_stripe_new_put(c, s, STRIPE_REF_stripe);
}

static struct ec_stripe_new *get_pending_stripe(struct bch_fs *c)
{
	struct ec_stripe_new *s;

	guard(mutex)(&c->ec.stripe_new_lock);
	list_for_each_entry(s, &c->ec.stripe_new_list, list)
		if (!atomic_read(&s->ref[STRIPE_REF_io]))
			return s;
	return NULL;
}

static void ec_stripe_create_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work,
		struct bch_fs, ec.stripe_create_work);
	struct ec_stripe_new *s;

	while ((s = get_pending_stripe(c)))
		ec_stripe_create(s);

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_create);
}

void bch2_ec_do_stripe_creates(struct bch_fs *c)
{
	enumerated_ref_get(&c->writes, BCH_WRITE_REF_stripe_create);

	if (!queue_work(system_long_wq, &c->ec.stripe_create_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_stripe_create);
}

static void ec_stripe_new_set_pending(struct bch_fs *c, struct ec_stripe_head *h)
{
	struct ec_stripe_new *s = h->s;

	lockdep_assert_held(&h->lock);

	BUG_ON(!s->allocated && !s->err);

	h->s		= NULL;
	s->pending	= true;

	scoped_guard(mutex, &c->ec.stripe_new_lock)
		list_add(&s->list, &c->ec.stripe_new_list);

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
	struct bch_devs_mask old_devs = h->devs;

	scoped_guard(rcu) {
		h->devs = target_rw_devs(c, BCH_DATA_user, h->disk_label
					 ? group_to_target(h->disk_label - 1)
					 : 0);
		for_each_member_device_rcu(c, ca, &h->devs)
			if (!ca->mi.durability)
				__clear_bit(ca->dev_idx, h->devs.d);

		h->blocksize = pick_blocksize(c, &h->devs);

		for_each_member_device_rcu(c, ca, &h->devs)
			if (ca->mi.bucket_size != h->blocksize)
				__clear_bit(ca->dev_idx, h->devs.d);

		h->nr_active_devs = dev_mask_nr(&h->devs);
	}

	/*
	 * If we only have redundancy + 1 devices, we're better off with just
	 * replication:
	 */
	h->insufficient_devs = h->nr_active_devs < h->redundancy + 2;

	struct bch_devs_mask devs_leaving;
	bitmap_andnot(devs_leaving.d, old_devs.d, h->devs.d, BCH_SB_MEMBERS_MAX);


	if (h->s && !h->s->allocated && dev_mask_nr(&devs_leaving))
		ec_stripe_new_cancel(c, h, -EINTR);
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

	list_add(&h->list, &c->ec.stripe_head_list);
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

	if (!redundancy)
		return NULL;

	int ret = bch2_trans_mutex_lock(trans, &c->ec.stripe_head_lock);
	if (ret)
		return ERR_PTR(ret);

	if (test_bit(BCH_FS_going_ro, &c->flags)) {
		h = ERR_PTR(bch_err_throw(c, erofs_no_writes));
		goto err;
	}

	list_for_each_entry(h, &c->ec.stripe_head_list, list)
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
	unsigned long rw_devs_change_count = READ_ONCE(c->allocator.rw_devs_change_count);
	if (h->rw_devs_change_count != rw_devs_change_count) {
		ec_stripe_head_devs_update(c, h);
		h->rw_devs_change_count = rw_devs_change_count;
	}

	if (h->insufficient_devs) {
		mutex_unlock(&h->lock);
		h = NULL;
	}
err:
	mutex_unlock(&c->ec.stripe_head_lock);
	return h;
}

static int __new_stripe_alloc_buckets(struct btree_trans *trans,
				    struct alloc_request *req,
				    struct ec_stripe_head *h, struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob;
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned i, j, nr_have_parity = 0, nr_have_data = 0;

	BUG_ON(v->nr_blocks	!= s->nr_data + s->nr_parity);
	BUG_ON(v->nr_redundant	!= s->nr_parity);

	/* * We bypass the sector allocator which normally does this: */
	bitmap_and(req->devs_may_alloc.d, req->devs_may_alloc.d,
		   c->allocator.rw_devs[BCH_DATA_user].d, BCH_SB_MEMBERS_MAX);

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

		int ret = bch2_bucket_alloc_set_trans(trans, req, &h->parity_stripe);

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
			return ret;
	}

	req->ptrs.nr = 0;
	if (nr_have_data < s->nr_data) {
		req->nr_replicas	= s->nr_data;
		req->nr_effective	= nr_have_data;
		req->data_type		= BCH_DATA_user;

		int ret = bch2_bucket_alloc_set_trans(trans, req, &h->block_stripe);

		open_bucket_for_each(c, &req->ptrs, ob, i) {
			j = find_next_zero_bit(s->blocks_gotten,
					       s->nr_data, 0);
			BUG_ON(j >= s->nr_data);

			s->blocks[j] = req->ptrs.v[i];
			v->ptrs[j] = bch2_ob_ptr(c, ob);
			__set_bit(j, s->blocks_gotten);
		}

		if (ret)
			return ret;
	}

	return 0;
}

static int new_stripe_alloc_buckets(struct btree_trans *trans,
				    struct alloc_request *req,
				    struct ec_stripe_head *h, struct ec_stripe_new *s)
{
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;

	if (bitmap_weight(s->blocks_gotten, v->nr_blocks) == v->nr_blocks)
		return 0;

	req->scratch_data_type		= req->data_type;
	req->scratch_ptrs		= req->ptrs;
	req->scratch_nr_replicas	= req->nr_replicas;
	req->scratch_nr_effective	= req->nr_effective;
	req->scratch_have_cache		= req->have_cache;
	req->scratch_devs_may_alloc	= req->devs_may_alloc;

	req->devs_may_alloc	= h->devs;
	req->have_cache		= true;

	int ret = __new_stripe_alloc_buckets(trans, req, h, s);

	req->data_type		= req->scratch_data_type;
	req->ptrs		= req->scratch_ptrs;
	req->nr_replicas	= req->scratch_nr_replicas;
	req->nr_effective	= req->scratch_nr_effective;
	req->have_cache		= req->scratch_have_cache;
	req->devs_may_alloc	= req->scratch_devs_may_alloc;
	return ret;
}

static bool may_reuse_stripe(struct ec_stripe_head *h, const struct bch_stripe *s)
{
	if (s->disk_label		!= h->disk_label ||
	    s->algorithm		!= h->algo ||
	    s->nr_redundant		!= h->redundancy)
		return false;

	struct bch_devs_mask devs_may_alloc = h->devs;
	unsigned nr_data = s->nr_blocks - s->nr_redundant;

	for (unsigned i = 0; i < nr_data; i++)
		if (stripe_blockcount_get(s, i)) {
			if (s->ptrs[i].dev == BCH_SB_MEMBER_INVALID)
				return false;

			__clear_bit(s->ptrs[i].dev, devs_may_alloc.d);
		}

	return dev_mask_nr(&devs_may_alloc) > h->redundancy;
}

static int __get_old_stripe(struct btree_trans *trans,
				 struct ec_stripe_head *head,
				 struct ec_stripe_buf *stripe,
				 u64 idx)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, idx), BTREE_ITER_nopreserve);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	/* We expect write buffer races here */
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);
	if (stripe_lru_pos(s.v) <= 1)
		return 0;

	bool ret = may_reuse_stripe(head, s.v) &&
		bch2_stripe_handle_tryget(c, &head->s->old_stripe_handle, idx);
	if (ret)
		bkey_reassemble(&stripe->key, k);
	return ret;
}

static int init_new_stripe_from_old(struct bch_fs *c, struct ec_stripe_new *s)
{
	struct bch_stripe *new_v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	struct bch_stripe *old_v = &bkey_i_to_stripe(&s->old_stripe.key)->v;
	unsigned i;

	BUG_ON(old_v->nr_redundant != s->nr_parity);

	int ret = ec_stripe_buf_init(c, &s->old_stripe, 0, le16_to_cpu(old_v->sectors));
	if (ret) {
		bch2_stripe_handle_put(c, &s->old_stripe_handle);
		return ret;
	}

	BUG_ON(s->old_stripe.size != le16_to_cpu(old_v->sectors));

	/*
	 * Free buckets we initially allocated - they might conflict with
	 * blocks from the stripe we're reusing:
	 */
	for_each_set_bit(i, s->blocks_gotten, new_v->nr_blocks) {
		bch2_open_bucket_put(c, c->allocator.open_buckets + s->blocks[i]);
		s->blocks[i] = 0;
	}
	memset(s->blocks_gotten, 0, sizeof(s->blocks_gotten));
	memset(s->blocks_allocated, 0, sizeof(s->blocks_allocated));

	for (unsigned i = 0; i < old_v->nr_blocks; i++) {
		if (stripe_blockcount_get(old_v, i)) {
			__set_bit(s->old_blocks_nr, s->blocks_gotten);
			__set_bit(s->old_blocks_nr, s->blocks_allocated);

			new_v->ptrs[s->old_blocks_nr] = old_v->ptrs[i];

			s->old_block_map[s->old_blocks_nr++] = i;
		}

		ec_block_io(c, &s->old_stripe, READ, i, &s->iodone);
	}

	s->have_old_stripe = true;

	return 0;
}

static int __bch2_ec_stripe_reuse(struct btree_trans *trans, struct ec_stripe_head *h,
				       struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;

	/*
	 * If we can't allocate a new stripe, and there's no stripes with empty
	 * blocks for us to reuse, that means we have to wait on copygc:
	 */
	if (may_create_new_stripe(c))
		return -1;

	struct bkey_s_c lru_k;
	int ret = 0;

	for_each_btree_key_max_norestart(trans, lru_iter, BTREE_ID_lru,
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, 0),
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, LRU_TIME_MAX),
			0, lru_k, ret) {
		ret = __get_old_stripe(trans, h, &s->old_stripe, lru_k.k->p.offset);
		if (ret)
			break;
	}
	if (ret <= 0)
		return ret ?: bch_err_throw(c, stripe_alloc_blocked);

	return init_new_stripe_from_old(c, s);
}

static int stripe_idx_alloc(struct btree_trans *trans, struct ec_stripe_new *s)
{
	/*
	 * Allocate stripe slot
	 * XXX: we're going to need a bitrange btree of free stripes
	 */
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	struct bpos min_pos = POS(0, 1);
	struct bpos start_pos = bpos_max(min_pos, POS(0, c->ec.stripe_hint));
	int ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_stripes, start_pos,
			   BTREE_ITER_slots|BTREE_ITER_intent, k, ret) {
		c->ec.stripe_hint = iter.pos.offset;

		if (bkey_gt(k.k->p, POS(0, U32_MAX))) {
			if (start_pos.offset) {
				start_pos = min_pos;
				bch2_btree_iter_set_pos(&iter, start_pos);
				continue;
			}

			ret = bch_err_throw(c, ENOSPC_stripe_create);
			break;
		}

		if (bkey_deleted(k.k) &&
		    bch2_stripe_handle_tryget(c, &s->new_stripe_handle, k.k->p.offset)) {
			ret = ec_stripe_mem_alloc(trans, &iter);
			if (ret)
				bch2_stripe_handle_put(c, &s->new_stripe_handle);
			s->new_stripe.key.k.p = iter.pos;
			break;
		}
	}

	return ret;
}

static int stripe_alloc_or_reuse(struct btree_trans *trans,
				 struct alloc_request *req,
				 struct ec_stripe_head *h,
				 struct ec_stripe_new *s,
				 bool *waiting)
{
	struct bch_fs *c = trans->c;

	if (!s->new_stripe.key.k.p.offset)
		try(stripe_idx_alloc(trans, s));

	if (!s->have_old_stripe) {
		/* First, try to allocate a full stripe: */
		enum bch_watermark saved_watermark = BCH_WATERMARK_stripe;
		unsigned saved_flags = req->flags | BCH_WRITE_alloc_nowait;
		swap(req->watermark,	saved_watermark);
		swap(req->flags,	saved_flags);

		int ret = new_stripe_alloc_buckets(trans, req, h, s);

		swap(req->watermark,	saved_watermark);
		swap(req->flags,	saved_flags);

		if (ret) {
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart) ||
			    bch2_err_matches(ret, ENOMEM))
				return ret;

			/*
			 * Not enough buckets available for a full stripe: we must reuse an
			 * oldstripe:
			 */
			while (1) {
				ret = __bch2_ec_stripe_reuse(trans, h, s);
				if (!ret)
					break;
				if (*waiting ||
				    (req->flags & BCH_WRITE_alloc_nowait) ||
				    ret != -BCH_ERR_stripe_alloc_blocked)
					return ret;

				if (req->watermark == BCH_WATERMARK_copygc) {
					/* Don't self-deadlock copygc */
					swap(req->flags, saved_flags);
					ret =   new_stripe_alloc_buckets(trans, req, h, s);
					swap(req->flags, saved_flags);

					try(ret);
					break;
				}

				/* XXX freelist_wait? */
				closure_wait(&c->allocator.freelist_wait, req->cl);
				*waiting = true;
			}
		}
	}

	/*
	 * Retry allocating buckets, with the watermark for this
	 * particular write:
	 */
	try(new_stripe_alloc_buckets(trans, req, h, s));
	try(ec_stripe_buf_init(c, &s->new_stripe, 0, h->blocksize));

	if (!s->res.sectors)
		bch2_disk_reservation_get(c, &s->res,
					  h->blocksize,
					  s->nr_parity,
					  BCH_DISK_RESERVATION_NOFAIL);

	stripe_new_buckets_add(c, s);
	s->allocated = true;
	return 0;
}

struct ec_stripe_head *bch2_ec_stripe_head_get(struct btree_trans *trans,
					       struct alloc_request *req,
					       unsigned algo)
{
	struct bch_fs *c = trans->c;
	unsigned redundancy = req->ec_replicas - 1;
	unsigned disk_label = 0;
	struct target t = target_decode(req->target);
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
	if (!s->allocated) {
		bool waiting = false;
		ret = stripe_alloc_or_reuse(trans, req, h, s, &waiting);
		if (waiting &&
		    !bch2_err_matches(ret, BCH_ERR_operation_blocked))
			closure_wake_up(&c->allocator.freelist_wait);

		if (ret)
			goto err;
	}
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
				  unsigned flags, struct printbuf *err)
{
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_i_stripe *s =
		errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, stripe));

	struct disk_accounting_pos acc;

	s64 sectors = 0;
	for (unsigned i = 0; i < s->v.nr_blocks; i++)
		sectors -= stripe_blockcount_get(&s->v, i);

	memset(&acc, 0, sizeof(acc));
	acc.type = BCH_DISK_ACCOUNTING_replicas;
	bch2_bkey_to_replicas(c, &acc.replicas, bkey_i_to_s_c(&s->k_i));
	acc.replicas.data_type = BCH_DATA_user;
	try(bch2_disk_accounting_mod(trans, &acc, &sectors, 1, false));

	struct bkey_ptrs ptrs = bch2_bkey_ptrs(bkey_i_to_s(&s->k_i));

	/* XXX: how much redundancy do we still have? check degraded flags */

	unsigned nr_good = 0;

	scoped_guard(rcu)
		bkey_for_each_ptr(ptrs, ptr) {
			if (ptr->dev == dev_idx)
				ptr->dev = BCH_SB_MEMBER_INVALID;

			struct bch_dev *ca = bch2_dev_rcu(c, ptr->dev);
			nr_good += ca && ca->mi.state != BCH_MEMBER_STATE_evacuating;
		}

	if (nr_good < s->v.nr_blocks && !(flags & BCH_FORCE_IF_DATA_DEGRADED)) {
		prt_str(err, "cannot drop device without degrading\n  ");
		bch2_bkey_val_to_text(err, c, k);
		prt_newline(err);
		return bch_err_throw(c, remove_would_lose_data);
	}

	unsigned nr_data = s->v.nr_blocks - s->v.nr_redundant;

	if (nr_good < nr_data && !(flags & BCH_FORCE_IF_DATA_LOST)) {
		prt_str(err, "cannot drop device without losing data\n  ");
		bch2_bkey_val_to_text(err, c, k);
		prt_newline(err);
		return bch_err_throw(c, remove_would_lose_data);
	}

	sectors = -sectors;

	memset(&acc, 0, sizeof(acc));
	acc.type = BCH_DISK_ACCOUNTING_replicas;
	bch2_bkey_to_replicas(c, &acc.replicas, bkey_i_to_s_c(&s->k_i));
	acc.replicas.data_type = BCH_DATA_user;
	return bch2_disk_accounting_mod(trans, &acc, &sectors, 1, false);
}

static int bch2_invalidate_stripe_to_dev_from_alloc(struct btree_trans *trans,
						    unsigned dev_idx, u64 stripe_idx,
						    unsigned flags, struct printbuf *err)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, stripe_idx), 0);
	struct bkey_s_c_stripe s = bkey_try(bch2_bkey_get_typed(&iter, stripe));

	return bch2_invalidate_stripe_to_dev(trans, &iter, s.s_c, dev_idx, flags, err);
}

int bch2_dev_remove_stripes(struct bch_fs *c, unsigned dev_idx,
			    unsigned flags, struct printbuf *err)
{
	CLASS(btree_trans, trans)(c);
	int ret = for_each_btree_key_max_commit(trans, iter,
				  BTREE_ID_bucket_to_stripe,
				  POS(bucket_to_u64(POS(dev_idx, 0)), 0),
				  POS(bucket_to_u64(POS(dev_idx, U64_MAX)), U64_MAX),
				  BTREE_ITER_intent, k,
				  NULL, NULL, 0, ({
		bch2_invalidate_stripe_to_dev_from_alloc(trans, dev_idx, k.k->p.offset, flags, err);
	}));
	bch_err_fn(c, ret);
	return ret;
}

/* startup/shutdown */

static bool should_cancel_stripe(struct bch_fs *c, struct ec_stripe_new *s, struct bch_dev *ca)
{
	if (!ca)
		return true;

	for (unsigned i = 0; i < bkey_i_to_stripe(&s->new_stripe.key)->v.nr_blocks; i++) {
		if (!s->blocks[i])
			continue;

		struct open_bucket *ob = c->allocator.open_buckets + s->blocks[i];
		if (ob->dev == ca->dev_idx)
			return true;
	}

	return false;
}

static void __bch2_ec_stop(struct bch_fs *c, struct bch_dev *ca)
{
	struct ec_stripe_head *h;

	guard(mutex)(&c->ec.stripe_head_lock);
	list_for_each_entry(h, &c->ec.stripe_head_list, list) {
		guard(mutex)(&h->lock);
		if (h->s && should_cancel_stripe(c, h->s, ca))
			ec_stripe_new_cancel(c, h, -BCH_ERR_erofs_no_writes);
	}
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

	guard(mutex)(&c->ec.stripe_new_lock);
	return list_empty(&c->ec.stripe_new_list);
}

void bch2_fs_ec_flush(struct bch_fs *c)
{
	wait_event(c->ec.stripe_new_wait, bch2_fs_ec_flush_done(c));
}

int bch2_stripes_read(struct bch_fs *c)
{
	return 0;
}

static void bch2_new_stripe_to_text(struct printbuf *out, struct bch_fs *c,
				    struct ec_stripe_new *s)
{
	prt_printf(out, "\tidx %llu blocks %u+%u allocated %u ref %u %u %s obs",
		   s->new_stripe.key.k.p.offset, s->nr_data, s->nr_parity,
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

	scoped_guard(mutex, &c->ec.stripe_head_lock)
		list_for_each_entry(h, &c->ec.stripe_head_list, list) {
			prt_printf(out, "disk label %u algo %u redundancy %u %s nr created %llu:\n",
			       h->disk_label, h->algo, h->redundancy,
			       bch2_watermarks[h->watermark],
			       h->nr_created);

			if (h->s)
				bch2_new_stripe_to_text(out, c, h->s);
		}

	prt_printf(out, "in flight:\n");

	scoped_guard(mutex, &c->ec.stripe_new_lock)
		list_for_each_entry(s, &c->ec.stripe_new_list, list)
			bch2_new_stripe_to_text(out, c, s);
}

void bch2_fs_ec_exit(struct bch_fs *c)
{

	while (1) {
		struct ec_stripe_head *h;

		scoped_guard(mutex, &c->ec.stripe_head_lock)
			h = list_pop_entry(&c->ec.stripe_head_list, struct ec_stripe_head, list);

		if (!h)
			break;

		if (h->s) {
			for (unsigned i = 0;
			     i < bkey_i_to_stripe(&h->s->new_stripe.key)->v.nr_blocks;
			     i++)
				BUG_ON(h->s->blocks[i]);

			kfree(h->s);
		}
		kfree(h);
	}

	BUG_ON(!list_empty(&c->ec.stripe_new_list));

	bioset_exit(&c->ec.block_bioset);
}

void bch2_fs_ec_init_early(struct bch_fs *c)
{
	spin_lock_init(&c->ec.stripes_new_lock);

	INIT_LIST_HEAD(&c->ec.stripe_head_list);
	mutex_init(&c->ec.stripe_head_lock);

	INIT_LIST_HEAD(&c->ec.stripe_new_list);
	mutex_init(&c->ec.stripe_new_lock);
	init_waitqueue_head(&c->ec.stripe_new_wait);

	INIT_WORK(&c->ec.stripe_create_work, ec_stripe_create_work);
	INIT_WORK(&c->ec.stripe_delete_work, ec_stripe_delete_work);
}

int bch2_fs_ec_init(struct bch_fs *c)
{
	return bioset_init(&c->ec.block_bioset, 1, offsetof(struct ec_bio, bio),
			   BIOSET_NEED_BVECS);
}

static int bucket_stripe_ref_mod(struct btree_trans *trans,
				 struct bpos bucket, u64 stripe, bool set)
{
	struct bkey_i_alloc_v4 *a = errptr_try(bch2_trans_start_alloc_update(trans, bucket, 0));
	a->v.stripe_refcount += set ? 1 : -1;

	try(bch2_btree_bit_mod(trans, BTREE_ID_bucket_to_stripe, POS(bucket_to_u64(bucket), stripe), set));

	return 0;
}

static int check_stripe_refs_one(struct btree_trans *trans,
				 struct bkey_s_c k,
				 struct wb_maybe_flush *last_flushed)
{
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bch_fs *c = trans->c;
	const struct bch_stripe *s = bkey_s_c_to_stripe(k).v;
	int ret = 0;

	u64 lru_idx = stripe_lru_pos(s);
	if (lru_idx)
		try(bch2_lru_check_set(trans, BCH_LRU_STRIPE_FRAGMENTATION,
				       k.k->p.offset, lru_idx, k, last_flushed));

	for (unsigned i = 0; i < s->nr_blocks; i++) {
		const struct bch_extent_ptr *ptr = s->ptrs + i;
		CLASS(bch2_dev_tryget_noerror, ca)(c, ptr->dev);
		if (!ca)
			continue;

		struct bpos bucket = PTR_BUCKET_POS(ca, ptr);

		CLASS(btree_iter, iter)(trans, BTREE_ID_bucket_to_stripe,
					POS(bucket_to_u64(bucket), k.k->p.offset), 0);
		struct bkey_s_c ref = bkey_try(bch2_btree_iter_peek_slot(&iter));

		CLASS(printbuf, buf)();

		if (fsck_err_on(ref.k->type != KEY_TYPE_set,
				trans, stripe_to_missing_bucket_ref,
				"stripe block %u missing bucket ref\n%s",
				i, (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			try(bucket_stripe_ref_mod(trans, bucket, k.k->p.offset, true));
	}
fsck_err:
	return ret;
}

static bool bucket_matches_stripe(struct bch_fs *c, struct bpos bucket, const struct bch_stripe *s)
{
	for (unsigned i = 0; i < s->nr_blocks; i++) {
		const struct bch_extent_ptr *ptr = s->ptrs + i;
		CLASS(bch2_dev_tryget_noerror, ca)(c, ptr->dev);

		if (ca && bpos_eq(bucket, PTR_BUCKET_POS(ca, ptr)))
			return true;
	}

	return false;
}

static int check_bucket_to_stripe_ref(struct btree_trans *trans, struct bpos ref)
{
	struct bpos bucket = u64_to_bucket(ref.inode);
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, ref.offset), 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));
	int ret = 0;

	if (fsck_err_on(k.k->type != KEY_TYPE_stripe,
			trans, bucket_stripe_ref_to_missing_stripe,
			"bucket %llu:%llu points to missing stripe %llu",
			bucket.inode, bucket.offset, ref.offset))
		return bucket_stripe_ref_mod(trans, bucket, ref.offset, false);

	if (fsck_err_on(!bucket_matches_stripe(trans->c, bucket, bkey_s_c_to_stripe(k).v),
			trans, bucket_stripe_ref_to_incorrect_stripe,
			"bucket %llu:%llu doesn't match stripe %llu",
			bucket.inode, bucket.offset, ref.offset))
		return bucket_stripe_ref_mod(trans, bucket, ref.offset, false);
fsck_err:
	return ret;
}

int bch2_bucket_nr_stripes(struct btree_trans *trans, struct bpos bucket)
{
	struct bkey_s_c k;
	unsigned nr = 0;
	int ret = 0;

	for_each_btree_key_max_norestart(trans, iter,
				  BTREE_ID_bucket_to_stripe,
				  POS(bucket_to_u64(bucket), 0),
				  POS(bucket_to_u64(bucket), U64_MAX),
				  0, k, ret)
		nr++;

	return ret ?: nr;
}

int bch2_check_stripe_refs(struct btree_trans *trans)
{
	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	try(for_each_btree_key_commit(trans, iter, BTREE_ID_stripes,
				POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		check_stripe_refs_one(trans, k, &last_flushed)));

	try(for_each_btree_key_commit(trans, iter, BTREE_ID_bucket_to_stripe,
				POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		check_bucket_to_stripe_ref(trans, k.k->p)));

	return 0;
}
