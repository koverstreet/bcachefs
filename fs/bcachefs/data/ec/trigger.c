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
#include "data/ec/create.h"
#include "data/ec/init.h"
#include "data/ec/trigger.h"
#include "data/read.h"
#include "data/write.h"
#include "data/keylist.h"
#include "data/reconcile/trigger.h"

#include "init/error.h"
#include "init/passes.h"
#include "init/recovery.h"

#include "sb/counters.h"
#include "sb/io.h"

#include "util/enumerated_ref.h"
#include "util/util.h"

#include <linux/sort.h>

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

	if (s.needs_reconcile)
		prt_str(out, " needs_reconcile");

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

static int mark_stripe_bp(struct btree_trans *trans, struct bkey_s_c k,
			  const struct bch_extent_ptr *ptr, bool insert)
{
	if (ptr->dev == BCH_SB_MEMBER_INVALID)
		return 0;

	struct extent_ptr_decoded p = {
		.ptr = *ptr,
		.crc = bch2_extent_crc_unpack(k.k, NULL),
	};
	struct bkey_i_backpointer bp;
	bch2_extent_ptr_to_bp(trans->c, BTREE_ID_stripes, 0, k, p, (const union bch_extent_entry *) ptr, &bp);

	try(bch2_bucket_backpointer_mod(trans, k, &bp, insert));
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

	CLASS(bch2_dev_bkey_tryget, ca)(c, s.s_c, ptr->dev);
	if (unlikely(!ca)) {
		if (ptr->dev != BCH_SB_MEMBER_INVALID && !(flags & BTREE_TRIGGER_overwrite))
			return bch_err_throw(c, mark_stripe);
		return 0;
	}

	struct bpos bucket = PTR_BUCKET_POS(ca, ptr);

	if (flags & BTREE_TRIGGER_transactional) {
		struct bkey_i_alloc_v4 *a =
			errptr_try(bch2_trans_start_alloc_update(trans, bucket, 0));
		try(__mark_stripe_bucket(trans, ca, s, ptr_idx, deleting, bucket, &a->v, flags));
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

	unsigned nr_blocks = max(old_s ? old_s->nr_blocks : 0,
				 new_s ? new_s->nr_blocks : 0);

	for (unsigned i = 0; i < nr_blocks; i++) {
		const struct bch_extent_ptr *old_ptr = old_s && i < old_s->nr_blocks ? old_s->ptrs + i : NULL;
		const struct bch_extent_ptr *new_ptr = new_s && i < new_s->nr_blocks ? new_s->ptrs + i : NULL;

		bool ptr_changing = !old_ptr || !new_ptr || memcmp(old_ptr, new_ptr, sizeof(*old_ptr));

		if (ptr_changing) {
			if (new_ptr)
				try(mark_stripe_bucket(trans, bkey_s_c_to_stripe(new), i, false, flags));

			if (old_ptr)
				try(mark_stripe_bucket(trans, bkey_s_c_to_stripe(old), i, true, flags));
		}

		if ((ptr_changing ||
		     new_s->needs_reconcile != old_s->needs_reconcile) &&
		    (flags & BTREE_TRIGGER_transactional)) {
			if (old_ptr)
				try(mark_stripe_bp(trans, old, old_ptr, false));

			if (new_ptr)
				try(mark_stripe_bp(trans, new, new_ptr, true));
		}
	}

	return 0;
}

static int stripe_needs_reconcile(const struct bch_stripe *s)
{
	return s ? s->needs_reconcile : 0;
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
	       (new_s->sectors		!= old_s->sectors ||
		new_s->nr_blocks	!= old_s->nr_blocks ||
		new_s->nr_redundant	!= old_s->nr_redundant));

	int needs_reconcile_delta =
		stripe_needs_reconcile(new_s) -
		stripe_needs_reconcile(old_s);

	if ((flags & (BTREE_TRIGGER_atomic|BTREE_TRIGGER_gc)) == BTREE_TRIGGER_atomic) {
		if (new_s && stripe_lru_pos(new_s) == 1)
			bch2_do_stripe_deletes(c);
	}

	if (flags & BTREE_TRIGGER_transactional) {
		u64 old_lru_pos = stripe_lru_pos(old_s);
		u64 new_lru_pos = stripe_lru_pos(new_s);

		if (unlikely(new_lru_pos == STRIPE_LRU_POS_EMPTY) &&
		    !bch2_stripe_is_open(c, idx)) {
			_new.k->type = KEY_TYPE_deleted;
			set_bkey_val_u64s(_new.k, 0);
			new_s = NULL;
			new_lru_pos = 0;
			needs_reconcile_delta =
				stripe_needs_reconcile(new_s) -
				stripe_needs_reconcile(old_s);
		}

		try(bch2_lru_change(trans,
				    BCH_LRU_STRIPE_FRAGMENTATION, idx,
				    old_lru_pos, new_lru_pos));

		if (needs_reconcile_delta)
			try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_reconcile_hipri,
					data_to_rb_work_pos(BTREE_ID_stripes, new.k->p),
					needs_reconcile_delta > 0));
	}

	if (flags & (BTREE_TRIGGER_transactional|BTREE_TRIGGER_gc)) {
		if (needs_reconcile_delta) {
			const struct bch_stripe *s = old_s ?: new_s;

			u64 v[2] = { s->nr_blocks * le16_to_cpu(s->sectors), 0 };
			v[0] *= needs_reconcile_delta;

			try(bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc, v,
						      reconcile_work, BCH_RECONCILE_ACCOUNTING_stripes));
		}

		/*
		 * If the pointers aren't changing, we don't need to do anything:
		 */
		if (new_s && old_s &&
		    new_s->needs_reconcile == old_s->needs_reconcile &&
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

int bch2_ec_stripe_mem_alloc(struct btree_trans *trans, struct btree_iter *iter)
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

void bch2_stripe_new_buckets_add(struct bch_fs *c, struct ec_stripe_new *s)
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

void bch2_stripe_new_buckets_del(struct bch_fs *c, struct ec_stripe_new *s)
{
	guard(spinlock)(&c->ec.stripes_new_lock);

	for (unsigned i = 0; i < s->new_stripe.key.v.nr_blocks; i++)
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

bool bch2_stripe_is_open(struct bch_fs *c, u64 idx)
{
	guard(spinlock)(&c->ec.stripes_new_lock);
	return bch2_open_stripe_find(c, idx) != NULL;
}

bool bch2_stripe_handle_tryget(struct bch_fs *c,
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

void bch2_stripe_handle_put(struct bch_fs *c, struct ec_stripe_handle *s)
{
	if (!s->idx)
		return;

	guard(spinlock)(&c->ec.stripes_new_lock);
	BUG_ON(bch2_open_stripe_find(c, s->idx) != s);
	hlist_del_init(&s->hash);

	s->idx = 0;
}
