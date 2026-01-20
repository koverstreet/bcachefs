// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"
#include "alloc/replicas.h"

#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/ec/create.h"
#include "data/ec/init.h"
#include "data/ec/io.h"
#include "data/ec/trigger.h"
#include "data/reconcile/trigger.h"

#include "init/error.h"

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

	struct bch_inode_opts opts;
	bch2_inode_opts_get(c, &opts, false);
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, &s->k_i,
					  SET_NEEDS_RECONCILE_opt_change, 0));

	s64 sectors = 0;
	for (unsigned i = 0; i < s->v.nr_blocks; i++)
		sectors -= stripe_blockcount_get(&s->v, i);

	struct disk_accounting_pos acc;
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

			struct bch_dev *ca = bch2_dev_rcu_noerror(c, ptr->dev);
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

	for (unsigned i = 0; i < s->new_stripe.key.v.nr_blocks; i++) {
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
			bch2_ec_stripe_new_cancel(c, h, -BCH_ERR_erofs_no_writes);
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
			     i < h->s->new_stripe.key.v.nr_blocks;
			     i++)
				BUG_ON(h->s->blocks[i]);

			kfree(h->s);
		}
		kfree(h);
	}

	while (!list_empty(&c->ec.dev_stripe_state_list)) {
		struct ec_dev_stripe_state *s =
			list_pop_entry(&c->ec.dev_stripe_state_list, struct ec_dev_stripe_state, list);
		kfree(s);
	}

	BUG_ON(!list_empty(&c->ec.stripe_new_list));

	bioset_exit(&c->ec.block_bioset);
}

void bch2_fs_ec_init_early(struct bch_fs *c)
{
	spin_lock_init(&c->ec.stripes_new_lock);

	INIT_LIST_HEAD(&c->ec.stripe_head_list);
	mutex_init(&c->ec.stripe_head_lock);

	INIT_LIST_HEAD(&c->ec.dev_stripe_state_list);
	mutex_init(&c->ec.dev_stripe_state_lock);

	INIT_LIST_HEAD(&c->ec.stripe_new_list);
	mutex_init(&c->ec.stripe_new_lock);
	init_waitqueue_head(&c->ec.stripe_new_wait);

	INIT_WORK(&c->ec.stripe_create_work, bch2_ec_stripe_create_work);
	INIT_WORK(&c->ec.stripe_delete_work, bch2_ec_stripe_delete_work);
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
