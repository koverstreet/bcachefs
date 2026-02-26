// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/backpointers.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/locking.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/ec/create.h"
#include "data/ec/io.h"
#include "data/ec/trigger.h"
#include "data/move.h"

#include "fs/logged_ops.h"

#include "init/error.h"

/*
 * dev stripe state
 *
 * block/parity striping, indexed by target:
 */

static struct ec_dev_stripe_state *ec_dev_stripe_state_get(struct btree_trans *trans, unsigned disk_label)
{
	struct bch_fs *c = trans->c;
	int ret = bch2_trans_mutex_lock(trans, &c->ec.dev_stripe_state_lock);
	if (ret)
		return ERR_PTR(ret);

	struct ec_dev_stripe_state *s;
	list_for_each_entry(s, &c->ec.dev_stripe_state_list, list)
		if (s->disk_label == disk_label) {
			int ret = bch2_trans_mutex_lock(trans, &s->lock);
			if (ret)
				s = ERR_PTR(ret);

			mutex_unlock(&c->ec.dev_stripe_state_lock);
			return s;
		}

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		s = ERR_PTR(-ENOMEM);
	} else {
		mutex_init(&s->lock);
		BUG_ON(!mutex_trylock(&s->lock));
		s->disk_label = disk_label;
		list_add(&s->list, &c->ec.dev_stripe_state_list);
	}

	mutex_unlock(&c->ec.dev_stripe_state_lock);
	return s;
}

/* stripe deletion */

static int ec_stripe_delete(struct btree_trans *trans, u64 idx, bool is_open)
{
	struct bch_fs *c = trans->c;
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, idx), BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (!is_open && bch2_stripe_is_open(c, idx))
		return 0;

	/*
	 * We expect write buffer races here
	 * Important: check stripe_is_open with stripe key locked:
	 */
	if (k.k->type != KEY_TYPE_stripe ||
	    stripe_lru_pos(bkey_s_c_to_stripe(k).v) != STRIPE_LRU_POS_EMPTY) {
		CLASS(printbuf, buf)();
		bch2_fs_inconsistent_on(is_open,
					c, "error deleting stripe: got non or nonempty stripe\n%s",
					(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		return 0;
	}

	event_inc_trace(c, stripe_delete, buf,
			bch2_bkey_val_to_text(&buf, c, k));

	return bch2_btree_delete_at(trans, &iter, 0);
}

/*
 * XXX
 * can we kill this and delete stripes from the trigger?
 */
void bch2_ec_stripe_delete_work(struct work_struct *work)
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

/* stripe creation */

static int ec_stripe_key_update(struct btree_trans *trans,
				struct bkey_i_stripe *new)
{
	struct bch_fs *c = trans->c;

	struct bkey_i *new_mut = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(&new->k)));
	bkey_copy(new_mut, &new->k_i);

	struct bch_inode_opts opts;
	bch2_inode_opts_get(c, &opts, false);
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, new_mut,
					  SET_NEEDS_RECONCILE_foreground, 0));

	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, new_mut->k.p, BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	CLASS(printbuf, buf)();
	if (bch2_fs_inconsistent_on(k.k->type,
				    c, "error creating stripe: got existing key\n%s",
				    (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
		return -EINVAL;

	return bch2_trans_update(trans, &iter, new_mut, 0);
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

static int stripe_update_extent(struct btree_trans *trans,
				struct bkey_i_stripe *old_stripe,
				struct bkey_i_stripe *new_stripe,
				struct bch_extent_ptr old_block,
				struct bch_extent_ptr new_block,
				unsigned new_blocknr,
				struct bkey_s_c_backpointer bp,
				struct stripe_update_bucket_stats *stats,
				struct disk_reservation *res,
				struct wb_maybe_flush *last_flushed)
{
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
		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_str(&buf, "backpointer race\n");
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new_stripe->k_i));
		}));
		return 0;
	}

	struct extent_ptr_decoded p;
	if (!bch2_bkey_has_device_decode(c, k, old_block.dev, &p) ||
	    !__bch2_ptr_matches_stripe(&old_block, &p.ptr, le16_to_cpu(old_stripe->v.sectors))) {
		stats->nr_no_match++;
		stats->sectors_no_match += bp.v->bucket_len;

		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_printf(&buf, "block %u: nomatch\n", new_blocknr);
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new_stripe->k_i));
		}));
		return 0;
	}

	if (p.has_ec) {
		if (p.ec.idx == new_stripe->k.p.offset)
			return 0;

		if (old_stripe == new_stripe ||
		    p.ec.idx != old_stripe->k.p.offset) {
			CLASS(printbuf, buf)();
			ret_log_fsck_err(trans, stripe_update_stale_stripe_ptr,
				"dropping stale stripe pointer (idx %llu) while updating extent\n%s",
				(u64) p.ec.idx,
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		}
	}

	if (p.ptr.cached) {
		BUG_ON(p.has_ec);

		stats->nr_cached++;
		stats->sectors_cached += bp.v->bucket_len;
		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_printf(&buf, "block %u: cached pointer\n", new_blocknr);
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new_stripe->k_i));
		}));
		return 0;
	}

	struct bch_extent_stripe_ptr stripe_ptr = (struct bch_extent_stripe_ptr) {
		.type		= 1 << BCH_EXTENT_ENTRY_stripe_ptr,
		.block		= new_blocknr,
		.redundancy	= new_stripe->v.nr_redundant,
		.idx		= new_stripe->k.p.offset,
	};

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, BKEY_EXTENT_U64s_MAX * sizeof(u64)));
	bkey_reassemble(n, k);

	if (p.has_ec)
		bch2_bkey_drop_stripe_ptr(c, bkey_i_to_s(n), p.ec.idx);

	struct bch_extent_ptr *ec_ptr = bch2_bkey_has_device(c, bkey_i_to_s(n), old_block.dev);
	ec_ptr->dev	= new_block.dev;
	ec_ptr->offset	-= old_block.offset;
	ec_ptr->offset	+= new_block.offset;
	ec_ptr->gen	= new_block.gen;

	bch2_bkey_drop_ptrs_noerror(bkey_i_to_s(n), p, entry, p.ptr.dev != new_block.dev);

	ec_ptr = bch2_bkey_has_device(c, bkey_i_to_s(n), new_block.dev);
	__extent_entry_insert(c, n,
			(union bch_extent_entry *) ec_ptr,
			(union bch_extent_entry *) &stripe_ptr);

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, bkey_i_to_s_c(n), &opts));
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, n, SET_NEEDS_RECONCILE_other, 0));
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

static int stripe_update_bucket(struct btree_trans *trans,
				struct bkey_i_stripe *old_stripe,
				struct bkey_i_stripe *new_stripe,
				unsigned old_blocknr,
				unsigned new_blocknr)
{
	struct bch_fs *c = trans->c;

	struct bch_extent_ptr old_block = old_stripe->v.ptrs[old_blocknr];
	struct bch_extent_ptr new_block = new_stripe->v.ptrs[new_blocknr];

	CLASS(bch2_dev_bkey_tryget, ca)(c, bkey_i_to_s_c(&old_stripe->k_i), old_block.dev);
	enum btree_id btree;
	struct bpos start, end;
	if (ca) {
		struct bpos bucket_pos = PTR_BUCKET_POS(ca, &old_block);

		btree	= BTREE_ID_backpointers;
		start	= bucket_pos_to_bp_start(ca, bucket_pos);
		end	= bucket_pos_to_bp_end(ca, bucket_pos);
	} else {
		u64 idx = old_stripe->k.p.offset;
		btree	= BTREE_ID_stripe_backpointers;
		start	= POS((idx << 8) | old_blocknr, 0);
		end	= POS((idx << 8) | old_blocknr, U64_MAX);
	}

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct stripe_update_bucket_stats stats = {};

	CLASS(disk_reservation, res)(c);

	try(for_each_btree_key_max(trans, bp_iter, btree, start, end, 0, bp_k, ({
		if (bp_k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(bp_k);
		if (bp.v->btree_id == BTREE_ID_stripes)
			continue;

		wb_maybe_flush_inc(&last_flushed);
		stripe_update_extent(trans, old_stripe, new_stripe,
				     old_block, new_block, new_blocknr,
				     bp, &stats, &res.r, &last_flushed);
	})));

	event_inc_trace(c, stripe_update_bucket, buf, ({
		prt_printf(&buf, "Updating block %u\n", new_blocknr);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new_stripe->k_i));
		prt_newline(&buf);

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

static int __stripe_update_extents(struct btree_trans *trans,
				   struct bkey_i_stripe *old_stripe,
				   struct bkey_i_stripe *new_stripe,
				   const u8 *old_block_map,
				   unsigned old_blocks_nr)
{
	unsigned nr_data = new_stripe->v.nr_blocks - new_stripe->v.nr_redundant;

	try(bch2_btree_write_buffer_flush_sync(trans));

	for (unsigned i = 0; i < nr_data; i++) {
		unsigned old_blocknr = i < old_blocks_nr
			? old_block_map[i] : i;
		struct bkey_i_stripe *old = i < old_blocks_nr
			? old_stripe : new_stripe;

		try(stripe_update_bucket(trans, old, new_stripe, old_blocknr, i));
	}

	return 0;
}

static int stripe_update_extents(struct bch_fs *c, struct ec_stripe_new *s)
{
	CLASS(btree_trans, trans)(c);

	return __stripe_update_extents(trans,
				       &s->old_stripe.key,
				       &s->new_stripe.key,
				       s->old_block_map,
				       s->old_blocks_nr);
}

void bch2_logged_op_stripe_update_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_logged_op_stripe_update op = bkey_s_c_to_logged_op_stripe_update(k);

	prt_printf(out, "old_idx=%llu", le64_to_cpu(op.v->old_idx));
	prt_printf(out, " new_idx=%llu", le64_to_cpu(op.v->new_idx));
	prt_printf(out, " old_blocks_nr=%u", op.v->old_blocks_nr);
}

int bch2_resume_logged_op_stripe_update(struct btree_trans *trans, struct bkey_i *op_k)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_logged_op_stripe_update *op = bkey_i_to_logged_op_stripe_update(op_k);
	u64 old_idx = le64_to_cpu(op->v.old_idx);
	u64 new_idx = le64_to_cpu(op->v.new_idx);

	struct bkey_buf new_sk __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&new_sk);

	struct bkey_buf old_sk __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&old_sk);

	/* Read new stripe */
	CLASS(btree_iter, new_iter)(trans, BTREE_ID_stripes, POS(0, new_idx), 0);
	struct bkey_s_c new_k = bkey_try(bch2_btree_iter_peek_slot(&new_iter));

	if (new_k.k->type != KEY_TYPE_stripe) {
		bch_err(c, "logged op stripe update: new stripe %llu missing", new_idx);
		return 0;
	}

	bch2_bkey_buf_reassemble(&new_sk, new_k);

	/* Read old stripe (may be same as new, or may be gone) */
	if (old_idx && old_idx != new_idx) {
		CLASS(btree_iter, old_iter)(trans, BTREE_ID_stripes, POS(0, old_idx), 0);
		struct bkey_s_c old_k = bkey_try(bch2_btree_iter_peek_slot(&old_iter));

		if (old_k.k->type == KEY_TYPE_stripe)
			bch2_bkey_buf_reassemble(&old_sk, old_k);
		else
			bch2_bkey_buf_reassemble(&old_sk, new_k);
	} else {
		bch2_bkey_buf_reassemble(&old_sk, new_k);
	}

	return __stripe_update_extents(trans,
				       bkey_i_to_stripe(old_sk.k),
				       bkey_i_to_stripe(new_sk.k),
				       op->v.old_block_map,
				       op->v.old_blocks_nr);
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
	bch2_stripe_new_buckets_del(c, s);
	bch2_stripe_handle_put(c, &s->new_stripe_handle);
	bch2_stripe_handle_put(c, &s->old_stripe_handle);
	kfree(s);
}

static int __ec_stripe_create(struct ec_stripe_new *s)
{
	struct bch_fs *c = s->c;
	struct bch_stripe *v = &s->new_stripe.key.v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	if (s->err) {
		if (!bch2_err_matches(s->err, EROFS))
			bch_err(c, "error creating stripe: error writing data buckets");
		return s->err;
	}

	for (unsigned i = s->old_blocks_nr; i < nr_data; i++) {
		struct open_bucket *ob = c->allocator.open_buckets + s->blocks[i];

		if (ob->sectors_free) {
			/* XXX: do this IO asynchronously */
			zero_out_rest_of_ec_bucket(c, s, i, ob);
		}
	}

	if (s->have_old_stripe) {
		/* XXX: we might end up blocking here on reading the old stripe,
		 * do we need to make this async? */

		try(bch2_stripe_buf_validate(c, &s->old_stripe, true));

		for (unsigned i = 0; i < s->old_blocks_nr; i++)
			swap(s->new_stripe.data[i],
			     s->old_stripe.data[s->old_block_map[i]]);

		bch2_ec_stripe_buf_exit(&s->old_stripe);
	}

	BUG_ON(!s->allocated);

	bch2_ec_generate_ec(&s->new_stripe);
	bch2_ec_generate_checksums(&s->new_stripe);

	/* write out data blocks that moved */
	for (unsigned i = 0; i < s->old_blocks_nr; i++)
		if (test_bit(i, s->blocks_moving))
			bch2_ec_block_io(c, &s->new_stripe, REQ_OP_WRITE, i);

	/* write p/q: */
	for (unsigned i = nr_data; i < v->nr_blocks; i++)
		bch2_ec_block_io(c, &s->new_stripe, REQ_OP_WRITE, i);
	closure_sync(&s->new_stripe.io);

	if (ec_nr_failed(&s->new_stripe)) {
		bch_err(c, "error creating stripe: error writing redundancy buckets");
		return bch_err_throw(c, ec_block_write);
	}

	struct bkey_i_logged_op_stripe_update op;
	bkey_logged_op_stripe_update_init(&op.k_i);
	op.v.old_idx		= cpu_to_le64(s->have_old_stripe
					? s->old_stripe.key.k.p.offset : 0);
	op.v.new_idx		= cpu_to_le64(s->new_stripe.key.k.p.offset);
	op.v.old_blocks_nr	= s->old_blocks_nr;
	memcpy(op.v.old_block_map, s->old_block_map, sizeof(op.v.old_block_map));

	try(bch2_trans_commit_do(c, &s->res, NULL,
				 BCH_TRANS_COMMIT_no_check_rw|
				 BCH_TRANS_COMMIT_no_enospc,
		ec_stripe_key_update(trans, &s->new_stripe.key) ?:
		__bch2_logged_op_start(trans, &op.k_i)));

	int ret = stripe_update_extents(c, s);

	{
		CLASS(btree_trans, trans)(c);
		ret = bch2_logged_op_finish(trans, &op.k_i) ?: ret;
	}

	return ret;
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
	struct bch_stripe *v = &s->new_stripe.key.v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	int ret = stripe_get_iorefs(c, v);
	if (!ret) {
		ret = __ec_stripe_create(s);
		stripe_put_iorefs(c, v);
	}
	if (ret && !s->err)
		s->err = ret;

	if (ret)
		event_inc_trace(c, stripe_create_fail, buf, ({
			prt_printf(&buf, "error %s\n", bch2_err_str(ret));
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key.k_i));
		}));
	else if (s->have_old_stripe)
		event_inc_trace(c, stripe_reuse, buf, ({
			struct bch_stripe *ov = &s->old_stripe.key.v;

			prt_printf(&buf, "Reused %u/%u data blocks\n", s->old_blocks_nr,
				   ov->nr_blocks - ov->nr_redundant);
			prt_printf(&buf, "\nOld: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key.k_i));
			prt_printf(&buf, "\nNew: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->old_stripe.key.k_i));
		}));
	else
		event_inc_trace(c, stripe_create, buf, ({
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key.k_i));
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

	bch2_ec_stripe_buf_exit(&s->old_stripe);
	bch2_ec_stripe_buf_exit(&s->new_stripe);

	if (s->ctxt) {
		unsigned stripe_sectors = le16_to_cpu(v->sectors) * v->nr_blocks;
		atomic_sub(stripe_sectors, &s->ctxt->write_sectors);
		atomic_dec(&s->ctxt->write_ios);
		wake_up(&s->ctxt->wait);
		closure_put(&s->ctxt->cl);
	}

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

void bch2_ec_stripe_create_work(struct work_struct *work)
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

/* returns blocksize */
static unsigned disk_label_ec_devs(struct bch_fs *c, unsigned disk_label,
				   struct bch_devs_mask *devs,
				   unsigned blocksize)
{
	guard(rcu)();

	*devs = target_rw_devs(c, BCH_DATA_user, disk_label
			       ? group_to_target(disk_label - 1)
			       : 0);
	for_each_member_device_rcu(c, ca, devs)
		if (!ca->mi.durability)
			__clear_bit(ca->dev_idx, devs->d);

	if (!blocksize)
		blocksize = pick_blocksize(c, devs);

	for_each_member_device_rcu(c, ca, devs)
		if (ca->mi.bucket_size != blocksize)
			__clear_bit(ca->dev_idx, devs->d);
	return blocksize;
}

static void ec_stripe_key_init(struct bch_fs *c,
			       struct bkey_i *k,
			       unsigned algorithm,
			       unsigned nr_data,
			       unsigned nr_parity,
			       unsigned stripe_size,
			       unsigned disk_label)
{
	struct bkey_i_stripe *s = bkey_stripe_init(k);
	unsigned u64s;

	s->v.sectors			= cpu_to_le16(stripe_size);
	s->v.algorithm			= algorithm;
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

static struct ec_stripe_new *ec_new_stripe_alloc(struct bch_fs *c,
						 struct bch_devs_mask devs,
						 enum bch_watermark watermark,
						 unsigned disk_label,
						 unsigned algorithm,
						 unsigned nr_data, unsigned nr_parity,
						 unsigned blocksize)
{
	struct ec_stripe_new *s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;

	mutex_init(&s->lock);
	closure_init(&s->old_stripe.io, NULL);
	closure_init(&s->new_stripe.io, NULL);
	atomic_set(&s->ref[STRIPE_REF_stripe], 1);
	atomic_set(&s->ref[STRIPE_REF_io], 1);
	s->c		= c;
	s->devs		= devs;
	s->watermark	= watermark;
	s->nr_data	= nr_data;
	s->nr_parity	= nr_parity,

	ec_stripe_key_init(c, &s->new_stripe.key.k_i,
			   algorithm,
			   s->nr_data, s->nr_parity,
			   blocksize, disk_label);
	return s;
}

static int __new_stripe_alloc_buckets(struct btree_trans *trans,
				    struct alloc_request *req,
				    struct ec_dev_stripe_state *dev_stripe,
				    struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;
	struct open_bucket *ob;
	struct bch_stripe *v = &s->new_stripe.key.v;
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

		int ret = bch2_bucket_alloc_set_trans(trans, req, &dev_stripe->parity_stripe);

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

		int ret = bch2_bucket_alloc_set_trans(trans, req, &dev_stripe->block_stripe);

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
				    struct ec_dev_stripe_state *dev_stripe,
				    struct ec_stripe_new *s)
{
	struct bch_stripe *v = &s->new_stripe.key.v;

	if (bitmap_weight(s->blocks_gotten, v->nr_blocks) == v->nr_blocks)
		return 0;

	req->scratch_data_type		= req->data_type;
	req->scratch_ptrs		= req->ptrs;
	req->scratch_nr_replicas	= req->nr_replicas;
	req->scratch_nr_effective	= req->nr_effective;
	req->scratch_have_cache		= req->have_cache;
	req->scratch_devs_may_alloc	= req->devs_may_alloc;

	req->devs_may_alloc	= s->devs;
	req->have_cache		= true;

	int ret = __new_stripe_alloc_buckets(trans, req, dev_stripe, s);

	req->data_type		= req->scratch_data_type;
	req->ptrs		= req->scratch_ptrs;
	req->nr_replicas	= req->scratch_nr_replicas;
	req->nr_effective	= req->scratch_nr_effective;
	req->have_cache		= req->scratch_have_cache;
	req->devs_may_alloc	= req->scratch_devs_may_alloc;
	return ret;
}

static bool may_reuse_stripe(struct bch_fs *c,
			     struct ec_stripe_new *new, const struct bch_stripe *old)
{
	if (old->disk_label		!= new->new_stripe.key.v.disk_label ||
	    old->algorithm		!= new->new_stripe.key.v.algorithm ||
	    old->nr_redundant		!= new->new_stripe.key.v.nr_redundant)
		return false;

	struct bch_devs_mask devs_may_alloc = new->devs;
	unsigned nr_data = old->nr_blocks - old->nr_redundant;

	for (unsigned i = 0; i < nr_data; i++)
		if (!bch2_dev_bad_or_evacuating(c, old->ptrs[i].dev) &&
		    stripe_blockcount_get(old, i))
			__clear_bit(old->ptrs[i].dev, devs_may_alloc.d);

	return dev_mask_nr(&devs_may_alloc) > new->nr_parity;
}

static int get_old_stripe(struct btree_trans *trans,
			  struct ec_stripe_new *new,
			  u64 idx)
{
	struct bch_fs *c = trans->c;

	/*
	 * We require an intent lock here until we have the stripe open, for
	 * exclusion with bch2_trigger_stripe() - which will delete empty
	 * stripes if they're not open, but it can't actually open them:
	 */
	CLASS(btree_iter, iter)(trans, BTREE_ID_stripes, POS(0, idx),
				BTREE_ITER_intent|
				BTREE_ITER_nopreserve);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	/* We expect write buffer races here */
	if (k.k->type != KEY_TYPE_stripe)
		return 0;

	struct bkey_s_c_stripe old = bkey_s_c_to_stripe(k);

	if (stripe_lru_pos(old.v) == STRIPE_LRU_POS_EMPTY) {
		/*
		 * We can't guarantee that the trigger will always delete
		 * stripes - the stripe might still be open when the last data
		 * in it was deleted
		 */
		return !bch2_stripe_is_open(c, idx)
			? bch2_btree_delete_at(trans, &iter, 0) ?:
			  bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc) ?:
			  bch_err_throw(c, transaction_restart_commit)
			: 0;
	}

	bool ret = may_reuse_stripe(c, new, old.v) &&
		bch2_stripe_handle_tryget(c, &new->old_stripe_handle, idx);
	if (ret)
		bkey_reassemble(&new->old_stripe.key.k_i, k);
	return ret;
}

static void init_new_stripe_from_old(struct bch_fs *c, struct ec_stripe_new *s)
{
	struct bch_stripe *new_v = &s->new_stripe.key.v;
	struct bch_stripe *old_v = &s->old_stripe.key.v;
	unsigned i;

	BUG_ON(old_v->nr_redundant != s->nr_parity);

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
			if (!bch2_dev_bad_or_evacuating(c, old_v->ptrs[i].dev))
				__set_bit(s->old_blocks_nr, s->blocks_gotten);
			else
				__set_bit(s->old_blocks_nr, s->blocks_moving);
			__set_bit(s->old_blocks_nr, s->blocks_allocated);

			new_v->ptrs[s->old_blocks_nr] = old_v->ptrs[i];

			s->old_block_map[s->old_blocks_nr++] = i;
		}
	}

	s->have_old_stripe = true;
}

static int stripe_reuse(struct btree_trans *trans, struct ec_stripe_new *s)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c lru_k;
	int ret = 0;

	for_each_btree_key_max_norestart(trans, lru_iter, BTREE_ID_lru,
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, 0),
			lru_pos(BCH_LRU_STRIPE_FRAGMENTATION, 2, LRU_TIME_MAX),
			0, lru_k, ret) {
		ret = get_old_stripe(trans, s, lru_k.k->p.offset);
		if (ret)
			break;
	}
	if (ret <= 0)
		return ret ?: bch_err_throw(c, stripe_alloc_blocked);

	ret = __bch2_ec_stripe_buf_init(c, &s->old_stripe, 0, le16_to_cpu(s->old_stripe.key.v.sectors));
	if (ret)
		bch2_stripe_handle_put(c, &s->old_stripe_handle);

	init_new_stripe_from_old(c, s);
	bch2_stripe_buf_read(c, &s->old_stripe);
	return ret;

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
			ret = bch2_ec_stripe_mem_alloc(trans, &iter);
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
				 struct ec_dev_stripe_state *dev_stripe,
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

		int ret = new_stripe_alloc_buckets(trans, req, dev_stripe, s);

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
				ret = stripe_reuse(trans, s);
				if (!ret)
					break;
				if (*waiting ||
				    (req->flags & BCH_WRITE_alloc_nowait) ||
				    ret != -BCH_ERR_stripe_alloc_blocked)
					return ret;

				if (req->watermark == BCH_WATERMARK_copygc) {
					/* Don't self-deadlock copygc */
					swap(req->flags, saved_flags);
					ret = new_stripe_alloc_buckets(trans, req, dev_stripe, s);
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
	try(new_stripe_alloc_buckets(trans, req, dev_stripe, s));
	try(__bch2_ec_stripe_buf_init(c, &s->new_stripe, 0, le16_to_cpu(s->new_stripe.key.v.sectors)));

	if (!s->res.sectors)
		bch2_disk_reservation_get(c, &s->res,
					  le16_to_cpu(s->new_stripe.key.v.sectors),
					  s->nr_parity,
					  BCH_DISK_RESERVATION_NOFAIL);

	bch2_stripe_new_buckets_add(c, s);
	s->allocated = true;
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
		   bch2_watermarks[s->watermark]);

	struct bch_stripe *v = &s->new_stripe.key.v;
	unsigned i;
	for_each_set_bit(i, s->blocks_gotten, v->nr_blocks)
		prt_printf(out, " %u", s->blocks[i]);
	prt_newline(out);
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&s->new_stripe.key.k_i));
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

/*
 * ec_stripe_head: interface from the sector allocator to erasure coding
 * We have one ec_stripe_head for every combination of replication, target and
 * watermark options, which are used for the staging of stripe creation via
 * struct ec_stripe_new
 */

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

void bch2_ec_stripe_new_cancel(struct bch_fs *c, struct ec_stripe_head *h, int err)
{
	h->s->err = err;
	ec_stripe_new_set_pending(c, h);
}

static void ec_stripe_head_devs_update(struct bch_fs *c, struct ec_stripe_head *h)
{
	struct bch_devs_mask old_devs = h->devs;

	h->blocksize		= disk_label_ec_devs(c, h->disk_label, &h->devs, 0);
	h->nr_active_devs	= dev_mask_nr(&h->devs);

	/*
	 * If we only have redundancy + 1 devices, we're better off with just
	 * replication:
	 */
	h->insufficient_devs = h->nr_active_devs < h->redundancy + 2;

	struct bch_devs_mask devs_leaving;
	bitmap_andnot(devs_leaving.d, old_devs.d, h->devs.d, BCH_SB_MEMBERS_MAX);

	if (h->s && !h->s->allocated && dev_mask_nr(&devs_leaving))
		bch2_ec_stripe_new_cancel(c, h, -EINTR);
}

static struct ec_stripe_head *
ec_new_stripe_head_alloc(struct bch_fs *c, unsigned disk_label,
			 unsigned algo, unsigned redundancy,
			 enum bch_watermark watermark)
{
	struct ec_stripe_head *h = kzalloc(sizeof(*h), GFP_KERNEL);
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

	unsigned long rw_devs_change_count;
found:
	rw_devs_change_count = READ_ONCE(c->allocator.rw_devs_change_count);
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
		h->s = ec_new_stripe_alloc(c,
					   h->devs,
					   h->watermark,
					   h->disk_label,
					   h->algo,
					   min_t(unsigned, h->nr_active_devs,
						 BCH_BKEY_PTRS_MAX) - h->redundancy,
					   h->redundancy,
					   h->blocksize);
		if (!h->s) {
			ret = bch_err_throw(c, ENOMEM_ec_new_stripe_alloc);
			bch_err(c, "failed to allocate new stripe");
			goto err;
		}

		h->nr_created++;
	}

	struct ec_stripe_new *s = h->s;
	if (!s->allocated) {
		if (!h->dev_stripe) {
			struct ec_dev_stripe_state *d = ec_dev_stripe_state_get(trans, h->disk_label);
			ret = PTR_ERR_OR_ZERO(d);
			if (ret)
				goto err;
			h->dev_stripe = d;
		} else {
			ret = bch2_trans_mutex_lock(trans, &h->dev_stripe->lock);
			if (ret)
				goto err;
		}

		bool waiting = false;
		ret = stripe_alloc_or_reuse(trans, req, h->dev_stripe, s, &waiting);
		if (waiting &&
		    !bch2_err_matches(ret, BCH_ERR_operation_blocked))
			closure_wake_up(&c->allocator.freelist_wait);

		mutex_unlock(&h->dev_stripe->lock);

		if (ret)
			goto err;

		event_inc_trace(c, stripe_alloc, buf, ({
			prt_printf(&buf, "\nnew: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key.k_i));
			if (s->have_old_stripe) {
				prt_printf(&buf, "\nold: ");
				bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->old_stripe.key.k_i));
			}
		}));
	}
	BUG_ON(!s->new_stripe.data[0]);
	BUG_ON(trans->restarted);
	return h;
err:
	bch2_ec_stripe_head_put(c, h);
	return ERR_PTR(ret);
}

/* reconcile/resilver: */

static bool stripe_degraded(struct bch_fs *c, const struct bch_stripe *s)
{
	for (unsigned i = 0; i < s->nr_blocks; i++)
		if (bch2_dev_bad_or_evacuating(c, s->ptrs[i].dev))
			return true;
	return false;
}

int bch2_stripe_repair(struct moving_context *ctxt,
		       struct btree_iter *iter, struct bkey_s_c_stripe s)
{
	struct btree_trans *trans = ctxt->trans;
	struct bch_fs *c = trans->c;

	/*
	 * Same as get_old_stripe() -
	 *
	 * We require an intent lock here until we have the stripe open, for
	 * exclusion with bch2_trigger_stripe() - which will delete empty
	 * stripes if they're not open, but it can't actually open them:
	 */
	BUG_ON(!btree_node_intent_locked(btree_iter_path(trans, iter), 0));

	const struct bch_stripe *old_s = s.v;
	if (!stripe_degraded(c, old_s)) {
		/* confused */
		BUG();
	}

	unsigned nr_data = old_s->nr_blocks - old_s->nr_redundant;
	unsigned nr_live_data_blocks = 0;
	for (unsigned i = 0; i < old_s->nr_blocks; i++)
		nr_live_data_blocks += stripe_blockcount_get(old_s, i) != 0;

	if (!nr_live_data_blocks)
		return 0;

	struct bch_devs_mask devs;
	disk_label_ec_devs(c, old_s->disk_label, &devs, le16_to_cpu(old_s->sectors));

	unsigned need_evacuate = max(0,
			(int) (nr_live_data_blocks + old_s->nr_redundant) - (int) dev_mask_nr(&devs));

	if (need_evacuate) {
		unsigned blocks_used[BCH_BKEY_PTRS_MAX], nr = 0;
		memset(blocks_used, 0, sizeof(blocks_used));

		for (unsigned i = 0; i < nr_data; i++)
			if (stripe_blockcount_get(old_s, i))
				blocks_used[nr++] = i;
		BUG_ON(nr < need_evacuate);

		bubble_sort(blocks_used, nr, cmp_int);

		for (unsigned i = 0; i < min(nr, need_evacuate); i++) {
			const struct bch_extent_ptr *ptr = old_s->ptrs + blocks_used[i];

			try(bch2_evacuate_data(ctxt, ptr->dev, ptr->offset, ptr->offset + le16_to_cpu(old_s->sectors)));
		}

		return bch_err_throw(c, stripe_needs_block_evacuate);
	}

	struct ec_stripe_new *new_s = ec_new_stripe_alloc(c, devs, BCH_WATERMARK_normal,
							  old_s->disk_label,
							  old_s->algorithm,
							  nr_live_data_blocks,
							  old_s->nr_redundant,
							  le16_to_cpu(old_s->sectors));
	if (unlikely(!new_s))
		return -ENOMEM;

	if (!bch2_stripe_handle_tryget(c, &new_s->old_stripe_handle, s.k->p.offset)) {
		/* trace this */
		kfree(new_s);
		return 0;
	}

	bkey_reassemble(&new_s->old_stripe.key.k_i, s.s_c);

	init_new_stripe_from_old(c, new_s);

	int ret = __bch2_ec_stripe_buf_init(c, &new_s->old_stripe, 0, le16_to_cpu(new_s->old_stripe.key.v.sectors)) ?:
		  __bch2_ec_stripe_buf_init(c, &new_s->new_stripe, 0, le16_to_cpu(new_s->new_stripe.key.v.sectors)) ?:
		  lockrestart_do(trans, stripe_idx_alloc(trans, new_s));
	if (ret) {
		bch2_stripe_handle_put(c, &new_s->old_stripe_handle);
		bch2_ec_stripe_buf_exit(&new_s->new_stripe);
		bch2_ec_stripe_buf_exit(&new_s->old_stripe);
		return ret;
	}

	unsigned target = old_s->disk_label
		? group_to_target(old_s->disk_label - 1)
		: 0;

	CLASS(closure_stack, cl)();
	while (true) {
		bch2_trans_begin(trans); /* avoid unnecessary restarts from dev_stripe_state_get() */

		struct ec_dev_stripe_state *dev_stripe =
			errptr_try(ec_dev_stripe_state_get(trans, old_s->disk_label));
		struct alloc_request *req;

		ret = lockrestart_do(trans, ({
			req = alloc_request_get(trans, target, false, NULL,
						0, 0, BCH_WATERMARK_normal, 0, &cl);

			PTR_ERR_OR_ZERO(req) ?:
			new_stripe_alloc_buckets(trans, req, dev_stripe, new_s);
		}));
		mutex_unlock(&dev_stripe->lock);

		bch2_trans_unlock_long(trans);

		if (!ret)
			break;

		if (!bch2_err_matches(ret, BCH_ERR_operation_blocked)) {
			CLASS(bch_log_msg, msg)(c);
			prt_str(&msg.m, "\nold: ");
			bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&new_s->old_stripe.key.k_i));;
			prt_str(&msg.m, "\nnew: ");
			bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&new_s->new_stripe.key.k_i));;
			prt_printf(&msg.m, "\nret %s", bch2_err_str(ret));

			bch2_stripe_handle_put(c, &new_s->new_stripe_handle);
			bch2_stripe_handle_put(c, &new_s->old_stripe_handle);
			bch2_ec_stripe_buf_exit(&new_s->new_stripe);
			bch2_ec_stripe_buf_exit(&new_s->old_stripe);
			kfree(new_s);
			return ret;
		}

		bch2_wait_on_allocator(c, req, ret, &cl);
	}

	bch2_stripe_new_buckets_add(c, new_s);
	new_s->allocated = true;
	new_s->pending = true;

	bch2_disk_reservation_get(c, &new_s->res,
				  le16_to_cpu(new_s->new_stripe.key.v.sectors),
				  new_s->nr_parity,
				  BCH_DISK_RESERVATION_NOFAIL);
	bch2_stripe_buf_read(c, &new_s->old_stripe);

	new_s->ctxt = ctxt;
	unsigned stripe_sectors = le16_to_cpu(new_s->new_stripe.key.v.sectors) *
				  new_s->new_stripe.key.v.nr_blocks;
	atomic_add(stripe_sectors, &ctxt->write_sectors);
	atomic_inc(&ctxt->write_ios);
	closure_get(&ctxt->cl);

	/* ec_stripe_new_set_pending */
	scoped_guard(mutex, &c->ec.stripe_new_lock)
		list_add(&new_s->list, &c->ec.stripe_new_list);

	ec_stripe_new_put(c, new_s, STRIPE_REF_io);
	return 0;
}
