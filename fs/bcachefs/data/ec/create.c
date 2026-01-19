// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/backpointers.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/ec/create.h"
#include "data/ec/io.h"
#include "data/ec/trigger.h"

#include "init/error.h"

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

static int stripe_update_extent(struct btree_trans *trans,
				struct ec_stripe_new *s,
				unsigned block,
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
		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_str(&buf, "backpointer race\n");
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}

	struct extent_ptr_decoded p;
	if (!bch2_bkey_has_device_decode(c, k, v->ptrs[block].dev, &p) ||
	    !__bch2_ptr_matches_stripe(&v->ptrs[block], &p.ptr, le16_to_cpu(v->sectors))) {
		stats->nr_no_match++;
		stats->sectors_no_match += bp.v->bucket_len;

		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_printf(&buf, "block %u: nomatch\n", block);
			bch2_bkey_val_to_text(&buf, c, bp.s_c);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}

	if (p.has_ec) {
		if (p.ec.idx == s->new_stripe.key.k.p.offset)
			return 0;

		if (!s->have_old_stripe ||
		    p.ec.idx != s->old_stripe.key.k.p.offset) {
			CLASS(printbuf, buf)();
			prt_printf(&buf, "Found unrelated stripe pointer when updating extent\n");
			bch2_bkey_val_to_text(&buf, c, k);
			prt_str(&buf, "\nNew: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));

			if (s->have_old_stripe) {
				prt_str(&buf, "\nOld: ");
				bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->old_stripe.key));
			}

			bch2_fs_inconsistent(c, "%s", buf.buf);
			return bch_err_throw(c, erasure_coding_stripe_update_err);
		}
	}

	if (p.ptr.cached) {
		BUG_ON(p.has_ec);

		stats->nr_cached++;
		stats->sectors_cached += bp.v->bucket_len;
		event_inc_trace(c, stripe_update_extent_fail, buf, ({
			prt_printf(&buf, "block %u: cached pointer\n", block);
			bch2_bkey_val_to_text(&buf, c, k);
			prt_newline(&buf);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
		return 0;
	}

	unsigned dev = v->ptrs[block].dev;

	struct bch_extent_stripe_ptr stripe_ptr = (struct bch_extent_stripe_ptr) {
		.type		= 1 << BCH_EXTENT_ENTRY_stripe_ptr,
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

static int stripe_update_bucket(struct btree_trans *trans, struct ec_stripe_new *s, unsigned block)
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
		stripe_update_extent(trans, s, block, bp, &stats, &res.r, &last_flushed);
	})));

	event_inc_trace(c, stripe_update_bucket, buf, ({
		prt_printf(&buf, "Updating block %u\n", block);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
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

static int stripe_update_extents(struct bch_fs *c, struct ec_stripe_new *s)
{
	CLASS(btree_trans, trans)(c);
	struct bch_stripe *v = &bkey_i_to_stripe(&s->new_stripe.key)->v;
	unsigned nr_data = v->nr_blocks - v->nr_redundant;

	try(bch2_btree_write_buffer_flush_sync(trans));

	for (unsigned i = 0; i < nr_data; i++)
		try(stripe_update_bucket(trans, s, i));

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
	bch2_stripe_new_buckets_del(c, s);
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
		bch2_ec_validate_checksums(c, &s->old_stripe);

		if (bch2_ec_do_recov(c, &s->old_stripe)) {
			bch_err(c, "error creating stripe: error reading old stripe");
			return bch_err_throw(c, ec_block_read);
		}

		for (unsigned i = 0; i < s->old_blocks_nr; i++)
			swap(s->new_stripe.data[i],
			     s->old_stripe.data[s->old_block_map[i]]);

		bch2_ec_stripe_buf_exit(&s->old_stripe);
	}

	BUG_ON(!s->allocated);

	bch2_ec_generate_ec(&s->new_stripe);
	bch2_ec_generate_checksums(&s->new_stripe);

	/* write p/q: */
	for (unsigned i = nr_data; i < v->nr_blocks; i++)
		bch2_ec_block_io(c, &s->new_stripe, REQ_OP_WRITE, i, &s->iodone);
	closure_sync(&s->iodone);

	if (ec_nr_failed(&s->new_stripe)) {
		bch_err(c, "error creating stripe: error writing redundancy buckets");
		return bch_err_throw(c, ec_block_write);
	}

	try(bch2_trans_commit_do(c, &s->res, NULL,
				 BCH_TRANS_COMMIT_no_check_rw|
				 BCH_TRANS_COMMIT_no_enospc,
		ec_stripe_key_update(trans, bkey_i_to_stripe(&s->new_stripe.key))));

	try(stripe_update_extents(c, s));

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

	if (ret)
		event_inc_trace(c, stripe_create_fail, buf, ({
			prt_printf(&buf, "error %s\n", bch2_err_str(ret));
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
		}));
	else if (s->have_old_stripe)
		event_inc_trace(c, stripe_reuse, buf, ({
			struct bch_stripe *ov = &bkey_i_to_stripe(&s->old_stripe.key)->v;

			prt_printf(&buf, "Reused %u/%u data blocks\n", s->old_blocks_nr,
				   ov->nr_blocks - ov->nr_redundant);
			prt_printf(&buf, "\nOld: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
			prt_printf(&buf, "\nNew: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->old_stripe.key));
		}));
	else
		event_inc_trace(c, stripe_create, buf, ({
			prt_newline(&buf);
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

	bch2_ec_stripe_buf_exit(&s->old_stripe);
	bch2_ec_stripe_buf_exit(&s->new_stripe);
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
		bch2_ec_stripe_new_cancel(c, h, -EINTR);
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

static int get_old_stripe(struct btree_trans *trans,
			  struct ec_stripe_head *head,
			  struct ec_stripe_buf *stripe,
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

	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);

	if (stripe_lru_pos(s.v) == STRIPE_LRU_POS_EMPTY) {
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

	int ret = bch2_ec_stripe_buf_init(c, &s->old_stripe, 0, le16_to_cpu(old_v->sectors));
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

		bch2_ec_block_io(c, &s->old_stripe, READ, i, &s->iodone);
	}

	s->have_old_stripe = true;

	return 0;
}

static int stripe_reuse(struct btree_trans *trans, struct ec_stripe_head *h,
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
		ret = get_old_stripe(trans, h, &s->old_stripe, lru_k.k->p.offset);
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
				ret = stripe_reuse(trans, h, s);
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
	try(bch2_ec_stripe_buf_init(c, &s->new_stripe, 0, h->blocksize));

	if (!s->res.sectors)
		bch2_disk_reservation_get(c, &s->res,
					  h->blocksize,
					  s->nr_parity,
					  BCH_DISK_RESERVATION_NOFAIL);

	bch2_stripe_new_buckets_add(c, s);
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

		s->allocated = true;

		event_inc_trace(c, stripe_alloc, buf, ({
			prt_printf(&buf, "\nnew: ");
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->new_stripe.key));
			if (s->have_old_stripe) {
				prt_printf(&buf, "\nold: ");
				bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&s->old_stripe.key));
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
