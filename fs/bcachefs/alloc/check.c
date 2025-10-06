// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/check.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/update.h"

#include "data/ec.h"

#include "init/error.h"
#include "init/progress.h"

/*
 * This synthesizes deleted extents for holes, similar to BTREE_ITER_slots for
 * extents style btrees, but works on non-extents btrees:
 */
static struct bkey_s_c bch2_get_key_or_hole(struct btree_iter *iter, struct bpos end, struct bkey *hole)
{
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);

	if (bkey_err(k))
		return k;

	if (k.k->type) {
		return k;
	} else {
		CLASS(btree_iter_copy, iter2)(iter);

		struct btree_path *path = btree_iter_path(iter->trans, iter);
		if (!bpos_eq(path->l[0].b->key.k.p, SPOS_MAX))
			end = bkey_min(end, bpos_nosnap_successor(path->l[0].b->key.k.p));

		end = bkey_min(end, POS(iter->pos.inode, iter->pos.offset + U32_MAX - 1));

		/*
		 * btree node min/max is a closed interval, upto takes a half
		 * open interval:
		 */
		k = bch2_btree_iter_peek_max(&iter2, end);
		if (bkey_err(k))
			return k;

		struct bpos next = iter2.pos;
		BUG_ON(next.offset >= iter->pos.offset + U32_MAX);

		bkey_init(hole);
		hole->p = iter->pos;

		bch2_key_resize(hole, next.offset - iter->pos.offset);
		return (struct bkey_s_c) { hole, NULL };
	}
}

static bool next_bucket(struct bch_fs *c, struct bch_dev **ca, struct bpos *bucket)
{
	if (*ca) {
		if (bucket->offset < (*ca)->mi.first_bucket)
			bucket->offset = (*ca)->mi.first_bucket;

		if (bucket->offset < (*ca)->mi.nbuckets)
			return true;

		bch2_dev_put(*ca);
		*ca = NULL;
		bucket->inode++;
		bucket->offset = 0;
	}

	guard(rcu)();
	*ca = __bch2_next_dev_idx(c, bucket->inode, NULL);
	if (*ca) {
		*bucket = POS((*ca)->dev_idx, (*ca)->mi.first_bucket);
		bch2_dev_get(*ca);
	}

	return *ca != NULL;
}

static struct bkey_s_c bch2_get_key_or_real_bucket_hole(struct btree_iter *iter,
					struct bch_dev **ca, struct bkey *hole)
{
	struct bch_fs *c = iter->trans->c;
	struct bkey_s_c k;
again:
	k = bch2_get_key_or_hole(iter, POS_MAX, hole);
	if (bkey_err(k))
		return k;

	*ca = bch2_dev_iterate_noerror(c, *ca, k.k->p.inode);

	if (!k.k->type) {
		struct bpos hole_start = bkey_start_pos(k.k);

		if (!*ca || !bucket_valid(*ca, hole_start.offset)) {
			if (!next_bucket(c, ca, &hole_start))
				return bkey_s_c_null;

			bch2_btree_iter_set_pos(iter, hole_start);
			goto again;
		}

		if (k.k->p.offset > (*ca)->mi.nbuckets)
			bch2_key_resize(hole, (*ca)->mi.nbuckets - hole_start.offset);
	}

	return k;
}

int bch2_need_discard_or_freespace_err(struct btree_trans *trans,
					 struct bkey_s_c alloc_k,
					 bool set, bool discard, bool repair)
{
	struct bch_fs *c = trans->c;
	enum bch_fsck_flags flags = FSCK_CAN_IGNORE|(repair ? FSCK_CAN_FIX : 0);
	enum bch_sb_error_id err_id = discard
		? BCH_FSCK_ERR_need_discard_key_wrong
		: BCH_FSCK_ERR_freespace_key_wrong;
	enum btree_id btree = discard ? BTREE_ID_need_discard : BTREE_ID_freespace;
	CLASS(printbuf, buf)();

	bch2_bkey_val_to_text(&buf, c, alloc_k);

	int ret = __bch2_fsck_err(NULL, trans, flags, err_id,
				  "bucket incorrectly %sset in %s btree\n%s",
				  set ? "" : "un",
				  bch2_btree_id_str(btree),
				  buf.buf);
	if (bch2_err_matches(ret, BCH_ERR_fsck_ignore) ||
	    bch2_err_matches(ret, BCH_ERR_fsck_errors_not_fixed))
		ret = 0;
	return ret;
}

static noinline_for_stack
int bch2_check_alloc_key(struct btree_trans *trans,
			 struct bkey_s_c alloc_k,
			 struct btree_iter *alloc_iter,
			 struct btree_iter *discard_iter,
			 struct btree_iter *freespace_iter,
			 struct btree_iter *bucket_gens_iter)
{
	struct bch_fs *c = trans->c;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	unsigned gens_offset;
	struct bkey_s_c k;
	CLASS(printbuf, buf)();
	int ret = 0;

	CLASS(bch2_dev_bucket_tryget_noerror, ca)(c, alloc_k.k->p);
	if (fsck_err_on(!ca,
			trans, alloc_key_to_missing_dev_bucket,
			"alloc key for invalid device:bucket %llu:%llu",
			alloc_k.k->p.inode, alloc_k.k->p.offset))
		ret = bch2_btree_delete_at(trans, alloc_iter, 0);
	if (!ca)
		return ret;

	if (!ca->mi.freespace_initialized)
		return 0;

	a = bch2_alloc_to_v4(alloc_k, &a_convert);

	bch2_btree_iter_set_pos(discard_iter, alloc_k.k->p);
	k = bkey_try(bch2_btree_iter_peek_slot(discard_iter));

	bool is_discarded = a->data_type == BCH_DATA_need_discard;
	if (need_discard_or_freespace_err_on(!!k.k->type != is_discarded,
					     trans, alloc_k, !is_discarded, true, true))
		try(bch2_btree_bit_mod_iter(trans, discard_iter, is_discarded));

	bch2_btree_iter_set_pos(freespace_iter, alloc_freespace_pos(alloc_k.k->p, *a));
	k = bkey_try(bch2_btree_iter_peek_slot(freespace_iter));

	bool is_free = a->data_type == BCH_DATA_free;
	if (need_discard_or_freespace_err_on(!!k.k->type != is_free,
					     trans, alloc_k, !is_free, false, true))
		try(bch2_btree_bit_mod_iter(trans, freespace_iter, is_free));

	bch2_btree_iter_set_pos(bucket_gens_iter, alloc_gens_pos(alloc_k.k->p, &gens_offset));
	k = bkey_try(bch2_btree_iter_peek_slot(bucket_gens_iter));

	if (fsck_err_on(a->gen != alloc_gen(k, gens_offset),
			trans, bucket_gens_key_wrong,
			"incorrect gen in bucket_gens btree (got %u should be %u)\n%s",
			alloc_gen(k, gens_offset), a->gen,
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		struct bkey_i_bucket_gens *g =
			errptr_try(bch2_trans_kmalloc(trans, sizeof(*g)));

		if (k.k->type == KEY_TYPE_bucket_gens) {
			bkey_reassemble(&g->k_i, k);
		} else {
			bkey_bucket_gens_init(&g->k_i);
			g->k.p = alloc_gens_pos(alloc_k.k->p, &gens_offset);
		}

		g->v.gens[gens_offset] = a->gen;

		try(bch2_trans_update(trans, bucket_gens_iter, &g->k_i, 0));
	}
fsck_err:
	return ret;
}

static noinline_for_stack
int bch2_check_alloc_hole_freespace(struct btree_trans *trans,
				    struct bch_dev *ca,
				    struct bpos start,
				    struct bpos *end,
				    struct btree_iter *freespace_iter)
{
	CLASS(printbuf, buf)();
	int ret = 0;

	if (!ca->mi.freespace_initialized)
		return 0;

	bch2_btree_iter_set_pos(freespace_iter, start);

	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(freespace_iter));

	*end = bkey_min(k.k->p, *end);

	if (fsck_err_on(k.k->type != KEY_TYPE_set,
			trans, freespace_hole_missing,
			"hole in alloc btree missing in freespace btree\n"
			"device %llu buckets %llu-%llu",
			freespace_iter->pos.inode,
			freespace_iter->pos.offset,
			end->offset)) {
		struct bkey_i *update =
			errptr_try(bch2_trans_kmalloc(trans, sizeof(*update)));

		bkey_init(&update->k);
		update->k.type	= KEY_TYPE_set;
		update->k.p	= freespace_iter->pos;
		bch2_key_resize(&update->k,
				min_t(u64, U32_MAX, end->offset -
				      freespace_iter->pos.offset));

		try(bch2_trans_update(trans, freespace_iter, update, 0));
	}
fsck_err:
	return ret;
}

static noinline_for_stack
int bch2_check_alloc_hole_bucket_gens(struct btree_trans *trans,
				      struct bpos start,
				      struct bpos *end,
				      struct btree_iter *bucket_gens_iter)
{
	CLASS(printbuf, buf)();
	unsigned gens_offset, gens_end_offset;
	int ret = 0;

	bch2_btree_iter_set_pos(bucket_gens_iter, alloc_gens_pos(start, &gens_offset));

	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(bucket_gens_iter));

	if (bkey_cmp(alloc_gens_pos(start, &gens_offset),
		     alloc_gens_pos(*end,  &gens_end_offset)))
		gens_end_offset = KEY_TYPE_BUCKET_GENS_NR;

	if (k.k->type == KEY_TYPE_bucket_gens) {
		struct bkey_i_bucket_gens g;
		bool need_update = false;

		bkey_reassemble(&g.k_i, k);

		for (unsigned i = gens_offset; i < gens_end_offset; i++) {
			if (fsck_err_on(g.v.gens[i], trans,
					bucket_gens_hole_wrong,
					"hole in alloc btree at %llu:%llu with nonzero gen in bucket_gens btree (%u)",
					bucket_gens_pos_to_alloc(k.k->p, i).inode,
					bucket_gens_pos_to_alloc(k.k->p, i).offset,
					g.v.gens[i])) {
				g.v.gens[i] = 0;
				need_update = true;
			}
		}

		if (need_update) {
			struct bkey_i *u = errptr_try(bch2_trans_kmalloc(trans, sizeof(g)));

			memcpy(u, &g, sizeof(g));

			try(bch2_trans_update(trans, bucket_gens_iter, u, 0));
		}
	}

	*end = bkey_min(*end, bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0));
fsck_err:
	return ret;
}

struct check_discard_freespace_key_async {
	struct work_struct	work;
	struct bch_fs		*c;
	struct bbpos		pos;
};

static int bch2_recheck_discard_freespace_key(struct btree_trans *trans, struct bbpos pos)
{
	CLASS(btree_iter, iter)(trans, pos.btree, pos.pos, 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	u8 gen;
	return k.k->type != KEY_TYPE_set
		? __bch2_check_discard_freespace_key(trans, &iter, &gen, FSCK_ERR_SILENT)
		: 0;
}

static void check_discard_freespace_key_work(struct work_struct *work)
{
	struct check_discard_freespace_key_async *w =
		container_of(work, struct check_discard_freespace_key_async, work);

	bch2_trans_do(w->c, bch2_recheck_discard_freespace_key(trans, w->pos));
	enumerated_ref_put(&w->c->writes, BCH_WRITE_REF_check_discard_freespace_key);
	kfree(w);
}

int __bch2_check_discard_freespace_key(struct btree_trans *trans, struct btree_iter *iter, u8 *gen,
				       enum bch_fsck_flags fsck_flags)
{
	struct bch_fs *c = trans->c;
	enum bch_data_type state = iter->btree_id == BTREE_ID_need_discard
		? BCH_DATA_need_discard
		: BCH_DATA_free;
	CLASS(printbuf, buf)();
	int ret = 0;

	bool async_repair = fsck_flags & FSCK_ERR_NO_LOG;
	fsck_flags |= FSCK_CAN_FIX|FSCK_CAN_IGNORE;

	struct bpos bucket = iter->pos;
	bucket.offset &= ~(~0ULL << 56);
	u64 genbits = iter->pos.offset & (~0ULL << 56);

	struct btree_iter alloc_iter;
	struct bkey_s_c alloc_k = bkey_try(bch2_bkey_get_iter(trans, &alloc_iter,
						     BTREE_ID_alloc, bucket,
						     async_repair ? BTREE_ITER_cached : 0));

	if (!bch2_dev_bucket_exists(c, bucket)) {
		if (__fsck_err(trans, fsck_flags,
			       need_discard_freespace_key_to_invalid_dev_bucket,
			       "entry in %s btree for nonexistant dev:bucket %llu:%llu",
			       bch2_btree_id_str(iter->btree_id), bucket.inode, bucket.offset))
			goto delete;
		ret = 1;
		goto out;
	}

	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(alloc_k, &a_convert);

	if (a->data_type != state ||
	    (state == BCH_DATA_free &&
	     genbits != alloc_freespace_genbits(*a))) {
		if (__fsck_err(trans, fsck_flags,
			       need_discard_freespace_key_bad,
			     "%s\nincorrectly set at %s:%llu:%llu:0 (free %u, genbits %llu should be %llu)",
			     (bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf),
			     bch2_btree_id_str(iter->btree_id),
			     iter->pos.inode,
			     iter->pos.offset,
			     a->data_type == state,
			     genbits >> 56, alloc_freespace_genbits(*a) >> 56))
			goto delete;
		ret = 1;
		goto out;
	}

	*gen = a->gen;
out:
fsck_err:
	bch2_set_btree_iter_dontneed(&alloc_iter);
	bch2_trans_iter_exit(&alloc_iter);
	return ret;
delete:
	if (!async_repair) {
		ret =   bch2_btree_bit_mod_iter(trans, iter, false) ?:
			bch2_trans_commit(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc) ?:
			bch_err_throw(c, transaction_restart_commit);
		goto out;
	} else {
		/*
		 * We can't repair here when called from the allocator path: the
		 * commit will recurse back into the allocator
		 */
		struct check_discard_freespace_key_async *w =
			kzalloc(sizeof(*w), GFP_KERNEL);
		if (!w)
			goto out;

		if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_check_discard_freespace_key)) {
			kfree(w);
			goto out;
		}

		INIT_WORK(&w->work, check_discard_freespace_key_work);
		w->c = c;
		w->pos = BBPOS(iter->btree_id, iter->pos);
		queue_work(c->write_ref_wq, &w->work);

		ret = 1; /* don't allocate from this bucket */
		goto out;
	}
}

static int bch2_check_discard_freespace_key(struct btree_trans *trans, struct btree_iter *iter)
{
	u8 gen;
	int ret = __bch2_check_discard_freespace_key(trans, iter, &gen, 0);
	return ret < 0 ? ret : 0;
}

/*
 * We've already checked that generation numbers in the bucket_gens btree are
 * valid for buckets that exist; this just checks for keys for nonexistent
 * buckets.
 */
static noinline_for_stack
int bch2_check_bucket_gens_key(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_bucket_gens g;
	u64 start = bucket_gens_pos_to_alloc(k.k->p, 0).offset;
	u64 end = bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0).offset;
	u64 b;
	bool need_update = false;
	CLASS(printbuf, buf)();
	int ret = 0;

	BUG_ON(k.k->type != KEY_TYPE_bucket_gens);
	bkey_reassemble(&g.k_i, k);

	CLASS(bch2_dev_tryget_noerror, ca)(c, k.k->p.inode);
	if (!ca) {
		if (fsck_err(trans, bucket_gens_to_invalid_dev,
			     "bucket_gens key for invalid device:\n%s",
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			return bch2_btree_delete_at(trans, iter, 0);
		return 0;
	}

	if (fsck_err_on(end <= ca->mi.first_bucket ||
			start >= ca->mi.nbuckets,
			trans, bucket_gens_to_invalid_buckets,
			"bucket_gens key for invalid buckets:\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		return bch2_btree_delete_at(trans, iter, 0);
	}

	for (b = start; b < ca->mi.first_bucket; b++)
		if (fsck_err_on(g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK],
				trans, bucket_gens_nonzero_for_invalid_buckets,
				"bucket_gens key has nonzero gen for invalid bucket")) {
			g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK] = 0;
			need_update = true;
		}

	for (b = ca->mi.nbuckets; b < end; b++)
		if (fsck_err_on(g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK],
				trans, bucket_gens_nonzero_for_invalid_buckets,
				"bucket_gens key has nonzero gen for invalid bucket")) {
			g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK] = 0;
			need_update = true;
		}

	if (need_update) {
		struct bkey_i *u = errptr_try(bch2_trans_kmalloc(trans, sizeof(g)));

		memcpy(u, &g, sizeof(g));
		return bch2_trans_update(trans, iter, u, 0);
	}
fsck_err:
	return ret;
}

int bch2_check_alloc_info(struct bch_fs *c)
{
	struct btree_iter iter, discard_iter, freespace_iter, bucket_gens_iter;
	struct bch_dev *ca = NULL;
	struct bkey hole;
	struct bkey_s_c k;
	int ret = 0;

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_alloc));

	CLASS(btree_trans, trans)(c);
	bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &discard_iter, BTREE_ID_need_discard, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &freespace_iter, BTREE_ID_freespace, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &bucket_gens_iter, BTREE_ID_bucket_gens, POS_MIN,
			     BTREE_ITER_prefetch);

	while (1) {
		struct bpos next;

		bch2_trans_begin(trans);

		k = bch2_get_key_or_real_bucket_hole(&iter, &ca, &hole);
		ret = bkey_err(k);
		if (ret)
			goto bkey_err;

		if (!k.k)
			break;

		progress_update_iter(trans, &progress, &iter);

		if (k.k->type) {
			next = bpos_nosnap_successor(k.k->p);

			ret = bch2_check_alloc_key(trans,
						   k, &iter,
						   &discard_iter,
						   &freespace_iter,
						   &bucket_gens_iter);
			BUG_ON(ret > 0);
			if (ret)
				goto bkey_err;
		} else {
			next = k.k->p;

			ret = bch2_check_alloc_hole_freespace(trans, ca,
						    bkey_start_pos(k.k),
						    &next,
						    &freespace_iter) ?:
				bch2_check_alloc_hole_bucket_gens(trans,
						    bkey_start_pos(k.k),
						    &next,
						    &bucket_gens_iter);
			BUG_ON(ret > 0);
			if (ret)
				goto bkey_err;
		}

		ret = bch2_trans_commit(trans, NULL, NULL,
					BCH_TRANS_COMMIT_no_enospc);
		if (ret)
			goto bkey_err;

		bch2_btree_iter_set_pos(&iter, next);
bkey_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;
	}
	bch2_trans_iter_exit(&bucket_gens_iter);
	bch2_trans_iter_exit(&freespace_iter);
	bch2_trans_iter_exit(&discard_iter);
	bch2_trans_iter_exit(&iter);
	bch2_dev_put(ca);
	ca = NULL;

	if (ret < 0)
		return ret;

	try(for_each_btree_key(trans, iter,
			BTREE_ID_need_discard, POS_MIN,
			BTREE_ITER_prefetch, k,
		bch2_check_discard_freespace_key(trans, &iter)));

	bch2_trans_iter_init(trans, &iter, BTREE_ID_freespace, POS_MIN,
			     BTREE_ITER_prefetch);
	while (1) {
		bch2_trans_begin(trans);
		k = bch2_btree_iter_peek(&iter);
		if (!k.k)
			break;

		ret = bkey_err(k) ?:
			bch2_check_discard_freespace_key(trans, &iter);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			ret = 0;
			continue;
		}
		if (ret) {
			CLASS(printbuf, buf)();
			bch2_bkey_val_to_text(&buf, c, k);
			bch_err(c, "while checking %s", buf.buf);
			break;
		}

		bch2_btree_iter_set_pos(&iter, bpos_nosnap_successor(iter.pos));
	}
	bch2_trans_iter_exit(&iter);
	if (ret)
		return ret;

	ret = for_each_btree_key_commit(trans, iter,
			BTREE_ID_bucket_gens, POS_MIN,
			BTREE_ITER_prefetch, k,
			NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		bch2_check_bucket_gens_key(trans, &iter, k));

	return ret;
}

static int bch2_check_alloc_to_lru_ref(struct btree_trans *trans,
				       struct btree_iter *alloc_iter,
				       struct bkey_buf *last_flushed)
{
	struct bch_fs *c = trans->c;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	CLASS(printbuf, buf)();
	int ret = 0;

	struct bkey_s_c alloc_k = bkey_try(bch2_btree_iter_peek(alloc_iter));
	if (!alloc_k.k)
		return 0;

	CLASS(bch2_dev_tryget_noerror, ca)(c, alloc_k.k->p.inode);
	if (!ca)
		return 0;

	a = bch2_alloc_to_v4(alloc_k, &a_convert);

	u64 lru_idx = alloc_lru_idx_fragmentation(*a, ca);
	if (lru_idx)
		try(bch2_lru_check_set(trans, BCH_LRU_BUCKET_FRAGMENTATION,
				       bucket_to_u64(alloc_k.k->p),
				       lru_idx, alloc_k, last_flushed));

	if (a->data_type == BCH_DATA_cached) {
		if (fsck_err_on(!a->io_time[READ],
				trans, alloc_key_cached_but_read_time_zero,
				"cached bucket with read_time 0\n%s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
			struct bkey_i_alloc_v4 *a_mut =
				errptr_try(bch2_alloc_to_v4_mut(trans, alloc_k));

			a_mut->v.io_time[READ] = bch2_current_io_time(c, READ);
			try(bch2_trans_update(trans, alloc_iter,
					      &a_mut->k_i, BTREE_TRIGGER_norun));

			a = &a_mut->v;
		}

		ret = bch2_lru_check_set(trans, alloc_k.k->p.inode,
					 bucket_to_u64(alloc_k.k->p),
					 a->io_time[READ],
					 alloc_k, last_flushed);
	}
fsck_err:
	return ret;
}

int bch2_check_alloc_to_lru_refs(struct bch_fs *c)
{
	struct bkey_buf last_flushed;
	bch2_bkey_buf_init(&last_flushed);
	bkey_init(&last_flushed.k->k);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_alloc));

	CLASS(btree_trans, trans)(c);
	int ret = for_each_btree_key_commit(trans, iter, BTREE_ID_alloc,
				POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			progress_update_iter(trans, &progress, &iter);
			bch2_check_alloc_to_lru_ref(trans, &iter, &last_flushed);
	}))?: bch2_check_stripe_to_lru_refs(trans);

	bch2_bkey_buf_exit(&last_flushed, c);
	return ret;
}

int bch2_dev_freespace_init(struct bch_fs *c, struct bch_dev *ca,
			    u64 bucket_start, u64 bucket_end)
{
	struct bkey_s_c k;
	struct bkey hole;
	struct bpos end = POS(ca->dev_idx, bucket_end);
	unsigned long last_updated = jiffies;
	int ret;

	BUG_ON(bucket_start > bucket_end);
	BUG_ON(bucket_end > ca->mi.nbuckets);

	CLASS(btree_trans, trans)(c);
	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc,
		POS(ca->dev_idx, max_t(u64, ca->mi.first_bucket, bucket_start)),
		BTREE_ITER_prefetch);
	/*
	 * Scan the alloc btree for every bucket on @ca, and add buckets to the
	 * freespace/need_discard/need_gc_gens btrees as needed:
	 */
	while (1) {
		if (time_after(jiffies, last_updated + HZ * 10)) {
			bch_info(ca, "%s: currently at %llu/%llu",
				 __func__, iter.pos.offset, ca->mi.nbuckets);
			last_updated = jiffies;
		}

		bch2_trans_begin(trans);

		if (bkey_ge(iter.pos, end)) {
			ret = 0;
			break;
		}

		k = bch2_get_key_or_hole(&iter, end, &hole);
		ret = bkey_err(k);
		if (ret)
			goto bkey_err;

		if (k.k->type) {
			/*
			 * We process live keys in the alloc btree one at a
			 * time:
			 */
			struct bch_alloc_v4 a_convert;
			const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);

			ret =   bch2_bucket_do_index(trans, ca, k, a, true) ?:
				bch2_trans_commit(trans, NULL, NULL,
						  BCH_TRANS_COMMIT_no_enospc);
			if (ret)
				goto bkey_err;

			bch2_btree_iter_advance(&iter);
		} else {
			struct bkey_i *freespace;

			freespace = bch2_trans_kmalloc(trans, sizeof(*freespace));
			ret = PTR_ERR_OR_ZERO(freespace);
			if (ret)
				goto bkey_err;

			bkey_init(&freespace->k);
			freespace->k.type	= KEY_TYPE_set;
			freespace->k.p		= k.k->p;
			freespace->k.size	= k.k->size;

			ret = bch2_btree_insert_trans(trans, BTREE_ID_freespace, freespace, 0) ?:
				bch2_trans_commit(trans, NULL, NULL,
						  BCH_TRANS_COMMIT_no_enospc);
			if (ret)
				goto bkey_err;

			bch2_btree_iter_set_pos(&iter, k.k->p);
		}
bkey_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;
	}

	if (ret < 0) {
		bch_err_msg(ca, ret, "initializing free space");
		return ret;
	}

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
		SET_BCH_MEMBER_FREESPACE_INITIALIZED(m, true);
	}

	return 0;
}

int bch2_fs_freespace_init(struct bch_fs *c)
{
	if (c->sb.features & BIT_ULL(BCH_FEATURE_small_image))
		return 0;

	/*
	 * We can crash during the device add path, so we need to check this on
	 * every mount:
	 */

	bool doing_init = false;
	for_each_member_device(c, ca) {
		if (ca->mi.freespace_initialized)
			continue;

		if (!doing_init) {
			bch_info(c, "initializing freespace");
			doing_init = true;
		}

		int ret = bch2_dev_freespace_init(c, ca, 0, ca->mi.nbuckets);
		if (ret) {
			bch2_dev_put(ca);
			bch_err_fn(c, ret);
			return ret;
		}
	}

	if (doing_init) {
		guard(mutex)(&c->sb_lock);
		bch2_write_super(c);
		bch_verbose(c, "done initializing freespace");
	}

	return 0;
}
