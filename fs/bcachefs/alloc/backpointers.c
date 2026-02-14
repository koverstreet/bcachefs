// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"

#include "btree/bbpos.h"
#include "btree/cache.h"
#include "btree/read.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/write_buffer.h"

#include "data/checksum.h"

#include "sb/io.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/passes.h"

#include <linux/mm.h>

static int bch2_bucket_bitmap_set(struct bch_dev *, struct bucket_bitmap *, u64);

static inline struct bbpos bp_to_bbpos(struct bch_backpointer bp)
{
	return (struct bbpos) {
		.btree	= bp.btree_id,
		.pos	= bp.pos,
	};
}

int bch2_backpointer_validate(struct bch_fs *c, struct bkey_s_c k,
			      struct bkey_validate_context from)
{
	struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);
	int ret = 0;

	bkey_fsck_err_on(bp.v->level > BTREE_MAX_DEPTH,
			 c, backpointer_level_bad,
			 "backpointer level bad: %u >= %u",
			 bp.v->level, BTREE_MAX_DEPTH);

	bkey_fsck_err_on(bp.k->p.inode == BCH_SB_MEMBER_INVALID,
			 c, backpointer_dev_bad,
			 "backpointer for BCH_SB_MEMBER_INVALID");
fsck_err:
	return ret;
}

void bch2_backpointer_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);

	struct bch_dev *ca;
	u32 bucket_offset;
	struct bpos bucket;
	scoped_guard(rcu) {
		ca = bch2_dev_rcu_noerror(c, bp.k->p.inode);
		if (ca)
			bucket = bp_pos_to_bucket_and_offset(ca, bp.k->p, &bucket_offset);
	}

	if (ca)
		prt_printf(out, "bucket=%llu:%llu:%u ", bucket.inode, bucket.offset, bucket_offset);
	else
		prt_printf(out, "sector=%llu:%llu ", bp.k->p.inode, bp.k->p.offset >> c->sb.extent_bp_shift);

	bch2_btree_id_level_to_text(out, bp.v->btree_id, bp.v->level);
	prt_str(out, " data_type=");
	bch2_prt_data_type(out, bp.v->data_type);
	prt_printf(out, " suboffset=%u len=%u gen=%u pos=",
		   (u32) bp.k->p.offset & ~(~0U << c->sb.extent_bp_shift),
		   bp.v->bucket_len,
		   bp.v->bucket_gen);
	bch2_bpos_to_text(out, bp.v->pos);

	if (BACKPOINTER_RECONCILE_PHYS(bp.v))
		prt_str(out, " phys");

	if (BACKPOINTER_STRIPE_PTR(bp.v))
		prt_str(out, " stripe");
}

void bch2_backpointer_swab(const struct bch_fs *c, struct bkey_s k)
{
	struct bkey_s_backpointer bp = bkey_s_to_backpointer(k);

	bp.v->flags		= swab32(bp.v->flags);
	bp.v->bucket_len	= swab32(bp.v->bucket_len);
	bch2_bpos_swab(&bp.v->pos);
}

static bool extent_matches_bp(struct bch_fs *c,
			      enum btree_id btree_id, unsigned level,
			      struct bkey_s_c k,
			      struct bkey_s_c_backpointer bp)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bkey_i_backpointer bp2;
		bch2_extent_ptr_to_bp(c, btree_id, level, k, p, entry, &bp2);

		if (bpos_eq(bp.k->p, bp2.k.p) &&
		    !memcmp(bp.v, &bp2.v, sizeof(bp2.v)))
			return true;
	}

	return false;
}

static noinline int backpointer_mod_err(struct btree_trans *trans,
					struct bkey_s_c orig_k,
					struct bkey_i_backpointer *new_bp,
					struct bkey_s_c found_bp,
					bool insert)
{
	struct bch_fs *c = trans->c;

	if (recovery_pass_will_run(c, BCH_RECOVERY_PASS_check_extents_to_backpointers))
		return 0;

	CLASS(bch_log_msg, msg)(c);
	if (insert) {
		prt_printf(&msg.m, "existing backpointer found when inserting ");
		bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&new_bp->k_i));
		prt_newline(&msg.m);
		guard(printbuf_indent)(&msg.m);

		prt_printf(&msg.m, "found ");
		bch2_bkey_val_to_text(&msg.m, c, found_bp);
		prt_newline(&msg.m);

		prt_printf(&msg.m, "for ");
		bch2_bkey_val_to_text(&msg.m, c, orig_k);
	} else {
		prt_printf(&msg.m, "backpointer not found when deleting\n");
		guard(printbuf_indent)(&msg.m);

		prt_printf(&msg.m, "searching for ");
		bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(&new_bp->k_i));
		prt_newline(&msg.m);

		prt_printf(&msg.m, "got ");
		bch2_bkey_val_to_text(&msg.m, c, found_bp);
		prt_newline(&msg.m);

		prt_printf(&msg.m, "for ");
		bch2_bkey_val_to_text(&msg.m, c, orig_k);
	}

	return bch2_run_explicit_recovery_pass(c, &msg.m,
			BCH_RECOVERY_PASS_check_extents_to_backpointers, 0);
}

int bch2_bucket_backpointer_mod_nowritebuffer(struct btree_trans *trans,
				struct bkey_s_c orig_k,
				struct bkey_i_backpointer *bp,
				bool insert)
{
	CLASS(btree_iter, bp_iter)(trans, backpointer_btree(&bp->v), bp->k.p,
				   BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&bp_iter));

	if (insert
	    ? k.k->type
	    : (k.k->type != KEY_TYPE_backpointer ||
	       memcmp(bkey_s_c_to_backpointer(k).v, &bp->v, sizeof(bp->v))))
		try(backpointer_mod_err(trans, orig_k, bp, k, insert));

	if (!insert) {
		bp->k.type = KEY_TYPE_deleted;
		set_bkey_val_u64s(&bp->k, 0);
	}

	return bch2_trans_update(trans, &bp_iter, &bp->k_i, 0);
}

static int bch2_backpointer_del(struct btree_trans *trans, struct bpos pos)
{
	return (!static_branch_unlikely(&bch2_backpointers_no_use_write_buffer)
		? bch2_btree_delete_at_buffered(trans, BTREE_ID_backpointers, pos)
		: bch2_btree_delete(trans, BTREE_ID_backpointers, pos, 0)) ?:
		 bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

static inline int bch2_backpointers_maybe_flush(struct btree_trans *trans,
					 struct bkey_s_c visiting_k,
					 struct wb_maybe_flush *last_flushed)
{
	return !static_branch_unlikely(&bch2_backpointers_no_use_write_buffer)
		? bch2_btree_write_buffer_maybe_flush(trans, visiting_k, last_flushed)
		: 0;
}

static int backpointer_target_not_found(struct btree_trans *trans,
				  struct bkey_s_c_backpointer bp,
				  struct bkey_s_c target_k,
				  struct wb_maybe_flush *last_flushed,
				  bool commit)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();

	/*
	 * If we're using the btree write buffer, the backpointer we were
	 * looking at may have already been deleted - failure to find what it
	 * pointed to is not an error:
	 */
	try(last_flushed
	    ? bch2_backpointers_maybe_flush(trans, bp.s_c, last_flushed)
	    : 0);

	prt_printf(&buf, "backpointer doesn't match %s it points to:\n",
		   bp.v->level ? "btree node" : "extent");
	bch2_bkey_val_to_text(&buf, c, target_k);

	prt_str(&buf, "\nfound: ");
	bch2_bkey_val_to_text(&buf, c, bp.s_c);

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(target_k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	bkey_for_each_ptr_decode(target_k.k, ptrs, p, entry)
		if (p.ptr.dev == bp.k->p.inode) {
			prt_str(&buf, "\nwant:  ");
			struct bkey_i_backpointer bp2;
			bch2_extent_ptr_to_bp(c, bp.v->btree_id, bp.v->level, target_k, p, entry, &bp2);
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&bp2.k_i));
		}

	if (ret_fsck_err(trans, backpointer_to_missing_ptr,
		     "%s", buf.buf)) {
		try(bch2_backpointer_del(trans, bp.k->p));

		/*
		 * Normally, on transaction commit from inside a transaction,
		 * we'll return -BCH_ERR_transaction_restart_nested, since a
		 * transaction commit invalidates pointers given out by peek().
		 *
		 * However, since we're updating a write buffer btree, if we
		 * return a transaction restart and loop we won't see that the
		 * backpointer has been deleted without an additional write
		 * buffer flush - and those are expensive.
		 *
		 * So we're relying on the caller immediately advancing to the
		 * next backpointer and starting a new transaction immediately
		 * after backpointer_get_key() returns NULL:
		 */
		try(commit
		    ? bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc)
		    : 0);
	}

	return 0;
}

static struct btree *__bch2_backpointer_get_node(struct btree_trans *trans,
						 struct bkey_s_c_backpointer bp,
						 struct btree_iter *iter,
						 struct wb_maybe_flush *last_flushed,
						 bool commit)
{
	struct bch_fs *c = trans->c;

	BUG_ON(!bp.v->level);

	bch2_trans_node_iter_init(trans, iter,
				  bp.v->btree_id,
				  bp.v->pos,
				  0,
				  bp.v->level - 1,
				  0);
	struct btree *b = bch2_btree_iter_peek_node(iter);
	if (IS_ERR(b))
		return b;

	if (!b) {
		/* Backpointer for nonexistent tree depth: */
		bkey_init(&iter->k);
		iter->k.p = bp.v->pos;
		struct bkey_s_c k = { &iter->k };

		int ret = backpointer_target_not_found(trans, bp, k, last_flushed, commit);
		return ret ? ERR_PTR(ret) : NULL;
	}

	BUG_ON(b->c.level != bp.v->level - 1);

	if (extent_matches_bp(c, bp.v->btree_id, bp.v->level,
			      bkey_i_to_s_c(&b->key), bp))
		return b;

	if (btree_node_will_make_reachable(b)) {
		return ERR_PTR(bch_err_throw(c, backpointer_to_overwritten_btree_node));
	} else {
		int ret = backpointer_target_not_found(trans, bp, bkey_i_to_s_c(&b->key),
						       last_flushed, commit);
		return ret ? ERR_PTR(ret) : NULL;
	}
}

static struct bkey_s_c __bch2_backpointer_get_key(struct btree_trans *trans,
						  struct bkey_s_c_backpointer bp,
						  struct btree_iter *iter,
						  unsigned iter_flags,
						  struct wb_maybe_flush *last_flushed,
						  bool commit)
{
	struct bch_fs *c = trans->c;

	if (unlikely(bp.v->btree_id >= btree_id_nr_alive(c)))
		return bkey_s_c_null;

	bch2_trans_node_iter_init(trans, iter,
				  bp.v->btree_id,
				  bp.v->pos,
				  0,
				  bp.v->level,
				  iter_flags);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
	if (bkey_err(k))
		return k;

	/*
	 * peek_slot() doesn't normally return NULL - except when we ask for a
	 * key at a btree level that doesn't exist.
	 *
	 * We may want to revisit this and change peek_slot():
	 */
	if (!k.k) {
		bkey_init(&iter->k);
		iter->k.p = bp.v->pos;
		k.k = &iter->k;
	}

	if (k.k &&
	    extent_matches_bp(c, bp.v->btree_id, bp.v->level, k, bp))
		return k;

	if (!bp.v->level) {
		int ret = backpointer_target_not_found(trans, bp, k, last_flushed, commit);
		return ret ? bkey_s_c_err(ret) : bkey_s_c_null;
	} else {
		struct btree *b = __bch2_backpointer_get_node(trans, bp, iter, last_flushed, commit);
		if (b == ERR_PTR(-BCH_ERR_backpointer_to_overwritten_btree_node))
			return bkey_s_c_null;
		if (IS_ERR_OR_NULL(b))
			return ((struct bkey_s_c) { .k = ERR_CAST(b) });

		return bkey_i_to_s_c(&b->key);
	}
}

struct btree *bch2_backpointer_get_node(struct btree_trans *trans,
					struct bkey_s_c_backpointer bp,
					struct btree_iter *iter,
					struct wb_maybe_flush *last_flushed)
{
	return __bch2_backpointer_get_node(trans, bp, iter, last_flushed, true);
}

struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *trans,
					 struct bkey_s_c_backpointer bp,
					 struct btree_iter *iter,
					 unsigned iter_flags,
					 struct wb_maybe_flush *last_flushed)
{
	return __bch2_backpointer_get_key(trans, bp, iter, iter_flags, last_flushed, true);
}

static int bch2_check_backpointer_has_valid_bucket(struct btree_trans *trans, struct bkey_s_c k,
						   struct wb_maybe_flush *last_flushed)
{
	if (k.k->type != KEY_TYPE_backpointer)
		return 0;

	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();

	struct bpos bucket;
	if (!bp_pos_to_bucket_nodev_noerror(c, k.k->p, &bucket)) {
		try(bch2_backpointers_maybe_flush(trans, k, last_flushed));

		if (ret_fsck_err(trans, backpointer_to_missing_device,
			     "backpointer for missing device:\n%s",
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			try(bch2_backpointer_del(trans, k.k->p));

		return 0;
	}

	CLASS(btree_iter, alloc_iter)(trans, BTREE_ID_alloc, bucket, 0);
	struct bkey_s_c alloc_k = bkey_try(bch2_btree_iter_peek_slot(&alloc_iter));

	if (alloc_k.k->type != KEY_TYPE_alloc_v4) {
		try(bch2_backpointers_maybe_flush(trans, k, last_flushed));

		if (ret_fsck_err(trans, backpointer_to_missing_alloc,
			     "backpointer for nonexistent alloc key: %llu:%llu:0\n%s",
			     alloc_iter.pos.inode, alloc_iter.pos.offset,
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			try(bch2_backpointer_del(trans, k.k->p));
	}

	return 0;
}

/* verify that every backpointer has a corresponding alloc key */
int bch2_check_btree_backpointers(struct bch_fs *c)
{
	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_backpointers), 0);

	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter,
			BTREE_ID_backpointers, POS_MIN, 0, k,
			NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		bch2_check_backpointer_has_valid_bucket(trans, k, &last_flushed);
	}));
}

struct extents_to_bp_state {
	struct bpos		bp_start;
	struct bpos		bp_end;
	struct wb_maybe_flush	last_flushed;
};

static int drop_dev_and_update(struct btree_trans *trans, enum btree_id btree,
			       struct bkey_s_c extent, unsigned dev)
{
	struct bch_fs *c = trans->c;
	struct bkey_i *n = errptr_try(bch2_bkey_make_mut_noupdate(trans, extent));

	bch2_bkey_drop_device(c, bkey_i_to_s(n), dev);

	if (!bch2_bkey_can_read(c, bkey_i_to_s_c(n)))
		bch2_set_bkey_error(c, n, KEY_TYPE_ERROR_double_allocation);

	return bch2_btree_insert_trans(trans, btree, n, 0);
}

/*
 * returns 0 if we didn't find a bad checksum, and did no work
 * returns 1 if we dropped bad replica
 */
static int kill_replica_if_checksum_bad(struct btree_trans *trans,
				 enum btree_id btree, struct bkey_s_c extent,
				 enum btree_id o_btree, struct bkey_s_c extent2, unsigned dev)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(extent);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	int ret = 0;

	bkey_for_each_ptr_decode(extent.k, ptrs, p, entry)
		if (p.ptr.dev == dev)
			goto found;
	BUG();
found:
	if (!bkey_is_btree_ptr(extent.k) && !p.crc.csum_type)
		return false;

	struct bch_dev *ca = bch2_dev_get_ioref(c, dev, READ,
				BCH_DEV_READ_REF_check_extent_checksums);
	if (!ca)
		return false;

	size_t bytes = bkey_is_btree_ptr(extent.k)
		? c->opts.btree_node_size
		: p.crc.compressed_size << 9;
	void *data_buf __free(kvfree) = kvmalloc(bytes, GFP_KERNEL);
	if (!data_buf) {
		enumerated_ref_put(&ca->io_ref[READ],
				   BCH_DEV_READ_REF_check_extent_checksums);
		return -ENOMEM;
	}

	struct bio *bio __free(bio_put) =
		bio_alloc(ca->disk_sb.bdev, buf_pages(data_buf, bytes), REQ_OP_READ, GFP_KERNEL);

	CLASS(printbuf, buf)(); /* before first goto */

	bio->bi_iter.bi_sector = p.ptr.offset;
	bch2_bio_map(bio, data_buf, bytes);
	ret = submit_bio_wait(bio);
	if (ret)
		goto err;

	bool bad;

	if (bkey_is_btree_ptr(extent.k)) {
		struct btree_node *bn = data_buf;

		if (le64_to_cpu(bn->magic) != bset_magic(c)) {
			bad = true;
		} else if (bch2_checksum_type_valid(c, BSET_CSUM_TYPE(&bn->keys))) {
			struct nonce nonce = btree_nonce(&bn->keys, 0);
			struct bch_csum csum = csum_vstruct(c, BSET_CSUM_TYPE(&bn->keys),
							    nonce, bn);
			bad = bch2_crc_cmp(bn->csum, csum);
		} else {
			bad = false;
		}

		if (!bad && extent.k->type == KEY_TYPE_btree_ptr_v2)
			bad = le64_to_cpu(bn->keys.seq) !=
			      le64_to_cpu(bkey_s_c_to_btree_ptr_v2(extent).v->seq);
	} else {
		struct nonce nonce = extent_nonce(extent.k->bversion, p.crc);
		struct bch_csum csum = bch2_checksum(c, p.crc.csum_type, nonce,
						     data_buf, bytes);
		bad = bch2_crc_cmp(csum, p.crc.csum);
	}

	if (!bad)
		goto out;

	prt_printf(&buf, "duplicate extents pointing to same space on dev %u, "
		   "checksum bad or wrong btree node - dropping:\n", dev);
	bch2_btree_id_to_text(&buf, btree);
	prt_str(&buf, " ");
	bch2_bkey_val_to_text(&buf, c, extent);
	prt_newline(&buf);
	bch2_btree_id_to_text(&buf, o_btree);
	prt_str(&buf, " ");
	bch2_bkey_val_to_text(&buf, c, extent2);

	if (fsck_err(trans, dup_backpointer_to_bad_csum_extent, "%s", buf.buf))
		ret = drop_dev_and_update(trans, btree, extent, dev) ?: 1;
fsck_err:
out:
err:
	enumerated_ref_put(&ca->io_ref[READ],
			   BCH_DEV_READ_REF_check_extent_checksums);
	return ret;
}

static int bp_missing(struct btree_trans *trans,
		      struct bkey_s_c extent,
		      struct bkey_i_backpointer *bp,
		      struct bkey_s_c bp_found)
{
	struct bch_fs *c = trans->c;

	CLASS(printbuf, buf)();
	prt_str(&buf, "missing backpointer\nfor:  ");
	bch2_bkey_val_to_text(&buf, c, extent);
	prt_printf(&buf, "\nwant: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&bp->k_i));

	if (!bkey_deleted(bp_found.k)) {
		prt_printf(&buf, "\ngot:  ");
		bch2_bkey_val_to_text(&buf, c, bp_found);
	}

	if (ret_fsck_err(trans, ptr_to_missing_backpointer, "%s", buf.buf))
		try(bch2_bucket_backpointer_mod(trans, extent, bp, true));

	return 0;
}

static bool bkey_dev_ptr_stale(struct bch_fs *c, struct bkey_s_c k, unsigned dev)
{
	guard(rcu)();
	struct bch_dev *ca = bch2_dev_rcu_noerror(c, dev);
	if (!ca)
		return false;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr(ptrs, ptr)
		if (ptr->dev == dev &&
		    dev_ptr_stale_rcu(ca, ptr))
			return true;
	return false;
}

static int check_bp_dup(struct btree_trans *trans,
			struct extents_to_bp_state *s,
			struct bkey_s_c extent,
			struct bkey_i_backpointer *bp,
			struct bkey_s_c_backpointer other_bp)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, other_extent_iter)(trans);
	struct bkey_s_c other_extent =
		__bch2_backpointer_get_key(trans, other_bp, &other_extent_iter, 0, NULL, false);
	int ret = bkey_err(other_extent);

	if (ret == -BCH_ERR_backpointer_to_overwritten_btree_node)
		return bp_missing(trans, extent, bp, other_bp.s_c);
	if (ret)
		return ret;
	if (!other_extent.k)
		return bp_missing(trans, extent, bp, other_bp.s_c);

	if (bkey_dev_ptr_stale(c, other_extent, bp->k.p.inode)) {
		try(drop_dev_and_update(trans, other_bp.v->btree_id, other_extent, bp->k.p.inode));
		return 0;
	}

	if (bch2_extents_match(c, extent, other_extent)) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "duplicate versions of same extent, deleting smaller\n");
		bch2_bkey_val_to_text(&buf, c, extent);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, other_extent);
		bch_err(c, "%s", buf.buf);

		if (other_extent.k->size <= extent.k->size) {
			try(drop_dev_and_update(trans, other_bp.v->btree_id, other_extent, bp->k.p.inode));
			return 0;
		} else {
			try(drop_dev_and_update(trans, bp->v.btree_id, extent, bp->k.p.inode));
			return bp_missing(trans, extent, bp, other_bp.s_c);
		}
	} else {
		ret = kill_replica_if_checksum_bad(trans,
					    other_bp.v->btree_id, other_extent,
					    bp->v.btree_id, extent,
					    bp->k.p.inode);
		if (ret < 0)
			return ret;
		if (ret)
			return bp_missing(trans, extent, bp, other_bp.s_c);

		ret = kill_replica_if_checksum_bad(trans, bp->v.btree_id, extent,
					    other_bp.v->btree_id, other_extent, bp->k.p.inode);
		if (ret < 0)
			return ret;
		if (ret)
			return 0;

		CLASS(printbuf, buf)();
		prt_printf(&buf, "duplicate extents pointing to same space on dev %llu\n", bp->k.p.inode);
		bch2_bkey_val_to_text(&buf, c, extent);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, other_extent);
		bch_err(c, "%s", buf.buf);
		return bch_err_throw(c, fsck_repair_unimplemented);
	}
}

static int check_bp_exists(struct btree_trans *trans,
			   struct extents_to_bp_state *s,
			   struct bkey_s_c extent,
			   struct bkey_i_backpointer *bp)
{
	CLASS(btree_iter, bp_iter)(trans, backpointer_btree(&bp->v), bp->k.p, 0);
	struct bkey_s_c bp_found = bkey_try(bch2_btree_iter_peek_slot(&bp_iter));

	if (bp_found.k->type != KEY_TYPE_backpointer) {
		try(bch2_btree_write_buffer_maybe_flush(trans, extent, &s->last_flushed));
		try(bp_missing(trans, extent, bp, bp_found));
	} else if (memcmp(bkey_s_c_to_backpointer(bp_found).v, &bp->v, sizeof(bp->v))) {
		try(bch2_btree_write_buffer_maybe_flush(trans, extent, &s->last_flushed));
		try(check_bp_dup(trans, s, extent, bp, bkey_s_c_to_backpointer(bp_found)));
	}

	return 0;
}

static int check_extent_to_backpointers(struct btree_trans *trans,
					struct extents_to_bp_state *s,
					enum btree_id btree, unsigned level,
					struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bkey_i_backpointer bp;
		bch2_extent_ptr_to_bp(c, btree, level, k, p, entry, &bp);

		if (p.ptr.dev == BCH_SB_MEMBER_INVALID) {
			if (p.has_ec)
				try(check_bp_exists(trans, s, k, &bp));
			continue;
		}

		bool empty;
		{
			/* scoped_guard() is a loop, so it breaks continue */
			guard(rcu)();
			struct bch_dev *ca = bch2_dev_rcu_noerror(c, p.ptr.dev);
			if (!ca)
				continue;

			if (p.ptr.cached && dev_ptr_stale_rcu(ca, &p.ptr))
				continue;

			u64 b = PTR_BUCKET_NR(ca, &p.ptr);
			if (!bch2_bucket_bitmap_test(&ca->bucket_backpointer_mismatch, b))
				continue;

			empty = bch2_bucket_bitmap_test(&ca->bucket_backpointer_empty, b);
		}

		if (bpos_lt(bp.k.p, s->bp_start) ||
		    bpos_gt(bp.k.p, s->bp_end))
			continue;

		try(!empty
		    ? check_bp_exists(trans, s, k, &bp)
		    : bch2_bucket_backpointer_mod(trans, k, &bp, true));
	}

	return 0;
}

static int check_btree_root_to_backpointers(struct btree_trans *trans,
					    struct extents_to_bp_state *s,
					    enum btree_id btree_id,
					    int *level)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_node_iter, iter)(trans, btree_id, POS_MIN, 0,
				     bch2_btree_id_root(c, btree_id)->b->c.level, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	if (b != btree_node_root(c, b))
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_root_race);

	*level = b->c.level;

	struct bkey_s_c k = bkey_i_to_s_c(&b->key);
	return check_extent_to_backpointers(trans, s, btree_id, b->c.level + 1, k);
}

static u64 system_totalram_bytes(void)
{
	struct sysinfo i;
	si_meminfo(&i);

	return i.totalram * i.mem_unit;
}

static u64 mem_may_pin_bytes(struct bch_fs *c)
{
	return div_u64(system_totalram_bytes() * c->opts.fsck_memory_usage_percent, 100);
}

static size_t btree_nodes_fit_in_ram(struct bch_fs *c)
{
	return div_u64(mem_may_pin_bytes(c), c->opts.btree_node_size);
}

static int bch2_get_btree_in_memory_pos(struct btree_trans *trans,
					u64 btree_leaf_mask,
					u64 btree_interior_mask,
					struct bbpos start, struct bbpos *end)
{
	struct bch_fs *c = trans->c;
	s64 mem_may_pin = mem_may_pin_bytes(c);
	int ret = 0;

	bch2_btree_cache_unpin(c);

	btree_interior_mask |= btree_leaf_mask;

	c->btree.cache.pinned_nodes_mask[0]		= btree_leaf_mask;
	c->btree.cache.pinned_nodes_mask[1]		= btree_interior_mask;
	c->btree.cache.pinned_nodes_start		= start;
	c->btree.cache.pinned_nodes_end			= *end = BBPOS_MAX;

	for (enum btree_id btree = start.btree;
	     btree < BTREE_ID_NR && !ret;
	     btree++) {
		unsigned depth = (BIT_ULL(btree) & btree_leaf_mask) ? 0 : 1;

		if (!(BIT_ULL(btree) & btree_leaf_mask) &&
		    !(BIT_ULL(btree) & btree_interior_mask))
			continue;

		ret = __for_each_btree_node(trans, iter, btree,
				      btree == start.btree ? start.pos : POS_MIN,
				      0, depth, BTREE_ITER_prefetch, b, ({
			mem_may_pin -= btree_buf_bytes(b);
			if (mem_may_pin <= 0) {
				c->btree.cache.pinned_nodes_end = *end =
					BBPOS(btree, b->key.k.p);
				break;
			}
			bch2_node_pin(c, b);
			0;
		}));
	}

	return ret;
}

static int bch2_check_extents_to_backpointers_pass(struct btree_trans *trans,
						   struct extents_to_bp_state *s)
{
	struct bch_fs *c = trans->c;

	struct progress_indicator progress;
	bch2_progress_init(&progress, "extents_to_backpointers", trans->c,
		btree_has_data_ptrs_mask,
		~0ULL);

	for (enum btree_id btree_id = 0;
	     btree_id < btree_id_nr_alive(c);
	     btree_id++) {
		int level, depth = btree_type_has_data_ptrs(btree_id) ? 0 : 1;

		try(commit_do(trans, NULL, NULL,
			      BCH_TRANS_COMMIT_no_enospc,
			      check_btree_root_to_backpointers(trans, s, btree_id, &level)));

		while (level >= depth) {
			CLASS(btree_node_iter, iter)(trans, btree_id, POS_MIN, 0, level, BTREE_ITER_prefetch);

			try(for_each_btree_key_continue(trans, iter, 0, k, ({
				bch2_progress_update_iter(trans, &progress, &iter) ?:
				wb_maybe_flush_inc(&s->last_flushed) ?:
				check_extent_to_backpointers(trans, s, btree_id, level, k) ?:
				bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
			})));

			--level;
		}
	}

	return 0;
}

enum alloc_sector_counter {
	ALLOC_dirty,
	ALLOC_cached,
	ALLOC_stripe,
	ALLOC_SECTORS_NR
};

static int data_type_to_alloc_counter(enum bch_data_type t)
{
	switch (t) {
	case BCH_DATA_btree:
	case BCH_DATA_user:
		return ALLOC_dirty;
	case BCH_DATA_cached:
		return ALLOC_cached;
	case BCH_DATA_stripe:
	case BCH_DATA_parity:
		return ALLOC_stripe;
	default:
		return -1;
	}
}

static int check_bucket_backpointers_to_extents(struct btree_trans *, struct bch_dev *, struct bpos,
						struct wb_maybe_flush *last_flushed);

static int check_bucket_backpointer_mismatch(struct btree_trans *trans, struct bkey_s_c alloc_k,
					     bool *had_mismatch,
					     struct wb_maybe_flush *last_flushed,
					     struct bpos *last_pos,
					     unsigned *nr_iters)
{
	struct bch_fs *c = trans->c;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(alloc_k, &a_convert);
	bool need_commit = false;

	if (!bpos_eq(*last_pos, alloc_k.k->p))
		*nr_iters = 0;

	*last_pos = alloc_k.k->p;

	*had_mismatch = false;

	if (a->data_type == BCH_DATA_sb ||
	    a->data_type == BCH_DATA_journal ||
	    a->data_type == BCH_DATA_parity)
		return 0;

	u32 sectors[ALLOC_SECTORS_NR];
	memset(sectors, 0, sizeof(sectors));

	CLASS(bch2_dev_bucket_tryget_noerror, ca)(trans->c, alloc_k.k->p);
	if (!ca)
		return 0;

	struct bkey_s_c bp_k;
	int ret = 0;
	unsigned nr_deletes = 0;

	for_each_btree_key_max_norestart(trans, iter, BTREE_ID_backpointers,
				bucket_pos_to_bp_start(ca, alloc_k.k->p),
				bucket_pos_to_bp_end(ca, alloc_k.k->p), 0, bp_k, ret) {
		if (bp_k.k->type != KEY_TYPE_backpointer)
			continue;

		struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(bp_k);

		if (c->sb.version_upgrade_complete < bcachefs_metadata_version_backpointer_bucket_gen &&
		    (bp.v->bucket_gen != a->gen ||
		     bp.v->flags)) {
			try(bch2_backpointer_del(trans, bp_k.k->p));
			nr_deletes++;

			if (nr_deletes > 256)
				return  bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc) ?:
					bch2_btree_write_buffer_flush_sync(trans) ?:
					bch_err_throw(c, transaction_restart_write_buffer_flush);

			need_commit = true;
			continue;
		}

		if (bp.v->bucket_gen != a->gen)
			continue;

		int alloc_counter = data_type_to_alloc_counter(bp.v->data_type);
		if (alloc_counter < 0)
			continue;

		sectors[alloc_counter] += bp.v->bucket_len;
	};
	if (ret)
		return ret;

	if (need_commit)
		try(bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

	if (sectors[ALLOC_dirty]  > a->dirty_sectors ||
	    sectors[ALLOC_cached] > a->cached_sectors ||
	    sectors[ALLOC_stripe] > a->stripe_sectors) {
		if (*nr_iters) {
			CLASS(bch_log_msg, msg)(c);

			prt_printf(&msg.m, "backpointer sectors > bucket sectors, but found no bad backpointers\n"
				   "bucket %llu:%llu data type %s, counters\n",
				   alloc_k.k->p.inode,
				   alloc_k.k->p.offset,
				   __bch2_data_types[a->data_type]);
			if (sectors[ALLOC_dirty]  > a->dirty_sectors)
				prt_printf(&msg.m, "dirty: %u > %u\n",
					   sectors[ALLOC_dirty], a->dirty_sectors);
			if (sectors[ALLOC_cached] > a->cached_sectors)
				prt_printf(&msg.m, "cached: %u > %u\n",
					   sectors[ALLOC_cached], a->cached_sectors);
			if (sectors[ALLOC_stripe] > a->stripe_sectors)
				prt_printf(&msg.m, "stripe: %u > %u\n",
					   sectors[ALLOC_stripe], a->stripe_sectors);

			for_each_btree_key_max_norestart(trans, iter, BTREE_ID_backpointers,
						bucket_pos_to_bp_start(ca, alloc_k.k->p),
						bucket_pos_to_bp_end(ca, alloc_k.k->p), 0, bp_k, ret) {
				bch2_bkey_val_to_text(&msg.m, c, bp_k);
				prt_newline(&msg.m);
			}

			__WARN();
			return ret;
		}

		*nr_iters += 1;

		return check_bucket_backpointers_to_extents(trans, ca, alloc_k.k->p, last_flushed) ?:
			bch_err_throw(c, transaction_restart_nested);
	}

	if (sectors[ALLOC_dirty]  != a->dirty_sectors ||
	    sectors[ALLOC_cached] != a->cached_sectors ||
	    sectors[ALLOC_stripe] != a->stripe_sectors) {
		/*
		 * Post 1.14 upgrade, we assume that backpointers are mostly
		 * correct and a sector count mismatch is probably due to a
		 * write buffer race
		 *
		 * Pre upgrade, we expect all the buckets to be wrong, a write
		 * buffer flush is pointless:
		 */
		if (c->sb.version_upgrade_complete >= bcachefs_metadata_version_backpointer_bucket_gen) {
			if (a->data_type == BCH_DATA_btree) {
				bch2_trans_unlock_long(trans);
				bch2_btree_interior_updates_flush(c);
			}
			try(bch2_backpointers_maybe_flush(trans, alloc_k, last_flushed));
		}

		bool empty = (sectors[ALLOC_dirty] +
			      sectors[ALLOC_stripe] +
			      sectors[ALLOC_cached]) == 0;

		try(bch2_bucket_bitmap_set(ca, &ca->bucket_backpointer_mismatch, alloc_k.k->p.offset));

		if (empty)
			try(bch2_bucket_bitmap_set(ca, &ca->bucket_backpointer_empty, alloc_k.k->p.offset));

		*had_mismatch = true;
	}

	return 0;
}

static bool backpointer_node_has_missing(struct bch_fs *c, struct bkey_s_c k)
{
	switch (k.k->type) {
	case KEY_TYPE_btree_ptr_v2: {
		bool ret = false;

		guard(rcu)();
		struct bpos pos = bkey_s_c_to_btree_ptr_v2(k).v->min_key;
		while (pos.inode <= k.k->p.inode) {
			if (pos.inode >= c->sb.nr_devices)
				break;

			struct bch_dev *ca = bch2_dev_rcu_noerror(c, pos.inode);
			if (!ca)
				goto next;

			struct bpos bucket = bp_pos_to_bucket(ca, pos);
			u64 next = min(bucket.offset, ca->mi.nbuckets);

			unsigned long *mismatch = READ_ONCE(ca->bucket_backpointer_mismatch.buckets);
			unsigned long *empty = READ_ONCE(ca->bucket_backpointer_empty.buckets);
			/*
			 * Find the first bucket with mismatches - but
			 * not empty buckets; we don't need to pin those
			 * because we just recreate all backpointers in
			 * those buckets
			 */
			if (mismatch && empty)
				next = find_next_andnot_bit(mismatch, empty, ca->mi.nbuckets, next);
			else if (mismatch)
				next = find_next_bit(mismatch, ca->mi.nbuckets, next);
			else
				next = ca->mi.nbuckets;

			bucket.offset = next;
			if (bucket.offset == ca->mi.nbuckets)
				goto next;

			ret = bpos_le(bucket_pos_to_bp_end(ca, bucket), k.k->p);
			if (ret)
				break;
next:
			pos = SPOS(pos.inode + 1, 0, 0);
		}

		return ret;
	}
	case KEY_TYPE_btree_ptr:
		return true;
	default:
		return false;
	}
}

static int btree_node_get_and_pin(struct btree_trans *trans, struct bkey_i *k,
				  enum btree_id btree, unsigned level)
{
	CLASS(btree_node_iter, iter)(trans, btree, k->k.p, 0, level, 0);
	struct btree *b = errptr_try(bch2_btree_iter_peek_node(&iter));

	if (b)
		bch2_node_pin(trans->c, b);
	return 0;
}

static int bch2_pin_backpointer_nodes_with_missing(struct btree_trans *trans,
						   struct bpos start, struct bpos *end)
{
	struct bch_fs *c = trans->c;

	struct bkey_buf tmp __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&tmp);

	bch2_btree_cache_unpin(c);

	*end = SPOS_MAX;

	{
		s64 mem_may_pin = mem_may_pin_bytes(c);

		CLASS(btree_node_iter, iter)(trans, BTREE_ID_backpointers, start, 0, 1, BTREE_ITER_prefetch);
		try(for_each_btree_key_continue(trans, iter, 0, k, ({
			if (!backpointer_node_has_missing(c, k))
				continue;

			mem_may_pin -= c->opts.btree_node_size;
			if (mem_may_pin <= 0)
				break;

			bch2_bkey_buf_reassemble(&tmp, k);
			struct btree_path *path = btree_iter_path(trans, &iter);

			BUG_ON(path->level != 1);

			bch2_btree_node_prefetch(trans, path, tmp.k, path->btree_id, path->level - 1);
		})));
	}

	{
		struct bpos pinned = SPOS_MAX;
		s64 mem_may_pin = mem_may_pin_bytes(c);

		CLASS(btree_node_iter, iter)(trans, BTREE_ID_backpointers, start, 0, 1, BTREE_ITER_prefetch);
		try(for_each_btree_key_continue(trans, iter, 0, k, ({
			if (!backpointer_node_has_missing(c, k))
				continue;

			mem_may_pin -= c->opts.btree_node_size;
			if (mem_may_pin <= 0) {
				*end = pinned;
				break;
			}

			bch2_bkey_buf_reassemble(&tmp, k);
			struct btree_path *path = btree_iter_path(trans, &iter);

			BUG_ON(path->level != 1);

			int ret = btree_node_get_and_pin(trans, tmp.k, path->btree_id, path->level - 1);
			if (!ret)
				pinned = tmp.k->k.p;

			ret;
		})));
	}

	return 0;
}

int bch2_check_extents_to_backpointers(struct bch_fs *c)
{
	int ret = 0;

	CLASS(btree_trans, trans)(c);
	struct extents_to_bp_state s = { .bp_start = POS_MIN };
	struct bpos last_pos = POS_MIN;
	unsigned nr_iters = 0;

	wb_maybe_flush_init(&s.last_flushed);

	ret = for_each_btree_key(trans, iter, BTREE_ID_alloc,
				 POS_MIN, BTREE_ITER_prefetch, k, ({
		bool had_mismatch;
		bch2_recovery_cancelled(c) ?:
		check_bucket_backpointer_mismatch(trans, k, &had_mismatch, &s.last_flushed,
						  &last_pos, &nr_iters);
	}));
	if (ret)
		goto err;

	u64 nr_buckets = 0, nr_mismatches = 0, nr_empty = 0;
	for_each_member_device(c, ca) {
		nr_buckets	+= ca->mi.nbuckets;
		nr_mismatches	+= ca->bucket_backpointer_mismatch.nr;
		nr_empty	+= ca->bucket_backpointer_empty.nr;
	}

#ifndef CONFIG_BCACHEFS_DEBUG
	if (!nr_mismatches)
		goto err;
#endif

	bch_info(c, "scanning for missing backpointers in %llu/%llu buckets, %llu buckets with no backpointers",
		 nr_mismatches - nr_empty, nr_buckets, nr_empty);

	while (1) {
		ret = bch2_pin_backpointer_nodes_with_missing(trans, s.bp_start, &s.bp_end);
		if (ret)
			break;

		if ( bpos_eq(s.bp_start, POS_MIN) &&
		    !bpos_eq(s.bp_end, SPOS_MAX))
			bch_info(c, "%s(): alloc info does not fit in ram, running in multiple passes with %zu nodes per pass",
				 __func__, btree_nodes_fit_in_ram(c));

		if (!bpos_eq(s.bp_start, POS_MIN) ||
		    !bpos_eq(s.bp_end, SPOS_MAX)) {
			CLASS(printbuf, buf)();

			prt_str(&buf, "check_extents_to_backpointers(): ");
			bch2_bpos_to_text(&buf, s.bp_start);
			prt_str(&buf, "-");
			bch2_bpos_to_text(&buf, s.bp_end);

			bch_verbose(c, "%s", buf.buf);
		}

		ret = bch2_check_extents_to_backpointers_pass(trans, &s);
		if (ret || bpos_eq(s.bp_end, SPOS_MAX))
			break;

		s.bp_start = bpos_successor(s.bp_end);
	}

	for_each_member_device(c, ca) {
		bch2_bucket_bitmap_free(&ca->bucket_backpointer_mismatch);
		bch2_bucket_bitmap_free(&ca->bucket_backpointer_empty);
	}
err:
	wb_maybe_flush_exit(&s.last_flushed);
	bch2_btree_cache_unpin(c);
	return ret;
}

static int check_bucket_backpointer_pos_mismatch(struct btree_trans *trans,
						 struct bpos bucket,
						 bool *had_mismatch,
						 struct wb_maybe_flush *last_flushed)
{
	CLASS(btree_iter, alloc_iter)(trans, BTREE_ID_alloc, bucket, BTREE_ITER_cached);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&alloc_iter));

	struct bpos last_pos = POS_MIN;
	unsigned nr_iters = 0;
	return check_bucket_backpointer_mismatch(trans, k, had_mismatch,
						 last_flushed,
						 &last_pos, &nr_iters);
}

int bch2_check_bucket_backpointer_mismatch(struct btree_trans *trans,
					   struct bch_dev *ca, u64 bucket,
					   bool copygc,
					   struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	bool had_mismatch;
	int ret = lockrestart_do(trans,
		check_bucket_backpointer_pos_mismatch(trans, POS(ca->dev_idx, bucket),
						      &had_mismatch, last_flushed));
	if (ret || !had_mismatch)
		return ret;

	u64 nr = ca->bucket_backpointer_mismatch.nr;
	u64 allowed = copygc ? ca->mi.nbuckets >> 7 : 0;

	CLASS(printbuf, buf)();
	__bch2_log_msg_start(ca->name, &buf);

	prt_printf(&buf, "Detected missing backpointers in bucket %llu, now have %llu/%llu with missing\n",
		   bucket, nr, ca->mi.nbuckets);

	bch2_run_explicit_recovery_pass(c, &buf,
			BCH_RECOVERY_PASS_check_extents_to_backpointers,
			nr < allowed ? RUN_RECOVERY_PASS_ratelimit : 0);

	bch2_print_str(c, KERN_ERR, buf.buf);
	return 0;
}

/* backpointers -> extents */

static int check_one_backpointer(struct btree_trans *trans,
				 struct bbpos start,
				 struct bbpos end,
				 struct bkey_s_c_backpointer bp,
				 struct wb_maybe_flush *last_flushed)
{
	struct bbpos pos = bp_to_bbpos(*bp.v);

	if (bbpos_cmp(pos, start) < 0 ||
	    bbpos_cmp(pos, end) > 0)
		return 0;

	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bch2_backpointer_get_key(trans, bp, &iter, 0, last_flushed);
	int ret = bkey_err(k);
	return ret == -BCH_ERR_backpointer_to_overwritten_btree_node
		? 0
		: ret;
}

static int check_bucket_backpointers_to_extents(struct btree_trans *trans,
						struct bch_dev *ca, struct bpos bucket,
						struct wb_maybe_flush *last_flushed)
{
	u32 restart_count = trans->restart_count;

	int ret = backpointer_scan_for_each(trans, iter, BTREE_ID_backpointers,
			bucket_pos_to_bp_start(ca, bucket),
			bucket_pos_to_bp_end(ca, bucket),
			last_flushed, NULL, bp,
		check_one_backpointer(trans, BBPOS_MIN, BBPOS_MAX, bp, last_flushed));

	return ret ?:
		bch2_btree_write_buffer_flush_sync(trans) ?: /* make sure bad backpointers that were deleted are visible */
		trans_was_restarted(trans, restart_count);
}

static int bch2_check_backpointers_to_extents_pass(struct btree_trans *trans,
						   struct bbpos start,
						   struct bbpos end)
{
	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct progress_indicator progress;
	bch2_progress_init(&progress, "backpointers_to_extents", trans->c,
			   BIT_ULL(BTREE_ID_backpointers)|
			   BIT_ULL(BTREE_ID_stripe_backpointers), 0);

	try(backpointer_scan_for_each(trans, iter, BTREE_ID_backpointers,
				      POS_MIN, POS_MAX,
			&last_flushed, &progress, bp,
		check_one_backpointer(trans, start, end, bp, &last_flushed)));

	try(backpointer_scan_for_each(trans, iter, BTREE_ID_stripe_backpointers,
				      POS_MIN, POS_MAX,
			&last_flushed, &progress, bp,
		check_one_backpointer(trans, start, end, bp, &last_flushed)));

	return 0;
}

int bch2_check_backpointers_to_extents(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	struct bbpos start = (struct bbpos) { .btree = 0, .pos = POS_MIN, }, end;
	int ret;

	while (1) {
		ret = bch2_get_btree_in_memory_pos(trans,
						   BIT_ULL(BTREE_ID_extents)|
						   BIT_ULL(BTREE_ID_reflink),
						   ~0,
						   start, &end);
		if (ret)
			break;

		if (!bbpos_cmp(start, BBPOS_MIN) &&
		    bbpos_cmp(end, BBPOS_MAX))
			bch_verbose(c, "%s(): extents do not fit in ram, running in multiple passes with %zu nodes per pass",
				    __func__, btree_nodes_fit_in_ram(c));

		if (bbpos_cmp(start, BBPOS_MIN) ||
		    bbpos_cmp(end, BBPOS_MAX)) {
			CLASS(printbuf, buf)();

			prt_str(&buf, "check_backpointers_to_extents(): ");
			bch2_bbpos_to_text(&buf, start);
			prt_str(&buf, "-");
			bch2_bbpos_to_text(&buf, end);

			bch_verbose(c, "%s", buf.buf);
		}

		ret = bch2_check_backpointers_to_extents_pass(trans, start, end);
		if (ret || !bbpos_cmp(end, BBPOS_MAX))
			break;

		start = bbpos_successor(end);
	}

	bch2_btree_cache_unpin(c);
	return ret;
}

static int bkey_i_backpointer_cmp(const void *_l, const void *_r)
{
	const struct bkey_i_backpointer *l = _l;
	const struct bkey_i_backpointer *r = _r;
	struct bbpos l_pos = BBPOS(l->v.btree_id, l->v.pos);
	struct bbpos r_pos = BBPOS(r->v.btree_id, r->v.pos);

	/* Sort in reverse order, we'll be iterating in reverse order */
	return -bbpos_cmp(l_pos, r_pos);
}

struct bkey_s_c_backpointer bch2_bp_scan_iter_peek(struct btree_trans *trans,
						   struct bp_scan_iter *iter, struct bpos end,
						   struct wb_maybe_flush *last_flushed)
{
	if (iter->nr_flushes != last_flushed->nr_flushes) {
		if (iter->bps.nr) {
			struct bkey_i_backpointer *prev = &darray_last(iter->bps);

			CLASS(btree_iter, bp_iter)(trans, iter->btree, prev->k.p, 0);
			struct bkey_s_c k;
			int ret = bkey_err(k = bch2_btree_iter_peek_slot(&bp_iter));
			if (bkey_err(k))
				return (struct bkey_s_c_backpointer) { .k = ERR_PTR(ret) };

			if (k.k->type == KEY_TYPE_backpointer)
				bkey_reassemble(&prev->k_i, k);
			else
				--iter->bps.nr;
		}

		iter->nr_flushes = last_flushed->nr_flushes;
	}

	if (!iter->bps.nr) {
		size_t limit = (system_totalram_bytes() / 16) /
			sizeof(struct bkey_i_backpointer);

		u32 restart_count = trans->restart_count;

		int ret = for_each_btree_key_max(trans, bp_iter, iter->btree,
					   iter->pos, end, BTREE_ITER_prefetch, k, ({
			if (k.k->type != KEY_TYPE_backpointer)
				continue;

			/* XXX: this is a really big allocation, we should drop
			 * srcu lock */

			struct bkey_i_backpointer bp;
			bkey_reassemble(&bp.k_i, k);
			if (iter->bps.nr > limit ||
			    darray_push_gfp(&iter->bps, bp, GFP_KERNEL|__GFP_NOWARN))
				break;

			iter->pos = bpos_nosnap_successor(k.k->p);
			(iter->progress
			 ? bch2_progress_update_iter(trans, iter->progress, &bp_iter)
			 : 0);
		}));

		if (ret)
			return ((struct bkey_s_c_backpointer) { .k = ERR_PTR(ret) });

		if (!iter->bps.nr)
			return (struct bkey_s_c_backpointer) {};

		bch2_trans_unlock_long(trans);
		darray_sort(iter->bps, bkey_i_backpointer_cmp);
		bch2_trans_begin(trans);
		trans->restart_count = restart_count;
	}

	return backpointer_i_to_s_c(&darray_last(iter->bps));
}

static int bch2_bucket_bitmap_set(struct bch_dev *ca, struct bucket_bitmap *b, u64 bit)
{
	scoped_guard(mutex, &b->lock) {
		if (!b->buckets) {
			b->buckets = kvcalloc(BITS_TO_LONGS(ca->mi.nbuckets),
					      sizeof(unsigned long), GFP_KERNEL);
			if (!b->buckets)
				return bch_err_throw(ca->fs, ENOMEM_backpointer_mismatches_bitmap);
		}

		b->nr += !__test_and_set_bit(bit, b->buckets);
	}

	return 0;
}

int bch2_bucket_bitmap_resize(struct bch_dev *ca, struct bucket_bitmap *b,
			      u64 old_size, u64 new_size)
{
	scoped_guard(mutex, &b->lock) {
		if (!b->buckets)
			return 0;

		unsigned long *n = kvcalloc(BITS_TO_LONGS(new_size),
					    sizeof(unsigned long), GFP_KERNEL);
		if (!n)
			return bch_err_throw(ca->fs, ENOMEM_backpointer_mismatches_bitmap);

		memcpy(n, b->buckets,
		       BITS_TO_LONGS(min(old_size, new_size)) * sizeof(unsigned long));
		kvfree(b->buckets);
		b->buckets = n;
	}

	return 0;
}

void bch2_bucket_bitmap_free(struct bucket_bitmap *b)
{
	mutex_lock(&b->lock);
	kvfree(b->buckets);
	b->buckets = NULL;
	b->nr	= 0;
	mutex_unlock(&b->lock);
}
