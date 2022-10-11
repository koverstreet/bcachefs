// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "bbpos.h"
#include "alloc_background.h"
#include "backpointers.h"
#include "btree_cache.h"
#include "btree_update.h"
#include "error.h"

#include <linux/mm.h>

#define MAX_EXTENT_COMPRESS_RATIO_SHIFT		10

/*
 * Convert from pos in backpointer btree to pos of corresponding bucket in alloc
 * btree:
 */
static inline struct bpos bp_pos_to_bucket(const struct bch_fs *c,
					   struct bpos bp_pos)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, bp_pos.inode);
	u64 bucket_sector = bp_pos.offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT;

	return POS(bp_pos.inode, sector_to_bucket(ca, bucket_sector));
}

/*
 * Convert from pos in alloc btree + bucket offset to pos in backpointer btree:
 */
static inline struct bpos bucket_pos_to_bp(const struct bch_fs *c,
					   struct bpos bucket,
					   u64 bucket_offset)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, bucket.inode);
	struct bpos ret;

	ret = POS(bucket.inode,
		  (bucket_to_sector(ca, bucket.offset) <<
		   MAX_EXTENT_COMPRESS_RATIO_SHIFT) + bucket_offset);

	BUG_ON(bkey_cmp(bucket, bp_pos_to_bucket(c, ret)));

	return ret;
}

void bch2_extent_ptr_to_bp(struct bch_fs *c,
			   enum btree_id btree_id, unsigned level,
			   struct bkey_s_c k, struct extent_ptr_decoded p,
			   struct bpos *bucket_pos, struct bch_backpointer *bp)
{
	enum bch_data_type data_type = level ? BCH_DATA_btree : BCH_DATA_user;
	s64 sectors = level ? btree_sectors(c) : k.k->size;
	u32 bucket_offset;

	*bucket_pos = PTR_BUCKET_POS_OFFSET(c, &p.ptr, &bucket_offset);
	*bp = (struct bch_backpointer) {
		.btree_id	= btree_id,
		.level		= level,
		.data_type	= data_type,
		.bucket_offset	= ((u64) bucket_offset << MAX_EXTENT_COMPRESS_RATIO_SHIFT) +
			p.crc.offset,
		.bucket_len	= ptr_disk_sectors(sectors, p),
		.pos		= k.k->p,
	};
}

static bool extent_matches_bp(struct bch_fs *c,
			      enum btree_id btree_id, unsigned level,
			      struct bkey_s_c k,
			      struct bpos bucket,
			      struct bch_backpointer bp)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bpos bucket2;
		struct bch_backpointer bp2;

		if (p.ptr.cached)
			continue;

		bch2_extent_ptr_to_bp(c, btree_id, level, k, p,
				      &bucket2, &bp2);
		if (!bpos_cmp(bucket, bucket2) &&
		    !memcmp(&bp, &bp2, sizeof(bp)))
			return true;
	}

	return false;
}

int bch2_backpointer_invalid(const struct bch_fs *c, struct bkey_s_c k,
			     int rw, struct printbuf *err)
{
	struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);
	struct bpos bucket = bp_pos_to_bucket(c, bp.k->p);

	if (bkey_val_bytes(bp.k) < sizeof(*bp.v)) {
		prt_str(err, "incorrect value size");
		return -EINVAL;
	}

	if (bpos_cmp(bp.k->p, bucket_pos_to_bp(c, bucket, bp.v->bucket_offset))) {
		prt_str(err, "backpointer at wrong pos");
		return -EINVAL;
	}

	return 0;
}

void bch2_backpointer_to_text(struct printbuf *out, const struct bch_backpointer *bp)
{
	prt_printf(out, "btree=%s l=%u offset=%llu:%u len=%u pos=",
	       bch2_btree_ids[bp->btree_id],
	       bp->level,
	       (u64) (bp->bucket_offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT),
	       (u32) bp->bucket_offset & ~(~0U << MAX_EXTENT_COMPRESS_RATIO_SHIFT),
	       bp->bucket_len);
	bch2_bpos_to_text(out, bp->pos);
}

void bch2_backpointer_k_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	bch2_backpointer_to_text(out, bkey_s_c_to_backpointer(k).v);
}

void bch2_backpointer_swab(struct bkey_s k)
{
	struct bkey_s_backpointer bp = bkey_s_to_backpointer(k);

	bp.v->bucket_offset	= swab32(bp.v->bucket_offset);
	bp.v->bucket_len	= swab32(bp.v->bucket_len);
	bch2_bpos_swab(&bp.v->pos);
}

#define BACKPOINTER_OFFSET_MAX	((1ULL << 40) - 1)

static inline int backpointer_cmp(struct bch_backpointer l, struct bch_backpointer r)
{
	return cmp_int(l.bucket_offset, r.bucket_offset);
}

static int bch2_backpointer_del_by_offset(struct btree_trans *trans,
					  struct bpos bucket,
					  u64 bp_offset,
					  struct bch_backpointer bp)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	if (bp_offset < BACKPOINTER_OFFSET_MAX) {
		struct bch_backpointer *bps;
		struct bkey_i_alloc_v4 *a;
		unsigned i, nr;

		bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc,
				     bucket,
				     BTREE_ITER_INTENT|
				     BTREE_ITER_SLOTS|
				     BTREE_ITER_WITH_UPDATES);
		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_alloc_v4) {
			ret = -ENOENT;
			goto err;
		}

		a = bch2_alloc_to_v4_mut(trans, k);
		ret = PTR_ERR_OR_ZERO(a);
		if (ret)
			goto err;
		bps = alloc_v4_backpointers(&a->v);
		nr = BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v);

		for (i = 0; i < nr; i++) {
			if (bps[i].bucket_offset == bp_offset)
				goto found;
			if (bps[i].bucket_offset > bp_offset)
				break;
		}

		ret = -ENOENT;
		goto err;
found:
		if (memcmp(&bps[i], &bp, sizeof(bp))) {
			ret = -ENOENT;
			goto err;
		}
		array_remove_item(bps, nr, i);
		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v, nr);
		set_alloc_v4_u64s(a);
		ret = bch2_trans_update(trans, &iter, &a->k_i, 0);
	} else {
		bp_offset -= BACKPOINTER_OFFSET_MAX;

		bch2_trans_iter_init(trans, &iter, BTREE_ID_backpointers,
				     bucket_pos_to_bp(c, bucket, bp_offset),
				     BTREE_ITER_INTENT|
				     BTREE_ITER_SLOTS|
				     BTREE_ITER_WITH_UPDATES);
		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_backpointer ||
		    memcmp(bkey_s_c_to_backpointer(k).v, &bp, sizeof(bp))) {
			ret = -ENOENT;
			goto err;
		}

		ret = bch2_btree_delete_at(trans, &iter, 0);
	}
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_bucket_backpointer_del(struct btree_trans *trans,
				struct bkey_i_alloc_v4 *a,
				struct bch_backpointer bp,
				struct bkey_s_c orig_k)
{
	struct bch_fs *c = trans->c;
	struct bch_backpointer *bps = alloc_v4_backpointers(&a->v);
	unsigned i, nr = BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v);
	struct btree_iter bp_iter;
	struct bkey_s_c k;
	int ret;

	for (i = 0; i < nr; i++) {
		int cmp = backpointer_cmp(bps[i], bp) ?:
			memcmp(&bps[i], &bp, sizeof(bp));
		if (!cmp)
			goto found;
		if (cmp >= 0)
			break;
	}

	goto btree;
found:
	array_remove_item(bps, nr, i);
	SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v, nr);
	set_alloc_v4_u64s(a);
	return 0;
btree:
	bch2_trans_iter_init(trans, &bp_iter, BTREE_ID_backpointers,
			     bucket_pos_to_bp(c, a->k.p, bp.bucket_offset),
			     BTREE_ITER_INTENT|
			     BTREE_ITER_SLOTS|
			     BTREE_ITER_WITH_UPDATES);
	k = bch2_btree_iter_peek_slot(&bp_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_backpointer ||
	    memcmp(bkey_s_c_to_backpointer(k).v, &bp, sizeof(bp))) {
		struct printbuf buf = PRINTBUF;

		prt_printf(&buf, "backpointer not found when deleting");
		prt_newline(&buf);
		printbuf_indent_add(&buf, 2);

		prt_printf(&buf, "searching for ");
		bch2_backpointer_to_text(&buf, &bp);
		prt_newline(&buf);

		prt_printf(&buf, "got ");
		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);

		prt_str(&buf, "alloc ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&a->k_i));
		prt_newline(&buf);

		prt_printf(&buf, "for ");
		bch2_bkey_val_to_text(&buf, c, orig_k);

		if (!test_bit(BCH_FS_CHECK_BACKPOINTERS_DONE, &c->flags)) {
			bch_err(c, "%s", buf.buf);
		} else {
			ret = -EIO;
			bch2_trans_inconsistent(trans, "%s", buf.buf);
		}
		printbuf_exit(&buf);
		goto err;
	}

	ret = bch2_btree_delete_at(trans, &bp_iter, 0);
err:
	bch2_trans_iter_exit(trans, &bp_iter);
	return ret;
}

int bch2_bucket_backpointer_add(struct btree_trans *trans,
				struct bkey_i_alloc_v4 *a,
				struct bch_backpointer bp,
				struct bkey_s_c orig_k)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca;
	struct bch_backpointer *bps = alloc_v4_backpointers(&a->v);
	unsigned i, nr = BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v);
	struct bkey_i_backpointer *bp_k;
	struct btree_iter bp_iter;
	struct bkey_s_c k;
	int ret;

	/* Check for duplicates: */
	for (i = 0; i < nr; i++) {
		int cmp = backpointer_cmp(bps[i], bp);
		if (cmp >= 0)
			break;
	}

	if ((i &&
	     (bps[i - 1].bucket_offset +
	      bps[i - 1].bucket_len > bp.bucket_offset)) ||
	    (i < nr &&
	     (bp.bucket_offset + bp.bucket_len > bps[i].bucket_offset))) {
		struct printbuf buf = PRINTBUF;

		prt_printf(&buf, "overlapping backpointer found when inserting ");
		bch2_backpointer_to_text(&buf, &bp);
		prt_newline(&buf);
		printbuf_indent_add(&buf, 2);

		prt_printf(&buf, "into ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&a->k_i));
		prt_newline(&buf);

		prt_printf(&buf, "for ");
		bch2_bkey_val_to_text(&buf, c, orig_k);

		if (!test_bit(BCH_FS_CHECK_BACKPOINTERS_DONE, &c->flags))
			bch_err(c, "%s", buf.buf);
		else {
			bch2_trans_inconsistent(trans, "%s", buf.buf);
			printbuf_exit(&buf);
			return -EIO;
		}
	}

	if (nr < BCH_ALLOC_V4_NR_BACKPOINTERS_MAX) {
		array_insert_item(bps, nr, i, bp);
		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v, nr);
		set_alloc_v4_u64s(a);
		return 0;
	}

	/* Overflow: use backpointer btree */
	bp_k = bch2_trans_kmalloc(trans, sizeof(*bp_k));
	ret = PTR_ERR_OR_ZERO(bp_k);
	if (ret)
		return ret;

	ca = bch_dev_bkey_exists(c, a->k.p.inode);

	bkey_backpointer_init(&bp_k->k_i);
	bp_k->k.p = bucket_pos_to_bp(c, a->k.p, bp.bucket_offset);
	bp_k->v = bp;

	bch2_trans_iter_init(trans, &bp_iter, BTREE_ID_backpointers, bp_k->k.p,
			     BTREE_ITER_INTENT|
			     BTREE_ITER_SLOTS|
			     BTREE_ITER_WITH_UPDATES);
	k = bch2_btree_iter_peek_slot(&bp_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type) {
		struct printbuf buf = PRINTBUF;

		prt_printf(&buf, "existing btree backpointer key found when inserting ");
		bch2_backpointer_to_text(&buf, &bp);
		prt_newline(&buf);
		printbuf_indent_add(&buf, 2);

		prt_printf(&buf, "found ");
		bch2_bkey_val_to_text(&buf, c, k);
		prt_newline(&buf);

		prt_printf(&buf, "for ");
		bch2_bkey_val_to_text(&buf, c, orig_k);

		if (!test_bit(BCH_FS_CHECK_BACKPOINTERS_DONE, &c->flags))
			bch_err(c, "%s", buf.buf);
		else {
			bch2_trans_inconsistent(trans, "%s", buf.buf);
			printbuf_exit(&buf);
			ret = -EIO;
			goto err;
		}
	}

	ret = bch2_trans_update(trans, &bp_iter, &bp_k->k_i, 0);
err:
	bch2_trans_iter_exit(trans, &bp_iter);
	return ret;
}

/*
 * Find the next backpointer >= *bp_offset:
 */
int bch2_get_next_backpointer(struct btree_trans *trans,
			      struct bpos bucket, int gen,
			      u64 *bp_offset,
			      struct bch_backpointer *dst)
{
	struct bch_fs *c = trans->c;
	struct bpos bp_pos, bp_end_pos;
	struct btree_iter alloc_iter, bp_iter = { NULL };
	struct bkey_s_c k;
	struct bkey_s_c_alloc_v4 a;
	size_t i;
	int ret;

	if (*bp_offset == U64_MAX)
		return 0;

	bp_pos = bucket_pos_to_bp(c, bucket,
				  max(*bp_offset, BACKPOINTER_OFFSET_MAX) - BACKPOINTER_OFFSET_MAX);
	bp_end_pos = bucket_pos_to_bp(c, bpos_nosnap_successor(bucket), 0);

	bch2_trans_iter_init(trans, &alloc_iter, BTREE_ID_alloc,
			     bucket, BTREE_ITER_CACHED);
	k = bch2_btree_iter_peek_slot(&alloc_iter);
	ret = bkey_err(k);
	if (ret)
		goto out;

	if (k.k->type != KEY_TYPE_alloc_v4)
		goto done;

	a = bkey_s_c_to_alloc_v4(k);
	if (gen >= 0 && a.v->gen != gen)
		goto done;

	for (i = 0; i < BCH_ALLOC_V4_NR_BACKPOINTERS(a.v); i++) {
		if (alloc_v4_backpointers_c(a.v)[i].bucket_offset < *bp_offset)
			continue;

		*dst = alloc_v4_backpointers_c(a.v)[i];
		*bp_offset = dst->bucket_offset;
		goto out;
	}

	for_each_btree_key_norestart(trans, bp_iter, BTREE_ID_backpointers,
				     bp_pos, 0, k, ret) {
		if (bpos_cmp(k.k->p, bp_end_pos) >= 0)
			break;

		if (k.k->type != KEY_TYPE_backpointer)
			continue;

		*dst = *bkey_s_c_to_backpointer(k).v;
		*bp_offset = dst->bucket_offset + BACKPOINTER_OFFSET_MAX;
		goto out;
	}
done:
	*bp_offset = U64_MAX;
out:
	bch2_trans_iter_exit(trans, &bp_iter);
	bch2_trans_iter_exit(trans, &alloc_iter);
	return ret;
}

static void backpointer_not_found(struct btree_trans *trans,
				  struct bpos bucket,
				  u64 bp_offset,
				  struct bch_backpointer bp,
				  struct bkey_s_c k,
				  const char *thing_it_points_to)
{
	struct bch_fs *c = trans->c;
	struct printbuf buf = PRINTBUF;

	prt_printf(&buf, "backpointer doesn't match %s it points to:\n  ",
		   thing_it_points_to);
	prt_printf(&buf, "bucket: ");
	bch2_bpos_to_text(&buf, bucket);
	prt_printf(&buf, "\n  ");

	if (bp_offset >= BACKPOINTER_OFFSET_MAX) {
		struct bpos bp_pos =
			bucket_pos_to_bp(c, bucket,
					bp_offset - BACKPOINTER_OFFSET_MAX);
		prt_printf(&buf, "backpointer pos: ");
		bch2_bpos_to_text(&buf, bp_pos);
		prt_printf(&buf, "\n  ");
	}

	bch2_backpointer_to_text(&buf, &bp);
	prt_printf(&buf, "\n  ");
	bch2_bkey_val_to_text(&buf, c, k);
	if (!test_bit(BCH_FS_CHECK_BACKPOINTERS_DONE, &c->flags))
		bch_err_ratelimited(c, "%s", buf.buf);
	else
		bch2_trans_inconsistent(trans, "%s", buf.buf);

	printbuf_exit(&buf);
}

struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *trans,
					 struct btree_iter *iter,
					 struct bpos bucket,
					 u64 bp_offset,
					 struct bch_backpointer bp)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;

	bch2_trans_node_iter_init(trans, iter,
				  bp.btree_id,
				  bp.pos,
				  0,
				  min(bp.level, c->btree_roots[bp.btree_id].level),
				  0);
	k = bch2_btree_iter_peek_slot(iter);
	if (bkey_err(k)) {
		bch2_trans_iter_exit(trans, iter);
		return k;
	}

	if (bp.level == c->btree_roots[bp.btree_id].level + 1)
		k = bkey_i_to_s_c(&c->btree_roots[bp.btree_id].key);

	if (extent_matches_bp(c, bp.btree_id, bp.level, k, bucket, bp))
		return k;

	bch2_trans_iter_exit(trans, iter);

	if (bp.level) {
		struct btree *b;

		/*
		 * If a backpointer for a btree node wasn't found, it may be
		 * because it was overwritten by a new btree node that hasn't
		 * been written out yet - backpointer_get_node() checks for
		 * this:
		 */
		b = bch2_backpointer_get_node(trans, iter, bucket, bp_offset, bp);
		if (!IS_ERR_OR_NULL(b))
			return bkey_i_to_s_c(&b->key);

		bch2_trans_iter_exit(trans, iter);

		if (IS_ERR(b))
			return bkey_s_c_err(PTR_ERR(b));
		return bkey_s_c_null;
	}

	backpointer_not_found(trans, bucket, bp_offset, bp, k, "extent");
	return bkey_s_c_null;
}

struct btree *bch2_backpointer_get_node(struct btree_trans *trans,
					struct btree_iter *iter,
					struct bpos bucket,
					u64 bp_offset,
					struct bch_backpointer bp)
{
	struct bch_fs *c = trans->c;
	struct btree *b;

	BUG_ON(!bp.level);

	bch2_trans_node_iter_init(trans, iter,
				  bp.btree_id,
				  bp.pos,
				  0,
				  bp.level - 1,
				  0);
	b = bch2_btree_iter_peek_node(iter);
	if (IS_ERR(b))
		goto err;

	if (extent_matches_bp(c, bp.btree_id, bp.level,
			      bkey_i_to_s_c(&b->key),
			      bucket, bp))
		return b;

	if (btree_node_will_make_reachable(b)) {
		b = ERR_PTR(-BCH_ERR_backpointer_to_overwritten_btree_node);
	} else {
		backpointer_not_found(trans, bucket, bp_offset, bp,
				      bkey_i_to_s_c(&b->key), "btree node");
		b = NULL;
	}
err:
	bch2_trans_iter_exit(trans, iter);
	return b;
}

static int bch2_check_btree_backpointer(struct btree_trans *trans, struct btree_iter *bp_iter,
					struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct btree_iter alloc_iter = { NULL };
	struct bch_dev *ca;
	struct bkey_s_c alloc_k;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	if (fsck_err_on(!bch2_dev_exists2(c, k.k->p.inode), c,
			"backpointer for mising device:\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		ret = bch2_btree_delete_at(trans, bp_iter, 0);
		goto out;
	}

	ca = bch_dev_bkey_exists(c, k.k->p.inode);

	bch2_trans_iter_init(trans, &alloc_iter, BTREE_ID_alloc,
			     bp_pos_to_bucket(c, k.k->p), 0);

	alloc_k = bch2_btree_iter_peek_slot(&alloc_iter);
	ret = bkey_err(alloc_k);
	if (ret)
		goto out;

	if (fsck_err_on(alloc_k.k->type != KEY_TYPE_alloc_v4, c,
			"backpointer for nonexistent alloc key: %llu:%llu:0\n%s",
			alloc_iter.pos.inode, alloc_iter.pos.offset,
			(bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		ret = bch2_btree_delete_at(trans, bp_iter, 0);
		goto out;
	}
out:
fsck_err:
	bch2_trans_iter_exit(trans, &alloc_iter);
	printbuf_exit(&buf);
	return ret;
}

/* verify that every backpointer has a corresponding alloc key */
int bch2_check_btree_backpointers(struct bch_fs *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	return bch2_trans_run(c,
		for_each_btree_key_commit(&trans, iter,
			BTREE_ID_backpointers, POS_MIN, 0, k,
			NULL, NULL, BTREE_INSERT_LAZY_RW|BTREE_INSERT_NOFAIL,
		  bch2_check_btree_backpointer(&trans, &iter, k)));
}

static int check_bp_exists(struct btree_trans *trans,
			   struct bpos bucket_pos,
			   struct bch_backpointer bp,
			   struct bkey_s_c orig_k,
			   struct bpos bucket_start,
			   struct bpos bucket_end)
{
	struct bch_fs *c = trans->c;
	struct btree_iter alloc_iter, bp_iter = { NULL };
	struct printbuf buf = PRINTBUF;
	struct bkey_s_c alloc_k, bp_k;
	int ret;

	if (bpos_cmp(bucket_pos, bucket_start) < 0 ||
	    bpos_cmp(bucket_pos, bucket_end) > 0)
		return 0;

	bch2_trans_iter_init(trans, &alloc_iter, BTREE_ID_alloc, bucket_pos, 0);
	alloc_k = bch2_btree_iter_peek_slot(&alloc_iter);
	ret = bkey_err(alloc_k);
	if (ret)
		goto err;

	if (alloc_k.k->type == KEY_TYPE_alloc_v4) {
		struct bkey_s_c_alloc_v4 a = bkey_s_c_to_alloc_v4(alloc_k);
		const struct bch_backpointer *bps = alloc_v4_backpointers_c(a.v);
		unsigned i, nr = BCH_ALLOC_V4_NR_BACKPOINTERS(a.v);

		for (i = 0; i < nr; i++) {
			int cmp = backpointer_cmp(bps[i], bp) ?:
				memcmp(&bps[i], &bp, sizeof(bp));
			if (!cmp)
				goto out;
			if (cmp >= 0)
				break;
		}
	} else {
		goto missing;
	}

	bch2_trans_iter_init(trans, &bp_iter, BTREE_ID_backpointers,
			     bucket_pos_to_bp(c, bucket_pos, bp.bucket_offset),
			     0);
	bp_k = bch2_btree_iter_peek_slot(&bp_iter);
	ret = bkey_err(bp_k);
	if (ret)
		goto err;

	if (bp_k.k->type != KEY_TYPE_backpointer ||
	    memcmp(bkey_s_c_to_backpointer(bp_k).v, &bp, sizeof(bp)))
		goto missing;
out:
err:
fsck_err:
	bch2_trans_iter_exit(trans, &bp_iter);
	bch2_trans_iter_exit(trans, &alloc_iter);
	printbuf_exit(&buf);
	return ret;
missing:
	prt_printf(&buf, "missing backpointer for btree=%s l=%u ",
	       bch2_btree_ids[bp.btree_id], bp.level);
	bch2_bkey_val_to_text(&buf, c, orig_k);
	prt_printf(&buf, "\nin alloc key ");
	bch2_bkey_val_to_text(&buf, c, alloc_k);

	if (c->sb.version < bcachefs_metadata_version_backpointers ||
	    c->opts.reconstruct_alloc ||
	    fsck_err(c, "%s", buf.buf)) {
		struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut(trans, alloc_k);

		ret   = PTR_ERR_OR_ZERO(a) ?:
			bch2_bucket_backpointer_add(trans, a, bp, orig_k) ?:
			bch2_trans_update(trans, &alloc_iter, &a->k_i, 0);
	}

	goto out;
}

static int check_extent_to_backpointers(struct btree_trans *trans,
					struct btree_iter *iter,
					struct bpos bucket_start,
					struct bpos bucket_end)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	struct bkey_s_c k;
	int ret;

	k = bch2_btree_iter_peek_all_levels(iter);
	ret = bkey_err(k);
	if (ret)
		return ret;
	if (!k.k)
		return 0;

	ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bpos bucket_pos;
		struct bch_backpointer bp;

		if (p.ptr.cached)
			continue;

		bch2_extent_ptr_to_bp(c, iter->btree_id, iter->path->level,
				      k, p, &bucket_pos, &bp);

		ret = check_bp_exists(trans, bucket_pos, bp, k, bucket_start, bucket_end);
		if (ret)
			return ret;
	}

	return 0;
}

static int check_btree_root_to_backpointers(struct btree_trans *trans,
					    enum btree_id btree_id,
					    struct bpos bucket_start,
					    struct bpos bucket_end)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct btree *b;
	struct bkey_s_c k;
	struct bkey_ptrs_c ptrs;
	struct extent_ptr_decoded p;
	const union bch_extent_entry *entry;
	int ret;

	bch2_trans_node_iter_init(trans, &iter, btree_id, POS_MIN, 0,
				  c->btree_roots[btree_id].level, 0);
	b = bch2_btree_iter_peek_node(&iter);
	ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		goto err;

	BUG_ON(b != btree_node_root(c, b));

	k = bkey_i_to_s_c(&b->key);
	ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bpos bucket_pos;
		struct bch_backpointer bp;

		if (p.ptr.cached)
			continue;

		bch2_extent_ptr_to_bp(c, iter.btree_id, iter.path->level + 1,
				      k, p, &bucket_pos, &bp);

		ret = check_bp_exists(trans, bucket_pos, bp, k, bucket_start, bucket_end);
		if (ret)
			goto err;
	}
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static inline struct bbpos bp_to_bbpos(struct bch_backpointer bp)
{
	return (struct bbpos) {
		.btree	= bp.btree_id,
		.pos	= bp.pos,
	};
}

static size_t btree_nodes_fit_in_ram(struct bch_fs *c)
{
	struct sysinfo i;
	u64 mem_bytes;

	si_meminfo(&i);
	mem_bytes = i.totalram * i.mem_unit;
	return (mem_bytes >> 1) / btree_bytes(c);
}

int bch2_get_btree_in_memory_pos(struct btree_trans *trans,
				 unsigned btree_leaf_mask,
				 unsigned btree_interior_mask,
				 struct bbpos start, struct bbpos *end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	size_t btree_nodes = btree_nodes_fit_in_ram(trans->c);
	enum btree_id btree;
	int ret = 0;

	for (btree = start.btree; btree < BTREE_ID_NR && !ret; btree++) {
		unsigned depth = ((1U << btree) & btree_leaf_mask) ? 1 : 2;

		if (!((1U << btree) & btree_leaf_mask) &&
		    !((1U << btree) & btree_interior_mask))
			continue;

		bch2_trans_node_iter_init(trans, &iter, btree,
					  btree == start.btree ? start.pos : POS_MIN,
					  0, depth, 0);
		/*
		 * for_each_btree_key_contineu() doesn't check the return value
		 * from bch2_btree_iter_advance(), which is needed when
		 * iterating over interior nodes where we'll see keys at
		 * SPOS_MAX:
		 */
		do {
			k = __bch2_btree_iter_peek_and_restart(trans, &iter, 0);
			ret = bkey_err(k);
			if (!k.k || ret)
				break;

			--btree_nodes;
			if (!btree_nodes) {
				*end = BBPOS(btree, k.k->p);
				bch2_trans_iter_exit(trans, &iter);
				return 0;
			}
		} while (bch2_btree_iter_advance(&iter));
		bch2_trans_iter_exit(trans, &iter);
	}

	*end = BBPOS_MAX;
	return ret;
}

static int bch2_check_extents_to_backpointers_pass(struct btree_trans *trans,
						   struct bpos bucket_start,
						   struct bpos bucket_end)
{
	struct btree_iter iter;
	enum btree_id btree_id;
	int ret = 0;

	for (btree_id = 0; btree_id < BTREE_ID_NR; btree_id++) {
		unsigned depth = btree_type_has_ptrs(btree_id) ? 0 : 1;

		bch2_trans_node_iter_init(trans, &iter, btree_id, POS_MIN, 0,
					  depth,
					  BTREE_ITER_ALL_LEVELS|
					  BTREE_ITER_PREFETCH);

		do {
			ret = commit_do(trans, NULL, NULL,
					BTREE_INSERT_LAZY_RW|
					BTREE_INSERT_NOFAIL,
					check_extent_to_backpointers(trans, &iter,
								bucket_start, bucket_end));
			if (ret)
				break;
		} while (!bch2_btree_iter_advance(&iter));

		bch2_trans_iter_exit(trans, &iter);

		if (ret)
			break;

		ret = commit_do(trans, NULL, NULL,
				BTREE_INSERT_LAZY_RW|
				BTREE_INSERT_NOFAIL,
				check_btree_root_to_backpointers(trans, btree_id,
							bucket_start, bucket_end));
		if (ret)
			break;
	}
	return ret;
}

int bch2_get_alloc_in_memory_pos(struct btree_trans *trans,
				 struct bpos start, struct bpos *end)
{
	struct btree_iter alloc_iter;
	struct btree_iter bp_iter;
	struct bkey_s_c alloc_k, bp_k;
	size_t btree_nodes = btree_nodes_fit_in_ram(trans->c);
	bool alloc_end = false, bp_end = false;
	int ret = 0;

	bch2_trans_node_iter_init(trans, &alloc_iter, BTREE_ID_alloc,
				  start, 0, 1, 0);
	bch2_trans_node_iter_init(trans, &bp_iter, BTREE_ID_backpointers,
				  bucket_pos_to_bp(trans->c, start, 0), 0, 1, 0);
	while (1) {
		alloc_k = !alloc_end
			? __bch2_btree_iter_peek_and_restart(trans, &alloc_iter, 0)
			: bkey_s_c_null;
		bp_k = !bp_end
			? __bch2_btree_iter_peek_and_restart(trans, &bp_iter, 0)
			: bkey_s_c_null;

		ret = bkey_err(alloc_k) ?: bkey_err(bp_k);
		if ((!alloc_k.k && !bp_k.k) || ret) {
			*end = SPOS_MAX;
			break;
		}

		--btree_nodes;
		if (!btree_nodes) {
			*end = alloc_k.k->p;
			break;
		}

		if (bpos_cmp(alloc_iter.pos, SPOS_MAX) &&
		    bpos_cmp(bucket_pos_to_bp(trans->c, alloc_iter.pos, 0), bp_iter.pos) < 0) {
			if (!bch2_btree_iter_advance(&alloc_iter))
				alloc_end = true;
		} else {
			if (!bch2_btree_iter_advance(&bp_iter))
				bp_end = true;
		}
	}
	bch2_trans_iter_exit(trans, &bp_iter);
	bch2_trans_iter_exit(trans, &alloc_iter);
	return ret;
}

int bch2_check_extents_to_backpointers(struct bch_fs *c)
{
	struct btree_trans trans;
	struct bpos start = POS_MIN, end;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);
	while (1) {
		ret = bch2_get_alloc_in_memory_pos(&trans, start, &end);
		if (ret)
			break;

		if (!bpos_cmp(start, POS_MIN) && bpos_cmp(end, SPOS_MAX))
			bch_verbose(c, "check_extents_to_backpointers(): alloc info does not fit in ram,"
				    "running in multiple passes with %zu nodes per pass",
				    btree_nodes_fit_in_ram(c));

		if (bpos_cmp(start, POS_MIN) || bpos_cmp(end, SPOS_MAX)) {
			struct printbuf buf = PRINTBUF;

			prt_str(&buf, "check_extents_to_backpointers(): ");
			bch2_bpos_to_text(&buf, start);
			prt_str(&buf, "-");
			bch2_bpos_to_text(&buf, end);

			bch_verbose(c, "%s", buf.buf);
			printbuf_exit(&buf);
		}

		ret = bch2_check_extents_to_backpointers_pass(&trans, start, end);
		if (ret || !bpos_cmp(end, SPOS_MAX))
			break;

		start = bpos_successor(end);
	}
	bch2_trans_exit(&trans);

	return ret;
}

static int check_one_backpointer(struct btree_trans *trans,
				 struct bpos bucket,
				 u64 *bp_offset,
				 struct bbpos start,
				 struct bbpos end)
{
	struct btree_iter iter;
	struct bch_backpointer bp;
	struct bbpos pos;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;
	int ret;

	ret = bch2_get_next_backpointer(trans, bucket, -1, bp_offset, &bp);
	if (ret || *bp_offset == U64_MAX)
		return ret;

	pos = bp_to_bbpos(bp);
	if (bbpos_cmp(pos, start) < 0 ||
	    bbpos_cmp(pos, end) > 0)
		return 0;

	k = bch2_backpointer_get_key(trans, &iter, bucket, *bp_offset, bp);
	ret = bkey_err(k);
	if (ret == -BCH_ERR_backpointer_to_overwritten_btree_node)
		return 0;
	if (ret)
		return ret;

	if (fsck_err_on(!k.k, trans->c,
			"%s backpointer points to missing extent\n%s",
			*bp_offset < BACKPOINTER_OFFSET_MAX ? "alloc" : "btree",
			(bch2_backpointer_to_text(&buf, &bp), buf.buf))) {
		ret = bch2_backpointer_del_by_offset(trans, bucket, *bp_offset, bp);
		if (ret == -ENOENT)
			bch_err(trans->c, "backpointer at %llu not found", *bp_offset);
	}

	bch2_trans_iter_exit(trans, &iter);
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static int bch2_check_backpointers_to_extents_pass(struct btree_trans *trans,
						   struct bbpos start,
						   struct bbpos end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
			   BTREE_ITER_PREFETCH, k, ret) {
		u64 bp_offset = 0;

		while (!(ret = commit_do(trans, NULL, NULL,
					 BTREE_INSERT_LAZY_RW|
					 BTREE_INSERT_NOFAIL,
				check_one_backpointer(trans, iter.pos, &bp_offset, start, end))) &&
		       bp_offset < U64_MAX)
			bp_offset++;

		if (ret)
			break;
	}
	bch2_trans_iter_exit(trans, &iter);
	return ret < 0 ? ret : 0;
}

int bch2_check_backpointers_to_extents(struct bch_fs *c)
{
	struct btree_trans trans;
	struct bbpos start = (struct bbpos) { .btree = 0, .pos = POS_MIN, }, end;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);
	while (1) {
		ret = bch2_get_btree_in_memory_pos(&trans,
						   (1U << BTREE_ID_extents)|
						   (1U << BTREE_ID_reflink),
						   ~0,
						   start, &end);
		if (ret)
			break;

		if (!bbpos_cmp(start, BBPOS_MIN) &&
		    bbpos_cmp(end, BBPOS_MAX))
			bch_verbose(c, "check_backpointers_to_extents(): extents do not fit in ram,"
				    "running in multiple passes with %zu nodes per pass",
				    btree_nodes_fit_in_ram(c));

		if (bbpos_cmp(start, BBPOS_MIN) ||
		    bbpos_cmp(end, BBPOS_MAX)) {
			struct printbuf buf = PRINTBUF;

			prt_str(&buf, "check_backpointers_to_extents(): ");
			bch2_bbpos_to_text(&buf, start);
			prt_str(&buf, "-");
			bch2_bbpos_to_text(&buf, end);

			bch_verbose(c, "%s", buf.buf);
			printbuf_exit(&buf);
		}

		ret = bch2_check_backpointers_to_extents_pass(&trans, start, end);
		if (ret || !bbpos_cmp(end, BBPOS_MAX))
			break;

		start = bbpos_successor(end);
	}
	bch2_trans_exit(&trans);

	return ret;
}
