// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "alloc_background.h"
#include "backpointers.h"
#include "btree_update.h"
#include "error.h"

#define MAX_EXTENT_COMPRESS_RATIO_SHIFT		10

int bch2_backpointer_invalid(const struct bch_fs *c, struct bkey_s_c k,
			     int rw, struct printbuf *err)
{
	struct bkey_s_c_backpointer bp = bkey_s_c_to_backpointer(k);

	if (bkey_val_bytes(k.k) != sizeof(*bp.v)) {
		pr_buf(err, "incorrect value size");
		return -EINVAL;
	}

	return 0;
}

void bch2_backpointer_to_text(struct printbuf *out, const struct bch_backpointer *bp)
{
	pr_buf(out, "btree=%s l=%u offset=%llu:%u len=%u pos=",
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

void bch2_pointer_to_bucket_and_backpointer(struct bch_fs *c,
				 enum btree_id btree_id, unsigned level,
				 struct bkey_s_c k,
				 struct extent_ptr_decoded p,
				 struct bpos *bucket_pos,
				 struct bch_backpointer *bp)
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

static inline struct bpos backpointer_pos(struct bch_fs *c,
					  struct bpos alloc_pos,
					  unsigned bucket_offset)
{
	struct bch_dev *ca = bch_dev_bkey_exists(c, alloc_pos.inode);

	return POS(alloc_pos.inode,
		   (bucket_to_sector(ca, alloc_pos.offset) <<
		    MAX_EXTENT_COMPRESS_RATIO_SHIFT) + bucket_offset);
}

static inline int backpointer_cmp(struct bch_backpointer l, struct bch_backpointer r)
{
	return cmp_int(l.bucket_offset, r.bucket_offset);
}

static int bch2_backpointer_del_by_offset(struct btree_trans *trans,
					  struct bpos alloc_pos,
					  u64 bp_offset)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	if (bp_offset < U32_MAX) {
		struct bch_backpointer *bps;
		struct bkey_i_alloc_v4 *a;
		unsigned i, nr;

		bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc,
				     alloc_pos,
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

		return -ENOENT;
found:
		array_remove_item(bps, nr, i);
		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&a->v, nr);
		set_alloc_v4_u64s(a);
		ret = bch2_trans_update(trans, &iter, &a->k_i, 0);
	} else {
		bch2_trans_iter_init(trans, &iter, BTREE_ID_backpointers,
				     backpointer_pos(c, alloc_pos, bp_offset - U32_MAX),
				     BTREE_ITER_INTENT|
				     BTREE_ITER_SLOTS|
				     BTREE_ITER_WITH_UPDATES);
		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type == KEY_TYPE_backpointer)
			ret = bch2_btree_delete_at(trans, &iter, 0);
		else
			ret = -ENOENT;
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
			     backpointer_pos(c, a->k.p, bp.bucket_offset),
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

		pr_buf(&buf, "backpointer not found when deleting");
		pr_newline(&buf);
		pr_indent_push(&buf, 2);

		pr_buf(&buf, "searching for ");
		bch2_backpointer_to_text(&buf, &bp);
		pr_newline(&buf);

		pr_buf(&buf, "got ");
		bch2_bkey_val_to_text(&buf, c, k);
		pr_newline(&buf);

		pr_buf(&buf, "alloc ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&a->k_i));
		pr_newline(&buf);

		pr_buf(&buf, "for ");
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

		pr_buf(&buf, "overlapping backpointer found when inserting ");
		bch2_backpointer_to_text(&buf, &bp);
		pr_newline(&buf);
		pr_indent_push(&buf, 2);

		pr_buf(&buf, "into ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&a->k_i));
		pr_newline(&buf);

		pr_buf(&buf, "for ");
		bch2_bkey_val_to_text(&buf, c, orig_k);

		bch2_trans_inconsistent(trans, "%s", buf.buf);

		printbuf_exit(&buf);
		return -EIO;
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
	bp_k->k.p = backpointer_pos(c, a->k.p, bp.bucket_offset);
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

		pr_buf(&buf, "existing btree backpointer key found when inserting ");
		bch2_backpointer_to_text(&buf, &bp);
		pr_newline(&buf);
		pr_indent_push(&buf, 2);

		pr_buf(&buf, "found ");
		bch2_bkey_val_to_text(&buf, c, k);
		pr_newline(&buf);

		pr_buf(&buf, "for ");
		bch2_bkey_val_to_text(&buf, c, orig_k);

		bch2_trans_inconsistent(trans, "%s", buf.buf);

		printbuf_exit(&buf);
		ret = -EIO;
		goto err;
	}

	ret = bch2_trans_update(trans, &bp_iter, &bp_k->k_i, 0);
err:
	bch2_trans_iter_exit(trans, &bp_iter);
	return ret;
}

int bch2_get_next_backpointer(struct btree_trans *trans,
			      unsigned dev, u64 bucket, int gen,
			      u64 *bp_offset,
			      struct bch_backpointer *dst)
{
	struct bch_fs *c = trans->c;
	struct bch_dev *ca = bch_dev_bkey_exists(c, dev);
	struct bpos alloc_pos = POS(dev, bucket);
	struct bpos bp_pos =
		backpointer_pos(c, alloc_pos,
				max_t(u64, *bp_offset, U32_MAX) - U32_MAX);
	struct bpos bp_end_pos =
		backpointer_pos(c, bpos_nosnap_successor(alloc_pos), 0);
	struct btree_iter alloc_iter, bp_iter = { NULL };
	struct bkey_s_c k;
	struct bkey_s_c_alloc_v4 a;
	size_t i;
	int ret;

	bch2_trans_iter_init(trans, &alloc_iter, BTREE_ID_alloc,
			     alloc_pos,
			     BTREE_ITER_CACHED);
	k = bch2_btree_iter_peek_slot(&alloc_iter);
	ret = bkey_err(k);
	if (ret)
		goto done;

	if (k.k->type != KEY_TYPE_alloc_v4)
		goto done;

	a = bkey_s_c_to_alloc_v4(k);
	if (gen >= 0 && a.v->gen != gen)
		goto done;

	for (i = 0; i < BCH_ALLOC_V4_NR_BACKPOINTERS(a.v); i++) {
		*dst = alloc_v4_backpointers_c(a.v)[i];

		if (dst->bucket_offset < *bp_offset)
			continue;

		*bp_offset = dst->bucket_offset;
		goto out;
	}

	for_each_btree_key(trans, bp_iter, BTREE_ID_backpointers,
			   bp_pos, 0, k, ret) {
		if (bpos_cmp(k.k->p, bp_end_pos) >= 0)
			break;

		if (k.k->type != KEY_TYPE_backpointer)
			continue;

		*bp_offset = k.k->p.offset - bucket_to_sector(ca, bucket) + U32_MAX;
		*dst = *bkey_s_c_to_backpointer(k).v;
		goto out;
	}
done:
	*bp_offset = U64_MAX;
out:
	bch2_trans_iter_exit(trans, &bp_iter);
	bch2_trans_iter_exit(trans, &alloc_iter);
	return ret;
}

struct bkey_s_c __bch2_backpointer_get_key(struct btree_trans *trans,
					   struct btree_iter *iter,
					   struct bch_backpointer bp,
					   bool in_fsck)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;

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

	/* Check if key matches backpointer: */
	ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bpos bucket_pos;
		struct bch_backpointer bp2;

		bch2_pointer_to_bucket_and_backpointer(c, bp.btree_id, bp.level,
						       k, p, &bucket_pos, &bp2);
		if (!memcmp(&bp, &bp2, sizeof(bp)))
			return k;
	}

	if (!in_fsck) {
		pr_buf(&buf, "backpointer doesn't match extent it points to:\n  ");
		bch2_backpointer_to_text(&buf, &bp);
		pr_buf(&buf, "\n  ");
		bch2_bkey_val_to_text(&buf, c, k);
		bch2_trans_inconsistent(trans, "%s", buf.buf);

		bch2_trans_iter_exit(trans, iter);
	}

	printbuf_exit(&buf);
	return bkey_s_c_null;
}

struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *trans,
					 struct btree_iter *iter,
					 struct bch_backpointer bp)
{
	return __bch2_backpointer_get_key(trans, iter, bp, false);
}

struct btree *bch2_backpointer_get_node(struct btree_trans *trans,
					struct btree_iter *iter,
					struct bch_backpointer bp)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	struct btree *b;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;

	BUG_ON(!bp.level);

	bch2_trans_node_iter_init(trans, iter,
				  bp.btree_id,
				  bp.pos,
				  0,
				  bp.level - 1,
				  0);
	b = bch2_btree_iter_peek_node(iter);
	if (IS_ERR(b)) {
		bch2_trans_iter_exit(trans, iter);
		return b;
	}

	/* Check if key matches backpointer: */
	k = bkey_i_to_s_c(&b->key);
	ptrs = bch2_bkey_ptrs_c(k);
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		struct bpos bucket_pos;
		struct bch_backpointer bp2;

		bch2_pointer_to_bucket_and_backpointer(c, bp.btree_id, bp.level,
						       k, p, &bucket_pos, &bp2);
		if (!memcmp(&bp, &bp2, sizeof(bp)))
			return b;
	}

	if (btree_node_will_make_reachable(b))
		goto out;

	pr_buf(&buf, "backpointer doesn't match btree node it points to:\n  ");
	bch2_backpointer_to_text(&buf, &bp);
	pr_buf(&buf, "\n  ");
	bch2_bkey_val_to_text(&buf, c, k);
	bch2_trans_inconsistent(trans, "%s", buf.buf);
out:
	bch2_trans_iter_exit(trans, iter);
	printbuf_exit(&buf);
	return NULL;
}

static int bch2_check_backpointer(struct btree_trans *trans, struct btree_iter *bp_iter)
{
	struct bch_fs *c = trans->c;
	struct btree_iter alloc_iter = { NULL };
	struct bch_dev *ca;
	struct bkey_s_c k, alloc_k;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	k = bch2_btree_iter_peek(bp_iter);
	ret = bkey_err(k);
	if (ret)
		return ret;
	if (!k.k)
		return 0;

	if (fsck_err_on(!bch2_dev_exists2(c, k.k->p.inode), c,
			"backpointer for mising device:\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		ret = bch2_btree_delete_at(trans, bp_iter, 0);
		goto out;
	}

	ca = bch_dev_bkey_exists(c, k.k->p.inode);

	bch2_trans_iter_init(trans, &alloc_iter, BTREE_ID_alloc,
			     POS(k.k->p.inode, sector_to_bucket(ca,
						k.k->p.offset >> MAX_EXTENT_COMPRESS_RATIO_SHIFT)), 0);

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
int bch2_check_backpointers(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);
	bch2_trans_iter_init(&trans, &iter, BTREE_ID_backpointers, POS_MIN, 0);

	do {
		ret = __bch2_trans_do(&trans, NULL, NULL,
				      BTREE_INSERT_LAZY_RW|
				      BTREE_INSERT_NOFAIL,
				      bch2_check_backpointer(&trans, &iter));
		if (ret)
			break;
	} while (bch2_btree_iter_advance(&iter));

	bch2_trans_iter_exit(&trans, &iter);
	bch2_trans_exit(&trans);
	return ret;
}

/*
 * Verify that @bp exists:
 */
static int backpointer_check(struct btree_trans *trans,
			     struct bpos bucket_pos,
			     struct bch_backpointer bp,
			     struct bkey_s_c orig_k)
{
	struct bch_fs *c = trans->c;
	struct btree_iter alloc_iter, bp_iter = { NULL };
	struct printbuf buf = PRINTBUF;
	struct bkey_s_c alloc_k, bp_k;
	int ret;

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
			     backpointer_pos(c, bucket_pos, bp.bucket_offset),
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
	pr_buf(&buf, "missing backpointer for btree=%s l=%u ",
	       bch2_btree_ids[bp.btree_id], bp.level);
	bch2_bkey_val_to_text(&buf, c, orig_k);
	pr_buf(&buf, "\nin alloc key ");
	bch2_bkey_val_to_text(&buf, c, alloc_k);

	if (c->sb.version < bcachefs_metadata_version_backpointers ||
	    fsck_err(c, "%s", buf.buf)) {
		struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut(trans, alloc_k);

		ret   = PTR_ERR_OR_ZERO(a) ?:
			bch2_bucket_backpointer_add(trans, a, bp, orig_k) ?:
			bch2_trans_update(trans, &alloc_iter, &a->k_i, 0);
	}

	goto out;
}

static int check_extent_to_backpointers(struct btree_trans *trans,
					struct btree_iter *iter)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	struct bpos bucket_pos;
	struct bch_backpointer bp;
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
		if (p.ptr.cached)
			continue;

		bch2_pointer_to_bucket_and_backpointer(c, iter->btree_id, iter->path->level,
						       k, p, &bucket_pos, &bp);

		ret = backpointer_check(trans, bucket_pos, bp, k);
		if (ret)
			return ret;
	}

	/* check root */
	if (!btree_path_node(iter->path, iter->path->level + 1) &&
	    !bpos_cmp(k.k->p, SPOS_MAX)) {
		k = bkey_i_to_s_c(&path_l(iter->path)->b->key);
		ptrs = bch2_bkey_ptrs_c(k);
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if (p.ptr.cached)
				continue;

			bch2_pointer_to_bucket_and_backpointer(c, iter->btree_id, iter->path->level + 1,
							       k, p, &bucket_pos, &bp);

			ret = backpointer_check(trans, bucket_pos, bp, k);
			if (ret)
				return ret;
		}
	}

	return 0;
}

int bch2_check_extents_to_backpointers(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	enum btree_id btree_id;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);
	for (btree_id = 0; btree_id < BTREE_ID_NR; btree_id++) {
		bch2_trans_node_iter_init(&trans, &iter, btree_id, POS_MIN, 0,
					  btree_type_has_ptrs(btree_id) ? 0 : 1,
					  BTREE_ITER_ALL_LEVELS|
					  BTREE_ITER_PREFETCH);

		do {
			ret = __bch2_trans_do(&trans, NULL, NULL,
					      BTREE_INSERT_LAZY_RW|
					      BTREE_INSERT_NOFAIL,
					      check_extent_to_backpointers(&trans, &iter));
			if (ret)
				break;
		} while (!bch2_btree_iter_advance(&iter));

		bch2_trans_iter_exit(&trans, &iter);
	}
	bch2_trans_exit(&trans);
	return ret;
}

static int check_one_backpointer(struct btree_trans *trans,
				 struct bpos alloc_pos,
				 u64 *bp_offset)
{
	struct btree_iter iter;
	struct bch_backpointer bp;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;
	int ret;

	ret = bch2_get_next_backpointer(trans, alloc_pos.inode,
					alloc_pos.offset, -1,
					bp_offset, &bp);
	if (ret || *bp_offset == U64_MAX)
		return ret;

	k = __bch2_backpointer_get_key(trans, &iter, bp, true);
	ret = bkey_err(k);
	if (ret)
		return ret;

	if (fsck_err_on(!k.k, trans->c,
			"backpointer points to missing extent\n%s",
			(bch2_backpointer_to_text(&buf, &bp), buf.buf)))
		ret = bch2_backpointer_del_by_offset(trans, alloc_pos, *bp_offset);

	bch2_trans_iter_exit(trans, &iter);
fsck_err:
	return ret;
}

int bch2_check_backpointers_to_extents(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);
	for_each_btree_key(&trans, iter, BTREE_ID_alloc, POS_MIN,
			   BTREE_ITER_PREFETCH, k, ret) {
		u64 bp_offset = 0;

		while (!(ret = __bch2_trans_do(&trans, NULL, NULL,
					       BTREE_INSERT_LAZY_RW|
					       BTREE_INSERT_NOFAIL,
				check_one_backpointer(&trans, iter.pos, &bp_offset))) &&
		       bp_offset < U64_MAX)
			bp_offset++;

		if (ret)
			break;
	}
	bch2_trans_iter_exit(&trans, &iter);
	bch2_trans_exit(&trans);
	return ret < 0 ? ret : 0;
}
