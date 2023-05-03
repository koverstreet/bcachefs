// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "dirent.h"
#include "fs.h"
#include "keylist.h"
#include "str_hash.h"
#include "subvolume.h"

#include <linux/dcache.h>

unsigned bch2_dirent_name_bytes(struct bkey_s_c_dirent d)
{
	unsigned len = bkey_val_bytes(d.k) -
		offsetof(struct bch_dirent, d_name);

	return strnlen(d.v->d_name, len);
}

static u64 bch2_dirent_hash(const struct bch_hash_info *info,
			    const struct qstr *name)
{
	struct bch_str_hash_ctx ctx;

	bch2_str_hash_init(&ctx, info);
	bch2_str_hash_update(&ctx, info, name->name, name->len);

	/* [0,2) reserved for dots */
	return max_t(u64, bch2_str_hash_end(&ctx, info), 2);
}

static u64 dirent_hash_key(const struct bch_hash_info *info, const void *key)
{
	return bch2_dirent_hash(info, key);
}

static u64 dirent_hash_bkey(const struct bch_hash_info *info, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);
	struct qstr name = QSTR_INIT(d.v->d_name, bch2_dirent_name_bytes(d));

	return bch2_dirent_hash(info, &name);
}

static bool dirent_cmp_key(struct bkey_s_c _l, const void *_r)
{
	struct bkey_s_c_dirent l = bkey_s_c_to_dirent(_l);
	int len = bch2_dirent_name_bytes(l);
	const struct qstr *r = _r;

	return len - r->len ?: memcmp(l.v->d_name, r->name, len);
}

static bool dirent_cmp_bkey(struct bkey_s_c _l, struct bkey_s_c _r)
{
	struct bkey_s_c_dirent l = bkey_s_c_to_dirent(_l);
	struct bkey_s_c_dirent r = bkey_s_c_to_dirent(_r);
	int l_len = bch2_dirent_name_bytes(l);
	int r_len = bch2_dirent_name_bytes(r);

	return l_len - r_len ?: memcmp(l.v->d_name, r.v->d_name, l_len);
}

static bool dirent_is_visible(subvol_inum inum, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);

	if (d.v->d_type == DT_SUBVOL)
		return le32_to_cpu(d.v->d_parent_subvol) == inum.subvol;
	return true;
}

const struct bch_hash_desc bch2_dirent_hash_desc = {
	.btree_id	= BTREE_ID_dirents,
	.key_type	= KEY_TYPE_dirent,
	.hash_key	= dirent_hash_key,
	.hash_bkey	= dirent_hash_bkey,
	.cmp_key	= dirent_cmp_key,
	.cmp_bkey	= dirent_cmp_bkey,
	.is_visible	= dirent_is_visible,
};

const char *bch2_dirent_invalid(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);
	unsigned len;

	if (bkey_val_bytes(k.k) < sizeof(struct bch_dirent))
		return "value too small";

	len = bch2_dirent_name_bytes(d);
	if (!len)
		return "empty name";

	if (bkey_val_u64s(k.k) > dirent_val_u64s(len))
		return "value too big";

	if (len > BCH_NAME_MAX)
		return "dirent name too big";

	if (len == 1 && !memcmp(d.v->d_name, ".", 1))
		return "invalid name";

	if (len == 2 && !memcmp(d.v->d_name, "..", 2))
		return "invalid name";

	if (memchr(d.v->d_name, '/', len))
		return "invalid name";

	if (d.v->d_type != DT_SUBVOL &&
	    le64_to_cpu(d.v->d_inum) == d.k->p.inode)
		return "dirent points to own directory";

	return NULL;
}

void bch2_dirent_to_text(struct printbuf *out, struct bch_fs *c,
			 struct bkey_s_c k)
{
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);

	pr_buf(out, "%.*s -> %llu type %s",
	       bch2_dirent_name_bytes(d),
	       d.v->d_name,
	       d.v->d_type != DT_SUBVOL
	       ? le64_to_cpu(d.v->d_inum)
	       : le32_to_cpu(d.v->d_child_subvol),
	       bch2_d_type_str(d.v->d_type));
}

static struct bkey_i_dirent *dirent_create_key(struct btree_trans *trans,
				subvol_inum dir, u8 type,
				const struct qstr *name, u64 dst)
{
	struct bkey_i_dirent *dirent;
	unsigned u64s = BKEY_U64s + dirent_val_u64s(name->len);

	if (name->len > BCH_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	BUG_ON(u64s > U8_MAX);

	dirent = bch2_trans_kmalloc(trans, u64s * sizeof(u64));
	if (IS_ERR(dirent))
		return dirent;

	bkey_dirent_init(&dirent->k_i);
	dirent->k.u64s = u64s;

	if (type != DT_SUBVOL) {
		dirent->v.d_inum = cpu_to_le64(dst);
	} else {
		dirent->v.d_parent_subvol = cpu_to_le32(dir.subvol);
		dirent->v.d_child_subvol = cpu_to_le32(dst);
	}

	dirent->v.d_type = type;

	memcpy(dirent->v.d_name, name->name, name->len);
	memset(dirent->v.d_name + name->len, 0,
	       bkey_val_bytes(&dirent->k) -
	       offsetof(struct bch_dirent, d_name) -
	       name->len);

	EBUG_ON(bch2_dirent_name_bytes(dirent_i_to_s_c(dirent)) != name->len);

	return dirent;
}

int bch2_dirent_create(struct btree_trans *trans, subvol_inum dir,
		       const struct bch_hash_info *hash_info,
		       u8 type, const struct qstr *name, u64 dst_inum,
		       u64 *dir_offset, int flags)
{
	struct bkey_i_dirent *dirent;
	int ret;

	dirent = dirent_create_key(trans, dir, type, name, dst_inum);
	ret = PTR_ERR_OR_ZERO(dirent);
	if (ret)
		return ret;

	ret = bch2_hash_set(trans, bch2_dirent_hash_desc, hash_info,
			    dir, &dirent->k_i, flags);
	*dir_offset = dirent->k.p.offset;

	return ret;
}

static void dirent_copy_target(struct bkey_i_dirent *dst,
			       struct bkey_s_c_dirent src)
{
	dst->v.d_inum = src.v->d_inum;
	dst->v.d_type = src.v->d_type;
}

int bch2_dirent_read_target(struct btree_trans *trans, subvol_inum dir,
			    struct bkey_s_c_dirent d, subvol_inum *target)
{
	struct bch_subvolume s;
	int ret = 0;

	if (d.v->d_type == DT_SUBVOL &&
	    d.v->d_parent_subvol != dir.subvol)
		return 1;

	if (likely(d.v->d_type != DT_SUBVOL)) {
		target->subvol	= dir.subvol;
		target->inum	= le64_to_cpu(d.v->d_inum);
	} else {
		target->subvol	= le32_to_cpu(d.v->d_child_subvol);

		ret = bch2_subvolume_get(trans, target->subvol, true, BTREE_ITER_CACHED, &s);

		target->inum	= le64_to_cpu(s.inode);
	}

	return ret;
}

int bch2_dirent_rename(struct btree_trans *trans,
		subvol_inum src_dir, struct bch_hash_info *src_hash,
		subvol_inum dst_dir, struct bch_hash_info *dst_hash,
		const struct qstr *src_name, subvol_inum *src_inum, u64 *src_offset,
		const struct qstr *dst_name, subvol_inum *dst_inum, u64 *dst_offset,
		enum bch_rename_mode mode)
{
	struct btree_iter src_iter = { NULL };
	struct btree_iter dst_iter = { NULL };
	struct bkey_s_c old_src, old_dst = bkey_s_c_null;
	struct bkey_i_dirent *new_src = NULL, *new_dst = NULL;
	struct bpos dst_pos =
		POS(dst_dir.inum, bch2_dirent_hash(dst_hash, dst_name));
	unsigned src_type = 0, dst_type = 0, src_update_flags = 0;
	int ret = 0;

	if (src_dir.subvol != dst_dir.subvol)
		return -EXDEV;

	memset(src_inum, 0, sizeof(*src_inum));
	memset(dst_inum, 0, sizeof(*dst_inum));

	/* Lookup src: */
	ret = bch2_hash_lookup(trans, &src_iter, bch2_dirent_hash_desc,
			       src_hash, src_dir, src_name,
			       BTREE_ITER_INTENT);
	if (ret)
		goto out;

	old_src = bch2_btree_iter_peek_slot(&src_iter);
	ret = bkey_err(old_src);
	if (ret)
		goto out;

	ret = bch2_dirent_read_target(trans, src_dir,
			bkey_s_c_to_dirent(old_src), src_inum);
	if (ret)
		goto out;

	src_type = bkey_s_c_to_dirent(old_src).v->d_type;

	if (src_type == DT_SUBVOL && mode == BCH_RENAME_EXCHANGE)
		return -EOPNOTSUPP;


	/* Lookup dst: */
	if (mode == BCH_RENAME) {
		/*
		 * Note that we're _not_ checking if the target already exists -
		 * we're relying on the VFS to do that check for us for
		 * correctness:
		 */
		ret = bch2_hash_hole(trans, &dst_iter, bch2_dirent_hash_desc,
				     dst_hash, dst_dir, dst_name);
		if (ret)
			goto out;
	} else {
		ret = bch2_hash_lookup(trans, &dst_iter, bch2_dirent_hash_desc,
				       dst_hash, dst_dir, dst_name,
				       BTREE_ITER_INTENT);
		if (ret)
			goto out;

		old_dst = bch2_btree_iter_peek_slot(&dst_iter);
		ret = bkey_err(old_dst);
		if (ret)
			goto out;

		ret = bch2_dirent_read_target(trans, dst_dir,
				bkey_s_c_to_dirent(old_dst), dst_inum);
		if (ret)
			goto out;

		dst_type = bkey_s_c_to_dirent(old_dst).v->d_type;

		if (dst_type == DT_SUBVOL)
			return -EOPNOTSUPP;
	}

	if (mode != BCH_RENAME_EXCHANGE)
		*src_offset = dst_iter.pos.offset;

	/* Create new dst key: */
	new_dst = dirent_create_key(trans, dst_dir, 0, dst_name, 0);
	ret = PTR_ERR_OR_ZERO(new_dst);
	if (ret)
		goto out;

	dirent_copy_target(new_dst, bkey_s_c_to_dirent(old_src));
	new_dst->k.p = dst_iter.pos;

	/* Create new src key: */
	if (mode == BCH_RENAME_EXCHANGE) {
		new_src = dirent_create_key(trans, src_dir, 0, src_name, 0);
		ret = PTR_ERR_OR_ZERO(new_src);
		if (ret)
			goto out;

		dirent_copy_target(new_src, bkey_s_c_to_dirent(old_dst));
		new_src->k.p = src_iter.pos;
	} else {
		new_src = bch2_trans_kmalloc(trans, sizeof(struct bkey_i));
		ret = PTR_ERR_OR_ZERO(new_src);
		if (ret)
			goto out;

		bkey_init(&new_src->k);
		new_src->k.p = src_iter.pos;

		if (bkey_cmp(dst_pos, src_iter.pos) <= 0 &&
		    bkey_cmp(src_iter.pos, dst_iter.pos) < 0) {
			/*
			 * We have a hash collision for the new dst key,
			 * and new_src - the key we're deleting - is between
			 * new_dst's hashed slot and the slot we're going to be
			 * inserting it into - oops.  This will break the hash
			 * table if we don't deal with it:
			 */
			if (mode == BCH_RENAME) {
				/*
				 * If we're not overwriting, we can just insert
				 * new_dst at the src position:
				 */
				new_src = new_dst;
				new_src->k.p = src_iter.pos;
				goto out_set_src;
			} else {
				/* If we're overwriting, we can't insert new_dst
				 * at a different slot because it has to
				 * overwrite old_dst - just make sure to use a
				 * whiteout when deleting src:
				 */
				new_src->k.type = KEY_TYPE_hash_whiteout;
			}
		} else {
			/* Check if we need a whiteout to delete src: */
			ret = bch2_hash_needs_whiteout(trans, bch2_dirent_hash_desc,
						       src_hash, &src_iter);
			if (ret < 0)
				goto out;

			if (ret)
				new_src->k.type = KEY_TYPE_hash_whiteout;
		}
	}

	ret = bch2_trans_update(trans, &dst_iter, &new_dst->k_i, 0);
	if (ret)
		goto out;
out_set_src:

	/*
	 * If we're deleting a subvolume, we need to really delete the dirent,
	 * not just emit a whiteout in the current snapshot:
	 */
	if (src_type == DT_SUBVOL) {
		bch2_btree_iter_set_snapshot(&src_iter, old_src.k->p.snapshot);
		ret = bch2_btree_iter_traverse(&src_iter);
		if (ret)
			goto out;

		new_src->k.p = src_iter.pos;
		src_update_flags |= BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE;
	}

	ret = bch2_trans_update(trans, &src_iter, &new_src->k_i, src_update_flags);
	if (ret)
		goto out;

	if (mode == BCH_RENAME_EXCHANGE)
		*src_offset = new_src->k.p.offset;
	*dst_offset = new_dst->k.p.offset;
out:
	bch2_trans_iter_exit(trans, &src_iter);
	bch2_trans_iter_exit(trans, &dst_iter);
	return ret;
}

int __bch2_dirent_lookup_trans(struct btree_trans *trans,
			       struct btree_iter *iter,
			       subvol_inum dir,
			       const struct bch_hash_info *hash_info,
			       const struct qstr *name, subvol_inum *inum,
			       unsigned flags)
{
	struct bkey_s_c k;
	struct bkey_s_c_dirent d;
	u32 snapshot;
	int ret;

	ret = bch2_subvolume_get_snapshot(trans, dir.subvol, &snapshot);
	if (ret)
		return ret;

	ret = bch2_hash_lookup(trans, iter, bch2_dirent_hash_desc,
			       hash_info, dir, name, flags);
	if (ret)
		return ret;

	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	d = bkey_s_c_to_dirent(k);

	ret = bch2_dirent_read_target(trans, dir, d, inum);
	if (ret > 0)
		ret = -ENOENT;
err:
	if (ret)
		bch2_trans_iter_exit(trans, iter);

	return ret;
}

u64 bch2_dirent_lookup(struct bch_fs *c, subvol_inum dir,
		       const struct bch_hash_info *hash_info,
		       const struct qstr *name, subvol_inum *inum)
{
	struct btree_trans trans;
	struct btree_iter iter;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);
retry:
	bch2_trans_begin(&trans);

	ret = __bch2_dirent_lookup_trans(&trans, &iter, dir, hash_info,
					  name, inum, 0);
	if (ret == -EINTR)
		goto retry;
	if (!ret)
		bch2_trans_iter_exit(&trans, &iter);
	bch2_trans_exit(&trans);
	return ret;
}

int bch2_empty_dir_trans(struct btree_trans *trans, subvol_inum dir)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u32 snapshot;
	int ret;

	ret = bch2_subvolume_get_snapshot(trans, dir.subvol, &snapshot);
	if (ret)
		return ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_dirents,
			   SPOS(dir.inum, 0, snapshot), 0, k, ret) {
		if (k.k->p.inode > dir.inum)
			break;

		if (k.k->type == KEY_TYPE_dirent) {
			ret = -ENOTEMPTY;
			break;
		}
	}
	bch2_trans_iter_exit(trans, &iter);

	return ret;
}

int bch2_readdir(struct bch_fs *c, subvol_inum inum, struct dir_context *ctx)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent dirent;
	subvol_inum target;
	u32 snapshot;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);
retry:
	bch2_trans_begin(&trans);

	ret = bch2_subvolume_get_snapshot(&trans, inum.subvol, &snapshot);
	if (ret)
		goto err;

	for_each_btree_key_norestart(&trans, iter, BTREE_ID_dirents,
			   SPOS(inum.inum, ctx->pos, snapshot), 0, k, ret) {
		if (k.k->p.inode > inum.inum)
			break;

		if (k.k->type != KEY_TYPE_dirent)
			continue;

		dirent = bkey_s_c_to_dirent(k);

		ret = bch2_dirent_read_target(&trans, inum, dirent, &target);
		if (ret < 0)
			break;
		if (ret)
			continue;

		/*
		 * XXX: dir_emit() can fault and block, while we're holding
		 * locks
		 */
		ctx->pos = dirent.k->p.offset;
		if (!dir_emit(ctx, dirent.v->d_name,
			      bch2_dirent_name_bytes(dirent),
			      target.inum,
			      vfs_d_type(dirent.v->d_type)))
			break;
		ctx->pos = dirent.k->p.offset + 1;

		/*
		 * read_target looks up subvolumes, we can overflow paths if the
		 * directory has many subvolumes in it
		 */
		ret = btree_trans_too_many_iters(&trans);
		if (ret)
			break;
	}
	bch2_trans_iter_exit(&trans, &iter);
err:
	if (ret == -EINTR)
		goto retry;

	bch2_trans_exit(&trans);

	return ret;
}
