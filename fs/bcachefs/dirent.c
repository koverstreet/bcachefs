
#include "bcachefs.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "dirent.h"
#include "fs.h"
#include "keylist.h"
#include "str_hash.h"

#include <linux/dcache.h>

unsigned bch2_dirent_name_bytes(struct bkey_s_c_dirent d)
{
	unsigned len = bkey_val_bytes(d.k) - sizeof(struct bch_dirent);

	while (len && !d.v->d_name[len - 1])
		--len;

	return len;
}

static unsigned dirent_val_u64s(unsigned len)
{
	return DIV_ROUND_UP(sizeof(struct bch_dirent) + len, sizeof(u64));
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

const struct bch_hash_desc bch2_dirent_hash_desc = {
	.btree_id	= BTREE_ID_DIRENTS,
	.key_type	= BCH_DIRENT,
	.whiteout_type	= BCH_DIRENT_WHITEOUT,
	.hash_key	= dirent_hash_key,
	.hash_bkey	= dirent_hash_bkey,
	.cmp_key	= dirent_cmp_key,
	.cmp_bkey	= dirent_cmp_bkey,
};

const char *bch2_dirent_invalid(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d;
	unsigned len;

	switch (k.k->type) {
	case BCH_DIRENT:
		if (bkey_val_bytes(k.k) < sizeof(struct bch_dirent))
			return "value too small";

		d = bkey_s_c_to_dirent(k);
		len = bch2_dirent_name_bytes(d);

		if (!len)
			return "empty name";

		if (bkey_val_u64s(k.k) > dirent_val_u64s(len))
			return "value too big";

		if (len > NAME_MAX)
			return "dirent name too big";

		if (memchr(d.v->d_name, '/', len))
			return "dirent name has invalid characters";

		return NULL;
	case BCH_DIRENT_WHITEOUT:
		return bkey_val_bytes(k.k) != 0
			? "value size should be zero"
			: NULL;

	default:
		return "invalid type";
	}
}

void bch2_dirent_to_text(struct bch_fs *c, char *buf,
			 size_t size, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d;
	size_t n = 0;

	switch (k.k->type) {
	case BCH_DIRENT:
		d = bkey_s_c_to_dirent(k);

		n += bch_scnmemcpy(buf + n, size - n, d.v->d_name,
				   bch2_dirent_name_bytes(d));
		n += scnprintf(buf + n, size - n, " -> %llu", d.v->d_inum);
		break;
	case BCH_DIRENT_WHITEOUT:
		scnprintf(buf, size, "whiteout");
		break;
	}
}

static struct bkey_i_dirent *dirent_create_key(u8 type,
				const struct qstr *name, u64 dst)
{
	struct bkey_i_dirent *dirent;
	unsigned u64s = BKEY_U64s + dirent_val_u64s(name->len);

	dirent = kmalloc(u64s * sizeof(u64), GFP_NOFS);
	if (!dirent)
		return NULL;

	bkey_dirent_init(&dirent->k_i);
	dirent->k.u64s = u64s;
	dirent->v.d_inum = cpu_to_le64(dst);
	dirent->v.d_type = type;

	memcpy(dirent->v.d_name, name->name, name->len);
	memset(dirent->v.d_name + name->len, 0,
	       bkey_val_bytes(&dirent->k) -
	       (sizeof(struct bch_dirent) + name->len));

	EBUG_ON(bch2_dirent_name_bytes(dirent_i_to_s_c(dirent)) != name->len);

	return dirent;
}

int bch2_dirent_create(struct bch_fs *c, u64 dir_inum,
		       const struct bch_hash_info *hash_info,
		       u8 type, const struct qstr *name, u64 dst_inum,
		       u64 *journal_seq, int flags)
{
	struct bkey_i_dirent *dirent;
	int ret;

	dirent = dirent_create_key(type, name, dst_inum);
	if (!dirent)
		return -ENOMEM;

	ret = bch2_hash_set(bch2_dirent_hash_desc, hash_info, c, dir_inum,
			   journal_seq, &dirent->k_i, flags);
	kfree(dirent);

	return ret;
}

static void dirent_copy_target(struct bkey_i_dirent *dst,
			       struct bkey_s_c_dirent src)
{
	dst->v.d_inum = src.v->d_inum;
	dst->v.d_type = src.v->d_type;
}

static struct bpos bch2_dirent_pos(struct bch_inode_info *inode,
				   const struct qstr *name)
{
	return POS(inode->v.i_ino, bch2_dirent_hash(&inode->ei_str_hash, name));
}

int bch2_dirent_rename(struct bch_fs *c,
		struct bch_inode_info *src_dir, const struct qstr *src_name,
		struct bch_inode_info *dst_dir, const struct qstr *dst_name,
		u64 *journal_seq, enum bch_rename_mode mode)
{
	struct btree_iter src_iter, dst_iter, whiteout_iter;
	struct bkey_s_c old_src, old_dst;
	struct bkey delete;
	struct bkey_i_dirent *new_src = NULL, *new_dst = NULL;
	struct bpos src_pos = bch2_dirent_pos(src_dir, src_name);
	struct bpos dst_pos = bch2_dirent_pos(dst_dir, dst_name);
	bool need_whiteout;
	int ret = -ENOMEM;

	bch2_btree_iter_init(&src_iter, c, BTREE_ID_DIRENTS, src_pos,
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	bch2_btree_iter_init(&dst_iter, c, BTREE_ID_DIRENTS, dst_pos,
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	bch2_btree_iter_link(&src_iter, &dst_iter);

	bch2_btree_iter_init(&whiteout_iter, c, BTREE_ID_DIRENTS, src_pos,
			     BTREE_ITER_SLOTS);
	bch2_btree_iter_link(&src_iter, &whiteout_iter);

	if (mode == BCH_RENAME_EXCHANGE) {
		new_src = dirent_create_key(0, src_name, 0);
		if (!new_src)
			goto err;
	} else {
		new_src = (void *) &delete;
	}

	new_dst = dirent_create_key(0, dst_name, 0);
	if (!new_dst)
		goto err;
retry:
	/*
	 * Note that on -EINTR/dropped locks we're not restarting the lookup
	 * from the original hashed position (like we do when creating dirents,
	 * in bch_hash_set) -  we never move existing dirents to different slot:
	 */
	old_src = bch2_hash_lookup_at(bch2_dirent_hash_desc,
				     &src_dir->ei_str_hash,
				     &src_iter, src_name);
	if ((ret = btree_iter_err(old_src)))
		goto err;

	ret = bch2_hash_needs_whiteout(bch2_dirent_hash_desc,
				&src_dir->ei_str_hash,
				&whiteout_iter, &src_iter);
	if (ret < 0)
		goto err;
	need_whiteout = ret;

	/*
	 * Note that in BCH_RENAME mode, we're _not_ checking if
	 * the target already exists - we're relying on the VFS
	 * to do that check for us for correctness:
	 */
	old_dst = mode == BCH_RENAME
		? bch2_hash_hole_at(bch2_dirent_hash_desc, &dst_iter)
		: bch2_hash_lookup_at(bch2_dirent_hash_desc,
				     &dst_dir->ei_str_hash,
				     &dst_iter, dst_name);
	if ((ret = btree_iter_err(old_dst)))
		goto err;

	switch (mode) {
	case BCH_RENAME:
		bkey_init(&new_src->k);
		dirent_copy_target(new_dst, bkey_s_c_to_dirent(old_src));

		if (bkey_cmp(dst_pos, src_iter.pos) <= 0 &&
		    bkey_cmp(src_iter.pos, dst_iter.pos) < 0) {
			/*
			 * If we couldn't insert new_dst at its hashed
			 * position (dst_pos) due to a hash collision,
			 * and we're going to be deleting in
			 * between the hashed position and first empty
			 * slot we found - just overwrite the pos we
			 * were going to delete:
			 *
			 * Note: this is a correctness issue, in this
			 * situation bch2_hash_needs_whiteout() could
			 * return false when the whiteout would have
			 * been needed if we inserted at the pos
			 * __dirent_find_hole() found
			 */
			new_dst->k.p = src_iter.pos;
			ret = bch2_btree_insert_at(c, NULL, NULL,
					journal_seq,
					BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&src_iter,
							   &new_dst->k_i));
			goto err;
		}

		if (need_whiteout)
			new_src->k.type = BCH_DIRENT_WHITEOUT;
		break;
	case BCH_RENAME_OVERWRITE:
		bkey_init(&new_src->k);
		dirent_copy_target(new_dst, bkey_s_c_to_dirent(old_src));

		if (bkey_cmp(dst_pos, src_iter.pos) <= 0 &&
		    bkey_cmp(src_iter.pos, dst_iter.pos) < 0) {
			/*
			 * Same case described above -
			 * bch_hash_needs_whiteout could spuriously
			 * return false, but we have to insert at
			 * dst_iter.pos because we're overwriting
			 * another dirent:
			 */
			new_src->k.type = BCH_DIRENT_WHITEOUT;
		} else if (need_whiteout)
			new_src->k.type = BCH_DIRENT_WHITEOUT;
		break;
	case BCH_RENAME_EXCHANGE:
		dirent_copy_target(new_src, bkey_s_c_to_dirent(old_dst));
		dirent_copy_target(new_dst, bkey_s_c_to_dirent(old_src));
		break;
	}

	new_src->k.p = src_iter.pos;
	new_dst->k.p = dst_iter.pos;
	ret = bch2_btree_insert_at(c, NULL, NULL, journal_seq,
			BTREE_INSERT_ATOMIC,
			BTREE_INSERT_ENTRY(&src_iter, &new_src->k_i),
			BTREE_INSERT_ENTRY(&dst_iter, &new_dst->k_i));
err:
	if (ret == -EINTR)
		goto retry;

	bch2_btree_iter_unlock(&whiteout_iter);
	bch2_btree_iter_unlock(&dst_iter);
	bch2_btree_iter_unlock(&src_iter);

	if (new_src != (void *) &delete)
		kfree(new_src);
	kfree(new_dst);
	return ret;
}

int bch2_dirent_delete(struct bch_fs *c, u64 dir_inum,
		       const struct bch_hash_info *hash_info,
		       const struct qstr *name,
		       u64 *journal_seq)
{
	return bch2_hash_delete(bch2_dirent_hash_desc, hash_info,
			       c, dir_inum, journal_seq, name);
}

u64 bch2_dirent_lookup(struct bch_fs *c, u64 dir_inum,
		       const struct bch_hash_info *hash_info,
		       const struct qstr *name)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 inum;

	k = bch2_hash_lookup(bch2_dirent_hash_desc, hash_info, c,
			    dir_inum, &iter, name);
	if (IS_ERR(k.k)) {
		bch2_btree_iter_unlock(&iter);
		return 0;
	}

	inum = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum);
	bch2_btree_iter_unlock(&iter);

	return inum;
}

int bch2_empty_dir(struct bch_fs *c, u64 dir_inum)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS(dir_inum, 0), 0, k) {
		if (k.k->p.inode > dir_inum)
			break;

		if (k.k->type == BCH_DIRENT) {
			ret = -ENOTEMPTY;
			break;
		}
	}
	bch2_btree_iter_unlock(&iter);

	return ret;
}

int bch2_readdir(struct bch_fs *c, struct file *file,
		 struct dir_context *ctx)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent dirent;
	unsigned len;

	if (!dir_emit_dots(file, ctx))
		return 0;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(inode->v.i_ino, ctx->pos), 0, k) {
		if (k.k->type != BCH_DIRENT)
			continue;

		dirent = bkey_s_c_to_dirent(k);

		if (bkey_cmp(k.k->p, POS(inode->v.i_ino, ctx->pos)) < 0)
			continue;

		if (k.k->p.inode > inode->v.i_ino)
			break;

		len = bch2_dirent_name_bytes(dirent);

		/*
		 * XXX: dir_emit() can fault and block, while we're holding
		 * locks
		 */
		if (!dir_emit(ctx, dirent.v->d_name, len,
			      le64_to_cpu(dirent.v->d_inum),
			      dirent.v->d_type))
			break;

		ctx->pos = k.k->p.offset + 1;
	}
	bch2_btree_iter_unlock(&iter);

	return 0;
}
