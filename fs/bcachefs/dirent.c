
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "dirent.h"
#include "fs.h"
#include "keylist.h"
#include "str_hash.h"

static unsigned dirent_name_bytes(struct bkey_s_c_dirent d)
{
	unsigned len = bkey_val_bytes(d.k) - sizeof(struct bch_dirent);

	while (len && !d.v->d_name[len - 1])
		--len;

	return len;
}

static u64 bch_dirent_hash(const struct bch_hash_info *info,
			   const struct qstr *name)
{
	switch (info->type) {
	case BCH_STR_HASH_SHA1: {
		SHASH_DESC_ON_STACK(desc, bch_sha1);
		u8 digest[SHA1_DIGEST_SIZE];
		u64 ret;
		desc->tfm = bch_sha1;
		desc->flags = 0;
		crypto_shash_init(desc);

		crypto_shash_update(desc, (void *) &info->seed, sizeof(info->seed));

		crypto_shash_update(desc, (void *) name->name, name->len);
		crypto_shash_final(desc, digest);
		memcpy(&ret, &digest, sizeof(ret));
		return max_t(u64, ret >> 1, 2);
	}
	default: {
		struct bch_str_hash_ctx ctx;

		bch_str_hash_init(&ctx, info->type);
		bch_str_hash_update(&ctx, info->type, &info->seed, sizeof(info->seed));

		bch_str_hash_update(&ctx, info->type, name->name, name->len);

		/* [0,2) reserved for dots */
		return max_t(u64, bch_str_hash_end(&ctx, info->type), 2);
	}
	}
}

static u64 dirent_hash_key(const struct bch_hash_info *info, const void *key)
{
	return bch_dirent_hash(info, key);
}

static u64 dirent_hash_bkey(const struct bch_hash_info *info, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);
	struct qstr name = QSTR_INIT(d.v->d_name, dirent_name_bytes(d));

	return bch_dirent_hash(info, &name);
}

static bool dirent_cmp_key(struct bkey_s_c _l, const void *_r)
{
	struct bkey_s_c_dirent l = bkey_s_c_to_dirent(_l);
	int len = dirent_name_bytes(l);
	const struct qstr *r = _r;

	return len - r->len ?: memcmp(l.v->d_name, r->name, len);
}

static bool dirent_cmp_bkey(struct bkey_s_c _l, struct bkey_s_c _r)
{
	struct bkey_s_c_dirent l = bkey_s_c_to_dirent(_l);
	struct bkey_s_c_dirent r = bkey_s_c_to_dirent(_r);
	int l_len = dirent_name_bytes(l);
	int r_len = dirent_name_bytes(r);

	return l_len - r_len ?: memcmp(l.v->d_name, r.v->d_name, l_len);
}

static const struct bch_hash_desc dirent_hash_desc = {
	.btree_id	= BTREE_ID_DIRENTS,
	.key_type	= BCH_DIRENT,
	.whiteout_type	= BCH_DIRENT_WHITEOUT,
	.hash_key	= dirent_hash_key,
	.hash_bkey	= dirent_hash_bkey,
	.cmp_key	= dirent_cmp_key,
	.cmp_bkey	= dirent_cmp_bkey,
};

static const char *bch_dirent_invalid(const struct cache_set *c,
				      struct bkey_s_c k)
{
	switch (k.k->type) {
	case BCH_DIRENT:
		return bkey_val_bytes(k.k) < sizeof(struct bch_dirent)
			? "value too small"
			: NULL;

	case BCH_DIRENT_WHITEOUT:
		return bkey_val_bytes(k.k) != 0
			? "value size should be zero"
			: NULL;

	default:
		return "invalid type";
	}
}

static void bch_dirent_to_text(struct cache_set *c, char *buf,
			       size_t size, struct bkey_s_c k)
{
	struct bkey_s_c_dirent d;

	switch (k.k->type) {
	case BCH_DIRENT:
		d = bkey_s_c_to_dirent(k);

		if (size) {
			unsigned n = min_t(unsigned, size,
					   dirent_name_bytes(d));
			memcpy(buf, d.v->d_name, n);
			buf[size - 1] = '\0';
			buf += n;
			size -= n;
		}

		scnprintf(buf, size, " -> %llu", d.v->d_inum);
		break;
	case BCH_DIRENT_WHITEOUT:
		scnprintf(buf, size, "whiteout");
		break;
	}
}

const struct bkey_ops bch_bkey_dirent_ops = {
	.key_invalid	= bch_dirent_invalid,
	.val_to_text	= bch_dirent_to_text,
};

static struct bkey_i_dirent *dirent_create_key(u8 type,
				const struct qstr *name, u64 dst)
{
	struct bkey_i_dirent *dirent;
	unsigned u64s = BKEY_U64s +
		DIV_ROUND_UP(sizeof(struct bch_dirent) + name->len,
			     sizeof(u64));

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

	EBUG_ON(dirent_name_bytes(dirent_i_to_s_c(dirent)) != name->len);

	return dirent;
}

int bch_dirent_create(struct inode *dir, u8 type,
		      const struct qstr *name, u64 dst_inum)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);
	struct bkey_i_dirent *dirent;
	int ret;

	dirent = dirent_create_key(type, name, dst_inum);
	if (!dirent)
		return -ENOMEM;

	ret = bch_hash_set(dirent_hash_desc, &ei->str_hash, c,
			   ei->vfs_inode.i_ino, &ei->journal_seq,
			   &dirent->k_i, BCH_HASH_SET_MUST_CREATE);
	kfree(dirent);

	return ret;
}

static void dirent_copy_target(struct bkey_i_dirent *dst,
			       struct bkey_s_c_dirent src)
{
	dst->v.d_inum = src.v->d_inum;
	dst->v.d_type = src.v->d_type;
}

static struct bpos bch_dirent_pos(struct bch_inode_info *ei,
				  const struct qstr *name)
{
	return POS(ei->vfs_inode.i_ino, bch_dirent_hash(&ei->str_hash, name));
}

int bch_dirent_rename(struct cache_set *c,
		      struct inode *src_dir, const struct qstr *src_name,
		      struct inode *dst_dir, const struct qstr *dst_name,
		      u64 *journal_seq, enum bch_rename_mode mode)
{
	struct bch_inode_info *src_ei = to_bch_ei(src_dir);
	struct bch_inode_info *dst_ei = to_bch_ei(dst_dir);
	struct btree_iter src_iter, dst_iter, whiteout_iter;
	struct bkey_s_c old_src, old_dst;
	struct bkey delete;
	struct bkey_i_dirent *new_src = NULL, *new_dst = NULL;
	struct bpos src_pos = bch_dirent_pos(src_ei, src_name);
	struct bpos dst_pos = bch_dirent_pos(dst_ei, dst_name);
	bool need_whiteout;
	int ret = -ENOMEM;

	bch_btree_iter_init_intent(&src_iter, c, BTREE_ID_DIRENTS, src_pos);
	bch_btree_iter_init_intent(&dst_iter, c, BTREE_ID_DIRENTS, dst_pos);
	bch_btree_iter_link(&src_iter, &dst_iter);

	bch_btree_iter_init(&whiteout_iter, c, BTREE_ID_DIRENTS, src_pos);
	bch_btree_iter_link(&src_iter, &whiteout_iter);

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
	old_src = bch_hash_lookup_at(dirent_hash_desc,
				     &src_ei->str_hash,
				     &src_iter, src_name);
	if ((ret = btree_iter_err(old_src)))
		goto err;

	ret = bch_hash_needs_whiteout(dirent_hash_desc,
				&src_ei->str_hash,
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
		? bch_hash_hole_at(dirent_hash_desc, &dst_iter)
		: bch_hash_lookup_at(dirent_hash_desc,
				     &dst_ei->str_hash,
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
			 * situation bch_hash_needs_whiteout() could
			 * return false when the whiteout would have
			 * been needed if we inserted at the pos
			 * __dirent_find_hole() found
			 */
			new_dst->k.p = src_iter.pos;
			ret = bch_btree_insert_at(c, NULL, NULL,
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
	ret = bch_btree_insert_at(c, NULL, NULL, journal_seq,
			BTREE_INSERT_ATOMIC,
			BTREE_INSERT_ENTRY(&src_iter, &new_src->k_i),
			BTREE_INSERT_ENTRY(&dst_iter, &new_dst->k_i));
err:
	if (ret == -EINTR)
		goto retry;

	bch_btree_iter_unlock(&whiteout_iter);
	bch_btree_iter_unlock(&dst_iter);
	bch_btree_iter_unlock(&src_iter);

	if (new_src != (void *) &delete)
		kfree(new_src);
	kfree(new_dst);
	return ret;
}

int bch_dirent_delete(struct inode *dir, const struct qstr *name)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);

	return bch_hash_delete(dirent_hash_desc, &ei->str_hash,
			       c, ei->vfs_inode.i_ino,
			       &ei->journal_seq, name);
}

u64 bch_dirent_lookup(struct inode *dir, const struct qstr *name)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 inum;

	k = bch_hash_lookup(dirent_hash_desc, &ei->str_hash, c,
			    ei->vfs_inode.i_ino, &iter, name);
	if (IS_ERR(k.k)) {
		bch_btree_iter_unlock(&iter);
		return 0;
	}

	inum = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum);
	bch_btree_iter_unlock(&iter);

	return inum;
}

int bch_empty_dir(struct cache_set *c, u64 dir_inum)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS(dir_inum, 0), k) {
		if (k.k->p.inode > dir_inum)
			break;

		if (k.k->type == BCH_DIRENT) {
			ret = -ENOTEMPTY;
			break;
		}
	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

int bch_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct cache_set *c = sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent dirent;
	unsigned len;

	if (!dir_emit_dots(file, ctx))
		return 0;

	pr_debug("listing for %lu from %llu", inode->i_ino, ctx->pos);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(inode->i_ino, ctx->pos), k) {
		if (k.k->type != BCH_DIRENT)
			continue;

		dirent = bkey_s_c_to_dirent(k);

		pr_debug("saw %llu:%llu (%s) -> %llu",
			 k.k->p.inode, k.k->p.offset,
			 dirent.v->d_name, dirent.v->d_inum);

		if (bkey_cmp(k.k->p, POS(inode->i_ino, ctx->pos)) < 0)
			continue;

		if (k.k->p.inode > inode->i_ino)
			break;

		len = dirent_name_bytes(dirent);

		pr_debug("emitting %s", dirent.v->d_name);

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
	bch_btree_iter_unlock(&iter);

	return 0;
}
