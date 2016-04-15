
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "dirent.h"
#include "fs.h"
#include "keylist.h"
#include "str_hash.h"

static struct bpos bch_dirent_pos(struct bch_inode_info *ei,
				  const struct qstr *name)
{
	struct bch_str_hash_ctx ctx;
	u64 hash;

	bch_str_hash_init(&ctx, ei->str_hash_type);

	bch_str_hash_update(&ctx, ei->str_hash_type,
			    &ei->str_hash_seed, sizeof(ei->str_hash_seed));
	bch_str_hash_update(&ctx, ei->str_hash_type, name->name, name->len);

	hash = bch_str_hash_end(&ctx, ei->str_hash_type);

	/* [0,2) reserved for dots */

	return POS(ei->vfs_inode.i_ino, hash >= 2 ? hash : 2);
}

static unsigned dirent_name_bytes(struct bkey_s_c_dirent d)
{
	unsigned len = bkey_val_bytes(d.k) - sizeof(struct bch_dirent);

	while (len && !d.v->d_name[len - 1])
		--len;

	return len;
}

static int dirent_cmp(struct bkey_s_c_dirent d,
		      const struct qstr *q)
{
	int len = dirent_name_bytes(d);

	return len - q->len ?: memcmp(d.v->d_name, q->name, len);
}

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

const struct btree_keys_ops bch_dirent_ops = {
};

const struct bkey_ops bch_bkey_dirent_ops = {
	.key_invalid	= bch_dirent_invalid,
	.val_to_text	= bch_dirent_to_text,
};

static struct bkey_i_dirent *dirent_create_key(u8 type,
					       const struct qstr *name,
					       u64 dst)
{
	struct bkey_i_dirent *dirent;
	unsigned u64s = BKEY_U64s +
		DIV_ROUND_UP(sizeof(struct bch_dirent) + name->len,
			     sizeof(u64));

	dirent = kmalloc(u64s * sizeof(u64), GFP_KERNEL);
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
	EBUG_ON(dirent_cmp(dirent_i_to_s_c(dirent), name));

	return dirent;
}

static struct bkey_s_c __dirent_find(struct btree_iter *iter,
				     u64 dir, const struct qstr *name)
{
	struct bkey_s_c k;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode != dir)
			break;

		switch (k.k->type) {
		case BCH_DIRENT:
			if (!dirent_cmp(bkey_s_c_to_dirent(k), name))
				return k;

			/* hash collision, keep going */
			break;
		case BCH_DIRENT_WHITEOUT:
			/* hash collision, keep going */
			break;
		default:
			/* hole, not found */
			goto not_found;
		}

		bch_btree_iter_advance_pos(iter);
	}
not_found:
	return (struct bkey_s_c) { .k = ERR_PTR(-ENOENT) };
}

static struct bkey_s_c __dirent_find_hole(struct btree_iter *iter,
					  u64 dir, const struct qstr *name)
{
	struct bkey_s_c k;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode != dir)
			break;

		switch (k.k->type) {
		case BCH_DIRENT:
			if (!dirent_cmp(bkey_s_c_to_dirent(k), name))
				return (struct bkey_s_c) { .k = ERR_PTR(-EEXIST) };

			/* hash collision, keep going */
			break;
		default:
			return k;
		}

		bch_btree_iter_advance_pos(iter);
	}

	return (struct bkey_s_c) { .k = ERR_PTR(-ENOSPC) };
}

int bch_dirent_create(struct inode *dir, u8 type,
		      const struct qstr *name, u64 dst_inum)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i_dirent *dirent;
	int ret;

	dirent = dirent_create_key(type, name, dst_inum);
	if (!dirent)
		return -ENOMEM;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_DIRENTS,
				   bch_dirent_pos(ei, name));

	do {
		k = __dirent_find_hole(&iter, dir->i_ino, name);
		if (IS_ERR(k.k)) {
			ret = bch_btree_iter_unlock(&iter) ?: PTR_ERR(k.k);
			break;
		}

		dirent->k.p = k.k->p;

		ret = bch_btree_insert_at(&iter, &dirent->k_i,
					  NULL, NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC);
		/*
		 * XXX: if we ever cleanup whiteouts, we may need to rewind
		 * iterator on -EINTR
		 */
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);
	kfree(dirent);

	return ret;
}

int bch_dirent_rename(struct cache_set *c,
		      struct inode *src_dir, const struct qstr *src_name,
		      struct inode *dst_dir, const struct qstr *dst_name,
		      u64 *journal_seq, enum bch_rename_mode mode)
{
	struct bch_inode_info *src_ei = to_bch_ei(src_dir);
	struct bch_inode_info *dst_ei = to_bch_ei(dst_dir);
	struct btree_iter src_iter;
	struct btree_iter dst_iter;
	struct bkey_s_c old_src, old_dst;
	struct bkey_s_c_dirent old_src_d, old_dst_d;
	struct bkey_i delete;
	struct bkey_i_dirent *new_src = NULL, *new_dst = NULL;
	int ret = -ENOMEM;

	if (mode == BCH_RENAME_EXCHANGE) {
		new_src = dirent_create_key(0, src_name, 0);
		if (!new_src)
			goto out;
	} else {
		new_src = (void *) &delete;
	}

	new_dst = dirent_create_key(0, dst_name, 0);
	if (!new_dst)
		goto out;

	bch_btree_iter_init_intent(&src_iter, c, BTREE_ID_DIRENTS,
			bch_dirent_pos(src_ei, src_name));
	bch_btree_iter_init_intent(&dst_iter, c, BTREE_ID_DIRENTS,
			bch_dirent_pos(dst_ei, dst_name));
	bch_btree_iter_link(&src_iter, &dst_iter);

	do {
		/*
		 * When taking intent locks, we have to take interior node locks
		 * before leaf node locks; if the second iter we traverse has
		 * locks_want > the first iter, we could end up taking an intent
		 * lock on an interior node after traversing the first iterator
		 * only took an intent lock on a leaf.
		 */
		src_iter.locks_want = dst_iter.locks_want =
			max(src_iter.locks_want, dst_iter.locks_want);

		/*
		 * Have to traverse lower btree nodes before higher - due to
		 * lock ordering.
		 */
		if (bkey_cmp(src_iter.pos, dst_iter.pos) < 0) {
			old_src = __dirent_find(&src_iter, src_dir->i_ino,
						src_name);

			old_dst = mode == BCH_RENAME
				? __dirent_find_hole(&dst_iter, dst_dir->i_ino,
						     dst_name)
				: __dirent_find(&dst_iter, dst_dir->i_ino,
						dst_name);
		} else {
			old_dst = mode == BCH_RENAME
				? __dirent_find_hole(&dst_iter, dst_dir->i_ino,
						     dst_name)
				: __dirent_find(&dst_iter, dst_dir->i_ino,
						dst_name);

			old_src = __dirent_find(&src_iter, src_dir->i_ino,
						src_name);
		}

		if (IS_ERR(old_src.k)) {
			ret = PTR_ERR(old_src.k);
			goto err;
		}

		if (IS_ERR(old_dst.k)) {
			ret = PTR_ERR(old_dst.k);
			goto err;
		}

		switch (mode) {
		case BCH_RENAME:
		case BCH_RENAME_OVERWRITE:
			bkey_init(&delete.k);
			delete.k.p = old_src.k->p;
			delete.k.type = BCH_DIRENT_WHITEOUT;
			break;
		case BCH_RENAME_EXCHANGE:
			old_dst_d = bkey_s_c_to_dirent(old_dst);

			new_src->k.p = old_src.k->p;
			new_src->v.d_inum = old_dst_d.v->d_inum;
			new_src->v.d_type = old_dst_d.v->d_type;
			break;
		}

		old_src_d = bkey_s_c_to_dirent(old_src);

		new_dst->k.p = old_dst.k->p;
		new_dst->v.d_inum = old_src_d.v->d_inum;
		new_dst->v.d_type = old_src_d.v->d_type;

		ret = bch_btree_insert_trans(&(struct btree_insert_trans) {
				.nr = 2,
				.entries = (struct btree_trans_entry[]) {
					{ &src_iter, &new_src->k_i, },
					{ &dst_iter, &new_dst->k_i, }
				}},
				NULL, NULL, journal_seq,
				BTREE_INSERT_ATOMIC);
		bch_btree_iter_unlock(&src_iter);
		bch_btree_iter_unlock(&dst_iter);
	} while (ret == -EINTR);

out:
	if (new_src != (void *) &delete)
		kfree(new_src);
	kfree(new_dst);
	return ret;
err:
	ret = bch_btree_iter_unlock(&src_iter) ?: ret;
	ret = bch_btree_iter_unlock(&dst_iter) ?: ret;
	goto out;
}

int bch_dirent_delete(struct inode *dir, const struct qstr *name)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i delete;
	int ret = -ENOENT;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_DIRENTS,
				   bch_dirent_pos(ei, name));

	do {
		k = __dirent_find(&iter, dir->i_ino, name);
		if (IS_ERR(k.k))
			return bch_btree_iter_unlock(&iter) ?: PTR_ERR(k.k);

		bkey_init(&delete.k);
		delete.k.p = k.k->p;
		delete.k.type = BCH_DIRENT_WHITEOUT;

		ret = bch_btree_insert_at(&iter, &delete,
					  NULL, NULL, &ei->journal_seq,
					  BTREE_INSERT_NOFAIL|
					  BTREE_INSERT_ATOMIC);
		/*
		 * XXX: if we ever cleanup whiteouts, we may need to rewind
		 * iterator on -EINTR
		 */
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);

	return ret;
}

u64 bch_dirent_lookup(struct inode *dir, const struct qstr *name)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(dir);
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 inum = 0;

	bch_btree_iter_init(&iter, c, BTREE_ID_DIRENTS,
			    bch_dirent_pos(ei, name));

	k = __dirent_find(&iter, dir->i_ino, name);
	if (!IS_ERR(k.k))
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
