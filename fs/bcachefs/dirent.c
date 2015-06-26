
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "dirent.h"
#include "keylist.h"
#include "siphash.h"

#include "linux/crc32c.h"
#include "linux/cryptohash.h"

#if 0
static u64 bch_dirent_hash(const struct qstr *name)
{
	union {
		u32 b[SHA_DIGEST_WORDS];
		u64 ret;
	} digest;

	unsigned done = 0;

	sha_init(digest.b);

	while (done < name->len) {
		u32 workspace[SHA_WORKSPACE_WORDS];
		u8 message[SHA_MESSAGE_BYTES];
		unsigned bytes = min_t(unsigned, name->len - done,
				       SHA_MESSAGE_BYTES);

		memcpy(message, name->name + done, bytes);
		memset(message + bytes, 0, SHA_MESSAGE_BYTES - bytes);
		sha_transform(digest.b, message, workspace);
		done += bytes;
	}

	/* [0,2) reserved for dots */

	return (digest.ret >= 2 ? digest.ret : 2) & S64_MAX;
}

static const SIPHASH_KEY bch_siphash_key;

static u64 bch_dirent_hash(const struct qstr *name)
{
	u64 hash = SipHash24(&bch_siphash_key,
			     name->name, name->len) >> 1;

	/* [0,2) reserved for dots */

	return (hash >= 2 ? hash : 2);
}
#endif

static u64 bch_dirent_hash(const struct qstr *name)
{
	u64 hash = crc32c(0, name->name, name->len);

	/* [0,2) reserved for dots */

	return (hash >= 2 ? hash : 2);
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

static struct bkey_i_dirent *dirent_create_key(struct keylist *keys, u8 type,
					       const struct qstr *name, u64 dst)
{
	struct bkey_i_dirent *dirent;
	unsigned u64s = BKEY_U64s +
		DIV_ROUND_UP(sizeof(struct bch_dirent) + name->len,
			     sizeof(u64));

	bch_keylist_init(keys, NULL, 0);

	/* XXX: should try to do this without a kmalloc (in keylist_realloc()) */

	if (bch_keylist_realloc(keys, u64s))
		return NULL;

	dirent = bkey_dirent_init(keys->top);
	dirent->k.u64s = u64s;
	dirent->v.d_inum = dst;
	dirent->v.d_type = type;

	memcpy(dirent->v.d_name, name->name, name->len);
	memset(dirent->v.d_name + name->len, 0,
	       bkey_val_bytes(&dirent->k) -
	       (sizeof(struct bch_dirent) + name->len));

	EBUG_ON(dirent_name_bytes(dirent_i_to_s_c(dirent)) != name->len);
	EBUG_ON(dirent_cmp(dirent_i_to_s_c(dirent), name));

	bch_keylist_enqueue(keys);
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

int bch_dirent_create(struct cache_set *c, u64 dir_inum, u8 type,
		      const struct qstr *name, u64 dst_inum,
		      u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct keylist keys;
	struct bkey_i_dirent *dirent;
	int ret;

	dirent = dirent_create_key(&keys, type, name, dst_inum);
	if (!dirent)
		return -ENOMEM;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_DIRENTS,
				   POS(dir_inum, bch_dirent_hash(name)));

	do {
		k = __dirent_find_hole(&iter, dir_inum, name);
		if (IS_ERR(k.k)) {
			ret = bch_btree_iter_unlock(&iter) ?: PTR_ERR(k.k);
			break;
		}

		dirent->k.p = k.k->p;

		ret = bch_btree_insert_at(&iter, &keys, NULL,
					  journal_seq,
					  BTREE_INSERT_ATOMIC);
		/*
		 * XXX: if we ever cleanup whiteouts, we may need to rewind
		 * iterator on -EINTR
		 */
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);
	bch_keylist_free(&keys);

	return ret;
}

int bch_dirent_update(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name, u64 dst_inum,
		      u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct keylist keys;
	struct bkey_i_dirent *dirent;
	int ret = -ENOENT;

	dirent = dirent_create_key(&keys, 0, name, dst_inum);
	if (!dirent)
		return -ENOMEM;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_DIRENTS,
				   POS(dir_inum, bch_dirent_hash(name)));

	do {
		k = __dirent_find(&iter, dir_inum, name);
		if (IS_ERR(k.k))
			return bch_btree_iter_unlock(&iter) ?: PTR_ERR(k.k);

		dirent->k.p = k.k->p;
		dirent->v.d_type = bkey_s_c_to_dirent(k).v->d_type;

		ret = bch_btree_insert_at(&iter, &keys, NULL,
					  journal_seq,
					  BTREE_INSERT_ATOMIC);
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);

	return ret;
}

int bch_dirent_delete(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i delete;
	int ret = -ENOENT;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_DIRENTS,
				   POS(dir_inum, bch_dirent_hash(name)));

	do {
		k = __dirent_find(&iter, dir_inum, name);
		if (IS_ERR(k.k))
			return bch_btree_iter_unlock(&iter) ?: PTR_ERR(k.k);

		bkey_init(&delete.k);
		delete.k.p = k.k->p;
		delete.k.type = BCH_DIRENT_WHITEOUT;

		ret = bch_btree_insert_at(&iter,
					  &keylist_single(&delete),
					  NULL, NULL,
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

u64 bch_dirent_lookup(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 inum = 0;

	bch_btree_iter_init(&iter, c, BTREE_ID_DIRENTS,
			    POS(dir_inum, bch_dirent_hash(name)));

	k = __dirent_find(&iter, dir_inum, name);
	if (!IS_ERR(k.k))
		inum = bkey_s_c_to_dirent(k).v->d_inum;

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
			      dirent.v->d_inum, dirent.v->d_type))
			break;

		ctx->pos = k.k->p.offset + 1;
	}
	bch_btree_iter_unlock(&iter);

	return 0;
}
