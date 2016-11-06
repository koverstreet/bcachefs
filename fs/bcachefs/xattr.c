
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "fs.h"
#include "str_hash.h"
#include "xattr.h"

#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>
#include <crypto/hash.h>

struct xattr_search_key {
	u8		type;
	struct qstr	name;
};

#define X_SEARCH(_type, _name, _len) ((struct xattr_search_key)	\
	{ .type = _type, .name = QSTR_INIT(_name, _len) })

static u64 bch_xattr_hash(const struct bch_hash_info *info,
			  const struct xattr_search_key *key)
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

		crypto_shash_update(desc, (void *) &key->type, sizeof(key->type));
		crypto_shash_update(desc, (void *) key->name.name, key->name.len);

		crypto_shash_final(desc, digest);
		memcpy(&ret, &digest, sizeof(ret));
		return ret >> 1;
	}
	default: {
		struct bch_str_hash_ctx ctx;

		bch_str_hash_init(&ctx, info->type);
		bch_str_hash_update(&ctx, info->type, &info->seed, sizeof(info->seed));

		bch_str_hash_update(&ctx, info->type, &key->type, sizeof(key->type));
		bch_str_hash_update(&ctx, info->type, key->name.name, key->name.len);

		return bch_str_hash_end(&ctx, info->type);
	}
	}
}

#define xattr_val(_xattr)	((_xattr)->x_name + (_xattr)->x_name_len)

static u64 xattr_hash_key(const struct bch_hash_info *info, const void *key)
{
	return bch_xattr_hash(info, key);
}

static u64 xattr_hash_bkey(const struct bch_hash_info *info, struct bkey_s_c k)
{
	struct bkey_s_c_xattr x = bkey_s_c_to_xattr(k);

	return bch_xattr_hash(info,
		 &X_SEARCH(x.v->x_type, x.v->x_name, x.v->x_name_len));
}

static bool xattr_cmp_key(struct bkey_s_c _l, const void *_r)
{
	struct bkey_s_c_xattr l = bkey_s_c_to_xattr(_l);
	const struct xattr_search_key *r = _r;

	return l.v->x_type != r->type ||
		l.v->x_name_len != r->name.len ||
		memcmp(l.v->x_name, r->name.name, r->name.len);
}

static bool xattr_cmp_bkey(struct bkey_s_c _l, struct bkey_s_c _r)
{
	struct bkey_s_c_xattr l = bkey_s_c_to_xattr(_l);
	struct bkey_s_c_xattr r = bkey_s_c_to_xattr(_r);

	return l.v->x_type != r.v->x_type ||
		l.v->x_name_len != r.v->x_name_len ||
		memcmp(l.v->x_name, r.v->x_name, r.v->x_name_len);
}

static const struct bch_hash_desc xattr_hash_desc = {
	.btree_id	= BTREE_ID_XATTRS,
	.key_type	= BCH_XATTR,
	.whiteout_type	= BCH_XATTR_WHITEOUT,
	.hash_key	= xattr_hash_key,
	.hash_bkey	= xattr_hash_bkey,
	.cmp_key	= xattr_cmp_key,
	.cmp_bkey	= xattr_cmp_bkey,
};

static const char *bch_xattr_invalid(const struct cache_set *c,
				     struct bkey_s_c k)
{
	switch (k.k->type) {
	case BCH_XATTR:
		return bkey_val_bytes(k.k) < sizeof(struct bch_xattr)
			? "value too small"
			: NULL;

	case BCH_XATTR_WHITEOUT:
		return bkey_val_bytes(k.k) != 0
			? "value size should be zero"
			: NULL;

	default:
		return "invalid type";
	}
}

static void bch_xattr_to_text(struct cache_set *c, char *buf,
			      size_t size, struct bkey_s_c k)
{
	struct bkey_s_c_xattr xattr;
	int n;

	switch (k.k->type) {
	case BCH_XATTR:
		xattr = bkey_s_c_to_xattr(k);

		if (size) {
			n = min_t(unsigned, size, xattr.v->x_name_len);
			memcpy(buf, xattr.v->x_name, n);
			buf[size - 1] = '\0';
			buf += n;
			size -= n;
		}

		n = scnprintf(buf, size, " -> ");
		buf += n;
		size -= n;

		if (size) {
			n = min_t(unsigned, size,
				  le16_to_cpu(xattr.v->x_val_len));
			memcpy(buf, xattr_val(xattr.v), n);
			buf[size - 1] = '\0';
			buf += n;
			size -= n;
		}

		break;
	case BCH_XATTR_WHITEOUT:
		scnprintf(buf, size, "whiteout");
		break;
	}
}

const struct bkey_ops bch_bkey_xattr_ops = {
	.key_invalid	= bch_xattr_invalid,
	.val_to_text	= bch_xattr_to_text,
};

int bch_xattr_get(struct inode *inode, const char *name,
		  void *buffer, size_t size, int type)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_xattr xattr;
	int ret;

	k = bch_hash_lookup(xattr_hash_desc, &ei->str_hash, c,
			    ei->vfs_inode.i_ino, &iter,
			    &X_SEARCH(type, name, strlen(name)));
	if (IS_ERR(k.k))
		return bch_btree_iter_unlock(&iter) ?: -ENODATA;

	xattr = bkey_s_c_to_xattr(k);
	ret = le16_to_cpu(xattr.v->x_val_len);
	if (buffer) {
		if (ret > size)
			ret = -ERANGE;
		else
			memcpy(buffer, xattr_val(xattr.v), ret);
	}

	bch_btree_iter_unlock(&iter);
	return ret;
}

int bch_xattr_set(struct inode *inode, const char *name,
		  const void *value, size_t size,
		  int flags, int type)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct xattr_search_key search = X_SEARCH(type, name, strlen(name));
	int ret;

	if (!value) {
		ret = bch_hash_delete(xattr_hash_desc, &ei->str_hash,
				      c, ei->vfs_inode.i_ino,
				      &ei->journal_seq, &search);
	} else {
		struct bkey_i_xattr *xattr;
		unsigned u64s = BKEY_U64s +
			DIV_ROUND_UP(sizeof(struct bch_xattr) +
				     search.name.len + size,
				     sizeof(u64));

		if (u64s > U8_MAX)
			return -ERANGE;

		xattr = kmalloc(u64s * sizeof(u64), GFP_NOFS);
		if (!xattr)
			return -ENOMEM;

		bkey_xattr_init(&xattr->k_i);
		xattr->k.u64s		= u64s;
		xattr->v.x_type		= type;
		xattr->v.x_name_len	= search.name.len;
		xattr->v.x_val_len	= cpu_to_le16(size);
		memcpy(xattr->v.x_name, search.name.name, search.name.len);
		memcpy(xattr_val(&xattr->v), value, size);

		ret = bch_hash_set(xattr_hash_desc, &ei->str_hash, c,
				ei->vfs_inode.i_ino, &ei->journal_seq,
				&xattr->k_i,
				(flags & XATTR_CREATE ? BCH_HASH_SET_MUST_CREATE : 0)|
				(flags & XATTR_REPLACE ? BCH_HASH_SET_MUST_REPLACE : 0));
		kfree(xattr);
	}

	if (ret == -ENOENT)
		ret = flags & XATTR_REPLACE ? -ENODATA : 0;

	return ret;
}

static const struct xattr_handler *bch_xattr_type_to_handler(unsigned);

static size_t bch_xattr_emit(struct dentry *dentry,
			     const struct bch_xattr *xattr,
			     char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler =
		bch_xattr_type_to_handler(xattr->x_type);

	if (handler && (!handler->list || handler->list(dentry))) {
		const char *prefix = handler->prefix ?: handler->name;
		const size_t prefix_len = strlen(prefix);
		const size_t total_len = prefix_len + xattr->x_name_len + 1;

		if (buffer && total_len <= buffer_size) {
			memcpy(buffer, prefix, prefix_len);
			memcpy(buffer + prefix_len,
			       xattr->x_name, xattr->x_name_len);
			buffer[prefix_len + xattr->x_name_len] = '\0';
		}

		return total_len;
	} else {
		return 0;
	}
}

ssize_t bch_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct cache_set *c = dentry->d_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	const struct bch_xattr *xattr;
	u64 inum = dentry->d_inode->i_ino;
	ssize_t ret = 0;
	size_t len;

	for_each_btree_key(&iter, c, BTREE_ID_XATTRS, POS(inum, 0), k) {
		BUG_ON(k.k->p.inode < inum);

		if (k.k->p.inode > inum)
			break;

		if (k.k->type != BCH_XATTR)
			continue;

		xattr = bkey_s_c_to_xattr(k).v;

		len = bch_xattr_emit(dentry, xattr, buffer, buffer_size);
		if (buffer) {
			if (len > buffer_size) {
				bch_btree_iter_unlock(&iter);
				return -ERANGE;
			}

			buffer += len;
			buffer_size -= len;
		}

		ret += len;

	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

static int bch_xattr_get_handler(const struct xattr_handler *handler,
				 struct dentry *dentry, struct inode *inode,
				 const char *name, void *buffer, size_t size)
{
	return bch_xattr_get(inode, name, buffer, size, handler->flags);
}

static int bch_xattr_set_handler(const struct xattr_handler *handler,
				 struct dentry *dentry, struct inode *inode,
				 const char *name, const void *value,
				 size_t size, int flags)
{
	return bch_xattr_set(inode, name, value, size, flags,
			     handler->flags);
}

static const struct xattr_handler bch_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.get	= bch_xattr_get_handler,
	.set	= bch_xattr_set_handler,
	.flags	= BCH_XATTR_INDEX_USER,
};

static bool bch_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static const struct xattr_handler bch_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= bch_xattr_trusted_list,
	.get	= bch_xattr_get_handler,
	.set	= bch_xattr_set_handler,
	.flags	= BCH_XATTR_INDEX_TRUSTED,
};

static const struct xattr_handler bch_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= bch_xattr_get_handler,
	.set	= bch_xattr_set_handler,
	.flags	= BCH_XATTR_INDEX_SECURITY,
};

static const struct xattr_handler *bch_xattr_handler_map[] = {
	[BCH_XATTR_INDEX_USER]			= &bch_xattr_user_handler,
	[BCH_XATTR_INDEX_POSIX_ACL_ACCESS]	=
		&posix_acl_access_xattr_handler,
	[BCH_XATTR_INDEX_POSIX_ACL_DEFAULT]	=
		&posix_acl_default_xattr_handler,
	[BCH_XATTR_INDEX_TRUSTED]		= &bch_xattr_trusted_handler,
	[BCH_XATTR_INDEX_SECURITY]		= &bch_xattr_security_handler,
};

const struct xattr_handler *bch_xattr_handlers[] = {
	&bch_xattr_user_handler,
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	&bch_xattr_trusted_handler,
	&bch_xattr_security_handler,
	NULL
};

static const struct xattr_handler *bch_xattr_type_to_handler(unsigned type)
{
	return type < ARRAY_SIZE(bch_xattr_handler_map)
		? bch_xattr_handler_map[type]
		: NULL;
}
