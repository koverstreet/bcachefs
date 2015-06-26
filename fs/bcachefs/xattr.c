
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "fs.h"
#include "keylist.h"
#include "siphash.h"
#include "xattr.h"

#include "linux/crc32c.h"
#include "linux/cryptohash.h"
#include "linux/posix_acl_xattr.h"
#include "linux/xattr.h"

#if 0
/*
 * XXX: should really include x_type here
 */
static u64 bch_xattr_hash(const struct qstr *name)
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

	return digest.ret;
}

static const SIPHASH_KEY bch_siphash_key;

static u64 bch_xattr_hash(const struct qstr *name, u8 type)
{
#if 0
	SIPHASH_CTX ctx;

	SipHash24_Init(&ctx, &bch_siphash_key);
	SipHash24_Update(&ctx, &type, sizeof(type));
	SipHash24_Update(&ctx, name->name, name->len);

	return SipHash24_End(&ctx) >> 1;
#else
	return SipHash24(&bch_siphash_key, name->name, name->len) >> 1;
#endif
}
#endif

static u64 bch_xattr_hash(const struct qstr *name, u8 type)
{
	return crc32c(0, name->name, name->len);
}

#define xattr_val(_xattr)	((_xattr)->x_name + (_xattr)->x_name_len)

static int xattr_cmp(const struct bch_xattr *xattr,
		     u8 type, const struct qstr *q)
{
	return xattr->x_type != type ||
		xattr->x_name_len != q->len ||
		memcmp(xattr->x_name, q->name, q->len);
}

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
			n = min_t(unsigned, size, xattr.v->x_val_len);
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

const struct btree_keys_ops bch_xattr_ops = {
};

const struct bkey_ops bch_bkey_xattr_ops = {
	.key_invalid	= bch_xattr_invalid,
	.val_to_text	= bch_xattr_to_text,
};

int bch_xattr_get(struct cache_set *c, u64 inum, const char *name,
		  void *buffer, size_t size, int type)
{
	struct qstr qname = (struct qstr) QSTR_INIT(name, strlen(name));
	struct btree_iter iter;
	struct bkey_s_c k;
	const struct bch_xattr *xattr;
	int ret = -ENODATA;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_XATTRS,
				      POS(inum, bch_xattr_hash(&qname, type)), k) {
		switch (k.k->type) {
		case BCH_XATTR:
			xattr = bkey_s_c_to_xattr(k).v;

			/* collision? */
			if (!xattr_cmp(xattr, type, &qname)) {
				ret = xattr->x_val_len;
				if (buffer) {
					if (xattr->x_val_len > size)
						ret = -ERANGE;
					else
						memcpy(buffer, xattr_val(xattr),
						       xattr->x_val_len);
				}
				goto out;
			}
			break;
		case BCH_XATTR_WHITEOUT:
			break;
		default:
			/* hole, not found */
			goto out;
		}
	}
out:
	bch_btree_iter_unlock(&iter);
	return ret;
}

int bch_xattr_set(struct inode *inode, const char *name,
		  const void *value, size_t size,
		  int flags, int type)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct qstr qname = (struct qstr) QSTR_INIT((char *) name,
						    strlen(name));
	int ret = -EINVAL;
	unsigned insert_flags = BTREE_INSERT_ATOMIC;

	if (!value)
		insert_flags |= BTREE_INSERT_NOFAIL;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_XATTRS,
				   POS(inode->i_ino,
				       bch_xattr_hash(&qname, type)));

	while ((k = bch_btree_iter_peek_with_holes(&iter)).k) {
		switch (k.k->type) {
		case BCH_XATTR:
			/* collision? */
			if (xattr_cmp(bkey_s_c_to_xattr(k).v, type, &qname)) {
				bch_btree_iter_advance_pos(&iter);
				continue;
			}

			if (flags & XATTR_CREATE) {
				ret = -EEXIST;
				goto out;
			}

			break;
		case BCH_XATTR_WHITEOUT:
			bch_btree_iter_advance_pos(&iter);
			continue;
		default:
			/* hole, not found */
			if (flags & XATTR_REPLACE) {
				ret = -ENODATA;
				goto out;
			}
			break;
		}

		if (value) {
			struct keylist keys;
			struct bkey_i_xattr *xattr;
			unsigned u64s = BKEY_U64s +
				DIV_ROUND_UP(sizeof(struct bch_xattr) +
					     qname.len + size,
					     sizeof(u64));

			if (u64s > U8_MAX) {
				ret = -ERANGE;
				break;
			}

			bch_keylist_init(&keys, NULL, 0);

			if (bch_keylist_realloc(&keys, u64s)) {
				ret = -ENOMEM;
				break;
			}

			xattr = bkey_xattr_init(keys.top);
			xattr->k.u64s		= u64s;
			xattr->k.p		= k.k->p;
			xattr->v.x_type		= type;
			xattr->v.x_name_len	= qname.len;
			xattr->v.x_val_len	= size;
			memcpy(xattr->v.x_name, qname.name, qname.len);
			memcpy(xattr_val(&xattr->v), value, size);

			BUG_ON(xattr_cmp(&xattr->v, type, &qname));

			bch_keylist_enqueue(&keys);

			ret = bch_btree_insert_at(&iter, &keys, NULL,
						  &ei->journal_seq,
						  insert_flags);
			bch_keylist_free(&keys);
		} else {
			struct bkey_i whiteout;
			/* removing */
			bkey_init(&whiteout.k);
			whiteout.k.type = BCH_XATTR_WHITEOUT;
			whiteout.k.p = k.k->p;

			ret = bch_btree_insert_at(&iter,
						  &keylist_single(&whiteout),
						  NULL, &ei->journal_seq,
						  insert_flags);
		}

		if (ret != -EINTR)
			break;
	}
out:
	bch_btree_iter_unlock(&iter);
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
		const size_t prefix_len = strlen(handler->prefix);
		const size_t total_len = prefix_len + xattr->x_name_len + 1;

		if (buffer && total_len <= buffer_size) {
			memcpy(buffer, handler->prefix, prefix_len);
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
	return bch_xattr_get(inode->i_sb->s_fs_info, inode->i_ino,
			     name, buffer, size, handler->flags);
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
