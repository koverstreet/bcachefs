// SPDX-License-Identifier: GPL-2.0
#ifdef CONFIG_BCACHEFS_POSIX_ACL

#include "bcachefs.h"

#include <linux/fs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "acl.h"
#include "fs.h"
#include "xattr.h"

static inline size_t bch2_acl_size(unsigned nr_short, unsigned nr_long)
{
	return sizeof(bch_acl_header) +
		sizeof(bch_acl_entry_short) * nr_short +
		sizeof(bch_acl_entry) * nr_long;
}

static inline int acl_to_xattr_type(int type)
{
	switch (type) {
	case ACL_TYPE_ACCESS:
		return KEY_TYPE_XATTR_INDEX_POSIX_ACL_ACCESS;
	case ACL_TYPE_DEFAULT:
		return KEY_TYPE_XATTR_INDEX_POSIX_ACL_DEFAULT;
	default:
		BUG();
	}
}

/*
 * Convert from filesystem to in-memory representation.
 */
static struct posix_acl *bch2_acl_from_disk(const void *value, size_t size)
{
	const void *p, *end = value + size;
	struct posix_acl *acl;
	struct posix_acl_entry *out;
	unsigned count = 0;

	if (!value)
		return NULL;
	if (size < sizeof(bch_acl_header))
		goto invalid;
	if (((bch_acl_header *)value)->a_version !=
	    cpu_to_le32(BCH_ACL_VERSION))
		goto invalid;

	p = value + sizeof(bch_acl_header);
	while (p < end) {
		const bch_acl_entry *entry = p;

		if (p + sizeof(bch_acl_entry_short) > end)
			goto invalid;

		switch (le16_to_cpu(entry->e_tag)) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			p += sizeof(bch_acl_entry_short);
			break;
		case ACL_USER:
		case ACL_GROUP:
			p += sizeof(bch_acl_entry);
			break;
		default:
			goto invalid;
		}

		count++;
	}

	if (p > end)
		goto invalid;

	if (!count)
		return NULL;

	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	out = acl->a_entries;

	p = value + sizeof(bch_acl_header);
	while (p < end) {
		const bch_acl_entry *in = p;

		out->e_tag  = le16_to_cpu(in->e_tag);
		out->e_perm = le16_to_cpu(in->e_perm);

		switch (out->e_tag) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			p += sizeof(bch_acl_entry_short);
			break;
		case ACL_USER:
			out->e_uid = make_kuid(&init_user_ns,
					       le32_to_cpu(in->e_id));
			p += sizeof(bch_acl_entry);
			break;
		case ACL_GROUP:
			out->e_gid = make_kgid(&init_user_ns,
					       le32_to_cpu(in->e_id));
			p += sizeof(bch_acl_entry);
			break;
		}

		out++;
	}

	BUG_ON(out != acl->a_entries + acl->a_count);

	return acl;
invalid:
	pr_err("invalid acl entry");
	return ERR_PTR(-EINVAL);
}

#define acl_for_each_entry(acl, acl_e)			\
	for (acl_e = acl->a_entries;			\
	     acl_e < acl->a_entries + acl->a_count;	\
	     acl_e++)

/*
 * Convert from in-memory to filesystem representation.
 */
static struct bkey_i_xattr *
bch2_acl_to_xattr(struct btree_trans *trans,
		  const struct posix_acl *acl,
		  int type)
{
	struct bkey_i_xattr *xattr;
	bch_acl_header *acl_header;
	const struct posix_acl_entry *acl_e;
	void *outptr;
	unsigned nr_short = 0, nr_long = 0, acl_len, u64s;

	acl_for_each_entry(acl, acl_e) {
		switch (acl_e->e_tag) {
		case ACL_USER:
		case ACL_GROUP:
			nr_long++;
			break;
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			nr_short++;
			break;
		default:
			return ERR_PTR(-EINVAL);
		}
	}

	acl_len = bch2_acl_size(nr_short, nr_long);
	u64s = BKEY_U64s + xattr_val_u64s(0, acl_len);

	if (u64s > U8_MAX)
		return ERR_PTR(-E2BIG);

	xattr = bch2_trans_kmalloc(trans, u64s * sizeof(u64));
	if (IS_ERR(xattr))
		return xattr;

	bkey_xattr_init(&xattr->k_i);
	xattr->k.u64s		= u64s;
	xattr->v.x_type		= acl_to_xattr_type(type);
	xattr->v.x_name_len	= 0,
	xattr->v.x_val_len	= cpu_to_le16(acl_len);

	acl_header = xattr_val(&xattr->v);
	acl_header->a_version = cpu_to_le32(BCH_ACL_VERSION);

	outptr = (void *) acl_header + sizeof(*acl_header);

	acl_for_each_entry(acl, acl_e) {
		bch_acl_entry *entry = outptr;

		entry->e_tag = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch (acl_e->e_tag) {
		case ACL_USER:
			entry->e_id = cpu_to_le32(
				from_kuid(&init_user_ns, acl_e->e_uid));
			outptr += sizeof(bch_acl_entry);
			break;
		case ACL_GROUP:
			entry->e_id = cpu_to_le32(
				from_kgid(&init_user_ns, acl_e->e_gid));
			outptr += sizeof(bch_acl_entry);
			break;

		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			outptr += sizeof(bch_acl_entry_short);
			break;
		}
	}

	BUG_ON(outptr != xattr_val(&xattr->v) + acl_len);

	return xattr;
}

struct posix_acl *bch2_get_acl(struct mnt_idmap *idmap,
			       struct dentry *dentry, int type)
{
	struct bch_inode_info *inode = to_bch_ei(dentry->d_inode);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_hash_info hash = bch2_hash_info_init(c, &inode->ei_inode);
	struct btree_trans trans;
	struct btree_iter iter = { NULL };
	struct bkey_s_c_xattr xattr;
	struct posix_acl *acl = NULL;
	struct bkey_s_c k;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);
retry:
	bch2_trans_begin(&trans);

	ret = bch2_hash_lookup(&trans, &iter, bch2_xattr_hash_desc,
			&hash, inode_inum(inode),
			&X_SEARCH(acl_to_xattr_type(type), "", 0),
			0);
	if (ret) {
		if (ret == -EINTR)
			goto retry;
		if (ret != -ENOENT)
			acl = ERR_PTR(ret);
		goto out;
	}

	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret) {
		acl = ERR_PTR(ret);
		goto out;
	}

	xattr = bkey_s_c_to_xattr(k);
	acl = bch2_acl_from_disk(xattr_val(xattr.v),
			le16_to_cpu(xattr.v->x_val_len));

	if (!IS_ERR(acl))
		set_cached_acl(&inode->v, type, acl);
out:
	bch2_trans_iter_exit(&trans, &iter);
	bch2_trans_exit(&trans);
	return acl;
}

int bch2_set_acl_trans(struct btree_trans *trans, subvol_inum inum,
		       struct bch_inode_unpacked *inode_u,
		       struct posix_acl *acl, int type)
{
	struct bch_hash_info hash_info = bch2_hash_info_init(trans->c, inode_u);
	int ret;

	if (type == ACL_TYPE_DEFAULT &&
	    !S_ISDIR(inode_u->bi_mode))
		return acl ? -EACCES : 0;

	if (acl) {
		struct bkey_i_xattr *xattr =
			bch2_acl_to_xattr(trans, acl, type);
		if (IS_ERR(xattr))
			return PTR_ERR(xattr);

		ret = bch2_hash_set(trans, bch2_xattr_hash_desc, &hash_info,
				    inum, &xattr->k_i, 0);
	} else {
		struct xattr_search_key search =
			X_SEARCH(acl_to_xattr_type(type), "", 0);

		ret = bch2_hash_delete(trans, bch2_xattr_hash_desc, &hash_info,
				       inum, &search);
	}

	return ret == -ENOENT ? 0 : ret;
}

int bch2_set_acl(struct mnt_idmap *idmap,
		 struct dentry *dentry,
		 struct posix_acl *_acl, int type)
{
	struct bch_inode_info *inode = to_bch_ei(dentry->d_inode);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct btree_trans trans;
	struct btree_iter inode_iter = { NULL };
	struct bch_inode_unpacked inode_u;
	struct posix_acl *acl;
	umode_t mode;
	int ret;

	mutex_lock(&inode->ei_update_lock);
	bch2_trans_init(&trans, c, 0, 0);
retry:
	bch2_trans_begin(&trans);
	acl = _acl;

	ret = bch2_inode_peek(&trans, &inode_iter, &inode_u, inode_inum(inode),
			      BTREE_ITER_INTENT);
	if (ret)
		goto btree_err;

	mode = inode_u.bi_mode;

	if (type == ACL_TYPE_ACCESS) {
		ret = posix_acl_update_mode(idmap, &inode->v, &mode, &acl);
		if (ret)
			goto btree_err;
	}

	ret = bch2_set_acl_trans(&trans, inode_inum(inode), &inode_u, acl, type);
	if (ret)
		goto btree_err;

	inode_u.bi_ctime	= bch2_current_time(c);
	inode_u.bi_mode		= mode;

	ret =   bch2_inode_write(&trans, &inode_iter, &inode_u) ?:
		bch2_trans_commit(&trans, NULL, NULL, 0);
btree_err:
	bch2_trans_iter_exit(&trans, &inode_iter);

	if (ret == -EINTR)
		goto retry;
	if (unlikely(ret))
		goto err;

	bch2_inode_update_after_write(c, inode, &inode_u,
				      ATTR_CTIME|ATTR_MODE);

	set_cached_acl(&inode->v, type, acl);
err:
	bch2_trans_exit(&trans);
	mutex_unlock(&inode->ei_update_lock);

	return ret;
}

int bch2_acl_chmod(struct btree_trans *trans, subvol_inum inum,
		   struct bch_inode_unpacked *inode,
		   umode_t mode,
		   struct posix_acl **new_acl)
{
	struct bch_hash_info hash_info = bch2_hash_info_init(trans->c, inode);
	struct btree_iter iter;
	struct bkey_s_c_xattr xattr;
	struct bkey_i_xattr *new;
	struct posix_acl *acl;
	struct bkey_s_c k;
	int ret;

	ret = bch2_hash_lookup(trans, &iter, bch2_xattr_hash_desc,
			       &hash_info, inum,
			&X_SEARCH(KEY_TYPE_XATTR_INDEX_POSIX_ACL_ACCESS, "", 0),
			BTREE_ITER_INTENT);
	if (ret)
		return ret == -ENOENT ? 0 : ret;

	k = bch2_btree_iter_peek_slot(&iter);
	xattr = bkey_s_c_to_xattr(k);
	if (ret)
		goto err;

	acl = bch2_acl_from_disk(xattr_val(xattr.v),
			le16_to_cpu(xattr.v->x_val_len));
	ret = PTR_ERR_OR_ZERO(acl);
	if (IS_ERR_OR_NULL(acl))
		goto err;

	ret = __posix_acl_chmod(&acl, GFP_KERNEL, mode);
	if (ret)
		goto err;

	new = bch2_acl_to_xattr(trans, acl, ACL_TYPE_ACCESS);
	if (IS_ERR(new)) {
		ret = PTR_ERR(new);
		goto err;
	}

	new->k.p = iter.pos;
	ret = bch2_trans_update(trans, &iter, &new->k_i, 0);
	*new_acl = acl;
	acl = NULL;
err:
	bch2_trans_iter_exit(trans, &iter);
	if (!IS_ERR_OR_NULL(acl))
		kfree(acl);
	return ret;
}

#endif /* CONFIG_BCACHEFS_POSIX_ACL */
