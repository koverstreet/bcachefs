
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"
#include "io.h"
#include "keylist.h"

ssize_t bch_inode_status(char *buf, size_t len, const struct bkey *k)
{
	if (k->p.offset)
		return scnprintf(buf, len, "offset nonzero: %llu", k->p.offset);

	if (k->size)
		return scnprintf(buf, len, "size nonzero: %u", k->size);

	switch (k->type) {
	case KEY_TYPE_DELETED:
		return scnprintf(buf, len, "deleted");
	case KEY_TYPE_DISCARD:
		return scnprintf(buf, len, "discarded");
	case KEY_TYPE_ERROR:
		return scnprintf(buf, len, "error");
	case KEY_TYPE_COOKIE:
		return scnprintf(buf, len, "cookie");

	case BCH_INODE_FS:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode))
			return scnprintf(buf, len, "bad size: %lu",
					 bkey_val_bytes(k));

		if (k->p.inode < BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "fs inode in blockdev range: %llu",
					 k->p.inode);
		return 0;

	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode_blockdev))
			return scnprintf(buf, len, "bad size: %lu",
					 bkey_val_bytes(k));

		if (k->p.inode >= BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "blockdev inode in fs range: %llu",
					 k->p.inode);
		return 0;

	default:
		return scnprintf(buf, len, "unknown inode type: %u", k->type);
	}
}

static bool bch_inode_invalid(const struct cache_set *c, struct bkey_s_c k)
{
	if (k.k->p.offset)
		return true;

	switch (k.k->type) {
	case BCH_INODE_FS:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode))
			return true;

		if (k.k->p.inode < BLOCKDEV_INODE_MAX)
			return true;

		return false;
	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode_blockdev))
			return true;

		if (k.k->p.inode >= BLOCKDEV_INODE_MAX)
			return true;

		return false;
	default:
		return true;
	}
}

static void bch_inode_to_text(struct cache_set *c, char *buf,
			      size_t size, struct bkey_s_c k)
{
	struct bkey_s_c_inode inode;

	switch (k.k->type) {
	case BCH_INODE_FS:
		inode = bkey_s_c_to_inode(k);

		scnprintf(buf, size, "i_size %llu", inode.v->i_size);
		break;
	}
}

const struct btree_keys_ops bch_inode_ops = {
};

const struct bkey_ops bch_bkey_inode_ops = {
	.key_invalid	= bch_inode_invalid,
	.val_to_text	= bch_inode_to_text,
};

int bch_inode_create(struct cache_set *c, struct bkey_i *inode,
		     u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	bool searched_from_start = false;
	int ret;

	if ((max && *hint >= max) || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(*hint, 0));

	while ((k = bch_btree_iter_peek_with_holes(&iter)).k) {
		if (max && k.k->p.inode >= max)
			break;

		if (k.k->type < BCH_INODE_FS) {
			inode->k.p = k.k->p;

			pr_debug("inserting inode %llu (size %u)",
				 inode->k.p.inode, inode->k.u64s);

			ret = bch_btree_insert_at(&iter, &keylist_single(inode),
						  NULL, NULL,
						  BTREE_INSERT_ATOMIC);

			if (ret == -EINTR || ret == -EAGAIN)
				continue;

			bch_btree_iter_unlock(&iter);
			if (!ret)
				*hint = k.k->p.inode + 1;

			return ret;
		} else {
			/* slot used */
			bch_btree_iter_advance_pos(&iter);
		}
	}
	bch_btree_iter_unlock(&iter);

	if (!searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	return -ENOSPC;
}

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size)
{
	return bch_discard(c, POS(inode_nr, new_size), POS(inode_nr + 1, 0), 0);
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i delete;
	int ret;

	ret = bch_inode_truncate(c, inode_nr, 0);
	if (ret < 0)
		return ret;

	for_each_btree_key_intent(&iter, c, BTREE_ID_XATTRS,
				  POS(inode_nr, 0), k) {
		if (k.k->p.inode > inode_nr)
			break;

		bkey_init(&delete.k);
		delete.k.p = k.k->p;

		ret = bch_btree_insert_at(&iter, &keylist_single(&delete),
					  NULL, NULL, 0);
		if (ret) {
			bch_btree_iter_unlock(&iter);
			return ret;
		}

	}
	bch_btree_iter_unlock(&iter);

	bkey_init(&delete.k);
	delete.k.p.inode = inode_nr;

	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&delete),
				NULL, NULL, NULL,
				BTREE_INSERT_NOFAIL);
}

int bch_inode_find_by_inum(struct cache_set *c, u64 inode_nr,
			   struct bkey_i_inode *inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = -ENOENT;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_INODES,
				      POS(inode_nr, 0), k) {
		switch (k.k->type) {
		case BCH_INODE_FS:
			ret = 0;
			bkey_reassemble(&inode->k_i, k);
			break;
		default:
			/* hole, not found */
			break;
		}

		break;

	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

int bch_cached_dev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				      struct bkey_i_inode_blockdev *ret)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	for_each_btree_key(&iter, c, BTREE_ID_INODES, POS(0, 0), k) {
		if (k.k->p.inode >= BLOCKDEV_INODE_MAX)
			break;

		if (k.k->type == BCH_INODE_CACHED_DEV) {
			struct bkey_s_c_inode_blockdev inode =
				bkey_s_c_to_inode_blockdev(k);

			pr_debug("found inode %llu: %pU (u64s %u)",
				 inode.k->p.inode, inode.v->i_uuid.b,
				 inode.k->u64s);

			if (!memcmp(uuid, &inode.v->i_uuid, 16)) {
				bkey_reassemble(&ret->k_i, k);
				bch_btree_iter_unlock(&iter);
				return 0;
			}
		}

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);
	return -ENOENT;
}
