
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"
#include "io.h"
#include "keylist.h"

#define key_to_inode(k)	container_of(k, struct bch_inode, i_key)

ssize_t bch_inode_status(char *buf, size_t len, const struct bkey *k)
{
	struct bch_inode *inode = key_to_inode(k);

	if (KEY_DELETED(k))
		return scnprintf(buf, len, "deleted");

	if (KEY_WIPED(k))
		return scnprintf(buf, len, "wiped");

	if (bkey_bytes(k) < sizeof(struct bch_inode))
		return scnprintf(buf, len, "key too small: %lu", bkey_bytes(k));

	if (KEY_OFFSET(k))
		return scnprintf(buf, len, "offset nonzero: %llu",
				 KEY_OFFSET(k));

	if (KEY_SIZE(k))
		return scnprintf(buf, len, "size nonzero: %llu", KEY_SIZE(k));

	switch (inode->i_inode_format) {
	case BCH_INODE_FS:
		if (KEY_INODE(k) < BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "fs inode in blockdev range: %llu",
					 KEY_INODE(k));

		if (bkey_bytes(k) != sizeof(struct bch_inode))
			return scnprintf(buf, len, "bad key size: %lu",
					 bkey_bytes(k));

		break;
	case BCH_INODE_BLOCKDEV:
		if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "blockdev inode in fs range: %llu",
					 KEY_INODE(k));

		if (bkey_bytes(k) != sizeof(struct bch_inode_blockdev))
			return scnprintf(buf, len, "bad key size: %lu",
					 bkey_bytes(k));

		break;
	default:
		return scnprintf(buf, len, "unknown inode format: %u",
				 inode->i_inode_format);
	}

	return 0;
}

bool bch_inode_invalid(const struct bkey *k)
{
	struct bch_inode *inode = key_to_inode(k);

	if (KEY_DELETED(k))
		return false;

	if (KEY_WIPED(k)) {
		/* We don't use WIPED keys for inodes */
		return true;
	}

	if (bkey_bytes(k) < sizeof(struct bch_inode))
		return true;

	if (KEY_OFFSET(k))
		return true;

	if (KEY_SIZE(k))
		return true;

	switch (inode->i_inode_format) {
	case BCH_INODE_FS:
		if (KEY_INODE(k) < BLOCKDEV_INODE_MAX)
			return true;

		if (bkey_bytes(k) != sizeof(struct bch_inode))
			return true;

		break;
	case BCH_INODE_BLOCKDEV:
		if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
			return true;

		if (bkey_bytes(k) != sizeof(struct bch_inode_blockdev))
			return true;

		break;
	default:
		return true;
	}

	return false;
}

static bool __inode_invalid(const struct btree_keys *bk, const struct bkey *k)
{
	return bch_inode_invalid(k);
}

const struct btree_keys_ops bch_inode_ops = {
	.sort_fixup	= bch_generic_sort_fixup,
	.key_invalid	= __inode_invalid,
};

int bch_inode_create(struct cache_set *c, struct bch_inode *inode,
		     u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	const struct bkey *k;
	bool searched_from_start = false;
	int ret;

	if ((max && *hint >= max) || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES,
				   &KEY(*hint, 0, 0));

	while ((k = bch_btree_iter_peek_with_holes(&iter))) {
		if (max && KEY_INODE(k) >= max)
			break;

		if (!bch_val_u64s(k)) {
			bkey_copy_key(&inode->i_key, k);

			pr_debug("inserting inode %llu (size %llu)",
				 KEY_INODE(&inode->i_key),
				 KEY_U64s(&inode->i_key));

			ret = bch_btree_insert_at(&iter,
					&keylist_single(&inode->i_key),
					NULL, NULL, 0, BTREE_INSERT_ATOMIC);
			bch_btree_iter_unlock(&iter);

			if (!ret)
				goto out;
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

	ret = -ENOSPC;
out:
	if (!ret)
		*hint = KEY_INODE(&inode->i_key) + 1;

	return ret;
}

int bch_inode_update(struct cache_set *c, struct bch_inode *inode)
{
	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&inode->i_key),
				NULL, NULL);
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct bkey inode;
	int ret;

	ret = bch_discard(c, &KEY(inode_nr, 0, 0),
			  &KEY(inode_nr + 1, 0, 0), 0);
	if (ret < 0)
		return ret;

	inode = KEY(inode_nr, 0, 0);
	SET_KEY_DELETED(&inode, 1);

	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&inode),
				NULL, NULL);
}

int bch_blockdev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				    struct bch_inode_blockdev *ret)
{
	struct btree_iter iter;
	const struct bkey *k;

	for_each_btree_key(&iter, c, BTREE_ID_INODES, &KEY(0, 0, 0), k) {
		const struct bch_inode *inode = key_to_inode(k);

		if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
			break;

		if (inode->i_inode_format == BCH_INODE_BLOCKDEV) {
			const struct bch_inode_blockdev *binode =
				container_of(inode, struct bch_inode_blockdev,
					     i_inode);

			pr_debug("found inode %llu: %pU (u64s %llu)",
				 KEY_INODE(k), binode->i_uuid.b, KEY_U64s(k));

			if (!memcmp(uuid, &binode->i_uuid, 16)) {
				memcpy(ret, binode, sizeof(*binode));
				bch_btree_iter_unlock(&iter);
				return 0;
			}
		}

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);
	return -ENOENT;
}
