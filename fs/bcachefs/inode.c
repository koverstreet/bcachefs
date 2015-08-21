
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"
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
	.insert_fixup	= bch_generic_insert_fixup,
	.key_invalid	= __inode_invalid,
};

struct create_op {
	struct btree_op		op;
	struct bch_inode	 *inode;
	u64			max;
};

static int bch_inode_create_fn(struct btree_op *b_op, struct btree *b,
			       struct bkey *k)
{
	struct create_op *op = container_of(b_op, struct create_op, op);

	/* slot used? */
	if (bch_val_u64s(k))
		return MAP_CONTINUE;

	/* hole: */

	if (op->max && KEY_INODE(k) >= op->max)
		return -ENOSPC;

	bkey_copy_key(&op->inode->i_key, k);

	pr_debug("inserting inode %llu (size %llu)",
		 KEY_INODE(&op->inode->i_key), KEY_U64s(&op->inode->i_key));

	return bch_btree_insert_node(b, b_op,
			&keylist_single(&op->inode->i_key), NULL, NULL, 0);
}

int bch_inode_create(struct cache_set *c, struct bch_inode *inode,
		     u64 min, u64 max, u64 *hint)
{
	int ret;
	struct create_op op;
	bool searched_from_start = false;

	if ((max && *hint >= max) || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, 0);
	op.inode	= inode;
	op.max		= max;
again:
	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(*hint, 0, 0),
				 bch_inode_create_fn, MAP_HOLES);
	if (ret == MAP_CONTINUE)
		ret = -ENOSPC;

	if (ret == -ENOSPC && !searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	if (!ret)
		*hint = KEY_INODE(&inode->i_key) + 1;

	return ret;
}

int bch_inode_update(struct cache_set *c, struct bch_inode *inode)
{
	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&inode->i_key), NULL);
}

struct inode_rm_op {
	struct btree_op		op;
	u64			inode_nr;
};

/* XXX: this is slow, due to writes and sequential lookups */
static int inode_rm_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct inode_rm_op *op = container_of(b_op, struct inode_rm_op, op);
	struct bkey erase_key;

	if (KEY_INODE(k) > op->inode_nr)
		return MAP_DONE;

	if (KEY_INODE(k) < op->inode_nr)
		BUG();

	erase_key = KEY(op->inode_nr,
			KEY_START(k) + KEY_SIZE_MAX,
			KEY_SIZE_MAX);
	SET_KEY_DELETED(&erase_key, 1);

	if (bkey_cmp(&erase_key, &b->key) > 0)
		bch_cut_back(&b->key, &erase_key);

	return bch_btree_insert_node(b, b_op,
			&keylist_single(&erase_key), NULL, NULL, 0)
		?: MAP_CONTINUE;
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct inode_rm_op op;
	struct bkey inode;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, 0);
	op.inode_nr = inode_nr;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(inode_nr, 0, 0),
				 inode_rm_fn, 0);
	if (ret < 0)
		return ret;

	inode = KEY(inode_nr, 0, 0);
	SET_KEY_DELETED(&inode, 1);

	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&inode), NULL);
}

struct find_op {
	struct btree_op		op;
	uuid_le			*uuid;
	struct bch_inode_blockdev	*ret;
};

static int blockdev_inode_find_fn(struct btree_op *b_op, struct btree *b,
				  struct bkey *k)
{
	struct find_op *op = container_of(b_op, struct find_op, op);
	struct bch_inode *inode = key_to_inode(k);

	if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
		return -ENOENT;

	if (inode->i_inode_format == BCH_INODE_BLOCKDEV) {
		struct bch_inode_blockdev *binode =
			container_of(inode, struct bch_inode_blockdev, i_inode);

		pr_debug("found inode %llu: %pU (u64s %llu)",
			 KEY_INODE(k), binode->i_uuid.b, KEY_U64s(k));

		if (!memcmp(op->uuid, &binode->i_uuid, 16)) {
			memcpy(op->ret, binode, sizeof(*binode));
			return MAP_DONE;
		}
	}

	return MAP_CONTINUE;
}

int bch_blockdev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				    struct bch_inode_blockdev *ret)
{
	struct find_op op;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, -1);
	op.uuid = uuid;
	op.ret = ret;

	return bch_btree_map_keys(&op.op, c, NULL,
				  blockdev_inode_find_fn, 0) == MAP_DONE
		? 0 : -ENOENT;
}
EXPORT_SYMBOL(bch_blockdev_inode_find_by_uuid);
