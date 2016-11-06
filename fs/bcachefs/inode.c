
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
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
			return scnprintf(buf, len, "bad size: %zu",
					 bkey_val_bytes(k));

		if (k->p.inode < BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "fs inode in blockdev range: %llu",
					 k->p.inode);
		return 0;

	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode_blockdev))
			return scnprintf(buf, len, "bad size: %zu",
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

static const char *bch_inode_invalid(const struct cache_set *c,
				     struct bkey_s_c k)
{
	if (k.k->p.offset)
		return "nonzero offset";

	switch (k.k->type) {
	case BCH_INODE_FS: {
		struct bkey_s_c_inode inode = bkey_s_c_to_inode(k);

		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode))
			return "incorrect value size";

		if (k.k->p.inode < BLOCKDEV_INODE_MAX)
			return "fs inode in blockdev range";

		if (INODE_STR_HASH_TYPE(inode.v) >= BCH_STR_HASH_NR)
			return "invalid str hash type";

		return NULL;
	}
	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode_blockdev))
			return "incorrect value size";

		if (k.k->p.inode >= BLOCKDEV_INODE_MAX)
			return "blockdev inode in fs range";

		return NULL;
	default:
		return "invalid type";
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

const struct bkey_ops bch_bkey_inode_ops = {
	.key_invalid	= bch_inode_invalid,
	.val_to_text	= bch_inode_to_text,
};

int bch_inode_create(struct cache_set *c, struct bkey_i *inode,
		     u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	bool searched_from_start = false;
	int ret;

	if (!max)
		max = ULLONG_MAX;

	if (c->opts.inodes_32bit)
		max = min_t(u64, max, U32_MAX);

	if (*hint >= max || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(*hint, 0));

	while (1) {
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);

		ret = btree_iter_err(k);
		if (ret) {
			bch_btree_iter_unlock(&iter);
			return ret;
		}

		if (k.k->type < BCH_INODE_FS) {
			inode->k.p = k.k->p;

			pr_debug("inserting inode %llu (size %u)",
				 inode->k.p.inode, inode->k.u64s);

			ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&iter, inode));

			if (ret == -EINTR)
				continue;

			bch_btree_iter_unlock(&iter);
			if (!ret)
				*hint = k.k->p.inode + 1;

			return ret;
		} else {
			if (iter.pos.inode == max)
				break;
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

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size,
		       struct extent_insert_hook *hook, u64 *journal_seq)
{
	return bch_discard(c, POS(inode_nr, new_size), POS(inode_nr + 1, 0),
			   0, NULL, hook, journal_seq);
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct bkey_i delete;
	int ret;

	ret = bch_inode_truncate(c, inode_nr, 0, NULL, NULL);
	if (ret < 0)
		return ret;

	ret = bch_btree_delete_range(c, BTREE_ID_XATTRS,
				     POS(inode_nr, 0),
				     POS(inode_nr + 1, 0),
				     0, NULL, NULL, NULL);
	if (ret < 0)
		return ret;

	/*
	 * If this was a directory, there shouldn't be any real dirents left -
	 * but there could be whiteouts (from hash collisions) that we should
	 * delete:
	 *
	 * XXX: the dirent could ideally would delete whitouts when they're no
	 * longer needed
	 */
	ret = bch_btree_delete_range(c, BTREE_ID_DIRENTS,
				     POS(inode_nr, 0),
				     POS(inode_nr + 1, 0),
				     0, NULL, NULL, NULL);
	if (ret < 0)
		return ret;

	bkey_init(&delete.k);
	delete.k.p.inode = inode_nr;

	return bch_btree_insert(c, BTREE_ID_INODES, &delete, NULL,
				NULL, NULL, BTREE_INSERT_NOFAIL);
}

int bch_inode_update(struct cache_set *c, struct bkey_i *inode,
		     u64 *journal_seq)
{
	return bch_btree_update(c, BTREE_ID_INODES, inode, journal_seq);
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

		if (k.k->type == BCH_INODE_BLOCKDEV) {
			struct bkey_s_c_inode_blockdev inode =
				bkey_s_c_to_inode_blockdev(k);

			pr_debug("found inode %llu: %pU (u64s %u)",
				 inode.k->p.inode, inode.v->i_uuid.b,
				 inode.k->u64s);

			if (CACHED_DEV(inode.v) &&
			    !memcmp(uuid, &inode.v->i_uuid, 16)) {
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
