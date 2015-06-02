
#include "bcache.h"
#include "btree.h"
#include "inode.h"

/* XXX: need ptr_invalid() method for inodes */

struct create_op {
	struct btree_op		op;
	struct bch_inode	 *inode;
	u64			max;
	u64			search;
};

static int bch_inode_create_fn(struct btree_op *b_op, struct btree *b,
			       struct bkey *k)
{
	struct create_op *op = container_of(b_op, struct create_op, op);
	struct keylist keys;
	int ret;

	if (k ? op->search < KEY_INODE(k)
	      : op->search <= KEY_INODE(&b->key))
		goto insert;

	op->search = (k ? KEY_INODE(k) : KEY_INODE(&b->key)) + 1;

	return MAP_CONTINUE;
insert:
	/* Found a gap */

	if (op->max && op->search >= op->max)
		return -ENOSPC;

	SET_KEY_INODE(&op->inode->i_key, op->search);

	pr_debug("inserting inode %llu (size %llu)",
		 KEY_INODE(&op->inode->i_key), KEY_U64s(&op->inode->i_key));

	bch_keylist_init_single(&keys, &op->inode->i_key);
	ret = bch_btree_insert_node(b, b_op, &keys, NULL, NULL);

	BUG_ON(!ret && !bch_keylist_empty(&keys));

	return ret;
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

	bch_btree_op_init(&op.op, 0);
	op.inode	= inode;
	op.max		= max;
	op.search	= *hint;
again:
	ret = bch_btree_map_keys(&op.op, c, BTREE_ID_INODES,
				 PRECEDING_KEY(&KEY(op.search, 0, 0)),
				 bch_inode_create_fn, MAP_END_KEY);
	if (ret == MAP_CONTINUE)
		ret = -ENOSPC;

	if (ret == -ENOSPC && !searched_from_start) {
		/* Retry from start */
		op.search = min;
		searched_from_start = true;
		goto again;
	}

	if (!ret)
		*hint = KEY_INODE(&inode->i_key) + 1;

	return ret;
}

int bch_inode_update(struct cache_set *c, struct bch_inode *inode)
{
	struct keylist keys;

	bch_keylist_init_single(&keys, &inode->i_key);
	return bch_btree_insert(c, BTREE_ID_INODES, &keys, NULL, NULL);
}

struct inode_rm_op {
	struct btree_op		op;
	u64			inode_nr;
};

/* XXX: this is slow, due to writes and sequential lookups */
static int inode_rm_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct inode_rm_op *op = container_of(b_op, struct inode_rm_op, op);
	struct keylist keys;
	struct bkey erase_key;
	int ret;

	if (KEY_INODE(k) > op->inode_nr)
		return MAP_DONE;

	if (KEY_INODE(k) < op->inode_nr)
		BUG();

	erase_key = KEY(op->inode_nr,
			KEY_START(k) + KEY_SIZE_MAX,
			KEY_SIZE_MAX);

	if (bkey_cmp(&erase_key, &b->key) > 0)
		bch_cut_back(&b->key, &erase_key);

	bch_keylist_init_single(&keys, &erase_key);

	ret = bch_btree_insert_node(b, b_op, &keys, NULL, NULL);
	BUG_ON(!ret && !bch_keylist_empty(&keys));

	return -EINTR;
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct inode_rm_op op;
	struct keylist keys;
	struct bkey inode;
	int ret;

	bch_btree_op_init(&op.op, 0);
	op.inode_nr = inode_nr;

	ret = bch_btree_map_keys(&op.op, c, BTREE_ID_EXTENTS,
				 PRECEDING_KEY(&KEY(inode_nr, 0, 0)),
				 inode_rm_fn, 0);
	if (ret < 0)
		BUG();

	inode = KEY(inode_nr, 0, 0);
	SET_KEY_DELETED(&inode, 1);
	bch_keylist_init_single(&keys, &inode);

	return bch_btree_insert(c, BTREE_ID_INODES, &keys, NULL, NULL);
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
	struct bch_inode *inode = container_of(k, struct bch_inode, i_key);

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

	bch_btree_op_init(&op.op, -1);
	op.uuid = uuid;
	op.ret = ret;

	return bch_btree_map_keys(&op.op, c, BTREE_ID_INODES, NULL,
				  blockdev_inode_find_fn, 0) == MAP_DONE
		? 0 : -ENOENT;
}
EXPORT_SYMBOL(bch_blockdev_inode_find_by_uuid);

/* Old UUID code */

#include "extents.h"
#include "journal.h"

static void uuid_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;

	closure_put(cl);
}

static int uuid_io(struct cache_set *c, struct bkey *k,
		   struct uuid_entry *uuids)
{
	struct closure cl;
	int err = -EIO;
	unsigned i;

	closure_init_stack(&cl);

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		struct bio *bio = bch_bbio_alloc(c);

		bio->bi_iter.bi_size = KEY_SIZE(k) << 9;
		bio->bi_end_io	= uuid_endio;
		bio->bi_private = &cl;
		bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC|REQ_META);
		bch_bio_map(bio, uuids);

		bch_submit_bbio(bio, c, k, i);
		closure_sync(&cl);

		err = bio->bi_error;
		bch_bbio_free(bio, c);

		if (!err)
			return 0;
	}

	return -EIO;

	return 0;
}

char *bch_uuid_convert(struct cache_set *c, struct jset *j, struct closure *cl)
{
	int i, level;
	unsigned order, nr_uuids = bucket_bytes(c) / sizeof(struct uuid_entry);
	struct uuid_entry *uuids;
	struct bkey *k;

	k = bch_journal_find_btree_root(c, j, BTREE_ID_UUIDS, &level);
	if (!k)
		return "bad uuid pointer";

	order = ilog2(bucket_pages(c));

	uuids = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!uuids)
		return "-ENOMEM";

	if (uuid_io(c, k, uuids))
		return "error reading old style uuids";

	if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
		struct uuid_entry_v0	*u0 = (void *) uuids;
		struct uuid_entry	*u1 = (void *) uuids;

		closure_sync(cl);

		/*
		 * Since the new uuid entry is bigger than the old, we have to
		 * convert starting at the highest memory address and work down
		 * in order to do it in place
		 */

		for (i = nr_uuids - 1;
		     i >= 0;
		     --i) {
			u1[i].uuid		= u0[i].uuid;
			memcpy(u1[i].label,	u0[i].label, 32);

			u1[i].first_reg		= u0[i].first_reg;
			u1[i].last_reg		= u0[i].last_reg;
			u1[i].invalidated	= u0[i].invalidated;

			u1[i].flags	= 0;
			u1[i].sectors	= 0;
		}
	}

	for (i = 0; i < nr_uuids; i++) {
		struct uuid_entry *u = uuids + i;
		struct bch_inode_blockdev ui;

		if (bch_is_zero(u->uuid.b, sizeof(u->uuid)))
			continue;

		pr_debug("Slot %zi: %pU: %s: 1st: %u last: %u inv: %u",
			 u - uuids, u->uuid.b, u->label,
			 u->first_reg, u->last_reg, u->invalidated);

		BCH_INODE_INIT(&ui);
		ui.i_inode.i_size	= u->sectors << 9;
		ui.i_inode.i_flags	= u->flags;
		ui.i_inode.i_ctime	= u->first_reg * NSEC_PER_SEC;
		ui.i_inode.i_mtime	= u->last_reg * NSEC_PER_SEC;

		ui.i_uuid = u->uuid;
		memcpy(ui.i_label, u->label, 32);
		SET_INODE_FLASH_ONLY(&ui, UUID_FLASH_ONLY(u));

		SET_KEY_INODE(&ui.i_inode.i_key, i);

		bch_inode_update(c, &ui.i_inode);
	}

	free_pages((unsigned long) uuids, order);

	return NULL;
}
