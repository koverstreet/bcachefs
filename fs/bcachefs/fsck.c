// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey_buf.h"
#include "btree_update.h"
#include "dirent.h"
#include "error.h"
#include "fs-common.h"
#include "fsck.h"
#include "inode.h"
#include "keylist.h"
#include "subvolume.h"
#include "super.h"
#include "xattr.h"

#include <linux/bsearch.h>
#include <linux/dcache.h> /* struct qstr */

#define QSTR(n) { { { .len = strlen(n) } }, .name = n }

static s64 bch2_count_inode_sectors(struct btree_trans *trans, u64 inum)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	u64 sectors = 0;
	int ret;

	for_each_btree_key(trans, iter, BTREE_ID_extents,
			   POS(inum, 0), 0, k, ret) {
		if (k.k->p.inode != inum)
			break;

		if (bkey_extent_is_allocation(k.k))
			sectors += k.k->size;
	}

	bch2_trans_iter_free(trans, iter);

	return ret ?: sectors;
}

static int __snapshot_lookup_subvol(struct btree_trans *trans, u32 snapshot,
				    u32 *subvol)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_snapshots,
			POS(0, snapshot), 0);
	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_snapshot) {
		bch_err(trans->c, "snapshot %u not fonud", snapshot);
		ret = -ENOENT;
		goto err;
	}

	*subvol = le32_to_cpu(bkey_s_c_to_snapshot(k).v->subvol);
err:
	bch2_trans_iter_free(trans, iter);
	return ret;

}

static int snapshot_lookup_subvol(struct btree_trans *trans, u32 snapshot,
				  u32 *subvol)
{
	return lockrestart_do(trans, __snapshot_lookup_subvol(trans, snapshot, subvol));
}

static int __subvol_lookup(struct btree_trans *trans, u32 subvol,
			   u32 *snapshot, u64 *inum)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_subvolumes,
				   POS(0, subvol), 0);
	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_subvolume) {
		bch_err(trans->c, "subvolume %u not fonud", subvol);
		ret = -ENOENT;
		goto err;
	}

	*snapshot = le32_to_cpu(bkey_s_c_to_subvolume(k).v->snapshot);
	*inum = le64_to_cpu(bkey_s_c_to_subvolume(k).v->inode);
err:
	bch2_trans_iter_free(trans, iter);
	return ret;

}

static int subvol_lookup(struct btree_trans *trans, u32 subvol,
			 u32 *snapshot, u64 *inum)
{
	return lockrestart_do(trans, __subvol_lookup(trans, subvol, snapshot, inum));
}

static int __lookup_inode(struct btree_trans *trans, u64 inode_nr,
			  struct bch_inode_unpacked *inode,
			  u32 *snapshot)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_inodes,
			POS(0, inode_nr), 0);
	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (snapshot)
		*snapshot = iter->pos.snapshot;
	ret = k.k->type == KEY_TYPE_inode
		? bch2_inode_unpack(bkey_s_c_to_inode(k), inode)
		: -ENOENT;
err:
	bch2_trans_iter_free(trans, iter);
	return ret;
}

static int lookup_inode(struct btree_trans *trans, u64 inode_nr,
			struct bch_inode_unpacked *inode,
			u32 *snapshot)
{
	return lockrestart_do(trans, __lookup_inode(trans, inode_nr, inode, snapshot));
}

static int __lookup_dirent(struct btree_trans *trans,
			   struct bch_hash_info hash_info,
			   subvol_inum dir, struct qstr *name,
			   u64 *target, unsigned *type)
{
	struct btree_iter *iter;
	struct bkey_s_c_dirent d;

	iter = bch2_hash_lookup(trans, bch2_dirent_hash_desc,
				&hash_info, dir, name, 0);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	d = bkey_s_c_to_dirent(bch2_btree_iter_peek_slot(iter));
	*target = le64_to_cpu(d.v->d_inum);
	*type = d.v->d_type;
	bch2_trans_iter_put(trans, iter);
	return 0;
}

static int lookup_dirent(struct btree_trans *trans,
			 struct bch_hash_info hash_info,
			 subvol_inum dir, struct qstr *name,
			 u64 *target, unsigned *type)
{
	return lockrestart_do(trans,
		__lookup_dirent(trans, hash_info, dir, name, target, type));
}

static int __write_inode(struct btree_trans *trans,
			 struct bch_inode_unpacked *inode,
			 u32 snapshot)
{
	struct btree_iter *inode_iter =
		bch2_trans_get_iter(trans, BTREE_ID_inodes,
				    SPOS(0, inode->bi_inum, snapshot),
				    BTREE_ITER_INTENT);
	int ret = bch2_inode_write(trans, inode_iter, inode);
	bch2_trans_iter_put(trans, inode_iter);
	return ret;
}

static int write_inode(struct btree_trans *trans,
		       struct bch_inode_unpacked *inode,
		       u32 snapshot)
{
	int ret = __bch2_trans_do(trans, NULL, NULL,
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_LAZY_RW,
				  __write_inode(trans, inode, snapshot));
	if (ret)
		bch_err(trans->c, "error in fsck: error %i updating inode", ret);
	return ret;
}

static int __remove_dirent(struct btree_trans *trans, struct bpos pos)
{
	struct bch_fs *c = trans->c;
	struct btree_iter *iter;
	struct bch_inode_unpacked dir_inode;
	struct bch_hash_info dir_hash_info;
	int ret;

	ret = lookup_inode(trans, pos.inode, &dir_inode, NULL);
	if (ret)
		return ret;

	dir_hash_info = bch2_hash_info_init(c, &dir_inode);

	iter = bch2_trans_get_iter(trans, BTREE_ID_dirents, pos, BTREE_ITER_INTENT);

	ret = bch2_hash_delete_at(trans, bch2_dirent_hash_desc,
				  &dir_hash_info, iter);
	bch2_trans_iter_put(trans, iter);
	return ret;
}

static int remove_dirent(struct btree_trans *trans, struct bpos pos)
{
	int ret = __bch2_trans_do(trans, NULL, NULL,
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_LAZY_RW,
				  __remove_dirent(trans, pos));
	if (ret)
		bch_err(trans->c, "remove_dirent: err %i deleting dirent", ret);
	return ret;
}

/* Get lost+found, create if it doesn't exist: */
static int lookup_lostfound(struct btree_trans *trans, u32 subvol,
			    struct bch_inode_unpacked *lostfound)
{
	struct bch_fs *c = trans->c;
	struct bch_inode_unpacked root;
	struct bch_hash_info root_hash_info;
	struct qstr lostfound_str = QSTR("lost+found");
	subvol_inum root_inum = { .subvol = subvol };
	u64 inum = 0;
	unsigned d_type = 0;
	u32 snapshot;
	int ret;

	ret = subvol_lookup(trans, subvol, &snapshot, &root_inum.inum);
	if (ret)
		return ret;

	ret = lookup_inode(trans, root_inum.inum, &root, &snapshot);
	if (ret) {
		bch_err(c, "error fetching subvol root: %i", ret);
		return ret;
	}

	root_hash_info = bch2_hash_info_init(c, &root);

	ret = lookup_dirent(trans, root_hash_info, root_inum,
			    &lostfound_str, &inum, &d_type);
	if (ret == -ENOENT) {
		bch_notice(c, "creating lost+found");
		goto create_lostfound;
	}

	if (ret) {
		bch_err(c, "error looking up lost+found: %i", ret);
		return ret;
	}

	if (d_type != DT_DIR) {
		bch_err(c, "error looking up lost+found: not a directory");
		return ret;

	}

	ret = lookup_inode(trans, inum, lostfound, &snapshot);
	if (ret && ret != -ENOENT) {
		/*
		 * The check_dirents pass has already run, dangling dirents
		 * shouldn't exist here:
		 */
		bch_err(c, "error looking up lost+found: %i", ret);
		return ret;
	}

	if (ret == -ENOENT) {
create_lostfound:
		bch2_inode_init_early(c, lostfound);

		ret = __bch2_trans_do(trans, NULL, NULL,
				      BTREE_INSERT_NOFAIL|
				      BTREE_INSERT_LAZY_RW,
			bch2_create_trans(trans, root_inum, &root,
					  lostfound, &lostfound_str,
					  0, 0, S_IFDIR|0700, 0, NULL, NULL, 0));
		if (ret)
			bch_err(c, "error creating lost+found: %i", ret);
	}

	return 0;
}

static int reattach_inode(struct btree_trans *trans,
			  struct bch_inode_unpacked *inode,
			  u32 inode_snapshot)
{
	struct bch_hash_info dir_hash;
	struct bch_inode_unpacked lostfound;
	char name_buf[20];
	struct qstr name;
	u64 dir_offset = 0;
	u32 subvol;
	int ret;

	ret = snapshot_lookup_subvol(trans, inode_snapshot, &subvol);
	if (ret)
		return ret;

	ret = lookup_lostfound(trans, subvol, &lostfound);
	if (ret)
		return ret;

	if (S_ISDIR(inode->bi_mode)) {
		lostfound.bi_nlink++;

		ret = write_inode(trans, &lostfound, U32_MAX);
		if (ret)
			return ret;
	}

	dir_hash = bch2_hash_info_init(trans->c, &lostfound);

	snprintf(name_buf, sizeof(name_buf), "%llu", inode->bi_inum);
	name = (struct qstr) QSTR(name_buf);

	ret = __bch2_trans_do(trans, NULL, NULL, BTREE_INSERT_LAZY_RW,
			bch2_dirent_create(trans,
					   (subvol_inum) {
						.subvol = subvol,
						.inum = lostfound.bi_inum,
					   },
					   &dir_hash,
					   mode_to_type(inode->bi_mode),
					   &name, inode->bi_inum, &dir_offset,
					   BCH_HASH_SET_MUST_CREATE));
	if (ret) {
		bch_err(trans->c, "error %i reattaching inode %llu",
			ret, inode->bi_inum);
		return ret;
	}

	inode->bi_dir		= lostfound.bi_inum;
	inode->bi_dir_offset	= dir_offset;

	return write_inode(trans, inode, inode_snapshot);
}

static int remove_backpointer(struct btree_trans *trans,
			      struct bch_inode_unpacked *inode)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_dirents,
				   POS(inode->bi_dir, inode->bi_dir_offset), 0);
	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto out;
	if (k.k->type != KEY_TYPE_dirent) {
		ret = -ENOENT;
		goto out;
	}

	ret = remove_dirent(trans, k.k->p);
out:
	bch2_trans_iter_put(trans, iter);
	return ret;
}

struct inode_walker {
	bool				first_this_inode;
	u64				cur_inum;
	u32				cur_snapshot;

	size_t				nr;
	size_t				size;
	struct inode_walker_entry {
		struct bch_inode_unpacked inode;
		u32			snapshot;
		bool			visited;
		u64			count;
	} *d;
};

static void inode_walker_exit(struct inode_walker *w)
{
	kfree(w->d);
	w->d = NULL;
}

static struct inode_walker inode_walker_init(void)
{
	return (struct inode_walker) { 0, };
}

static int add_inode(struct inode_walker *w, struct bkey_s_c_inode inode)
{
	struct bch_inode_unpacked u;

	if (w->nr == w->size) {
		size_t new_size = max_t(size_t, 8UL, w->size * 2);
		void *d = krealloc(w->d, new_size * sizeof(w->d[0]),
				   GFP_KERNEL);
		if (!d) {
			return -ENOMEM;
		}

		w->d = d;
		w->size = new_size;
	}

	BUG_ON(bch2_inode_unpack(inode, &u));

	w->d[w->nr++] = (struct inode_walker_entry) {
		.inode		= u,
		.snapshot	= inode.k->p.snapshot,
	};

	return 0;
}

static int __walk_inode(struct btree_trans *trans,
			struct inode_walker *w, u64 inum)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	if (inum == w->cur_inum) {
		w->first_this_inode = false;
		return 0;
	}

	w->nr = 0;

	for_each_btree_key(trans, iter, BTREE_ID_inodes, POS(0, inum),
			   BTREE_ITER_ALL_SNAPSHOTS, k, ret) {
		if (k.k->p.offset != inum)
			break;

		if (k.k->type == KEY_TYPE_inode)
			add_inode(w, bkey_s_c_to_inode(k));
	}
	bch2_trans_iter_put(trans, iter);

	if (!ret) {
		w->cur_inum		= inum;
		w->cur_snapshot		= 0;
		w->first_this_inode	= true;
	}

	return ret;
}

static int walk_inode(struct btree_trans *trans,
		      struct inode_walker *w, u64 inum)
{
	return lockrestart_do(trans, __walk_inode(trans, w, inum));
}

static struct inode_walker_entry *get_next_inode(struct bch_fs *c,
						 struct inode_walker *w, u32 snapshot)
{
	struct inode_walker_entry *i;

	for (i = w->d; i < w->d + w->nr; i++) {
		if (i->visited)
			continue;

		if (i->snapshot < snapshot &&
		    bch2_snapshot_is_ancestor(c, i->snapshot, snapshot)) {
			i->visited = true;
			return i;
		}

		if (snapshot <= i->snapshot &&
		    snapshot == w->cur_snapshot)
			break;

		if (snapshot <= i->snapshot &&
		    bch2_snapshot_is_ancestor(c, snapshot, i->snapshot)) {
			w->cur_snapshot = snapshot;
			i->visited = true;
			return i;
		}
	}

	return NULL;
}

static int hash_redo_key(struct btree_trans *trans,
			 const struct bch_hash_desc desc,
			 struct bch_hash_info *hash_info,
			 struct btree_iter *k_iter, struct bkey_s_c k)
{
	bch_err(trans->c, "hash_redo_key() not implemented yet");
	return -EINVAL;
#if 0
	struct bkey_i *delete;
	struct bkey_i *tmp;

	delete = bch2_trans_kmalloc(trans, sizeof(*delete));
	if (IS_ERR(delete))
		return PTR_ERR(delete);

	tmp = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	bkey_reassemble(tmp, k);

	bkey_init(&delete->k);
	delete->k.p = k_iter->pos;
	bch2_trans_update(trans, k_iter, delete, 0);

	return bch2_hash_set(trans, desc, hash_info, k_iter->pos.inode, tmp, 0);
#endif
}

static int fsck_hash_delete_at(struct btree_trans *trans,
			       const struct bch_hash_desc desc,
			       struct bch_hash_info *info,
			       struct btree_iter *iter)
{
	int ret;
retry:
	ret   = bch2_hash_delete_at(trans, desc, info, iter) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_LAZY_RW);
	if (ret == -EINTR) {
		ret = bch2_btree_iter_traverse(iter);
		if (!ret)
			goto retry;
	}

	return ret;
}

static int hash_check_key(struct btree_trans *trans,
			  const struct bch_hash_desc desc,
			  struct bch_hash_info *hash_info,
			  struct btree_iter *k_iter, struct bkey_s_c hash_k)
{
	struct bch_fs *c = trans->c;
	struct btree_iter *iter = NULL;
	char buf[200];
	struct bkey_s_c k;
	u64 hash;
	int ret = 0;

	if (hash_k.k->type != desc.key_type)
		return 0;

	hash = desc.hash_bkey(hash_info, hash_k);

	if (likely(hash == hash_k.k->p.offset))
		return 0;

	if (hash_k.k->p.offset < hash)
		goto bad_hash;

	for_each_btree_key(trans, iter, desc.btree_id, POS(hash_k.k->p.inode, hash),
			   BTREE_ITER_SLOTS, k, ret) {
		if (!bkey_cmp(k.k->p, hash_k.k->p))
			break;

		if (fsck_err_on(k.k->type == desc.key_type &&
				!desc.cmp_bkey(k, hash_k), c,
				"duplicate hash table keys:\n%s",
				(bch2_bkey_val_to_text(&PBUF(buf), c,
						       hash_k), buf))) {
			ret = fsck_hash_delete_at(trans, desc, hash_info, k_iter);
			if (ret)
				return ret;
			ret = 1;
			break;
		}

		if (bkey_deleted(k.k)) {
			bch2_trans_iter_free(trans, iter);
			goto bad_hash;
		}

	}
	bch2_trans_iter_free(trans, iter);
	return ret;
bad_hash:
	if (fsck_err(c, "hash table key at wrong offset: btree %u inode %llu offset %llu, "
		     "hashed to %llu\n%s",
		     desc.btree_id, hash_k.k->p.inode, hash_k.k->p.offset, hash,
		     (bch2_bkey_val_to_text(&PBUF(buf), c, hash_k), buf)) == FSCK_ERR_IGNORE)
		return 0;

	ret = __bch2_trans_do(trans, NULL, NULL,
			      BTREE_INSERT_NOFAIL|BTREE_INSERT_LAZY_RW,
		hash_redo_key(trans, desc, hash_info, k_iter, hash_k));
	if (ret) {
		bch_err(c, "hash_redo_key err %i", ret);
		return ret;
	}
	return -EINTR;
fsck_err:
	return ret;
}

static int check_inode(struct btree_trans *trans,
		       struct btree_iter *iter,
		       struct bch_inode_unpacked *prev,
		       struct bch_inode_unpacked u)
{
	struct bch_fs *c = trans->c;
	bool do_update = false;
	int ret = 0;

	if (fsck_err_on(prev &&
			(prev->bi_hash_seed		!= u.bi_hash_seed ||
			 mode_to_type(prev->bi_mode) != mode_to_type(u.bi_mode)), c,
			"inodes in different snapshots don't match")) {
		BUG();
	}

	if (u.bi_flags & BCH_INODE_UNLINKED &&
	    (!c->sb.clean ||
	     fsck_err(c, "filesystem marked clean, but inode %llu unlinked",
		      u.bi_inum))) {
		/*
		 * XXX: check if this inode isn't deleted in newer snapshots, if
		 * so we can't delete it and should probably copy the inode
		 * from the newer snapshot instead
		 */
		bch_verbose(c, "deleting inode %llu", u.bi_inum);
		bch_err(c, "repair not implemented yet");
		return -EINVAL;
#if 0
		bch2_trans_unlock(trans);
		bch2_fs_lazy_rw(c);

		ret = bch2_inode_rm(c, u.bi_inum, false);
		if (ret)
			bch_err(c, "error in fsck: error %i while deleting inode", ret);
		return ret;
#endif
	}

	if (u.bi_flags & BCH_INODE_I_SIZE_DIRTY &&
	    (!c->sb.clean ||
	     fsck_err(c, "filesystem marked clean, but inode %llu has i_size dirty",
		      u.bi_inum))) {
		bch_verbose(c, "truncating inode %llu", u.bi_inum);

		bch2_trans_unlock(trans);
		bch2_fs_lazy_rw(c);

		/*
		 * XXX: need to truncate partial blocks too here - or ideally
		 * just switch units to bytes and that issue goes away
		 */
		ret = bch2_btree_delete_range_trans(trans, BTREE_ID_extents,
				POS(u.bi_inum, round_up(u.bi_size, block_bytes(c))),
				POS(u.bi_inum, U64_MAX),
				NULL);
		if (ret) {
			bch_err(c, "error in fsck: error %i truncating inode", ret);
			return ret;
		}

		/*
		 * We truncated without our normal sector accounting hook, just
		 * make sure we recalculate it:
		 */
		u.bi_flags |= BCH_INODE_I_SECTORS_DIRTY;

		u.bi_flags &= ~BCH_INODE_I_SIZE_DIRTY;
		do_update = true;
	}

	if (u.bi_flags & BCH_INODE_I_SECTORS_DIRTY &&
	    (!c->sb.clean ||
	     fsck_err(c, "filesystem marked clean, but inode %llu has i_sectors dirty",
		      u.bi_inum))) {
		s64 sectors;

		bch_verbose(c, "recounting sectors for inode %llu",
			    u.bi_inum);

		sectors = bch2_count_inode_sectors(trans, u.bi_inum);
		if (sectors < 0) {
			bch_err(c, "error in fsck: error %i recounting inode sectors",
				(int) sectors);
			return sectors;
		}

		u.bi_sectors = sectors;
		u.bi_flags &= ~BCH_INODE_I_SECTORS_DIRTY;
		do_update = true;
	}

	if (u.bi_flags & BCH_INODE_BACKPTR_UNTRUSTED) {
		u.bi_dir = 0;
		u.bi_dir_offset = 0;
		u.bi_flags &= ~BCH_INODE_BACKPTR_UNTRUSTED;
		do_update = true;
	}

	if (do_update) {
		ret = __bch2_trans_do(trans, NULL, NULL,
				      BTREE_INSERT_NOFAIL|
				      BTREE_INSERT_LAZY_RW,
				bch2_inode_write(trans, iter, &u));
		if (ret)
			bch_err(c, "error in fsck: error %i "
				"updating inode", ret);
	}
fsck_err:
	return ret;
}

noinline_for_stack
static int check_inodes(struct bch_fs *c, bool full)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_s_c_inode inode;
	struct bch_inode_unpacked prev, u;
	int ret;

	memset(&prev, 0, sizeof(prev));

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_inodes, POS_MIN,
			   BTREE_ITER_ALL_SNAPSHOTS, k, ret) {
		if (k.k->type != KEY_TYPE_inode)
			continue;

		inode = bkey_s_c_to_inode(k);

		if (!full &&
		    !(inode.v->bi_flags & (BCH_INODE_I_SIZE_DIRTY|
					   BCH_INODE_I_SECTORS_DIRTY|
					   BCH_INODE_UNLINKED)))
			continue;

		BUG_ON(bch2_inode_unpack(inode, &u));

		ret = check_inode(&trans, iter,
				  full && prev.bi_inum == u.bi_inum
				  ? &prev : NULL, u);
		if (ret)
			break;

		prev = u;
	}
	bch2_trans_iter_put(&trans, iter);

	BUG_ON(ret == -EINTR);

	return bch2_trans_exit(&trans) ?: ret;
}

noinline_for_stack
static int check_subvols(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_subvolumes, POS_MIN,
			   0, k, ret) {
	}
	bch2_trans_iter_put(&trans, iter);

	bch2_trans_exit(&trans);
	return ret;
}

/*
 * Checking for overlapping extents needs to be reimplemented
 */
#if 0
static int fix_overlapping_extent(struct btree_trans *trans,
				       struct bkey_s_c k, struct bpos cut_at)
{
	struct btree_iter *iter;
	struct bkey_i *u;
	int ret;

	u = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
	ret = PTR_ERR_OR_ZERO(u);
	if (ret)
		return ret;

	bkey_reassemble(u, k);
	bch2_cut_front(cut_at, u);


	/*
	 * We don't want to go through the extent_handle_overwrites path:
	 *
	 * XXX: this is going to screw up disk accounting, extent triggers
	 * assume things about extent overwrites - we should be running the
	 * triggers manually here
	 */
	iter = bch2_trans_get_iter(trans, BTREE_ID_extents, u->k.p,
				   BTREE_ITER_INTENT|BTREE_ITER_NOT_EXTENTS);

	BUG_ON(iter->flags & BTREE_ITER_IS_EXTENTS);
	bch2_trans_update(trans, iter, u, BTREE_TRIGGER_NORUN);
	bch2_trans_iter_put(trans, iter);

	return bch2_trans_commit(trans, NULL, NULL,
				 BTREE_INSERT_NOFAIL|
				 BTREE_INSERT_LAZY_RW);
}
#endif

static int inode_backpointer_exists(struct btree_trans *trans,
				    struct bch_inode_unpacked *inode,
				    u32 snapshot)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_dirents,
			SPOS(inode->bi_dir, inode->bi_dir_offset, snapshot), 0);
	k = bch2_btree_iter_peek_slot(iter);
	ret = bkey_err(k);
	if (ret)
		goto out;
	if (k.k->type != KEY_TYPE_dirent)
		goto out;

	ret = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum) == inode->bi_inum;
out:
	bch2_trans_iter_free(trans, iter);
	return ret;
}

static bool inode_backpointer_matches(struct bkey_s_c_dirent d,
				      struct bch_inode_unpacked *inode)
{
	return d.k->p.inode == inode->bi_dir &&
		d.k->p.offset == inode->bi_dir_offset;
}

static int check_i_sectors(struct btree_trans *trans, struct inode_walker *w)
{
	struct bch_fs *c = trans->c;
	struct inode_walker_entry *i;
	int ret = 0;

	for (i = w->d; i < w->d + w->nr; i++) {
		if (i->inode.bi_sectors == i->count)
			continue;

		if (fsck_err_on(!(i->inode.bi_flags & BCH_INODE_I_SECTORS_DIRTY), c,
			    "inode %llu:%u has incorrect i_sectors: got %llu, should be %llu",
			    w->cur_inum, i->snapshot,
			    i->inode.bi_sectors, i->count) == FSCK_ERR_IGNORE)
			continue;

		i->inode.bi_sectors = i->count;
		ret = write_inode(trans, &i->inode, i->snapshot);
		if (ret)
			break;
	}
fsck_err:
	return ret;
}

/*
 * Walk extents: verify that extents have a corresponding S_ISREG inode, and
 * that i_size an i_sectors are consistent
 */
noinline_for_stack
static int check_extents(struct bch_fs *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret = 0;

#if 0
	struct bkey_buf prev;
	bch2_bkey_buf_init(&prev);
	prev.k->k = KEY(0, 0, 0);
#endif
	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	bch_verbose(c, "checking extents");

	iter = bch2_trans_get_iter(&trans, BTREE_ID_extents,
				   POS(BCACHEFS_ROOT_INO, 0),
				   BTREE_ITER_INTENT);
retry:
	while ((k = bch2_btree_iter_peek(iter)).k &&
	       !(ret = bkey_err(k))) {
		struct inode_walker_entry *i;

		if (w.cur_inum != k.k->p.inode) {
			ret = check_i_sectors(&trans, &w);
			if (ret)
				break;
		}
#if 0
		if (bkey_cmp(prev.k->k.p, bkey_start_pos(k.k)) > 0) {
			char buf1[200];
			char buf2[200];

			bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(prev.k));
			bch2_bkey_val_to_text(&PBUF(buf2), c, k);

			if (fsck_err(c, "overlapping extents:\n%s\n%s", buf1, buf2))
				return fix_overlapping_extent(&trans, k, prev.k->k.p) ?: -EINTR;
		}
#endif
		ret = walk_inode(&trans, &w, k.k->p.inode);
		if (ret)
			break;

		if (fsck_err_on(!w.nr, c,
				"extent type %u for missing inode %llu",
				k.k->type, k.k->p.inode) ||
		    fsck_err_on(!S_ISREG(w.d[0].inode.bi_mode) &&
				!S_ISLNK(w.d[0].inode.bi_mode), c,
				"extent type %u for non regular file, inode %llu mode %o",
				k.k->type, k.k->p.inode, i->inode.bi_mode)) {
			bch2_fs_lazy_rw(c);
			ret = bch2_btree_delete_range_trans(&trans, BTREE_ID_extents,
						       POS(k.k->p.inode, 0),
						       POS(k.k->p.inode, U64_MAX),
						       NULL);
			continue;
		}

		while ((i = get_next_inode(c, &w, k.k->p.snapshot))) {
			if (fsck_err_on(!(i->inode.bi_flags & BCH_INODE_I_SIZE_DIRTY) &&
					k.k->type != KEY_TYPE_reservation &&
					k.k->p.offset > round_up(i->inode.bi_size, block_bytes(c)) >> 9, c,
					"extent type %u offset %llu past end of inode %llu, i_size %llu",
					k.k->type, k.k->p.offset, k.k->p.inode, i->inode.bi_size)) {
				bch2_fs_lazy_rw(c);
				ret = bch2_btree_delete_range_trans(&trans, BTREE_ID_extents,
						POS(k.k->p.inode, round_up(i->inode.bi_size, block_bytes(c))),
						POS(k.k->p.inode, U64_MAX),
						NULL);
				continue;
			}

			if (bkey_extent_is_allocation(k.k))
				i->count += k.k->size;
		}
#if 0
		bch2_bkey_buf_reassemble(&prev, c, k);
#endif
		bch2_btree_iter_advance(iter);
	}
fsck_err:
	if (ret == -EINTR)
		goto retry;
	bch2_trans_iter_put(&trans, iter);
#if 0
	bch2_bkey_buf_exit(&prev, c);
#endif
	inode_walker_exit(&w);
	return bch2_trans_exit(&trans) ?: ret;
}

static int check_subdir_count(struct btree_trans *trans, struct inode_walker *w)
{
	struct bch_fs *c = trans->c;
	struct inode_walker_entry *i;
	int ret = 0;

	for (i = w->d; i < w->d + w->nr; i++) {
		if (i->inode.bi_nlink == i->count)
			continue;

		if (fsck_err_on(i->inode.bi_nlink != i->count, c,
				"directory %llu:%u with wrong i_nlink: got %u, should be %llu",
				w->cur_inum, i->snapshot, i->inode.bi_nlink, i->count)) {
			i->inode.bi_nlink = i->count;
			ret = write_inode(trans, &i->inode, i->snapshot);
			if (ret)
				break;
		}
	}
fsck_err:
	return ret;
}

static int check_dirent_target(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c_dirent d,
			       struct bch_inode_unpacked *target,
			       u32 target_snapshot)
{
	struct bch_fs *c = trans->c;
	bool backpointer_exists = true;
	char buf[200];
	int ret = 0;

	if (!target->bi_dir &&
	    !target->bi_dir_offset) {
		target->bi_dir		= d.k->p.inode;
		target->bi_dir_offset	= d.k->p.offset;

		ret = write_inode(trans, target, target_snapshot);
		if (ret)
			goto err;
	}

	if (!inode_backpointer_matches(d, target)) {
		ret = inode_backpointer_exists(trans, target, d.k->p.snapshot);
		if (ret < 0)
			goto err;

		backpointer_exists = ret;
		ret = 0;

		if (fsck_err_on(S_ISDIR(target->bi_mode) &&
				backpointer_exists, c,
				"directory %llu with multiple links",
				target->bi_inum)) {
			ret = remove_dirent(trans, d.k->p);
			if (ret)
				goto err;
			return 0;
		}

		if (fsck_err_on(backpointer_exists &&
				!target->bi_nlink, c,
				"inode %llu has multiple links but i_nlink 0",
				target->bi_inum)) {
			target->bi_nlink++;
			target->bi_flags &= ~BCH_INODE_UNLINKED;

			ret = write_inode(trans, target, target_snapshot);
			if (ret)
				goto err;
		}

		if (fsck_err_on(!backpointer_exists, c,
				"inode %llu has wrong backpointer:\n"
				"got       %llu:%llu\n"
				"should be %llu:%llu",
				target->bi_inum,
				target->bi_dir,
				target->bi_dir_offset,
				d.k->p.inode,
				d.k->p.offset)) {
			target->bi_dir		= d.k->p.inode;
			target->bi_dir_offset	= d.k->p.offset;

			ret = write_inode(trans, target, target_snapshot);
			if (ret)
				goto err;
		}
	}

	if (fsck_err_on(vfs_d_type(d.v->d_type) != mode_to_type(target->bi_mode), c,
			"incorrect d_type: should be %u:\n%s",
			mode_to_type(target->bi_mode),
			(bch2_bkey_val_to_text(&PBUF(buf), c, d.s_c), buf))) {
		struct bkey_i_dirent *n;

		n = kmalloc(bkey_bytes(d.k), GFP_KERNEL);
		if (!n) {
			ret = -ENOMEM;
			goto err;
		}

		bkey_reassemble(&n->k_i, d.s_c);
		n->v.d_type = mode_to_type(target->bi_mode);

		ret = __bch2_trans_do(trans, NULL, NULL,
				      BTREE_INSERT_NOFAIL|
				      BTREE_INSERT_LAZY_RW,
			(bch2_trans_update(trans, iter, &n->k_i, 0), 0));
		kfree(n);
		if (ret)
			goto err;
	}
err:
fsck_err:
	return ret;
}

/*
 * Walk dirents: verify that they all have a corresponding S_ISDIR inode,
 * validate d_type
 */
noinline_for_stack
static int check_dirents(struct bch_fs *c)
{
	struct inode_walker dir = inode_walker_init();
	struct inode_walker target = inode_walker_init();
	struct bch_hash_info hash_info;
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	char buf[200];
	int ret = 0;

	bch_verbose(c, "checking dirents");

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	iter = bch2_trans_get_iter(&trans, BTREE_ID_dirents,
				   POS(BCACHEFS_ROOT_INO, 0), 0);
retry:
	while ((k = bch2_btree_iter_peek(iter)).k &&
	       !(ret = bkey_err(k))) {
		struct bkey_s_c_dirent d;
		u32 target_snapshot;
		u32 target_subvol;
		u64 target_inum;
		struct inode_walker_entry *i;

		if (dir.cur_inum != k.k->p.inode) {
			ret = check_subdir_count(&trans, &dir);
			if (ret)
				break;
		}

		ret = walk_inode(&trans, &dir, k.k->p.inode);
		if (ret)
			break;

		if (fsck_err_on(!dir.nr, c,
				"dirent in nonexisting directory:\n%s",
				(bch2_bkey_val_to_text(&PBUF(buf), c,
						       k), buf)) ||
		    fsck_err_on(!S_ISDIR(dir.d[0].inode.bi_mode), c,
				"dirent in non directory inode type %u:\n%s",
				mode_to_type(dir.d[0].inode.bi_mode),
				(bch2_bkey_val_to_text(&PBUF(buf), c,
						       k), buf))) {
			ret = lockrestart_do(&trans,
					bch2_btree_delete_at(&trans, iter, 0));
			if (ret)
				goto err;
			goto next;
		}

		if (!dir.nr)
			goto next;

		if (dir.first_this_inode)
			hash_info = bch2_hash_info_init(c, &dir.d[0].inode);

		ret = hash_check_key(&trans, bch2_dirent_hash_desc,
				     &hash_info, iter, k);
		if (ret > 0) {
			ret = 0;
			goto next;
		}
		if (ret)
			goto fsck_err;

		if (k.k->type != KEY_TYPE_dirent)
			goto next;

		d = bkey_s_c_to_dirent(k);

		while ((i = get_next_inode(c, &dir, k.k->p.snapshot)))
			i->count += d.v->d_type == DT_DIR;

		ret = lockrestart_do(&trans,
			__bch2_dirent_read_target(&trans, d,
						  &target_subvol,
						  &target_snapshot,
						  &target_inum));
		if (fsck_err_on(ret == -ENOENT, c,
				"dirent points to missing subvolume %llu",
				le64_to_cpu(d.v->d_inum))) {
			BUG();
		}

		if (ret && ret != -ENOENT)
			break;

		if (target_subvol) {
			struct bch_inode_unpacked subvol_root;

			ret = lookup_inode(&trans, target_inum,
					   &subvol_root, &target_snapshot);
			if (fsck_err_on(ret == -ENOENT, c,
					"subvolume %u points to missing subvolume root %llu",
					target_subvol,
					target_inum)) {
				BUG();
			}

			if (ret)
				return ret;

			if (fsck_err_on(subvol_root.bi_subvol != target_subvol, c,
					"subvol root %llu has wrong bi_subvol field: got %u, should be %u",
					target_inum,
					subvol_root.bi_subvol, target_subvol)) {

				subvol_root.bi_subvol = target_subvol;
				ret = write_inode(&trans, &subvol_root, target_snapshot);
				if (ret)
					goto err;
			}

			ret = check_dirent_target(&trans, iter, d, &subvol_root,
						  target_snapshot);
			if (ret)
				goto err;
		} else {
			bool have_target = false;

			target.cur_inum = 0;
			ret = walk_inode(&trans, &target, target_inum);
			if (ret)
				break;

			while ((i = get_next_inode(c, &target, target_inum))) {
				ret = check_dirent_target(&trans, iter, d,
							  &i->inode, i->snapshot);
				if (ret)
					goto err;

				have_target = true;
			}

			if (fsck_err_on(!have_target, c,
					"dirent points to missing inode:\n%s",
					(bch2_bkey_val_to_text(&PBUF(buf), c,
							       k), buf))) {
				ret = remove_dirent(&trans, d.k->p);
				if (ret)
					goto err;
			}
		}
next:
		bch2_btree_iter_advance(iter);
	}
err:
fsck_err:
	if (ret == -EINTR)
		goto retry;

	bch2_trans_iter_put(&trans, iter);
	return bch2_trans_exit(&trans) ?: ret;
}

/*
 * Walk xattrs: verify that they all have a corresponding inode
 */
noinline_for_stack
static int check_xattrs(struct bch_fs *c)
{
	struct inode_walker w = inode_walker_init();
	struct bch_hash_info hash_info;
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret = 0;

	bch_verbose(c, "checking xattrs");

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	iter = bch2_trans_get_iter(&trans, BTREE_ID_xattrs,
				   POS(BCACHEFS_ROOT_INO, 0), 0);
retry:
	while ((k = bch2_btree_iter_peek(iter)).k &&
	       !(ret = bkey_err(k))) {
		ret = walk_inode(&trans, &w, k.k->p.inode);
		if (ret)
			break;

		if (fsck_err_on(!w.nr, c,
				"xattr for missing inode %llu",
				k.k->p.inode)) {
			ret = bch2_btree_delete_at(&trans, iter, 0);
			if (ret)
				break;
			continue;
		}

		if (!w.nr)
			goto next;

		if (w.first_this_inode)
			hash_info = bch2_hash_info_init(c, &w.d[0].inode);

		ret = hash_check_key(&trans, bch2_xattr_hash_desc,
				     &hash_info, iter, k);
		if (ret)
			break;
next:
		bch2_btree_iter_advance(iter);
	}
fsck_err:
	if (ret == -EINTR)
		goto retry;

	bch2_trans_iter_put(&trans, iter);
	return bch2_trans_exit(&trans) ?: ret;
}

/* Get root directory, create if it doesn't exist: */
static int check_root(struct bch_fs *c, struct bch_inode_unpacked *root_inode)
{
	struct bkey_inode_buf packed;
	u32 snapshot;
	int ret;

	bch_verbose(c, "checking root directory");

	ret = bch2_trans_do(c, NULL, NULL, 0,
		lookup_inode(&trans, BCACHEFS_ROOT_INO, root_inode, &snapshot));
	if (ret && ret != -ENOENT)
		return ret;

	if (fsck_err_on(ret, c, "root directory missing"))
		goto create_root;

	if (fsck_err_on(!S_ISDIR(root_inode->bi_mode), c,
			"root inode not a directory"))
		goto create_root;

	return 0;
fsck_err:
	return ret;
create_root:
	bch2_inode_init(c, root_inode, 0, 0, S_IFDIR|0755,
			0, NULL);
	root_inode->bi_inum = BCACHEFS_ROOT_INO;

	bch2_inode_pack(c, &packed, root_inode);

	return bch2_btree_insert(c, BTREE_ID_inodes, &packed.inode.k_i,
				 NULL, NULL,
				 BTREE_INSERT_NOFAIL|
				 BTREE_INSERT_LAZY_RW);
}

struct pathbuf {
	size_t		nr;
	size_t		size;

	struct pathbuf_entry {
		u64	inum;
	}		*entries;
};

static int path_down(struct pathbuf *p, u64 inum)
{
	if (p->nr == p->size) {
		size_t new_size = max_t(size_t, 256UL, p->size * 2);
		void *n = krealloc(p->entries,
				   new_size * sizeof(p->entries[0]),
				   GFP_KERNEL);
		if (!n) {
			return -ENOMEM;
		}

		p->entries = n;
		p->size = new_size;
	};

	p->entries[p->nr++] = (struct pathbuf_entry) {
		.inum = inum,
	};
	return 0;
}

static int check_path(struct btree_trans *trans,
		      struct pathbuf *p,
		      struct bch_inode_unpacked *inode,
		      u32 snapshot)
{
	struct bch_fs *c = trans->c;
	size_t i;
	int ret = 0;

	p->nr = 0;

	while (inode->bi_inum != BCACHEFS_ROOT_INO) {
		ret = lockrestart_do(trans,
			inode_backpointer_exists(trans, inode, snapshot));
		if (ret < 0)
			break;

		if (!ret) {
			if (fsck_err(c,  "unreachable inode %llu, type %u nlink %u backptr %llu:%llu",
				     inode->bi_inum,
				     mode_to_type(inode->bi_mode),
				     inode->bi_nlink,
				     inode->bi_dir,
				     inode->bi_dir_offset))
				ret = reattach_inode(trans, inode, snapshot);
			break;
		}
		ret = 0;

		if (!S_ISDIR(inode->bi_mode))
			break;

		ret = path_down(p, inode->bi_inum);
		if (ret) {
			bch_err(c, "memory allocation failure");
			return ret;
		}

		for (i = 0; i < p->nr; i++) {
			if (inode->bi_dir != p->entries[i].inum)
				continue;

			/* XXX print path */
			if (!fsck_err(c, "directory structure loop"))
				return 0;

			ret = lockrestart_do(trans,
					remove_backpointer(trans, inode));
			if (ret) {
				bch_err(c, "error removing dirent: %i", ret);
				break;
			}

			ret = reattach_inode(trans, inode, snapshot);
			break;
		}

		ret = lookup_inode(trans, inode->bi_dir, inode, &snapshot);
		if (ret) {
			/* Should have been caught in dirents pass */
			bch_err(c, "error looking up parent directory: %i", ret);
			break;
		}
	}
fsck_err:
	if (ret)
		bch_err(c, "%s: err %i", __func__, ret);
	return ret;
}

/*
 * Check for unreachable inodes, as well as loops in the directory structure:
 * After check_dirents(), if an inode backpointer doesn't exist that means it's
 * unreachable:
 */
static int check_directory_structure(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bch_inode_unpacked u;
	struct pathbuf path = { 0, 0, NULL };
	int ret;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_inodes, POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_inode)
			continue;

		ret = bch2_inode_unpack(bkey_s_c_to_inode(k), &u);
		if (ret) {
			/* Should have been caught earlier in fsck: */
			bch_err(c, "error unpacking inode %llu: %i", k.k->p.offset, ret);
			break;
		}

		ret = check_path(&trans, &path, &u, iter->pos.snapshot);
		if (ret)
			break;
	}
	bch2_trans_iter_put(&trans, iter);

	BUG_ON(ret == -EINTR);

	kfree(path.entries);

	return bch2_trans_exit(&trans) ?: ret;
}

struct nlink_table {
	size_t		nr;
	size_t		size;

	struct nlink {
		u64	inum;
		u32	snapshot;
		u32	count;
	}		*d;
};

static int add_nlink(struct nlink_table *t, u64 inum, u32 snapshot)
{
	if (t->nr == t->size) {
		size_t new_size = max_t(size_t, 128UL, t->size * 2);
		void *d = kvmalloc(new_size * sizeof(t->d[0]), GFP_KERNEL);
		if (!d) {
			return -ENOMEM;
		}

		memcpy(d, t->d, t->size * sizeof(t->d[0]));
		kvfree(t->d);

		t->d = d;
		t->size = new_size;
	}


	t->d[t->nr++] = (struct nlink) {
		.inum		= inum,
		.snapshot	= snapshot,
	};

	return 0;
}

static int nlink_cmp(const void *_l, const void *_r)
{
	const struct nlink *l = _l;
	const struct nlink *r = _r;

	return cmp_int(l->inum, r->inum) ?: cmp_int(l->snapshot, r->snapshot);
}

static void inc_link(struct bch_fs *c, struct nlink_table *links,
		     u64 range_start, u64 range_end, u64 inum)
{
	struct nlink *link, key = {
		.inum = inum, .snapshot = U32_MAX,
	};

	if (inum < range_start || inum >= range_end)
		return;

	link = __inline_bsearch(&key, links->d, links->nr,
				sizeof(links->d[0]), nlink_cmp);
	if (link)
		link->count++;
}

noinline_for_stack
static int check_nlinks_find_hardlinks(struct bch_fs *c,
				       struct nlink_table *t,
				       u64 start, u64 *end)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_s_c_inode inode;
	struct bch_inode_unpacked u;
	int ret = 0;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_inodes,
			   POS(0, start), 0, k, ret) {
		if (k.k->type != KEY_TYPE_inode)
			continue;

		inode = bkey_s_c_to_inode(k);

		/*
		 * Backpointer and directory structure checks are sufficient for
		 * directories, since they can't have hardlinks:
		 */
		if (S_ISDIR(le16_to_cpu(inode.v->bi_mode)))
			continue;

		/* Should never fail, checked by bch2_inode_invalid: */
		BUG_ON(bch2_inode_unpack(inode, &u));

		if (!u.bi_nlink)
			continue;

		ret = add_nlink(t, k.k->p.offset, k.k->p.snapshot);
		if (ret) {
			*end = k.k->p.offset;
			ret = 0;
			break;
		}

	}
	bch2_trans_iter_put(&trans, iter);
	bch2_trans_exit(&trans);

	if (ret)
		bch_err(c, "error in fsck: btree error %i while walking inodes", ret);

	return ret;
}

noinline_for_stack
static int check_nlinks_walk_dirents(struct bch_fs *c, struct nlink_table *links,
				     u64 range_start, u64 range_end)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent d;
	int ret;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_dirents, POS_MIN, 0, k, ret) {
		switch (k.k->type) {
		case KEY_TYPE_dirent:
			d = bkey_s_c_to_dirent(k);

			if (d.v->d_type != DT_DIR)
				inc_link(c, links, range_start, range_end,
					 le64_to_cpu(d.v->d_inum));
			break;
		}

		bch2_trans_cond_resched(&trans);
	}
	bch2_trans_iter_put(&trans, iter);

	ret = bch2_trans_exit(&trans) ?: ret;
	if (ret)
		bch_err(c, "error in fsck: btree error %i while walking dirents", ret);

	return ret;
}

noinline_for_stack
static int check_nlinks_update_hardlinks(struct bch_fs *c,
			       struct nlink_table *links,
			       u64 range_start, u64 range_end)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_s_c_inode inode;
	struct bch_inode_unpacked u;
	struct nlink *link = links->d;
	int ret = 0;

	bch2_trans_init(&trans, c, BTREE_ITER_MAX, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_inodes,
			   POS(0, range_start), 0, k, ret) {
		if (k.k->p.offset >= range_end)
			break;

		if (k.k->type != KEY_TYPE_inode)
			continue;

		inode = bkey_s_c_to_inode(k);
		if (S_ISDIR(le16_to_cpu(inode.v->bi_mode)))
			continue;

		BUG_ON(bch2_inode_unpack(inode, &u));

		if (!u.bi_nlink)
			continue;

		while (link->inum < k.k->p.offset) {
			link++;
			BUG_ON(link >= links->d + links->nr);
		}

		if (fsck_err_on(bch2_inode_nlink_get(&u) != link->count, c,
				"inode %llu has wrong i_nlink (type %u i_nlink %u, should be %u)",
				u.bi_inum, mode_to_type(u.bi_mode),
				bch2_inode_nlink_get(&u), link->count)) {
			bch2_inode_nlink_set(&u, link->count);

			ret = __bch2_trans_do(&trans, NULL, NULL,
					      BTREE_INSERT_NOFAIL|
					      BTREE_INSERT_LAZY_RW,
					bch2_inode_write(&trans, iter, &u));
			if (ret)
				bch_err(c, "error in fsck: error %i updating inode", ret);
		}
	}
fsck_err:
	bch2_trans_iter_put(&trans, iter);
	bch2_trans_exit(&trans);

	if (ret)
		bch_err(c, "error in fsck: btree error %i while walking inodes", ret);

	return ret;
}

noinline_for_stack
static int check_nlinks(struct bch_fs *c)
{
	struct nlink_table links = { 0 };
	u64 this_iter_range_start, next_iter_range_start = 0;
	int ret = 0;

	bch_verbose(c, "checking inode nlinks");

	do {
		this_iter_range_start = next_iter_range_start;
		next_iter_range_start = U64_MAX;

		ret = check_nlinks_find_hardlinks(c, &links,
						  this_iter_range_start,
						  &next_iter_range_start);

		ret = check_nlinks_walk_dirents(c, &links,
					  this_iter_range_start,
					  next_iter_range_start);
		if (ret)
			break;

		ret = check_nlinks_update_hardlinks(c, &links,
					 this_iter_range_start,
					 next_iter_range_start);
		if (ret)
			break;

		links.nr = 0;
	} while (next_iter_range_start != U64_MAX);

	kvfree(links.d);

	return ret;
}

/*
 * Checks for inconsistencies that shouldn't happen, unless we have a bug.
 * Doesn't fix them yet, mainly because they haven't yet been observed:
 */
int bch2_fsck_full(struct bch_fs *c)
{
	struct bch_inode_unpacked root_inode;

	return  bch2_fs_snapshots_check(c) ?:
		check_inodes(c, true) ?:
		check_subvols(c) ?:
		check_extents(c) ?:
		check_dirents(c) ?:
		check_xattrs(c) ?:
		check_root(c, &root_inode) ?:
		check_directory_structure(c) ?:
		check_nlinks(c);
}

int bch2_fsck_walk_inodes_only(struct bch_fs *c)
{
	return check_inodes(c, false);
}
