// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "fs/check.h"

#include <linux/bsearch.h>

struct nlink_table {
	size_t		nr;
	size_t		size;

	struct nlink {
		u64	inum;
		u32	snapshot;
		u32	count;
	}		*d;
};

static int add_nlink(struct bch_fs *c, struct nlink_table *t,
		     u64 inum, u32 snapshot)
{
	if (t->nr == t->size) {
		size_t new_size = max_t(size_t, 128UL, t->size * 2);
		void *d = kvmalloc_array(new_size, sizeof(t->d[0]), GFP_KERNEL);

		if (!d) {
			bch_err(c, "fsck: error allocating memory for nlink_table, size %zu",
				new_size);
			return bch_err_throw(c, ENOMEM_fsck_add_nlink);
		}

		if (t->d)
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

	return cmp_int(l->inum, r->inum);
}

static void inc_link(struct bch_fs *c, struct snapshots_seen *s,
		     struct nlink_table *links,
		     u64 range_start, u64 range_end, u64 inum, u32 snapshot)
{
	struct nlink *link, key = {
		.inum = inum, .snapshot = U32_MAX,
	};

	if (inum < range_start || inum >= range_end)
		return;

	link = __inline_bsearch(&key, links->d, links->nr,
				sizeof(links->d[0]), nlink_cmp);
	if (!link)
		return;

	while (link > links->d && link[0].inum == link[-1].inum)
		--link;

	for (; link < links->d + links->nr && link->inum == inum; link++)
		if (bch2_ref_visible(c, s, snapshot, link->snapshot)) {
			link->count++;
			if (link->snapshot >= snapshot)
				break;
		}
}

noinline_for_stack
static int check_nlinks_find_hardlinks(struct bch_fs *c,
				       struct nlink_table *t,
				       u64 start, u64 *end)
{
	CLASS(btree_trans, trans)(c);
	int ret = for_each_btree_key(trans, iter, BTREE_ID_inodes,
				   POS(0, start),
				   BTREE_ITER_intent|
				   BTREE_ITER_prefetch|
				   BTREE_ITER_all_snapshots, k, ({
			if (!bkey_is_inode(k.k))
				continue;

			/* Should never fail, checked by bch2_inode_invalid: */
			struct bch_inode_unpacked u;
			_ret3 = bch2_inode_unpack(k, &u);
			if (_ret3)
				break;

			/*
			 * Backpointer and directory structure checks are sufficient for
			 * directories, since they can't have hardlinks:
			 */
			if (S_ISDIR(u.bi_mode))
				continue;

			/*
			 * Previous passes ensured that bi_nlink is nonzero if
			 * it had multiple hardlinks:
			 */
			if (!u.bi_nlink)
				continue;

			ret = add_nlink(c, t, k.k->p.offset, k.k->p.snapshot);
			if (ret) {
				*end = k.k->p.offset;
				ret = 0;
				break;
			}
			0;
		}));

	bch_err_fn(c, ret);
	return ret;
}

noinline_for_stack
static int check_nlinks_walk_dirents(struct bch_fs *c, struct nlink_table *links,
				     u64 range_start, u64 range_end)
{
	CLASS(btree_trans, trans)(c);
	CLASS(snapshots_seen, s)();

	int ret = for_each_btree_key(trans, iter, BTREE_ID_dirents, POS_MIN,
				   BTREE_ITER_intent|
				   BTREE_ITER_prefetch|
				   BTREE_ITER_all_snapshots, k, ({
		ret = bch2_snapshots_seen_update(c, &s, iter.btree_id, k.k->p);
		if (ret)
			break;

		if (k.k->type == KEY_TYPE_dirent) {
			struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);

			if (d.v->d_type != DT_DIR &&
			    d.v->d_type != DT_SUBVOL)
				inc_link(c, &s, links, range_start, range_end,
					 le64_to_cpu(d.v->d_inum), d.k->p.snapshot);
		}
		0;
	}));

	bch_err_fn(c, ret);
	return ret;
}

static int check_nlinks_update_inode(struct btree_trans *trans, struct btree_iter *iter,
				     struct bkey_s_c k,
				     struct nlink_table *links,
				     size_t *idx, u64 range_end)
{
	struct bch_inode_unpacked u;
	struct nlink *link = &links->d[*idx];
	int ret = 0;

	if (k.k->p.offset >= range_end)
		return 1;

	if (!bkey_is_inode(k.k))
		return 0;

	ret = bch2_inode_unpack(k, &u);
	if (ret)
		return ret;

	if (S_ISDIR(u.bi_mode))
		return 0;

	if (!u.bi_nlink)
		return 0;

	while ((cmp_int(link->inum, k.k->p.offset) ?:
		cmp_int(link->snapshot, k.k->p.snapshot)) < 0) {
		BUG_ON(*idx == links->nr);
		link = &links->d[++*idx];
	}

	if (fsck_err_on(bch2_inode_nlink_get(&u) != link->count,
			trans, inode_wrong_nlink,
			"inode %llu type %s has wrong i_nlink (%u, should be %u)",
			u.bi_inum, bch2_d_types[mode_to_type(u.bi_mode)],
			bch2_inode_nlink_get(&u), link->count)) {
		bch2_inode_nlink_set(&u, link->count);
		ret = __bch2_fsck_write_inode(trans, &u);
	}
fsck_err:
	return ret;
}

noinline_for_stack
static int check_nlinks_update_hardlinks(struct bch_fs *c,
			       struct nlink_table *links,
			       u64 range_start, u64 range_end)
{
	CLASS(btree_trans, trans)(c);
	size_t idx = 0;

	int ret = for_each_btree_key_commit(trans, iter, BTREE_ID_inodes,
				POS(0, range_start),
				BTREE_ITER_intent|BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			check_nlinks_update_inode(trans, &iter, k, links, &idx, range_end));
	if (ret < 0) {
		bch_err(c, "error in fsck walking inodes: %s", bch2_err_str(ret));
		return ret;
	}

	return 0;
}

int bch2_check_nlinks(struct bch_fs *c)
{
	struct nlink_table links = { 0 };
	u64 this_iter_range_start, next_iter_range_start = 0;
	int ret = 0;

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
