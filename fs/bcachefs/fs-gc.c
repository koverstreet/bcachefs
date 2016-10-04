
#include "bcache.h"
#include "btree_update.h"
#include "dirent.h"
#include "error.h"
#include "fs.h"
#include "fs-gc.h"
#include "inode.h"
#include "keylist.h"
#include "super.h"

#include <linux/generic-radix-tree.h>

#define unfixable_fsck_err(c, msg, ...)					\
do {									\
	bch_err(c, msg " (repair unimplemented)", ##__VA_ARGS__);	\
	ret = BCH_FSCK_REPAIR_UNIMPLEMENTED;				\
	goto fsck_err;							\
} while (0)

#define unfixable_fsck_err_on(cond, c, ...)				\
do {									\
	if (cond)							\
		unfixable_fsck_err(c, __VA_ARGS__);			\
} while (0)

#define fsck_err(c, msg, ...)						\
do {									\
	if (!(c)->opts.fix_errors) {					\
		bch_err(c, msg, ##__VA_ARGS__);				\
		ret = BCH_FSCK_ERRORS_NOT_FIXED;			\
		goto fsck_err;						\
	}								\
	set_bit(CACHE_SET_FSCK_FIXED_ERRORS, &(c)->flags);		\
	bch_err(c, msg ", fixing", ##__VA_ARGS__);			\
} while (0)

#define fsck_err_on(cond, c, ...)					\
({									\
	bool _ret = (cond);						\
									\
	if (_ret)							\
		fsck_err(c, __VA_ARGS__);				\
	_ret;								\
})

struct nlink {
	u32	count;
	u32	dir_count;
};

DECLARE_GENRADIX_TYPE(nlinks, struct nlink);

static void inc_link(struct cache_set *c, struct nlinks *links,
		     u64 range_start, u64 *range_end,
		     u64 inum, bool dir)
{
	struct nlink *link;

	if (inum < range_start || inum >= *range_end)
		return;

	link = genradix_ptr_alloc(links, inum - range_start, GFP_KERNEL);
	if (!link) {
		bch_verbose(c, "allocation failed during fs gc - will need another pass");
		*range_end = inum;
		return;
	}

	if (dir)
		link->dir_count++;
	else
		link->count++;
}

/*
 * XXX: should do a DFS (via filesystem heirarchy), and make sure all dirents
 * are reachable
 */

noinline_for_stack
static int bch_gc_walk_dirents(struct cache_set *c, struct nlinks *links,
			       u64 range_start, u64 *range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent d;
	u64 d_inum;
	int ret;

	inc_link(c, links, range_start, range_end, BCACHE_ROOT_INO, false);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS_MIN, k) {
		switch (k.k->type) {
		case BCH_DIRENT:
			d = bkey_s_c_to_dirent(k);
			d_inum = le64_to_cpu(d.v->d_inum);

			if (d.v->d_type == DT_DIR)
				inc_link(c, links, range_start, range_end,
					 d.k->p.inode, true);

			inc_link(c, links, range_start, range_end,
				 d_inum, false);

			break;
		}

		bch_btree_iter_cond_resched(&iter);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		bch_err(c, "error in fs gc: btree error %i while walking dirents", ret);

	return ret;
}

s64 bch_count_inode_sectors(struct cache_set *c, u64 inum)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 sectors = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS(inum, 0), k) {
		if (k.k->p.inode != inum)
			break;

		if (bkey_extent_is_allocation(k.k))
			sectors += k.k->size;
	}

	return bch_btree_iter_unlock(&iter) ?: sectors;
}

static int bch_gc_do_inode(struct cache_set *c, struct btree_iter *iter,
			   struct bkey_s_c_inode inode, struct nlink link)
{
	u16 i_mode  = le16_to_cpu(inode.v->i_mode);
	u32 i_flags = le32_to_cpu(inode.v->i_flags);
	u32 i_nlink = le32_to_cpu(inode.v->i_nlink);
	u64 i_size  = le64_to_cpu(inode.v->i_size);
	s64 i_sectors = 0;
	int ret = 0;
	u32 real_i_nlink;

	fsck_err_on(i_nlink < link.count, c,
		    "inode %llu i_link too small (%u < %u, type %i)",
		    inode.k->p.inode, i_nlink,
		    link.count, mode_to_type(i_mode));

	if (S_ISDIR(i_mode)) {
		unfixable_fsck_err_on(link.count > 1, c,
			"directory %llu with multiple hardlinks: %u",
			inode.k->p.inode, link.count);

		real_i_nlink = link.count * 2 + link.dir_count;
	} else {
		unfixable_fsck_err_on(link.dir_count, c,
			"found dirents for non directory %llu",
			inode.k->p.inode);

		real_i_nlink = link.count + link.dir_count;
	}

	if (!link.count) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but found orphaned inode %llu",
			    inode.k->p.inode);

		unfixable_fsck_err_on(S_ISDIR(i_mode) &&
			bch_empty_dir(c, inode.k->p.inode), c,
			"non empty directory with link count 0, "
			"inode nlink %u, dir links found %u",
			i_nlink, link.dir_count);

		bch_verbose(c, "deleting inode %llu", inode.k->p.inode);

		ret = bch_inode_rm(c, inode.k->p.inode);
		if (ret)
			bch_err(c, "error in fs gc: error %i "
				"while deleting inode", ret);
		return ret;
	}

	if (i_flags & BCH_INODE_I_SIZE_DIRTY) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has i_size dirty",
			    inode.k->p.inode);

		bch_verbose(c, "truncating inode %llu", inode.k->p.inode);

		/*
		 * XXX: need to truncate partial blocks too here - or ideally
		 * just switch units to bytes and that issue goes away
		 */

		ret = bch_inode_truncate(c, inode.k->p.inode,
				round_up(i_size, PAGE_SIZE) >> 9,
				NULL, NULL);
		if (ret) {
			bch_err(c, "error in fs gc: error %i "
				"truncating inode", ret);
			return ret;
		}

		/*
		 * We truncated without our normal sector accounting hook, just
		 * make sure we recalculate it:
		 */
		i_flags |= BCH_INODE_I_SECTORS_DIRTY;
	}

	if (i_flags & BCH_INODE_I_SECTORS_DIRTY) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has i_sectors dirty",
			    inode.k->p.inode);

		bch_verbose(c, "recounting sectors for inode %llu",
			    inode.k->p.inode);

		i_sectors = bch_count_inode_sectors(c, inode.k->p.inode);
		if (i_sectors < 0) {
			bch_err(c, "error in fs gc: error %i "
				"recounting inode sectors",
				(int) i_sectors);
			return i_sectors;
		}
	}

	if (i_nlink != real_i_nlink) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has wrong i_nlink "
			    "(type %u i_nlink %u, should be %u)",
			    inode.k->p.inode, mode_to_type(i_mode),
			    i_nlink, real_i_nlink);

		bch_verbose(c, "setting inode %llu nlinks from %u to %u",
			    inode.k->p.inode, i_nlink, real_i_nlink);
	}

	if (i_nlink != real_i_nlink||
	    i_flags & BCH_INODE_I_SECTORS_DIRTY ||
	    i_flags & BCH_INODE_I_SIZE_DIRTY) {
		struct bkey_i_inode update;

		bkey_reassemble(&update.k_i, inode.s_c);
		update.v.i_nlink = cpu_to_le32(real_i_nlink);
		update.v.i_flags = cpu_to_le32(i_flags &
				~(BCH_INODE_I_SIZE_DIRTY|
				  BCH_INODE_I_SECTORS_DIRTY));

		if (i_flags & BCH_INODE_I_SECTORS_DIRTY)
			update.v.i_sectors = cpu_to_le64(i_sectors);

		ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(iter, &update.k_i));
		if (ret && ret != -EINTR)
			bch_err(c, "error in fs gc: error %i "
				"updating inode", ret);
	}
fsck_err:
	return ret;
}

noinline_for_stack
static int bch_gc_walk_inodes(struct cache_set *c, struct nlinks *links,
			      u64 range_start, u64 range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct nlink *link, zero_links = { 0, 0 };
	struct genradix_iter nlinks_iter;
	int ret = 0, ret2 = 0;
	u64 nlinks_pos;

	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(range_start, 0));
	genradix_iter_init(&nlinks_iter);

	while (1) {
		k = bch_btree_iter_peek(&iter);
peek_nlinks:	link = genradix_iter_peek(&nlinks_iter, links);

		if (!link && (!k.k || iter.pos.inode >= range_end))
			break;

		nlinks_pos = range_start + nlinks_iter.pos;
		if (iter.pos.inode > nlinks_pos) {
			unfixable_fsck_err_on(link && link->count, c,
				"missing inode %llu (nlink %u)",
				nlinks_pos, link->count);
			genradix_iter_advance(&nlinks_iter, links);
			goto peek_nlinks;
		}

		if (iter.pos.inode < nlinks_pos || !link)
			link = &zero_links;

		if (k.k && k.k->type == BCH_INODE_FS) {
			/*
			 * Avoid potential deadlocks with iter for
			 * truncate/rm/etc.:
			 */
			bch_btree_iter_unlock(&iter);

			ret = bch_gc_do_inode(c, &iter,
					      bkey_s_c_to_inode(k),
					      *link);
			if (ret == -EINTR)
				continue;
			if (ret)
				break;

			if (link->count)
				atomic_long_inc(&c->nr_inodes);
		} else {
			unfixable_fsck_err_on(link->count, c,
				"missing inode %llu (nlink %u)",
				nlinks_pos, link->count);
		}

		if (nlinks_pos == iter.pos.inode)
			genradix_iter_advance(&nlinks_iter, links);

		bch_btree_iter_advance_pos(&iter);
		bch_btree_iter_cond_resched(&iter);
	}
fsck_err:
	ret2 = bch_btree_iter_unlock(&iter);
	if (ret2)
		bch_err(c, "error in fs gc: btree error %i while walking inodes", ret2);

	return ret ?: ret2;
}

int bch_gc_inode_nlinks(struct cache_set *c)
{
	struct nlinks links;
	u64 this_iter_range_start, next_iter_range_start = 0;
	int ret = 0;

	genradix_init(&links);

	do {
		this_iter_range_start = next_iter_range_start;
		next_iter_range_start = U64_MAX;

		ret = bch_gc_walk_dirents(c, &links,
					  this_iter_range_start,
					  &next_iter_range_start);
		if (ret)
			break;

		ret = bch_gc_walk_inodes(c, &links,
					 this_iter_range_start,
					 next_iter_range_start);
		if (ret)
			break;

		genradix_free(&links);
	} while (next_iter_range_start != U64_MAX);

	genradix_free(&links);

	return ret;
}

static void next_inode(struct cache_set *c, u64 inum, u64 *cur_inum,
		       struct bkey_i_inode *inode,
		       bool *first_this_inode, bool *have_inode,
		       u64 *i_size, u16 *i_mode)
{
	*first_this_inode = inum != *cur_inum;
	*cur_inum = inum;

	if (*first_this_inode) {
		*have_inode = !bch_inode_find_by_inum(c, inum, inode);

		if (*have_inode) {
			*i_mode = le16_to_cpu(inode->v.i_mode);
			*i_size = le64_to_cpu(inode->v.i_size);
		}
	}
}

/*
 * Checks for inconsistencies that shouldn't happen, unless we have a bug.
 * Doesn't fix them yet, mainly because they haven't yet been observed:
 */
int bch_fsck(struct cache_set *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i_inode inode;
	bool first_this_inode, have_inode;
	u64 cur_inum, i_sectors;
	u64 i_size = 0;
	u16 i_mode = 0;
	int ret = 0;

	cur_inum = -1;
	have_inode = false;
	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		if (k.k->type == KEY_TYPE_DISCARD)
			continue;

		next_inode(c, k.k->p.inode, &cur_inum, &inode,
			   &first_this_inode, &have_inode,
			   &i_size, &i_mode);

		unfixable_fsck_err_on(!have_inode, c,
			"extent type %u for missing inode %llu",
			k.k->type, k.k->p.inode);

		unfixable_fsck_err_on(first_this_inode && have_inode &&
			le64_to_cpu(inode.v.i_sectors) !=
			(i_sectors = bch_count_inode_sectors(c, cur_inum)),
			c, "i_sectors wrong: got %llu, should be %llu",
			le64_to_cpu(inode.v.i_sectors), i_sectors);

		unfixable_fsck_err_on(have_inode &&
			!S_ISREG(i_mode) && !S_ISLNK(i_mode), c,
			"extent type %u for non regular file, inode %llu mode %o",
			k.k->type, k.k->p.inode, i_mode);

		unfixable_fsck_err_on(k.k->type != BCH_RESERVATION &&
			k.k->p.offset > round_up(i_size, PAGE_SIZE) >> 9, c,
			"extent type %u offset %llu past end of inode %llu, i_size %llu",
			k.k->type, k.k->p.offset, k.k->p.inode, i_size);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	cur_inum = -1;
	have_inode = false;
	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		struct bkey_s_c_dirent d;
		struct bkey_i_inode target;
		bool have_target;
		u64 d_inum;

		next_inode(c, k.k->p.inode, &cur_inum, &inode,
			   &first_this_inode, &have_inode,
			   &i_size, &i_mode);

		unfixable_fsck_err_on(!have_inode, c,
			"dirent in nonexisting directory %llu",
			k.k->p.inode);

		unfixable_fsck_err_on(!S_ISDIR(i_mode), c,
			"dirent in non directory inode %llu, type %u",
			k.k->p.inode, mode_to_type(i_mode));

		if (k.k->type != BCH_DIRENT)
			continue;

		d = bkey_s_c_to_dirent(k);
		d_inum = le64_to_cpu(d.v->d_inum);

		unfixable_fsck_err_on(d_inum == d.k->p.inode, c,
			"dirent points to own directory");

		have_target = !bch_inode_find_by_inum(c, d_inum, &target);

		unfixable_fsck_err_on(!have_target, c,
			"dirent points to missing inode %llu, type %u filename %s",
			d_inum, d.v->d_type, d.v->d_name);

		unfixable_fsck_err_on(have_target &&
			d.v->d_type !=
			mode_to_type(le16_to_cpu(target.v.i_mode)), c,
			"incorrect d_type: got %u should be %u, filename %s",
			d.v->d_type,
			mode_to_type(le16_to_cpu(target.v.i_mode)),
			d.v->d_name);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	cur_inum = -1;
	have_inode = false;
	for_each_btree_key(&iter, c, BTREE_ID_XATTRS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		next_inode(c, k.k->p.inode, &cur_inum, &inode,
			   &first_this_inode, &have_inode,
			   &i_size, &i_mode);

		unfixable_fsck_err_on(!have_inode, c,
			"xattr for missing inode %llu",
			k.k->p.inode);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	return 0;
fsck_err:
	bch_btree_iter_unlock(&iter);
	return ret;
}
