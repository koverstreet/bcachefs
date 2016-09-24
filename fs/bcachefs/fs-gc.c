
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

struct nlink {
	u32	count;
	u32	dir_count;
};

DECLARE_GENRADIX_TYPE(nlinks, struct nlink);

static void inc_link(struct cache_set *c, struct nlinks *links,
		     u64 range_start, u64 *range_end,
		     u64 inum, unsigned count, bool dir)
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
		link->dir_count += count;
	else
		link->count += count;
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

	inc_link(c, links, range_start, range_end, BCACHE_ROOT_INO, 2, false);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS_MIN, k) {
		switch (k.k->type) {
		case BCH_DIRENT:
			d = bkey_s_c_to_dirent(k);
			d_inum = le64_to_cpu(d.v->d_inum);

			if (d.v->d_type == DT_DIR) {
				inc_link(c, links, range_start, range_end,
					 d_inum, 2, false);
				inc_link(c, links, range_start, range_end,
					 d.k->p.inode, 1, true);
			} else {
				inc_link(c, links, range_start, range_end,
					 d_inum, 1, false);
			}

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

	cache_set_inconsistent_on(i_nlink < link.count, c,
			 "i_link too small (%u < %u, type %i)",
			 i_nlink, link.count + link.dir_count,
			 mode_to_type(i_mode));

	if (!link.count) {
		cache_set_inconsistent_on(CACHE_SET_CLEAN(&c->disk_sb), c,
				"filesystem marked clean, "
				"but found orphaned inode %llu",
				inode.k->p.inode);

		cache_set_inconsistent_on(S_ISDIR(i_mode) &&
			bch_empty_dir(c, inode.k->p.inode), c,
			"non empty directory with link count 0, "
			"inode nlink %u, dir links found %u",
			i_nlink, link.dir_count);

		bch_verbose(c, "deleting inum %llu", inode.k->p.inode);

		ret = bch_inode_rm(c, inode.k->p.inode);
		if (ret)
			bch_err(c, "error in fs gc: error %i while deleting inode", ret);
		return ret;
	}

	if (i_flags & BCH_INODE_I_SIZE_DIRTY) {
		cache_set_inconsistent_on(CACHE_SET_CLEAN(&c->disk_sb), c,
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
		cache_set_inconsistent_on(CACHE_SET_CLEAN(&c->disk_sb), c,
				"filesystem marked clean, "
				"but inode %llu has i_sectors dirty",
				inode.k->p.inode);

		bch_verbose(c, "recounting sectors for inode %llu", inode.k->p.inode);

		i_sectors = bch_count_inode_sectors(c, inode.k->p.inode);
		if (i_sectors < 0) {
			bch_err(c, "error in fs gc: error %i "
				"recounting inode sectors",
				(int) i_sectors);
			return i_sectors;
		}
	}

	if (i_nlink != link.count + link.dir_count) {
		cache_set_inconsistent_on(CACHE_SET_CLEAN(&c->disk_sb), c,
				"filesystem marked clean, "
				"but inode %llu has wrong i_nlink "
				"(type %u i_nlink %u, should be %u)",
				inode.k->p.inode,
				mode_to_type(i_mode), i_nlink,
				link.count + link.dir_count);

		bch_verbose(c, "setting inum %llu nlinks from %u to %u",
			    inode.k->p.inode, i_nlink,
			    link.count + link.dir_count);
	}

	if (i_nlink != link.count + link.dir_count ||
	    i_flags & BCH_INODE_I_SECTORS_DIRTY ||
	    i_flags & BCH_INODE_I_SIZE_DIRTY) {
		struct bkey_i_inode update;

		bkey_reassemble(&update.k_i, inode.s_c);
		update.v.i_nlink = cpu_to_le32(link.count + link.dir_count);
		update.v.i_flags = cpu_to_le32(i_flags &
				~(BCH_INODE_I_SIZE_DIRTY|BCH_INODE_I_SECTORS_DIRTY));

		if (i_flags & BCH_INODE_I_SECTORS_DIRTY)
			update.v.i_sectors = cpu_to_le64(i_sectors);

		ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(iter, &update.k_i));
		if (ret && ret != -EINTR)
			bch_err(c, "error in fs gc: error %i "
				"updating inode", ret);
	}

	return ret;
}

noinline_for_stack
static int bch_gc_walk_inodes(struct cache_set *c, struct nlinks *links,
			      u64 range_start, u64 range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct nlink *link, zero_links = { 0, 0 };
	int ret = 0, ret2 = 0;
	u64 i = 0;

	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(range_start, 0));

	while ((k = bch_btree_iter_peek(&iter)).k) {
		if (k.k->p.inode >= range_end)
			break;

		link = genradix_ptr(links, i) ?: &zero_links;

		while (i < k.k->p.inode - range_start) {
			cache_set_inconsistent_on(link->count, c,
					 "missing inode %llu",
					 range_start + i);
			i++;
			link = genradix_ptr(links, i) ?: &zero_links;
		}

		switch (k.k->type) {
		case BCH_INODE_FS:
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
				goto out;

			break;
		default:
			cache_set_inconsistent_on(link->count, c,
					 "missing inode %llu",
					 range_start + i);
			break;
		}

		if (link->count)
			atomic_long_inc(&c->nr_inodes);

		bch_btree_iter_advance_pos(&iter);
		i++;
		bch_btree_iter_cond_resched(&iter);
	}
out:
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

static inline bool next_inode(struct cache_set *c, struct bkey_s_c k,
			      u64 *cur_inum,
			      struct bkey_i_inode *inode,
			      struct bch_inode **bi,
			      u64 *i_size, u16 *i_mode)
{
	if (k.k->p.inode == *cur_inum)
		return false;

	if (!bch_inode_find_by_inum(c, k.k->p.inode, inode)) {
		*i_mode = le16_to_cpu(inode->v.i_mode);
		*i_size = le64_to_cpu(inode->v.i_size);
		*bi = &inode->v;
	} else {
		*bi = NULL;
	}

	*cur_inum = k.k->p.inode;
	return true;
}

#define fsck_err(c, fmt, ...)					\
do {								\
	bch_err(c, fmt,  ##__VA_ARGS__);			\
} while (0)

/*
 * Checks for inconsistencies that shouldn't happen, unless we have a bug.
 * Doesn't fix them yet, mainly because they haven't yet been observed:
 */
void bch_fsck(struct cache_set *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i_inode inode;
	struct bch_inode *bi = NULL;
	u64 i_size = 0;
	u16 i_mode = 0;
	u64 cur_inum;
	char buf[100];

	cur_inum = -1;
	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		if (k.k->type == KEY_TYPE_DISCARD)
			continue;

		if (next_inode(c, k, &cur_inum, &inode, &bi,
			       &i_size, &i_mode) &&
		    bi &&
		    !(le32_to_cpu(bi->i_flags) & BCH_INODE_I_SECTORS_DIRTY)) {
			u64 i_sectors = bch_count_inode_sectors(c, cur_inum);

			if (i_sectors != le64_to_cpu(bi->i_sectors))
				fsck_err(c,
					 "i_sectors wrong: got %llu, should be %llu",
					 le64_to_cpu(bi->i_sectors), i_sectors);
		}

		if (!S_ISREG(i_mode) &&
		    !S_ISLNK(i_mode))
			fsck_err(c,
				 "extent type %u for non regular file, inode %llu mode %o",
				 k.k->type, k.k->p.inode, i_mode);

		if (k.k->type != BCH_RESERVATION &&
		    k.k->p.offset > round_up(i_size, PAGE_SIZE) >> 9) {
			bch_bkey_val_to_text(c, BTREE_ID_EXTENTS, buf,
					     sizeof(buf), k);
			fsck_err(c,
				"extent past end of inode %llu: i_size %llu extent\n%s",
				k.k->p.inode, i_size, buf);
		}
	}
	bch_btree_iter_unlock(&iter);

	cur_inum = -1;
	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		next_inode(c, k, &cur_inum, &inode, &bi, &i_size, &i_mode);

		if (!bi)
			fsck_err(c, "dirent for missing inode %llu", k.k->p.inode);

		if (!S_ISDIR(i_mode))
			fsck_err(c,
				 "dirent for non directory, inode %llu mode %o",
				 k.k->p.inode, i_mode);
	}
	bch_btree_iter_unlock(&iter);

	cur_inum = -1;
	for_each_btree_key(&iter, c, BTREE_ID_XATTRS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		next_inode(c, k, &cur_inum, &inode, &bi, &i_size, &i_mode);

		if (!bi)
			fsck_err(c, "xattr for missing inode %llu",
				 k.k->p.inode);
	}
	bch_btree_iter_unlock(&iter);
}
