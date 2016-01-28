
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

static void inc_link(struct nlinks *links,
		     u64 range_start, u64 *range_end,
		     u64 inum, unsigned count, bool dir)
{
	struct nlink *link;

	if (inum < range_start || inum >= *range_end)
		return;

	link = genradix_ptr_alloc(links, inum - range_start, GFP_KERNEL);
	if (!link) {
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

	inc_link(links, range_start, range_end, BCACHE_ROOT_INO, 2, false);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS_MIN, k) {
		switch (k.k->type) {
		case BCH_DIRENT:
			d = bkey_s_c_to_dirent(k);
			d_inum = le64_to_cpu(d.v->d_inum);

			if (d.v->d_type == DT_DIR) {
				inc_link(links, range_start, range_end,
					 d_inum, 2, false);
				inc_link(links, range_start, range_end,
					 d.k->p.inode, 1, true);
			} else {
				inc_link(links, range_start, range_end,
					 d_inum, 1, false);
			}

			break;
		}

		bch_btree_iter_cond_resched(&iter);
	}
	return bch_btree_iter_unlock(&iter);
}

static int bch_gc_do_inode(struct cache_set *c, struct btree_iter *iter,
			   struct bkey_s_c_inode inode, struct nlink link)
{
	struct bkey_i_inode update;
	int ret;
	u16 i_mode  = le16_to_cpu(inode.v->i_mode);
	u32 i_flags = le32_to_cpu(inode.v->i_flags);
	u32 i_nlink = le32_to_cpu(inode.v->i_nlink);
	u64 i_size  = le64_to_cpu(inode.v->i_size);

	cache_set_inconsistent_on(i_nlink < link.count, c,
			 "i_link too small (%u < %u, type %i)",
			 i_nlink, link.count + link.dir_count,
			 mode_to_type(i_mode));

	if (!link.count) {
		cache_set_inconsistent_on(S_ISDIR(i_mode) &&
			bch_empty_dir(c, inode.k->p.inode), c,
			"non empty directory with link count 0,inode nlink %u, dir links found %u",
			i_nlink, link.dir_count);

		if (c->opts.verbose_recovery)
			pr_info("deleting inum %llu", inode.k->p.inode);

		bch_btree_iter_unlock(iter);
		return bch_inode_rm(c, inode.k->p.inode);
	}

	if (i_flags & BCH_INODE_I_SIZE_DIRTY) {
		if (c->opts.verbose_recovery)
			pr_info("truncating inode %llu", inode.k->p.inode);

		/*
		 * XXX: need to truncate partial blocks too here - or ideally
		 * just switch units to bytes and that issue goes away
		 */

		ret = bch_inode_truncate(c, inode.k->p.inode,
				round_up(i_size, PAGE_SIZE) >> 9,
				NULL, NULL);
		if (ret)
			return ret;
	}

	if (i_nlink != link.count + link.dir_count ||
	    i_flags & BCH_INODE_I_SIZE_DIRTY) {
		if (c->opts.verbose_recovery &&
		    i_nlink != link.count + link.dir_count)
			pr_info("setting inum %llu nlinks from %u to %u",
				inode.k->p.inode, i_nlink,
				link.count + link.dir_count);

		bkey_reassemble(&update.k_i, inode.s_c);
		update.v.i_nlink = cpu_to_le32(link.count + link.dir_count);
		update.v.i_flags = cpu_to_le32(i_flags & ~BCH_INODE_I_SIZE_DIRTY);

		return bch_btree_insert_at(iter,
					   &keylist_single(&update.k_i),
					   NULL, NULL,
					   BTREE_INSERT_ATOMIC|
					   BTREE_INSERT_NOFAIL);
	}

	return 0;
}

noinline_for_stack
static int bch_gc_walk_inodes(struct cache_set *c, struct nlinks *links,
			      u64 range_start, u64 range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct nlink *link, zero_links = { 0, 0 };
	int ret = 0;
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
	return bch_btree_iter_unlock(&iter) ?: ret;
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
