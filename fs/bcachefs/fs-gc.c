
#include "bcache.h"
#include "btree.h"
#include "dirent.h"
#include "fs.h"
#include "inode.h"
#include "keylist.h"
#include "super.h"

#define INODES_PER_ITER		(1 << 24)

struct nlink {
	u32	count;
	u32	dir_count;
};

static void inc_link(u64 pos, struct nlink *links, bool *need_loop,
		     u64 inum, unsigned count, bool dir)
{
	if (inum >= pos + INODES_PER_ITER) {
		*need_loop = true;
	} else if (inum >= pos) {
		if (dir)
			links[inum - pos].dir_count += count;
		else
			links[inum - pos].count += count;
	}
}

/*
 * XXX: should do a DFS (via filesystem heirarchy), and make sure all dirents
 * are reachable
 */

noinline_for_stack
static int bch_gc_walk_dirents(struct cache_set *c, u64 pos,
			       struct nlink *links, bool *need_loop)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent d;

	need_loop = false;
	memset(links, 0, INODES_PER_ITER * sizeof(*links));

	inc_link(pos, links, need_loop, BCACHE_ROOT_INO, 2, false);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS_MIN, k) {
		switch (k.k->type) {
		case BCH_DIRENT:
			d = bkey_s_c_to_dirent(k);

			if (d.v->d_type == DT_DIR) {
				inc_link(pos, links, need_loop,
					 d.v->d_inum, 2, false);
				inc_link(pos, links, need_loop,
					 d.k->p.inode, 1, true);
			} else {
				inc_link(pos, links, need_loop,
					 d.v->d_inum, 1, false);
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

	cache_set_err_on(inode.v->i_nlink < link.count, c,
			 "i_link too small (%u < %u, type %i)",
			 inode.v->i_nlink, link.count + link.dir_count,
			 mode_to_type(inode.v->i_mode));

	if (!link.count) {
		cache_set_err_on(S_ISDIR(inode.v->i_mode) &&
			bch_empty_dir(c, inode.k->p.inode), c,
			"non empty directory with link count 0,inode nlink %u, dir links found %u",
			inode.v->i_nlink, link.dir_count);
		pr_info("deleting inum %llu", inode.k->p.inode);

		bch_btree_iter_unlock(iter);
		return bch_inode_rm(c, inode.k->p.inode);
	}

	if (inode.v->i_flags & BCH_INODE_I_SIZE_DIRTY) {
		pr_info("truncating inode %llu", inode.k->p.inode);

		/*
		 * XXX: need to truncate partial blocks too here - or ideally
		 * just switch units to bytes and that issue goes away
		 */

		ret = bch_inode_truncate(c, inode.k->p.inode,
				round_up(inode.v->i_size, PAGE_SIZE) >> 9);
		if (ret)
			return ret;
	}

	if (inode.v->i_nlink != link.count + link.dir_count ||
	    inode.v->i_flags & BCH_INODE_I_SIZE_DIRTY) {
		if (inode.v->i_nlink != link.count + link.dir_count)
			pr_info("setting inum %llu nlinks from %u to %u",
				inode.k->p.inode, inode.v->i_nlink,
				link.count + link.dir_count);

		bkey_reassemble(&update.k_i, inode.s_c);
		update.v.i_nlink = link.count + link.dir_count;
		update.v.i_flags &= ~BCH_INODE_I_SIZE_DIRTY;

		return bch_btree_insert_at(iter,
					   &keylist_single(&update.k_i),
					   NULL, NULL,
					   BTREE_INSERT_ATOMIC);
	}

	return 0;
}

noinline_for_stack
static int bch_gc_walk_inodes(struct cache_set *c, u64 pos, struct nlink *links)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;
	u64 i = 0;

	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(pos, 0));

	while ((k = bch_btree_iter_peek(&iter)).k) {
		if (k.k->p.inode - pos >= INODES_PER_ITER)
			break;

		while (i < k.k->p.inode - pos) {
			cache_set_err_on(links[i].count, c,
					 "missing inode %llu",
					 pos + i);
			i++;
		}

		switch (k.k->type) {
		case BCH_INODE_FS:
			ret = bch_gc_do_inode(c, &iter,
					      bkey_s_c_to_inode(k),
					      links[i]);
			if (ret == -EAGAIN || ret == -EINTR)
				continue;
			if (ret)
				goto out;

			break;
		default:
			cache_set_err_on(links[i].count, c,
					 "missing inode %llu",
					 pos + i);
			break;
		}

		if (links[i].count)
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
	bool need_loop = false;
	u64 pos = 0;
	struct nlink *links = vmalloc(INODES_PER_ITER * sizeof(*links));
	int ret = 0;

	if (!links)
		return -ENOMEM;

	do {
		ret = bch_gc_walk_dirents(c, pos, links, &need_loop);
		if (ret)
			break;

		ret = bch_gc_walk_inodes(c, pos, links);
		if (ret)
			break;

		pos += INODES_PER_ITER;
	} while (need_loop);

	vfree(links);

	return ret;
}
