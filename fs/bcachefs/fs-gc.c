
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

#define QSTR(n) { { { .len = strlen(n) } }, .name = n }

struct inode_walker {
	bool			first_this_inode;
	bool			have_inode;
	u16			i_mode;
	u64			i_size;
	u64			cur_inum;
	struct bkey_i_inode	inode;
};

static struct inode_walker inode_walker_init(void)
{
	return (struct inode_walker) {
		.cur_inum	= -1,
		.have_inode	= false,
	};
}

static int walk_inode(struct cache_set *c, struct inode_walker *w, u64 inum)
{
	w->first_this_inode	= inum != w->cur_inum;
	w->cur_inum		= inum;

	if (w->first_this_inode) {
		int ret = bch_inode_find_by_inum(c, inum, &w->inode);

		if (ret && ret != -ENOENT)
			return ret;

		w->have_inode = !ret;

		if (w->have_inode) {
			w->i_mode = le16_to_cpu(w->inode.v.i_mode);
			w->i_size = le64_to_cpu(w->inode.v.i_size);
		}
	}

	return 0;
}

/*
 * Walk extents: verify that extents have a corresponding S_ISREG inode, and
 * that i_size an i_sectors are consistent
 */
noinline_for_stack
static int check_extents(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 i_sectors;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		if (k.k->type == KEY_TYPE_DISCARD)
			continue;

		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
			"extent type %u for missing inode %llu",
			k.k->type, k.k->p.inode);

		unfixable_fsck_err_on(w.first_this_inode && w.have_inode &&
			le64_to_cpu(w.inode.v.i_sectors) !=
			(i_sectors = bch_count_inode_sectors(c, w.cur_inum)),
			c, "i_sectors wrong: got %llu, should be %llu",
			le64_to_cpu(w.inode.v.i_sectors), i_sectors);

		unfixable_fsck_err_on(w.have_inode &&
			!S_ISREG(w.i_mode) && !S_ISLNK(w.i_mode), c,
			"extent type %u for non regular file, inode %llu mode %o",
			k.k->type, k.k->p.inode, w.i_mode);

		unfixable_fsck_err_on(k.k->type != BCH_RESERVATION &&
			k.k->p.offset > round_up(w.i_size, PAGE_SIZE) >> 9, c,
			"extent type %u offset %llu past end of inode %llu, i_size %llu",
			k.k->type, k.k->p.offset, k.k->p.inode, w.i_size);
	}
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/*
 * Walk dirents: verify that they all have a corresponding S_ISDIR inode,
 * validate d_type
 */
noinline_for_stack
static int check_dirents(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		struct bkey_s_c_dirent d;
		struct bkey_i_inode target;
		bool have_target;
		u64 d_inum;

		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
			"dirent in nonexisting directory %llu",
			k.k->p.inode);

		unfixable_fsck_err_on(!S_ISDIR(w.i_mode), c,
			"dirent in non directory inode %llu, type %u",
			k.k->p.inode, mode_to_type(w.i_mode));

		if (k.k->type != BCH_DIRENT)
			continue;

		d = bkey_s_c_to_dirent(k);
		d_inum = le64_to_cpu(d.v->d_inum);

		unfixable_fsck_err_on(d_inum == d.k->p.inode, c,
			"dirent points to own directory");

		ret = bch_inode_find_by_inum(c, d_inum, &target);
		if (ret && ret != -ENOENT)
			break;

		have_target = !ret;
		ret = 0;

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
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/*
 * Walk xattrs: verify that they all have a corresponding inode
 */
noinline_for_stack
static int check_xattrs(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_XATTRS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
			"xattr for missing inode %llu",
			k.k->p.inode);
	}
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/* Get root directory, create if it doesn't exist: */
static int check_root(struct cache_set *c, struct bkey_i_inode *root_inode)
{
	int ret;

	ret = bch_inode_find_by_inum(c, BCACHE_ROOT_INO, root_inode);
	if (ret && ret != -ENOENT)
		return ret;

	if (fsck_err_on(ret, c, "root directory missing"))
		goto create_root;

	if (fsck_err_on(!S_ISDIR(le16_to_cpu(root_inode->v.i_mode)), c,
			"root inode not a directory"))
		goto create_root;

	return 0;
fsck_err:
	return ret;
create_root:
	bch_inode_init(c, root_inode, 0, 0, S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0);
	root_inode->k.p.inode = BCACHE_ROOT_INO;

	return bch_btree_insert(c, BTREE_ID_INODES, &root_inode->k_i,
				NULL, NULL, NULL, 0);
}

/* Get lost+found, create if it doesn't exist: */
static int check_lostfound(struct cache_set *c,
			   struct bkey_i_inode *root_inode,
			   struct bkey_i_inode *lostfound_inode)
{
	struct qstr lostfound = QSTR("lost+found");
	struct bch_hash_info root_str_hash = bch_hash_info_init(&root_inode->v);
	u64 inum;
	int ret;

	inum = bch_dirent_lookup(c, BCACHE_ROOT_INO, &root_str_hash,
				 &lostfound);
	if (!inum) {
		bch_notice(c, "creating lost+found");
		goto create_lostfound;
	}

	ret = bch_inode_find_by_inum(c, inum, lostfound_inode);
	if (ret && ret != -ENOENT)
		return ret;

	if (fsck_err_on(ret, c, "lost+found missing"))
		goto create_lostfound;

	if (fsck_err_on(!S_ISDIR(le16_to_cpu(lostfound_inode->v.i_mode)), c,
			"lost+found inode not a directory"))
		goto create_lostfound;

	return 0;
fsck_err:
	return ret;
create_lostfound:
	le32_add_cpu(&root_inode->v.i_nlink, 1);

	ret = bch_btree_insert(c, BTREE_ID_INODES, &root_inode->k_i,
			       NULL, NULL, NULL, 0);
	if (ret)
		return ret;

	bch_inode_init(c, lostfound_inode, 0, 0, S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0);

	ret = bch_inode_create(c, &lostfound_inode->k_i, BLOCKDEV_INODE_MAX, 0,
			       &c->unused_inode_hint);
	if (ret)
		return ret;

	ret = bch_dirent_create(c, BCACHE_ROOT_INO, &root_str_hash, DT_DIR,
				&lostfound, lostfound_inode->k.p.inode, NULL, 0);
	if (ret)
		return ret;

	return 0;
}

struct inode_bitmap {
	unsigned long	*bits;
	size_t		size;
};

static inline bool inode_bitmap_test(struct inode_bitmap *b, size_t nr)
{
	return nr < b->size ? test_bit(nr, b->bits) : false;
}

static inline int inode_bitmap_set(struct inode_bitmap *b, size_t nr)
{
	if (nr >= b->size) {
		size_t new_size = max(max(PAGE_SIZE * 8,
					  b->size * 2),
					  nr + 1);
		void *n;

		new_size = roundup_pow_of_two(new_size);
		n = krealloc(b->bits, new_size / 8, GFP_KERNEL|__GFP_ZERO);
		if (!n)
			return -ENOMEM;

		b->bits = n;
		b->size = new_size;
	}

	__set_bit(nr, b->bits);
	return 0;
}

struct pathbuf {
	size_t		nr;
	size_t		size;

	struct pathbuf_entry {
		u64	inum;
		u64	offset;
	}		*entries;
};

static int path_down(struct pathbuf *p, u64 inum)
{
	if (p->nr == p->size) {
		size_t new_size = max(256UL, p->size * 2);
		void *n = krealloc(p->entries,
				   new_size * sizeof(p->entries[0]),
				   GFP_KERNEL);
		if (!n)
			return -ENOMEM;

		p->entries = n;
		p->size = new_size;
	};

	p->entries[p->nr++] = (struct pathbuf_entry) {
		.inum = inum,
		.offset = 0,
	};
	return 0;
}

noinline_for_stack
static int check_directory_structure(struct cache_set *c)
{
	struct bkey_i_inode root_inode, lostfound_inode;
	struct inode_bitmap dirs_done = { NULL, 0 };
	struct pathbuf path = { 0, 0, NULL };
	struct pathbuf_entry *e;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent dirent;
	u64 d_inum;
	int ret = 0;

	ret = check_root(c, &root_inode);
	if (ret)
		return ret;

	ret = check_lostfound(c, &root_inode, &lostfound_inode);
	if (ret)
		return ret;

	/* DFS: */

	ret = inode_bitmap_set(&dirs_done, BCACHE_ROOT_INO);
	if (ret)
		goto err;

	ret = path_down(&path, BCACHE_ROOT_INO);
	if (ret)
		return ret;

	while (path.nr) {
down:
		e = &path.entries[path.nr - 1];

		if (e->offset == U64_MAX)
			goto up;

		for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
				   POS(e->inum, e->offset + 1), k) {
			if (k.k->p.inode != e->inum)
				break;

			e->offset = k.k->p.offset;

			if (k.k->type != BCH_DIRENT)
				continue;

			dirent = bkey_s_c_to_dirent(k);

			if (dirent.v->d_type != DT_DIR)
				continue;

			d_inum = le64_to_cpu(dirent.v->d_inum);

			unfixable_fsck_err_on(inode_bitmap_test(&dirs_done, d_inum), c,
					      "directory with multiple hardlinks");

			ret = inode_bitmap_set(&dirs_done, d_inum);
			if (ret)
				goto err;

			ret = path_down(&path, d_inum);
			if (ret)
				goto err;

			bch_btree_iter_unlock(&iter);
			goto down;
		}
		ret = bch_btree_iter_unlock(&iter);
		if (ret)
			goto err;
up:
		path.nr--;
	}

	for_each_btree_key(&iter, c, BTREE_ID_INODES, POS_MIN, k) {
		if (k.k->type != BCH_INODE_FS ||
		    !S_ISDIR(le16_to_cpu(bkey_s_c_to_inode(k).v->i_mode)))
			continue;

		unfixable_fsck_err_on(!inode_bitmap_test(&dirs_done, k.k->p.inode), c,
				      "unreachable directory found (inum %llu)",
				      k.k->p.inode);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		goto err;
out:
	kfree(dirs_done.bits);
	kfree(path.entries);
	return ret;
err:
fsck_err:
	ret = bch_btree_iter_unlock(&iter) ?: ret;
	goto out;
}

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

	while ((k = bch_btree_iter_peek(&iter)).k &&
	       !btree_iter_err(k)) {
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

noinline_for_stack
static int check_inode_nlinks(struct cache_set *c)
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

/*
 * Checks for inconsistencies that shouldn't happen, unless we have a bug.
 * Doesn't fix them yet, mainly because they haven't yet been observed:
 */
int bch_fsck(struct cache_set *c, bool full_fsck)
{
	int ret;

	if (!full_fsck)
		goto check_nlinks;

	ret = check_extents(c);
	if (ret)
		return ret;

	ret = check_dirents(c);
	if (ret)
		return ret;

	ret = check_xattrs(c);
	if (ret)
		return ret;

	ret = check_directory_structure(c);
	if (ret)
		return ret;
check_nlinks:
	ret = check_inode_nlinks(c);
	if (ret)
		return ret;

	return 0;
}
