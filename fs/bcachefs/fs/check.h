/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FSCK_H
#define _BCACHEFS_FSCK_H

#include "str_hash.h"

/* recoverds snapshot IDs of overwrites at @pos */
struct snapshots_seen {
	struct bpos			pos;
	snapshot_id_list		ids;
};

static inline void snapshots_seen_exit(struct snapshots_seen *s)
{
	darray_exit(&s->ids);
}

static inline struct snapshots_seen snapshots_seen_init(void)
{
	return (struct snapshots_seen) {};
}

DEFINE_CLASS(snapshots_seen, struct snapshots_seen,
	     snapshots_seen_exit(&_T),
	     snapshots_seen_init(), void)

int bch2_snapshots_seen_update(struct bch_fs *, struct snapshots_seen *,
			       enum btree_id, struct bpos);

bool bch2_key_visible_in_snapshot(struct bch_fs *, struct snapshots_seen *, u32, u32);

bool bch2_ref_visible(struct bch_fs *, struct snapshots_seen *, u32, u32);
int bch2_ref_visible2(struct bch_fs *,
		      u32, struct snapshots_seen *,
		      u32, struct snapshots_seen *);

struct inode_walker_entry {
	struct bch_inode_unpacked inode;
	bool			whiteout;
	u64			count;
	u64			i_size;
};

struct inode_walker {
	bool				first_this_inode;
	bool				have_inodes;
	bool				recalculate_sums;
	struct bpos			last_pos;

	DARRAY(struct inode_walker_entry) inodes;
	snapshot_id_list		deletes;
};

static inline void inode_walker_exit(struct inode_walker *w)
{
	darray_exit(&w->inodes);
	darray_exit(&w->deletes);
}

static inline struct inode_walker inode_walker_init(void)
{
	return (struct inode_walker) {};
}

DEFINE_CLASS(inode_walker, struct inode_walker,
	     inode_walker_exit(&_T),
	     inode_walker_init(), void)

struct inode_walker_entry *bch2_walk_inode(struct btree_trans *,
					   struct inode_walker *,
					   struct bkey_s_c);

void bch2_dirent_inode_mismatch_msg(struct printbuf *, struct bch_fs *,
				    struct bkey_s_c_dirent,
				    struct bch_inode_unpacked *);

int bch2_reattach_inode(struct btree_trans *, struct bch_inode_unpacked *);

int bch2_fsck_update_backpointers(struct btree_trans *,
				  struct snapshots_seen *,
				  const struct bch_hash_desc,
				  struct bch_hash_info *,
				  struct bkey_i *);

int bch2_check_key_has_inode(struct btree_trans *,
			     struct btree_iter *,
			     struct inode_walker *,
			     struct inode_walker_entry *,
			     struct bkey_s_c);

int bch2_check_inodes(struct bch_fs *);
int bch2_check_extents(struct bch_fs *);
int bch2_check_indirect_extents(struct bch_fs *);
int bch2_check_dirents(struct bch_fs *);
int bch2_check_xattrs(struct bch_fs *);
int bch2_check_root(struct bch_fs *);
int bch2_check_subvolume_structure(struct bch_fs *);
int bch2_check_unreachable_inodes(struct bch_fs *);
int bch2_check_directory_structure(struct bch_fs *);
int bch2_check_nlinks(struct bch_fs *);
int bch2_fix_reflink_p(struct bch_fs *);

long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *);
long bch2_ioctl_fsck_online(struct bch_fs *, struct bch_ioctl_fsck_online);

#endif /* _BCACHEFS_FSCK_H */
