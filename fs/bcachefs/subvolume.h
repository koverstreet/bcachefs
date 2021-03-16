/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SUBVOLUME_H
#define _BCACHEFS_SUBVOLUME_H

void bch2_snapshot_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
const char *bch2_snapshot_invalid(const struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_snapshot (struct bkey_ops) {		\
	.key_invalid	= bch2_snapshot_invalid,		\
	.val_to_text	= bch2_snapshot_to_text,		\
}

static inline bool bch2_snapshot_is_ancestor(struct bch_fs *c, u32 id, u32 ancestor)
{
	if (id < ancestor) {
		struct bch_snapshot_table *t;

		rcu_read_lock();
		t = rcu_dereference(c->snapshot_table);

		do {
			if (id < t->base) {
				rcu_read_unlock();
				return false;
			}

			id = t->d[id - t->base];
		} while (id < ancestor);

		rcu_read_unlock();
	}

	return id == ancestor;
}

int bch2_fs_snapshots_check(struct bch_fs *);
void bch2_fs_snapshots_exit(struct bch_fs *);
int bch2_fs_snapshots_start(struct bch_fs *);

const char *bch2_subvolume_invalid(const struct bch_fs *, struct bkey_s_c);
void bch2_subvolume_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_subvolume (struct bkey_ops) {		\
	.key_invalid	= bch2_subvolume_invalid,		\
	.val_to_text	= bch2_subvolume_to_text,		\
}

int bch2_subvolume_get_snapshot(struct btree_trans *, u32, u32 *);

int bch2_subvolume_delete(struct btree_trans *, u32);
int bch2_subvolume_create(struct btree_trans *, u64, u32,
			  u32 *, u32 *, bool);

#endif /* _BCACHEFS_SUBVOLUME_H */
