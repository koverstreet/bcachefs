/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SNAPSHOT_FORMAT_H
#define _BCACHEFS_SNAPSHOT_FORMAT_H

struct bch_snapshot {
	struct bch_val		v;
	__le32			flags;
	__le32			parent;
	__le32			children[2];
	__le32			subvol;
	/* corresponds to a bch_snapshot_tree in BTREE_ID_snapshot_trees */
	__le32			tree;
	__le32			depth;
	__le32			skip[3];
	bch_le128		btime;
};

/*
 * WILL_DELETE: leaf node that's no longer referenced by a subvolume, still has
 * keys, will be deleted by delete_dead_snapshots
 *
 * SUBVOL: true if a subvol points to this snapshot (why do we have this?
 * subvols are nonzero)
 *
 * DELETED: we never delete snapshot keys, we mark them as deleted so that we
 * can distinguish between a key for a missing snapshot (and we have no idea
 * what happened) and a key for a deleted snapshot (delete_dead_snapshots() missed
 * something, key should be deleted)
 *
 * NO_KEYS: we don't remove interior snapshot nodes from snapshot trees at
 * runtime, since we can't do the adjustements for the depth/skiplist field
 * atomically - and that breaks e.g. is_ancestor(). Instead, we mark it to be
 * deleted at the next remount; this tells us that we don't need to run the full
 * delete_dead_snapshots().
 *
 *
 * XXX - todo item:
 *
 * We should guard against a bitflip causing us to delete a snapshot incorrectly
 * by cross checking with the subvolume btree: delete_dead_snapshots() can take
 * out more data than any other codepath if it runs incorrectly
 */
LE32_BITMASK(BCH_SNAPSHOT_WILL_DELETE,	struct bch_snapshot, flags,  0,  1)
LE32_BITMASK(BCH_SNAPSHOT_SUBVOL,	struct bch_snapshot, flags,  1,  2)
LE32_BITMASK(BCH_SNAPSHOT_DELETED,	struct bch_snapshot, flags,  2,  3)
LE32_BITMASK(BCH_SNAPSHOT_NO_KEYS,	struct bch_snapshot, flags,  3,  4)

/*
 * Snapshot trees:
 *
 * The snapshot_trees btree gives us persistent indentifier for each tree of
 * bch_snapshot nodes, and allow us to record and easily find the root/master
 * subvolume that other snapshots were created from:
 */
struct bch_snapshot_tree {
	struct bch_val		v;
	__le32			master_subvol;
	__le32			root_snapshot;
};

#endif /* _BCACHEFS_SNAPSHOT_FORMAT_H */
