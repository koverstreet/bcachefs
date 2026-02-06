/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RECOVERY_PASSES_FORMAT_H
#define _BCACHEFS_RECOVERY_PASSES_FORMAT_H

#define PASS_SILENT		BIT(0)
#define PASS_FSCK		BIT(1)
#define PASS_UNCLEAN		BIT(2)
#define PASS_ALWAYS		BIT(3)
#define PASS_ONLINE		BIT(4)
#define PASS_ALLOC		BIT(5)
#define PASS_NODEFER		BIT(6)
#define PASS_FSCK_ALLOC		(PASS_FSCK|PASS_ALLOC)

#ifdef CONFIG_BCACHEFS_DEBUG
#define PASS_FSCK_DEBUG		BIT(1)
#else
#define PASS_FSCK_DEBUG		0
#endif

/*
 * Passes may be reordered, but the second field is a persistent identifier and
 * must never change:
 */
#define BCH_RECOVERY_PASSES()									\
	x(recovery_pass_empty,			41, PASS_SILENT,			0,	\
	  "Placeholder so scan_for_btree_nodes is not index 0")					\
	x(scan_for_btree_nodes,			37, 0,					0,	\
	  "Scan all devices for btree nodes by magic number, "					\
	  "deduplicate replicas, and build node scan table "					\
	  "for topology repair")								\
	x(check_topology,			 4, 0,						\
	  BIT_ULL(BCH_RECOVERY_PASS_scan_for_btree_nodes),					\
	  "Verify btree roots exist (reconstructing from node "					\
	  "scan if missing), then recursively validate "					\
	  "parent-child links and min/max key boundaries")					\
	x(accounting_read,			39, PASS_ALWAYS,				\
	  BIT_ULL(BCH_RECOVERY_PASS_check_topology),						\
	  "Read accounting keys from btree and journal into "					\
	  "memory, merging deltas and initializing per-device "					\
	  "usage counters")									\
	x(alloc_read,				 0, PASS_ALWAYS,			0,	\
	  "Populate in-memory bucket generation cache from "					\
	  "bucket_gens btree (or alloc btree on older "						\
	  "filesystems)")									\
	x(discard_buckets_populate,		48, PASS_ALWAYS|PASS_SILENT,		0,	\
	  "Populate per-device discard FIFO from need_discard btree, "		\
	  "ordering buckets by journal_seq_empty so oldest generations "	\
	  "are discarded first")							\
	x(stripes_read,				 1, 0,					0,	\
	  "Reserved for erasure-coding stripe initialization; "					\
	  "currently a no-op")									\
	x(initialize_subvolumes,		 2, 0,					0,	\
	  "Create root snapshot tree, root snapshot node, "					\
	  "and root subvolume for a new filesystem")						\
	x(snapshots_read,			 3, PASS_ALWAYS,			0,	\
	  "Populate in-memory snapshot table with ancestry "					\
	  "bitmaps and depth info by iterating snapshot "					\
	  "btree in reverse order")								\
	x(check_allocations,			 5, PASS_FSCK_ALLOC,				\
	  BIT_ULL(BCH_RECOVERY_PASS_check_topology),						\
	  "Full GC pass: walk all btrees marking referenced "					\
	  "buckets, then compare against alloc btree to "					\
	  "repair data_type, sector counts, and stripe refs")					\
	x(trans_mark_dev_sbs,			 6, PASS_ALWAYS|PASS_SILENT|PASS_ALLOC,	0,	\
	  "Mark superblock and journal regions in alloc btree")					\
	x(fs_journal_alloc,			 7, PASS_ALWAYS|PASS_SILENT|PASS_ALLOC,	0,	\
	  "Ensure journal has allocated buckets")						\
	x(set_may_go_rw,			 8, PASS_ALWAYS|PASS_SILENT,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Enable read-write mode; btree updates go to "					\
	  "journal instead of replay buffer")							\
	x(journal_replay,			 9, PASS_ALWAYS,				\
	  BIT_ULL(BCH_RECOVERY_PASS_set_may_go_rw),						\
	  "Replay pending journal keys into btrees, "						\
	  "accounting keys first; sorted-order bulk insert "					\
	  "with per-key fallback for journal deadlocks")					\
	x(merge_btree_nodes,			45, PASS_ONLINE,			0,	\
	  "Merge adjacent underfull btree nodes to reclaim "					\
	  "wasted space")									\
	x(check_alloc_info,			10, PASS_ONLINE|PASS_FSCK_ALLOC,		\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Cross-check alloc btree against freespace, "						\
	  "need_discard, and bucket_gens btrees; repair "					\
	  "missing or incorrect entries in each")						\
	x(check_lrus,				11, PASS_ONLINE|PASS_FSCK_ALLOC,		\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Verify LRU btree entries match alloc key "						\
	  "timestamps for cached-data and fragmentation "					\
	  "LRUs; delete stale entries")								\
	x(check_btree_backpointers,		12, PASS_ONLINE|PASS_FSCK_ALLOC,		\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Verify every backpointer entry references a "					\
	  "valid alloc key; remove backpointers for "						\
	  "nonexistent buckets")								\
	x(check_backpointers_to_extents,	13, PASS_ONLINE,				\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Verify each backpointer matches an actual extent "					\
	  "or btree pointer at the claimed location; "						\
	  "remove stale entries")								\
	x(check_extents_to_backpointers,	14, PASS_ONLINE|PASS_FSCK_ALLOC,		\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Find buckets with missing backpointers by "						\
	  "scanning alloc btree, then regenerate them "						\
	  "from extent and btree pointer data")							\
	x(check_alloc_to_lru_refs,		15, PASS_ONLINE|PASS_FSCK_ALLOC,		\
	  BIT_ULL(BCH_RECOVERY_PASS_check_allocations),						\
	  "Ensure cached buckets have correct cached-data "					\
	  "LRU entries and fragmentable buckets have correct "					\
	  "fragmentation LRU entries")								\
	x(fs_freespace_init,			16, PASS_ALWAYS|PASS_SILENT,		0,	\
	  "Initialize freespace btree from alloc info")						\
	x(bucket_gens_init,			17, 0,					0,	\
	  "Populate bucket_gens btree from alloc btree "					\
	  "generation numbers; one-time migration")						\
	x(reconstruct_snapshots,		38, 0,					0,	\
	  "Scan snapshot-bearing btrees to find snapshot IDs "					\
	  "in use, then reconstruct missing snapshot nodes "					\
	  "and tree entries")									\
	x(delete_dead_interior_snapshots,	44, 0,					0,	\
	  "Collapse interior snapshot nodes with no remaining "					\
	  "keys by re-parenting their single live child")					\
	x(check_snapshot_trees,			18, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_reconstruct_snapshots),					\
	  "Validate snapshot_tree entries: root snapshot "					\
	  "reference, back-link consistency, master_subvol "					\
	  "points to a real non-snapshot subvolume")						\
	x(check_snapshots,			19, PASS_ALWAYS|PASS_ONLINE|PASS_FSCK|PASS_NODEFER,	\
	  BIT_ULL(BCH_RECOVERY_PASS_reconstruct_snapshots)|					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshot_trees),					\
	  "Validate snapshot btree in reverse order: "						\
	  "parent/child bidirectional links, tree_id, "						\
	  "depth, subvol flag, and skiplist pointers")						\
	x(check_subvols,			20, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshots),						\
	  "Validate subvolume entries: snapshot exists, "					\
	  "root inode has correct bi_subvol, "							\
	  "fs_path_parent is valid; delete unlinked subvols")					\
	x(check_subvol_children,		35, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_subvols),						\
	  "Walk subvolume_children btree and remove entries "					\
	  "not matching a real subvolume with correct "						\
	  "fs_path_parent")									\
	x(delete_dead_snapshots,		21, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshots),						\
	  "Delete snapshot data keys across all "						\
	  "snapshot-bearing btrees, then remove snapshot "					\
	  "nodes and mark empty interior nodes")						\
	x(fs_upgrade_for_subvolumes,		22, 0,					0,	\
	  "One-time migration: set bi_subvol on root inode "					\
	  "for pre-subvolumes filesystems")							\
	x(check_inodes,				24, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshots),						\
	  "Validate inode fields (mode, flags, i_size, "					\
	  "bi_subvol), delete orphaned unlinked inodes, "					\
	  "repair invalid backpointers")							\
	x(check_extents,			25, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes),						\
	  "Validate extent keys: owning inode exists, "						\
	  "snapshot valid, no overlaps, i_size and "						\
	  "i_sectors consistent")								\
	x(check_indirect_extents,		26, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshots),						\
	  "Validate reflink indirect extents; drop stale "					\
	  "device pointers whose generation no longer "						\
	  "matches")										\
	x(check_dirents,			27, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes),						\
	  "Validate directory entries: target inode exists "					\
	  "in correct snapshot, d_type matches inode mode, "					\
	  "hash values correct")								\
	x(check_xattrs,				28, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes),						\
	  "Validate xattr entries: owning inode exists "					\
	  "in valid snapshot, hash correct; delete orphans")					\
	x(check_root,				29, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes),						\
	  "Ensure root subvolume and root directory inode "					\
	  "exist; create them if missing")							\
	x(check_unreachable_inodes,		40, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes)|						\
	  BIT_ULL(BCH_RECOVERY_PASS_check_dirents),						\
	  "Find inodes with no directory entry (unset "						\
	  "bi_dir backpointer); reattach to lost+found")					\
	x(check_subvolume_structure,		36, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_subvols)|						\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes),						\
	  "Follow each subvolume's fs_path_parent chain "					\
	  "to root, verify no cycles or dead ends; "						\
	  "reattach disconnected subvolumes")							\
	x(check_directory_structure,		30, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_unreachable_inodes),					\
	  "DFS from each directory following parent "						\
	  "pointers, detect cycles, renumber bi_depth, "					\
	  "reattach disconnected directories")							\
	x(check_nlinks,				31, PASS_FSCK,					\
	  BIT_ULL(BCH_RECOVERY_PASS_check_inodes)|						\
	  BIT_ULL(BCH_RECOVERY_PASS_check_dirents),						\
	  "Two-pass nlink verification: collect hardlinked "					\
	  "inodes, count directory references, fix "						\
	  "bi_nlink mismatches")								\
	x(check_reconcile_work,			43, PASS_ONLINE|PASS_FSCK,			\
	  BIT_ULL(BCH_RECOVERY_PASS_check_snapshots),						\
	  "Validate reconcile work/hipri/pending/scan "						\
	  "btrees against actual extent data; remove "						\
	  "stale entries")									\
	x(resume_logged_ops,			23, PASS_ALWAYS,			0,	\
	  "Resume incomplete logged operations "						\
	  "(fallocate, stripe creation) from logged_ops "					\
	  "btree, then delete completed entries")						\
	x(delete_dead_inodes,			32, PASS_ALWAYS,			0,	\
	  "Scan deleted_inodes btree and fully remove "						\
	  "inodes with nlink == 0 that are not open")						\
	x(kill_i_generation_keys,		47, PASS_ONLINE,			0,	\
	  "Remove KEY_TYPE_inode_generation keys; this older "					\
	  "generation persistence mechanism has been "						\
	  "superseded")										\
	x(fix_reflink_p,			33, 0,					0,	\
	  "One-time migration: clear stale front_pad/"						\
	  "back_pad fields in KEY_TYPE_reflink_p keys")						\
	x(set_fs_needs_reconcile,		34, 0,					0,	\
	  "One-time pass: insert full-filesystem "						\
	  "reconcile_scan entry to trigger background "						\
	  "data verification")									\
	x(btree_bitmap_gc,			46, PASS_ONLINE,			0,	\
	  "Recompute per-device btree_allocated_bitmap "					\
	  "by scanning all live btree node pointers")						\
	x(lookup_root_inode,			42, PASS_ALWAYS|PASS_SILENT,		0,	\
	  "Verify root inode is readable before "						\
	  "completing recovery")

/* We normally enumerate recovery passes in the order we run them: */
enum bch_recovery_pass {
#define x(n, ...)	BCH_RECOVERY_PASS_##n,
	BCH_RECOVERY_PASSES()
#undef x
	BCH_RECOVERY_PASS_NR
};

/* But we also need stable identifiers that can be used in the superblock */
enum bch_recovery_pass_stable {
#define x(n, id, ...)	BCH_RECOVERY_PASS_STABLE_##n = id,
	BCH_RECOVERY_PASSES()
#undef x
};

struct recovery_pass_entry {
	__le64			last_run;
	__le32			last_runtime;
	__le32			flags;
};

LE32_BITMASK(BCH_RECOVERY_PASS_NO_RATELIMIT,	struct recovery_pass_entry, flags, 0, 1)

struct bch_sb_field_recovery_passes {
	struct bch_sb_field	field;
	struct recovery_pass_entry start[];
};

static inline unsigned
recovery_passes_nr_entries(struct bch_sb_field_recovery_passes *r)
{
	return r
		? ((vstruct_end(&r->field) - (void *) &r->start[0]) /
		   sizeof(struct recovery_pass_entry))
		: 0;
}

#endif /* _BCACHEFS_RECOVERY_PASSES_FORMAT_H */
