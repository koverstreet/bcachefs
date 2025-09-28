/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_FORMAT_H
#define _BCACHEFS_REBALANCE_FORMAT_H

/*
 * rebalance on disk data structures:
 *
 * extents will contain a bch_extent_rebalance if they have background
 * processing pending; additionally, indirect extents will always have a
 * bch_extent_rebalance if they had any io path options set on the inode, since
 * we don't (yet) have backpointers that would let us look up the "owning" inode
 * of an indirect extent to recover the io path options.
 *
 * We also have 4 btrees for keeping track of pending rebalance work:
 *
 * BTREE_ID_rebalance_scan:
 *   Inum 0:
 *     Holds "scan cookies", which are created on option change to indicate that
 *     new options need to be propagated to each extent; this happens before the
 *     actual data processing.
 *
 *     A scan cookie may be for the entire filesystem, a specific device, or a
 *     specific inode.
 *
 *   Inum 1:
 *     Btree nodes that need background processing cannot be tracked by the
 *     other rebalance btrees; instead they have backpointers
 *     (KEY_TYPE_backpointer) created here.
 *
 *     This has the added benefit that btree nodes will be processed before
 *     regular data, which is beneficial if e.g. we're recovering from data
 *     being degraded.
 *
 *  BTREE_ID_rebalance_work:
 *    The main "pending rebalance work" btree: it's a simple bitset btree where
 *    a set bit indicates that an an extent in BTREE_ID_extents or
 *    BTREE_ID_reflink needs to be processed.
 *
 *  BTREE_ID_rebalance_hipri:
 *    If bch_extent_rebalance.hipri is set, the extent will be tracked here
 *    instead of BTREE_ID_rebalance_work and processed ahead of extents in
 *    BTREE_ID_rebalance_work; this is so that we can evacuate failed devices
 *    before other work.
 *
 *  BTREE_ID_rebalance_pending:
 *    If we'd like to move an extent to a specific target, but can't because the
 *    target is full, we set bch_extent_rebalance.pending and switch to tracking
 *    it here; pending rebalance work is re-attempted on device resize, add, or
 *    label change.
 */

struct bch_extent_rebalance {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u64	type:6,
		ptrs_moving:5,
		hipri:1,
		pending:1,
		need_rb:5,

		data_replicas_from_inode:1,
		data_checksum_from_inode:1,
		erasure_code_from_inode:1,
		background_compression_from_inode:1,
		background_target_from_inode:1,
		promote_target_from_inode:1,

		data_replicas:3,
		data_checksum:4,
		erasure_code:1,
		background_compression:8, /* enum bch_compression_opt */
		background_target:12,
		promote_target:12;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u64	promote_target:12,
		background_target:12,
		background_compression:8,
		erasure_code:1,
		data_checksum:4,
		data_replicas:3,

		promote_target_from_inode:1,
		background_target_from_inode:1,
		background_compression_from_inode:1,
		erasure_code_from_inode:1,
		data_checksum_from_inode:1,
		data_replicas_from_inode:1,

		need_rb:5,
		pending:1,
		hipri:1,
		ptrs_moving:5,
		type:6;
#endif
};

struct bch_extent_rebalance_bp {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u64			type:8,
				idx:56;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u64			idx:56,
				type:8;
#endif
};

/* subset of BCH_INODE_OPTS */
#define BCH_REBALANCE_OPTS()			\
	x(data_replicas)			\
	x(data_checksum)			\
	x(erasure_code)				\
	x(background_compression)		\
	x(background_target)			\
	x(promote_target)

enum bch_rebalance_opts {
#define x(n)	BCH_REBALANCE_##n,
	BCH_REBALANCE_OPTS()
#undef x
};

#define BCH_REBALANCE_ACCOUNTING()		\
	x(data_replicas)			\
	x(data_checksum)			\
	x(erasure_code)				\
	x(background_compression)		\
	x(background_target)			\
	x(high_priority)			\
	x(pending)				\

enum bch_rebalance_accounting_type {
#define x(n) BCH_REBALANCE_ACCOUNTING_##n,
	BCH_REBALANCE_ACCOUNTING()
#undef x
};

#endif /* _BCACHEFS_REBALANCE_FORMAT_H */

