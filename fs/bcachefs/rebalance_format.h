/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_FORMAT_H
#define _BCACHEFS_REBALANCE_FORMAT_H

struct bch_extent_rebalance {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u64			type:6,
				unused:5,
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
	__u64			promote_target:12,
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
				unused:5,
				type:6;
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

