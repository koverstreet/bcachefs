/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_COMPRESS_TYPES_H
#define _BCACHEFS_DATA_COMPRESS_TYPES_H

struct bch_fs_compress {
	mempool_t		bounce[2];
	mempool_t		workspace[BCH_COMPRESSION_OPT_NR];
	size_t			zstd_workspace_size;
};

#endif /* _BCACHEFS_DATA_COMPRESS_TYPES_H */
