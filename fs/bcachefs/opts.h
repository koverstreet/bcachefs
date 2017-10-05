#ifndef _BCACHEFS_OPTS_H
#define _BCACHEFS_OPTS_H

#include <linux/bug.h>
#include <linux/log2.h>
#include <linux/string.h>
#include "bcachefs_format.h"

extern const char * const bch2_error_actions[];
extern const char * const bch2_csum_types[];
extern const char * const bch2_compression_types[];
extern const char * const bch2_str_hash_types[];
extern const char * const bch2_data_types[];
extern const char * const bch2_cache_replacement_policies[];
extern const char * const bch2_cache_modes[];
extern const char * const bch2_dev_state[];

/*
 * Mount options; we also store defaults in the superblock.
 *
 * Also exposed via sysfs: if an option is writeable, and it's also stored in
 * the superblock, changing it via sysfs (currently? might change this) also
 * updates the superblock.
 *
 * We store options as signed integers, where -1 means undefined. This means we
 * can pass the mount options to bch2_fs_alloc() as a whole struct, and then only
 * apply the options from that struct that are defined.
 */

/* dummy option, for options that aren't stored in the superblock */
LE64_BITMASK(NO_SB_OPT,		struct bch_sb, flags[0], 0, 0);

/**
 * BCH_OPT(name, mode, sb_opt, type, ...)
 *
 * @name	- name of mount option, sysfs attribute, and struct bch_opts
 *		  member
 *
 * @mode	- sysfs attr permissions
 *
 * @sb_option	- name of corresponding superblock option
 *
 * @type	- one of OPT_BOOL, OPT_UINT, OPT_STR
 */

enum opt_type {
	BCH_OPT_BOOL,
	BCH_OPT_UINT,
	BCH_OPT_STR,
};

#define BCH_VISIBLE_OPTS()						\
	BCH_OPT(errors,			0644,	BCH_SB_ERROR_ACTION,	\
		s8,  OPT_STR(bch2_error_actions))			\
	BCH_OPT(metadata_replicas,	0444,	BCH_SB_META_REPLICAS_WANT,\
		s8,  OPT_UINT(1, BCH_REPLICAS_MAX))			\
	BCH_OPT(data_replicas,		0444,	BCH_SB_DATA_REPLICAS_WANT,\
		s8,  OPT_UINT(1, BCH_REPLICAS_MAX))			\
	BCH_OPT(metadata_replicas_required, 0444, BCH_SB_META_REPLICAS_REQ,\
		s8,  OPT_UINT(1, BCH_REPLICAS_MAX))			\
	BCH_OPT(data_replicas_required,	0444,	BCH_SB_DATA_REPLICAS_REQ,\
		s8,  OPT_UINT(1, BCH_REPLICAS_MAX))			\
	BCH_OPT(degraded,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(metadata_checksum,	0644,	BCH_SB_META_CSUM_TYPE,	\
		s8,  OPT_STR(bch2_csum_types))				\
	BCH_OPT(data_checksum,		0644,	BCH_SB_DATA_CSUM_TYPE,	\
		s8,  OPT_STR(bch2_csum_types))				\
	BCH_OPT(compression,		0644,	BCH_SB_COMPRESSION_TYPE,\
		s8,  OPT_STR(bch2_compression_types))			\
	BCH_OPT(str_hash,		0644,	BCH_SB_STR_HASH_TYPE,	\
		s8,  OPT_STR(bch2_str_hash_types))			\
	BCH_OPT(inodes_32bit,		0644,	BCH_SB_INODE_32BIT,	\
		s8,  OPT_BOOL())					\
	BCH_OPT(gc_reserve_percent,	0444,	BCH_SB_GC_RESERVE,	\
		s8,  OPT_UINT(5, 21))					\
	BCH_OPT(root_reserve_percent,	0444,	BCH_SB_ROOT_RESERVE,	\
		s8,  OPT_UINT(0, 100))					\
	BCH_OPT(wide_macs,		0644,	BCH_SB_128_BIT_MACS,	\
		s8,  OPT_BOOL())					\
	BCH_OPT(verbose_recovery,	0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(posix_acl,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(journal_flush_disabled,	0644,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(nofsck,			0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(fix_errors,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(nochanges,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(noreplay,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(norecovery,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(noexcl,			0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(sb,			0444,	NO_SB_OPT,		\
		s64, OPT_UINT(0, S64_MAX))				\

#define BCH_OPTS()							\
	BCH_OPT(read_only,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_OPT(nostart,		0444,	NO_SB_OPT,		\
		s8,  OPT_BOOL())					\
	BCH_VISIBLE_OPTS()

struct bch_opts {
#define BCH_OPT(_name, _mode, _sb_opt, _bits, ...)			\
	_bits	_name;

	BCH_OPTS()
#undef BCH_OPT
};

enum bch_opt_id {
#define BCH_OPT(_name, ...)			\
	Opt_##_name,

	BCH_VISIBLE_OPTS()
#undef BCH_OPT
};

struct bch_option {
	const char		*name;
	void			(*set_sb)(struct bch_sb *, u64);
	enum opt_type		type;

	union {
	struct {
		u64		min, max;
	};
	struct {
		const char * const *choices;
	};
	};

};

extern const struct bch_option bch2_opt_table[];

static inline struct bch_opts bch2_opts_empty(void)
{
	struct bch_opts ret;

	memset(&ret, 255, sizeof(ret));
	return ret;
}

static inline void bch2_opts_apply(struct bch_opts *dst, struct bch_opts src)
{
#define BCH_OPT(_name, ...)			\
	if (src._name >= 0)						\
		dst->_name = src._name;

	BCH_OPTS()
#undef BCH_OPT
}

#define opt_defined(_opt)		((_opt) >= 0)

void bch2_opt_set(struct bch_opts *, enum bch_opt_id, u64);
struct bch_opts bch2_sb_opts(struct bch_sb *);

int bch2_parse_mount_opts(struct bch_opts *, char *);
enum bch_opt_id bch2_parse_sysfs_opt(const char *, const char *, u64 *);

ssize_t bch2_opt_show(struct bch_opts *, const char *, char *, size_t);

#endif /* _BCACHEFS_OPTS_H */
