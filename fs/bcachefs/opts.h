#ifndef _BCACHE_OPTS_H
#define _BCACHE_OPTS_H

#include <linux/string.h>
#include "bcachefs_format.h"

/*
 * Mount options; we also store defaults in the superblock.
 *
 * Also exposed via sysfs: if an option is writeable, and it's also stored in
 * the superblock, changing it via sysfs (currently? might change this) also
 * updates the superblock.
 *
 * We store options as signed integers, where -1 means undefined. This means we
 * can pass the mount options to cache_set_alloc() as a whole struct, and then
 * only apply the options from that struct that are defined.
 */

extern const char * const bch_bool_opt[];
extern const char * const bch_error_actions[];
extern const char * const bch_csum_types[];
extern const char * const bch_compression_types[];

/* dummy option, for options that aren't stored in the superblock */
BITMASK(NO_SB_OPT,		struct cache_sb, flags, 0, 0);

/**
 * CACHE_SET_OPT(name, nr_bits, choices, sb_option, sysfs_writeable)
 *
 * @name - name of mount option, sysfs attribute, and struct cache_set_opts
 *	member
 *
 * @nr_bits - number of bits for cache_set_opts field, remember it's stored as a
 *	signed integer
 *
 * @choices - array of strings that the user can select from - option is by
 *	array index
 *
 *	Booleans are special cased; if @choices is bch_bool_opt the mount
 *	options name and noname will work as expected.
 *
 * @sb_option - name of corresponding superblock option
 *
 * @sysfs_writeable - if true, option will be modifiable at runtime via sysfs
 */

#define CACHE_SET_VISIBLE_OPTS()				\
	CACHE_SET_OPT(errors, 3,				\
		      bch_error_actions,			\
		      CACHE_ERROR_ACTION,			\
		      true)					\
	CACHE_SET_OPT(metadata_checksum, 4,			\
		      bch_csum_types,				\
		      CACHE_META_PREFERRED_CSUM_TYPE,		\
		      true)					\
	CACHE_SET_OPT(data_checksum, 4,				\
		      bch_csum_types,				\
		      CACHE_DATA_PREFERRED_CSUM_TYPE,		\
		      true)					\
	CACHE_SET_OPT(compression, 4,				\
		      bch_compression_types,			\
		      CACHE_COMPRESSION_TYPE,			\
		      true)					\
	CACHE_SET_OPT(verbose_recovery, 2,			\
		      bch_bool_opt,				\
		      NO_SB_OPT, false)				\
	CACHE_SET_OPT(posix_acl, 2,				\
		      bch_bool_opt,				\
		      NO_SB_OPT, false)				\
	CACHE_SET_OPT(journal_flush_disabled, 2,		\
		      bch_bool_opt,				\
		      NO_SB_OPT, true)

#define CACHE_SET_OPTS()					\
	CACHE_SET_OPT(read_only, 2,				\
		      bch_bool_opt,				\
		      NO_SB_OPT, 0)				\
	CACHE_SET_VISIBLE_OPTS()

struct cache_set_opts {
#define CACHE_SET_OPT(_name, _bits, _options, _sb_opt, _perm)	\
	int _name:_bits;

	CACHE_SET_OPTS()
#undef CACHE_SET_OPT
};

static inline struct cache_set_opts cache_set_opts_empty(void)
{
	struct cache_set_opts ret;

	memset(&ret, 255, sizeof(ret));
	return ret;
}

/*
 * Initial options from superblock - here we don't want any options undefined,
 * any options the superblock doesn't specify are set to 0:
 */
static inline struct cache_set_opts cache_superblock_opts(struct cache_sb *sb)
{
	return (struct cache_set_opts) {
#define CACHE_SET_OPT(_name, _bits, _options, _sb_opt, _perm)	\
		._name = _sb_opt##_BITS ? _sb_opt(sb) : 0,

	CACHE_SET_OPTS()
#undef CACHE_SET_OPT
	};
}

static inline void cache_set_opts_apply(struct cache_set_opts *dst,
					struct cache_set_opts src)
{
#define CACHE_SET_OPT(_name, _bits, _options, _sb_opt, _perm)	\
	if (src._name >= 0)					\
		dst->_name = src._name;

	CACHE_SET_OPTS()
#undef CACHE_SET_OPT
}

int bch_parse_options(struct cache_set_opts *, int, char *);

#endif /* _BCACHE_OPTS_H */
