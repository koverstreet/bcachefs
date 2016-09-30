#ifndef _BCACHE_OPTS_H
#define _BCACHE_OPTS_H

#include <linux/bug.h>
#include <linux/log2.h>
#include <linux/string.h>
#include "bcachefs_format.h"

extern const char * const bch_error_actions[];
extern const char * const bch_csum_types[];
extern const char * const bch_compression_types[];
extern const char * const bch_str_hash_types[];
extern const char * const bch_cache_replacement_policies[];
extern const char * const bch_cache_modes[];
extern const char * const bch_cache_state[];

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
extern const char * const bch_uint_opt[];

/* dummy option, for options that aren't stored in the superblock */
LE64_BITMASK(NO_SB_OPT,		struct bch_sb, flags[0], 0, 0);

#define BCH_VISIBLE_OPTS()					\
	BCH_OPT(verbose_recovery,				\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, false)				\
	BCH_OPT(posix_acl,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, false)				\
	BCH_OPT(journal_flush_disabled,				\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, true)				\
	BCH_OPT(nofsck,						\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, true)				\
	BCH_OPT(fix_errors,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, true)				\
	BCH_OPT(nochanges,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, 0)					\
	BCH_OPT(noreplay,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, 0)					\
	BCH_OPT(norecovery,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, 0)					\
	BCH_SB_OPTS()

#define BCH_OPTS()						\
	BCH_OPT(read_only,					\
		bch_bool_opt, 0, 2,				\
		NO_SB_OPT, 0)					\
	BCH_VISIBLE_OPTS()

struct cache_set_opts {
#define BCH_OPT(_name, _choices, _min, _max, _sb_opt, _perm)\
	s8 _name;

	BCH_OPTS()
#undef BCH_OPT
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
static inline struct cache_set_opts cache_superblock_opts(struct bch_sb *sb)
{
	return (struct cache_set_opts) {
#define BCH_OPT(_name, _choices, _min, _max, _sb_opt, _perm)\
		._name = _sb_opt##_BITS ? _sb_opt(sb) : 0,

	BCH_SB_OPTS()
#undef BCH_OPT
	};
}

static inline void cache_set_opts_apply(struct cache_set_opts *dst,
					struct cache_set_opts src)
{
#define BCH_OPT(_name, _choices, _min, _max, _sb_opt, _perm)\
	BUILD_BUG_ON(_max > S8_MAX);				\
	if (src._name >= 0)					\
		dst->_name = src._name;

	BCH_SB_OPTS()
#undef BCH_OPT
}

int bch_parse_options(struct cache_set_opts *, int, char *);

#endif /* _BCACHE_OPTS_H */
