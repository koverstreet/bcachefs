#ifndef _BCACHE_OPTS_H
#define _BCACHE_OPTS_H

#include <linux/bug.h>
#include <linux/log2.h>
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
extern const char * const bch_uint_opt[];
extern const char * const bch_error_actions[];
extern const char * const bch_csum_types[];
extern const char * const bch_compression_types[];
extern const char * const bch_str_hash_types[];

/* dummy option, for options that aren't stored in the superblock */
LE64_BITMASK(NO_SB_OPT,		struct cache_sb, flags, 0, 0);

#define CACHE_SET_VISIBLE_OPTS()				\
	CACHE_SET_OPT(verbose_recovery,				\
		      bch_bool_opt, 2,				\
		      NO_SB_OPT, false)				\
	CACHE_SET_OPT(posix_acl,				\
		      bch_bool_opt, 2,				\
		      NO_SB_OPT, false)				\
	CACHE_SET_OPT(journal_flush_disabled,			\
		      bch_bool_opt, 2,				\
		      NO_SB_OPT, true)				\
	CACHE_SET_SB_OPTS()

#define CACHE_SET_OPTS()					\
	CACHE_SET_OPT(read_only,				\
		      bch_bool_opt, 2,				\
		      NO_SB_OPT, 0)				\
	CACHE_SET_VISIBLE_OPTS()

struct cache_set_opts {
#define CACHE_SET_OPT(_name, _opts, _nr_opts, _sb_opt, _perm)	\
	s8 _name;

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
#define CACHE_SET_OPT(_name, _options, _nr_opts, _sb_opt, _perm)\
		._name = _sb_opt##_BITS ? _sb_opt(sb) : 0,

	CACHE_SET_OPTS()
#undef CACHE_SET_OPT
	};
}

static inline void cache_set_opts_apply(struct cache_set_opts *dst,
					struct cache_set_opts src)
{
#define CACHE_SET_OPT(_name, _options, _nr_opts, _sb_opt, _perm)\
	BUILD_BUG_ON(_nr_opts > S8_MAX);			\
	if (src._name >= 0)					\
		dst->_name = src._name;

	CACHE_SET_OPTS()
#undef CACHE_SET_OPT
}

int bch_parse_options(struct cache_set_opts *, int, char *);

#endif /* _BCACHE_OPTS_H */
