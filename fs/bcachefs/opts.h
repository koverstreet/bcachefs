#ifndef _BCACHE_OPTS_H
#define _BCACHE_OPTS_H

/*
 * We store options as signed integers, where -1 means undefined. This means we
 * can pass the mount options to cache_set_alloc() as a whole struct, and then
 * only apply the options from that struct that are defined.
 */

#define CACHE_SET_OPTS()				\
	DEF_CACHE_SET_OPT(read_only, 2)			\
	DEF_CACHE_SET_OPT(on_error_action, 3)		\
	DEF_CACHE_SET_OPT(meta_csum_type, 4)		\
	DEF_CACHE_SET_OPT(data_csum_type, 4)		\
	DEF_CACHE_SET_OPT(compression_type, 4)		\
	DEF_CACHE_SET_OPT(verbose_recovery, 2)		\
	DEF_CACHE_SET_OPT(posix_acl, 2)

struct cache_set_opts {
#define DEF_CACHE_SET_OPT(opt, bits)	int opt:bits;
	CACHE_SET_OPTS()
#undef DEF_CACHE_SET_OPT
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
		   .read_only = 0,
		   .on_error_action	= CACHE_ERROR_ACTION(sb),
		   .meta_csum_type	= CACHE_META_PREFERRED_CSUM_TYPE(sb),
		   .data_csum_type	= CACHE_DATA_PREFERRED_CSUM_TYPE(sb),
		   .compression_type	= CACHE_COMPRESSION_TYPE(sb),
		   .verbose_recovery = 0,
	};
}

static inline void cache_set_opts_apply(struct cache_set_opts *dst,
					struct cache_set_opts src)
{
#define DEF_CACHE_SET_OPT(opt, bits)			\
	if (src.opt >= 0)				\
		dst->opt = src.opt;

	CACHE_SET_OPTS()
#undef DEF_CACHE_SET_OPT
}

#endif /* _BCACHE_OPTS_H */
