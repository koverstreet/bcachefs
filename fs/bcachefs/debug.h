#ifndef _BCACHE_DEBUG_H
#define _BCACHE_DEBUG_H

#include "bcache.h"

struct bio;
struct btree;
struct cached_dev;
struct cache_set;

#define BCH_DEBUG_PARAM(name, description) extern bool bch_##name;
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

#define BCH_DEBUG_PARAM(name, description)				\
	static inline bool name(struct cache_set *c)			\
	{ return bch_##name || c->name;	}
BCH_DEBUG_PARAMS_ALWAYS()
#undef BCH_DEBUG_PARAM

#ifdef CONFIG_BCACHEFS_DEBUG

#define BCH_DEBUG_PARAM(name, description)				\
	static inline bool name(struct cache_set *c)			\
	{ return bch_##name || c->name;	}
BCH_DEBUG_PARAMS_DEBUG()
#undef BCH_DEBUG_PARAM

void __bch_btree_verify(struct cache_set *, struct btree *);
void bch_data_verify(struct cached_dev *, struct bio *);

#define bypass_torture_test(d)		((d)->bypass_torture_test)

#else /* DEBUG */

#define BCH_DEBUG_PARAM(name, description)				\
	static inline bool name(struct cache_set *c) { return false; }
BCH_DEBUG_PARAMS_DEBUG()
#undef BCH_DEBUG_PARAM

static inline void __bch_btree_verify(struct cache_set *c, struct btree *b) {}
static inline void bch_data_verify(struct cached_dev *dc, struct bio *bio) {}

#define bypass_torture_test(d)		0

#endif

static inline void bch_btree_verify(struct cache_set *c, struct btree *b)
{
	if (verify_btree_ondisk(c))
		__bch_btree_verify(c, b);
}

#ifdef CONFIG_DEBUG_FS
void bch_debug_exit_cache_set(struct cache_set *);
void bch_debug_init_cache_set(struct cache_set *);
#else
static inline void bch_debug_exit_cache_set(struct cache_set *c) {}
static inline void bch_debug_init_cache_set(struct cache_set *c) {}
#endif

#endif
