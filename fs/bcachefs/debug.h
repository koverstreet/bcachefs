#ifndef _BCACHE_DEBUG_H
#define _BCACHE_DEBUG_H

struct bio;
struct btree;
struct cached_dev;
struct cache_set;

#ifdef CONFIG_BCACHEFS_DEBUG

void bch_btree_verify(struct cache_set *, struct btree *);
void bch_data_verify(struct cached_dev *, struct bio *);
void bch_verify_inode_refs(struct cache_set *);

#define expensive_debug_checks(c)	((c)->expensive_debug_checks)
#define key_merging_disabled(c)		((c)->key_merging_disabled)
#define bypass_torture_test(d)		((d)->bypass_torture_test)

#else /* DEBUG */

static inline void bch_btree_verify(struct cache_set *c, struct btree *b) {}
static inline void bch_data_verify(struct cached_dev *dc, struct bio *bio) {}
static inline void bch_verify_inode_refs(struct cache_set *c) {}

#define expensive_debug_checks(c)	0
#define key_merging_disabled(c)		0
#define bypass_torture_test(d)		0

#endif

#ifdef CONFIG_DEBUG_FS
void bch_debug_exit_cache_set(struct cache_set *);
void bch_debug_init_cache_set(struct cache_set *);
#else
static inline void bch_debug_exit_cache_set(struct cache_set *c) {}
static inline void bch_debug_init_cache_set(struct cache_set *c) {}
#endif

#endif
