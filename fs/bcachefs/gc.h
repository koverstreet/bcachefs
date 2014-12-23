#ifndef _BCACHE_GC_H
#define _BCACHE_GC_H

static inline void set_gc_sectors(struct cache_set *c)
{
	atomic64_set(&c->sectors_until_gc, c->capacity / 16);
}

void bch_gc(struct cache_set *);
int bch_gc_thread_start(struct cache_set *);
int bch_initial_gc(struct cache_set *, struct list_head *);
u8 bch_btree_mark_last_gc(struct cache_set *, struct bkey *);
u8 __bch_btree_mark_key(struct cache_set *, int, struct bkey *);

bool btree_gc_mark_node(struct cache_set *, struct btree *,
			struct gc_stat *);

/**
 * __gc_will_visit_node - for checking GC marks while holding a btree read lock
 *
 * Since btree GC takes intent locks, it might advance the current key, so in
 * this case the entire reading of the mark has to be surrounded with the
 * seqlock.
 */
static inline bool __gc_will_visit_node(struct cache_set *c,
					struct btree *b)
{
	return b->btree_id != c->gc_cur_btree
		? b->btree_id > c->gc_cur_btree
		: bkey_cmp(&b->key, &c->gc_cur_key)
		? bkey_cmp(&b->key, &c->gc_cur_key) > 0
		: b->level > c->gc_cur_level;
}

/**
 * gc_will_visit_key - is the currently-running GC pass going to visit the given
 * btree node?
 *
 * If so, we don't have to update reference counts for buckets this key points
 * into -- the GC will do it before the current pass ends.
 */
static inline bool gc_will_visit_node(struct cache_set *c,
				      struct btree *b)
{
	unsigned seq;
	bool ret;

	do {
		seq = read_seqbegin(&c->gc_cur_lock);
		ret = __gc_will_visit_node(c, b);
	} while (read_seqretry(&c->gc_cur_lock, seq));

	return ret;
}

#endif
