#ifndef _BCACHE_GC_H
#define _BCACHE_GC_H

#include "btree_types.h"

void bch_gc(struct cache_set *);
void bch_gc_thread_stop(struct cache_set *);
int bch_gc_thread_start(struct cache_set *);
int bch_initial_gc(struct cache_set *, struct list_head *);
u8 bch_btree_key_recalc_oldest_gen(struct cache_set *, struct bkey_s_c);
void __bch_btree_mark_key(struct cache_set *, int, struct bkey_s_c);

bool btree_gc_mark_node(struct cache_set *, struct btree *);

static inline bool __gc_will_visit(struct cache_set *c, enum gc_phase phase,
				   struct bpos pos, unsigned level)
{
	return phase != c->gc_cur_phase
		? phase > c->gc_cur_phase
		: bkey_cmp(pos, c->gc_cur_pos)
		? bkey_cmp(pos, c->gc_cur_pos) > 0
		: level > c->gc_cur_level;
}

static inline bool gc_will_visit(struct cache_set *c, enum gc_phase phase,
				 struct bpos pos, unsigned level)
{
	unsigned seq;
	bool ret;

	do {
		seq = read_seqcount_begin(&c->gc_cur_lock);
		ret = __gc_will_visit(c, phase, pos, level);
	} while (read_seqcount_retry(&c->gc_cur_lock, seq));

	return ret;
}

/**
 * __gc_will_visit_node - for checking GC marks while holding a btree read lock
 *
 * Since btree GC takes intent locks, it might advance the current key, so in
 * this case the entire reading of the mark has to be surrounded with the
 * seqlock.
 */
static inline bool __gc_will_visit_node(struct cache_set *c, struct btree *b)
{
	return __gc_will_visit(c, b->btree_id, b->key.k.p, b->level);
}

/**
 * gc_will_visit_key - is the currently-running GC pass going to visit the given
 * btree node?
 *
 * If so, we don't have to update reference counts for buckets this key points
 * into -- the GC will do it before the current pass ends.
 */
static inline bool gc_will_visit_node(struct cache_set *c, struct btree *b)
{
	return gc_will_visit(c, b->btree_id, b->key.k.p, b->level);
}

static inline bool gc_will_visit_root(struct cache_set *c, enum btree_id id)
{
	return gc_will_visit(c, (int) id, POS_MAX, U8_MAX);
}

#endif
