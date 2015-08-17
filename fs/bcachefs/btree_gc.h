#ifndef _BCACHE_GC_H
#define _BCACHE_GC_H

#include "btree_types.h"

void bch_gc(struct cache_set *);
void bch_gc_thread_stop(struct cache_set *);
int bch_gc_thread_start(struct cache_set *);
int bch_initial_gc(struct cache_set *, struct list_head *);
u8 bch_btree_key_recalc_oldest_gen(struct cache_set *, struct bkey_s_c);
void __bch_btree_mark_key(struct cache_set *, int, struct bkey_s_c);

/*
 * For concurrent mark and sweep (with other index updates), we define a total
 * ordering of _all_ references GC walks:
 *
 * Note that some references will have the same GC position as others - e.g.
 * everything within the same btree node; in those cases we're relying on
 * whatever locking exists for where those references live, i.e. the write lock
 * on a btree node.
 *
 * That locking is also required to ensure GC doesn't pass the updater in
 * between the updater adding/removing the reference and updating the GC marks;
 * without that, we would at best double count sometimes.
 *
 * That part is important - whenever calling bch_mark_pointers(), a lock _must_
 * be held that prevents GC from passing the position the updater is at.
 *
 * (What about the start of gc, when we're clearing all the marks? GC clears the
 * mark with the gc pos seqlock held, and bch_mark_bucket checks against the gc
 * position inside its cmpxchg loop, so crap magically works).
 */

/* Position of (the start of) a gc phase: */
static inline struct gc_pos gc_phase(enum gc_phase phase)
{
	return (struct gc_pos) {
		.phase	= phase,
		.pos	= POS_MIN,
		.level	= 0,
	};
}

#define GC_POS_MIN	gc_phase(0)

static inline int gc_pos_cmp(struct gc_pos l, struct gc_pos r)
{
	if (l.phase != r.phase)
		return l.phase < r.phase ? -1 : 1;
	if (bkey_cmp(l.pos, r.pos))
		return bkey_cmp(l.pos, r.pos);
	if (l.level != r.level)
		return l.level < r.level ? -1 : 1;
	return 0;
}

/*
 * GC position of the pointers within a btree node: note, _not_ for &b->key
 * itself, that lives in the parent node:
 */
static inline struct gc_pos gc_pos_btree_node(struct btree *b)
{
	return (struct gc_pos) {
		.phase	= b->btree_id,
		.pos	= b->key.k.p,
		.level	= b->level,
	};
}

/*
 * GC position of the pointer to a btree root: we don't use
 * gc_pos_pointer_to_btree_node() here to avoid a potential race with
 * btree_split() increasing the tree depth - the new root will have level > the
 * old root and thus have a greater gc position than the old root, but that
 * would be incorrect since once gc has marked the root it's not coming back.
 */
static inline struct gc_pos gc_pos_btree_root(enum btree_id id)
{
	return (struct gc_pos) {
		.phase	= id,
		.pos	= POS_MAX,
		.level	= U8_MAX,
	};
}

static inline bool gc_will_visit(struct cache_set *c, struct gc_pos pos)
{
	unsigned seq;
	bool ret;

	do {
		seq = read_seqcount_begin(&c->gc_pos_lock);
		ret = gc_pos_cmp(c->gc_pos, pos) < 0;
	} while (read_seqcount_retry(&c->gc_pos_lock, seq));

	return ret;
}

#endif
