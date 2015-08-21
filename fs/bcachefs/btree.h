#ifndef _BCACHE_BTREE_H
#define _BCACHE_BTREE_H

/*
 * THE BTREE:
 *
 * At a high level, bcache's btree is relatively standard b+ tree. All keys and
 * pointers are in the leaves; interior nodes only have pointers to the child
 * nodes.
 *
 * In the interior nodes, a struct bkey always points to a child btree node, and
 * the key is the highest key in the child node - except that the highest key in
 * an interior node is always MAX_KEY. The size field refers to the size on disk
 * of the child node - this would allow us to have variable sized btree nodes
 * (handy for keeping the depth of the btree 1 by expanding just the root).
 *
 * Btree nodes are themselves log structured, but this is hidden fairly
 * thoroughly. Btree nodes on disk will in practice have extents that overlap
 * (because they were written at different times), but in memory we never have
 * overlapping extents - when we read in a btree node from disk, the first thing
 * we do is resort all the sets of keys with a mergesort, and in the same pass
 * we check for overlapping extents and adjust them appropriately.
 *
 * struct btree_op is a central interface to the btree code. It's used for
 * specifying read vs. write locking, and the embedded closure is used for
 * waiting on IO or reserve memory.
 *
 * BTREE CACHE:
 *
 * Btree nodes are cached in memory; traversing the btree might require reading
 * in btree nodes which is handled mostly transparently.
 *
 * bch_btree_node_get() looks up a btree node in the cache and reads it in from
 * disk if necessary. This function is almost never called directly though - the
 * btree() macro is used to get a btree node, call some function on it, and
 * unlock the node after the function returns.
 *
 * The root is special cased - it's taken out of the cache's lru (thus pinning
 * it in memory), so we can find the root of the btree by just dereferencing a
 * pointer instead of looking it up in the cache. This makes locking a bit
 * tricky, since the root pointer is protected by the lock in the btree node it
 * points to - the btree_root() macro handles this.
 *
 * In various places we must be able to allocate memory for multiple btree nodes
 * in order to make forward progress. To do this we use the btree cache itself
 * as a reserve; if __get_free_pages() fails, we'll find a node in the btree
 * cache we can reuse. We can't allow more than one thread to be doing this at a
 * time, so there's a lock, implemented by a pointer to the btree_op closure -
 * this allows the btree_root() macro to implicitly release this lock.
 *
 * BTREE IO:
 *
 * Btree nodes never have to be explicitly read in; bch_btree_node_get() handles
 * this.
 *
 * For writing, we have two btree_write structs embeddded in struct btree - one
 * write in flight, and one being set up, and we toggle between them.
 *
 * LOCKING:
 *
 * When traversing the btree, we may need write locks starting at some level -
 * inserting a key into the btree will typically only require a write lock on
 * the leaf node.
 *
 * This is specified with the lock field in struct btree_op; lock = 0 means we
 * take write locks at level <= 0, i.e. only leaf nodes. bch_btree_node_get()
 * checks this field and returns the node with the appropriate lock held.
 *
 * If, after traversing the btree, the insertion code discovers it has to split
 * then it must restart from the root and take new locks - to do this it changes
 * the lock field and returns -EINTR, which causes the btree_root() macro to
 * loop.
 *
 * Handling cache misses require a different mechanism for upgrading to a write
 * lock. We do cache lookups with only a read lock held, but if we get a cache
 * miss and we wish to insert this data into the cache, we have to insert a
 * placeholder key to detect races - otherwise, we could race with a write and
 * overwrite the data that was just written to the cache with stale data from
 * the backing device.
 *
 * For this we use a sequence number that write locks and unlocks increment - to
 * insert the check key it unlocks the btree node and then takes a write lock,
 * and fails if the sequence number doesn't match.
 */

#include "bset.h"
#include "debug.h"
#include "six.h"

struct btree_write {
	atomic_t		*journal;
};

struct btree {
	/* Hottest entries first */
	struct rhash_head	hash;

	/* Key/pointer for this btree node */
	BKEY_PADDED(key);

	/* Single bit - set when accessed, cleared by shrinker */
	unsigned long		accessed;

	struct six_lock		lock;

	struct cache_set	*c;
	struct btree		*parent;

	unsigned long		flags;
	u16			written;	/* would be nice to kill */
	u8			level;
	u8			btree_id;

	struct btree_keys	keys;

	/* For outstanding btree writes, used as a lock - protects write_idx */
	struct closure		io;
	struct semaphore	io_mutex;

	struct list_head	list;
	struct delayed_work	work;

	struct btree_write	writes[2];
	struct bio		*bio;
};

#define BTREE_FLAG(flag)						\
static inline bool btree_node_ ## flag(struct btree *b)			\
{	return test_bit(BTREE_NODE_ ## flag, &b->flags); }		\
									\
static inline void set_btree_node_ ## flag(struct btree *b)		\
{	set_bit(BTREE_NODE_ ## flag, &b->flags); }			\

enum btree_flags {
	BTREE_NODE_io_error,
	BTREE_NODE_dirty,
	BTREE_NODE_write_idx,
};

BTREE_FLAG(io_error);
BTREE_FLAG(dirty);
BTREE_FLAG(write_idx);

static inline struct btree_write *btree_current_write(struct btree *b)
{
	return b->writes + btree_node_write_idx(b);
}

static inline struct btree_write *btree_prev_write(struct btree *b)
{
	return b->writes + (btree_node_write_idx(b) ^ 1);
}

static inline struct bset *btree_bset_first(struct btree *b)
{
	return b->keys.set->data;
}

static inline struct bset *btree_bset_last(struct btree *b)
{
	return bset_tree_last(&b->keys)->data;
}

static inline unsigned bset_block_offset(struct btree *b, struct bset *i)
{
	return bset_sector_offset(&b->keys, i) >> b->c->block_bits;
}

static inline void set_gc_sectors(struct cache_set *c)
{
	atomic64_set(&c->sectors_until_gc, c->capacity / 16);
}

static inline size_t btree_bytes(struct cache_set *c)
{
	return c->btree_pages * PAGE_SIZE;
}

static inline unsigned btree_sectors(struct cache_set *c)
{
	return c->btree_pages * PAGE_SECTORS;
}

static inline unsigned btree_blocks(struct cache_set *c)
{
	return btree_sectors(c) >> c->block_bits;
}

/* Looping macros */

#define for_each_cached_btree(_b, _c, _tbl, _iter, _pos)		\
	for ((_tbl) = rht_dereference_rcu((_c)->btree_cache_table.tbl,	\
					  &(_c)->btree_cache_table),	\
	     _iter = 0;	_iter < (_tbl)->size; _iter++)			\
		rht_for_each_entry_rcu((_b), (_pos), _tbl, _iter, hash)

/* Recursing down the btree */

#define BTREE_MAX_DEPTH		4

struct btree_op {
	struct closure		cl;

	/*
	 * Sequence number of the corresponding btree node's six lock. Used so
	 * that we can unlock, and then relock later iff the btree node hasn't
	 * been modified in the meantime.
	 */
	u32			lock_seq[BTREE_MAX_DEPTH];

	/* Bitmasks for read/intent locks held per level */
	u8			nodes_locked;
	u8			nodes_intent_locked;

	/* Btree level below which we start taking intent locks */
	s8			locks_want;

	enum btree_id		id:8;

	unsigned		iterator_invalidated:1;

	/* State used by btree insertion is also stored here for convenience */
	unsigned		insert_collision:1;
};

/**
 * __bch_btree_op_init - initialize btree op
 *
 * @write_lock_level: -1 for read locks only
 *                    0 for write lock on leaf
 *                    SHRT_MAX for write locks only
 *
 * Does not initialize @op->cl -- you must do that yourself.
 */
static inline void __bch_btree_op_init(struct btree_op *op, enum btree_id id,
					int write_lock_level)
{
	op->id = id;
	op->locks_want = write_lock_level;
	op->iterator_invalidated = 0;
	op->insert_collision = 0;
}

/**
 * bch_btree_op_init - initialize synchronous btree op
 */
static inline void bch_btree_op_init(struct btree_op *op, enum btree_id id,
				     int write_lock_level)
{
	closure_init_stack(&op->cl);
	__bch_btree_op_init(op, id, write_lock_level);
}

struct btree_iter {
	struct btree_op		op;

	/* Current btree depth */
	u8			level;

	/*
	 * Used in bch_btree_iter_traverse(), to indicate whether we're
	 * searching for @pos or the first key strictly greater than @pos
	 */
	u8			is_extents;

	s8			error;

	struct cache_set	*c;

	/* Current position of the iterator */
	struct bkey		pos;

	/*
	 * Previous key returned - so that bch_btree_iter_next()/
	 * bch_btree_iter_next_with_holes() can correctly advance pos.
	 *
	 * NOTE: KEY_DELETED(&iter->k) is used to remember whether or not the
	 * previous key returned was a hole, so bch_btree_iter_advance_pos()
	 * knows whether or not to advance the btree_node_iter.
	 */
	struct bkey		k;

	/*
	 * NOTE: Never set iter->nodes to NULL except in btree_iter_lock_root().
	 *
	 * This is because iter->nodes[iter->level] == NULL is how
	 * btree_iter_next_node() knows that it's finished with a depth first
	 * traversal. Just unlocking a node (with btree_node_unlock()) is fine,
	 * and if you really don't want that node used again (e.g. btree_split()
	 * freed it) decrementing lock_seq will cause btree_node_relock() to
	 * always fail (but since freeing a btree node takes a write lock on the
	 * node, which increments the node's lock seq, that's not actually
	 * necessary in that example).
	 *
	 * One extra slot for a sentinel NULL:
	 */
	struct btree		*nodes[BTREE_MAX_DEPTH + 1];

	struct btree_node_iter	node_iters[BTREE_MAX_DEPTH];
};

int bch_btree_iter_unlock(struct btree_iter *);
void __bch_btree_iter_init(struct btree_iter *, struct cache_set *,
			   enum btree_id, const struct bkey *, int);

static inline void bch_btree_iter_init(struct btree_iter *iter,
				       struct cache_set *c,
				       enum btree_id btree_id,
				       struct bkey *search)
{
	__bch_btree_iter_init(iter, c, btree_id, search, -1);
}

static inline void bch_btree_iter_init_intent(struct btree_iter *iter,
					      struct cache_set *c,
					      enum btree_id btree_id,
					      struct bkey *search)
{
	__bch_btree_iter_init(iter, c, btree_id, search, 0);
}

struct btree *bch_btree_iter_peek_node(struct btree_iter *);
struct btree *bch_btree_iter_next_node(struct btree_iter *);

const struct bkey *bch_btree_iter_peek(struct btree_iter *);
const struct bkey *bch_btree_iter_peek_with_holes(struct btree_iter *);
void bch_btree_iter_set_pos(struct btree_iter *, const struct bkey *);
void bch_btree_iter_advance_pos(struct btree_iter *);
bool bch_btree_iter_upgrade(struct btree_iter *);

#define for_each_btree_node(_iter, _c, _btree_id, _start, _b)		\
	for (bch_btree_iter_init((_iter), (_c), (_btree_id), _start),	\
	     (_iter)->is_extents = false,				\
	     _b = bch_btree_iter_peek_node(_iter);			\
	     (_b);							\
	     (_b) = bch_btree_iter_next_node(_iter))

#define __for_each_btree_key(_iter, _c, _btree_id,  _start,		\
			     _k, _locks_want)				\
	for (__bch_btree_iter_init((_iter), (_c), (_btree_id),		\
				   _start, _locks_want);		\
	     ((k) = bch_btree_iter_peek(_iter));			\
	     bch_btree_iter_advance_pos(_iter))

#define for_each_btree_key(_iter, _c, _btree_id,  _start, _k)		\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, -1)

#define for_each_btree_key_intent(_iter, _c, _btree_id,  _start, _k)	\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, 0)

#define __for_each_btree_key_with_holes(_iter, _c, _btree_id,		\
					_start, _k, _locks_want)	\
	for (__bch_btree_iter_init((_iter), (_c), (_btree_id),		\
				   _start, _locks_want);		\
	     ((_k) = bch_btree_iter_peek_with_holes(_iter));		\
	     bch_btree_iter_advance_pos(_iter))

#define for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k)	\
	__for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k, -1)

#define for_each_btree_key_with_holes_intent(_iter, _c, _btree_id,	\
					     _start, _k)		\
	__for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k, 0)

/*
 * Unlocks before scheduling
 * Note: does not revalidate iterator
 */
static inline void bch_btree_iter_cond_resched(struct btree_iter *iter)
{
	if (need_resched()) {
		bch_btree_iter_unlock(iter);
		schedule();
		bch_btree_iter_upgrade(iter);
	} else if (race_fault()) {
		bch_btree_iter_unlock(iter);
		bch_btree_iter_upgrade(iter);
	}
}

#define btree_node_root(_b)	((_b)->c->btree_roots[(_b)->btree_id])

void bch_btree_node_read_done(struct btree *, struct cache *, unsigned);
void bch_btree_flush(struct cache_set *);
void bch_btree_write_oldest(struct cache_set *);

int bch_btree_root_alloc(struct cache_set *, enum btree_id, struct closure *);
int bch_btree_root_read(struct cache_set *, enum btree_id,
			struct bkey *, unsigned);

struct bch_replace_info;

int bch_btree_insert_check_key(struct btree *, struct btree_op *,
			       struct bkey *);
int bch_btree_insert(struct cache_set *, enum btree_id, struct keylist *,
		     struct bch_replace_info *, struct closure *);
int bch_btree_insert_node(struct btree *, struct btree_op *, struct keylist *,
			  struct bch_replace_info *,
			  struct closure *, enum alloc_reserve);

int bch_gc_thread_start(struct cache_set *);
int bch_initial_gc(struct cache_set *, struct list_head *);
u8 bch_btree_mark_last_gc(struct cache_set *, struct bkey *);
u8 __bch_btree_mark_key(struct cache_set *, int, struct bkey *);

void bch_btree_cache_free(struct cache_set *);
int bch_btree_cache_alloc(struct cache_set *);

/* Return values from @fn parameter to map_keys and map_nodes */
#define MAP_DONE	0  /* We're done */
#define MAP_CONTINUE	1  /* Continue and advance the iterator */

/* Values for @flags parameter to map_nodes and map_keys */
#define MAP_HOLES	1  /* Only map_keys */
#define MAP_ASYNC	2
#define MAP_ALL_NODES	4  /* Meaningfull only for bch_btree_map_nodes */

typedef int (btree_map_nodes_fn)(struct btree_op *, struct btree *);
int bch_btree_map_nodes(struct btree_op *, struct cache_set *,
			struct bkey *, btree_map_nodes_fn *, int);

typedef int (btree_map_keys_fn)(struct btree_op *, struct btree *,
				struct bkey *);
int bch_btree_map_keys(struct btree_op *, struct cache_set *, struct bkey *,
		       btree_map_keys_fn *, int);

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

bool btree_move_node(struct btree *, struct btree_op *);

#endif
