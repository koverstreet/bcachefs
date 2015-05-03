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

#include "bcache.h"
#include "alloc.h"
#include "bset.h"
#include "debug.h"
#include "six.h"
#include "journal_types.h"

struct open_bucket;

extern const char *bch_btree_id_names[BTREE_ID_NR];

struct btree_write {
	unsigned			index;
	bool				have_pin;
	struct journal_entry_pin	journal;
};

struct btree {
	/* Hottest entries first */
	struct rhash_head	hash;

	/* Key/pointer for this btree node */
	BKEY_PADDED(key);

	/* Single bit - set when accessed, cleared by shrinker */
	unsigned long		accessed;

	struct six_lock		lock;

	unsigned long		flags;
	u16			written;	/* would be nice to kill */
	u8			level;
	u8			btree_id;

	struct btree_keys	keys;
	struct btree_node	*data;

	struct cache_set	*c;

	struct open_bucket	*ob;

	/* lru list */
	struct list_head	list;

	/* For outstanding btree writes, used as a lock - protects write_idx */
	struct closure		io;
	struct semaphore	io_mutex;
	struct delayed_work	work;

	struct btree_write	writes[2];
	struct bio		*bio;

	struct list_head	journal_seq_blacklisted;
};

#define BTREE_FLAG(flag)						\
static inline bool btree_node_ ## flag(struct btree *b)			\
{	return test_bit(BTREE_NODE_ ## flag, &b->flags); }		\
									\
static inline void set_btree_node_ ## flag(struct btree *b)		\
{	set_bit(BTREE_NODE_ ## flag, &b->flags); }			\
									\
static inline void clear_btree_node_ ## flag(struct btree *b)		\
{	clear_bit(BTREE_NODE_ ## flag, &b->flags); }

enum btree_flags {
	BTREE_NODE_io_error,
	BTREE_NODE_dirty,
	BTREE_NODE_write_idx,
	BTREE_NODE_need_init_next,
};

BTREE_FLAG(io_error);
BTREE_FLAG(dirty);
BTREE_FLAG(write_idx);
BTREE_FLAG(need_init_next);

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

static inline unsigned bset_byte_offset(struct btree *b, void *i)
{
	return i - (void *) b->data;
}

static inline size_t btree_bytes(struct cache_set *c)
{
	return c->btree_pages * PAGE_SIZE;
}

static inline unsigned btree_sectors(struct cache_set *c)
{
	return c->btree_pages << (PAGE_SHIFT - 9);
}

static inline unsigned btree_blocks(struct cache_set *c)
{
	return btree_sectors(c) >> c->block_bits;
}

static inline size_t bch_btree_keys_u64s_remaining(struct btree *b)
{
	struct bset *i = btree_bset_last(b);

	BUG_ON((PAGE_SIZE << b->keys.page_order) <
	       (bset_byte_offset(b, i) + set_bytes(i)));

	if (!b->keys.last_set_unwritten) {
		BUG_ON(b->written < btree_blocks(b->c));
		return 0;
	}

	return ((PAGE_SIZE << b->keys.page_order) -
		(bset_byte_offset(b, i) + set_bytes(i))) /
		sizeof(u64);
}

#define for_each_cached_btree(_b, _c, _tbl, _iter, _pos)		\
	for ((_tbl) = rht_dereference_rcu((_c)->btree_cache_table.tbl,	\
					  &(_c)->btree_cache_table),	\
	     _iter = 0;	_iter < (_tbl)->size; _iter++)			\
		rht_for_each_entry_rcu((_b), (_pos), _tbl, _iter, hash)

#define BTREE_MAX_DEPTH		4

struct btree_iter {
	struct closure		cl;

	/* Current btree depth */
	u8			level;

	/*
	 * Used in bch_btree_iter_traverse(), to indicate whether we're
	 * searching for @pos or the first key strictly greater than @pos
	 */
	u8			is_extents;

	/* Bitmasks for read/intent locks held per level */
	u8			nodes_locked;
	u8			nodes_intent_locked;

	/* Btree level below which we start taking intent locks */
	s8			locks_want;

	enum btree_id		btree_id:8;

	s8			error;

	struct cache_set	*c;

	/* Current position of the iterator */
	struct bpos		pos;

	u32			lock_seq[BTREE_MAX_DEPTH];

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

	/*
	 * Current unpacked key - so that bch_btree_iter_next()/
	 * bch_btree_iter_next_with_holes() can correctly advance pos.
	 */
	struct bkey_tup		tup;
};

static inline bool btree_node_locked(struct btree_iter *iter, unsigned level)
{
	return iter->nodes_locked & (1 << level);
}

static inline void mark_btree_node_unlocked(struct btree_iter *iter,
					    unsigned level)
{
	iter->nodes_locked &= ~(1 << level);
	iter->nodes_intent_locked &= ~(1 << level);
}

int bch_btree_iter_unlock(struct btree_iter *);
void __bch_btree_iter_init(struct btree_iter *, struct cache_set *,
			   enum btree_id, struct bpos, int);

static inline void bch_btree_iter_init(struct btree_iter *iter,
				       struct cache_set *c,
				       enum btree_id btree_id,
				       struct bpos pos)
{
	__bch_btree_iter_init(iter, c, btree_id, pos, -1);
}

static inline void bch_btree_iter_init_intent(struct btree_iter *iter,
					      struct cache_set *c,
					      enum btree_id btree_id,
					      struct bpos pos)
{
	__bch_btree_iter_init(iter, c, btree_id, pos, 0);
}

struct btree *bch_btree_iter_peek_node(struct btree_iter *);
struct btree *bch_btree_iter_next_node(struct btree_iter *);

struct bkey_s_c bch_btree_iter_peek(struct btree_iter *);
struct bkey_s_c bch_btree_iter_peek_with_holes(struct btree_iter *);
void bch_btree_iter_set_pos(struct btree_iter *, struct bpos);
void bch_btree_iter_advance_pos(struct btree_iter *);
bool bch_btree_iter_upgrade(struct btree_iter *);

static inline struct bpos __bch_btree_iter_advance_pos(struct btree_iter *iter,
						       struct bpos pos)
{
	if (iter->btree_id == BTREE_ID_INODES) {
		pos.inode++;
		pos.offset = 0;
	} else if (iter->btree_id != BTREE_ID_EXTENTS) {
		pos = bkey_successor(pos);
	}

	return pos;
}

static inline void __btree_iter_node_set(struct btree_iter *iter,
					 struct btree *b,
					 struct bpos pos)
{
	iter->lock_seq[b->level] = b->lock.state.seq;
	iter->nodes[b->level] = b;
	bch_btree_node_iter_init(&iter->node_iters[b->level], &b->keys,
				 pos, iter->is_extents);
}

static inline void btree_iter_node_set(struct btree_iter *iter, struct btree *b)
{
	__btree_iter_node_set(iter, b, iter->pos);
}

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
	     ((_k) = bch_btree_iter_peek(_iter)).k;			\
	     bch_btree_iter_advance_pos(_iter))

#define for_each_btree_key(_iter, _c, _btree_id,  _start, _k)		\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, -1)

#define for_each_btree_key_intent(_iter, _c, _btree_id,  _start, _k)	\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, 0)

#define __for_each_btree_key_with_holes(_iter, _c, _btree_id,		\
					_start, _k, _locks_want)	\
	for (__bch_btree_iter_init((_iter), (_c), (_btree_id),		\
				   _start, _locks_want);		\
	     ((_k) = bch_btree_iter_peek_with_holes(_iter)).k;		\
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

void btree_node_free(struct cache_set *, struct btree *);

void bch_btree_node_write(struct btree *, struct closure *,
			  struct btree_iter *);
void bch_btree_node_read_done(struct cache_set *, struct btree *,
			      struct cache *, const struct bch_extent_ptr *);
void bch_btree_flush(struct cache_set *);
void bch_btree_push_journal_seq(struct cache_set *, struct btree *,
				struct closure *);

/**
 * btree_node_format_fits - check if we could rewrite node with a new format
 *
 * This assumes all keys can pack with the new format -- it just checks if
 * the re-packed keys would fit inside the node itself.
 */
static inline bool btree_node_format_fits(struct btree *b,
					  struct bkey_format *new_f)
{
	struct bkey_format *old_f = &b->keys.format;

	/* stupid integer promotion rules */
	ssize_t new_u64s =
	    (((int) new_f->key_u64s - old_f->key_u64s) *
	     (int) b->keys.nr.packed_keys) +
	    (((int) new_f->key_u64s - BKEY_U64s) *
	     (int) b->keys.nr.unpacked_keys);

	bch_verify_btree_nr_keys(&b->keys);

	BUG_ON(new_u64s + b->keys.nr.live_u64s < 0);

	return __set_bytes(b->data, b->keys.nr.live_u64s + new_u64s) <
		PAGE_SIZE << b->keys.page_order;
}

void __bch_btree_calc_format(struct bkey_format_state *, struct btree *);

#define BTREE_RESERVE_MAX						\
	(btree_reserve_required_nodes(BTREE_MAX_DEPTH) + GC_MERGE_NODES)

struct btree_reserve {
	unsigned		nr;
	struct btree		*b[];
};

#define BTREE_RESERVE_SIZE						\
	(sizeof(struct btree_reserve) +					\
	 sizeof(struct btree *) * BTREE_RESERVE_MAX)

void bch_btree_reserve_put(struct cache_set *, struct btree_reserve *);
struct btree_reserve *bch_btree_reserve_get(struct cache_set *c,
					    struct btree *,
					    struct btree_iter *,
					    unsigned, bool);

static inline void btree_open_bucket_put(struct cache_set *c, struct btree *b)
{
	bch_open_bucket_put(c, b->ob);
	b->ob = NULL;
}

struct btree *__btree_node_alloc_replacement(struct cache_set *,
					     struct btree *,
					     struct bkey_format,
					     struct btree_reserve *);
struct btree *btree_node_alloc_replacement(struct cache_set *, struct btree *,
					   struct btree_reserve *);

int bch_btree_root_alloc(struct cache_set *, enum btree_id, struct closure *);
int bch_btree_root_read(struct cache_set *, enum btree_id,
			const struct bkey_i *, unsigned);

void bch_btree_insert_and_journal(struct cache_set *, struct btree *,
				  struct btree_node_iter *,
				  struct bkey_i *,
				  struct journal_res *);

struct bch_replace_info;

int bch_btree_insert_node(struct btree *, struct btree_iter *,
			  struct keylist *, struct bch_replace_info *,
			  u64 *, unsigned, struct btree_reserve *);

/*
 * Don't drop/retake locks: instead return -EINTR if need to upgrade to intent
 * locks, -EAGAIN if need to wait on btree reserve
 */
#define BTREE_INSERT_ATOMIC		(1 << 0)

/* Don't check for -ENOSPC: */
#define BTREE_INSERT_NOFAIL		(1 << 1)

/*
 * Fail a btree insert if dirty stale pointers are being added
 *
 * Needs to be set for compare exchange and device removal, and not
 * set for journal replay. See big comment in bch_insert_fixup_extent()
 */
#define FAIL_IF_STALE			(1 << 2)

int bch_btree_insert_at(struct btree_iter *, struct keylist *,
			struct bch_replace_info *, u64 *, unsigned);
int bch_btree_insert_check_key(struct btree_iter *, struct bkey_i *);
int bch_btree_insert(struct cache_set *, enum btree_id, struct keylist *,
		     struct bch_replace_info *, struct closure *,
		     u64 *, int flags);
int bch_btree_update(struct cache_set *, enum btree_id, struct bkey_i *,
		     struct closure *, u64 *);

int bch_btree_node_rewrite(struct btree *, struct btree_iter *, bool);

void bch_btree_cache_free(struct cache_set *);
int bch_btree_cache_alloc(struct cache_set *);

#endif
