#ifndef _BCACHE_BTREE_TYPES_H
#define _BCACHE_BTREE_TYPES_H

#include <linux/list.h>
#include <linux/rhashtable.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "bkey_methods.h"
#include "bset.h"
#include "journal_types.h"
#include "six.h"

struct cache_set;
struct open_bucket;
struct async_split;

struct btree_write {
	unsigned			index;
	bool				have_pin;
	struct journal_entry_pin	journal;
	struct closure_waitlist		wait;
};

struct btree_root {
	struct btree		*b;

	struct async_split	*as;

	/* On disk root - see async splits: */
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
	u8			level;
	u8			alive;
};

struct btree {
	/* Hottest entries first */
	struct rhash_head	hash;

	/* Key/pointer for this btree node */
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);

	/* Single bit - set when accessed, cleared by shrinker */
	unsigned long		accessed;

	struct six_lock		lock;

	unsigned long		flags;
	u16			written;	/* would be nice to kill */
	u8			level;
	u8			btree_id;

	/*
	 * For asynchronous splits/interior node updates:
	 * When we do a split, we allocate new child nodes and update the parent
	 * node to point to them: we update the parent in memory immediately,
	 * but then we must wait until the children have been written out before
	 * the update to the parent can be written - this is a list of the
	 * async_splits that are blocking this node from being written:
	 */
	struct list_head	write_blocked;

	struct btree_keys	keys;
	struct btree_node	*data;

	struct cache_set	*c;

	struct open_bucket	*ob;

	/*
	 * When a node is going to be freed while write_blocked nonzero, we have
	 * to preserve the write ordering - this then points to the async_split
	 * that's waiting on writes before making the new node visible:
	 */
	struct async_split	*as;

	/* lru list */
	struct list_head	list;

	/* For outstanding btree writes, used as a lock - protects write_idx */
	struct closure		io;
	struct semaphore	io_mutex;
	struct delayed_work	work;

	struct btree_write	writes[2];

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
	BTREE_NODE_read_error,
	BTREE_NODE_write_error,
	BTREE_NODE_dirty,
	BTREE_NODE_write_idx,
};

BTREE_FLAG(read_error);
BTREE_FLAG(write_error);
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

static inline unsigned bset_byte_offset(struct btree *b, void *i)
{
	return i - (void *) b->data;
}

/* Type of keys @b contains: */
static inline enum bkey_type btree_node_type(struct btree *b)
{
	return b->level ? BKEY_TYPE_BTREE : b->btree_id;
}

static inline bool btree_node_has_ptrs(struct btree *b)
{
	return btree_type_has_ptrs(btree_node_type(b));
}

/*
 * Optional hook that will be called just prior to a btree node update, when
 * we're holding the write lock and we know what key is about to be overwritten:
 */

struct btree_iter;
struct bucket_stats_cache_set;

enum extent_insert_hook_ret {
	BTREE_HOOK_DO_INSERT,
	BTREE_HOOK_NO_INSERT,
};

struct extent_insert_hook {
	enum extent_insert_hook_ret
	(*fn)(struct extent_insert_hook *, struct btree_iter *,
	      struct bpos, struct bkey_s_c, const struct bkey_i *);
};

enum btree_insert_ret {
	BTREE_INSERT_OK,
	/* extent spanned multiple leaf nodes: have to traverse to next node: */
	BTREE_INSERT_NEED_TRAVERSE,
	/* write lock held for too long */
	BTREE_INSERT_NEED_RESCHED,
	/* leaf node needs to be split */
	BTREE_INSERT_BTREE_NODE_FULL,
	BTREE_INSERT_JOURNAL_RES_FULL,
};

#endif /* _BCACHE_BTREE_TYPES_H */
