#ifndef _BCACHE_BTREE_TYPES_H
#define _BCACHE_BTREE_TYPES_H

#include <linux/list.h>
#include <linux/rhashtable.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "bset.h"
#include "journal_types.h"
#include "six.h"

struct cache_set;
struct open_bucket;

struct btree_write {
	unsigned			index;
	bool				have_pin;
	struct journal_entry_pin	journal;
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

#endif /* _BCACHE_BTREE_TYPES_H */
