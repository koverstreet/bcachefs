#ifndef _BCACHEFS_BTREE_IO_H
#define _BCACHEFS_BTREE_IO_H

#include "extents.h"

struct bch_fs;
struct btree_write;
struct btree;
struct btree_iter;

struct btree_read_bio {
	struct bch_fs		*c;
	u64			start_time;
	struct extent_pick_ptr	pick;
	struct work_struct	work;
	struct bio		bio;
};

static inline void btree_node_io_unlock(struct btree *b)
{
	EBUG_ON(!btree_node_write_in_flight(b));
	clear_btree_node_write_in_flight(b);
	wake_up_bit(&b->flags, BTREE_NODE_write_in_flight);
}

static inline void btree_node_io_lock(struct btree *b)
{
	wait_on_bit_lock_io(&b->flags, BTREE_NODE_write_in_flight,
			    TASK_UNINTERRUPTIBLE);
}

static inline void btree_node_wait_on_io(struct btree *b)
{
	wait_on_bit_io(&b->flags, BTREE_NODE_write_in_flight,
		       TASK_UNINTERRUPTIBLE);
}

static inline bool btree_node_may_write(struct btree *b)
{
	return list_empty_careful(&b->write_blocked) &&
		!b->will_make_reachable;
}

enum compact_mode {
	COMPACT_LAZY,
	COMPACT_WRITTEN,
	COMPACT_WRITTEN_NO_WRITE_LOCK,
};

bool __bch2_compact_whiteouts(struct bch_fs *, struct btree *, enum compact_mode);

static inline bool bch2_maybe_compact_whiteouts(struct bch_fs *c, struct btree *b)
{
	struct bset_tree *t;

	for_each_bset(b, t) {
		unsigned live_u64s = b->nr.bset_u64s[t - b->set];
		unsigned bset_u64s = le16_to_cpu(bset(b, t)->u64s);

		if (live_u64s * 4 < bset_u64s * 3)
			goto compact;
	}

	return false;
compact:
	return __bch2_compact_whiteouts(c, b, COMPACT_LAZY);
}

void bch2_btree_sort_into(struct bch_fs *, struct btree *, struct btree *);

void bch2_btree_build_aux_trees(struct btree *);
void bch2_btree_init_next(struct bch_fs *, struct btree *,
			 struct btree_iter *);

int bch2_btree_node_read_done(struct bch_fs *, struct btree *, bool);
void bch2_btree_node_read(struct bch_fs *, struct btree *, bool);
int bch2_btree_root_read(struct bch_fs *, enum btree_id,
			 const struct bkey_i *, unsigned);

void bch2_btree_complete_write(struct bch_fs *, struct btree *,
			      struct btree_write *);
void bch2_btree_write_error_work(struct work_struct *);

void __bch2_btree_node_write(struct bch_fs *, struct btree *,
			    struct closure *, enum six_lock_type);
bool bch2_btree_post_write_cleanup(struct bch_fs *, struct btree *);

void bch2_btree_node_write(struct bch_fs *, struct btree *,
			  struct closure *, enum six_lock_type);

#define bch2_btree_node_write_dirty(_c, _b, _cl, cond)			\
do {									\
	while ((_b)->written && btree_node_dirty(_b) &&	(cond)) {	\
		set_btree_node_need_write(_b);				\
									\
		if (!btree_node_may_write(_b))				\
			break;						\
									\
		if (!btree_node_write_in_flight(_b)) {			\
			bch2_btree_node_write(_c, _b, _cl, SIX_LOCK_read);\
			break;						\
		}							\
									\
		six_unlock_read(&(_b)->lock);				\
		btree_node_wait_on_io(_b);				\
		six_lock_read(&(_b)->lock);				\
	}								\
} while (0)

void bch2_btree_verify_flushed(struct bch_fs *);

#endif /* _BCACHEFS_BTREE_IO_H */
