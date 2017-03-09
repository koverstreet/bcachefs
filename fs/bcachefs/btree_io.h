#ifndef _BCACHE_BTREE_IO_H
#define _BCACHE_BTREE_IO_H

struct bch_fs;
struct btree_write;
struct btree;
struct btree_iter;

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

enum compact_mode {
	COMPACT_LAZY,
	COMPACT_WRITTEN,
	COMPACT_WRITTEN_NO_WRITE_LOCK,
};

bool __bch_compact_whiteouts(struct bch_fs *, struct btree *, enum compact_mode);

static inline bool bch_maybe_compact_whiteouts(struct bch_fs *c, struct btree *b)
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
	return __bch_compact_whiteouts(c, b, COMPACT_LAZY);
}

void bch_btree_sort_into(struct bch_fs *, struct btree *, struct btree *);

void bch_btree_build_aux_trees(struct btree *);
void bch_btree_init_next(struct bch_fs *, struct btree *,
			 struct btree_iter *);

void bch_btree_node_read_done(struct bch_fs *, struct btree *,
			      struct bch_dev *, const struct bch_extent_ptr *);
void bch_btree_node_read(struct bch_fs *, struct btree *);
int bch_btree_root_read(struct bch_fs *, enum btree_id,
			const struct bkey_i *, unsigned);

void bch_btree_complete_write(struct bch_fs *, struct btree *,
			      struct btree_write *);

void __bch_btree_node_write(struct bch_fs *, struct btree *,
			    struct closure *, enum six_lock_type, int);
bool bch_btree_post_write_cleanup(struct bch_fs *, struct btree *);

void bch_btree_node_write(struct bch_fs *, struct btree *,
			  struct closure *, enum six_lock_type, int);

void bch_btree_flush(struct bch_fs *);
void bch_btree_node_flush_journal_entries(struct bch_fs *, struct btree *,
					  struct closure *);

#endif /* _BCACHE_BTREE_IO_H */
