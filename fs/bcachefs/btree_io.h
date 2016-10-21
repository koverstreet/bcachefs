#ifndef _BCACHE_BTREE_IO_H
#define _BCACHE_BTREE_IO_H

struct cache_set;
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

void bch_btree_init_next(struct cache_set *, struct btree *,
			 struct btree_iter *);

void bch_btree_node_read_done(struct cache_set *, struct btree *,
			      struct cache *, const struct bch_extent_ptr *);
void bch_btree_node_read(struct cache_set *, struct btree *);
int bch_btree_root_read(struct cache_set *, enum btree_id,
			const struct bkey_i *, unsigned);

void bch_btree_complete_write(struct cache_set *, struct btree *,
			      struct btree_write *);

void __bch_btree_node_write(struct btree *, struct closure *, int);
void bch_btree_node_write(struct btree *, struct closure *,
			  struct btree_iter *);
void bch_btree_node_write_lazy(struct btree *, struct btree_iter *);
void btree_node_write_work(struct work_struct *);

void bch_btree_flush(struct cache_set *);
void bch_btree_node_flush_journal_entries(struct cache_set *, struct btree *,
					  struct closure *);

#endif /* _BCACHE_BTREE_IO_H */
