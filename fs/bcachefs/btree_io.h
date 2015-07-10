#ifndef _BCACHE_BTREE_IO_H
#define _BCACHE_BTREE_IO_H

struct cache_set;
struct btree_write;
struct btree;
struct btree_iter;

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
void bch_btree_node_write_sync(struct btree *, struct btree_iter *);
void bch_btree_node_write_lazy(struct btree *, struct btree_iter *);
void btree_node_write_work(struct work_struct *);

void bch_btree_flush(struct cache_set *);
void bch_btree_node_flush_journal_entries(struct cache_set *, struct btree *,
					  struct closure *);

#endif /* _BCACHE_BTREE_IO_H */
