/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_WRITE_BUFFER_H
#define _BCACHEFS_BTREE_WRITE_BUFFER_H

int bch2_btree_write_buffer_flush_locked(struct btree_trans *, unsigned, bool);
int bch2_btree_write_buffer_flush_sync(struct btree_trans *, unsigned);
int bch2_btree_write_buffer_flush(struct btree_trans *);

int bch2_write_buffer_key(struct bch_fs *, u64, unsigned,
			  enum btree_id, struct bkey_i *);
void bch2_queue_btree_write_buffer_flush(struct bch_fs *);

void bch2_fs_btree_write_buffer_exit(struct bch_fs *);
int bch2_fs_btree_write_buffer_init(struct bch_fs *);

#endif /* _BCACHEFS_BTREE_WRITE_BUFFER_H */
