/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_INIT_H
#define _BCACHEFS_BTREE_INIT_H

void bch2_fs_btree_exit(struct bch_fs *);
void bch2_fs_btree_init_early(struct bch_fs *);
int bch2_fs_btree_init(struct bch_fs *);
int bch2_fs_btree_init_rw(struct bch_fs *);

#endif /* _BCACHEFS_BTREE_INIT_H */
