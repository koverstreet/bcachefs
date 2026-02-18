/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_EC_INIT_H
#define _BCACHEFS_DATA_EC_INIT_H

int bch2_invalidate_stripe_to_dev(struct btree_trans *, struct btree_iter *,
				  struct bkey_s_c, unsigned,
				  unsigned, struct printbuf *);
int bch2_dev_remove_stripes(struct bch_fs *, unsigned, unsigned, struct printbuf *);

void bch2_ec_stop_dev_cutoff(struct bch_fs *, struct bch_dev *, u64);
void bch2_ec_stop_dev(struct bch_fs *, struct bch_dev *);
void bch2_fs_ec_stop(struct bch_fs *);
void bch2_fs_ec_flush(struct bch_fs *);

int bch2_stripes_read(struct bch_fs *);

void bch2_fs_ec_exit(struct bch_fs *);
void bch2_fs_ec_init_early(struct bch_fs *);
int bch2_fs_ec_init(struct bch_fs *);

int bch2_bucket_nr_stripes(struct btree_trans *, struct bpos);

int bch2_check_stripe_refs(struct btree_trans *);

#endif /* _BCACHEFS_DATA_EC_INIT_H */
