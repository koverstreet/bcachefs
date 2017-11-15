#ifndef _BCACHEFS_TIER_H
#define _BCACHEFS_TIER_H

void bch2_rebalance_add_key(struct bch_fs *, struct bkey_s_c,
			    struct bch_io_opts *);
void bch2_rebalance_add_work(struct bch_fs *, u64);

void bch2_rebalance_stop(struct bch_fs *);
int bch2_rebalance_start(struct bch_fs *);
void bch2_fs_rebalance_init(struct bch_fs *);

#endif /* _BCACHEFS_TIER_H */
