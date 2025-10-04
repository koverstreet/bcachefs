/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_JOURNAL_INIT_H
#define _BCACHEFS_JOURNAL_INIT_H

int bch2_set_nr_journal_buckets(struct bch_fs *, struct bch_dev *, unsigned);
int bch2_dev_journal_bucket_delete(struct bch_dev *, u64);

int bch2_dev_journal_alloc(struct bch_dev *, bool);
int bch2_fs_journal_alloc(struct bch_fs *);

void bch2_dev_journal_stop(struct journal *, struct bch_dev *);

void bch2_fs_journal_stop(struct journal *);
int bch2_fs_journal_start(struct journal *, u64, u64);
void bch2_journal_set_replay_done(struct journal *);

void bch2_dev_journal_exit(struct bch_dev *);
int bch2_dev_journal_init(struct bch_dev *, struct bch_sb *);
void bch2_fs_journal_exit(struct journal *);
void bch2_fs_journal_init_early(struct journal *);
int bch2_fs_journal_init(struct journal *);

#endif /* _BCACHEFS_JOURNAL_INIT_H */
