/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RECOVERY_H
#define _BCACHEFS_RECOVERY_H

int bch2_journal_replay(struct bch_fs *);

int bch2_fs_recovery(struct bch_fs *);
int bch2_fs_initialize(struct bch_fs *);

#endif /* _BCACHEFS_RECOVERY_H */
