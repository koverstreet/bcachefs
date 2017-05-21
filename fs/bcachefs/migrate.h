#ifndef _BCACHEFS_MIGRATE_H
#define _BCACHEFS_MIGRATE_H

int bch2_dev_data_migrate(struct bch_fs *, struct bch_dev *, int);
int bch2_dev_data_drop(struct bch_fs *, unsigned, int);

#endif /* _BCACHEFS_MIGRATE_H */
