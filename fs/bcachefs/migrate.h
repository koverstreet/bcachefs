#ifndef _BCACHEFS_MIGRATE_H
#define _BCACHEFS_MIGRATE_H

int bch2_move_data_off_device(struct bch_dev *);
int bch2_move_metadata_off_device(struct bch_dev *);
int bch2_flag_data_bad(struct bch_dev *);

#endif /* _BCACHEFS_MIGRATE_H */
