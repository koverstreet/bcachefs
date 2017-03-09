#ifndef _BCACHE_MIGRATE_H
#define _BCACHE_MIGRATE_H

int bch_move_data_off_device(struct bch_dev *);
int bch_move_metadata_off_device(struct bch_dev *);
int bch_flag_data_bad(struct bch_dev *);

#endif /* _BCACHE_MIGRATE_H */
