#ifndef _BCACHE_MIGRATE_H
#define _BCACHE_MIGRATE_H

int bch_move_data_off_device(struct cache *);
int bch_move_meta_data_off_device(struct cache *);
int bch_flag_data_bad(struct cache *);

#endif /* _BCACHE_MIGRATE_H */
