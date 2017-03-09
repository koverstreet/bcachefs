#ifndef _BCACHE_TIER_H
#define _BCACHE_TIER_H

void bch_tiering_stop(struct bch_fs *);
int bch_tiering_start(struct bch_fs *);
void bch_fs_tiering_init(struct bch_fs *);

#endif
