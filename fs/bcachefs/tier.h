#ifndef _BCACHE_TIER_H
#define _BCACHE_TIER_H

void bch2_tiering_stop(struct bch_fs *);
int bch2_tiering_start(struct bch_fs *);
void bch2_fs_tiering_init(struct bch_fs *);

#endif
