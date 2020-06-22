/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_BCH2_H
#define _BCACHE_BCH2_H

void bch2_cached_dev_make_request(struct cached_dev *dc, struct bio *bio);
int bch2_cached_dev_attach(struct cached_dev *dc, uint8_t *fs_uuid);

void bch2_request_exit(struct cached_dev *dc);
int bch2_request_init(struct cached_dev *dc);

#endif /* _BCACHE_BCH2_H_ */
