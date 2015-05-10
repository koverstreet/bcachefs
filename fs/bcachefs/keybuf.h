#ifndef _BCACHE_KEYBUF_H
#define _BCACHE_KEYBUF_H

#include "keybuf_types.h"

typedef bool (keybuf_pred_fn)(struct keybuf *, struct bkey *);

void bch_keybuf_init(struct keybuf *);
void bch_refill_keybuf(struct cache_set *, struct keybuf *,
		       struct bkey *, keybuf_pred_fn *);
bool bch_keybuf_check_overlapping(struct keybuf *, struct bkey *,
				  struct bkey *);
void bch_keybuf_put(struct keybuf *, struct keybuf_key *);
struct keybuf_key *bch_keybuf_next(struct keybuf *);
struct keybuf_key *bch_keybuf_next_rescan(struct cache_set *, struct keybuf *,
					  struct bkey *, keybuf_pred_fn *);

#endif /* _BCACHE_KEYBUF_H */
