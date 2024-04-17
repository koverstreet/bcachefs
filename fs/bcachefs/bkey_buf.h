/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_BUF_H
#define _BCACHEFS_BKEY_BUF_H

#include "bcachefs.h"
#include "bkey.h"

struct bkey_buf {
	struct bkey_i	*k;
	u64		onstack[12];
};

static inline void bch2_bkey_buf_realloc_noprof(struct bkey_buf *s,
					 struct bch_fs *c, unsigned u64s)
{
	if (s->k == (void *) s->onstack &&
	    u64s > ARRAY_SIZE(s->onstack)) {
		s->k = mempool_alloc_noprof(&c->large_bkey_pool, GFP_NOFS);
		memcpy(s->k, s->onstack, sizeof(s->onstack));
	}
}

#define bch2_bkey_buf_realloc(...)	alloc_hooks_void(bch2_bkey_buf_realloc_noprof(__VA_ARGS__))

#define bch2_bkey_buf_reassemble(_s, _c, _k)				\
do {									\
	bch2_bkey_buf_realloc(_s, _c, (_k).k->u64s);			\
	bkey_reassemble((_s)->k, _k);					\
} while (0)

#define bch2_bkey_buf_copy(_s, _c, _src)				\
do {									\
	bch2_bkey_buf_realloc(_s, _c, (_src)->k.u64s);			\
	bkey_copy((_s)->k, _src);					\
} while (0)

#define bch2_bkey_buf_unpack(_s, _c, _b, _src)				\
do {									\
	bch2_bkey_buf_realloc(_s, _c, BKEY_U64s +			\
			      bkeyp_val_u64s(&_b->format, _src));	\
	bch2_bkey_unpack(_b, (_s)->k, _src);				\
} while (0)

static inline void bch2_bkey_buf_init(struct bkey_buf *s)
{
	s->k = (void *) s->onstack;
}

static inline void bch2_bkey_buf_exit(struct bkey_buf *s, struct bch_fs *c)
{
	if (s->k != (void *) s->onstack)
		mempool_free(s->k, &c->large_bkey_pool);
	s->k = NULL;
}

#endif /* _BCACHEFS_BKEY_BUF_H */
