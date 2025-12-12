/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_BUF_H
#define _BCACHEFS_BKEY_BUF_H

#include <linux/mempool.h>

#include "bcachefs.h"
#include "btree/bkey.h"

struct bkey_buf {
	struct bkey_i	*k;
	u64		onstack[12];
};

static inline int bch2_bkey_buf_realloc_noprof(struct bkey_buf *s, unsigned u64s)
{
	if (s->k == (void *) s->onstack &&
	    u64s > ARRAY_SIZE(s->onstack)) {
		s->k = kmalloc_noprof(2048, GFP_KERNEL|__GFP_NOFAIL);
		memcpy(s->k, s->onstack, sizeof(s->onstack));
	}

	return 0; /* for alloc_hooks() macro */
}
#define bch2_bkey_buf_realloc(...)	alloc_hooks(bch2_bkey_buf_realloc_noprof(__VA_ARGS__))

static inline int bch2_bkey_buf_reassemble_noprof(struct bkey_buf *s, struct bkey_s_c k)
{
	bch2_bkey_buf_realloc_noprof(s, k.k->u64s);
	bkey_reassemble(s->k, k);
	return 0;
}
#define bch2_bkey_buf_reassemble(...)	alloc_hooks(bch2_bkey_buf_reassemble_noprof(__VA_ARGS__))

static inline int bch2_bkey_buf_copy_noprof(struct bkey_buf *s, struct bkey_i *src)
{
	bch2_bkey_buf_realloc_noprof(s, src->k.u64s);
	bkey_copy(s->k, src);
	return 0;
}
#define bch2_bkey_buf_copy(...)	alloc_hooks(bch2_bkey_buf_copy_noprof(__VA_ARGS__))

static inline int bch2_bkey_buf_unpack_noprof(struct bkey_buf *s,
					      struct btree *b,
					      struct bkey_packed *src)
{
	bch2_bkey_buf_realloc_noprof(s, BKEY_U64s + bkeyp_val_u64s(&b->format, src));
	bch2_bkey_unpack(b, s->k, src);
	return 0;
}
#define bch2_bkey_buf_unpack(...)	alloc_hooks(bch2_bkey_buf_unpack_noprof(__VA_ARGS__))

static inline void bch2_bkey_buf_init(struct bkey_buf *s)
{
	s->k = (void *) s->onstack;
	bkey_init(&s->k->k);
}

static inline void bch2_bkey_buf_exit(struct bkey_buf *s)
{
	if (s->k != (void *) s->onstack)
		kfree(s->k);
	s->k = NULL;
}

#endif /* _BCACHEFS_BKEY_BUF_H */
