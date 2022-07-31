/* SPDX-License-Identifier: GPL-2.0 */
/*
 * code tag context
 */
#ifndef _LINUX_CODETAG_CTX_H
#define _LINUX_CODETAG_CTX_H

#include <linux/codetag.h>
#include <linux/kref.h>

/* Code tag hit context. */
struct codetag_ctx {
	unsigned int flags; /* has to be the first member shared with codetag */
	struct codetag_with_ctx *ctc;
	struct list_head node;
	struct kref refcount;
} __aligned(8);

static inline struct codetag_ctx *kref_to_ctx(struct kref *refcount)
{
	return container_of(refcount, struct codetag_ctx, refcount);
}

static inline void add_ctx(struct codetag_ctx *ctx,
			   struct codetag_with_ctx *ctc)
{
	kref_init(&ctx->refcount);
	spin_lock(&ctc->ctx_lock);
	ctx->flags = CTC_FLAG_CTX_PTR;
	ctx->ctc = ctc;
	list_add_tail(&ctx->node, &ctc->ctx_head);
	spin_unlock(&ctc->ctx_lock);
}

static inline void rem_ctx(struct codetag_ctx *ctx,
			   void (*free_ctx)(struct kref *refcount))
{
	struct codetag_with_ctx *ctc = ctx->ctc;

	spin_lock(&ctc->ctx_lock);
	/* ctx might have been removed while we were using it */
	if (!list_empty(&ctx->node))
		list_del_init(&ctx->node);
	spin_unlock(&ctc->ctx_lock);
	kref_put(&ctx->refcount, free_ctx);
}

#endif /* _LINUX_CODETAG_CTX_H */
