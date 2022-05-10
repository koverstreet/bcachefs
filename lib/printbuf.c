// SPDX-License-Identifier: LGPL-2.1+
/* Copyright (C) 2022 Kent Overstreet */

#ifdef __KERNEL__
#include <linux/export.h>
#include <linux/kernel.h>
#else
#define EXPORT_SYMBOL(x)
#endif

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/printbuf.h>

int printbuf_make_room(struct printbuf *out, unsigned extra)
{
	unsigned new_size;
	char *buf;

	if (!out->heap_allocated)
		return 0;

	/* Reserved space for terminating nul: */
	extra += 1;

	if (out->pos + extra < out->size)
		return 0;

	new_size = roundup_pow_of_two(out->size + extra);

	/*
	 * Note: output buffer must be freeable with kfree(), it's not required
	 * that the user use printbuf_exit().
	 */
	buf = krealloc(out->buf, new_size, !out->atomic ? GFP_KERNEL : GFP_NOWAIT);

	if (!buf) {
		out->allocation_failure = true;
		return -ENOMEM;
	}

	out->buf	= buf;
	out->size	= new_size;
	return 0;
}
EXPORT_SYMBOL(printbuf_make_room);

/**
 * printbuf_str - returns printbuf's buf as a C string, guaranteed to be null
 * terminated
 */
const char *printbuf_str(const struct printbuf *buf)
{
	/*
	 * If we've written to a printbuf then it's guaranteed to be a null
	 * terminated string - but if we haven't, then we might not have
	 * allocated a buffer at all:
	 */
	return buf->pos
		? buf->buf
		: "";
}
EXPORT_SYMBOL(printbuf_str);

/**
 * printbuf_exit - exit a printbuf, freeing memory it owns and poisoning it
 * against accidental use.
 */
void printbuf_exit(struct printbuf *buf)
{
	if (buf->heap_allocated) {
		kfree(buf->buf);
		buf->buf = ERR_PTR(-EINTR); /* poison value */
	}
}
EXPORT_SYMBOL(printbuf_exit);
