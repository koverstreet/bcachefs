/* SPDX-License-Identifier: LGPL-2.1+ */
/* Copyright (C) 2022 Kent Overstreet */

#ifndef _LINUX_PRINTBUF_H
#define _LINUX_PRINTBUF_H

#include <linux/string.h>

/*
 * Printbufs: String buffer for outputting (printing) to, for vsnprintf
 */

struct printbuf {
	char			*buf;
	unsigned		size;
	unsigned		pos;
};

static inline unsigned printbuf_remaining(struct printbuf *out)
{
	return out->pos < out->size ? out->size - out->pos : 0;
}

static inline unsigned printbuf_written(struct printbuf *out)
{
	return min(out->pos, out->size);
}

static inline void printbuf_nul_terminate(struct printbuf *out)
{
	if (out->pos < out->size)
		out->buf[out->pos] = 0;
	else if (out->size)
		out->buf[out->size - 1] = 0;
}

static inline void pr_chars(struct printbuf *out, char c, unsigned n)
{
	memset(out->buf + out->pos,
	       c,
	       min(n, printbuf_remaining(out)));
	out->pos += n;
	printbuf_nul_terminate(out);
}

static inline void __pr_char(struct printbuf *out, char c)
{
	if (printbuf_remaining(out))
		out->buf[out->pos] = c;
	out->pos++;
}

static inline void pr_char(struct printbuf *out, char c)
{
	__pr_char(out, c);
	printbuf_nul_terminate(out);
}

static inline void pr_bytes(struct printbuf *out, const void *b, unsigned n)
{
	memcpy(out->buf + out->pos,
	       b,
	       min(n, printbuf_remaining(out)));
	out->pos += n;
	printbuf_nul_terminate(out);
}

static inline void pr_str(struct printbuf *out, const char *str)
{
	pr_bytes(out, str, strlen(str));
}

static inline void pr_hex_byte(struct printbuf *out, u8 byte)
{
	__pr_char(out, hex_asc_hi(byte));
	__pr_char(out, hex_asc_lo(byte));
	printbuf_nul_terminate(out);
}

static inline void pr_hex_byte_upper(struct printbuf *out, u8 byte)
{
	__pr_char(out, hex_asc_upper_hi(byte));
	__pr_char(out, hex_asc_upper_lo(byte));
	printbuf_nul_terminate(out);
}

#define PRINTBUF_EXTERN(_buf, _size)			\
((struct printbuf) {					\
	.buf	= _buf,					\
	.size	= _size,				\
})

#endif /* _LINUX_PRINTBUF_H */
