/* SPDX-License-Identifier: LGPL-2.1+ */
/* Copyright (C) 2022 Kent Overstreet */

#ifndef _LINUX_PRINTBUF_H
#define _LINUX_PRINTBUF_H

#include <linux/kernel.h>
#include <linux/string.h>

/*
 * Printbufs: String buffer for outputting (printing) to, for vsnprintf
 */

struct printbuf {
	char			*buf;
	unsigned		size;
	unsigned		pos;
};

/*
 * Returns size remaining of output buffer:
 */
static inline unsigned printbuf_remaining_size(struct printbuf *out)
{
	return out->pos < out->size ? out->size - out->pos : 0;
}

/*
 * Returns number of characters we can print to the output buffer - i.e.
 * excluding the terminating nul:
 */
static inline unsigned printbuf_remaining(struct printbuf *out)
{
	return out->pos < out->size ? out->size - out->pos - 1 : 0;
}

static inline unsigned printbuf_written(struct printbuf *out)
{
	return min(out->pos, out->size);
}

/*
 * Returns true if output was truncated:
 */
static inline bool printbuf_overflowed(struct printbuf *out)
{
	return out->pos >= out->size;
}

static inline void printbuf_nul_terminate(struct printbuf *out)
{
	if (out->pos < out->size)
		out->buf[out->pos] = 0;
	else if (out->size)
		out->buf[out->size - 1] = 0;
}

static inline void __prt_char(struct printbuf *out, char c)
{
	if (printbuf_remaining(out))
		out->buf[out->pos] = c;
	out->pos++;
}

static inline void prt_char(struct printbuf *out, char c)
{
	__prt_char(out, c);
	printbuf_nul_terminate(out);
}

static inline void __prt_chars(struct printbuf *out, char c, unsigned n)
{
	unsigned i, can_print = min(n, printbuf_remaining(out));

	for (i = 0; i < can_print; i++)
		out->buf[out->pos++] = c;
	out->pos += n - can_print;
}

static inline void prt_chars(struct printbuf *out, char c, unsigned n)
{
	__prt_chars(out, c, n);
	printbuf_nul_terminate(out);
}

static inline void prt_bytes(struct printbuf *out, const void *b, unsigned n)
{
	unsigned i, can_print = min(n, printbuf_remaining(out));

	for (i = 0; i < can_print; i++)
		out->buf[out->pos++] = ((char *) b)[i];
	out->pos += n - can_print;

	printbuf_nul_terminate(out);
}

static inline void prt_str(struct printbuf *out, const char *str)
{
	prt_bytes(out, str, strlen(str));
}

static inline void prt_hex_byte(struct printbuf *out, u8 byte)
{
	__prt_char(out, hex_asc_hi(byte));
	__prt_char(out, hex_asc_lo(byte));
	printbuf_nul_terminate(out);
}

static inline void prt_hex_byte_upper(struct printbuf *out, u8 byte)
{
	__prt_char(out, hex_asc_upper_hi(byte));
	__prt_char(out, hex_asc_upper_lo(byte));
	printbuf_nul_terminate(out);
}

#define PRINTBUF_EXTERN(_buf, _size)			\
((struct printbuf) {					\
	.buf	= _buf,					\
	.size	= _size,				\
})

/*
 * This is used for the %pf(%p) sprintf format extension, where we pass a pretty
 * printer and arguments to the pretty-printer to sprintf
 *
 * Instead of passing a pretty-printer function to sprintf directly, we pass it
 * a pointer to a struct call_pp, so that sprintf can check that the magic
 * number is present, which in turn ensures that the CALL_PP() macro has been
 * used in order to typecheck the arguments to the pretty printer function
 *
 * Example usage:
 *   sprintf("%pf(%p)", CALL_PP(prt_bdev, bdev));
 */
struct call_pp {
	unsigned long	magic;
	void		*fn;
};

#define PP_TYPECHECK(fn, ...)					\
	({ while (0) fn((struct printbuf *) NULL, ##__VA_ARGS__); })

#define CALL_PP_MAGIC		(unsigned long) 0xce0b92d22f6b6be4

#define CALL_PP(fn, ...)					\
	(PP_TYPECHECK(fn, ##__VA_ARGS__),			\
	 &((struct call_pp) { CALL_PP_MAGIC, fn })), ##__VA_ARGS__

#endif /* _LINUX_PRINTBUF_H */
