/* SPDX-License-Identifier: LGPL-2.1+ */
/* Copyright (C) 2022 Kent Overstreet */

#ifndef _LINUX_PRINTBUF_H
#define _LINUX_PRINTBUF_H

/*
 * Printbufs: Simple strings for printing to, with optional heap allocation
 *
 * This code has provisions for use in userspace, to aid in making other code
 * portable between kernelspace and userspace.
 *
 * Basic example:
 *   struct printbuf buf = PRINTBUF;
 *
 *   prt_printf(&buf, "foo=");
 *   foo_to_text(&buf, foo);
 *   printk("%s", buf.buf);
 *   printbuf_exit(&buf);
 *
 * Or
 *   struct printbuf buf = PRINTBUF_EXTERN(char_buf, char_buf_size)
 *
 * We can now write pretty printers instead of writing code that dumps
 * everything to the kernel log buffer, and then those pretty-printers can be
 * used by other code that outputs to kernel log, sysfs, debugfs, etc.
 *
 * Memory allocation: Outputing to a printbuf may allocate memory. This
 * allocation is done with GFP_KERNEL, by default: use the newer
 * memalloc_*_(save|restore) functions as needed.
 *
 * Since no equivalent yet exists for GFP_ATOMIC/GFP_NOWAIT, memory allocations
 * will be done with GFP_NOWAIT if printbuf->atomic is nonzero.
 *
 * It's allowed to grab the output buffer and free it later with kfree() instead
 * of using printbuf_exit(), if the user just needs a heap allocated string at
 * the end.
 *
 * Memory allocation failures: We don't return errors directly, because on
 * memory allocation failure we usually don't want to bail out and unwind - we
 * want to print what we've got, on a best-effort basis. But code that does want
 * to return -ENOMEM may check printbuf.allocation_failure.
 */

#include <linux/kernel.h>
#include <linux/string.h>

struct printbuf {
	char			*buf;
	unsigned		size;
	unsigned		pos;
	/*
	 * If nonzero, allocations will be done with GFP_ATOMIC:
	 */
	u8			atomic;
	bool			allocation_failure:1;
	bool			heap_allocated:1;
};

int printbuf_make_room(struct printbuf *, unsigned);
const char *printbuf_str(const struct printbuf *);
void printbuf_exit(struct printbuf *);

/* Initializer for a heap allocated printbuf: */
#define PRINTBUF ((struct printbuf) { .heap_allocated = true })

/* Initializer a printbuf that points to an external buffer: */
#define PRINTBUF_EXTERN(_buf, _size)			\
((struct printbuf) {					\
	.buf	= _buf,					\
	.size	= _size,				\
})

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
	return out->size ? min(out->pos, out->size - 1) : 0;
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
	printbuf_make_room(out, 1);

	if (out->pos < out->size)
		out->buf[out->pos] = 0;
	else if (out->size)
		out->buf[out->size - 1] = 0;
}

/* Doesn't call printbuf_make_room(), doesn't nul terminate: */
static inline void __prt_char_reserved(struct printbuf *out, char c)
{
	if (printbuf_remaining(out))
		out->buf[out->pos] = c;
	out->pos++;
}

/* Doesn't nul terminate: */
static inline void __prt_char(struct printbuf *out, char c)
{
	printbuf_make_room(out, 1);
	__prt_char_reserved(out, c);
}

static inline void prt_char(struct printbuf *out, char c)
{
	__prt_char(out, c);
	printbuf_nul_terminate(out);
}

static inline void __prt_chars_reserved(struct printbuf *out, char c, unsigned n)
{
	unsigned i, can_print = min(n, printbuf_remaining(out));

	for (i = 0; i < can_print; i++)
		out->buf[out->pos++] = c;
	out->pos += n - can_print;
}

static inline void prt_chars(struct printbuf *out, char c, unsigned n)
{
	printbuf_make_room(out, n);
	__prt_chars_reserved(out, c, n);
	printbuf_nul_terminate(out);
}

static inline void prt_bytes(struct printbuf *out, const void *b, unsigned n)
{
	unsigned i, can_print;

	printbuf_make_room(out, n);

	can_print = min(n, printbuf_remaining(out));

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
	printbuf_make_room(out, 2);
	__prt_char_reserved(out, hex_asc_hi(byte));
	__prt_char_reserved(out, hex_asc_lo(byte));
	printbuf_nul_terminate(out);
}

static inline void prt_hex_byte_upper(struct printbuf *out, u8 byte)
{
	printbuf_make_room(out, 2);
	__prt_char_reserved(out, hex_asc_upper_hi(byte));
	__prt_char_reserved(out, hex_asc_upper_lo(byte));
	printbuf_nul_terminate(out);
}

/**
 * printbuf_reset - re-use a printbuf without freeing and re-initializing it:
 */
static inline void printbuf_reset(struct printbuf *buf)
{
	buf->pos		= 0;
	buf->allocation_failure	= 0;
}

/**
 * printbuf_atomic_inc - mark as entering an atomic section
 */
static inline void printbuf_atomic_inc(struct printbuf *buf)
{
	buf->atomic++;
}

/**
 * printbuf_atomic_inc - mark as leaving an atomic section
 */
static inline void printbuf_atomic_dec(struct printbuf *buf)
{
	buf->atomic--;
}

#endif /* _LINUX_PRINTBUF_H */
