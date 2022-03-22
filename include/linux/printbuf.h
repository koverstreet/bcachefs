/* SPDX-License-Identifier: LGPL-2.1+ */
/* Copyright (C) 2022 Kent Overstreet */

#ifndef _LINUX_PRINTBUF_H
#define _LINUX_PRINTBUF_H

/*
 * Printbufs: Simple heap allocated strings, with some features for structered
 * formatting.
 *
 * This code has provisions for use in userspace, to aid in making other code
 * portable between kernelspace and userspace.
 *
 * Basic example:
 *
 *   struct printbuf buf = PRINTBUF;
 *
 *   pr_buf(&buf, "foo=");
 *   foo_to_text(&buf, foo);
 *   printk("%s", buf.buf);
 *   printbuf_exit(&buf);
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
 * will be done with GFP_ATOMIC if printbuf->atomic is nonzero.
 *
 * Memory allocation failures: We don't return errors directly, because on
 * memory allocation failure we usually don't want to bail out and unwind - we
 * want to print what we've got, on a best-effort basis. But code that does want
 * to return -ENOMEM may check printbuf.allocation_failure.
 *
 * Indenting, tabstops:
 *
 * To aid is writing multi-line pretty printers spread across multiple
 * functions, printbufs track the current indent level.
 *
 * pr_indent_push() and pr_indent_pop() increase and decrease the current indent
 * level, respectively.
 *
 * To use tabstops, set printbuf->tabstops[]; they are in units of spaces, from
 * start of line. Once set, pr_tab() will output spaces up to the next tabstop.
 * pr_tab_rjust() will also advance the current line of text up to the next
 * tabstop, but it does so by shifting text since the previous tabstop up to the
 * next tabstop - right justifying it.
 *
 * Make sure you use pr_newline() instead of \n in the format string for indent
 * level and tabstops to work corretly.
 *
 * Output units: printbuf->units exists to tell pretty-printers how to output
 * numbers: a raw value (e.g. directly from a superblock field), as bytes, or as
 * human readable bytes. pr_units() and pr_sectors() obey it.
 *
 * Other helpful functions:
 *
 * pr_human_readable_u64, pr_human_readable_s64: Print an integer with human
 * readable units.
 *
 * pr_time(): for printing a time_t with strftime in userspace, prints as an
 * integer number of seconds in the kernel.
 *
 * pr_string_option: Given an enumerated value and a string array with names for
 * each option, prints out the enum names with the selected one indicated with
 * square brackets.
 *
 * pr_bitflags: Given a bitflag and a string array with names for each bit,
 * prints out the names of the selected bits.
 */

#include <linux/slab.h>
#include <linux/string_helpers.h>

enum printbuf_units {
	PRINTBUF_UNITS_RAW,
	PRINTBUF_UNITS_BYTES,
	PRINTBUF_UNITS_HUMAN_READABLE,
};

struct printbuf {
	char			*buf;
	unsigned		size;
	unsigned		pos;
	unsigned		last_newline;
	unsigned		last_field;
	unsigned		indent;
	enum printbuf_units	units:8;
	/*
	 * If nonzero, allocations will be done with GFP_ATOMIC:
	 */
	u8			atomic;
	bool			allocation_failure:1;
	/* SI units (10^3), or 2^10: */
	enum string_size_units	human_readable_units:1;
	u8			tabstop;
	u8			tabstops[4];
};

#define PRINTBUF ((struct printbuf) { .human_readable_units = STRING_UNITS_2 })

/**
 * printbuf_exit - exit a printbuf, freeing memory it owns and poisoning it
 * against accidental use.
 */
static inline void printbuf_exit(struct printbuf *buf)
{
	kfree(buf->buf);
	buf->buf = ERR_PTR(-EINTR); /* poison value */
}

/**
 * printbuf_reset - re-use a printbuf without freeing and re-initializing it:
 */
static inline void printbuf_reset(struct printbuf *buf)
{
	buf->pos		= 0;
	buf->last_newline	= 0;
	buf->last_field		= 0;
	buf->indent		= 0;
	buf->tabstop		= 0;
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

void pr_buf(struct printbuf *out, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void pr_char(struct printbuf *buf, char c);
void pr_newline(struct printbuf *);
void pr_indent_push(struct printbuf *, unsigned);
void pr_indent_pop(struct printbuf *, unsigned);
void pr_tab(struct printbuf *);
void pr_tab_rjust(struct printbuf *);
void pr_human_readable_u64(struct printbuf *, u64);
void pr_human_readable_s64(struct printbuf *, s64);
void pr_units(struct printbuf *, s64, s64);
void pr_sectors(struct printbuf *, u64);
void pr_time(struct printbuf *, u64);
void pr_uuid(struct printbuf *, u8 *);
void pr_string_option(struct printbuf *, const char * const list[], size_t);
void pr_bitflags(struct printbuf *, const char * const list[], u64);
const char *printbuf_str(const struct printbuf *);

#endif /* _LINUX_PRINTBUF_H */
