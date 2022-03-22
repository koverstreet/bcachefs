// SPDX-License-Identifier: LGPL-2.1+
/* Copyright (C) 2022 Kent Overstreet */

#ifdef __KERNEL__
#include <linux/export.h>
#include <linux/kernel.h>
#else
#define EXPORT_SYMBOL(x)
#endif

#include <linux/log2.h>
#include <linux/printbuf.h>
#include <linux/string_helpers.h>

static inline size_t printbuf_remaining(struct printbuf *buf)
{
	return buf->size - buf->pos;
}

static inline size_t printbuf_linelen(struct printbuf *buf)
{
	return buf->pos - buf->last_newline;
}

static int printbuf_realloc(struct printbuf *out, unsigned extra)
{
	unsigned new_size;
	char *buf;

	if (out->pos + extra + 1 < out->size)
		return 0;

	new_size = roundup_pow_of_two(out->size + extra);
	buf = krealloc(out->buf, new_size, !out->atomic ? GFP_KERNEL : GFP_ATOMIC);

	if (!buf) {
		out->allocation_failure = true;
		return -ENOMEM;
	}

	out->buf	= buf;
	out->size	= new_size;
	return 0;
}

void pr_buf(struct printbuf *out, const char *fmt, ...)
{
	va_list args;
	int len;

	do {
		va_start(args, fmt);
		len = vsnprintf(out->buf + out->pos, printbuf_remaining(out), fmt, args);
		va_end(args);
	} while (len + 1 >= printbuf_remaining(out) &&
		 !printbuf_realloc(out, len + 1));

	len = min_t(size_t, len,
		  printbuf_remaining(out) ? printbuf_remaining(out) - 1 : 0);
	out->pos += len;
}
EXPORT_SYMBOL(pr_buf);

void pr_char(struct printbuf *buf, char c)
{
	if (!printbuf_realloc(buf, 1)) {
		buf->buf[buf->pos++] = c;
		buf->buf[buf->pos] = 0;
	}
}
EXPORT_SYMBOL(pr_char);

void pr_newline(struct printbuf *buf)
{
	unsigned i;

	pr_char(buf, '\n');

	buf->last_newline	= buf->pos;

	for (i = 0; i < buf->indent; i++)
		pr_char(buf, ' ');

	buf->last_field		= buf->pos;
	buf->tabstop = 0;
}
EXPORT_SYMBOL(pr_newline);

void pr_indent_push(struct printbuf *buf, unsigned spaces)
{
	buf->indent += spaces;
	while (spaces--)
		pr_char(buf, ' ');
}
EXPORT_SYMBOL(pr_indent_push);

void pr_indent_pop(struct printbuf *buf, unsigned spaces)
{
	if (buf->last_newline + buf->indent == buf->pos) {
		buf->pos -= spaces;
		buf->buf[buf->pos] = 0;
	}
	buf->indent -= spaces;
}
EXPORT_SYMBOL(pr_indent_pop);

void pr_tab(struct printbuf *buf)
{
	BUG_ON(buf->tabstop > ARRAY_SIZE(buf->tabstops));

	while (printbuf_remaining(buf) > 1 &&
	       printbuf_linelen(buf) < buf->tabstops[buf->tabstop])
		pr_char(buf, ' ');

	buf->last_field = buf->pos;
	buf->tabstop++;
}
EXPORT_SYMBOL(pr_tab);

void pr_tab_rjust(struct printbuf *buf)
{
	BUG_ON(buf->tabstop > ARRAY_SIZE(buf->tabstops));

	if (printbuf_linelen(buf) < buf->tabstops[buf->tabstop]) {
		unsigned move = buf->pos - buf->last_field;
		unsigned shift = buf->tabstops[buf->tabstop] -
			printbuf_linelen(buf);

		printbuf_realloc(buf, shift);

		if (buf->last_field + shift + 1 < buf->size) {
			move = min(move, buf->size - 1 - buf->last_field - shift);

			memmove(buf->buf + buf->last_field + shift,
				buf->buf + buf->last_field,
				move);
			memset(buf->buf + buf->last_field, ' ', shift);
			buf->pos += shift;
			buf->buf[buf->pos] = 0;
		}
	}

	buf->last_field = buf->pos;
	buf->tabstop++;
}
EXPORT_SYMBOL(pr_tab_rjust);

void pr_human_readable_u64(struct printbuf *buf, u64 v)
{
	printbuf_realloc(buf, 10);
	string_get_size(v, 1, buf->human_readable_units, buf->buf + buf->pos,
			printbuf_remaining(buf));
	buf->pos += strlen(buf->buf + buf->pos);
}
EXPORT_SYMBOL(pr_human_readable_u64);

void pr_human_readable_s64(struct printbuf *buf, s64 v)
{
	if (v < 0)
		pr_char(buf, '-');
	pr_human_readable_u64(buf, abs(v));
}
EXPORT_SYMBOL(pr_human_readable_s64);

void pr_units(struct printbuf *out, s64 raw, s64 bytes)
{
	switch (out->units) {
	case PRINTBUF_UNITS_RAW:
		pr_buf(out, "%llu", raw);
		break;
	case PRINTBUF_UNITS_BYTES:
		pr_buf(out, "%llu", bytes);
		break;
	case PRINTBUF_UNITS_HUMAN_READABLE:
		pr_human_readable_s64(out, bytes);
		break;
	}
}
EXPORT_SYMBOL(pr_units);

void pr_sectors(struct printbuf *out, u64 v)
{
	pr_units(out, v, v << 9);
}
EXPORT_SYMBOL(pr_sectors);

#ifdef __KERNEL__

void pr_time(struct printbuf *out, u64 time)
{
	pr_buf(out, "%llu", time);
}
EXPORT_SYMBOL(pr_time);

void pr_uuid(struct printbuf *out, u8 *uuid)
{
	pr_buf(out, "%pUb", uuid);
}
EXPORT_SYMBOL(pr_uuid);

#else

#include <time.h>
#include <uuid.h>

void pr_time(struct printbuf *out, u64 _time)
{
	char time_str[64];
	time_t time = _time;
	struct tm *tm = localtime(&time);
	size_t err = strftime(time_str, sizeof(time_str), "%c", tm);

	if (!err)
		pr_buf(out, "(formatting error)");
	else
		pr_buf(out, "%s", time_str);
}

void pr_uuid(struct printbuf *out, u8 *uuid)
{
	char uuid_str[40];

	uuid_unparse_lower(uuid, uuid_str);
	pr_buf(out, uuid_str);
}

#endif

void pr_string_option(struct printbuf *out,
		      const char * const list[],
		      size_t selected)
{
	size_t i;

	for (i = 0; list[i]; i++)
		pr_buf(out, i == selected ? "[%s] " : "%s ", list[i]);
}
EXPORT_SYMBOL(pr_string_option);

void pr_bitflags(struct printbuf *out,
		 const char * const list[], u64 flags)
{
	unsigned bit, nr = 0;
	bool first = true;

	while (list[nr])
		nr++;

	while (flags && (bit = __ffs(flags)) < nr) {
		if (!first)
			pr_buf(out, ",");
		first = false;
		pr_buf(out, "%s", list[bit]);
		flags ^= 1 << bit;
	}
}
EXPORT_SYMBOL(pr_bitflags);

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
