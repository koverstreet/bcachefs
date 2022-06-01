// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/hexdump.c
 */

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/export.h>
#include <linux/printbuf.h>
#include <asm/unaligned.h>

const char hex_asc[] = "0123456789abcdef";
EXPORT_SYMBOL(hex_asc);
const char hex_asc_upper[] = "0123456789ABCDEF";
EXPORT_SYMBOL(hex_asc_upper);

/**
 * hex_to_bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hex_to_bin() converts one hex digit to its actual value or -1 in case of bad
 * input.
 *
 * This function is used to load cryptographic keys, so it is coded in such a
 * way that there are no conditions or memory accesses that depend on data.
 *
 * Explanation of the logic:
 * (ch - '9' - 1) is negative if ch <= '9'
 * ('0' - 1 - ch) is negative if ch >= '0'
 * we "and" these two values, so the result is negative if ch is in the range
 *	'0' ... '9'
 * we are only interested in the sign, so we do a shift ">> 8"; note that right
 *	shift of a negative value is implementation-defined, so we cast the
 *	value to (unsigned) before the shift --- we have 0xffffff if ch is in
 *	the range '0' ... '9', 0 otherwise
 * we "and" this value with (ch - '0' + 1) --- we have a value 1 ... 10 if ch is
 *	in the range '0' ... '9', 0 otherwise
 * we add this value to -1 --- we have a value 0 ... 9 if ch is in the range '0'
 *	... '9', -1 otherwise
 * the next line is similar to the previous one, but we need to decode both
 *	uppercase and lowercase letters, so we use (ch & 0xdf), which converts
 *	lowercase to uppercase
 */
int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}
EXPORT_SYMBOL(hex_to_bin);

/**
 * hex2bin - convert an ascii hexadecimal string to its binary representation
 * @dst: binary result
 * @src: ascii hexadecimal string
 * @count: result length
 *
 * Return 0 on success, -EINVAL in case of bad input.
 */
int hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		int hi, lo;

		hi = hex_to_bin(*src++);
		if (unlikely(hi < 0))
			return -EINVAL;
		lo = hex_to_bin(*src++);
		if (unlikely(lo < 0))
			return -EINVAL;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}
EXPORT_SYMBOL(hex2bin);

/**
 * prt_hex_bytes - Print a string of hex bytes, with optional separator
 *
 * @out: The printbuf to output to
 * @addr: Buffer to print
 * @nr: Number of bytes to print
 * @separator: Optional separator character between each byte
 */
void prt_hex_bytes(struct printbuf *out, const void *buf, unsigned len,
		   unsigned groupsize, unsigned separator)
{
	const u8 *ptr = buf;
	unsigned i;

	if (!groupsize)
		groupsize = 1;

	for (i = 0; i < len ; ++i) {
		if (i && separator && !(i % groupsize))
			__prt_char(out, separator);
		prt_hex_byte(out, ptr[i]);
	}
}
EXPORT_SYMBOL(prt_hex_bytes);

/**
 * prt_hex_line - convert a blob of data to "hex ASCII" in memory
 * @out: printbuf to output to
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @ascii: include ASCII after the hex output
 *
 * prt_hex_line() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of u8 data, hex_dump_to_buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output is always NUL-terminated.
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1,
 *			linebuf, sizeof(linebuf), true);
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 */
void prt_hex_line(struct printbuf *out, const void *buf, size_t len,
		  int rowsize, int groupsize, bool ascii)
{
	unsigned saved_pos = out->pos;
	const u8 *ptr = buf;
	int i, ngroups;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;
	if (!is_power_of_2(groupsize) || groupsize > 8)
		groupsize = 1;
	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	ngroups = len / groupsize;

	if (!len)
		return;

	prt_hex_bytes(out, ptr, len, groupsize, ' ');

	if (ascii) {
		unsigned ascii_column = rowsize * 2 + rowsize / groupsize + 1;

		prt_chars(out, ' ', max_t(int, 0, ascii_column - (out->pos - saved_pos)));

		for (i = 0; i < len; i++) {
			u8 ch = ptr[i];
			prt_char(out, isascii(ch) && isprint(ch) ? ch : '.');
		}
	}
}
EXPORT_SYMBOL(prt_hex_line);

/**
 * prt_hex_dump - print multiline formatted hex dump
 * @out: printbuf to output to
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @ascii: include ASCII after the hex output
 *
 * Function is an analogue of print_hex_dump() and thus has similar interface.
 *
 * linebuf size is maximal length for one line.
 * 32 * 3 - maximum bytes per line, each printed into 2 chars + 1 for
 *	separating space
 * 2 - spaces separating hex dump and ascii representation
 * 32 - ascii representation
 * 1 - terminating '\0'
 */
void prt_hex_dump(struct printbuf *out, const void *buf, size_t len,
		  const char *prefix_str, int prefix_type,
		  unsigned rowsize, unsigned groupsize, bool ascii)
{
	const u8 *ptr = buf;
	size_t i;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		prt_str(out, prefix_str);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			prt_printf(out, "%p: ", ptr + i);
			break;
		case DUMP_PREFIX_OFFSET:
			prt_printf(out, "%.8zx: ", i);
			break;
		}

		prt_hex_line(out, ptr + i, min_t(size_t, len - i, rowsize),
			     rowsize, groupsize, ascii);
		prt_char(out, '\n');
	}
}

/**
 * bin2hex - convert binary data to an ascii hexadecimal string
 * @dst: ascii hexadecimal result
 * @src: binary data
 * @count: binary data length
 */
char *bin2hex(char *dst, const void *src, size_t count)
{
	struct printbuf out = PRINTBUF_EXTERN(dst, count * 4);

	prt_hex_bytes(&out, src, count, 0, 0);
	return dst + out.pos;
}
EXPORT_SYMBOL(bin2hex);

/**
 * hex_dump_to_buffer - convert a blob of data to "hex ASCII" in memory
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @linebuf: where to put the converted data
 * @linebuflen: total size of @linebuf, including space for terminating NUL
 * @ascii: include ASCII after the hex output
 *
 * hex_dump_to_buffer() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of u8 data, hex_dump_to_buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output is always NUL-terminated.
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1,
 *			linebuf, sizeof(linebuf), true);
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 *
 * Return:
 * The amount of bytes placed in the buffer without terminating NUL. If the
 * output was truncated, then the return value is the number of bytes
 * (excluding the terminating NUL) which would have been written to the final
 * string if enough space had been available.
 */
int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize,
		       char *linebuf, size_t linebuflen, bool ascii)
{
	struct printbuf out = PRINTBUF_EXTERN(linebuf, linebuflen);

	prt_hex_line(&out, buf, len, rowsize, groupsize, ascii);
	return out.pos;
}
EXPORT_SYMBOL(hex_dump_to_buffer);

#ifdef CONFIG_PRINTK
/**
 * print_hex_dump - print a text hex dump to syslog for a binary blob of data
 * @level: kernel log level (e.g. KERN_DEBUG)
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @ascii: include ASCII after the hex output
 *
 * Given a buffer of u8 data, print_hex_dump() prints a hex + ASCII dump
 * to the kernel log at the specified kernel log level, with an optional
 * leading prefix.
 *
 * print_hex_dump() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 * print_hex_dump() iterates over the entire input @buf, breaking it into
 * "line size" chunks to format and print.
 *
 * E.g.:
 *   print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS,
 *		    16, 1, frame->data, frame->len, true);
 *
 * Example output using %DUMP_PREFIX_OFFSET and 1-byte mode:
 * 0009ab42: 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 * Example output using %DUMP_PREFIX_ADDRESS and 4-byte mode:
 * ffffffff88089af0: 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.
 */
void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, bool ascii)
{
	/*
	 * XXX: this code does the exact same thing as prt_hex_dump(): we should
	 * be able to call that and printk() the result, except printk is
	 * restricted to 1024 bytes of output per call
	 */
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			printk("%s%s%p: %s\n",
			       level, prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
			break;
		default:
			printk("%s%s%s\n", level, prefix_str, linebuf);
			break;
		}
	}
}
EXPORT_SYMBOL(print_hex_dump);

#endif /* defined(CONFIG_PRINTK) */
