// SPDX-License-Identifier: LGPL-2.1+
/* Copyright (C) 2022 Kent Overstreet */

#include <linux/kernel.h>
#include <linux/printbuf.h>

/**
 * pr_hex_bytes - Print a string of hex bytes, with optional separator
 *
 * @out: The printbuf to output to
 * @addr: Buffer to print
 * @nr: Number of bytes to print
 * @separator: Optional separator character between each byte
 */
void pr_hex_bytes(struct printbuf *out, const u8 *addr,
		  unsigned nr, unsigned separator)
{
	unsigned i;

	for (i = 0; i < nr; ++i) {
		if (separator && i)
			pr_char(out, separator);
		pr_hex_byte(out, addr[i]);
	}

	printbuf_nul_terminate(out);
}
EXPORT_SYMBOL(pr_hex_bytes);

/**
 * pr_string_option - Given a list of strings, print out the list and indicate
 * which option is selected, with square brackets (sysfs style)
 *
 * @out: The printbuf to output to
 * @list: List of strings to choose from
 * @selected: The option to highlight, with square brackets
 */
void pr_string_option(struct printbuf *out,
		      const char * const list[],
		      size_t selected)
{
	size_t i;

	for (i = 0; list[i]; i++) {
		if (i)
			pr_char(out, ' ');
		if (i == selected)
			pr_char(out, '[');
		pr_str(out, list[i]);
		if (i == selected)
			pr_char(out, ']');
	}
}
EXPORT_SYMBOL(pr_string_option);

/**
 * pr_bitflags: Given a bitmap and a list of names for each bit, print out which
 * bits are on, comma separated
 *
 * @out: The printbuf to output to
 * @list: List of names for each bit
 * @flags: Bits to print
 */
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
		pr_str(out, list[bit]);
		flags ^= 1 << bit;
	}
}
EXPORT_SYMBOL(pr_bitflags);
