// SPDX-License-Identifier: LGPL-2.1+
/* Copyright (C) 2022 Kent Overstreet */

#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/printbuf.h>
#include <linux/pretty-printers.h>

/**
 * prt_string_option - Given a list of strings, print out the list and indicate
 * which option is selected, with square brackets (sysfs style)
 *
 * @out: The printbuf to output to
 * @list: List of strings to choose from
 * @selected: The option to highlight, with square brackets
 */
void prt_string_option(struct printbuf *out,
		       const char * const list[],
		       size_t selected)
{
	size_t i;

	for (i = 0; list[i]; i++) {
		if (i)
			prt_char(out, ' ');
		if (i == selected)
			prt_char(out, '[');
		prt_str(out, list[i]);
		if (i == selected)
			prt_char(out, ']');
	}
}
EXPORT_SYMBOL(prt_string_option);

/**
 * prt_bitflags: Given a bitmap and a list of names for each bit, print out which
 * bits are on, comma separated
 *
 * @out: The printbuf to output to
 * @list: List of names for each bit
 * @flags: Bits to print
 */
void prt_bitflags(struct printbuf *out,
		  const char * const list[], u64 flags)
{
	unsigned bit, nr = 0;
	bool first = true;

	while (list[nr])
		nr++;

	while (flags && (bit = __ffs(flags)) < nr) {
		if (!first)
			prt_char(out, ',');
		first = false;
		prt_str(out, list[bit]);
		flags ^= 1 << bit;
	}
}
EXPORT_SYMBOL(prt_bitflags);
