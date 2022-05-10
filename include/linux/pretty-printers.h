/* SPDX-License-Identifier: LGPL-2.1+ */
/* Copyright (C) 2022 Kent Overstreet */

#ifndef _LINUX_PRETTY_PRINTERS_H
#define _LINUX_PRETTY_PRINTERS_H

void prt_string_option(struct printbuf *, const char * const[], size_t);
void prt_bitflags(struct printbuf *, const char * const[], u64);

#endif /* _LINUX_PRETTY_PRINTERS_H */
