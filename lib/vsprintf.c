// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/* vsprintf.c -- Lars Wirzenius & Linus Torvalds. */
/*
 * Wirzenius wrote this portably, Torvalds fucked it up :-)
 */

/*
 * Fri Jul 13 2001 Crutcher Dunnavant <crutcher+kernel@datastacks.com>
 * - changed to provide snprintf and vsnprintf functions
 * So Feb  1 16:51:32 CET 2004 Juergen Quade <quade@hsnr.de>
 * - scnprintf and vscnprintf
 */

#include <linux/stdarg.h>
#include <linux/build_bug.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/errname.h>
#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/uuid.h>
#include <linux/of.h>
#include <net/addrconf.h>
#include <linux/siphash.h>
#include <linux/compiler.h>
#include <linux/property.h>
#ifdef CONFIG_BLOCK
#include <linux/blkdev.h>
#endif
#include <linux/printbuf.h>

#include "../mm/internal.h"	/* For the trace_print_flags arrays */

#include <asm/page.h>		/* for PAGE_SIZE */
#include <asm/byteorder.h>	/* cpu_to_le16 */
#include <asm/unaligned.h>

#include <linux/string_helpers.h>
#include "kstrtox.h"

/* Disable pointer hashing if requested */
bool no_hash_pointers __ro_after_init;
EXPORT_SYMBOL_GPL(no_hash_pointers);

static noinline unsigned long long simple_strntoull(const char *startp, size_t max_chars, char **endp, unsigned int base)
{
	const char *cp;
	unsigned long long result = 0ULL;
	size_t prefix_chars;
	unsigned int rv;

	cp = _parse_integer_fixup_radix(startp, &base);
	prefix_chars = cp - startp;
	if (prefix_chars < max_chars) {
		rv = _parse_integer_limit(cp, base, &result, max_chars - prefix_chars);
		/* FIXME */
		cp += (rv & ~KSTRTOX_OVERFLOW);
	} else {
		/* Field too short for prefix + digit, skip over without converting */
		cp = startp + max_chars;
	}

	if (endp)
		*endp = (char *)cp;

	return result;
}

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoull instead.
 */
noinline
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoull(cp, INT_MAX, endp, base);
}
EXPORT_SYMBOL(simple_strtoull);

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoul instead.
 */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{
	return simple_strtoull(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtoul);

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtol instead.
 */
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoul(cp + 1, endp, base);

	return simple_strtoul(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtol);

static long long simple_strntoll(const char *cp, size_t max_chars, char **endp,
				 unsigned int base)
{
	/*
	 * simple_strntoull() safely handles receiving max_chars==0 in the
	 * case cp[0] == '-' && max_chars == 1.
	 * If max_chars == 0 we can drop through and pass it to simple_strntoull()
	 * and the content of *cp is irrelevant.
	 */
	if (*cp == '-' && max_chars > 0)
		return -simple_strntoull(cp + 1, max_chars - 1, endp, base);

	return simple_strntoull(cp, max_chars, endp, base);
}

/**
 * simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoll instead.
 */
long long simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoll(cp, INT_MAX, endp, base);
}
EXPORT_SYMBOL(simple_strtoll);

static noinline_for_stack
int skip_atoi(const char **s)
{
	int i = 0;

	do {
		i = i*10 + *((*s)++) - '0';
	} while (isdigit(**s));

	return i;
}

/*
 * Decimal conversion is by far the most typical, and is used for
 * /proc and /sys data. This directly impacts e.g. top performance
 * with many processes running. We optimize it for speed by emitting
 * two characters at a time, using a 200 byte lookup table. This
 * roughly halves the number of multiplications compared to computing
 * the digits one at a time. Implementation strongly inspired by the
 * previous version, which in turn used ideas described at
 * <http://www.cs.uiowa.edu/~jones/bcd/divide.html> (with permission
 * from the author, Douglas W. Jones).
 *
 * It turns out there is precisely one 26 bit fixed-point
 * approximation a of 64/100 for which x/100 == (x * (u64)a) >> 32
 * holds for all x in [0, 10^8-1], namely a = 0x28f5c29. The actual
 * range happens to be somewhat larger (x <= 1073741898), but that's
 * irrelevant for our purpose.
 *
 * For dividing a number in the range [10^4, 10^6-1] by 100, we still
 * need a 32x32->64 bit multiply, so we simply use the same constant.
 *
 * For dividing a number in the range [100, 10^4-1] by 100, there are
 * several options. The simplest is (x * 0x147b) >> 19, which is valid
 * for all x <= 43698.
 */

static const u16 decpair[100] = {
#define _(x) (__force u16) cpu_to_le16(((x % 10) | ((x / 10) << 8)) + 0x3030)
	_( 0), _( 1), _( 2), _( 3), _( 4), _( 5), _( 6), _( 7), _( 8), _( 9),
	_(10), _(11), _(12), _(13), _(14), _(15), _(16), _(17), _(18), _(19),
	_(20), _(21), _(22), _(23), _(24), _(25), _(26), _(27), _(28), _(29),
	_(30), _(31), _(32), _(33), _(34), _(35), _(36), _(37), _(38), _(39),
	_(40), _(41), _(42), _(43), _(44), _(45), _(46), _(47), _(48), _(49),
	_(50), _(51), _(52), _(53), _(54), _(55), _(56), _(57), _(58), _(59),
	_(60), _(61), _(62), _(63), _(64), _(65), _(66), _(67), _(68), _(69),
	_(70), _(71), _(72), _(73), _(74), _(75), _(76), _(77), _(78), _(79),
	_(80), _(81), _(82), _(83), _(84), _(85), _(86), _(87), _(88), _(89),
	_(90), _(91), _(92), _(93), _(94), _(95), _(96), _(97), _(98), _(99),
#undef _
};

/*
 * This will print a single '0' even if r == 0, since we would
 * immediately jump to out_r where two 0s would be written but only
 * one of them accounted for in buf. This is needed by ip4_string
 * below. All other callers pass a non-zero value of r.
*/
static noinline_for_stack
char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	/* 1 <= r < 10^8 */
	if (r < 100)
		goto out_r;

	/* 100 <= r < 10^8 */
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 1 <= q < 10^6 */
	if (q < 100)
		goto out_q;

	/*  100 <= q < 10^6 */
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	/* 1 <= r < 10^4 */
	if (r < 100)
		goto out_r;

	/* 100 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;
out_q:
	/* 1 <= q < 100 */
	r = q;
out_r:
	/* 1 <= r < 100 */
	*((u16 *)buf) = decpair[r];
	buf += r < 10 ? 1 : 2;
	return buf;
}

#if BITS_PER_LONG == 64 && BITS_PER_LONG_LONG == 64
static noinline_for_stack
char *put_dec_full8(char *buf, unsigned r)
{
	unsigned q;

	/* 0 <= r < 10^8 */
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 0 <= q < 10^6 */
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	/* 0 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 0 <= q < 100 */
	*((u16 *)buf) = decpair[q];
	buf += 2;
	return buf;
}

static noinline_for_stack
char *put_dec(char *buf, unsigned long long n)
{
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	/* 1 <= n <= 1.6e11 */
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	/* 1 <= n < 1e8 */
	return put_dec_trunc8(buf, n);
}

#elif BITS_PER_LONG == 32 && BITS_PER_LONG_LONG == 64

static void
put_dec_full4(char *buf, unsigned r)
{
	unsigned q;

	/* 0 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;
	/* 0 <= q < 100 */
	*((u16 *)buf) = decpair[q];
}

/*
 * Call put_dec_full4 on x % 10000, return x / 10000.
 * The approximation x/10000 == (x * 0x346DC5D7) >> 43
 * holds for all x < 1,128,869,999.  The largest value this
 * helper will ever be asked to convert is 1,125,520,955.
 * (second call in the put_dec code, assuming n is all-ones).
 */
static noinline_for_stack
unsigned put_dec_helper4(char *buf, unsigned x)
{
        uint32_t q = (x * (uint64_t)0x346DC5D7) >> 43;

        put_dec_full4(buf, x - q * 10000);
        return q;
}

/* Based on code by Douglas W. Jones found at
 * <http://www.cs.uiowa.edu/~jones/bcd/decimal.html#sixtyfour>
 * (with permission from the author).
 * Performs no 64-bit division and hence should be fast on 32-bit machines.
 */
static
char *put_dec(char *buf, unsigned long long n)
{
	uint32_t d3, d2, d1, q, h;

	if (n < 100*1000*1000)
		return put_dec_trunc8(buf, n);

	d1  = ((uint32_t)n >> 16); /* implicit "& 0xffff" */
	h   = (n >> 32);
	d2  = (h      ) & 0xffff;
	d3  = (h >> 16); /* implicit "& 0xffff" */

	/* n = 2^48 d3 + 2^32 d2 + 2^16 d1 + d0
	     = 281_4749_7671_0656 d3 + 42_9496_7296 d2 + 6_5536 d1 + d0 */
	q   = 656 * d3 + 7296 * d2 + 5536 * d1 + ((uint32_t)n & 0xffff);
	q = put_dec_helper4(buf, q);

	q += 7671 * d3 + 9496 * d2 + 6 * d1;
	q = put_dec_helper4(buf+4, q);

	q += 4749 * d3 + 42 * d2;
	q = put_dec_helper4(buf+8, q);

	q += 281 * d3;
	buf += 12;
	if (q)
		buf = put_dec_trunc8(buf, q);
	else while (buf[-1] == '0')
		--buf;

	return buf;
}

#endif

/**
 * prt_u64_minwidth - print a u64, in decimal, with zero padding
 * @out: printbuf to output to
 * @num: u64 to print
 * @width: minimum width
 */
void prt_u64_minwidth(struct printbuf *out, u64 num, unsigned width)
{
	/* put_dec requires 2-byte alignment of the buffer. */
	char tmp[sizeof(num) * 3] __aligned(2);
	unsigned len = put_dec(tmp, num) - tmp;

	printbuf_make_room(out, max(len, width));

	if (width > len)
		__prt_chars_reserved(out, ' ', width - len);

	while (len)
		__prt_char_reserved(out, tmp[--len]);
	printbuf_nul_terminate(out);
}

/**
 * prt_u64 - print a simple u64, in decimal
 * @out: printbuf to output to
 * @num: u64 to print
 */
void prt_u64(struct printbuf *out, u64 num)
{
	prt_u64_minwidth(out, num, 0);
}
EXPORT_SYMBOL_GPL(prt_u64);

/*
 * Convert passed number to decimal string.
 * Returns the length of string.  On buffer overflow, returns 0.
 *
 * Consider switching to printbufs and using prt_u64() or prt_u64_minwith()
 * instead.
 */
int num_to_str(char *buf, int size, unsigned long long num, unsigned int width)
{
	struct printbuf out = PRINTBUF_EXTERN(buf, size);

	prt_u64_minwidth(&out, num, width);
	return out.pos;
}

#define SIGN	1		/* unsigned/signed, must be 1 */
#define LEFT	2		/* left justified */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define ZEROPAD	16		/* pad with zero, must be 16 == '0' - ' ' */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */

static_assert(SIGN == 1);
static_assert(ZEROPAD == ('0' - ' '));
static_assert(SMALL == ('a' ^ 'A'));

enum format_type {
	FORMAT_TYPE_NONE, /* Just a string part */
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF
};

struct printf_spec {
	unsigned int	type:8;		/* format_type enum */
	signed int	field_width:24;	/* width of output field */
	unsigned int	flags:8;	/* flags to number() */
	unsigned int	base:8;		/* number base, 8, 10 or 16 only */
	signed int	precision:16;	/* # of digits/chars */
} __packed;
static_assert(sizeof(struct printf_spec) == 8);

#define FIELD_WIDTH_MAX ((1 << 23) - 1)
#define PRECISION_MAX ((1 << 15) - 1)

static noinline_for_stack
void number(struct printbuf *out, unsigned long long num,
	    struct printf_spec spec)
{
	/* put_dec requires 2-byte alignment of the buffer. */
	char tmp[3 * sizeof(num)] __aligned(2);
	char sign = 0;
	/* locase = 0 or 0x20. ORing digits or letters with 'locase'
	 * produces same digits or (maybe lowercased) letters */
	char locase = (spec.flags & SMALL);
	int need_pfx = ((spec.flags & SPECIAL) && spec.base != 10);
	bool is_zero = num == 0LL;
	int field_width = spec.field_width;
	int precision = spec.precision;
	int nr_digits = 0;
	int output_bytes = 0;

	if (spec.flags & LEFT)
		spec.flags &= ~ZEROPAD;
	if (spec.flags & SIGN) {
		if ((signed long long)num < 0) {
			sign = '-';
			num = -(signed long long)num;
			output_bytes++;
		} else if (spec.flags & PLUS) {
			sign = '+';
			output_bytes++;
		} else if (spec.flags & SPACE) {
			sign = ' ';
			output_bytes++;
		}
	}
	if (need_pfx) {
		if (spec.base == 16)
			output_bytes += 2;
		else if (!is_zero)
			output_bytes++;
	}

	/* generate full string in tmp[], in reverse order */
	if (spec.base == 10) {
		nr_digits = put_dec(tmp, num) - tmp;
	} else { /* 8 or 16 */
		int mask = spec.base - 1;
		int shift = ilog2((unsigned) spec.base);

		do {
			tmp[nr_digits++] = (hex_asc_upper[((unsigned char)num) & mask] | locase);
			num >>= shift;
		} while (num);
	}

	/* printing 100 using %2d gives "100", not "00" */
	precision = max(nr_digits, precision);
	output_bytes += precision;
	field_width = max(0, field_width - output_bytes);

	printbuf_make_room(out, field_width + output_bytes);

	/* leading space padding */
	if (!(spec.flags & (ZEROPAD | LEFT)) && field_width) {
		__prt_chars_reserved(out, ' ', field_width);
		field_width = 0;
	}

	/* sign */
	if (sign)
		__prt_char_reserved(out, sign);

	/* "0x" / "0" prefix */
	if (need_pfx) {
		if (spec.base == 16 || !is_zero)
			__prt_char_reserved(out, '0');
		if (spec.base == 16)
			__prt_char_reserved(out, 'X' | locase);
	}

	/* zero padding */
	if (!(spec.flags & LEFT) && field_width)
		__prt_chars_reserved(out, '0', field_width);

	/* zero padding from precision */
	if (precision > nr_digits)
		__prt_chars_reserved(out, '0', precision - nr_digits);

	/* actual digits of result */
	while (--nr_digits >= 0)
		__prt_char_reserved(out, tmp[nr_digits]);

	/* trailing space padding */
	if ((spec.flags & LEFT) && field_width)
		__prt_chars_reserved(out, ' ', field_width);

	printbuf_nul_terminate(out);
}

static noinline_for_stack
void special_hex_number(struct printbuf *out, unsigned long long num, int size)
{
	struct printf_spec spec;

	spec.type = FORMAT_TYPE_PTR;
	spec.field_width = 2 + 2 * size;	/* 0x + hex */
	spec.flags = SPECIAL | SMALL | ZEROPAD;
	spec.base = 16;
	spec.precision = -1;

	number(out, num, spec);
}

/*
 * inserts @spaces spaces @len from the end of @out
 */
static void move_right(struct printbuf *out,
		       unsigned len, unsigned spaces)
{
	unsigned move_src = out->pos - len;
	unsigned move_dst = move_src + spaces;
	unsigned remaining_from_dst = move_dst < out->size ? out->size - move_dst : 0;
	unsigned remaining_from_src = move_src < out->size ? out->size - move_src : 0;

	BUG_ON(len > out->pos);

	memmove(out->buf + move_dst,
		out->buf + move_src,
		min(remaining_from_dst, len));
	memset(out->buf + move_src, ' ',
	       min(remaining_from_src, spaces));
	out->pos += spaces;
}

/*
 * Handle field width padding for a string.
 * @buf: current buffer position
 * @n: length of string
 * @end: end of output buffer
 * @spec: for field width and flags
 * Returns: new buffer position after padding.
 */
static noinline_for_stack
void widen_string(struct printbuf *out, int n,
		  struct printf_spec spec)
{
	unsigned spaces;

	if (likely(n >= spec.field_width))
		return;
	/* we want to pad the sucker */
	spaces = spec.field_width - n;
	if (!(spec.flags & LEFT))
		move_right(out, n, spaces);
	else
		prt_chars(out, ' ', spaces);
}

static void do_width_precision(struct printbuf *out, unsigned prev_pos,
			       struct printf_spec spec)
{
	unsigned n = out->pos - prev_pos;

	if (n > spec.precision) {
		out->pos -= n - spec.precision;
		n = spec.precision;
	}

	widen_string(out, n, spec);
}

/* Handle string from a well known address. */
static void string_nocheck(struct printbuf *out,
			   const char *s,
			   struct printf_spec spec)
{
	int len = strnlen(s, spec.precision);

	prt_bytes(out, s, len);
	widen_string(out, len, spec);
}

static void err_ptr(struct printbuf *out, void *ptr,
		    struct printf_spec spec)
{
	int err = PTR_ERR(ptr);
	const char *sym = errname(err);

	if (sym) {
		string_nocheck(out, sym, spec);
	} else {
		/*
		 * Somebody passed ERR_PTR(-1234) or some other non-existing
		 * Efoo - or perhaps CONFIG_SYMBOLIC_ERRNAME=n. Fall back to
		 * printing it as its decimal representation.
		 */
		spec.flags |= SIGN;
		spec.base = 10;
		number(out, err, spec);
	}
}

/* Be careful: error messages must fit into the given buffer. */
static void error_string_spec(struct printbuf *out, const char *s,
			 struct printf_spec spec)
{
	/*
	 * Hard limit to avoid a completely insane messages. It actually
	 * works pretty well because most error messages are in
	 * the many pointer format modifiers.
	 */
	if (spec.precision == -1)
		spec.precision = 2 * sizeof(void *);

	string_nocheck(out, s, spec);
}

/*
 * Do not call any complex external code here. Nested printk()/vsprintf()
 * might cause infinite loops. Failures might break printk() and would
 * be hard to debug.
 */
static const char *check_pointer_msg(const void *ptr)
{
	if (!ptr)
		return "(null)";

	if ((unsigned long)ptr < PAGE_SIZE || IS_ERR_VALUE(ptr))
		return "(efault)";

	return NULL;
}

static int check_pointer_spec(struct printbuf *out,
			 const void *ptr,
			 struct printf_spec spec)
{
	const char *err_msg;

	err_msg = check_pointer_msg(ptr);
	if (err_msg) {
		error_string_spec(out, err_msg, spec);
		return -EFAULT;
	}

	return 0;
}

static noinline_for_stack
void string_spec(struct printbuf *out,
	    const char *s,
	    struct printf_spec spec)
{
	if (check_pointer_spec(out, s, spec))
		return;

	string_nocheck(out, s, spec);
}

static void error_string(struct printbuf *out, const char *s)
{
	/*
	 * Hard limit to avoid a completely insane messages. It actually
	 * works pretty well because most error messages are in
	 * the many pointer format modifiers.
	 */
	prt_bytes(out, s, min(strlen(s), 2 * sizeof(void *)));
}

static int check_pointer(struct printbuf *out, const void *ptr)
{
	const char *err_msg;

	err_msg = check_pointer_msg(ptr);
	if (err_msg) {
		error_string(out, err_msg);
		return -EFAULT;
	}

	return 0;
}

static void string(struct printbuf *out, const char *s)
{
	if (check_pointer(out, s))
		return;

	prt_str(out, s);
}

static void pointer_string(struct printbuf *out,
			   const void *ptr,
			   struct printf_spec spec)
{
	spec.base = 16;
	spec.flags |= SMALL;
	if (spec.field_width == -1) {
		spec.field_width = 2 * sizeof(ptr);
		spec.flags |= ZEROPAD;
	}

	number(out, (unsigned long int)ptr, spec);
}

/* Make pointers available for printing early in the boot sequence. */
static int debug_boot_weak_hash __ro_after_init;

static int __init debug_boot_weak_hash_enable(char *str)
{
	debug_boot_weak_hash = 1;
	pr_info("debug_boot_weak_hash enabled\n");
	return 0;
}
early_param("debug_boot_weak_hash", debug_boot_weak_hash_enable);

static bool filled_random_ptr_key __read_mostly;
static siphash_key_t ptr_key __read_mostly;
static void fill_ptr_key_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(fill_ptr_key_work, fill_ptr_key_workfn);

static void fill_ptr_key_workfn(struct work_struct *work)
{
	if (!rng_is_initialized()) {
		queue_delayed_work(system_unbound_wq, &fill_ptr_key_work, HZ  * 2);
		return;
	}

	get_random_bytes(&ptr_key, sizeof(ptr_key));

	/* Pairs with smp_rmb() before reading ptr_key. */
	smp_wmb();
	WRITE_ONCE(filled_random_ptr_key, true);
}

static int __init vsprintf_init_hashval(void)
{
	fill_ptr_key_workfn(NULL);
	return 0;
}
subsys_initcall(vsprintf_init_hashval)

/* Maps a pointer to a 32 bit unique identifier. */
static inline int __ptr_to_hashval(const void *ptr, unsigned long *hashval_out)
{
	unsigned long hashval;

	if (!READ_ONCE(filled_random_ptr_key))
		return -EBUSY;

	/* Pairs with smp_wmb() after writing ptr_key. */
	smp_rmb();

#ifdef CONFIG_64BIT
	hashval = (unsigned long)siphash_1u64((u64)ptr, &ptr_key);
	/*
	 * Mask off the first 32 bits, this makes explicit that we have
	 * modified the address (and 32 bits is plenty for a unique ID).
	 */
	hashval = hashval & 0xffffffff;
#else
	hashval = (unsigned long)siphash_1u32((u32)ptr, &ptr_key);
#endif
	*hashval_out = hashval;
	return 0;
}

int ptr_to_hashval(const void *ptr, unsigned long *hashval_out)
{
	return __ptr_to_hashval(ptr, hashval_out);
}

static void ptr_to_id(struct printbuf *out,
		      const void *ptr,
		      struct printf_spec spec)
{
	const char *str = sizeof(ptr) == 8 ? "(____ptrval____)" : "(ptrval)";
	unsigned long hashval;
	int ret;

	/*
	 * Print the real pointer value for NULL and error pointers,
	 * as they are not actual addresses.
	 */
	if (IS_ERR_OR_NULL(ptr))
		return pointer_string(out, ptr, spec);

	/* When debugging early boot use non-cryptographically secure hash. */
	if (unlikely(debug_boot_weak_hash)) {
		hashval = hash_long((unsigned long)ptr, 32);
		return pointer_string(out, (const void *)hashval, spec);
	}

	ret = __ptr_to_hashval(ptr, &hashval);
	if (ret) {
		spec.field_width = 2 * sizeof(ptr);
		/* string length must be less than default_width */
		return error_string_spec(out, str, spec);
	}

	pointer_string(out, (const void *)hashval, spec);
}

static void default_pointer(struct printbuf *out,
			    const void *ptr,
			    struct printf_spec spec)
{
	/*
	 * default is to _not_ leak addresses, so hash before printing,
	 * unless no_hash_pointers is specified on the command line.
	 */
	if (unlikely(no_hash_pointers))
		return pointer_string(out, ptr, spec);

	return ptr_to_id(out, ptr, spec);
}

int kptr_restrict __read_mostly;

static noinline_for_stack
void restricted_pointer(struct printbuf *out,
			const void *ptr,
			struct printf_spec spec)
{
	switch (kptr_restrict) {
	case 0:
		/* Handle as %p, hash and do _not_ leak addresses. */
		return default_pointer(out, ptr, spec);
	case 1: {
		const struct cred *cred;

		/*
		 * kptr_restrict==1 cannot be used in IRQ context
		 * because its test for CAP_SYSLOG would be meaningless.
		 */
		if (in_irq() || in_serving_softirq() || in_nmi()) {
			if (spec.field_width == -1)
				spec.field_width = 2 * sizeof(ptr);
			return error_string_spec(out, "pK-error", spec);
		}

		/*
		 * Only print the real pointer value if the current
		 * process has CAP_SYSLOG and is running with the
		 * same credentials it started with. This is because
		 * access to files is checked at open() time, but %pK
		 * checks permission at read() time. We don't want to
		 * leak pointer values if a binary opens a file using
		 * %pK and then elevates privileges before reading it.
		 */
		cred = current_cred();
		if (!has_capability_noaudit(current, CAP_SYSLOG) ||
		    !uid_eq(cred->euid, cred->uid) ||
		    !gid_eq(cred->egid, cred->gid))
			ptr = NULL;
		break;
	}
	case 2:
	default:
		/* Always print 0's for %pK */
		ptr = NULL;
		break;
	}

	return pointer_string(out, ptr, spec);
}

static noinline_for_stack
void dentry_name(struct printbuf *out, const struct dentry *d,
		 const char *fmt)
{
	const char *array[4];
	const struct dentry *p;
	int i, depth;

	switch (fmt[1]) {
		case '2': case '3': case '4':
			depth = fmt[1] - '0';
			break;
		default:
			depth = 1;
	}

	rcu_read_lock();
	for (i = 0; i < depth; i++, d = p) {
		if (check_pointer(out, d)) {
			rcu_read_unlock();
			return;
		}

		p = READ_ONCE(d->d_parent);
		array[i] = READ_ONCE(d->d_name.name);
		if (p == d) {
			if (i)
				array[i] = "";
			i++;
			break;
		}
	}
	while (1) {
		prt_str(out, array[--i]);
		if (!i)
			break;
		prt_char(out, '/');
	}
	rcu_read_unlock();
}

static noinline_for_stack
void file_dentry_name(struct printbuf *out, const struct file *f,
		      const char *fmt)
{
	if (check_pointer(out, f))
		return;

	return dentry_name(out, f->f_path.dentry, fmt);
}
#ifdef CONFIG_BLOCK
static noinline_for_stack
void bdev_name(struct printbuf *out, struct block_device *bdev)
{
	struct gendisk *hd;

	if (check_pointer(out, bdev))
		return;

	hd = bdev->bd_disk;
	string(out, hd->disk_name);
	if (bdev->bd_partno) {
		if (isdigit(hd->disk_name[strlen(hd->disk_name)-1]))
			prt_char(out, 'p');
		prt_u64(out, bdev->bd_partno);
	}
}
#endif

static noinline_for_stack
void symbol_string(struct printbuf *out, void *ptr,
		   const char *fmt)
{
	unsigned long value;
#ifdef CONFIG_KALLSYMS
	char sym[KSYM_SYMBOL_LEN];
#endif

	if (fmt[1] == 'R')
		ptr = __builtin_extract_return_addr(ptr);
	value = (unsigned long)ptr;

#ifdef CONFIG_KALLSYMS
	if (*fmt == 'B' && fmt[1] == 'b')
		sprint_backtrace_build_id(sym, value);
	else if (*fmt == 'B')
		sprint_backtrace(sym, value);
	else if (*fmt == 'S' && (fmt[1] == 'b' || (fmt[1] == 'R' && fmt[2] == 'b')))
		sprint_symbol_build_id(sym, value);
	else if (*fmt != 's')
		sprint_symbol(sym, value);
	else
		sprint_symbol_no_offset(sym, value);

	prt_str(out, sym);
#else
	special_hex_number(out, value, sizeof(void *));
#endif
}

static const struct printf_spec default_flag_spec = {
	.base = 16,
	.precision = -1,
	.flags = SPECIAL | SMALL,
};

static const struct printf_spec default_dec_spec = {
	.base = 10,
	.precision = -1,
};

static noinline_for_stack
void resource_string(struct printbuf *out, struct resource *res,
		     int decode)
{
#ifndef IO_RSRC_PRINTK_SIZE
#define IO_RSRC_PRINTK_SIZE	6
#endif

#ifndef MEM_RSRC_PRINTK_SIZE
#define MEM_RSRC_PRINTK_SIZE	10
#endif
	static const struct printf_spec io_spec = {
		.base = 16,
		.field_width = IO_RSRC_PRINTK_SIZE,
		.precision = -1,
		.flags = SPECIAL | SMALL | ZEROPAD,
	};
	static const struct printf_spec mem_spec = {
		.base = 16,
		.field_width = MEM_RSRC_PRINTK_SIZE,
		.precision = -1,
		.flags = SPECIAL | SMALL | ZEROPAD,
	};
	static const struct printf_spec bus_spec = {
		.base = 16,
		.field_width = 2,
		.precision = -1,
		.flags = SMALL | ZEROPAD,
	};
	static const struct printf_spec str_spec = {
		.field_width = -1,
		.precision = 10,
		.flags = LEFT,
	};

	/* 32-bit res (sizeof==4): 10 chars in dec, 10 in hex ("0x" + 8)
	 * 64-bit res (sizeof==8): 20 chars in dec, 18 in hex ("0x" + 16) */
#define RSRC_BUF_SIZE		((2 * sizeof(resource_size_t)) + 4)
#define FLAG_BUF_SIZE		(2 * sizeof(res->flags))
#define DECODED_BUF_SIZE	sizeof("[mem - 64bit pref window disabled]")
#define RAW_BUF_SIZE		sizeof("[mem - flags 0x]")
	const struct printf_spec *specp;

	if (check_pointer(out, res))
		return;

	prt_char(out, '[');
	if (res->flags & IORESOURCE_IO) {
		string_nocheck(out, "io  ", str_spec);
		specp = &io_spec;
	} else if (res->flags & IORESOURCE_MEM) {
		string_nocheck(out, "mem ", str_spec);
		specp = &mem_spec;
	} else if (res->flags & IORESOURCE_IRQ) {
		string_nocheck(out, "irq ", str_spec);
		specp = &default_dec_spec;
	} else if (res->flags & IORESOURCE_DMA) {
		string_nocheck(out, "dma ", str_spec);
		specp = &default_dec_spec;
	} else if (res->flags & IORESOURCE_BUS) {
		string_nocheck(out, "bus ", str_spec);
		specp = &bus_spec;
	} else {
		string_nocheck(out, "??? ", str_spec);
		specp = &mem_spec;
		decode = 0;
	}
	if (decode && res->flags & IORESOURCE_UNSET) {
		string_nocheck(out, "size ", str_spec);
		number(out, resource_size(res), *specp);
	} else {
		number(out, res->start, *specp);
		if (res->start != res->end) {
			prt_char(out, '-');
			number(out, res->end, *specp);
		}
	}
	if (decode) {
		if (res->flags & IORESOURCE_MEM_64)
			string_nocheck(out, " 64bit", str_spec);
		if (res->flags & IORESOURCE_PREFETCH)
			string_nocheck(out, " pref", str_spec);
		if (res->flags & IORESOURCE_WINDOW)
			string_nocheck(out, " window", str_spec);
		if (res->flags & IORESOURCE_DISABLED)
			string_nocheck(out, " disabled", str_spec);
	} else {
		string_nocheck(out, " flags ", str_spec);
		number(out, res->flags, default_flag_spec);
	}
	prt_char(out, ']');

	printbuf_nul_terminate(out);
}

static noinline_for_stack
void hex_string(struct printbuf *out, u8 *addr,
		struct printf_spec spec, const char *fmt)
{
	int i, len = 1;		/* if we pass '%ph[CDN]', field width remains
				   negative value, fallback to the default */
	char separator;

	if (spec.field_width == 0)
		/* nothing to print */
		return;

	if (check_pointer_spec(out, addr, spec))
		return;

	switch (fmt[1]) {
	case 'C':
		separator = ':';
		break;
	case 'D':
		separator = '-';
		break;
	case 'N':
		separator = 0;
		break;
	default:
		separator = ' ';
		break;
	}

	if (spec.field_width > 0)
		len = min_t(int, spec.field_width, 64);

	for (i = 0; i < len; ++i) {
		__prt_char(out, hex_asc_hi(addr[i]));
		__prt_char(out, hex_asc_lo(addr[i]));

		if (separator && i != len - 1)
			__prt_char(out, separator);
	}

	printbuf_nul_terminate(out);
}

static noinline_for_stack
void bitmap_string(struct printbuf *out, const unsigned long *bitmap,
		   struct printf_spec spec, const char *fmt)
{
	const int CHUNKSZ = 32;
	int nr_bits = max_t(int, spec.field_width, 0);
	int i, chunksz;
	bool first = true;

	if (check_pointer_spec(out, bitmap, spec))
		return;

	/* reused to print numbers */
	spec = (struct printf_spec){ .flags = SMALL | ZEROPAD, .base = 16 };

	chunksz = nr_bits & (CHUNKSZ - 1);
	if (chunksz == 0)
		chunksz = CHUNKSZ;

	i = ALIGN(nr_bits, CHUNKSZ) - CHUNKSZ;
	for (; i >= 0; i -= CHUNKSZ) {
		u32 chunkmask, val;
		int word, bit;

		chunkmask = ((1ULL << chunksz) - 1);
		word = i / BITS_PER_LONG;
		bit = i % BITS_PER_LONG;
		val = (bitmap[word] >> bit) & chunkmask;

		if (!first)
			prt_char(out, ',');
		first = false;

		spec.field_width = DIV_ROUND_UP(chunksz, 4);
		number(out, val, spec);

		chunksz = CHUNKSZ;
	}
}

static noinline_for_stack
void bitmap_list_string(struct printbuf *out, const unsigned long *bitmap,
			struct printf_spec spec, const char *fmt)
{
	int nr_bits = max_t(int, spec.field_width, 0);
	bool first = true;
	int rbot, rtop;

	if (check_pointer_spec(out, bitmap, spec))
		return ;

	for_each_set_bitrange(rbot, rtop, bitmap, nr_bits) {
		if (!first)
			prt_char(out, ',');
		first = false;

		prt_u64(out, rbot);
		if (rtop == rbot + 1)
			continue;

		prt_char(out, '-');
		prt_u64(out, rtop - 1);
	}
}

static noinline_for_stack
void mac_address_string(struct printbuf *out, u8 *addr,
			const char *fmt)
{
	int i;
	char separator;
	bool reversed = false;

	if (check_pointer(out, addr))
		return;

	switch (fmt[1]) {
	case 'F':
		separator = '-';
		break;

	case 'R':
		reversed = true;
		fallthrough;

	default:
		separator = ':';
		break;
	}

	for (i = 0; i < 6; i++) {
		if (reversed)
			prt_hex_byte(out, addr[5 - i]);
		else
			prt_hex_byte(out, addr[i]);

		if (fmt[0] == 'M' && i != 5)
			prt_char(out, separator);
	}
}

static noinline_for_stack
void ip4_string(struct printbuf *out, const u8 *addr, const char *fmt)
{
	struct printf_spec spec = default_dec_spec;
	int i, index, step;

	if (fmt[0] == 'i')
		spec.precision = 3;

	switch (fmt[2]) {
	case 'h':
#ifdef __BIG_ENDIAN
		index = 0;
		step = 1;
#else
		index = 3;
		step = -1;
#endif
		break;
	case 'l':
		index = 3;
		step = -1;
		break;
	case 'n':
	case 'b':
	default:
		index = 0;
		step = 1;
		break;
	}
	for (i = 0; i < 4; i++) {
		if (i)
			prt_char(out, '.');
		number(out, addr[index], spec);
		index += step;
	}
}

static noinline_for_stack
void ip6_compressed_string(struct printbuf *out, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	bool needcolon = false;
	bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				__prt_char(out, ':');
			__prt_char(out, ':');
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			__prt_char(out, ':');
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				prt_hex_byte(out, hi);
			else
				__prt_char(out, hex_asc_lo(hi));
			prt_hex_byte(out, lo);
		}
		else if (lo > 0x0f)
			prt_hex_byte(out, lo);
		else
			__prt_char(out, hex_asc_lo(lo));
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			__prt_char(out, ':');
		ip4_string(out, &in6.s6_addr[12], "I4");
	}
}

static noinline_for_stack
void ip6_string(struct printbuf *out, const char *addr, const char *fmt)
{
	int i;

	for (i = 0; i < 8; i++) {
		prt_hex_byte(out, *addr++);
		prt_hex_byte(out, *addr++);
		if (fmt[0] == 'I' && i != 7)
			prt_char(out, ':');
	}
}

static noinline_for_stack
void ip6_addr_string(struct printbuf *out, const u8 *addr,
		     const char *fmt)
{
	if (fmt[0] == 'I' && fmt[2] == 'c')
		ip6_compressed_string(out, addr);
	else
		ip6_string(out, addr, fmt);
}

static noinline_for_stack
void ip6_addr_string_sa(struct printbuf *out,
			const struct sockaddr_in6 *sa,
			const char *fmt)
{
	bool have_p = false, have_s = false, have_f = false, have_c = false;
	const u8 *addr = (const u8 *) &sa->sin6_addr;
	char fmt6[2] = { fmt[0], '6' };

	fmt++;
	while (isalpha(*++fmt)) {
		switch (*fmt) {
		case 'p':
			have_p = true;
			break;
		case 'f':
			have_f = true;
			break;
		case 's':
			have_s = true;
			break;
		case 'c':
			have_c = true;
			break;
		}
	}

	if (have_p || have_s || have_f)
		prt_char(out, '[');

	if (fmt6[0] == 'I' && have_c)
		ip6_compressed_string(out, addr);
	else
		ip6_string(out, addr, fmt6);

	if (have_p || have_s || have_f)
		prt_char(out, ']');

	if (have_p) {
		prt_char(out, ':');
		prt_u64(out, ntohs(sa->sin6_port));
	}
	if (have_f) {
		prt_char(out, '/');
		prt_u64(out, ntohl(sa->sin6_flowinfo & IPV6_FLOWINFO_MASK));
	}
	if (have_s) {
		prt_char(out, '%');
		prt_u64(out, sa->sin6_scope_id);
	}
}

static noinline_for_stack
void ip4_addr_string_sa(struct printbuf *out, const struct sockaddr_in *sa,
			const char *fmt)
{
	bool have_p = false;
	const u8 *addr = (const u8 *) &sa->sin_addr.s_addr;
	char fmt4[3] = { fmt[0], '4', 0 };

	fmt++;
	while (isalpha(*++fmt)) {
		switch (*fmt) {
		case 'p':
			have_p = true;
			break;
		case 'h':
		case 'l':
		case 'n':
		case 'b':
			fmt4[2] = *fmt;
			break;
		}
	}

	ip4_string(out, addr, fmt4);
	if (have_p) {
		prt_char(out, ':');
		prt_u64(out, ntohs(sa->sin_port));
	}
}

static noinline_for_stack
void ip_addr_string(struct printbuf *out, const void *ptr,
		    const char *fmt)
{
	char *err_fmt_msg;

	if (check_pointer(out, ptr))
		return;

	switch (fmt[1]) {
	case '6':
		return ip6_addr_string(out, ptr, fmt);
	case '4':
		return ip4_string(out, ptr, fmt);
	case 'S': {
		const union {
			struct sockaddr		raw;
			struct sockaddr_in	v4;
			struct sockaddr_in6	v6;
		} *sa = ptr;

		switch (sa->raw.sa_family) {
		case AF_INET:
			return ip4_addr_string_sa(out, &sa->v4, fmt);
		case AF_INET6:
			return ip6_addr_string_sa(out, &sa->v6, fmt);
		default:
			return error_string(out, "(einval)");
		}}
	}

	err_fmt_msg = fmt[0] == 'i' ? "(%pi?)" : "(%pI?)";
	error_string(out, err_fmt_msg);
}

static noinline_for_stack
void escaped_string(struct printbuf *out, u8 *addr,
		    struct printf_spec spec, const char *fmt)
{
	bool found = true;
	int count = 1;
	unsigned int flags = 0;
	int len;

	if (spec.field_width == 0)
		return;				/* nothing to print */

	if (check_pointer_spec(out, addr, spec))
		return;

	do {
		switch (fmt[count++]) {
		case 'a':
			flags |= ESCAPE_ANY;
			break;
		case 'c':
			flags |= ESCAPE_SPECIAL;
			break;
		case 'h':
			flags |= ESCAPE_HEX;
			break;
		case 'n':
			flags |= ESCAPE_NULL;
			break;
		case 'o':
			flags |= ESCAPE_OCTAL;
			break;
		case 'p':
			flags |= ESCAPE_NP;
			break;
		case 's':
			flags |= ESCAPE_SPACE;
			break;
		default:
			found = false;
			break;
		}
	} while (found);

	if (!flags)
		flags = ESCAPE_ANY_NP;

	len = spec.field_width < 0 ? 1 : spec.field_width;
	prt_escaped_string(out, addr, len, flags, NULL);
}

static void va_format(struct printbuf *out,
		      struct va_format *va_fmt,
		      struct printf_spec spec, const char *fmt)
{
	va_list va;

	if (check_pointer_spec(out, va_fmt, spec))
		return;

	va_copy(va, *va_fmt->va);
	prt_vprintf(out, va_fmt->fmt, va);
	va_end(va);
}

static noinline_for_stack
void uuid_string(struct printbuf *out, const u8 *addr, const char *fmt)
{
	int i;
	const u8 *index = uuid_index;
	bool uc = false;

	if (check_pointer(out, addr))
		return;

	switch (*(++fmt)) {
	case 'L':
		uc = true;
		fallthrough;
	case 'l':
		index = guid_index;
		break;
	case 'B':
		uc = true;
		break;
	}

	for (i = 0; i < 16; i++) {
		if (uc)
			prt_hex_byte_upper(out, addr[index[i]]);
		else
			prt_hex_byte(out, addr[index[i]]);
		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			prt_char(out, '-');
			break;
		}
	}
}

static noinline_for_stack
void netdev_bits(struct printbuf *out, const void *addr,
		 const char *fmt)
{
	unsigned long long num;
	int size;

	if (check_pointer(out, addr))
		return;

	switch (fmt[1]) {
	case 'F':
		num = *(const netdev_features_t *)addr;
		size = sizeof(netdev_features_t);
		special_hex_number(out, num, size);
		break;
	default:
		error_string(out, "(%pN?)");
		break;
	}
}

static noinline_for_stack
void fourcc_string(struct printbuf *out, const u32 *fourcc,
		   const char *fmt)
{
	unsigned int i;
	u32 orig, val;

	if (fmt[1] != 'c' || fmt[2] != 'c')
		return error_string(out, "(%p4?)");

	if (check_pointer(out, fourcc))
		return;

	orig = get_unaligned(fourcc);
	val = orig & ~BIT(31);

	for (i = 0; i < sizeof(u32); i++) {
		unsigned char c = val >> (i * 8);

		/* Print non-control ASCII characters as-is, dot otherwise */
		prt_char(out, isascii(c) && isprint(c) ? c : '.');
	}

	prt_char(out, ' ');
	prt_str(out, orig & BIT(31) ? "big-endian" : "little-endian");

	prt_char(out, ' ');
	prt_char(out, '(');
	special_hex_number(out, orig, sizeof(u32));
	prt_char(out, ')');
}

static noinline_for_stack
void address_val(struct printbuf *out, const void *addr,
		 const char *fmt)
{
	unsigned long long num;
	int size;

	if (check_pointer(out, addr))
		return;

	switch (fmt[1]) {
	case 'd':
		num = *(const dma_addr_t *)addr;
		size = sizeof(dma_addr_t);
		break;
	case 'p':
	default:
		num = *(const phys_addr_t *)addr;
		size = sizeof(phys_addr_t);
		break;
	}

	special_hex_number(out, num, size);
}

static noinline_for_stack
void date_str(struct printbuf *out,
	      const struct rtc_time *tm, bool r)
{
	int year = tm->tm_year + (r ? 0 : 1900);
	int mon = tm->tm_mon + (r ? 0 : 1);

	prt_u64_minwidth(out, year, 4);
	prt_char(out, '-');
	prt_u64_minwidth(out, mon, 2);
	prt_char(out, '-');
	prt_u64_minwidth(out, tm->tm_mday, 2);
}

static noinline_for_stack
void time_str(struct printbuf *out, const struct rtc_time *tm, bool r)
{
	prt_u64_minwidth(out, tm->tm_hour, 2);
	prt_char(out, ':');
	prt_u64_minwidth(out, tm->tm_min, 2);
	prt_char(out, ':');
	prt_u64_minwidth(out, tm->tm_sec, 2);
}

static noinline_for_stack
void rtc_str(struct printbuf *out, const struct rtc_time *tm,
	     const char *fmt)
{
	bool have_t = true, have_d = true;
	bool raw = false, iso8601_separator = true;
	bool found = true;
	int count = 2;

	if (check_pointer(out, tm))
		return;

	switch (fmt[count]) {
	case 'd':
		have_t = false;
		count++;
		break;
	case 't':
		have_d = false;
		count++;
		break;
	}

	do {
		switch (fmt[count++]) {
		case 'r':
			raw = true;
			break;
		case 's':
			iso8601_separator = false;
			break;
		default:
			found = false;
			break;
		}
	} while (found);

	if (have_d)
		date_str(out, tm, raw);
	if (have_d && have_t)
		prt_char(out, iso8601_separator ? 'T' : ' ');
	if (have_t)
		time_str(out, tm, raw);
}

static noinline_for_stack
void time64_str(struct printbuf *out, const time64_t time,
		const char *fmt)
{
	struct rtc_time rtc_time;
	struct tm tm;

	time64_to_tm(time, 0, &tm);

	rtc_time.tm_sec = tm.tm_sec;
	rtc_time.tm_min = tm.tm_min;
	rtc_time.tm_hour = tm.tm_hour;
	rtc_time.tm_mday = tm.tm_mday;
	rtc_time.tm_mon = tm.tm_mon;
	rtc_time.tm_year = tm.tm_year;
	rtc_time.tm_wday = tm.tm_wday;
	rtc_time.tm_yday = tm.tm_yday;

	rtc_time.tm_isdst = 0;

	rtc_str(out, &rtc_time, fmt);
}

static noinline_for_stack
void time_and_date(struct printbuf *out, void *ptr,
		   const char *fmt)
{
	switch (fmt[1]) {
	case 'R':
		return rtc_str(out, (const struct rtc_time *)ptr, fmt);
	case 'T':
		return time64_str(out, *(const time64_t *)ptr, fmt);
	default:
		return error_string(out, "(%pt?)");
	}
}

static noinline_for_stack
void clock(struct printbuf *out, struct clk *clk,
	   struct printf_spec spec, const char *fmt)
{
	if (!IS_ENABLED(CONFIG_HAVE_CLK))
		return error_string_spec(out, "(%pC?)", spec);

	if (check_pointer_spec(out, clk, spec))
		return;

	switch (fmt[1]) {
	case 'n':
	default:
#ifdef CONFIG_COMMON_CLK
		return string_spec(out, __clk_get_name(clk), spec);
#else
		return ptr_to_id(out, clk, spec);
#endif
	}
}

static
void format_flags(struct printbuf *out, unsigned long flags,
		  const struct trace_print_flags *names)
{
	unsigned long mask;

	for ( ; flags && names->name; names++) {
		mask = names->mask;
		if ((flags & mask) != mask)
			continue;

		string(out, names->name);

		flags &= ~mask;
		if (flags)
			prt_char(out, '|');
	}

	if (flags)
		number(out, flags, default_flag_spec);
}

struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

static const struct page_flags_fields pff[] = {
	{SECTIONS_WIDTH, SECTIONS_PGSHIFT, SECTIONS_MASK,
	 &default_dec_spec, "section"},
	{NODES_WIDTH, NODES_PGSHIFT, NODES_MASK,
	 &default_dec_spec, "node"},
	{ZONES_WIDTH, ZONES_PGSHIFT, ZONES_MASK,
	 &default_dec_spec, "zone"},
	{LAST_CPUPID_WIDTH, LAST_CPUPID_PGSHIFT, LAST_CPUPID_MASK,
	 &default_flag_spec, "lastcpupid"},
	{KASAN_TAG_WIDTH, KASAN_TAG_PGSHIFT, KASAN_TAG_MASK,
	 &default_flag_spec, "kasantag"},
};

static
void format_page_flags(struct printbuf *out, unsigned long flags)
{
	unsigned long main_flags = flags & PAGEFLAGS_MASK;
	bool append = false;
	int i;

	number(out, flags, default_flag_spec);
	prt_char(out, '(');

	/* Page flags from the main area. */
	if (main_flags) {
		format_flags(out, main_flags, pageflag_names);
		append = true;
	}

	/* Page flags from the fields area */
	for (i = 0; i < ARRAY_SIZE(pff); i++) {
		/* Skip undefined fields. */
		if (!pff[i].width)
			continue;

		/* Format: Flag Name + '=' (equals sign) + Number + '|' (separator) */
		if (append)
			prt_char(out, '|');

		string(out, pff[i].name);
		prt_char(out, '=');
		number(out, (flags >> pff[i].shift) & pff[i].mask, *pff[i].spec);

		append = true;
	}
	prt_char(out, ')');
}

static noinline_for_stack
void flags_string(struct printbuf *out, void *flags_ptr,
		  const char *fmt)
{
	unsigned long flags;
	const struct trace_print_flags *names;

	if (check_pointer(out, flags_ptr))
		return;

	switch (fmt[1]) {
	case 'p':
		return format_page_flags(out, *(unsigned long *)flags_ptr);
	case 'v':
		flags = *(unsigned long *)flags_ptr;
		names = vmaflag_names;
		break;
	case 'g':
		flags = (__force unsigned long)(*(gfp_t *)flags_ptr);
		names = gfpflag_names;
		break;
	default:
		return error_string(out, "(%pG?)");
	}

	return format_flags(out, flags, names);
}

static noinline_for_stack
void fwnode_full_name_string(struct printbuf *out,
			     struct fwnode_handle *fwnode)
{
	int depth;

	/* Loop starting from the root node to the current node. */
	for (depth = fwnode_count_parents(fwnode); depth >= 0; depth--) {
		struct fwnode_handle *__fwnode =
			fwnode_get_nth_parent(fwnode, depth);

		string(out, fwnode_get_name_prefix(__fwnode));
		string(out, fwnode_get_name(__fwnode));

		fwnode_handle_put(__fwnode);
	}
}

static noinline_for_stack
void device_node_string(struct printbuf *out, struct device_node *dn,
			const char *fmt)
{
	const char *p;
	int ret;
	struct property *prop;
	bool has_mult, pass;

	if (fmt[0] != 'F')
		return error_string(out, "(%pO?)");

	if (!IS_ENABLED(CONFIG_OF))
		return error_string(out, "(%pOF?)");

	if (check_pointer(out, dn))
		return;

	/* simple case without anything any more format specifiers */
	fmt++;
	if (fmt[0] == '\0' || strcspn(fmt,"fnpPFcC") > 0)
		fmt = "f";

	for (pass = false; strspn(fmt,"fnpPFcC"); fmt++, pass = true) {
		if (pass)
			prt_char(out, ':');

		switch (*fmt) {
		case 'f':	/* full_name */
			fwnode_full_name_string(out, of_fwnode_handle(dn));
			break;
		case 'n': {	/* name */
			const char *name = fwnode_get_name(of_fwnode_handle(dn));
			unsigned len = strchrnul(name, '@') - name;

			prt_bytes(out, name, len);
			break;
		}
		case 'p':	/* phandle */
			prt_u64(out, dn->phandle);
			break;
		case 'P':	/* path-spec */
			p = fwnode_get_name(of_fwnode_handle(dn));
			if (!p[1])
				p = "/";
			string(out, p);
			break;
		case 'F':	/* flags */
			prt_char(out, of_node_check_flag(dn, OF_DYNAMIC) ? 'D' : '-');
			prt_char(out, of_node_check_flag(dn, OF_DETACHED) ? 'd' : '-');
			prt_char(out, of_node_check_flag(dn, OF_POPULATED) ? 'P' : '-');
			prt_char(out, of_node_check_flag(dn, OF_POPULATED_BUS) ? 'B' : '-');
			break;
		case 'c':	/* major compatible string_spec */
			ret = of_property_read_string(dn, "compatible", &p);
			if (!ret)
				string(out, p);
			break;
		case 'C':	/* full compatible string_spec */
			has_mult = false;
			of_property_for_each_string(dn, "compatible", prop, p) {
				if (has_mult)
					prt_char(out, ',');
				prt_char(out, '\"');
				string(out, p);
				prt_char(out, '\"');

				has_mult = true;
			}
			break;
		default:
			break;
		}
	}
}

static noinline_for_stack
void fwnode_string(struct printbuf *out,
		   struct fwnode_handle *fwnode,
		   const char *fmt)
{
	if (*fmt != 'w')
		return error_string(out, "(%pf?)");

	if (check_pointer(out, fwnode))
		return;

	fmt++;

	switch (*fmt) {
	case 'P':	/* name */
		string(out, fwnode_get_name(fwnode));
		break;
	case 'f':	/* full_name */
	default:
		fwnode_full_name_string(out, fwnode);
		break;
	}
}

int __init no_hash_pointers_enable(char *str)
{
	if (no_hash_pointers)
		return 0;

	no_hash_pointers = true;

	pr_warn("**********************************************************\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** This system shows unhashed kernel memory addresses   **\n");
	pr_warn("** via the console, logs, and other interfaces. This    **\n");
	pr_warn("** might reduce the security of your system.            **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** If you see this message and you are not debugging    **\n");
	pr_warn("** the kernel, report this immediately to your system   **\n");
	pr_warn("** administrator!                                       **\n");
	pr_warn("**                                                      **\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**********************************************************\n");

	return 0;
}
early_param("no_hash_pointers", no_hash_pointers_enable);

/* Used for Rust formatting ('%pA'). */
char *rust_fmt_argument(char *buf, char *end, void *ptr);

/*
 * Show a '%p' thing.  A kernel extension is that the '%p' is followed
 * by an extra set of alphanumeric characters that are extended format
 * specifiers.
 *
 * Please update scripts/checkpatch.pl when adding/removing conversion
 * characters.  (Search for "check for vsprintf extension").
 *
 * Right now we handle:
 *
 * - 'S' For symbolic direct pointers (or function descriptors) with offset
 * - 's' For symbolic direct pointers (or function descriptors) without offset
 * - '[Ss]R' as above with __builtin_extract_return_addr() translation
 * - 'S[R]b' as above with module build ID (for use in backtraces)
 * - '[Ff]' %pf and %pF were obsoleted and later removed in favor of
 *	    %ps and %pS. Be careful when re-using these specifiers.
 * - 'B' For backtraced symbolic direct pointers with offset
 * - 'Bb' as above with module build ID (for use in backtraces)
 * - 'R' For decoded struct resource, e.g., [mem 0x0-0x1f 64bit pref]
 * - 'r' For raw struct resource, e.g., [mem 0x0-0x1f flags 0x201]
 * - 'b[l]' For a bitmap, the number of bits is determined by the field
 *       width which must be explicitly specified either as part of the
 *       format string '%32b[l]' or through '%*b[l]', [l] selects
 *       range-list format instead of hex format
 * - 'M' For a 6-byte MAC address, it prints the address in the
 *       usual colon-separated hex notation
 * - 'm' For a 6-byte MAC address, it prints the hex address without colons
 * - 'MF' For a 6-byte MAC FDDI address, it prints the address
 *       with a dash-separated hex notation
 * - '[mM]R' For a 6-byte MAC address, Reverse order (Bluetooth)
 * - 'I' [46] for IPv4/IPv6 addresses printed in the usual way
 *       IPv4 uses dot-separated decimal without leading 0's (1.2.3.4)
 *       IPv6 uses colon separated network-order 16 bit hex with leading 0's
 *       [S][pfs]
 *       Generic IPv4/IPv6 address (struct sockaddr *) that falls back to
 *       [4] or [6] and is able to print port [p], flowinfo [f], scope [s]
 * - 'i' [46] for 'raw' IPv4/IPv6 addresses
 *       IPv6 omits the colons (01020304...0f)
 *       IPv4 uses dot-separated decimal with leading 0's (010.123.045.006)
 *       [S][pfs]
 *       Generic IPv4/IPv6 address (struct sockaddr *) that falls back to
 *       [4] or [6] and is able to print port [p], flowinfo [f], scope [s]
 * - '[Ii][4S][hnbl]' IPv4 addresses in host, network, big or little endian order
 * - 'I[6S]c' for IPv6 addresses printed as specified by
 *       https://tools.ietf.org/html/rfc5952
 * - 'E[achnops]' For an escaped buffer, where rules are defined by combination
 *                of the following flags (see string_escape_mem() for the
 *                details):
 *                  a - ESCAPE_ANY
 *                  c - ESCAPE_SPECIAL
 *                  h - ESCAPE_HEX
 *                  n - ESCAPE_NULL
 *                  o - ESCAPE_OCTAL
 *                  p - ESCAPE_NP
 *                  s - ESCAPE_SPACE
 *                By default ESCAPE_ANY_NP is used.
 * - 'U' For a 16 byte UUID/GUID, it prints the UUID/GUID in the form
 *       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 *       Options for %pU are:
 *         b big endian lower case hex (default)
 *         B big endian UPPER case hex
 *         l little endian lower case hex
 *         L little endian UPPER case hex
 *           big endian output byte order is:
 *             [0][1][2][3]-[4][5]-[6][7]-[8][9]-[10][11][12][13][14][15]
 *           little endian output byte order is:
 *             [3][2][1][0]-[5][4]-[7][6]-[8][9]-[10][11][12][13][14][15]
 * - 'V' For a struct va_format which contains a format string * and va_list *,
 *       call vsnprintf(->format, *->va_list).
 *       Implements a "recursive vsnprintf".
 *       Do not use this feature without some mechanism to verify the
 *       correctness of the format string and va_list arguments.
 * - 'K' For a kernel pointer that should be hidden from unprivileged users.
 *       Use only for procfs, sysfs and similar files, not printk(); please
 *       read the documentation (path below) first.
 * - 'NF' For a netdev_features_t
 * - '4cc' V4L2 or DRM FourCC code, with endianness and raw numerical value.
 * - 'h[CDN]' For a variable-length buffer, it prints it as a hex string with
 *            a certain separator (' ' by default):
 *              C colon
 *              D dash
 *              N no separator
 *            The maximum supported length is 64 bytes of the input. Consider
 *            to use print_hex_dump() for the larger input.
 * - 'a[pd]' For address types [p] phys_addr_t, [d] dma_addr_t and derivatives
 *           (default assumed to be phys_addr_t, passed by reference)
 * - 'd[234]' For a dentry name (optionally 2-4 last components)
 * - 'D[234]' Same as 'd' but for a struct file
 * - 'g' For block_device name (gendisk + partition number)
 * - 't[RT][dt][r][s]' For time and date as represented by:
 *      R    struct rtc_time
 *      T    time64_t
 * - 'C' For a clock, it prints the name (Common Clock Framework) or address
 *       (legacy clock framework) of the clock
 * - 'Cn' For a clock, it prints the name (Common Clock Framework) or address
 *        (legacy clock framework) of the clock
 * - 'G' For flags to be printed as a collection of symbolic strings that would
 *       construct the specific value. Supported flags given by option:
 *       p page flags (see struct page) given as pointer to unsigned long
 *       g gfp flags (GFP_* and __GFP_*) given as pointer to gfp_t
 *       v vma flags (VM_*) given as pointer to unsigned long
 * - 'OF[fnpPcCF]'  For a device tree object
 *                  Without any optional arguments prints the full_name
 *                  f device node full_name
 *                  n device node name
 *                  p device node phandle
 *                  P device node path spec (name + @unit)
 *                  F device node flags
 *                  c major compatible string
 *                  C full compatible string
 * - 'fw[fP]'	For a firmware node (struct fwnode_handle) pointer
 *		Without an option prints the full name of the node
 *		f full name
 *		P node name, including a possible unit address
 * - 'x' For printing the address unmodified. Equivalent to "%lx".
 *       Please read the documentation (path below) before using!
 * - '[ku]s' For a BPF/tracing related format specifier, e.g. used out of
 *           bpf_trace_printk() where [ku] prefix specifies either kernel (k)
 *           or user (u) memory to probe, and:
 *              s a string, equivalent to "%s" on direct vsnprintf() use
 *
 * ** When making changes please also update:
 *	Documentation/core-api/printk-formats.rst
 *
 * Note: The default behaviour (unadorned %p) is to hash the address,
 * rendering it useful as a unique identifier.
 *
 * There is also a '%pA' format specifier, but it is only intended to be used
 * from Rust code to format core::fmt::Arguments. Do *not* use it from C.
 * See rust/kernel/print.rs for details.
 */
static noinline_for_stack
void pointer(struct printbuf *out, const char *fmt,
	     void *ptr, struct printf_spec spec)
{
	unsigned prev_pos = out->pos;

	switch (*fmt) {
	case 'S':
	case 's':
		ptr = dereference_symbol_descriptor(ptr);
		fallthrough;
	case 'B':
		symbol_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'R':
	case 'r':
		resource_string(out, ptr, fmt[0] == 'R');
		return do_width_precision(out, prev_pos, spec);
	case 'h':
		return hex_string(out, ptr, spec, fmt);
	case 'b':
		switch (fmt[1]) {
		case 'l':
			return bitmap_list_string(out, ptr, spec, fmt);
		default:
			return bitmap_string(out, ptr, spec, fmt);
		}
	case 'M':			/* Colon separated: 00:01:02:03:04:05 */
	case 'm':			/* Contiguous: 000102030405 */
					/* [mM]F (FDDI) */
					/* [mM]R (Reverse order; Bluetooth) */
		mac_address_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'I':			/* Formatted IP supported
					 * 4:	1.2.3.4
					 * 6:	0001:0203:...:0708
					 * 6c:	1::708 or 1::1.2.3.4
					 */
	case 'i':			/* Contiguous:
					 * 4:	001.002.003.004
					 * 6:   000102...0f
					 */
		ip_addr_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'E':
		return escaped_string(out, ptr, spec, fmt);
	case 'U':
		uuid_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'V':
		return va_format(out, ptr, spec, fmt);
	case 'K':
		return restricted_pointer(out, ptr, spec);
	case 'N':
		netdev_bits(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case '4':
		fourcc_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'a':
		address_val(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'd':
		dentry_name(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 't':
		time_and_date(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'C':
		return clock(out, ptr, spec, fmt);
	case 'D':
		file_dentry_name(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
#ifdef CONFIG_BLOCK
	case 'g':
		bdev_name(out, ptr);
		return do_width_precision(out, prev_pos, spec);
#endif

	case 'G':
		flags_string(out, ptr, fmt);
		return do_width_precision(out, prev_pos, spec);
	case 'O':
		device_node_string(out, ptr, fmt + 1);
		return do_width_precision(out, prev_pos, spec);
	case 'f':
		fwnode_string(out, ptr, fmt + 1);
		return do_width_precision(out, prev_pos, spec);
	case 'A':
		if (!IS_ENABLED(CONFIG_RUST)) {
			WARN_ONCE(1, "Please remove %%pA from non-Rust code\n");
			error_string(out, "(%pA?)");
			return do_width_precision(out, prev_pos, spec);
		}
		out->pos += rust_fmt_argument(out->buf + out->pos,
					      out->buf + out->size, ptr) -
			(out->buf + out->pos);
		return do_width_precision(out, prev_pos, spec);
	case 'x':
		return pointer_string(out, ptr, spec);
	case 'e':
		/* %pe with a non-ERR_PTR gets treated as plain %p */
		if (!IS_ERR(ptr))
			return default_pointer(out, ptr, spec);
		return err_ptr(out, ptr, spec);
	case 'u':
	case 'k':
		switch (fmt[1]) {
		case 's':
			return string_spec(out, ptr, spec);
		default:
			return error_string_spec(out, "(einval)", spec);
		}
	default:
		return default_pointer(out, ptr, spec);
	}
}

/*
 * Helper function to decode printf style format.
 * Each call decode a token from the format and return the
 * number of characters read (or likely the delta where it wants
 * to go on the next call).
 * The decoded token is returned through the parameters
 *
 * 'h', 'l', or 'L' for integer fields
 * 'z' support added 23/7/1999 S.H.
 * 'z' changed to 'Z' --davidm 1/25/99
 * 'Z' changed to 'z' --adobriyan 2017-01-25
 * 't' added for ptrdiff_t
 *
 * @fmt: the format string
 * @type of the token returned
 * @flags: various flags such as +, -, # tokens..
 * @field_width: overwritten width
 * @base: base of the number (octal, hex, ...)
 * @precision: precision of a number
 * @qualifier: qualifier of a number (long, size_t, ...)
 */
static noinline_for_stack
int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;
	char qualifier;

	/* we finished early by reading the field width */
	if (spec->type == FORMAT_TYPE_WIDTH) {
		if (spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	/* we finished early by reading the precision */
	if (spec->type == FORMAT_TYPE_PRECISION) {
		if (spec->precision < 0)
			spec->precision = 0;

		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	/* By default */
	spec->type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	/* Return the current non-format string */
	if (fmt != start || !*fmt)
		return fmt - start;

	/* Process flags */
	spec->flags = 0;

	while (1) { /* this also skips first '%' */
		bool found = true;

		++fmt;

		switch (*fmt) {
		case '-': spec->flags |= LEFT;    break;
		case '+': spec->flags |= PLUS;    break;
		case ' ': spec->flags |= SPACE;   break;
		case '#': spec->flags |= SPECIAL; break;
		case '0': spec->flags |= ZEROPAD; break;
		default:  found = false;
		}

		if (!found)
			break;
	}

	/* get field width */
	spec->field_width = -1;

	if (isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);
	else if (*fmt == '*') {
		/* it's the next argument */
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	/* get the precision */
	spec->precision = -1;
	if (*fmt == '.') {
		++fmt;
		if (isdigit(*fmt)) {
			spec->precision = skip_atoi(&fmt);
			if (spec->precision < 0)
				spec->precision = 0;
		} else if (*fmt == '*') {
			/* it's the next argument */
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	/* get the conversion qualifier */
	qualifier = 0;
	if (*fmt == 'h' || _tolower(*fmt) == 'l' ||
	    *fmt == 'z' || *fmt == 't') {
		qualifier = *fmt++;
		if (unlikely(qualifier == *fmt)) {
			if (qualifier == 'l') {
				qualifier = 'L';
				++fmt;
			} else if (qualifier == 'h') {
				qualifier = 'H';
				++fmt;
			}
		}
	}

	/* default base */
	spec->base = 10;
	switch (*fmt) {
	case 'c':
		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	case 'p':
		spec->type = FORMAT_TYPE_PTR;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	/* integer number formats - set up the flags and "break" */
	case 'o':
		spec->base = 8;
		break;

	case 'x':
		spec->flags |= SMALL;
		fallthrough;

	case 'X':
		spec->base = 16;
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;
		break;
	case 'u':
		break;

	case 'n':
		/*
		 * Since %n poses a greater security risk than
		 * utility, treat it as any other invalid or
		 * unsupported format specifier.
		 */
		fallthrough;

	default:
		WARN_ONCE(1, "Please remove unsupported %%%c in format string\n", *fmt);
		spec->type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if (qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if (qualifier == 'l') {
		BUILD_BUG_ON(FORMAT_TYPE_ULONG + SIGN != FORMAT_TYPE_LONG);
		spec->type = FORMAT_TYPE_ULONG + (spec->flags & SIGN);
	} else if (qualifier == 'z') {
		spec->type = FORMAT_TYPE_SIZE_T;
	} else if (qualifier == 't') {
		spec->type = FORMAT_TYPE_PTRDIFF;
	} else if (qualifier == 'H') {
		BUILD_BUG_ON(FORMAT_TYPE_UBYTE + SIGN != FORMAT_TYPE_BYTE);
		spec->type = FORMAT_TYPE_UBYTE + (spec->flags & SIGN);
	} else if (qualifier == 'h') {
		BUILD_BUG_ON(FORMAT_TYPE_USHORT + SIGN != FORMAT_TYPE_SHORT);
		spec->type = FORMAT_TYPE_USHORT + (spec->flags & SIGN);
	} else {
		BUILD_BUG_ON(FORMAT_TYPE_UINT + SIGN != FORMAT_TYPE_INT);
		spec->type = FORMAT_TYPE_UINT + (spec->flags & SIGN);
	}

	return ++fmt - start;
}

static void
set_field_width(struct printf_spec *spec, int width)
{
	spec->field_width = width;
	if (WARN_ONCE(spec->field_width != width, "field width %d too large", width)) {
		spec->field_width = clamp(width, -FIELD_WIDTH_MAX, FIELD_WIDTH_MAX);
	}
}

static void
set_precision(struct printf_spec *spec, int prec)
{
	spec->precision = prec;
	if (WARN_ONCE(spec->precision != prec, "precision %d too large", prec)) {
		spec->precision = clamp(prec, 0, PRECISION_MAX);
	}
}

/**
 * prt_vprintf - Format a string, outputting to a printbuf
 * @out: The printbuf to output to
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * prt_vprintf works much like the traditional vsnprintf(), but outputs to a
 * printbuf instead of raw pointer/size.
 *
 * If you're not already dealing with a va_list consider using prt_printf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
void prt_vprintf(struct printbuf *out, const char *fmt, va_list args)
{
	unsigned long long num;
	struct printf_spec spec = {0};

	/* Reject out-of-range values early.  Large positive sizes are
	   used for unknown buffer sizes. */
	if (WARN_ON_ONCE(out->size > INT_MAX))
		return;

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
			prt_bytes(out, old_fmt, read);
			break;

		case FORMAT_TYPE_WIDTH:
			set_field_width(&spec, va_arg(args, int));
			break;

		case FORMAT_TYPE_PRECISION:
			set_precision(&spec, va_arg(args, int));
			break;

		case FORMAT_TYPE_CHAR:
			if (spec.field_width > 0 && !(spec.flags & LEFT))
				prt_chars(out, spec.field_width, ' ');

			__prt_char(out, (unsigned char) va_arg(args, int));

			if (spec.field_width > 0 && (spec.flags & LEFT))
				prt_chars(out, spec.field_width, ' ');
			spec.field_width = 0;
			break;

		case FORMAT_TYPE_STR:
			/*
			 * we can't use string() then do_width_precision
			 * afterwards: people use the field width for passing
			 * non nul terminated strings
			 */
			string_spec(out, va_arg(args, char *), spec);
			break;

		case FORMAT_TYPE_PTR:
			pointer(out, fmt, va_arg(args, void *), spec);
			while (isalnum(*fmt))
				fmt++;
			break;

		case FORMAT_TYPE_PERCENT_CHAR:
			__prt_char(out, '%');
			break;

		case FORMAT_TYPE_INVALID:
			/*
			 * Presumably the arguments passed gcc's type
			 * checking, but there is no safe or sane way
			 * for us to continue parsing the format and
			 * fetching from the va_list; the remaining
			 * specifiers and arguments would be out of
			 * sync.
			 */
			goto out;

		default:
			switch (spec.type) {
			case FORMAT_TYPE_LONG_LONG:
				num = va_arg(args, long long);
				break;
			case FORMAT_TYPE_ULONG:
				num = va_arg(args, unsigned long);
				break;
			case FORMAT_TYPE_LONG:
				num = va_arg(args, long);
				break;
			case FORMAT_TYPE_SIZE_T:
				if (spec.flags & SIGN)
					num = va_arg(args, ssize_t);
				else
					num = va_arg(args, size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				num = va_arg(args, ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
				num = (unsigned char) va_arg(args, int);
				break;
			case FORMAT_TYPE_BYTE:
				num = (signed char) va_arg(args, int);
				break;
			case FORMAT_TYPE_USHORT:
				num = (unsigned short) va_arg(args, int);
				break;
			case FORMAT_TYPE_SHORT:
				num = (short) va_arg(args, int);
				break;
			case FORMAT_TYPE_INT:
				num = (int) va_arg(args, int);
				break;
			default:
				num = va_arg(args, unsigned int);
			}

			number(out, num, spec);
		}
	}
out:
	printbuf_nul_terminate(out);
}
EXPORT_SYMBOL(prt_vprintf);

/**
 * prt_printf - Format a string, outputting to a printbuf
 * @out: The printbuf to output to
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 *
 * prt_printf works much like the traditional sprintf(), but outputs to a
 * printbuf instead of raw pointer/size.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
void prt_printf(struct printbuf *out, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	prt_vprintf(out, fmt, args);
	va_end(args);
}
EXPORT_SYMBOL(prt_printf);

/**
 * vsnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * This function generally follows C99 vsnprintf, but has some
 * extensions and a few limitations:
 *
 *  - ``%n`` is unsupported
 *  - ``%p*`` is handled by pointer()
 *
 * See pointer() or Documentation/core-api/printk-formats.rst for more
 * extensive description.
 *
 * **Please update the documentation in both places when making changes**
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 *
 * If you're not already dealing with a va_list consider using snprintf().
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	struct printbuf out = PRINTBUF_EXTERN(buf, size);

	prt_vprintf(&out, fmt, args);
	return out.pos;
}
EXPORT_SYMBOL(vsnprintf);

/**
 * vscnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which have been written into
 * the @buf not including the trailing '\0'. If @size is == 0 the function
 * returns 0.
 *
 * If you're not already dealing with a va_list consider using scnprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	if (unlikely(!size))
		return 0;

	i = vsnprintf(buf, size, fmt, args);

	if (likely(i < size))
		return i;

	return size - 1;
}
EXPORT_SYMBOL(vscnprintf);

/**
 * snprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters which would be
 * generated for the given input, excluding the trailing null,
 * as per ISO C99.  If the return is greater than or equal to
 * @size, the resulting string is truncated.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(snprintf);

/**
 * scnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters written into @buf not including
 * the trailing '\0'. If @size is == 0 the function returns 0.
 */

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(scnprintf);

/**
 * vsprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use vsnprintf() or vscnprintf() in order to avoid
 * buffer overflows.
 *
 * If you're not already dealing with a va_list consider using sprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vsprintf(char *buf, const char *fmt, va_list args)
{
	return vsnprintf(buf, INT_MAX, fmt, args);
}
EXPORT_SYMBOL(vsprintf);

/**
 * sprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use snprintf() or scnprintf() in order to avoid
 * buffer overflows.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sprintf);

#ifdef CONFIG_BINARY_PRINTF
/*
 * bprintf service:
 * vbin_printf() - VA arguments to binary data
 * bstr_printf() - Binary data to text string
 */

static inline void printbuf_align(struct printbuf *out, unsigned align)
{
	/* Assumes output buffer is correctly aligned: */
	out->pos += align - 1;
	out->pos &= ~(align - 1);
}

/**
 * prt_vbinprintf - Parse a format string and place args' binary value in a buffer
 * @out: The buffer to place args' binary value
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The format follows C99 vsnprintf, except %n is ignored, and its argument
 * is skipped.
 *
 * NOTE:
 * If the return value is greater than @size, the resulting bin_buf is NOT
 * valid for bstr_printf().
 */
void prt_vbinprintf(struct printbuf *out, const char *fmt, va_list args)
{
	struct printf_spec spec = {0};
	int width;

#define save_arg(type)							\
({									\
	unsigned long long value;					\
	if (sizeof(type) == 8) {					\
		u64 val8 = va_arg(args, u64);				\
		printbuf_align(out, sizeof(u32));			\
		prt_bytes(out, (u32 *) &val8, 4);			\
		prt_bytes(out, ((u32 *) &val8) + 1, 4);			\
		value = val8;						\
	} else {							\
		u32 val4 = va_arg(args, u32);				\
		printbuf_align(out, sizeof(type));			\
		prt_bytes(out, &val4, sizeof(type));			\
		value = (unsigned long long)val4;			\
	}								\
	value;								\
})

	while (*fmt) {
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
		case FORMAT_TYPE_PERCENT_CHAR:
			break;
		case FORMAT_TYPE_INVALID:
			goto out;

		case FORMAT_TYPE_WIDTH:
		case FORMAT_TYPE_PRECISION:
			width = (int)save_arg(int);
			/* Pointers may require the width */
			if (*fmt == 'p')
				set_field_width(&spec, width);
			break;

		case FORMAT_TYPE_CHAR:
			save_arg(char);
			break;

		case FORMAT_TYPE_STR: {
			const char *save_str = va_arg(args, char *);
			const char *err_msg;

			err_msg = check_pointer_msg(save_str);
			if (err_msg)
				save_str = err_msg;

			prt_str(out, save_str);
			break;
		}

		case FORMAT_TYPE_PTR:
			/* Dereferenced pointers must be done now */
			switch (*fmt) {
			/* Dereference of functions is still OK */
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				save_arg(void *);
				break;
			default:
				if (!isalnum(*fmt)) {
					save_arg(void *);
					break;
				}
				pointer(out, fmt, va_arg(args, void *), spec);
			}
			/* skip all alphanumeric pointer suffixes */
			while (isalnum(*fmt))
				fmt++;
			break;

		default:
			switch (spec.type) {

			case FORMAT_TYPE_LONG_LONG:
				save_arg(long long);
				break;
			case FORMAT_TYPE_ULONG:
			case FORMAT_TYPE_LONG:
				save_arg(unsigned long);
				break;
			case FORMAT_TYPE_SIZE_T:
				save_arg(size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				save_arg(ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
			case FORMAT_TYPE_BYTE:
				save_arg(char);
				break;
			case FORMAT_TYPE_USHORT:
			case FORMAT_TYPE_SHORT:
				save_arg(short);
				break;
			default:
				save_arg(int);
			}
		}
	}

out:
	printbuf_nul_terminate(out);
	printbuf_align(out, 4);
#undef save_arg
}
EXPORT_SYMBOL_GPL(prt_vbinprintf);

/**
 * prt_bstrprintf - Format a string from binary arguments and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @bin_buf: Binary arguments for the format string
 *
 * This function like C99 vsnprintf, but the difference is that vsnprintf gets
 * arguments from stack, and bstr_printf gets arguments from @bin_buf which is
 * a binary buffer that generated by vbin_printf.
 *
 * The format follows C99 vsnprintf, but has some extensions:
 *  see vsnprintf comment for details.
 */
void prt_bstrprintf(struct printbuf *out, const char *fmt, const u32 *bin_buf)
{
	struct printf_spec spec = {0};
	const char *args = (const char *)bin_buf;

	if (WARN_ON_ONCE(out->size > INT_MAX))
		return;

#define get_arg(type)							\
({									\
	typeof(type) value;						\
	if (sizeof(type) == 8) {					\
		args = PTR_ALIGN(args, sizeof(u32));			\
		*(u32 *)&value = *(u32 *)args;				\
		*((u32 *)&value + 1) = *(u32 *)(args + 4);		\
	} else {							\
		args = PTR_ALIGN(args, sizeof(type));			\
		value = *(typeof(type) *)args;				\
	}								\
	args += sizeof(type);						\
	value;								\
})

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
			prt_bytes(out, old_fmt, read);
			break;

		case FORMAT_TYPE_WIDTH:
			set_field_width(&spec, get_arg(int));
			break;

		case FORMAT_TYPE_PRECISION:
			set_precision(&spec, get_arg(int));
			break;

		case FORMAT_TYPE_CHAR:
			if (!(spec.flags & LEFT))
				prt_chars(out, spec.field_width, ' ');
			__prt_char(out, (unsigned char) get_arg(char));
			if ((spec.flags & LEFT))
				prt_chars(out, spec.field_width, ' ');
			break;

		case FORMAT_TYPE_STR: {
			const char *str_arg = args;
			args += strlen(str_arg) + 1;
			string_spec(out, (char *)str_arg, spec);
			break;
		}

		case FORMAT_TYPE_PTR: {
			bool process = false;
			int len;
			/* Non function dereferences were already done */
			switch (*fmt) {
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				process = true;
				break;
			default:
				if (!isalnum(*fmt)) {
					process = true;
					break;
				}
				/* Pointer dereference was already processed */
				len = strlen(args);
				prt_bytes(out, args, len);
				args += len + 1;
			}
			if (process)
				pointer(out, fmt, get_arg(void *), spec);

			while (isalnum(*fmt))
				fmt++;
			break;
		}

		case FORMAT_TYPE_PERCENT_CHAR:
			__prt_char(out, '%');
			break;

		case FORMAT_TYPE_INVALID:
			goto out;

		default: {
			unsigned long long num;

			switch (spec.type) {

			case FORMAT_TYPE_LONG_LONG:
				num = get_arg(long long);
				break;
			case FORMAT_TYPE_ULONG:
			case FORMAT_TYPE_LONG:
				num = get_arg(unsigned long);
				break;
			case FORMAT_TYPE_SIZE_T:
				num = get_arg(size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				num = get_arg(ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
				num = get_arg(unsigned char);
				break;
			case FORMAT_TYPE_BYTE:
				num = get_arg(signed char);
				break;
			case FORMAT_TYPE_USHORT:
				num = get_arg(unsigned short);
				break;
			case FORMAT_TYPE_SHORT:
				num = get_arg(short);
				break;
			case FORMAT_TYPE_UINT:
				num = get_arg(unsigned int);
				break;
			default:
				num = get_arg(int);
			}

			number(out, num, spec);
		} /* default: */
		} /* switch(spec.type) */
	} /* while(*fmt) */

out:
#undef get_arg
	printbuf_nul_terminate(out);
}
EXPORT_SYMBOL_GPL(prt_bstrprintf);

/**
 * prt_bprintf - Parse a format string and place args' binary value in a buffer
 * @out: The buffer to place args' binary value
 * @fmt: The format string to use
 * @...: Arguments for the format string
 */
void prt_bprintf(struct printbuf *out, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	prt_vbinprintf(out, fmt, args);
	va_end(args);
}
EXPORT_SYMBOL_GPL(prt_bprintf);

/**
 * vbin_printf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The format follows C99 vsnprintf, except %n is ignored, and its argument
 * is skipped.
 *
 * The return value is the number of words(32bits) which would be generated for
 * the given input.
 *
 * NOTE:
 * If the return value is greater than @size, the resulting bin_buf is NOT
 * valid for bstr_printf().
 */
int vbin_printf(u32 *bin_buf, size_t size, const char *fmt, va_list args)
{
	struct printbuf out = PRINTBUF_EXTERN((char *) bin_buf, size);

	prt_vbinprintf(&out, fmt, args);
	return out.pos;
}
EXPORT_SYMBOL_GPL(vbin_printf);

/**
 * bstr_printf - Format a string from binary arguments and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @bin_buf: Binary arguments for the format string
 *
 * This function like C99 vsnprintf, but the difference is that vsnprintf gets
 * arguments from stack, and bstr_printf gets arguments from @bin_buf which is
 * a binary buffer that generated by vbin_printf.
 *
 * The format follows C99 vsnprintf, but has some extensions:
 *  see vsnprintf comment for details.
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 */
int bstr_printf(char *buf, size_t size, const char *fmt, const u32 *bin_buf)
{
	struct printbuf out = PRINTBUF_EXTERN(buf, size);

	prt_bstrprintf(&out, fmt, bin_buf);
	return out.pos;
}
EXPORT_SYMBOL_GPL(bstr_printf);

/**
 * bprintf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of words(u32) written
 * into @bin_buf.
 */
int bprintf(u32 *bin_buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vbin_printf(bin_buf, size, fmt, args);
	va_end(args);

	return ret;
}
EXPORT_SYMBOL_GPL(bprintf);

#endif /* CONFIG_BINARY_PRINTF */

/**
 * vsscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	format of buffer
 * @args:	arguments
 */
int vsscanf(const char *buf, const char *fmt, va_list args)
{
	const char *str = buf;
	char *next;
	char digit;
	int num = 0;
	u8 qualifier;
	unsigned int base;
	union {
		long long s;
		unsigned long long u;
	} val;
	s16 field_width;
	bool is_sign;

	while (*fmt) {
		/* skip any white space in format */
		/* white space in format matches any amount of
		 * white space, including none, in the input.
		 */
		if (isspace(*fmt)) {
			fmt = skip_spaces(++fmt);
			str = skip_spaces(str);
		}

		/* anything that is not a conversion must match exactly */
		if (*fmt != '%' && *fmt) {
			if (*fmt++ != *str++)
				break;
			continue;
		}

		if (!*fmt)
			break;
		++fmt;

		/* skip this conversion.
		 * advance both strings to next white space
		 */
		if (*fmt == '*') {
			if (!*str)
				break;
			while (!isspace(*fmt) && *fmt != '%' && *fmt) {
				/* '%*[' not yet supported, invalid format */
				if (*fmt == '[')
					return num;
				fmt++;
			}
			while (!isspace(*str) && *str)
				str++;
			continue;
		}

		/* get field width */
		field_width = -1;
		if (isdigit(*fmt)) {
			field_width = skip_atoi(&fmt);
			if (field_width <= 0)
				break;
		}

		/* get conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || _tolower(*fmt) == 'l' ||
		    *fmt == 'z') {
			qualifier = *fmt++;
			if (unlikely(qualifier == *fmt)) {
				if (qualifier == 'h') {
					qualifier = 'H';
					fmt++;
				} else if (qualifier == 'l') {
					qualifier = 'L';
					fmt++;
				}
			}
		}

		if (!*fmt)
			break;

		if (*fmt == 'n') {
			/* return number of characters read so far */
			*va_arg(args, int *) = str - buf;
			++fmt;
			continue;
		}

		if (!*str)
			break;

		base = 10;
		is_sign = false;

		switch (*fmt++) {
		case 'c':
		{
			char *s = (char *)va_arg(args, char*);
			if (field_width == -1)
				field_width = 1;
			do {
				*s++ = *str++;
			} while (--field_width > 0 && *str);
			num++;
		}
		continue;
		case 's':
		{
			char *s = (char *)va_arg(args, char *);
			if (field_width == -1)
				field_width = SHRT_MAX;
			/* first, skip leading white space in buffer */
			str = skip_spaces(str);

			/* now copy until next white space */
			while (*str && !isspace(*str) && field_width--)
				*s++ = *str++;
			*s = '\0';
			num++;
		}
		continue;
		/*
		 * Warning: This implementation of the '[' conversion specifier
		 * deviates from its glibc counterpart in the following ways:
		 * (1) It does NOT support ranges i.e. '-' is NOT a special
		 *     character
		 * (2) It cannot match the closing bracket ']' itself
		 * (3) A field width is required
		 * (4) '%*[' (discard matching input) is currently not supported
		 *
		 * Example usage:
		 * ret = sscanf("00:0a:95","%2[^:]:%2[^:]:%2[^:]",
		 *		buf1, buf2, buf3);
		 * if (ret < 3)
		 *    // etc..
		 */
		case '[':
		{
			char *s = (char *)va_arg(args, char *);
			DECLARE_BITMAP(set, 256) = {0};
			unsigned int len = 0;
			bool negate = (*fmt == '^');

			/* field width is required */
			if (field_width == -1)
				return num;

			if (negate)
				++fmt;

			for ( ; *fmt && *fmt != ']'; ++fmt, ++len)
				__set_bit((u8)*fmt, set);

			/* no ']' or no character set found */
			if (!*fmt || !len)
				return num;
			++fmt;

			if (negate) {
				bitmap_complement(set, set, 256);
				/* exclude null '\0' byte */
				__clear_bit(0, set);
			}

			/* match must be non-empty */
			if (!test_bit((u8)*str, set))
				return num;

			while (test_bit((u8)*str, set) && field_width--)
				*s++ = *str++;
			*s = '\0';
			++num;
		}
		continue;
		case 'o':
			base = 8;
			break;
		case 'x':
		case 'X':
			base = 16;
			break;
		case 'i':
			base = 0;
			fallthrough;
		case 'd':
			is_sign = true;
			fallthrough;
		case 'u':
			break;
		case '%':
			/* looking for '%' in str */
			if (*str++ != '%')
				return num;
			continue;
		default:
			/* invalid format; stop here */
			return num;
		}

		/* have some sort of integer conversion.
		 * first, skip white space in buffer.
		 */
		str = skip_spaces(str);

		digit = *str;
		if (is_sign && digit == '-') {
			if (field_width == 1)
				break;

			digit = *(str + 1);
		}

		if (!digit
		    || (base == 16 && !isxdigit(digit))
		    || (base == 10 && !isdigit(digit))
		    || (base == 8 && (!isdigit(digit) || digit > '7'))
		    || (base == 0 && !isdigit(digit)))
			break;

		if (is_sign)
			val.s = simple_strntoll(str,
						field_width >= 0 ? field_width : INT_MAX,
						&next, base);
		else
			val.u = simple_strntoull(str,
						 field_width >= 0 ? field_width : INT_MAX,
						 &next, base);

		switch (qualifier) {
		case 'H':	/* that's 'hh' in format */
			if (is_sign)
				*va_arg(args, signed char *) = val.s;
			else
				*va_arg(args, unsigned char *) = val.u;
			break;
		case 'h':
			if (is_sign)
				*va_arg(args, short *) = val.s;
			else
				*va_arg(args, unsigned short *) = val.u;
			break;
		case 'l':
			if (is_sign)
				*va_arg(args, long *) = val.s;
			else
				*va_arg(args, unsigned long *) = val.u;
			break;
		case 'L':
			if (is_sign)
				*va_arg(args, long long *) = val.s;
			else
				*va_arg(args, unsigned long long *) = val.u;
			break;
		case 'z':
			*va_arg(args, size_t *) = val.u;
			break;
		default:
			if (is_sign)
				*va_arg(args, int *) = val.s;
			else
				*va_arg(args, unsigned int *) = val.u;
			break;
		}
		num++;

		if (!next)
			break;
		str = next;
	}

	return num;
}
EXPORT_SYMBOL(vsscanf);

/**
 * sscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	formatting of buffer
 * @...:	resulting arguments
 */
int sscanf(const char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsscanf(buf, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sscanf);
