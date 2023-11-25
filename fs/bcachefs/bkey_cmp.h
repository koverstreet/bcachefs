/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_CMP_H
#define _BCACHEFS_BKEY_CMP_H

#include "bkey.h"

#ifdef CONFIG_X86_64
static inline int __bkey_cmp_bits(const u64 *l, const u64 *r,
				  unsigned nr_key_bits)
{
	int cmp;

	asm(".intel_syntax noprefix;"
	    "mov eax, %[nr_key_bits];"
	    "mov ecx, 63;"
	    "and eax, ecx;"
	    "sub ecx, eax;"

	    "xor edx, edx;"
	    "neg rdx;"
	    "shl rdx, 1;"
	    "shl rdx, cl;"			// mask for low bits

	    "mov ecx, %[nr_key_bits];"
	    "shr ecx, 6;"			// number of (full) high words
	    "neg rcx;"
	    "lea %[l], [%[l] + 8 * rcx - 8];"
	    "lea %[r], [%[r] + 8 * rcx - 8];"	// l, r now point to low bits

	    "add ecx, 2;"
	    "shl ecx, 4;"			// ecx is now the size of our jump

	    "mov rax, [%[l]];"
	    "and rax, rdx;"
	    "and rdx, [%[r]];"
	    "sub rax, rdx;"			// subtract low bits

	    "jmp cx;"

	    "xchg ax, ax;"
	    "lea %[l], [%[l] + 8];"
	    "lea %[r], [%[r] + 8];"
	    "mov rax, [%[l]];"
	    "sbb rax, [%[r]];"

	    "xchg ax, ax;"
	    "lea %[l], [%[l] + 8];"
	    "lea %[r], [%[r] + 8];"
	    "mov rax, [%[l]];"
	    "sbb rax, [%[r]];"

	    "seta al;"
	    "setb dl;"
	    "sub eax, edx;"
	    ".att_syntax prefix;"
	    : "=&a" (cmp)
	    : [l] "r" (l), [r] "r" (r), [nr_key_bits] "r" (nr_key_bits)
	    : "cx", "dx", "cc", "memory");

	return cmp;
}
#else
static inline int __bkey_cmp_bits(const u64 *l, const u64 *r,
				  unsigned nr_key_bits)
{
	u64 l_v, r_v;

	if (!nr_key_bits)
		return 0;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (!nr_key_bits || l_v != r_v)
			break;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}

	return cmp_int(l_v, r_v);
}
#endif

static inline __pure __flatten
int __bch2_bkey_cmp_packed_format_checked_inlined(const struct bkey_packed *l,
					  const struct bkey_packed *r,
					  const struct btree *b)
{
	const struct bkey_format *f = &b->format;
	int ret;

	EBUG_ON(!bkey_packed(l) || !bkey_packed(r));
	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(f));

	ret = __bkey_cmp_bits(high_word(f, l),
			      high_word(f, r),
			      b->nr_key_bits);

	EBUG_ON(ret != bpos_cmp(bkey_unpack_pos(b, l),
				bkey_unpack_pos(b, r)));
	return ret;
}

static inline __pure __flatten
int bch2_bkey_cmp_packed_inlined(const struct btree *b,
			 const struct bkey_packed *l,
			 const struct bkey_packed *r)
{
	struct bkey unpacked;

	if (likely(bkey_packed(l) && bkey_packed(r)))
		return __bch2_bkey_cmp_packed_format_checked_inlined(l, r, b);

	if (bkey_packed(l)) {
		__bkey_unpack_key_format_checked(b, &unpacked, l);
		l = (void *) &unpacked;
	} else if (bkey_packed(r)) {
		__bkey_unpack_key_format_checked(b, &unpacked, r);
		r = (void *) &unpacked;
	}

	return bpos_cmp(((struct bkey *) l)->p, ((struct bkey *) r)->p);
}

#endif /* _BCACHEFS_BKEY_CMP_H */
