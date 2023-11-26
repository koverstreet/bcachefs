/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_CMP_H
#define _BCACHEFS_BKEY_CMP_H

#include "bkey.h"

#ifdef CONFIG_X86_64
static inline int __bkey_cmp_bits(const u64 *l, const u64 *r, unsigned nr_key_bits)
{
	s8 cmp;

	asm(".intel_syntax noprefix;"
	    "mov eax, %[nr_key_bits];"
	    "mov ecx, 63;"
	    "and eax, ecx;"
	    "sub ecx, eax;"

	    "xor ebx, ebx;"
	    "not rbx;"
	    "shl rbx, 1;"
	    "shl rbx, cl;"			// mask for low bits

	    "mov ecx, %[nr_key_bits];"
	    "shr ecx, 6;"			// number of (full) high words
	    "neg ecx;"
	    "add ecx, 2;"

	    "mov rax, [%[l]];"
	    "and rax, rbx;"
	    "and rbx, [%[r]];"
	    "sub rax, rbx;"			// subtract low bits

	    "lea rax, [1f + 8 * rcx];"
	    "jmp rax;"

	    "1:;"

	    "mov rbx, [%[l] + 8];"
	    "sbb rbx, [%[r] + 8];"

	    "mov rbx, [%[l] + 16];"
	    "sbb rbx, [%[r] + 16];"

	    "seta al;"
	    "setb dl;"
	    "sub al, dl;"
	    ".att_syntax prefix;"
	    : "=&a" (cmp), [l] "+r" (l), [r] "+r" (r)
	    : [nr_key_bits] "r" (nr_key_bits)
	    : "cx", "dx", "bx", "cc", "memory");

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

noinline
int __bch2_bkey_cmp_packed2(const struct bkey_packed *l,
			    const struct bkey_packed *r,
			    const struct btree *b);

static inline __pure
int __bch2_bkey_cmp_packed_format_checked_inlined(const struct bkey_packed *l,
					  const struct bkey_packed *r,
					  const struct btree *b)
{
	//const struct bkey_format *f = &b->format;
	int ret;

	//EBUG_ON(!bkey_packed(l) || !bkey_packed(r));
	//EBUG_ON(b->nr_key_bits != bkey_format_key_bits(f));

	int ret2 = __bch2_bkey_cmp_packed2(l, r, b);

	ret = __bkey_cmp_bits((u64 *) l + b->key_low_word_start,
			      (u64 *) r + b->key_low_word_start,
			      b->nr_key_bits);
	BUG_ON(ret != ret2);
	return ret;
}

static inline __pure
int bch2_bkey_cmp_packed_inlined(const struct btree *b,
			 const struct bkey_packed *l,
			 const struct bkey_packed *r)
{
	struct bkey unpacked;

	if (likely(bkey_packed(l) && bkey_packed(r)))
		return __bch2_bkey_cmp_packed_format_checked(l, r, b);

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
