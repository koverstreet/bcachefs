/************************************************************************
*  Copyright(c) 2011-2015 Intel Corporation All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*    * Redistributions of source code must retain the above copyright
*      notice, this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in
*      the documentation and/or other materials provided with the
*      distribution.
*    * Neither the name of Intel Corporation nor the names of its
*      contributors may be used to endorse or promote products derived
*      from this software without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
*  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
*  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES* LOSS OF USE,
*  DATA, OR PROFITS* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
*  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
************************************************************************/

/***
*** gf_6vect_mad_avx2(len, vec, vec_i, mul_array, src, dest);
***/

#include <linux/linkage.h>

#define PS 8

#define arg0  rdi
#define arg0_w edi
#define arg1  rsi
#define arg2  rdx
#define arg3  rcx
#define arg4  r8
#define arg5  r9
#define tmp   r11
#define tmp_w r11d
#define tmp_b r11b
#define tmp2   r10
#define tmp3   r12
#define return rax
#define return_w eax

/*** gf_6vect_mad_avx2(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec    arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest1  arg5
#define pos   return
#define pos_w return_w

#define dest2 tmp3
#define dest3 tmp2
#define dest4 mul_array
#define dest5 vec
#define dest6 vec_i

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f  ymm15
#define xmask0fx  xmm15
#define xgft1_lo  ymm14
#define xgft2_lo  ymm13
#define xgft3_lo  ymm12
#define xgft4_lo  ymm11
#define xgft5_lo  ymm10
#define xgft6_lo  ymm9

#define x0         ymm0
#define xtmpa      ymm1
#define xtmpl      ymm2
#define xtmplx     xmm2
#define xtmph      ymm3
#define xtmphx     xmm3
#define xd1        ymm4
#define xd2        ymm5
#define xd3        ymm6
#define xd4        ymm7
#define xd5        ymm8
#define xd6        xd1

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_6vect_mad_avx2)
	push	r12
	sub	len, 32
	jl	.return_fail
	xor	pos, pos
	mov	tmp_b, 0x0f
	vpinsrb	xmask0fx, xmask0fx, tmp_w, 0
	vpbroadcastb xmask0f, xmask0fx	/* Construct mask 0x0f0f0f... */

	sal	vec_i, 5		/* Multiply by 32 */
	sal	vec, 5			/* Multiply by 32 */
	lea	tmp, [mul_array + vec_i]
	mov	vec_i, vec
	mov	mul_array, vec
	sal	vec_i, 1
	sal	mul_array, 1
	add	vec_i, vec		/* vec_i=vec*96 */
	add	mul_array, vec_i	/* vec_i=vec*160 */

	vmovdqu	xgft1_lo, [tmp]			/* Load array Ax{00}, Ax{01}, ..., Ax{0f} */
						/*     "     Ax{00}, Ax{10}, ..., Ax{f0} */
	vmovdqu	xgft2_lo, [tmp+vec]		/* Load array Bx{00}, Bx{01}, ..., Bx{0f} */
						/*     "     Bx{00}, Bx{10}, ..., Bx{f0} */
	vmovdqu	xgft3_lo, [tmp+2*vec]		/* Load array Cx{00}, Cx{01}, ..., Cx{0f} */
						/*     "     Cx{00}, Cx{10}, ..., Cx{f0} */
	vmovdqu	xgft4_lo, [tmp+vec_i]		/* Load array Fx{00}, Fx{01}, ..., Fx{0f} */
						/*     "     Fx{00}, Fx{10}, ..., Fx{f0} */
	vmovdqu	xgft5_lo, [tmp+4*vec]		/* Load array Ex{00}, Ex{01}, ..., Ex{0f} */
						/*     "     Ex{00}, Ex{10}, ..., Ex{f0} */
	vmovdqu	xgft6_lo, [tmp+mul_array]	/* Load array Dx{00}, Dx{01}, ..., Dx{0f} */
						/*     "     Dx{00}, Dx{10}, ..., Dx{f0} */

	mov	dest2, [dest1+PS]    /* reuse tmp3 */
	mov	dest3, [dest1+2*PS]  /* reuse tmp2 */
	mov	dest4, [dest1+3*PS]  /* reuse mul_array */
	mov	dest5, [dest1+4*PS]  /* reuse vec */
	mov	dest6, [dest1+5*PS]  /* reuse vec_i */
	mov	dest1, [dest1]

.loop32:
	XLDR	x0, [src+pos]		/* Get next source vector */
	XLDR	xd1, [dest1+pos]	/* Get next dest vector */
	XLDR	xd2, [dest2+pos]	/* Get next dest vector */
	XLDR	xd3, [dest3+pos]	/* Get next dest vector */
	XLDR	xd4, [dest4+pos]	/* Get next dest vector */
	XLDR	xd5, [dest5+pos]	/* Get next dest vector */

	vpand	xtmpl, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */
	vperm2i128 xtmpa, xtmpl, x0, 0x30 	/* swap xtmpa from 1lo|2lo to 1lo|2hi */
	vperm2i128 x0, xtmpl, x0, 0x12	/* swap x0 from    1hi|2hi to 1hi|2lo */

	/* dest1 */
	vperm2i128 xtmph, xgft1_lo, xgft1_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd1, xd1, xtmph		/* xd1 += partial */

	XSTR	[dest1+pos], xd1	/* Store result into dest1 */

	/* dest2 */
	vperm2i128 xtmph, xgft2_lo, xgft2_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft2_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd2, xd2, xtmph		/* xd2 += partial */

	/* dest3 */
	vperm2i128 xtmph, xgft3_lo, xgft3_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft3_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd3, xd3, xtmph		/* xd3 += partial */

	XLDR	xd6, [dest6+pos]	/* reuse xd1. Get next dest vector */

	/* dest4 */
	vperm2i128 xtmph, xgft4_lo, xgft4_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft4_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd4, xd4, xtmph		/* xd4 += partial */

	/* dest5 */
	vperm2i128 xtmph, xgft5_lo, xgft5_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft5_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd5, xd5, xtmph		/* xd5 += partial */

	/* dest6 */
	vperm2i128 xtmph, xgft6_lo, xgft6_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft6_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl		/* GF add high and low partials */
	vpxor	xd6, xd6, xtmph		/* xd6 += partial */

	XSTR	[dest2+pos], xd2	/* Store result into dest2 */
	XSTR	[dest3+pos], xd3	/* Store result into dest3 */
	XSTR	[dest4+pos], xd4	/* Store result into dest4 */
	XSTR	[dest5+pos], xd5	/* Store result into dest5 */
	XSTR	[dest6+pos], xd6	/* Store result into dest6 */

	add	pos, 32			/* Loop on 32 bytes at a time */
	cmp	pos, len
	jle	.loop32

	lea	tmp, [len + 32]
	cmp	pos, tmp
	je	.return_pass

.lessthan32:
	/** Tail len **/
	/** Do one more overlap pass **/
	mov	tmp_b, 0x1f
	vpinsrb	xtmphx, xtmphx, tmp_w, 0
	vpbroadcastb xtmph, xtmphx	/* Construct mask 0x1f1f1f... */

	mov	tmp, len		/* Overlapped offset length-32 */

	XLDR	x0, [src+tmp]		/* Get next source vector */
	XLDR	xd1, [dest1+tmp]	/* Get next dest vector */
	XLDR	xd2, [dest2+tmp]	/* Get next dest vector */
	XLDR	xd3, [dest3+tmp]	/* Get next dest vector */
	XLDR	xd4, [dest4+tmp]	/* Get next dest vector */
	XLDR	xd5, [dest5+tmp]	/* Get next dest vector */

	sub	len, pos

	vpinsrb	xtmplx, xtmplx, len_w, 15
	vinserti128	xtmpl, xtmpl, xtmplx, 1 /* swapped to xtmplx | xtmplx */
	vpshufb	xtmpl, xtmpl, xtmph	/* Broadcast len to all bytes. xtmph=0x1f1f1f... */
	vpcmpgtb	xtmpl, xtmpl, [constip32]

	vpand	xtmph, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */
	vperm2i128 xtmpa, xtmph, x0, 0x30 	/* swap xtmpa from 1lo|2lo to 1lo|2hi */
	vperm2i128 x0, xtmph, x0, 0x12	/* swap x0 from    1hi|2hi to 1hi|2lo */

	/* dest1 */
	vperm2i128 xtmph, xgft1_lo, xgft1_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft1_lo, xgft1_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft1_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd1, xd1, xtmph		/* xd1 += partial */

	XSTR	[dest1+tmp], xd1	/* Store result into dest1 */

	/* dest2 */
	vperm2i128 xtmph, xgft2_lo, xgft2_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft2_lo, xgft2_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft2_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd2, xd2, xtmph		/* xd2 += partial */

	/* dest3 */
	vperm2i128 xtmph, xgft3_lo, xgft3_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft3_lo, xgft3_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft3_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd3, xd3, xtmph		/* xd3 += partial */

	XLDR	xd6, [dest6+tmp]	/* reuse xd1. Get next dest vector */

	/* dest4 */
	vperm2i128 xtmph, xgft4_lo, xgft4_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft4_lo, xgft4_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft4_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd4, xd4, xtmph		/* xd4 += partial */

	/* dest5 */
	vperm2i128 xtmph, xgft5_lo, xgft5_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft5_lo, xgft5_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft5_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd5, xd5, xtmph		/* xd5 += partial */

	/* dest6 */
	vperm2i128 xtmph, xgft6_lo, xgft6_lo, 0x01 /* swapped to hi | lo */
	vpshufb	xtmph, xtmph, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft6_lo, xgft6_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xgft6_lo		/* GF add high and low partials */
	vpand	xtmph, xtmph, xtmpl
	vpxor	xd6, xd6, xtmph		/* xd6 += partial */

	XSTR	[dest2+tmp], xd2	/* Store result into dest2 */
	XSTR	[dest3+tmp], xd3	/* Store result into dest3 */
	XSTR	[dest4+tmp], xd4	/* Store result into dest4 */
	XSTR	[dest5+tmp], xd5	/* Store result into dest5 */
	XSTR	[dest6+tmp], xd6	/* Store result into dest6 */

.return_pass:
	pop	r12
	mov	return, 0
	ret

.return_fail:
	pop	r12
	mov	return, 1
	ret
ENDPROC(gf_6vect_mad_avx2)

.section .data
.align 32

constip32:
	.quad 0xf8f9fafbfcfdfeff
	.quad 0xf0f1f2f3f4f5f6f7
	.quad 0xe8e9eaebecedeeef
	.quad 0xe0e1e2e3e4e5e6e7

.att_syntax prefix 