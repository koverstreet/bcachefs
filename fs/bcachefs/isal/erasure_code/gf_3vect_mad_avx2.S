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
*** gf_3vect_mad_avx2(len, vec, vec_i, mul_array, src, dest);
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
#define return rax
#define return_w eax

/*** gf_3vect_mad_avx2(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec    arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest1 arg5
#define pos   return
#define pos_w return_w

#define dest2 mul_array
#define dest3 vec_i

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f   ymm15
#define xmask0fx  xmm15
#define xgft1_lo  ymm14
#define xgft1_hi  ymm13
#define xgft2_lo  ymm12
#define xgft3_lo  ymm11

#define x0      ymm0
#define xtmpa   ymm1
#define xtmph1  ymm2
#define xtmpl1  ymm3
#define xtmph2  ymm4
#define xtmpl2  ymm5
#define xtmpl2x xmm5
#define xtmph3  ymm6
#define xtmpl3  ymm7
#define xtmpl3x xmm7
#define xd1     ymm8
#define xd2     ymm9
#define xd3     ymm10

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_3vect_mad_avx2)
	sub	len, 32
	jl	.return_fail
	xor	pos, pos
	mov	tmp_b, 0x0f
	vpinsrb	xmask0fx, xmask0fx, tmp_w, 0
	vpbroadcastb xmask0f, xmask0fx	/* Construct mask 0x0f0f0f... */

	sal	vec_i, 5		/* Multiply by 32 */
	sal	vec, 5
	lea	tmp, [mul_array + vec_i]

	vmovdqu	xgft1_lo, [tmp]		/* Load array Ax{00}, Ax{01}, ..., Ax{0f} */
					/*      "     Ax{00}, Ax{10}, ..., Ax{f0} */
	vperm2i128 xgft1_hi, xgft1_lo, xgft1_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xgft1_lo, xgft1_lo, xgft1_lo, 0x00 /* swapped to lo | lo */

	vmovdqu	xgft2_lo, [tmp+vec]	/* Load array Bx{00}, Bx{01}, Bx{02}, ... */
					/* " Bx{00}, Bx{10}, Bx{20}, ... , Bx{f0} */
	vmovdqu	xgft3_lo, [tmp+2*vec]	/* Load array Cx{00}, Cx{01}, Cx{02}, ... */
					/* " Cx{00}, Cx{10}, Cx{20}, ... , Cx{f0} */
	mov	dest2, [dest1+PS]	/* reuse mul_array */
	mov	dest3, [dest1+2*PS]	/* reuse vec_i */
	mov	dest1, [dest1]

.loop32:
	XLDR	x0, [src+pos]		/* Get next source vector */
	XLDR	xd1, [dest1+pos]		/* Get next dest vector */
	XLDR	xd2, [dest2+pos]		/* Get next dest vector */
	XLDR	xd3, [dest3+pos]		/* Get next dest vector */
	vperm2i128 xtmph2, xgft2_lo, xgft2_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xtmpl2, xgft2_lo, xgft2_lo, 0x00 /* swapped to lo | lo */

	vperm2i128 xtmph3, xgft3_lo, xgft3_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xtmpl3, xgft3_lo, xgft3_lo, 0x00 /* swapped to lo | lo */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	/* dest1 */
	vpshufb	xtmph1, xgft1_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl1, xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph1, xtmph1, xtmpl1		/* GF add high and low partials */
	vpxor	xd1, xd1, xtmph1		/* xd1 += partial */

	/* dest2 */
	vpshufb	xtmph2, xtmph2, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl2, xtmpl2, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph2, xtmph2, xtmpl2		/* GF add high and low partials */
	vpxor	xd2, xd2, xtmph2		/* xd2 += partial */

	/* dest3 */
	vpshufb	xtmph3, xtmph3, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl3, xtmpl3, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph3, xtmph3, xtmpl3		/* GF add high and low partials */
	vpxor	xd3, xd3, xtmph3		/* xd3 += partial */

	XSTR	[dest1+pos], xd1
	XSTR	[dest2+pos], xd2
	XSTR	[dest3+pos], xd3

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
	vpinsrb	xtmpl2x, xtmpl2x, tmp_w, 0
	vpbroadcastb xtmpl2, xtmpl2x	/* Construct mask 0x1f1f1f... */

	mov	tmp, len		/* Overlapped offset length-32 */

	XLDR	x0, [src+tmp]		/* Get next source vector */
	XLDR	xd1, [dest1+tmp]	/* Get next dest vector */
	XLDR	xd2, [dest2+tmp]	/* Get next dest vector */
	XLDR	xd3, [dest3+tmp]	/* Get next dest vector */

	sub	len, pos

	vmovdqa	xtmph3, [constip32]	/* Load const of i + 32 */
	vpinsrb	xtmpl3x, xtmpl3x, len_w, 15
	vinserti128	xtmpl3, xtmpl3, xtmpl3x, 1 /* swapped to xtmpl3x | xtmpl3x */
	vpshufb	xtmpl3, xtmpl3, xtmpl2	/* Broadcast len to all bytes. xtmpl2=0x1f1f1f... */
	vpcmpgtb	xtmpl3, xtmpl3, xtmph3

	vperm2i128 xtmph2, xgft2_lo, xgft2_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xgft2_lo, xgft2_lo, xgft2_lo, 0x00 /* swapped to lo | lo */

	vperm2i128 xtmph3, xgft3_lo, xgft3_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xgft3_lo, xgft3_lo, xgft3_lo, 0x00 /* swapped to lo | lo */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	/* dest1 */
	vpshufb	xtmph1, xgft1_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl1, xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph1, xtmph1, xtmpl1		/* GF add high and low partials */
	vpand	xtmph1, xtmph1, xtmpl3
	vpxor	xd1, xd1, xtmph1		/* xd1 += partial */

	/* dest2 */
	vpshufb	xtmph2, xtmph2, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft2_lo, xgft2_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph2, xtmph2, xgft2_lo	/* GF add high and low partials */
	vpand	xtmph2, xtmph2, xtmpl3
	vpxor	xd2, xd2, xtmph2		/* xd2 += partial */

	/* dest3 */
	vpshufb	xtmph3, xtmph3, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft3_lo, xgft3_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph3, xtmph3, xgft3_lo	/* GF add high and low partials */
	vpand	xtmph3, xtmph3, xtmpl3
	vpxor	xd3, xd3, xtmph3		/* xd3 += partial */

	XSTR	[dest1+tmp], xd1
	XSTR	[dest2+tmp], xd2
	XSTR	[dest3+tmp], xd3

.return_pass:
	mov	return, 0
	ret

.return_fail:
	mov	return, 1
	ret
ENDPROC(gf_3vect_mad_avx2)

.section .data

.align 32

constip32:
	.quad 0xf8f9fafbfcfdfeff 
	.quad 0xf0f1f2f3f4f5f6f7
	.quad 0xe8e9eaebecedeeef 
	.quad 0xe0e1e2e3e4e5e6e7

.att_syntax prefix 