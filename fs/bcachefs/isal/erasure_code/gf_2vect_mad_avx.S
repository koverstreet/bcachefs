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
*** gf_2vect_mad_avx(len, vec, vec_i, mul_array, src, dest);
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
#define tmp2   r10
#define return rax
#define return_w eax

/*** gf_2vect_mad_avx(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec    arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest1 arg5
#define pos   return
#define pos_w return_w

#define dest2 tmp2

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f  xmm14
#define xgft1_lo  xmm13
#define xgft1_hi  xmm12
#define xgft2_lo  xmm11
#define xgft2_hi  xmm10

#define x0      xmm0
#define xtmpa   xmm1
#define xtmph1  xmm2
#define xtmpl1  xmm3
#define xtmph2  xmm4
#define xtmpl2  xmm5
#define xd1     xmm6
#define xd2     xmm7
#define xtmpd1  xmm8
#define xtmpd2  xmm9

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_2vect_mad_avx)
	sub	len, 16
	jl	.return_fail

	xor	pos, pos
	vmovdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */
	sal	vec_i, 5		/* Multiply by 32 */
	sal	vec, 5
	lea	tmp, [mul_array + vec_i]
	vmovdqu	xgft1_lo, [tmp]		/* Load array Ax{00}, Ax{01}, Ax{02}, ... */
	vmovdqu	xgft1_hi, [tmp+16]	/*  " Ax{00}, Ax{10}, Ax{20}, ... , Ax{f0} */
	vmovdqu	xgft2_lo, [tmp+vec]	/* Load array Bx{00}, Bx{01}, Bx{02}, ... */
	vmovdqu	xgft2_hi, [tmp+vec+16]	/*  " Bx{00}, Bx{10}, Bx{20}, ... , Bx{f0} */

	mov	dest2, [dest1+PS]
	mov	dest1, [dest1]

	XLDR	xtmpd1, [dest1+len]	/* backup the last 16 bytes in dest */
	XLDR	xtmpd2, [dest2+len]	/* backup the last 16 bytes in dest */

.loop16:
	XLDR	xd1, [dest1+pos]		/* Get next dest vector */
	XLDR	xd2, [dest2+pos]		/* Get next dest vector */
.loop16_overlap:
	XLDR	x0, [src+pos]		/* Get next source vector */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	vpshufb	xtmph1, xgft1_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl1, xgft1_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph1, xtmph1, xtmpl1 /* GF add high and low partials */
	vpxor	xd1, xd1, xtmph1	/* xd1 += partial */

	vpshufb	xtmph2, xgft2_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl2, xgft2_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph2, xtmph2, xtmpl2 /* GF add high and low partials */
	vpxor	xd2, xd2, xtmph2	/* xd2 += partial */

	XSTR	[dest1+pos], xd1
	XSTR	[dest2+pos], xd2

	add	pos, 16			/* Loop on 16 bytes at a time */
	cmp	pos, len
	jle	.loop16

	lea	tmp, [len + 16]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, len	/* Overlapped offset length-16 */
	vmovdqa	xd1, xtmpd1	/* Restore xd1 */
	vmovdqa	xd2, xtmpd2	/* Restore xd2 */
	jmp	.loop16_overlap	/* Do one more overlap pass */

.return_pass:
	mov	return, 0
	ret

.return_fail:
	mov	return, 1
	ret
ENDPROC(gf_2vect_mad_avx)

.section .data

.align 16
mask0f: 
	.quad 0x0f0f0f0f0f0f0f0f
	.quad 0x0f0f0f0f0f0f0f0f

.att_syntax prefix 