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
*** gf_4vect_mad_avx(len, vec, vec_i, mul_array, src, dest);
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
 #define tmp3   r12
 #define return rax
 #define return_w eax

/*** gf_4vect_mad_avx(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec    arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest1  arg5
#define pos   return
#define pos_w return_w

#define dest2 mul_array
#define dest3 tmp2
#define dest4 vec_i

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f  xmm15
#define xgft3_hi xmm14
#define xgft4_hi xmm13
#define xgft4_lo xmm12

#define x0      xmm0
#define xtmpa   xmm1
#define xtmph1  xmm2
#define xtmpl1  xmm3
#define xtmph2  xmm4
#define xtmpl2  xmm5
#define xtmph3  xmm6
#define xtmpl3  xmm7
#define xtmph4  xmm8
#define xtmpl4  xmm9
#define xd1     xmm10
#define xd2     xmm11
#define xd3     xtmph1
#define xd4     xtmpl1

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_4vect_mad_avx)
	push	r12
	sub	len, 16
	jl	.return_fail
	xor	pos, pos
	vmovdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */

	mov	tmp, vec

	sal	vec_i, 5		/* Multiply by 32 */
	lea	tmp3, [mul_array + vec_i]

	sal	tmp, 6			/* Multiply by 64 */
	vmovdqu	xgft3_hi, [tmp3+tmp+16]	/*  " Cx{00}, Cx{10}, Cx{20}, ... , Cx{f0} */
	sal	vec, 5			/* Multiply by 32 */
	add	tmp, vec
	vmovdqu	xgft4_lo, [tmp3+tmp]	/* Load array Dx{00}, Dx{01}, Dx{02}, ... */
	vmovdqu	xgft4_hi, [tmp3+tmp+16]	/*  " Dx{00}, Dx{10}, Dx{20}, ... , Dx{f0} */

	mov	dest2, [dest1+PS]		/*  reuse mul_array */
	mov	dest3, [dest1+2*PS]
	mov	dest4, [dest1+3*PS]		/*  reuse vec_i */
	mov	dest1, [dest1]

.loop16:
	XLDR	x0, [src+pos]		/* Get next source vector */
	vmovdqu	xtmph1, [tmp3+16]	/*  " Ax{00}, Ax{10}, Ax{20}, ... , Ax{f0} */
	vmovdqu	xtmpl1, [tmp3]		/* Load array Ax{00}, Ax{01}, Ax{02}, ... */
	vmovdqu	xtmph2, [tmp3+vec+16]	/*  " Bx{00}, Bx{10}, Bx{20}, ... , Bx{f0} */
	vmovdqu	xtmpl2, [tmp3+vec]	/* Load array Bx{00}, Bx{01}, Bx{02}, ... */
	vmovdqu	xtmpl3, [tmp3+2*vec]	/* Load array Cx{00}, Cx{01}, Cx{02}, ... */

	XLDR	xd1, [dest1+pos]	/* Get next dest vector */
	XLDR	xd2, [dest2+pos]	/* Get next dest vector */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	/* dest1 */
	vpshufb	xtmph1, xtmph1, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl1, xtmpl1, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph1, xtmph1, xtmpl1		/* GF add high and low partials */
	vpxor	xd1, xd1, xtmph1

	XLDR	xd3, [dest3+pos]	/* Reuse xtmph1, Get next dest vector */
	XLDR	xd4, [dest4+pos]	/* Reuse xtmpl1, Get next dest vector */

	/* dest2 */
	vpshufb	xtmph2, xtmph2, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl2, xtmpl2, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph2, xtmph2, xtmpl2		/* GF add high and low partials */
	vpxor	xd2, xd2, xtmph2

	/* dest3 */
	vpshufb	xtmph3, xgft3_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl3, xtmpl3, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph3, xtmph3, xtmpl3		/* GF add high and low partials */
	vpxor	xd3, xd3, xtmph3

	/* dest4 */
	vpshufb	xtmph4, xgft4_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl4, xgft4_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xtmph4, xtmph4, xtmpl4		/* GF add high and low partials */
	vpxor	xd4, xd4, xtmph4

	XSTR	[dest1+pos], xd1	/* Store result */
	XSTR	[dest2+pos], xd2	/* Store result */
	XSTR	[dest3+pos], xd3	/* Store result */
	XSTR	[dest4+pos], xd4	/* Store result */

	add	pos, 16			/* Loop on 16 bytes at a time */
	cmp	pos, len
	jle	.loop16

	lea	tmp, [len + 16]
	cmp	pos, tmp
	je	.return_pass

.lessthan16:
	/** Tail len **/
	/** Do one more overlap pass **/

	mov	tmp, len	/* Overlapped offset length-16 */

	XLDR	x0, [src+tmp]		/* Get next source vector */

	vmovdqu	xtmph1, [tmp3+16]	/*  " Ax{00}, Ax{10}, Ax{20}, ... , Ax{f0} */
	vmovdqu	xtmpl1, [tmp3]		/* Load array Ax{00}, Ax{01}, Ax{02}, ... */
	vmovdqu	xtmph2, [tmp3+vec+16]	/*  " Bx{00}, Bx{10}, Bx{20}, ... , Bx{f0} */
	vmovdqu	xtmpl2, [tmp3+vec]	/* Load array Bx{00}, Bx{01}, Bx{02}, ... */
	vmovdqu	xtmpl3, [tmp3+2*vec]	/* Load array Cx{00}, Cx{01}, Cx{02}, ... */

	XLDR	xd1, [dest1+tmp]	/* Get next dest vector */
	XLDR	xd2, [dest2+tmp]	/* Get next dest vector */
	XLDR	xtmph4, [dest3+tmp]	/* Get next dest vector */

	sub	len, pos

	vmovdqa	xtmpl4, [constip16]	/* Load const of i + 16 */
	vpinsrb	xtmph3, xtmph3, len_w, 15
	vpshufb	xtmph3, xtmph3, xmask0f		/* Broadcast len to all bytes */
	vpcmpgtb	xtmph3, xtmph3, xtmpl4

	XLDR	xtmpl4, [dest4+tmp]	/* Get next dest vector */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	/* dest1 */
	vpshufb	xtmph1, xtmph1, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl1, xtmpl1, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph1, xtmph1, xtmpl1	/* GF add high and low partials */
	vpand	xtmph1, xtmph1, xtmph3
	vpxor	xd1, xd1, xtmph1

	/* dest2 */
	vpshufb	xtmph2, xtmph2, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl2, xtmpl2, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph2, xtmph2, xtmpl2	/* GF add high and low partials */
	vpand	xtmph2, xtmph2, xtmph3
	vpxor	xd2, xd2, xtmph2

	/* dest3 */
	vpshufb	xgft3_hi, xgft3_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl3, xtmpl3, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft3_hi, xgft3_hi, xtmpl3	/* GF add high and low partials */
	vpand	xgft3_hi, xgft3_hi, xtmph3
	vpxor	xtmph4, xtmph4, xgft3_hi

	/* dest4 */
	vpshufb	xgft4_hi, xgft4_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft4_lo, xgft4_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xgft4_hi, xgft4_hi, xgft4_lo	/* GF add high and low partials */
	vpand	xgft4_hi, xgft4_hi, xtmph3
	vpxor	xtmpl4, xtmpl4, xgft4_hi

	XSTR	[dest1+tmp], xd1	/* Store result */
	XSTR	[dest2+tmp], xd2	/* Store result */
	XSTR	[dest3+tmp], xtmph4	/* Store result */
	XSTR	[dest4+tmp], xtmpl4	/* Store result */

.return_pass:
	mov	return, 0
	pop	r12
	ret

.return_fail:
	mov	return, 1
	pop	r12
	ret

ENDPROC(gf_4vect_mad_avx)

.section .data

.align 16

mask0f:	
	.quad 0x0f0f0f0f0f0f0f0f 
	.quad 0x0f0f0f0f0f0f0f0f

constip16:
	.quad 0xf8f9fafbfcfdfeff 
	.quad 0xf0f1f2f3f4f5f6f7

.att_syntax prefix 