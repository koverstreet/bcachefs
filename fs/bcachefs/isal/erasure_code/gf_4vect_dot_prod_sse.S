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
*** gf_4vect_dot_prod_sse(len, vec, *g_tbls, **buffs, **dests)*
***/

#include <linux/linkage.h>

 #define arg0  rdi
 #define arg1  rsi
 #define arg2  rdx
 #define arg3  rcx
 #define arg4  r8
 #define arg5  r9

 #define tmp   r11
 #define tmp2  r10
 #define tmp3  r13		/* must be saved and restored */
 #define tmp4  r12		/* must be saved and restored */
 #define tmp5  r14		/* must be saved and restored */
 #define tmp6  r15		/* must be saved and restored */
 #define return rax
 #define PS     8
 #define LOG_PS 3

#define len    arg0
#define vec    arg1
#define mul_array arg2
#define	src    arg3
#define dest1  arg4
#define ptr    arg5
#define vec_i  tmp2
#define dest2  tmp3
#define dest3  tmp4
#define dest4  tmp5
#define vskip3 tmp6
#define pos    return

/*** Use Un-aligned load/store ***/
#define XLDR movdqu
#define XSTR movdqu

#define xmask0f   xmm14
#define xgft1_lo  xmm2
#define xgft1_hi  xmm3
#define xgft2_lo  xmm11
#define xgft2_hi  xmm4
#define xgft3_lo  xmm9
#define xgft3_hi  xmm5
#define xgft4_lo  xmm7
#define xgft4_hi  xmm6

#define x0     xmm0
#define xtmpa  xmm1
#define xp1    xmm8
#define xp2    xmm10
#define xp3    xmm12
#define xp4    xmm13

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_4vect_dot_prod_sse)
	push	r12
	push	r13
	push	r14
	push	r15

	sub	len, 16
	jl	.return_fail
	xor	pos, pos
	movdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */
	mov	vskip3,  vec
	imul	vskip3,  96
	sal	vec, 	 LOG_PS		/* vec *= PS. Make vec_i count by PS */
	mov	dest2, 	 [dest1+PS]
	mov	dest3, 	 [dest1+2*PS]
	mov	dest4, 	 [dest1+3*PS]
	mov	dest1, 	 [dest1]

.loop16:
	pxor	xp1, xp1
	pxor	xp2, xp2
	pxor	xp3, xp3
	pxor	xp4, xp4
	mov	tmp, mul_array
	xor	vec_i, vec_i

.next_vect:
	mov	ptr, [src+vec_i]

	movdqu	xgft1_lo, [tmp]			/* Load array Ax{00}, Ax{01}, ..., Ax{0f} */
	movdqu	xgft1_hi, [tmp+16]		/*      "     Ax{00}, Ax{10}, ..., Ax{f0} */
	movdqu	xgft2_lo, [tmp+vec*(32/PS)]	/* Load array Bx{00}, Bx{01}, ..., Bx{0f} */
	movdqu	xgft2_hi, [tmp+vec*(32/PS)+16]	/*      "     Bx{00}, Bx{10}, ..., Bx{f0} */
	movdqu	xgft3_lo, [tmp+vec*(64/PS)]	/* Load array Cx{00}, Cx{01}, ..., Cx{0f} */
	movdqu	xgft3_hi, [tmp+vec*(64/PS)+16]	/*      "     Cx{00}, Cx{10}, ..., Cx{f0} */
	movdqu	xgft4_lo, [tmp+vskip3]		/* Load array Dx{00}, Dx{01}, ..., Dx{0f} */
	movdqu	xgft4_hi, [tmp+vskip3+16]	/*      "     Dx{00}, Dx{10}, ..., Dx{f0} */

	XLDR	x0, 	[ptr+pos]	/* Get next source vector */
	add	tmp, 	32
	add	vec_i, 	PS

	movdqa	xtmpa, x0		/* Keep unshifted copy of src */
	psraw	x0, 4			/* Shift to put high nibble into bits 4-0 */
	pand	x0, xmask0f		/* Mask high src nibble in bits 4-0 */
	pand	xtmpa, 	xmask0f		/* Mask low src nibble in bits 4-0 */

	pshufb	xgft1_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft1_hi, xgft1_lo	/* GF add high and low partials */
	pxor	xp1, xgft1_hi		/* xp1 += partial */

	pshufb	xgft2_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft2_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft2_hi, xgft2_lo	/* GF add high and low partials */
	pxor	xp2, xgft2_hi		/* xp2 += partial */

	pshufb	xgft3_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft3_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft3_hi, xgft3_lo	/* GF add high and low partials */
	pxor	xp3, xgft3_hi		/* xp3 += partial */

	pshufb	xgft4_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft4_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft4_hi, xgft4_lo	/* GF add high and low partials */
	pxor	xp4, xgft4_hi		/* xp4 += partial */

	cmp	vec_i, vec
	jl	.next_vect

	XSTR	[dest1+pos], xp1
	XSTR	[dest2+pos], xp2
	XSTR	[dest3+pos], xp3
	XSTR	[dest4+pos], xp4

	add	pos, 16			/* Loop on 16 bytes at a time */
	cmp	pos, len
	jle	.loop16

	lea	tmp, [len + 16]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, len	/* Overlapped offset length-16 */
	jmp	.loop16		/* Do one more overlap pass */

.return_pass:
	mov	return, 0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

.return_fail:
	mov	return, 1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

ENDPROC(gf_4vect_dot_prod_sse)

.section .data

.align 16

mask0f:	
	.quad 0x0f0f0f0f0f0f0f0f
	.quad 0x0f0f0f0f0f0f0f0f

.att_syntax prefix 