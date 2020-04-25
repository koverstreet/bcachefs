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
*** gf_2vect_dot_prod_sse(len, vec, *g_tbls, **buffs, **dests);
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
#define tmp3  r9
#define tmp4  r12		/* must be saved and restored */
#define return rax
#define PS 8
#define LOG_PS 3

#define len   arg0
#define vec   arg1
#define mul_array arg2
#define	src   arg3
#define dest1  arg4

#define vec_i tmp2
#define ptr   tmp3
#define dest2 tmp4
#define pos   return

/*** Use Un-aligned load/store ***/
#define XLDR movdqu
#define XSTR movdqu

#define xmask0f   xmm8
#define xgft1_lo  xmm7
#define xgft1_hi  xmm6
#define xgft2_lo  xmm5
#define xgft2_hi  xmm4

#define x0     xmm0
#define xtmpa  xmm1
#define xp1    xmm2
#define xp2    xmm3

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_2vect_dot_prod_sse)
	push	r12
	sub	len, 16
	jl	.return_fail
	xor	pos, pos
	movdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */
	sal	vec, LOG_PS		/* vec *= PS. Make vec_i count by PS */
	mov	dest2, [dest1+PS]
	mov	dest1, [dest1]

.loop16:
	pxor	xp1, xp1
	pxor	xp2, xp2
	mov	tmp, mul_array
	xor	vec_i, vec_i

.next_vect:
	mov	ptr, [src+vec_i]

	movdqu	xgft1_lo, [tmp]		/* Load array Ax{00}, Ax{01}, ..., Ax{0f} */
	movdqu	xgft1_hi, [tmp+16]	/*     "     Ax{00}, Ax{10}, ..., Ax{f0} */
	movdqu	xgft2_lo, [tmp+vec*(32/PS)]	/* Load array Bx{00}, Bx{01}, ..., Bx{0f} */
	movdqu	xgft2_hi, [tmp+vec*(32/PS)+16]	/*     "     Bx{00}, Bx{10}, ..., Bx{f0} */
	add	tmp, 32
	add	vec_i, PS
	XLDR	x0, [ptr+pos]		/* Get next source vector */

	movdqa	xtmpa, x0		/* Keep unshifted copy of src */
	psraw	x0, 4			/* Shift to put high nibble into bits 4-0 */
	pand	x0, xmask0f		/* Mask high src nibble in bits 4-0 */
	pand	xtmpa, xmask0f		/* Mask low src nibble in bits 4-0 */

	pshufb	xgft1_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft1_hi, xgft1_lo	/* GF add high and low partials */
	pxor	xp1, xgft1_hi		/* xp1 += partial */
	pshufb	xgft2_hi, x0		/* Lookup mul table of high nibble */
	pshufb	xgft2_lo, xtmpa		/* Lookup mul table of low nibble */
	pxor	xgft2_hi, xgft2_lo	/* GF add high and low partials */
	pxor	xp2, xgft2_hi		/* xp2 += partial */

	cmp	vec_i, vec
	jl	.next_vect

	XSTR	[dest1+pos], xp1
	XSTR	[dest2+pos], xp2

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
	pop	r12
	ret

.return_fail:
	mov	return, 1
	pop	r12
	ret

ENDPROC(gf_2vect_dot_prod_sse)

.section .data

.align 16
mask0f: 
	.quad 0x0f0f0f0f0f0f0f0f
	.quad 0x0f0f0f0f0f0f0f0f

.att_syntax prefix 