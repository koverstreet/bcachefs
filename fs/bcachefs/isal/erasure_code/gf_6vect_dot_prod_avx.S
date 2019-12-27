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
*** gf_6vect_dot_prod_avx(len, vec, *g_tbls, **buffs, **dests);
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
#define PS 8
#define LOG_PS 3

#define len    arg0
#define vec    arg1
#define mul_array arg2
#define	src    arg3
#define dest   arg4
#define ptr    arg5
#define vec_i  tmp2
#define dest1  tmp3
#define dest2  tmp4
#define vskip1 tmp5
#define vskip3 tmp6
#define pos    return

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f   xmm15
#define xgft1_lo  xmm14
#define xgft1_hi  xmm13
#define xgft2_lo  xmm12
#define xgft2_hi  xmm11
#define xgft3_lo  xmm10
#define xgft3_hi  xmm9
#define x0     xmm0
#define xtmpa  xmm1
#define xp1    xmm2
#define xp2    xmm3
#define xp3    xmm4
#define xp4    xmm5
#define xp5    xmm6
#define xp6    xmm7

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_6vect_dot_prod_avx)
	push	r12
	push	r13
	push	r14
	push	r15
	sub	len, 16
	jl	.return_fail
	xor	pos, pos
	vmovdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */
	mov	vskip1, vec
	imul	vskip1, 32
	mov	vskip3, vec
	imul	vskip3, 96
	sal	vec, LOG_PS		/* vec *= PS. Make vec_i count by PS */
	mov	dest1, [dest]
	mov	dest2, [dest+PS]


.loop16:
	mov	tmp, mul_array
	xor	vec_i, vec_i
	vpxor	xp1, xp1, xp1
	vpxor	xp2, xp2, xp2
	vpxor	xp3, xp3, xp3
	vpxor	xp4, xp4, xp4
	vpxor	xp5, xp5, xp5
	vpxor	xp6, xp6, xp6

.next_vect:
	mov	ptr, [src+vec_i]
	add	vec_i, PS
	XLDR	x0, [ptr+pos]		/* Get next source vector */

	vmovdqu	xgft1_lo, [tmp]			/* Load array Ax{00}, Ax{01}, ..., Ax{0f} */
	vmovdqu	xgft1_hi, [tmp+16]		/*      "     Ax{00}, Ax{10}, ..., Ax{f0} */
	vmovdqu	xgft2_lo, [tmp+vskip1*1]	/* Load array Bx{00}, Bx{01}, ..., Bx{0f} */
	vmovdqu	xgft2_hi, [tmp+vskip1*1+16]	/*      "     Bx{00}, Bx{10}, ..., Bx{f0} */
	vmovdqu	xgft3_lo, [tmp+vskip1*2]	/* Load array Cx{00}, Cx{01}, ..., Cx{0f} */
	vmovdqu	xgft3_hi, [tmp+vskip1*2+16]	/*      "     Cx{00}, Cx{10}, ..., Cx{f0} */
	lea	ptr, [vskip1 + vskip1*4]	/* ptr = vskip5 */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */


	vpshufb	xgft1_hi, xgft1_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft1_lo, xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft1_hi, xgft1_hi, xgft1_lo	/* GF add high and low partials */
	vpxor	xp1, xp1, xgft1_hi		/* xp1 += partial */

	vpshufb	xgft2_hi, xgft2_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft2_lo, xgft2_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft2_hi, xgft2_hi, xgft2_lo	/* GF add high and low partials */
	vpxor	xp2, xp2, xgft2_hi		/* xp2 += partial */

	vpshufb	xgft3_hi, xgft3_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft3_lo, xgft3_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft3_hi, xgft3_hi, xgft3_lo	/* GF add high and low partials */
	vpxor	xp3, xp3, xgft3_hi		/* xp3 += partial */


	vmovdqu	xgft1_lo, [tmp+vskip3]		/* Load array Dx{00}, Dx{01}, ..., Dx{0f} */
	vmovdqu	xgft1_hi, [tmp+vskip3+16]	/*      "     Dx{00}, Dx{10}, ..., Dx{f0} */
	vmovdqu	xgft2_lo, [tmp+vskip1*4]	/* Load array Ex{00}, Ex{01}, ..., Ex{0f} */
	vmovdqu	xgft2_hi, [tmp+vskip1*4+16]	/*      "     Ex{00}, Ex{10}, ..., Ex{f0} */
	vmovdqu	xgft3_lo, [tmp+ptr]			/* Load array Fx{00}, Fx{01}, ..., Fx{0f} */
	vmovdqu	xgft3_hi, [tmp+ptr+16]		/*      "     Fx{00}, Fx{10}, ..., Fx{f0} */
	add	tmp, 32


	vpshufb	xgft1_hi, xgft1_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft1_lo, xgft1_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft1_hi, xgft1_hi, xgft1_lo	/* GF add high and low partials */
	vpxor	xp4, xp4, xgft1_hi		/* xp4 += partial */

	vpshufb	xgft2_hi, xgft2_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft2_lo, xgft2_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft2_hi, xgft2_hi, xgft2_lo	/* GF add high and low partials */
	vpxor	xp5, xp5, xgft2_hi		/* xp5 += partial */

	vpshufb	xgft3_hi, xgft3_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft3_lo, xgft3_lo, xtmpa		/* Lookup mul table of low nibble */
	vpxor	xgft3_hi, xgft3_hi, xgft3_lo	/* GF add high and low partials */
	vpxor	xp6, xp6, xgft3_hi		/* xp6 += partial */

	cmp	vec_i, vec
	jl	.next_vect


	mov	tmp, [dest+2*PS]
	mov	ptr, [dest+3*PS]
	mov	vec_i, [dest+4*PS]

	XSTR	[dest1+pos], xp1
	XSTR	[dest2+pos], xp2
	XSTR	[tmp+pos], xp3
	mov	tmp, [dest+5*PS]
	XSTR	[ptr+pos], xp4
	XSTR	[vec_i+pos], xp5
	XSTR	[tmp+pos], xp6

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
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	mov	return, 0
	ret

.return_fail:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	mov	return, 1
	ret
ENDPROC(gf_6vect_dot_prod_avx)

.section .data

.align 16

mask0f:	
	.quad 0x0f0f0f0f0f0f0f0f
	.quad 0x0f0f0f0f0f0f0f0f

.att_syntax prefix 