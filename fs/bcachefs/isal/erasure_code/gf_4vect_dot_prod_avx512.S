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
*** gf_4vect_dot_prod_avx512(len, vec, *g_tbls, **buffs, **dests);
***/

#include <linux/linkage.h>

#define arg0  rdi
#define arg1  rsi
#define arg2  rdx
#define arg3  rcx
#define arg4  r8
#define arg5  r9

#define tmp   r11
#define tmp_w r11d
#define tmp_b r11b
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
#define src    arg3
#define dest1  arg4
#define ptr    arg5
#define vec_i  tmp2
#define dest2  tmp3
#define dest3  tmp4
#define dest4  tmp5
#define vskip3 tmp6
#define pos    return

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu8
#define XSTR vmovdqu8

#define xmask0f   zmm14
#define xgft1_lo  zmm13
#define xgft1_loy ymm13
#define xgft1_hi  zmm12
#define xgft2_lo  zmm11
#define xgft2_loy ymm11
#define xgft2_hi  zmm10
#define xgft3_lo  zmm9
#define xgft3_loy ymm9
#define xgft3_hi  zmm8
#define xgft4_lo  zmm7
#define xgft4_loy ymm7
#define xgft4_hi  zmm6

#define x0        zmm0
#define xtmpa     zmm1
#define xp1       zmm2
#define xp2       zmm3
#define xp3       zmm4
#define xp4       zmm5

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_4vect_dot_prod_avx512)
	push	r12
	push	r13
	push	r14
	push	r15
	sub	len, 64
	jl	.return_fail

	xor	pos, pos
	mov	tmp_w, 0x0f
	vpbroadcastb xmask0f, tmp_w	/* Construct mask 0x0f0f0f... */
	mov	vskip3, vec
	imul	vskip3, 96
	sal	vec, LOG_PS		/* vec *= PS. Make vec_i count by PS */
	mov	dest2, [dest1+PS]
	mov	dest3, [dest1+2*PS]
	mov	dest4, [dest1+3*PS]
	mov	dest1, [dest1]

.loop64:
	vpxorq	xp1, xp1, xp1
	vpxorq	xp2, xp2, xp2
	vpxorq	xp3, xp3, xp3
	vpxorq	xp4, xp4, xp4
	mov	tmp, mul_array
	xor	vec_i, vec_i

.next_vect:
	mov	ptr, [src+vec_i]
	XLDR	x0, [ptr+pos]		/* Get next source vector */
	add	vec_i, PS

	vpandq	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpandq	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	vmovdqu8 xgft1_loy, [tmp]		/* Load array Ax{00}..{0f}, Ax{00}..{f0} */
	vmovdqu8 xgft2_loy, [tmp+vec*(32/PS)]	/* Load array Bx{00}..{0f}, Bx{00}..{f0} */
	vmovdqu8 xgft3_loy, [tmp+vec*(64/PS)]	/* Load array Cx{00}..{0f}, Cx{00}..{f0} */
	vmovdqu8 xgft4_loy, [tmp+vskip3]	/* Load array Dx{00}..{0f}, Dx{00}..{f0} */
	add	tmp, 32

	vshufi64x2 xgft1_hi, xgft1_lo, xgft1_lo, 0x55
	vshufi64x2 xgft1_lo, xgft1_lo, xgft1_lo, 0x00
	vshufi64x2 xgft2_hi, xgft2_lo, xgft2_lo, 0x55
	vshufi64x2 xgft2_lo, xgft2_lo, xgft2_lo, 0x00

	vpshufb	xgft1_hi, xgft1_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft1_lo, xgft1_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xgft1_hi, xgft1_hi, xgft1_lo	/* GF add high and low partials */
	vpxorq	xp1, xp1, xgft1_hi		/* xp1 += partial */

	vpshufb	xgft2_hi, xgft2_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft2_lo, xgft2_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xgft2_hi, xgft2_hi, xgft2_lo	/* GF add high and low partials */
	vpxorq	xp2, xp2, xgft2_hi		/* xp2 += partial */

	vshufi64x2 xgft3_hi, xgft3_lo, xgft3_lo, 0x55
	vshufi64x2 xgft3_lo, xgft3_lo, xgft3_lo, 0x00
	vshufi64x2 xgft4_hi, xgft4_lo, xgft4_lo, 0x55
	vshufi64x2 xgft4_lo, xgft4_lo, xgft4_lo, 0x00

	vpshufb	xgft3_hi, xgft3_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft3_lo, xgft3_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xgft3_hi, xgft3_hi, xgft3_lo	/* GF add high and low partials */
	vpxorq	xp3, xp3, xgft3_hi		/* xp3 += partial */

	vpshufb	xgft4_hi, xgft4_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xgft4_lo, xgft4_lo, xtmpa 	/* Lookup mul table of low nibble */
	vpxorq	xgft4_hi, xgft4_hi, xgft4_lo	/* GF add high and low partials */
	vpxorq	xp4, xp4, xgft4_hi		/* xp4 += partial */

	cmp	vec_i, vec
	jl	.next_vect

	XSTR	[dest1+pos], xp1
	XSTR	[dest2+pos], xp2
	XSTR	[dest3+pos], xp3
	XSTR	[dest4+pos], xp4

	add	pos, 64			/* Loop on 64 bytes at a time */
	cmp	pos, len
	jle	.loop64

	lea	tmp, [len + 64]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, len	/* Overlapped offset length-64 */
	jmp	.loop64		/* Do one more overlap pass */

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
ENDPROC(gf_4vect_dot_prod_avx512)

.att_syntax prefix 