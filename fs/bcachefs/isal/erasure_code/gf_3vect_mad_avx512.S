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
*** gf_3vect_mad_avx512(len, vec, vec_i, mul_array, src, dest);
***/

#include <linux/linkage.h>

#define arg0   rdi
#define arg1   rsi
#define arg2   rdx
#define arg3   rcx
#define arg4   r8
#define arg5   r9
#define tmp    r11
#define tmp_w    r11d
#define return rax

#define PS    8
#define len   arg0
#define vec   arg1
#define vec_i arg2
#define mul_array arg3
#define	src   arg4
#define dest1 arg5
#define pos   return
#define dest2 mul_array
#define dest3 vec_i

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu8
#define XSTR vmovdqu8

#define x0        zmm0
#define xtmpa     zmm1
#define xtmph1    zmm2
#define xtmpl1    zmm3
#define xtmph2    zmm4
#define xtmpl2    zmm5
#define xtmph3    zmm6
#define xtmpl3    zmm7
#define xgft1_hi  zmm8
#define xgft1_lo  zmm9
#define xgft1_loy ymm9
#define xgft2_hi  zmm10
#define xgft2_lo  zmm11
#define xgft2_loy ymm11
#define xgft3_hi  zmm12
#define xgft3_lo  zmm13
#define xgft3_loy ymm13
#define xd1       zmm14
#define xd2       zmm15
#define xd3       zmm16
#define xmask0f   zmm17

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_3vect_mad_avx512)
	sub	len, 64
	jl	.return_fail
	xor	pos, pos
	mov	tmp_w, 0x0f
	vpbroadcastb xmask0f, tmp_w	/* Construct mask 0x0f0f0f... */
	sal	vec_i, 5		/* Multiply by 32 */
	sal	vec, 5
	lea	tmp, [mul_array + vec_i]
	vmovdqu	xgft1_loy, [tmp]	/* Load array Ax{00}..{0f}, Ax{00}..{f0} */
	vmovdqu	xgft2_loy, [tmp+vec]	/* Load array Bx{00}..{0f}, Bx{00}..{f0} */
	vmovdqu	xgft3_loy, [tmp+2*vec]	/* Load array Cx{00}..{0f}, Cx{00}..{f0} */
	vshufi64x2 xgft1_hi, xgft1_lo, xgft1_lo, 0x55
	vshufi64x2 xgft1_lo, xgft1_lo, xgft1_lo, 0x00
	vshufi64x2 xgft2_hi, xgft2_lo, xgft2_lo, 0x55
	vshufi64x2 xgft2_lo, xgft2_lo, xgft2_lo, 0x00
	vshufi64x2 xgft3_hi, xgft3_lo, xgft3_lo, 0x55
	vshufi64x2 xgft3_lo, xgft3_lo, xgft3_lo, 0x00
	mov	dest2, [dest1+PS]	/* reuse mul_array */
	mov	dest3, [dest1+2*PS]	/* reuse vec_i */
	mov	dest1, [dest1]
	mov	tmp, -1
	kmovq	k1, tmp

.loop64:
	XLDR	x0, [src+pos]		/* Get next source vector */
	XLDR	xd1, [dest1+pos]	/* Get next dest vector */
	XLDR	xd2, [dest2+pos]	/* Get next dest vector */
	XLDR	xd3, [dest3+pos]	/* Get next dest vector */

	vpandq	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpandq	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	/* dest1 */
	vpshufb	xtmph1 {k1}{z}, xgft1_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl1 {k1}{z}, xgft1_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xtmph1, xtmph1, xtmpl1		/* GF add high and low partials */
	vpxorq	xd1, xd1, xtmph1		/* xd1 += partial */

	/* dest2 */
	vpshufb	xtmph2 {k1}{z}, xgft2_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl2 {k1}{z}, xgft2_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xtmph2, xtmph2, xtmpl2		/* GF add high and low partials */
	vpxorq	xd2, xd2, xtmph2		/* xd2 += partial */

	/* dest3 */
	vpshufb	xtmph3 {k1}{z}, xgft3_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl3 {k1}{z}, xgft3_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxorq	xtmph3, xtmph3, xtmpl3		/* GF add high and low partials */
	vpxorq	xd3, xd3, xtmph3		/* xd2 += partial */

	XSTR	[dest1+pos], xd1
	XSTR	[dest2+pos], xd2
	XSTR	[dest3+pos], xd3

	add	pos, 64			/* Loop on 64 bytes at a time */
	cmp	pos, len
	jle	.loop64

	lea	tmp, [len + 64]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, (1 << 63)
	lea	tmp, [len + 64 - 1]
	and	tmp, 63
	sarx	pos, pos, tmp
	kmovq	k1, pos
	mov	pos, len	/* Overlapped offset length-64 */
	jmp	.loop64		/* Do one more overlap pass */

.return_pass:
	mov	return, 0
	ret

.return_fail:
	mov	return, 1
	ret
ENDPROC(gf_3vect_mad_avx512)

.att_syntax prefix 