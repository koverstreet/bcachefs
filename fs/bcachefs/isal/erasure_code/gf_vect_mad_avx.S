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
*** gf_vect_mad_avx(len, vec, vec_i, mul_array, src, dest);
***/

#include <linux/linkage.h>

 #define arg0  rdi
 #define arg0_w edi
 #define arg1  rsi
 #define arg2  rdx
 #define arg3  rcx
 #define arg4  r8
 #define arg5  r9
 #define tmp   r11
 #define return rax
 #define return_w eax

/*** gf_vect_mad_avx(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec    arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest  arg5
#define pos   return
#define pos_w return_w

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f  xmm8
#define xgft_lo  xmm7
#define xgft_hi  xmm6

#define x0     xmm0
#define xtmpa  xmm1
#define xtmph  xmm2
#define xtmpl  xmm3
#define xd     xmm4
#define xtmpd  xmm5

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_vect_mad_avx)
	sub	len, 16
	jl	.return_fail

	xor	pos, pos
	vmovdqa	xmask0f, [mask0f]	/* Load mask of lower nibble in each byte */

	sal	vec_i, 5		/* Multiply by 32 */
	vmovdqu	xgft_lo, [vec_i+mul_array]	/* Load array Cx{00}, Cx{01}, Cx{02}, ... */
	vmovdqu	xgft_hi, [vec_i+mul_array+16]	/* " Cx{00}, Cx{10}, Cx{20}, ... , Cx{f0} */

	XLDR	xtmpd, [dest+len]	/* backup the last 16 bytes in dest */

.loop16:
	XLDR	xd, [dest+pos]		/* Get next dest vector */
.loop16_overlap:
	XLDR	x0, [src+pos]		/* Get next source vector */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4			/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	vpshufb	xtmph, xgft_hi, x0		/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl 	/* GF add high and low partials */
	vpxor	xd, xd, xtmph			/* xd += partial */

	XSTR	[dest+pos], xd
	add	pos, 16			/* Loop on 16 bytes at a time */
	cmp	pos, len
	jle	.loop16

	lea	tmp, [len + 16]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, len		/* Overlapped offset length-16 */
	vmovdqa	xd, xtmpd	/* estore xd */
	jmp	.loop16_overlap	/* Do one more overlap pass */

.return_pass:
	mov	return, 0
	ret

.return_fail:
	mov	return, 1
	ret
ENDPROC(gf_vect_mad_avx)

.section .data

.align 16

mask0f: 
	.quad 0x0f0f0f0f0f0f0f0f
	.quad 0x0f0f0f0f0f0f0f0f

.att_syntax prefix 