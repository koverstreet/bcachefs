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
*** gf_vect_mad_avx2(len, vec, vec_i, mul_array, src, dest);
***/

#include <linux/linkage.h>

#define arg0  rdi
#define arg0_w edi
#define arg1  rsi
#define arg2  rdx
#define arg3  rcx
#define arg4  r8
#define arg5  r9

#define tmp      r11
#define tmp_w    r11d
#define tmp_b    r11b
#define return rax
#define return_w eax

/*** gf_vect_mad_avx2(len, vec, vec_i, mul_array, src, dest) ***/
#define len   arg0
#define len_w arg0_w
#define vec   arg1
#define vec_i    arg2
#define mul_array arg3
#define	src   arg4
#define dest  arg5
#define pos   return
#define pos_w return_w

/*** Use Un-aligned load/store ***/
#define XLDR vmovdqu
#define XSTR vmovdqu

#define xmask0f  ymm8
#define xmask0fx xmm8
#define xgft_lo  ymm7
#define xgft_hi  ymm6

#define x0     ymm0
#define xtmpa  ymm1
#define xtmph  ymm2
#define xtmpl  ymm3
#define xd     ymm4
#define xtmpd  ymm5

.intel_syntax noprefix 

.section .text
.align 16

ENTRY(gf_vect_mad_avx2)
	sub	len, 32
	jl	.return_fail
	xor	pos, pos
	mov	tmp_b, 0x0f
	vpinsrb	xmask0fx, xmask0fx, tmp_w, 0
	vpbroadcastb xmask0f, xmask0fx	/* Construct mask 0x0f0f0f... */

	sal	vec_i, 5		/* Multiply by 32 */
	vmovdqu	xgft_lo, [vec_i+mul_array]	/* Load array Cx{00}, Cx{01}, Cx{02}, ... */
						/* " Cx{00}, Cx{10}, Cx{20}, ... , Cx{f0} */
	vperm2i128 xgft_hi, xgft_lo, xgft_lo, 0x11 /* swapped to hi | hi */
	vperm2i128 xgft_lo, xgft_lo, xgft_lo, 0x00 /* swapped to lo | lo */

	XLDR	xtmpd, [dest+len]	/* backup the last 32 bytes in dest */

.loop32:
	XLDR	xd, [dest+pos]		/* Get next dest vector */
.loop32_overlap:
	XLDR	x0, [src+pos]		/* Get next source vector */

	vpand	xtmpa, x0, xmask0f	/* Mask low src nibble in bits 4-0 */
	vpsraw	x0, x0, 4		/* Shift to put high nibble into bits 4-0 */
	vpand	x0, x0, xmask0f		/* Mask high src nibble in bits 4-0 */

	vpshufb	xtmph, xgft_hi, x0	/* Lookup mul table of high nibble */
	vpshufb	xtmpl, xgft_lo, xtmpa	/* Lookup mul table of low nibble */
	vpxor	xtmph, xtmph, xtmpl /* GF add high and low partials */
	vpxor	xd, xd, xtmph		/* xd += partial */

	XSTR	[dest+pos], xd
	add	pos, 32			/* Loop on 32 bytes at a time */
	cmp	pos, len
	jle	.loop32

	lea	tmp, [len + 32]
	cmp	pos, tmp
	je	.return_pass

	/** Tail len **/
	mov	pos, len	/* Overlapped offset length-32 */
	vmovdqa	xd, xtmpd	/* Restore xd */
	jmp	.loop32_overlap	/* Do one more overlap pass */

.return_pass:
	mov	return, 0
	ret

.return_fail:
	mov	return, 1
	ret
ENDPROC(gf_vect_mad_avx2)

.att_syntax prefix 