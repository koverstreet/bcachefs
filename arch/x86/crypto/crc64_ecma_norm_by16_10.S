/* SPDX-License-Identifier: BSD-3-Clause */

/* 
 * This is a GAS port of Intel's ISA-L CRC64 ECMA 182 implementation. The technique used to calculate the CRC can be found here: 
 * https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/fast-crc-computation-generic-polynomials-pclmulqdq-paper.pdf 
 * 
 * Copyright(c) 2019 Robbie Litchfield <blam.kiwi@gmail.com>
 */

/* 
 * Copyright(c) 2011-2016 Intel Corporation All rights reserved.
 * Copyright(c) 2019 Robbie Litchfield All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * PECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES/* LOSS OF USE,
 * DATA, OR PROFITS/* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/linkage.h>

#define stack_space 40
#define state rdi 
#define data_pointer rsi 
#define data_length rdx
#define return_value rax

.intel_syntax noprefix 

.section .text                   
.align  16

ENTRY(crc64_ecma_norm_by16_10)
	sub		rsp, stack_space
	vbroadcasti32x4 zmm18, [shuf_mask]
	cmp		data_length, 256
	jl		_less_than_256

	/* load the initial crc value */
	vmovq		xmm10, state      /* initial crc */

	/* crc value does not need to be byte-reflected, but it needs to be moved to the high part of the register. 
	 * because data will be byte-reflected and will align with initial crc at correct place.
	 */
	vpslldq		xmm10, xmm10, 8

	/* receive the initial 128B data, xor the initial crc value  */
	vmovdqu8	zmm0, [data_pointer+16*0]
	vmovdqu8	zmm4, [data_pointer+16*4]
	vpshufb		zmm0, zmm0, zmm18
	vpshufb		zmm4, zmm4, zmm18
	vpxorq		zmm0, zmm0, zmm10
	vbroadcasti32x4 zmm10, [rk3]	/*zmm10 has rk3 and rk4 */
					/*imm value of pclmulqdq instruction will determine which constant to use */
	sub		data_length, 256
	cmp		data_length, 256
	jl		_fold_128_B_loop

	vmovdqu8	zmm7, [data_pointer+16*8]
	vmovdqu8	zmm8, [data_pointer+16*12]
	vpshufb		zmm7, zmm7, zmm18
	vpshufb		zmm8, zmm8, zmm18
	vbroadcasti32x4 zmm16, [rk_1]	/*zmm16 has rk-1 and rk-2 */
	sub		data_length, 256

_fold_256_B_loop:
	add		data_pointer, 256
	vmovdqu8	zmm3, [data_pointer+16*0]
	vpshufb		zmm3, zmm3, zmm18
	vpclmulqdq	zmm1, zmm0, zmm16, 0x00
	vpclmulqdq	zmm2, zmm0, zmm16, 0x11
	vpxorq		zmm0, zmm1, zmm2
	vpxorq		zmm0, zmm0, zmm3

	vmovdqu8	zmm9, [data_pointer+16*4]
	vpshufb		zmm9, zmm9, zmm18
	vpclmulqdq	zmm5, zmm4, zmm16, 0x00
	vpclmulqdq	zmm6, zmm4, zmm16, 0x11
	vpxorq		zmm4, zmm5, zmm6
	vpxorq		zmm4, zmm4, zmm9

	vmovdqu8	zmm11, [data_pointer+16*8]
	vpshufb		zmm11, zmm11, zmm18
	vpclmulqdq	zmm12, zmm7, zmm16, 0x00
	vpclmulqdq	zmm13, zmm7, zmm16, 0x11
	vpxorq		zmm7, zmm12, zmm13
	vpxorq		zmm7, zmm7, zmm11

	vmovdqu8	zmm17, [data_pointer+16*12]
	vpshufb		zmm17, zmm17, zmm18
	vpclmulqdq	zmm14, zmm8, zmm16, 0x00
	vpclmulqdq	zmm15, zmm8, zmm16, 0x11
	vpxorq		zmm8, zmm14, zmm15
	vpxorq		zmm8, zmm8, zmm17

	sub		data_length, 256
	jge		_fold_256_B_loop

	/* Fold 256 into  */
	add		data_pointer, 256
	vpclmulqdq	zmm1, zmm0, zmm10, 0x00
	vpclmulqdq	zmm2, zmm0, zmm10, 0x11
	vpternlogq	zmm7, zmm1, zmm2, 0x96	/* xor ABC */

	vpclmulqdq	zmm5, zmm4, zmm10, 0x00
	vpclmulqdq	zmm6, zmm4, zmm10, 0x11
	vpternlogq	zmm8, zmm5, zmm6, 0x96	/* xor ABC */

	vmovdqa32	zmm0, zmm7
	vmovdqa32	zmm4, zmm8

	add		data_length, 128
	jmp		_fold_128_B_register

	/* fold 128B at a time. This section of the code folds 2 zmm registers in parallel */
_fold_128_B_loop:
	add		data_pointer, 128	/* update the buffer pointer */
	vmovdqu8	zmm8, [data_pointer+16*0]
	vpshufb		zmm8, zmm8, zmm18
	vpclmulqdq	zmm1, zmm0, zmm10, 0x00
	vpclmulqdq	zmm2, zmm0, zmm10, 0x11
	vpxorq		zmm0, zmm1, zmm2
	vpxorq		zmm0, zmm0, zmm8

	vmovdqu8	zmm9, [data_pointer+16*4]
	vpshufb		zmm9, zmm9, zmm18
	vpclmulqdq	zmm5, zmm4, zmm10, 0x00
	vpclmulqdq	zmm6, zmm4, zmm10, 0x11
	vpxorq		zmm4, zmm5, zmm6
	vpxorq		zmm4, zmm4, zmm9
	sub		data_length, 128
	jge		_fold_128_B_loop

	add		data_pointer, 128
	/* at this point, the buffer pointer is pointing at the last y Bytes of the buffer, where 0 <= y < 128
	 * the 128B of folded data is in 2 zmm registers: zmm0, zmm4
	 */

_fold_128_B_register:
	/* fold the 8 128b parts into 1 xmm register with different constants */
	vmovdqu8	zmm16, [rk9]		/* multiply by rk9-rk16 */
	vmovdqu8	zmm11, [rk17]		/* multiply by rk17-rk20, rk1,rk2, 0,0 */
	vpclmulqdq	zmm1, zmm0, zmm16, 0x00
	vpclmulqdq	zmm2, zmm0, zmm16, 0x11
	vextracti64x2	xmm7, zmm4, 3		/* save last that has no multiplicand */

	vpclmulqdq	zmm5, zmm4, zmm11, 0x00
	vpclmulqdq	zmm6, zmm4, zmm11, 0x11
	vmovdqa		xmm10, [rk1]		/* Needed later in reduction loop */
	vpternlogq	zmm1, zmm2, zmm5, 0x96	/* xor ABC */
	vpternlogq	zmm1, zmm6, zmm7, 0x96	/* xor ABC */

	vshufi64x2      zmm8, zmm1, zmm1, 0x4e /* Swap 1,0,3,2 - 01 00 11 10 */
	vpxorq          ymm8, ymm8, ymm1
	vextracti64x2   xmm5, ymm8, 1
	vpxorq          xmm7, xmm5, xmm8

	/* instead of 128, we add 128-16 to the loop counter to save 1 instruction from the loop
	 * instead of a cmp instruction, we use the negative flag with the jl instruction
	 */
	add		data_length, 128-16
	jl		_final_reduction_for_128

	/* now we have 16+y bytes left to reduce. 16 Bytes is in register xmm7 and the rest is in memory
	 * we can fold 16 bytes at a time if y>=16
	 * continue folding 16B at a time
	 */

_16B_reduction_loop:
	vmovdqa		xmm8, xmm7
	vpclmulqdq	xmm7, xmm7, xmm10, 0x11
	vpclmulqdq	xmm8, xmm8, xmm10, 0x00
	vpxor		xmm7, xmm7, xmm8
	vmovdqu		xmm0, [data_pointer]
	vpshufb		xmm0, xmm0, xmm18
	vpxor		xmm7, xmm7, xmm0
	add		data_pointer, 16
	sub		data_length, 16
	/* instead of a cmp instruction, we utilize the flags with the jge instruction
	 * equivalent of: cmp data_length, 16-16
	 * check if there is any more 16B in the buffer to be able to fold
	 */
	jge		_16B_reduction_loop

	/*now we have 16+z bytes left to reduce, where 0<= z < 16.
	 *first, we reduce the data in the xmm7 register
	 */


_final_reduction_for_128:
	add		data_length, 16
	je		_128_done
	/* here we are getting data that is less than 16 bytes.
	 * since we know that there was data before the pointer, we can offset
	 * the input pointer before the actual point, to receive exactly 16 bytes.
	 * after that the registers need to be adjusted.
	 */
_get_last_two_xmms:

	vmovdqa		xmm2, xmm7
	vmovdqu		xmm1, [data_pointer - 16 + data_length]
	vpshufb		xmm1, xmm1, xmm18

	/* get rid of the extra data that was loaded before
	 * load the shift constant
	 */
	lea		return_value, [pshufb_shf_table + 16]
	sub		return_value, data_length
	vmovdqu		xmm0, [return_value]

	/* shift xmm2 to the left by data_length bytes */
	vpshufb		xmm2, xmm2, xmm0

	/* shift xmm7 to the right by 16-data_length bytes */
	vpxor		xmm0, xmm0, [mask1]
	vpshufb		xmm7, xmm7, xmm0
	vpblendvb	xmm1, xmm1, xmm2, xmm0

	/* fold 16 Bytes */
	vmovdqa		xmm2, xmm1
	vmovdqa		xmm8, xmm7
	vpclmulqdq	xmm7, xmm7, xmm10, 0x11
	vpclmulqdq	xmm8, xmm8, xmm10, 0x0
	vpxor		xmm7, xmm7, xmm8
	vpxor		xmm7, xmm7, xmm2

_128_done:
	/* compute crc of a 128-bit value */
	vmovdqa		xmm10, [rk5]
	vmovdqa		xmm0, xmm7

	/* 64b fold
	 */
	vpclmulqdq	xmm7, xmm7, xmm10, 0x01	/* H*L */
	vpslldq		xmm0, xmm0, 8
	vpxor		xmm7, xmm7, xmm0

	/*barrett reduction */
_barrett:
	vmovdqa		xmm10, [rk7]	/* rk7 and rk8 in xmm10 */
	vmovdqa		xmm0, xmm7

	vmovdqa		xmm1, xmm7
    vpand		xmm1, xmm1, [mask3]
	vpclmulqdq	xmm7, xmm7, xmm10, 0x01
	vpxor		xmm7, xmm7, xmm1

	vpclmulqdq	xmm7, xmm7, xmm10, 0x11
	vpxor		xmm7, xmm7, xmm0
	vpextrq		return_value, xmm7, 0

_cleanup:
	add		rsp, stack_space
	ret

.align 16
_less_than_256:

	/* check if there is enough buffer to be able to fold 16B at a time */
	cmp	data_length, 32
	jl	_less_than_32

	/* if there is, load the constants */
	vmovdqa	xmm10, [rk1]	/* rk1 and rk2 in xmm10 */

	vmovq	xmm0, state	/* get the initial crc value */
	vpslldq	xmm0, xmm0, 8	/* .align it to its correct place */
	vmovdqu	xmm7, [data_pointer]	/* load the plaintext */
	vpshufb	xmm7, xmm7, xmm18	/* byte-reflect the plaintext */
	vpxor	xmm7, xmm7, xmm0

	/* update the buffer pointer */
	add	data_pointer, 16

	/* update the counter. subtract 32 instead of 16 to save one instruction from the loop */
	sub	data_length, 32

	jmp	_16B_reduction_loop

.align 16
_less_than_32:
	/* mov initial crc to the return value. this is necessary for zero-length buffers. */
	mov	return_value, state
	test	data_length, data_length
	je	_cleanup

	vmovq	xmm0, state	/* get the initial crc value */
	vpslldq	xmm0, xmm0, 8	/* align it to its correct place */

	cmp	data_length, 16
	je	_exact_16_left
	jl	_less_than_16_left

	vmovdqu	xmm7, [data_pointer]	/* load the plaintext */
	vpshufb	xmm7, xmm7, xmm18	/* byte-reflect the plaintext */
	vpxor	xmm7, xmm7, xmm0	/* xor the initial crc value */
	add	data_pointer, 16
	sub	data_length, 16
	vmovdqa	xmm10, [rk1]    /* rk1 and rk2 in xmm10 */
	jmp	_get_last_two_xmms


.align 16
_less_than_16_left:
	/* use stack space to load data less than 16 bytes, zero-out the 16B in memory first. */

	vpxor	xmm1, xmm1, xmm1
	mov	r11, rsp
	vmovdqa	[r11], xmm1

	/* backup the counter value */
	mov	r9, data_length
	cmp	data_length, 8
	jl	_less_than_8_left

	/* load 8 Bytes */
	mov	return_value, [data_pointer]
	mov	[r11], return_value
	add	r11, 8
	sub	data_length, 8
	add	data_pointer, 8
_less_than_8_left:

	cmp	data_length, 4
	jl	_less_than_4_left

	/* load 4 Bytes */
	mov	eax, [data_pointer]
	mov	[r11], eax
	add	r11, 4
	sub	data_length, 4
	add	data_pointer, 4
_less_than_4_left:

	cmp	data_length, 2
	jl	_less_than_2_left

	/* load 2 Bytes */
	mov	ax, [data_pointer]
	mov	[r11], ax
	add	r11, 2
	sub	data_length, 2
	add	data_pointer, 2
_less_than_2_left:
	cmp	data_length, 1
	jl	_zero_left

	/* load 1 Byte */
	mov	al, [data_pointer]
	mov	[r11], al

_zero_left:
	vmovdqa	xmm7, [rsp]
	vpshufb	xmm7, xmm7, xmm18
	vpxor	xmm7, xmm7, xmm0	/* xor the initial crc value */

	lea	return_value, [pshufb_shf_table + 16]
	sub	return_value, r9

	cmp	r9, 8
	jl	_end_1to7

_end_8to15:
	vmovdqu	xmm0, [return_value]
	vpxor	xmm0, xmm0, [mask1]

	vpshufb	xmm7, xmm7, xmm0
	jmp	_128_done

_end_1to7:
	/* Right shift (8-length) bytes in XMM */
	add	return_value, 8
	vmovdqu	xmm0, [return_value]
	vpshufb	xmm7, xmm7,xmm0

	jmp	_barrett

.align 16
_exact_16_left:
	vmovdqu	xmm7, [data_pointer]
	vpshufb	xmm7, xmm7, xmm18
	vpxor	xmm7, xmm7, xmm0	/* xor the initial crc value */

	jmp	_128_done                        
ENDPROC(crc64_ecma_norm_by16_10) 

.section .data
.align  32

rk_1: 
	.quad 0x7f52691a60ddc70d
	.quad 0x7036b0389f6a0c82
rk1: 
	.quad 0x05f5c3c7eb52fab6
	.quad 0x4eb938a7d257740e
rk3: 
	.quad 0x05cf79dea9ac37d6
	.quad 0x001067e571d7d5c2
rk5: 
	.quad 0x05f5c3c7eb52fab6
	.quad 0x0000000000000000
rk7: 
	.quad 0x578d29d06cc4f872
	.quad 0x42f0e1eba9ea3693
rk9: 
	.quad 0xe464f4df5fb60ac1
	.quad 0xb649c5b35a759cf2
rk11: 
	.quad 0x9af04e1eff82d0dd
	.quad 0x6e82e609297f8fe8
rk13: 
	.quad 0x097c516e98bd2e73
	.quad 0x0b76477b31e22e7b
rk15: 
	.quad 0x5f6843ca540df020
	.quad 0xddf4b6981205b83f
rk17: 
	.quad 0x54819d8713758b2c
	.quad 0x4a6b90073eb0af5a
rk19: 
	.quad 0x571bee0a227ef92b
	.quad 0x44bef2a201b5200c
rk_ex: 
	.quad 0x05f5c3c7eb52fab6
	.quad 0x4eb938a7d257740e
	.quad 0x0000000000000000
	.quad 0x0000000000000000

mask1: 
	.quad 0x8080808080808080
	.quad 0x8080808080808080
mask2: 
	.quad 0xFFFFFFFFFFFFFFFF
	.quad 0x00000000FFFFFFFF
mask3: 
	.quad 0x0000000000000000 
	.quad 0xFFFFFFFFFFFFFFFF

shuf_mask: 
	.quad 0x08090A0B0C0D0E0F
	.quad 0x0001020304050607                                

pshufb_shf_table:
	.quad 0x8786858483828100
	.quad 0x8f8e8d8c8b8a8988
	.quad 0x0706050403020100
	.quad 0x0f0e0d0c0b0a0908
	.quad 0x8080808080808080
	.quad 0x0f0e0d0c0b0a0908
	.quad 0x8080808080808080
	.quad 0x8080808080808080

.att_syntax prefix 
