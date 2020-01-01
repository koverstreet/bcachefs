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
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/linkage.h>

#define stack_space 40
#define state rdi 
#define data_pointer rsi 
#define data_length rdx
#define fetch_dist 1024
#define return_value rax

.intel_syntax noprefix 

.section .text                   
.align  16

ENTRY(crc64_ecma_norm_by8)           
	sub	rsp, stack_space

	/* check if smaller than 256 */
	cmp	data_length, 256

	/* for sizes less than 256, we can't fold 128B at a time... */
	jl	_less_than_256

	/* load the initial crc value */
	movq	xmm10, state

	/* crc value does not need to be byte-reflected, but it needs to be moved to the high part of the register.
	 * because data will be byte-reflected and will align with initial crc at correct place.
	 */
	pslldq	xmm10, 8

	movdqa xmm11, [shuf_mask]
	/* receive the initial 128B data, xor the initial crc value */
	movdqu	xmm0, [data_pointer+16*0]
	movdqu	xmm1, [data_pointer+16*1]
	movdqu	xmm2, [data_pointer+16*2]
	movdqu	xmm3, [data_pointer+16*3]
	movdqu	xmm4, [data_pointer+16*4]
	movdqu	xmm5, [data_pointer+16*5]
	movdqu	xmm6, [data_pointer+16*6]
	movdqu	xmm7, [data_pointer+16*7]

	pshufb	xmm0, xmm11
	/* XOR the initial_crc value */
	pxor	xmm0, xmm10
	pshufb	xmm1, xmm11
	pshufb	xmm2, xmm11
	pshufb	xmm3, xmm11
	pshufb	xmm4, xmm11
	pshufb	xmm5, xmm11
	pshufb	xmm6, xmm11
	pshufb	xmm7, xmm11

    /* imm value of pclmulqdq instruction will determine which constant to use */
	movdqa	xmm10, [rk3]
					
	/* we subtract 256 instead of 128 to save one instruction from the loop */
	sub	data_length, 256

	/* at this section of the code, there is 128*x+y (0<=y<128) bytes of buffer. The _fold_128_B_loop
	 * loop will fold 128B at a time until we have 128+y Bytes of buffer
	 */

	/* fold 128B at a time. This section of the code folds 8 xmm registers in parallel */
_fold_128_B_loop:

	/* update the buffer pointer */
	add	data_pointer, 128

	prefetchnta [data_pointer+fetch_dist+0]
	movdqu	xmm9, [data_pointer+16*0]
	movdqu	xmm12, [data_pointer+16*1]
	pshufb	xmm9, xmm11
	pshufb	xmm12, xmm11
	movdqa	xmm8, xmm0
	movdqa	xmm13, xmm1
	pclmulqdq	xmm0, xmm10, 0x00
	pclmulqdq	xmm8, xmm10 , 0x11
	pclmulqdq	xmm1, xmm10, 0x00
	pclmulqdq	xmm13, xmm10 , 0x11
	pxor	xmm0, xmm9
	xorps	xmm0, xmm8
	pxor	xmm1, xmm12
	xorps	xmm1, xmm13

	prefetchnta [data_pointer+fetch_dist+32]
	movdqu	xmm9, [data_pointer+16*2]
	movdqu	xmm12, [data_pointer+16*3]
	pshufb	xmm9, xmm11
	pshufb	xmm12, xmm11
	movdqa	xmm8, xmm2
	movdqa	xmm13, xmm3
	pclmulqdq	xmm2, xmm10, 0x00
	pclmulqdq	xmm8, xmm10 , 0x11
	pclmulqdq	xmm3, xmm10, 0x00
	pclmulqdq	xmm13, xmm10 , 0x11
	pxor	xmm2, xmm9
	xorps	xmm2, xmm8
	pxor	xmm3, xmm12
	xorps	xmm3, xmm13

	prefetchnta [data_pointer+fetch_dist+64]
	movdqu	xmm9, [data_pointer+16*4]
	movdqu	xmm12, [data_pointer+16*5]
	pshufb	xmm9, xmm11
	pshufb	xmm12, xmm11
	movdqa	xmm8, xmm4
	movdqa	xmm13, xmm5
	pclmulqdq	xmm4, xmm10, 0x00
	pclmulqdq	xmm8, xmm10 , 0x11
	pclmulqdq	xmm5, xmm10, 0x00
	pclmulqdq	xmm13, xmm10 , 0x11
	pxor	xmm4, xmm9
	xorps	xmm4, xmm8
	pxor	xmm5, xmm12
	xorps	xmm5, xmm13

	prefetchnta [data_pointer+fetch_dist+96]
	movdqu	xmm9, [data_pointer+16*6]
	movdqu	xmm12, [data_pointer+16*7]
	pshufb	xmm9, xmm11
	pshufb	xmm12, xmm11
	movdqa	xmm8, xmm6
	movdqa	xmm13, xmm7
	pclmulqdq	xmm6, xmm10, 0x00
	pclmulqdq	xmm8, xmm10 , 0x11
	pclmulqdq	xmm7, xmm10, 0x00
	pclmulqdq	xmm13, xmm10 , 0x11
	pxor	xmm6, xmm9
	xorps	xmm6, xmm8
	pxor	xmm7, xmm12
	xorps	xmm7, xmm13

	sub	data_length, 128

	/* check if there is another 128B in the buffer to be able to fold */
	jge	_fold_128_B_loop

	add	data_pointer, 128
    /* at this point, the buffer pointer is pointing at the last y Bytes of the buffer, where 0 <= y < 128
     * the 128B of folded data is in 8 of the xmm registers: xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
	 */

	/* fold the 8 xmm registers to 1 xmm register with different constants */

	movdqa	xmm10, [rk9]
	movdqa	xmm8, xmm0
	pclmulqdq	xmm0, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	xorps	xmm7, xmm0

	movdqa	xmm10, [rk11]
	movdqa	xmm8, xmm1
	pclmulqdq	xmm1, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	xorps	xmm7, xmm1

	movdqa	xmm10, [rk13]
	movdqa	xmm8, xmm2
	pclmulqdq	xmm2, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	pxor	xmm7, xmm2

	movdqa	xmm10, [rk15]
	movdqa	xmm8, xmm3
	pclmulqdq	xmm3, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	xorps	xmm7, xmm3

	movdqa	xmm10, [rk17]
	movdqa	xmm8, xmm4
	pclmulqdq	xmm4, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	pxor	xmm7, xmm4

	movdqa	xmm10, [rk19]
	movdqa	xmm8, xmm5
	pclmulqdq	xmm5, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	xorps	xmm7, xmm5

	movdqa	xmm10, [rk1]

	movdqa	xmm8, xmm6
	pclmulqdq	xmm6, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	pxor	xmm7, xmm6


	/* instead of 128, we add 112 to the loop counter to save 1 instruction from the loop
	 * instead of a cmp instruction, we use the negative flag with the jl instruction
	 */
	add	data_length, 128-16
	jl	_final_reduction_for_128

	/* now we have 16+y bytes left to reduce. 16 Bytes is in register xmm7 and the rest is in memory
	 * we can fold 16 bytes at a time if y>=16
	 * continue folding 16B at a time
	 */

_16B_reduction_loop:
	movdqa	xmm8, xmm7
	pclmulqdq	xmm7, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	movdqu	xmm0, [data_pointer]
	pshufb	xmm0, xmm11
	pxor	xmm7, xmm0
	add	data_pointer, 16
	sub	data_length, 16
	/* instead of a cmp instruction, we utilize the flags with the jge instruction
	 * equivalent of: cmp data_length, 16-16
	 * check if there is any more 16B in the buffer to be able to fold
	 */
	jge	_16B_reduction_loop

	/* now we have 16+z bytes left to reduce, where 0<= z < 16.
	 * first, we reduce the data in the xmm7 register
	 */


_final_reduction_for_128:
	/* check if any more data to fold. If not, compute the CRC of the final 128 bits */
	add	data_length, 16
	je	_128_done

	/* here we are getting data that is less than 16 bytes.
	 * since we know that there was data before the pointer, we can offset the input pointer before the actual point, to receive exactly 16 bytes.
	 * after that the registers need to be adjusted.
	 */
_get_last_two_xmms:
	movdqa	xmm2, xmm7

	movdqu	xmm1, [data_pointer - 16 + data_length]
	pshufb	xmm1, xmm11

	/* get rid of the extra data that was loaded before
	 * load the shift constant
	 */
	lea	return_value, [pshufb_shf_table + 16]
	sub	return_value, data_length
	movdqu	xmm0, [return_value]

	/* shift xmm2 to the left by data_length bytes */
	pshufb	xmm2, xmm0

	/* shift xmm7 to the right by 16-data_length bytes */
	pxor	xmm0, [mask1]
	pshufb	xmm7, xmm0
	pblendvb	xmm1, xmm2			/* xmm0 is implicit */

	/* fold 16 Bytes */
	movdqa	xmm2, xmm1
	movdqa	xmm8, xmm7
	pclmulqdq	xmm7, xmm10, 0x11
	pclmulqdq	xmm8, xmm10, 0x00
	pxor	xmm7, xmm8
	pxor	xmm7, xmm2

_128_done:
	/* compute crc of a 128-bit value */
	movdqa	xmm10, [rk5]
	movdqa	xmm0, xmm7

	/* 64b fold */
	pclmulqdq	xmm7, xmm10, 0x01
	pslldq	xmm0, 8
	pxor	xmm7, xmm0

	/* barrett reduction */
_barrett:
	movdqa	xmm10, [rk7]
	movdqa	xmm0, xmm7

	movdqa	xmm1, xmm7
        pand    xmm1, [mask3]
	pclmulqdq	xmm7, xmm10, 0x01
	pxor	xmm7, xmm1

	pclmulqdq	xmm7, xmm10, 0x11
	pxor	xmm7, xmm0
	pextrq	return_value, xmm7, 0

_cleanup:
	add	rsp, stack_space
	ret

.align 16
_less_than_256:

	/* check if there is enough buffer to be able to fold 16B at a time */
	cmp	data_length, 32
	jl	_less_than_32
	movdqa xmm11, [shuf_mask]

	/* load the constants */
	movdqa	xmm10, [rk1]

	movq	xmm0, state				/* get the initial crc value */
	pslldq	xmm0, 8					/* align it to its correct place */
	movdqu	xmm7, [data_pointer]	/* load the plaintext */
	pshufb	xmm7, xmm11				/* byte-reflect the plaintext */
	pxor	xmm7, xmm0


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

	movdqa xmm11, [shuf_mask]

	movq	xmm0, state				/* get the initial crc value */
	pslldq	xmm0, 8					/* align it to its correct place */

	cmp	data_length, 16
	je	_exact_16_left
	jl	_less_than_16_left

	movdqu	xmm7, [data_pointer]	/* load the plaintext */
	pshufb	xmm7, xmm11				/* byte-reflect the plaintext */
	pxor	xmm7, xmm0				/* xor the initial crc value */
	add	data_pointer, 16
	sub	data_length, 16
	movdqa	xmm10, [rk1]	
	jmp	_get_last_two_xmms
.align 16
_less_than_16_left:
	/* use stack space to load data less than 16 bytes, zero-out the 16B in memory first. */
	pxor	xmm1, xmm1
	mov	r11, rsp
	movdqa	[r11], xmm1

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
	cmp     data_length, 1
    jl      _zero_left

	/* load 1 Byte */
	mov	al, [data_pointer]
	mov	[r11], al
_zero_left:
	movdqa	xmm7, [rsp]
	pshufb	xmm7, xmm11
	pxor	xmm7, xmm0	/* xor the initial crc value */

	/* shl r9, 4 */
	lea	return_value, [pshufb_shf_table + 16]
	sub	return_value, r9

	cmp     r9, 8
    jl      _end_1to7

_end_8to15:
	movdqu	xmm0, [return_value]
	pxor	xmm0, [mask1]

	pshufb	xmm7, xmm0
	jmp	_128_done

_end_1to7:
	/* Right shift (8-length) bytes in XMM */
	add	return_value, 8
    movdqu  xmm0, [return_value]
    pshufb  xmm7,xmm0

    jmp     _barrett
.align 16
_exact_16_left: 
	movdqu	xmm7, [data_pointer]
	pshufb	xmm7, xmm11
	pxor	xmm7, xmm0	/* xor the initial crc value */

	jmp	_128_done                        

ENDPROC(crc64_ecma_norm_by8)          

.section .data
.align  16

rk1:
    .quad 0x5f5c3c7eb52fab6
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
