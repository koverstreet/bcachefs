/*
*  xxHash - Fast Hash algorithm
*  Copyright (C) 2012-2016, Yann Collet
*
*  BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions are
*  met:
*
*  * Redistributions of source code must retain the above copyright
*  notice, this list of conditions and the following disclaimer.
*  * Redistributions in binary form must reproduce the above
*  copyright notice, this list of conditions and the following disclaimer
*  in the documentation and/or other materials provided with the
*  distribution.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
*  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
*  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
*  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
*  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*  You can contact the author at :
*  - xxHash homepage: http://www.xxhash.com
*  - xxHash source repository : https://github.com/Cyan4973/xxHash
*/

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "xxhash.h"

/* *************************************
*  Macros
***************************************/
#define XXH_STATIC_ASSERT(c)   { enum { XXH_static_assert = 1/(int)(!!(c)) }; }    /* use only *after* variable declarations */


/* *************************************
*  Constants
***************************************/
static const u32 PRIME32_1 = 2654435761U;
static const u32 PRIME32_2 = 2246822519U;
static const u32 PRIME32_3 = 3266489917U;
static const u32 PRIME32_4 =  668265263U;
static const u32 PRIME32_5 =  374761393U;

static const u64 PRIME64_1 = 11400714785074694791ULL;
static const u64 PRIME64_2 = 14029467366897019727ULL;
static const u64 PRIME64_3 =  1609587929392839161ULL;
static const u64 PRIME64_4 =  9650029242287828579ULL;
static const u64 PRIME64_5 =  2870177450012600261ULL;


/* **************************
*  Utils
****************************/
void XXH32_copyState(XXH32_state_t* restrict dstState, const XXH32_state_t* restrict srcState)
{
    memcpy(dstState, srcState, sizeof(*dstState));
}

void XXH64_copyState(XXH64_state_t* restrict dstState, const XXH64_state_t* restrict srcState)
{
    memcpy(dstState, srcState, sizeof(*dstState));
}


/* ***************************
*  Simple Hash Functions
*****************************/

static u32 XXH32_round(u32 seed, u32 input)
{
    seed += input * PRIME32_2;
    seed  = rol32(seed, 13);
    seed *= PRIME32_1;
    return seed;
}

u32 XXH32(const void *input, size_t len, u32 seed)
{
    const u8* p = (const u8*)input;
    const u8* bEnd = p + len;
    u32 h32;

    if (len>=16) {
        const u8* const limit = bEnd - 16;
        u32 v1 = seed + PRIME32_1 + PRIME32_2;
        u32 v2 = seed + PRIME32_2;
        u32 v3 = seed + 0;
        u32 v4 = seed - PRIME32_1;

        do {
            v1 = XXH32_round(v1, get_unaligned_le32(p)); p+=4;
            v2 = XXH32_round(v2, get_unaligned_le32(p)); p+=4;
            v3 = XXH32_round(v3, get_unaligned_le32(p)); p+=4;
            v4 = XXH32_round(v4, get_unaligned_le32(p)); p+=4;
        } while (p<=limit);

        h32 = rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12) + rol32(v4, 18);
    } else {
        h32  = seed + PRIME32_5;
    }

    h32 += (u32) len;

    while (p+4<=bEnd) {
        h32 += get_unaligned_le32(p) * PRIME32_3;
        h32  = rol32(h32, 17) * PRIME32_4 ;
        p+=4;
    }

    while (p<bEnd) {
        h32 += (*p) * PRIME32_5;
        h32 = rol32(h32, 11) * PRIME32_1 ;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}


static u64 XXH64_round(u64 acc, u64 input)
{
    acc += input * PRIME64_2;
    acc  = rol64(acc, 31);
    acc *= PRIME64_1;
    return acc;
}

static u64 XXH64_mergeRound(u64 acc, u64 val)
{
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * PRIME64_1 + PRIME64_4;
    return acc;
}

u64 XXH64(const void *input, size_t len, u64 seed)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;
    u64 h64;

    if (len>=32) {
        const u8* const limit = bEnd - 32;
        u64 v1 = seed + PRIME64_1 + PRIME64_2;
        u64 v2 = seed + PRIME64_2;
        u64 v3 = seed + 0;
        u64 v4 = seed - PRIME64_1;

        do {
            v1 = XXH64_round(v1, get_unaligned_le64(p)); p+=8;
            v2 = XXH64_round(v2, get_unaligned_le64(p)); p+=8;
            v3 = XXH64_round(v3, get_unaligned_le64(p)); p+=8;
            v4 = XXH64_round(v4, get_unaligned_le64(p)); p+=8;
        } while (p<=limit);

        h64 = rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12) + rol64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);

    } else {
        h64  = seed + PRIME64_5;
    }

    h64 += (u64) len;

    while (p+8<=bEnd) {
        u64 const k1 = XXH64_round(0, get_unaligned_le64(p));
        h64 ^= k1;
        h64  = rol64(h64,27) * PRIME64_1 + PRIME64_4;
        p+=8;
    }

    if (p+4<=bEnd) {
        h64 ^= (u64)(get_unaligned_le32(p)) * PRIME64_1;
        h64 = rol64(h64, 23) * PRIME64_2 + PRIME64_3;
        p+=4;
    }

    while (p<bEnd) {
        h64 ^= (*p) * PRIME64_5;
        h64 = rol64(h64, 11) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}


/* **************************************************
*  Advanced Hash Functions
****************************************************/


/*** Hash feed ***/

XXH_errorcode XXH32_reset(XXH32_state_t* statePtr, unsigned int seed)
{
    XXH32_state_t state;   /* using a local state to memcpy() in order to avoid strict-aliasing warnings */
    memset(&state, 0, sizeof(state)-4);   /* do not write into reserved, for future removal */
    state.v1 = seed + PRIME32_1 + PRIME32_2;
    state.v2 = seed + PRIME32_2;
    state.v3 = seed + 0;
    state.v4 = seed - PRIME32_1;
    memcpy(statePtr, &state, sizeof(state));
    return XXH_OK;
}


XXH_errorcode XXH64_reset(XXH64_state_t* statePtr, unsigned long long seed)
{
    XXH64_state_t state;   /* using a local state to memcpy() in order to avoid strict-aliasing warnings */
    memset(&state, 0, sizeof(state)-8);   /* do not write into reserved, for future removal */
    state.v1 = seed + PRIME64_1 + PRIME64_2;
    state.v2 = seed + PRIME64_2;
    state.v3 = seed + 0;
    state.v4 = seed - PRIME64_1;
    memcpy(statePtr, &state, sizeof(state));
    return XXH_OK;
}


XXH_errorcode XXH32_update(XXH32_state_t *state, const void *input, size_t len)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;

    state->total_len_32 += (unsigned)len;
    state->large_len |= (len>=16) | (state->total_len_32>=16);

    if (state->memsize + len < 16)  {   /* fill in tmp buffer */
        memcpy((u8*)(state->mem32) + state->memsize, input, len);
        state->memsize += (unsigned)len;
        return XXH_OK;
    }

    if (state->memsize) {   /* some data left from previous update */
        memcpy((u8*)(state->mem32) + state->memsize, input, 16-state->memsize);
        {   const u32* p32 = state->mem32;
            state->v1 = XXH32_round(state->v1, get_unaligned_le32(p32)); p32++;
            state->v2 = XXH32_round(state->v2, get_unaligned_le32(p32)); p32++;
            state->v3 = XXH32_round(state->v3, get_unaligned_le32(p32)); p32++;
            state->v4 = XXH32_round(state->v4, get_unaligned_le32(p32)); p32++;
        }
        p += 16-state->memsize;
        state->memsize = 0;
    }

    if (p <= bEnd-16) {
        const u8* const limit = bEnd - 16;
        u32 v1 = state->v1;
        u32 v2 = state->v2;
        u32 v3 = state->v3;
        u32 v4 = state->v4;

        do {
            v1 = XXH32_round(v1, get_unaligned_le32(p)); p+=4;
            v2 = XXH32_round(v2, get_unaligned_le32(p)); p+=4;
            v3 = XXH32_round(v3, get_unaligned_le32(p)); p+=4;
            v4 = XXH32_round(v4, get_unaligned_le32(p)); p+=4;
        } while (p<=limit);

        state->v1 = v1;
        state->v2 = v2;
        state->v3 = v3;
        state->v4 = v4;
    }

    if (p < bEnd) {
        memcpy(state->mem32, p, (size_t)(bEnd-p));
        state->memsize = (unsigned)(bEnd-p);
    }

    return XXH_OK;
}


u32 XXH32_digest(const XXH32_state_t *state)
{
    const u8 * p = (const u8*)state->mem32;
    const u8* const bEnd = (const u8*)(state->mem32) + state->memsize;
    u32 h32;

    if (state->large_len) {
        h32 = rol32(state->v1, 1) + rol32(state->v2, 7) + rol32(state->v3, 12) + rol32(state->v4, 18);
    } else {
        h32 = state->v3 /* == seed */ + PRIME32_5;
    }

    h32 += state->total_len_32;

    while (p+4<=bEnd) {
        h32 += get_unaligned_le32(p) * PRIME32_3;
        h32  = rol32(h32, 17) * PRIME32_4;
        p+=4;
    }

    while (p<bEnd) {
        h32 += (*p) * PRIME32_5;
        h32  = rol32(h32, 11) * PRIME32_1;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}


/* **** XXH64 **** */

XXH_errorcode XXH64_update(XXH64_state_t *state, const void *input, size_t len)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;

    state->total_len += len;

    if (state->memsize + len < 32) {  /* fill in tmp buffer */
        memcpy(((u8*)state->mem64) + state->memsize, input, len);
        state->memsize += (u32)len;
        return XXH_OK;
    }

    if (state->memsize) {   /* tmp buffer is full */
        memcpy(((u8*)state->mem64) + state->memsize, input, 32-state->memsize);
        state->v1 = XXH64_round(state->v1, get_unaligned_le64(state->mem64+0));
        state->v2 = XXH64_round(state->v2, get_unaligned_le64(state->mem64+1));
        state->v3 = XXH64_round(state->v3, get_unaligned_le64(state->mem64+2));
        state->v4 = XXH64_round(state->v4, get_unaligned_le64(state->mem64+3));
        p += 32-state->memsize;
        state->memsize = 0;
    }

    if (p+32 <= bEnd) {
        const u8* const limit = bEnd - 32;
        u64 v1 = state->v1;
        u64 v2 = state->v2;
        u64 v3 = state->v3;
        u64 v4 = state->v4;

        do {
            v1 = XXH64_round(v1, get_unaligned_le64(p)); p+=8;
            v2 = XXH64_round(v2, get_unaligned_le64(p)); p+=8;
            v3 = XXH64_round(v3, get_unaligned_le64(p)); p+=8;
            v4 = XXH64_round(v4, get_unaligned_le64(p)); p+=8;
        } while (p<=limit);

        state->v1 = v1;
        state->v2 = v2;
        state->v3 = v3;
        state->v4 = v4;
    }

    if (p < bEnd) {
        memcpy(state->mem64, p, (size_t)(bEnd-p));
        state->memsize = (unsigned)(bEnd-p);
    }

    return XXH_OK;
}


u64 XXH64_digest(const XXH64_state_t *state)
{
    const u8 * p = (const u8*)state->mem64;
    const u8* const bEnd = (const u8*)state->mem64 + state->memsize;
    u64 h64;

    if (state->total_len >= 32) {
        u64 const v1 = state->v1;
        u64 const v2 = state->v2;
        u64 const v3 = state->v3;
        u64 const v4 = state->v4;

        h64 = rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12) + rol64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);
    } else {
        h64  = state->v3 + PRIME64_5;
    }

    h64 += (u64) state->total_len;

    while (p+8<=bEnd) {
        u64 const k1 = XXH64_round(0, get_unaligned_le64(p));
        h64 ^= k1;
        h64  = rol64(h64,27) * PRIME64_1 + PRIME64_4;
        p+=8;
    }

    if (p+4<=bEnd) {
        h64 ^= (u64)get_unaligned_le32(p) * PRIME64_1;
        h64  = rol64(h64, 23) * PRIME64_2 + PRIME64_3;
        p+=4;
    }

    while (p<bEnd) {
        h64 ^= (*p) * PRIME64_5;
        h64  = rol64(h64, 11) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}


/* **************************
*  Canonical representation
****************************/

/*! Default XXH result types are basic unsigned 32 and 64 bits.
*   The canonical representation follows human-readable write convention, aka big-endian (large digits first).
*   These functions allow transformation of hash result into and from its canonical format.
*   This way, hash values can be written into a file or buffer, and remain comparable across different systems and programs.
*/

void XXH32_canonicalFromHash(XXH32_canonical_t* dst, u32 hash)
{
    XXH_STATIC_ASSERT(sizeof(XXH32_canonical_t) == sizeof(u32));

    hash = be32_to_cpu(hash);
    memcpy(dst, &hash, sizeof(*dst));
}

void XXH64_canonicalFromHash(XXH64_canonical_t* dst, u64 hash)
{
    XXH_STATIC_ASSERT(sizeof(XXH64_canonical_t) == sizeof(u64));

    hash = be64_to_cpu(hash);
    memcpy(dst, &hash, sizeof(*dst));
}

u32 XXH32_hashFromCanonical(const XXH32_canonical_t* src)
{
    return get_unaligned_be32(src);
}

u64 XXH64_hashFromCanonical(const XXH64_canonical_t* src)
{
    return get_unaligned_be64(src);
}
