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

/* *************************************
*  Tuning parameters
***************************************/
/*!XXH_FORCE_MEMORY_ACCESS :
 * By default, access to unaligned memory is controlled by `memcpy()`, which is safe and portable.
 * Unfortunately, on some target/compiler combinations, the generated assembly is sub-optimal.
 * The below switch allow to select different access method for improved performance.
 * Method 0 (default) : use `memcpy()`. Safe and portable.
 * Method 1 : `__packed` statement. It depends on compiler extension (ie, not portable).
 *            This method is safe if your compiler supports it, and *generally* as fast or faster than `memcpy`.
 * Method 2 : direct access. This method doesn't depend on compiler but violate C standard.
 *            It can generate buggy code on targets which do not support unaligned memory accesses.
 *            But in some circumstances, it's the only known way to get the most performance (ie GCC + ARMv6)
 * See http://stackoverflow.com/a/32095106/646947 for details.
 * Prefer these methods in priority order (0 > 1 > 2)
 */
#ifndef XXH_FORCE_MEMORY_ACCESS   /* can be defined externally, on command line for example */
#  if defined(__GNUC__) && ( defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6T2__) )
#    define XXH_FORCE_MEMORY_ACCESS 2
#  elif (defined(__INTEL_COMPILER) && !defined(WIN32)) || \
  (defined(__GNUC__) && ( defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__) ))
#    define XXH_FORCE_MEMORY_ACCESS 1
#  endif
#endif

/*!XXH_ACCEPT_NULL_INPUT_POINTER :
 * If the input pointer is a null pointer, xxHash default behavior is to trigger a memory access error, since it is a bad pointer.
 * When this option is enabled, xxHash output for null input pointers will be the same as a null-length input.
 * By default, this option is disabled. To enable it, uncomment below define :
 */
/* #define XXH_ACCEPT_NULL_INPUT_POINTER 1 */

/*!XXH_FORCE_NATIVE_FORMAT :
 * By default, xxHash library provides endian-independant Hash values, based on little-endian convention.
 * Results are therefore identical for little-endian and big-endian CPU.
 * This comes at a performance cost for big-endian CPU, since some swapping is required to emulate little-endian format.
 * Should endian-independance be of no importance for your application, you may set the #define below to 1,
 * to improve speed for Big-endian CPU.
 * This option has no impact on Little_Endian CPU.
 */
#ifndef XXH_FORCE_NATIVE_FORMAT   /* can be defined externally */
#  define XXH_FORCE_NATIVE_FORMAT 0
#endif

/*!XXH_FORCE_ALIGN_CHECK :
 * This is a minor performance trick, only useful with lots of very small keys.
 * It means : check for aligned/unaligned input.
 * The check costs one initial branch per hash; set to 0 when the input data
 * is guaranteed to be aligned.
 */
#ifndef XXH_FORCE_ALIGN_CHECK /* can be defined externally */
#  if defined(__i386) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64)
#    define XXH_FORCE_ALIGN_CHECK 0
#  else
#    define XXH_FORCE_ALIGN_CHECK 1
#  endif
#endif

#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"


/* *************************************
*  Basic Types
***************************************/

/* Force direct memory access. Only works on CPU which support unaligned memory access in hardware */
static u32 XXH_read32(const void* memPtr) { return get_unaligned((u32 *) memPtr); }
static u64 XXH_read64(const void* memPtr) { return get_unaligned((u64 *) memPtr); }


/* *************************************
*  Architecture Macros
***************************************/
typedef enum { XXH_bigEndian=0, XXH_littleEndian=1 } XXH_endianess;

/* XXH_CPU_LITTLE_ENDIAN can be defined externally, for example on the compiler command line */
#ifndef XXH_CPU_LITTLE_ENDIAN
    static const int g_one = 1;
#   define XXH_CPU_LITTLE_ENDIAN   (*(const char*)(&g_one))
#endif


/* ***************************
*  Memory reads
*****************************/
typedef enum { XXH_aligned, XXH_unaligned } XXH_alignment;

__always_inline u32 XXH_readLE32_align(const void* ptr, XXH_endianess endian, XXH_alignment align)
{
    if (align==XXH_unaligned)
        return endian==XXH_littleEndian ? XXH_read32(ptr) : swab32(XXH_read32(ptr));
    else
        return endian==XXH_littleEndian ? *(const u32*)ptr : swab32(*(const u32*)ptr);
}

__always_inline u32 XXH_readLE32(const void* ptr, XXH_endianess endian)
{
    return XXH_readLE32_align(ptr, endian, XXH_unaligned);
}

static u32 XXH_readBE32(const void* ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? swab32(XXH_read32(ptr)) : XXH_read32(ptr);
}

__always_inline u64 XXH_readLE64_align(const void* ptr, XXH_endianess endian, XXH_alignment align)
{
    if (align==XXH_unaligned)
        return endian==XXH_littleEndian ? XXH_read64(ptr) : swab64(XXH_read64(ptr));
    else
        return endian==XXH_littleEndian ? *(const u64*)ptr : swab64(*(const u64*)ptr);
}

__always_inline u64 XXH_readLE64(const void* ptr, XXH_endianess endian)
{
    return XXH_readLE64_align(ptr, endian, XXH_unaligned);
}

static u64 XXH_readBE64(const void* ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? swab64(XXH_read64(ptr)) : XXH_read64(ptr);
}


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

unsigned XXH_versionNumber (void) { return XXH_VERSION_NUMBER; }


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

__always_inline u32 XXH32_endian_align(const void* input, size_t len, u32 seed, XXH_endianess endian, XXH_alignment align)
{
    const u8* p = (const u8*)input;
    const u8* bEnd = p + len;
    u32 h32;
#define XXH_get32bits(p) XXH_readLE32_align(p, endian, align)

#ifdef XXH_ACCEPT_NULL_INPUT_POINTER
    if (p==NULL) {
        len=0;
        bEnd=p=(const u8*)(size_t)16;
    }
#endif

    if (len>=16) {
        const u8* const limit = bEnd - 16;
        u32 v1 = seed + PRIME32_1 + PRIME32_2;
        u32 v2 = seed + PRIME32_2;
        u32 v3 = seed + 0;
        u32 v4 = seed - PRIME32_1;

        do {
            v1 = XXH32_round(v1, XXH_get32bits(p)); p+=4;
            v2 = XXH32_round(v2, XXH_get32bits(p)); p+=4;
            v3 = XXH32_round(v3, XXH_get32bits(p)); p+=4;
            v4 = XXH32_round(v4, XXH_get32bits(p)); p+=4;
        } while (p<=limit);

        h32 = rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12) + rol32(v4, 18);
    } else {
        h32  = seed + PRIME32_5;
    }

    h32 += (u32) len;

    while (p+4<=bEnd) {
        h32 += XXH_get32bits(p) * PRIME32_3;
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


unsigned int XXH32 (const void* input, size_t len, unsigned int seed)
{
#if 0
    /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
    XXH32_CREATESTATE_STATIC(state);
    XXH32_reset(state, seed);
    XXH32_update(state, input, len);
    return XXH32_digest(state);
#else
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if (XXH_FORCE_ALIGN_CHECK) {
        if ((((size_t)input) & 3) == 0) {   /* Input is 4-bytes aligned, leverage the speed benefit */
            if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
                return XXH32_endian_align(input, len, seed, XXH_littleEndian, XXH_aligned);
            else
                return XXH32_endian_align(input, len, seed, XXH_bigEndian, XXH_aligned);
    }   }

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH32_endian_align(input, len, seed, XXH_littleEndian, XXH_unaligned);
    else
        return XXH32_endian_align(input, len, seed, XXH_bigEndian, XXH_unaligned);
#endif
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

__always_inline u64 XXH64_endian_align(const void* input, size_t len, u64 seed, XXH_endianess endian, XXH_alignment align)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;
    u64 h64;
#define XXH_get64bits(p) XXH_readLE64_align(p, endian, align)

#ifdef XXH_ACCEPT_NULL_INPUT_POINTER
    if (p==NULL) {
        len=0;
        bEnd=p=(const u8*)(size_t)32;
    }
#endif

    if (len>=32) {
        const u8* const limit = bEnd - 32;
        u64 v1 = seed + PRIME64_1 + PRIME64_2;
        u64 v2 = seed + PRIME64_2;
        u64 v3 = seed + 0;
        u64 v4 = seed - PRIME64_1;

        do {
            v1 = XXH64_round(v1, XXH_get64bits(p)); p+=8;
            v2 = XXH64_round(v2, XXH_get64bits(p)); p+=8;
            v3 = XXH64_round(v3, XXH_get64bits(p)); p+=8;
            v4 = XXH64_round(v4, XXH_get64bits(p)); p+=8;
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
        u64 const k1 = XXH64_round(0, XXH_get64bits(p));
        h64 ^= k1;
        h64  = rol64(h64,27) * PRIME64_1 + PRIME64_4;
        p+=8;
    }

    if (p+4<=bEnd) {
        h64 ^= (u64)(XXH_get32bits(p)) * PRIME64_1;
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


unsigned long long XXH64 (const void* input, size_t len, unsigned long long seed)
{
#if 0
    /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
    XXH64_CREATESTATE_STATIC(state);
    XXH64_reset(state, seed);
    XXH64_update(state, input, len);
    return XXH64_digest(state);
#else
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if (XXH_FORCE_ALIGN_CHECK) {
        if ((((size_t)input) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
            if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
                return XXH64_endian_align(input, len, seed, XXH_littleEndian, XXH_aligned);
            else
                return XXH64_endian_align(input, len, seed, XXH_bigEndian, XXH_aligned);
    }   }

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH64_endian_align(input, len, seed, XXH_littleEndian, XXH_unaligned);
    else
        return XXH64_endian_align(input, len, seed, XXH_bigEndian, XXH_unaligned);
#endif
}


/* **************************************************
*  Advanced Hash Functions
****************************************************/

XXH32_state_t* XXH32_createState(void)
{
    return kmalloc(sizeof(XXH32_state_t), GFP_KERNEL);
}
XXH_errorcode XXH32_freeState(XXH32_state_t* statePtr)
{
    kfree(statePtr);
    return XXH_OK;
}

XXH64_state_t* XXH64_createState(void)
{
    return kmalloc(sizeof(XXH64_state_t), GFP_KERNEL);
}
XXH_errorcode XXH64_freeState(XXH64_state_t* statePtr)
{
    kfree(statePtr);
    return XXH_OK;
}


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


__always_inline XXH_errorcode XXH32_update_endian (XXH32_state_t* state, const void* input, size_t len, XXH_endianess endian)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;

#ifdef XXH_ACCEPT_NULL_INPUT_POINTER
    if (input==NULL) return XXH_ERROR;
#endif

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
            state->v1 = XXH32_round(state->v1, XXH_readLE32(p32, endian)); p32++;
            state->v2 = XXH32_round(state->v2, XXH_readLE32(p32, endian)); p32++;
            state->v3 = XXH32_round(state->v3, XXH_readLE32(p32, endian)); p32++;
            state->v4 = XXH32_round(state->v4, XXH_readLE32(p32, endian)); p32++;
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
            v1 = XXH32_round(v1, XXH_readLE32(p, endian)); p+=4;
            v2 = XXH32_round(v2, XXH_readLE32(p, endian)); p+=4;
            v3 = XXH32_round(v3, XXH_readLE32(p, endian)); p+=4;
            v4 = XXH32_round(v4, XXH_readLE32(p, endian)); p+=4;
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

XXH_errorcode XXH32_update (XXH32_state_t* state_in, const void* input, size_t len)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH32_update_endian(state_in, input, len, XXH_littleEndian);
    else
        return XXH32_update_endian(state_in, input, len, XXH_bigEndian);
}



__always_inline u32 XXH32_digest_endian (const XXH32_state_t* state, XXH_endianess endian)
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
        h32 += XXH_readLE32(p, endian) * PRIME32_3;
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


unsigned int XXH32_digest (const XXH32_state_t* state_in)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH32_digest_endian(state_in, XXH_littleEndian);
    else
        return XXH32_digest_endian(state_in, XXH_bigEndian);
}



/* **** XXH64 **** */

__always_inline XXH_errorcode XXH64_update_endian (XXH64_state_t* state, const void* input, size_t len, XXH_endianess endian)
{
    const u8* p = (const u8*)input;
    const u8* const bEnd = p + len;

#ifdef XXH_ACCEPT_NULL_INPUT_POINTER
    if (input==NULL) return XXH_ERROR;
#endif

    state->total_len += len;

    if (state->memsize + len < 32) {  /* fill in tmp buffer */
        memcpy(((u8*)state->mem64) + state->memsize, input, len);
        state->memsize += (u32)len;
        return XXH_OK;
    }

    if (state->memsize) {   /* tmp buffer is full */
        memcpy(((u8*)state->mem64) + state->memsize, input, 32-state->memsize);
        state->v1 = XXH64_round(state->v1, XXH_readLE64(state->mem64+0, endian));
        state->v2 = XXH64_round(state->v2, XXH_readLE64(state->mem64+1, endian));
        state->v3 = XXH64_round(state->v3, XXH_readLE64(state->mem64+2, endian));
        state->v4 = XXH64_round(state->v4, XXH_readLE64(state->mem64+3, endian));
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
            v1 = XXH64_round(v1, XXH_readLE64(p, endian)); p+=8;
            v2 = XXH64_round(v2, XXH_readLE64(p, endian)); p+=8;
            v3 = XXH64_round(v3, XXH_readLE64(p, endian)); p+=8;
            v4 = XXH64_round(v4, XXH_readLE64(p, endian)); p+=8;
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

XXH_errorcode XXH64_update (XXH64_state_t* state_in, const void* input, size_t len)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH64_update_endian(state_in, input, len, XXH_littleEndian);
    else
        return XXH64_update_endian(state_in, input, len, XXH_bigEndian);
}



__always_inline u64 XXH64_digest_endian (const XXH64_state_t* state, XXH_endianess endian)
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
        u64 const k1 = XXH64_round(0, XXH_readLE64(p, endian));
        h64 ^= k1;
        h64  = rol64(h64,27) * PRIME64_1 + PRIME64_4;
        p+=8;
    }

    if (p+4<=bEnd) {
        h64 ^= (u64)(XXH_readLE32(p, endian)) * PRIME64_1;
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


unsigned long long XXH64_digest (const XXH64_state_t* state_in)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((endian_detected==XXH_littleEndian) || XXH_FORCE_NATIVE_FORMAT)
        return XXH64_digest_endian(state_in, XXH_littleEndian);
    else
        return XXH64_digest_endian(state_in, XXH_bigEndian);
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
    if (XXH_CPU_LITTLE_ENDIAN) hash = swab32(hash);
    memcpy(dst, &hash, sizeof(*dst));
}

void XXH64_canonicalFromHash(XXH64_canonical_t* dst, u64 hash)
{
    XXH_STATIC_ASSERT(sizeof(XXH64_canonical_t) == sizeof(u64));
    if (XXH_CPU_LITTLE_ENDIAN) hash = swab64(hash);
    memcpy(dst, &hash, sizeof(*dst));
}

u32 XXH32_hashFromCanonical(const XXH32_canonical_t* src)
{
    return XXH_readBE32(src);
}

u64 XXH64_hashFromCanonical(const XXH64_canonical_t* src)
{
    return XXH_readBE64(src);
}
