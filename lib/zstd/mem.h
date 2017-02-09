/**
 * Copyright (c) 2016-present, Yann Collet, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

#ifndef MEM_H_MODULE
#define MEM_H_MODULE

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*-**************************************************************
*  Memory I/O
*****************************************************************/

static inline unsigned MEM_32bits(void) { return sizeof(size_t)==4; }
static inline unsigned MEM_64bits(void) { return sizeof(size_t)==8; }

static inline unsigned MEM_isLittleEndian(void)
{
    const union { u32 u; u8 c[4]; } one = { 1 };   /* don't use static : performance detrimental  */
    return one.c[0];
}

static inline u16 MEM_read16(const void *p)
{
    return get_unaligned((u16 *) p);
}

static inline u32 MEM_read32(const void *p)
{
    return get_unaligned((u32 *) p);
}

static inline u64 MEM_read64(const void *p)
{
    return get_unaligned((u64 *) p);
}

static inline size_t MEM_readST(const void *p)
{
    return get_unaligned((size_t *) p);
}

static inline void MEM_write16(void *p, u16 v)
{
    put_unaligned(v, (u16 *) p);
}

static inline void MEM_write32(void *p, u32 v)
{
    put_unaligned(v, (u32 *) p);
}

static inline void MEM_write64(void *p, u64 v)
{
    put_unaligned(v, (u64 *) p);
}

/*=== Little endian r/w ===*/

static inline u16 MEM_readLE16(const void *p)
{
    return get_unaligned_le16(p);
}

static inline void MEM_writeLE16(void *p, u16 v)
{
    put_unaligned_le16(v, p);
}

static inline u32 MEM_readLE24(const void *p)
{
    return MEM_readLE16(p) + (((const u8*) p)[2] << 16);
}

static inline void MEM_writeLE24(void *p, u32 v)
{
    MEM_writeLE16(p, (u16)v);
    ((u8*)p)[2] = (u8)(v>>16);
}

static inline u32 MEM_readLE32(const void *p)
{
    return get_unaligned_le32(p);
}

static inline void MEM_writeLE32(void *p, u32 v)
{
    put_unaligned_le32(v, p);
}

static inline u64 MEM_readLE64(const void *p)
{
    return get_unaligned_le64(p);
}

static inline void MEM_writeLE64(void *p, u64 v)
{
    put_unaligned_le64(v, p);
}

static inline size_t MEM_readLEST(const void *p)
{
    return __get_unaligned_le((size_t *) p);
}

static inline void MEM_writeLEST(void *p, size_t v)
{
    __put_unaligned_le(v, (size_t *) p);
}

/*=== Big endian r/w ===*/

static inline u32 MEM_readBE32(const void *p)
{
    return get_unaligned_be32(p);
}

static inline void MEM_writeBE32(void *p, u32 v)
{
    put_unaligned_be32(v, p);
}

static inline u64 MEM_readBE64(const void *p)
{
    return get_unaligned_be64(p);
}

static inline void MEM_writeBE64(void *p, u64 v)
{
    put_unaligned_be64(v, p);
}

static inline size_t MEM_readBEST(const void *p)
{
    return __get_unaligned_be((size_t *) p);
}

static inline void MEM_writeBEST(void *p, size_t v)
{
    __put_unaligned_be(v, (size_t *) p);
}


/* function safe only for comparisons */
static inline u32 MEM_readMINMATCH(const void *p, u32 length)
{
    switch (length) {
    default :
    case 4 : return MEM_read32(p);
    case 3 : if (MEM_isLittleEndian())
                return MEM_read32(p)<<8;
             else
                return MEM_read32(p)>>8;
    }
}

#endif /* MEM_H_MODULE */
