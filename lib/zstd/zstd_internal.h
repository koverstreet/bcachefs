/**
 * Copyright (c) 2016-present, Yann Collet, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

#ifndef ZSTD_CCOMMON_H_MODULE
#define ZSTD_CCOMMON_H_MODULE

/*-*************************************
*  Dependencies
***************************************/
#include "mem.h"
#include "error_private.h"
#include <linux/zstd.h>


/*-*************************************
*  shared macros
***************************************/
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#define MAX(a,b) ((a)>(b) ? (a) : (b))
#define CHECK_F(f) { size_t const errcod = f; if (ERR_isError(errcod)) return errcod; }  /* check and Forward error code */
#define CHECK_E(f, e) { size_t const errcod = f; if (ERR_isError(errcod)) return ERROR(e); }  /* check and send Error code */


/*-*************************************
*  Common constants
***************************************/
#define ZSTD_OPT_NUM    (1<<12)
#define ZSTD_DICT_MAGIC  0xEC30A437   /* v0.7+ */

#define ZSTD_REP_NUM      3                 /* number of repcodes */
#define ZSTD_REP_CHECK    (ZSTD_REP_NUM)    /* number of repcodes to check by the optimal parser */
#define ZSTD_REP_MOVE     (ZSTD_REP_NUM-1)
#define ZSTD_REP_MOVE_OPT (ZSTD_REP_NUM)
static const u32 repStartValue[ZSTD_REP_NUM] = { 1, 4, 8 };

#define KB *(1 <<10)
#define MB *(1 <<20)
#define GB *(1U<<30)

#define BIT7 128
#define BIT6  64
#define BIT5  32
#define BIT4  16
#define BIT1   2
#define BIT0   1

#define ZSTD_WINDOWLOG_ABSOLUTEMIN 10
static const size_t ZSTD_fcs_fieldSize[4] = { 0, 2, 4, 8 };
static const size_t ZSTD_did_fieldSize[4] = { 0, 1, 2, 4 };

#define ZSTD_BLOCKHEADERSIZE 3   /* C standard doesn't allow `static const` variable to be init using another `static const` variable */
static const size_t ZSTD_blockHeaderSize = ZSTD_BLOCKHEADERSIZE;
typedef enum { bt_raw, bt_rle, bt_compressed, bt_reserved } blockType_e;

#define MIN_SEQUENCES_SIZE 1 /* nbSeq==0 */
#define MIN_CBLOCK_SIZE (1 /*litCSize*/ + 1 /* RLE or RAW */ + MIN_SEQUENCES_SIZE /* nbSeq==0 */)   /* for a non-null block */

#define HufLog 12
typedef enum { set_basic, set_rle, set_compressed, set_repeat } symbolEncodingType_e;

#define LONGNBSEQ 0x7F00

#define MINMATCH 3
#define EQUAL_READ32 4

#define Litbits  8
#define MaxLit ((1<<Litbits) - 1)
#define MaxML  52
#define MaxLL  35
#define MaxOff 28
#define MaxSeq MAX(MaxLL, MaxML)   /* Assumption : MaxOff < MaxLL,MaxML */
#define MLFSELog    9
#define LLFSELog    9
#define OffFSELog   8

static const u32 LL_bits[MaxLL+1] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9,10,11,12,
                                     13,14,15,16 };
static const s16 LL_defaultNorm[MaxLL+1] = { 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
                                             2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
                                            -1,-1,-1,-1 };
#define LL_DEFAULTNORMLOG 6  /* for static allocation */
static const u32 LL_defaultNormLog = LL_DEFAULTNORMLOG;

static const u32 ML_bits[MaxML+1] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,10,11,
                                     12,13,14,15,16 };
static const s16 ML_defaultNorm[MaxML+1] = { 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,-1,-1,
                                            -1,-1,-1,-1,-1 };
#define ML_DEFAULTNORMLOG 6  /* for static allocation */
static const u32 ML_defaultNormLog = ML_DEFAULTNORMLOG;

static const s16 OF_defaultNorm[MaxOff+1] = { 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                                              1, 1, 1, 1, 1, 1, 1, 1,-1,-1,-1,-1,-1 };
#define OF_DEFAULTNORMLOG 5  /* for static allocation */
static const u32 OF_defaultNormLog = OF_DEFAULTNORMLOG;


/*-*******************************************
*  Shared functions to include for inlining
*********************************************/
static void ZSTD_copy8(void* dst, const void* src) { memcpy(dst, src, 8); }
#define COPY8(d,s) { ZSTD_copy8(d,s); d+=8; s+=8; }

/*! ZSTD_wildcopy() :
*   custom version of memcpy(), can copy up to 7 bytes too many (8 bytes if length==0) */
#define WILDCOPY_OVERLENGTH 8
static inline void ZSTD_wildcopy(void* dst, const void* src, ptrdiff_t length)
{
    const u8* ip = (const u8*)src;
    u8* op = (u8*)dst;
    u8* const oend = op + length;
    do
        COPY8(op, ip)
    while (op < oend);
}

static inline void ZSTD_wildcopy_e(void* dst, const void* src, void* dstEnd)   /* should be faster for decoding, but strangely, not verified on all platform */
{
    const u8* ip = (const u8*)src;
    u8* op = (u8*)dst;
    u8* const oend = (u8*)dstEnd;
    do
        COPY8(op, ip)
    while (op < oend);
}


/*-*******************************************
*  Private interfaces
*********************************************/
typedef struct ZSTD_stats_s ZSTD_stats_t;

typedef struct {
    u32 off;
    u32 len;
} ZSTD_match_t;

typedef struct {
    u32 price;
    u32 off;
    u32 mlen;
    u32 litlen;
    u32 rep[ZSTD_REP_NUM];
} ZSTD_optimal_t;


typedef struct seqDef_s {
    u32 offset;
    u16 litLength;
    u16 matchLength;
} seqDef;


typedef struct {
    seqDef* sequencesStart;
    seqDef* sequences;
    u8* litStart;
    u8* lit;
    u8* llCode;
    u8* mlCode;
    u8* ofCode;
    u32   longLengthID;   /* 0 == no longLength; 1 == Lit.longLength; 2 == Match.longLength; */
    u32   longLengthPos;
    /* opt */
    ZSTD_optimal_t* priceTable;
    ZSTD_match_t* matchTable;
    u32* matchLengthFreq;
    u32* litLengthFreq;
    u32* litFreq;
    u32* offCodeFreq;
    u32  matchLengthSum;
    u32  matchSum;
    u32  litLengthSum;
    u32  litSum;
    u32  offCodeSum;
    u32  log2matchLengthSum;
    u32  log2matchSum;
    u32  log2litLengthSum;
    u32  log2litSum;
    u32  log2offCodeSum;
    u32  factor;
    u32  staticPrices;
    u32  cachedPrice;
    u32  cachedLitLength;
    const u8* cachedLiterals;
} seqStore_t;

const seqStore_t* ZSTD_getSeqStore(const ZSTD_CCtx* ctx);
void ZSTD_seqToCodes(const seqStore_t* seqStorePtr);
int ZSTD_isSkipFrame(ZSTD_DCtx* dctx);

/* hidden functions */

/* ZSTD_invalidateRepCodes() :
 * ensures next compression will not use repcodes from previous block.
 * Note : only works with regular variant;
 *        do not use with extDict variant ! */
void ZSTD_invalidateRepCodes(ZSTD_CCtx* cctx);


#endif   /* ZSTD_CCOMMON_H_MODULE */
