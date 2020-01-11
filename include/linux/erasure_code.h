/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Generalized GF(256) Erasure Coding with Hardware Acceleration. 
 * This library complements linux/raid for larger parity sizes.
 * This library uses implementations ported from Intel ISA-L. 
 * 
 * Provides implementations of various EC algorithms:
 * - Vandermonde RS
 * - Cauchy RS
 * 
 * See documentation/erasure_code for more information.
 * 
 * Copyright (c) 2020 Robbie Litchfield <blam.kiwi@gmail.com>
 */

#ifndef ERASURE_CODE_H_INCLUDED
#define ERASURE_CODE_H_INCLUDED

#include <linux/compiler.h>
#include <linux/types.h>

struct erasure_code_ctx;
struct erasure_code_cache_entry;
struct erasure_code_decode_cache;

enum erasure_code_algorithm {
    ERASURE_CODE_VANDERMONDE_RS,
    ERASURE_CODE_CAUCHY_RS
};

typedef int (*erasure_code_encode_impl_t)(const struct erasure_code_ctx* ctx, const struct erasure_code_cache_entry *encode, size_t symbol_len, void **symbols);
typedef int (*erasure_code_decode_impl_t)(struct erasure_code_ctx* ctx, size_t symbol_len, void **symbols, size_t num_erasures, const int* erasures);

struct erasure_code_ctx {
    enum erasure_code_algorithm alg;
    u8 data;
    u8 parity;
    
    erasure_code_encode_impl_t encode_func;
    erasure_code_decode_impl_t decode_func;
    
    struct erasure_code_cache_entry *encode_cache;
    struct erasure_code_decode_cache *decode_cache;
};

int erasure_code_num_decode_combinations(u8 data, u8 parity, size_t *value);

int erasure_code_context_init(struct erasure_code_ctx* ctx, enum erasure_code_algorithm alg, u8 data, u8 parity, size_t max_cache_size);
void erasure_code_context_destroy(struct erasure_code_ctx* ctx);

static __always_inline int erasure_code_encode(const struct erasure_code_ctx* ctx, size_t symbol_len, void **symbols) {
    return ctx->encode_func(ctx, ctx->encode_cache, symbol_len, symbols);
}
static __always_inline int erasure_code_decode(struct erasure_code_ctx* ctx, size_t symbol_len, void **symbols, size_t num_erasures, const int* erasures) {
    return ctx->decode_func(ctx, symbol_len, symbols, num_erasures, erasures);
}

#endif // ERASURE_CODE_H_INCLUDED
