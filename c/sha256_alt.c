/*
 * Copyright (c) 2024 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>

#include "common.h"
#include "mbedtls/sha256.h"
#include "pico.h"
#include "stdio.h"

#ifdef MBEDTLS_SHA256_ALT
#if !LIB_PICO_SHA256
#error SHA256 hardware acceleration not supported
#endif

// PICO_CONFIG: PICO_MBEDTLS_SHA256_ALT_USE_DMA, Whether to use DMA for writing
// to hardware for the mbedtls SHA-256 hardware acceleration, type=int,
// default=1, group=pico_stdlib
#ifndef PICO_MBEDTLS_SHA256_ALT_USE_DMA
#define PICO_MBEDTLS_SHA256_ALT_USE_DMA 1
#endif

uint8_t buf_0[8192] = {0};
size_t buf_0_len = 0;

int sha_index = 0;
void mbedtls_sha256_init(__unused mbedtls_sha256_context *ctx) {
    ctx->index = sha_index;
    sha_index++;
}

void mbedtls_sha256_free(__unused mbedtls_sha256_context *ctx) {}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    hard_assert(!is224);  // that's annoying

    if (ctx->index == 0) {
        return 0;
    }

    pico_sha256_start_blocking(&ctx->pico_sha256_state, SHA256_BIG_ENDIAN,
                               PICO_MBEDTLS_SHA256_ALT_USE_DMA);

    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input, size_t ilen) {
    if (ilen == 0 || ctx->index == 0) {
        memcpy(buf_0 + buf_0_len, input, ilen);
        buf_0_len += ilen;
        return 0;
    }

    pico_sha256_update_blocking(&ctx->pico_sha256_state, input, ilen);

    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char output[32]) {
    sha256_result_t result;

    if (ctx->index == 0) {
        pico_sha256_start_blocking(&ctx->pico_sha256_state, SHA256_BIG_ENDIAN,
                                   PICO_MBEDTLS_SHA256_ALT_USE_DMA);
        pico_sha256_update_blocking(&ctx->pico_sha256_state, buf_0, buf_0_len);
        pico_sha256_finish(&ctx->pico_sha256_state, &result);
        memcpy(output, result.bytes, 32);
        return 0;
    }

    pico_sha256_finish(&ctx->pico_sha256_state, &result);

    memcpy(output, result.bytes, 32);
    return 0;

    return 0;
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src) {
    *dst = *src;
}

#endif  // MBEDTLS_SHA256_ALT