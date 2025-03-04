/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___SHA256CF_H_
#define ___SHA256CF_H_

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


// SHA-256 parameters
enum {
    SHA256_WORD_SIZE_IN_BITS = 32,
    SHA256_WORD_SIZE_IN_BYTES = 32 / 8,

    SHA256_MESSAGE_BLOCK_SIZE_IN_BITS = 512,
    SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES = 512 / 8,
    SHA256_MESSAGE_BLOCK_SIZE_IN_WORDS = 512 / 32,

    SHA256_CHAIN_SIZE_IN_BITS = 256,
    SHA256_CHAIN_SIZE_IN_BYTES = 256 / 8,
    SHA256_CHAIN_SIZE_IN_WORDS = 256 / 32,

    SHA256_HASH_SIZE_IN_BITS = 256,
    SHA256_HASH_SIZE_IN_BYTES = 256 / 8,
    SHA256_HASH_SIZE_IN_WORDS = 256 / 32,
};

// The structure for holding information for SHA-256
typedef struct {
    // Chaining value: Noe that the order is somewhat odd.
    // first 128bits: h0|h1|h4|h5 or a|b|e|f
    // last  128bits: h2:h3:h6:h7 or c|d|g|h
    __m128i h0145, h2367;
    // a remaining message to be hashed
    uint8_t *remMessage;
    // the byte length of the remaining message
    size_t remMessageByteLength;
} Sha256Context;


static inline void printXmm(const __m128i *const xmm)
{
    const uint32_t *x = (const uint32_t *) xmm;
    fprintf(stdout, "%08x %08x %08x %08x", x[0], x[1], x[2], x[3]);
    fflush(stdout);
}


static inline void printLnXmm(const __m128i *const xmm)
{
    printXmm(xmm);
    fputc('\n', stdout);
    fflush(stdout);
}


static inline void printLnXmm2(const __m128i *const x1,
                               const __m128i *const x2)
{
    printXmm(x1);
    fputc(' ', stdout);
    printLnXmm(x2);
}


static inline void swapPrintLnXmm2(const __m128i *const x1,
                                   const __m128i *const x2)
{
    __m128i lt = _mm_unpackhi_epi64(*x2, *x1);
    __m128i rt = _mm_unpacklo_epi64(*x2, *x1);
    printLnXmm2(&lt, &rt);
}


/* sha256cf.c */
void Sha256CompressionFunction(Sha256Context *const c);
uint32_t *Sha256CompressionFunctionRef(uint32_t
                                       inout[SHA256_CHAIN_SIZE_IN_WORDS],
                                       const uint8_t
                                       messageBlock
                                       [SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES]);

#endif                          // ___SHA256CF_H_

// end of file
