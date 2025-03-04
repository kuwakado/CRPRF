/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___SHA256_H_
#define ___SHA256_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sha256cf.h"


static void printMessageBlock(const uint8_t *const mb)
{
    for (size_t i = 0; i < SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES; ++i) {
        printf("%02x", mb[i]);
    }
    putchar('\n');
}


static void printDigest(const uint8_t *const d)
{
    for (int i = 0; i < SHA256_HASH_SIZE_IN_BYTES; ++i) {
        printf("%02x", d[i]);
        if (i == SHA256_HASH_SIZE_IN_BYTES - 1) {
            fputc('\n', stdout);
        } else if (i % 4 == 3) {
            fputc(' ', stdout);
        } else {
            // Do nothing
        }
    }
}


static void printLnSha256Context(const Sha256Context *const c)
{
    const __m128i x = c->h0145;
    const __m128i y = c->h2367;
    // Show in ascending order of indexes.
    __m128i a = _mm_unpackhi_epi64(y, x);
    __m128i b = _mm_unpacklo_epi64(y, x);
    const uint32_t *p = (const uint32_t *) &a;
    fputs("h0123 h4567  ", stdout);
    printf("%08x %08x %08x %08x  ", p[0], p[1], p[2], p[3]);
    p = (const uint32_t *) &b;
    printf("%08x %08x %08x %08x\n", p[0], p[1], p[2], p[3]);
    printf("remMessage  %sNULL\n", c->remMessage == NULL ? "" : "not ");
    if (c->remMessage != NULL && c->remMessageByteLength != 0) {
        enum { MAX_IDX = 24, };
        const size_t max_idx =
            (c->remMessageByteLength <
             MAX_IDX) ? c->remMessageByteLength : MAX_IDX;
        for (size_t i = 0; i < max_idx; ++i) {
            printf("%02x", c->remMessage[i]);
            if (i == max_idx - 1) {
                if (max_idx < c->remMessageByteLength) {
                    fputs("...", stdout);
                }
                fputc('\n', stdout);
            } else {
                fputc(' ', stdout);
            }
        }
    }
    printf("remMessageByteLength  %zu\n", c->remMessageByteLength);
}


/* sha256.c */
void Sha256Init(Sha256Context *const c,
                uint8_t iv[SHA256_CHAIN_SIZE_IN_BYTES], uint8_t *message,
                const size_t messageByteLength);
void Sha256Update(Sha256Context *const c);
void Sha256Final(uint8_t digest[SHA256_HASH_SIZE_IN_BYTES],
                 Sha256Context *const c, const size_t messageByteLength);
void Sha256(uint8_t digest[SHA256_HASH_SIZE_IN_BYTES],
            uint8_t iv[SHA256_CHAIN_SIZE_IN_BYTES], uint8_t *message,
            size_t messageByteLength);

#endif                          // ___SHA256_H_

//  end of file
