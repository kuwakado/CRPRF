/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "sha256cf.h"
#include "sha256.h"
#include "macro.h"


void Sha256Init(Sha256Context *const c,
                uint8_t iv[SHA256_CHAIN_SIZE_IN_BYTES],
                uint8_t *message, const size_t messageByteLength)
{
    assert(c != NULL);
    assert((message == NULL && messageByteLength == 0) ||
           (message != NULL && messageByteLength > 0));

    // Default IV
    // These values are given in a 32-bit array by the specification.
    uint32_t H[SHA256_CHAIN_SIZE_IN_WORDS] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    assert(IS_16_BYTE_ALIGNED(H));

    if (iv != NULL) {
        // To use a given iv instead of the default iv, convert the endianess.
        // __m128i *Hmm = byteSwapping32x8To2x128(iv);
        const __m128i toBig =
            _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2,
                         3);
        __m128i *Hmm = (__m128i *) iv;
        Hmm[0] = _mm_shuffle_epi8(_mm_loadu_si128(Hmm + 0), toBig);
        Hmm[1] = _mm_shuffle_epi8(_mm_loadu_si128(Hmm + 1), toBig);
        memcpy(H, Hmm, sizeof(H));
        if (false) {
            for (size_t i = 0; i < NELMS(H); ++i) {
                fprintf(stdout, "%08x ", H[i]);
            }
            fputc('\n', stdout);
        }
    }
    // The order of 32-bit ivs is somewhat odd due to SHA-NI.
    c->h0145 = _mm_set_epi32(H[0], H[1], H[4], H[5]);
    c->h2367 = _mm_set_epi32(H[2], H[3], H[6], H[7]);
    c->remMessage = message;
    c->remMessageByteLength = messageByteLength;
    if (false) {
        printLnSha256Context(c);
        EXIT_HERE();
    }
}


void Sha256Update(Sha256Context *const c)
{
    assert(c != NULL);
    assert((c->remMessage == NULL && c->remMessageByteLength == 0) ||
           (c->remMessage != NULL && c->remMessageByteLength > 0));

    while (c->remMessageByteLength >= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES) {
        Sha256CompressionFunction(c);
        if (false) {
            fputs("h0123 h4567  ", stdout);
            swapPrintLnXmm2(&c->h0145, &c->h2367);
        }
        c->remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        c->remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    }
    if (c->remMessageByteLength == 0) {
        c->remMessage = NULL;
    }
}

static inline void reverseByteOrder(uint8_t a[8])
{
    uint8_t tmp = a[0];
    a[0] = a[7];
    a[7] = tmp;
    tmp = a[1];
    a[1] = a[6];
    a[6] = tmp;
    tmp = a[2];
    a[2] = a[5];
    a[5] = tmp;
    tmp = a[3];
    a[3] = a[4];
    a[4] = tmp;
}

void Sha256Final(uint8_t digest[SHA256_HASH_SIZE_IN_BYTES],
                 Sha256Context *const c, const size_t messageByteLength)
{
    assert(digest != NULL);
    assert(c != NULL);

    // Since 'bitLength' is not used in AVX, the alignment does not matter.
    uint8_t bitLength[8] = { 0x00, };
    uint64_t messageBitLength = 8 * (uint64_t) messageByteLength;
    assert(sizeof(messageBitLength) == sizeof(bitLength));
    memcpy(bitLength, &messageBitLength, sizeof(bitLength));
    // Convert little endian to big endian.
    reverseByteOrder(bitLength);
    if (false) {
        fputs("bitLength  ", stdout);
        for (size_t i = 0; i < NELMS(bitLength); ++i) {
            fprintf(stdout, "%02x", bitLength[i]);
            if (i % NELMS(bitLength) == NELMS(bitLength) - 1) {
                fprintf(stdout, " (%zu)\n", messageBitLength);
            } else if (i % 4 == 3) {
                fputc(' ', stdout);
            } else {
                // Do nothing.
            }
        }
        EXIT_HERE();
    }

    uint8_t block[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00, };
    assert(IS_16_BYTE_ALIGNED(block));
    if (c->remMessageByteLength == 0) {
        block[0] = 0x80;
        memcpy(block + SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES -
               sizeof(bitLength), bitLength, sizeof(bitLength));
        c->remMessage = block;
        c->remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        Sha256CompressionFunction(c);
        c->remMessage = NULL;
        c->remMessageByteLength = 0;
    } else if (c->remMessageByteLength <=
               SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES - 1 - NELMS(bitLength)) {
        memcpy(block, c->remMessage, c->remMessageByteLength);
        block[c->remMessageByteLength] = 0x80;
        memcpy(block + SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES -
               sizeof(bitLength), bitLength, sizeof(bitLength));
        c->remMessage = block;
        c->remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        if (false) {
            printMessageBlock(block);
            EXIT_HERE();
        }
        Sha256CompressionFunction(c);
        c->remMessage = NULL;
        c->remMessageByteLength = 0;
    } else if (c->remMessageByteLength <
               SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES) {
        // The second block from the last
        memcpy(block, c->remMessage, c->remMessageByteLength);
        block[c->remMessageByteLength] = 0x80;
        c->remMessage = block;
        c->remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        Sha256CompressionFunction(c);
        // The last block
        memset(block, 0x00, sizeof(block) - sizeof(bitLength));
        memcpy(block + sizeof(block) - sizeof(bitLength), bitLength,
               sizeof(bitLength));
        Sha256CompressionFunction(c);
        c->remMessage = NULL;
        c->remMessageByteLength = 0;
    } else {
        fputs("Error: Unreachable part\n", stdout);
        EXIT_HERE();
    }

    // Exchange words.
    // h0:h1:h4:h5, h2:h3:h6:h7 -> h0:h1:h2:h3, h4:h5:h6:h7
    __m128i h0123 = _mm_unpackhi_epi64(c->h2367, c->h0145);
    __m128i h4567 = _mm_unpacklo_epi64(c->h2367, c->h0145);
    // Convert big endian to little endian.
    const __m128i toLittle =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    h0123 = _mm_shuffle_epi8(h0123, toLittle);
    h4567 = _mm_shuffle_epi8(h4567, toLittle);
    __m128i *const mdmm = (__m128i *const) digest;
    _mm_storeu_si128(mdmm + 0, h0123);
    _mm_storeu_si128(mdmm + 1, h4567);
}


// No zero-byte array is allowed in ISO C, so a zero-byte message is represented
// as NULL.
void Sha256(uint8_t digest[SHA256_HASH_SIZE_IN_BYTES],
            uint8_t iv[SHA256_CHAIN_SIZE_IN_BYTES],
            uint8_t *message, size_t messageByteLength)
{
    assert(digest != NULL);
    assert((message == NULL && messageByteLength == 0)
           || (message != NULL && messageByteLength != 0));

#ifndef SHA266_MOC
    Sha256Context c = { 0x00, };
    Sha256Init(&c, iv, message, messageByteLength);
    Sha256Update(&c);
    Sha256Final(digest, &c, messageByteLength);
#endif                          // SHA266_MOC
}


#ifdef CHECK_SHA256
#include <openssl/sha.h>

int main(int argc, char *argv[])
{
    enum {
        // 5 message blocks = 5 * 512 bits = 320 bytes
        MAX_MESSAGE_BYTE_LENGTH = 320,
        MAX_REPEAT_COUNT = 1 + 1024 * 4,
    };

    for (size_t mBLen = 0; mBLen <= MAX_MESSAGE_BYTE_LENGTH; ++mBLen) {
        uint8_t *m1 = NULL;
        uint8_t *m2 = NULL;
        uint8_t *m3 = NULL;
        if (mBLen != 0) {
            // The address of a block returned by malloc in GCC is always a
            // multiple of sixteen on 64-bit systems.
            // https://www.gnu.org/software/libc/manual/html_node/Aligned-Memory-Blocks.html
            m1 = calloc(mBLen, sizeof(uint8_t));
            m2 = calloc(mBLen, sizeof(uint8_t));
            m3 = calloc(mBLen, sizeof(uint8_t));
            assert(m1 != NULL && m2 != NULL && m3 != NULL);
            assert(IS_16_BYTE_ALIGNED(m1) && IS_16_BYTE_ALIGNED(m2)
                   && IS_16_BYTE_ALIGNED(m3));
        }

        for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
            if (m1 != NULL && m2 != NULL && m3 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                memcpy(m2, m1, sizeof(uint8_t) * mBLen);
                memcpy(m3, m1, sizeof(uint8_t) * mBLen);
            }
            // OpenSSL SHA-256
            uint8_t digest1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(digest1));
            SHA256(m1, mBLen, digest1);
            //Self-made SHA-256
            uint8_t digest2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(digest2));
            Sha256(digest2, NULL, m2, mBLen);
            // Self-made SHA-256, given iv
            uint8_t digest3[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(digest3));
            uint8_t iv[8 * 4] = {
                0x6a, 0x09, 0xe6, 0x67, // 0x6a09e667
                0xbb, 0x67, 0xae, 0x85, // 0xbb67ae85
                0x3c, 0x6e, 0xf3, 0x72, // 0x3c6ef372
                0xa5, 0x4f, 0xf5, 0x3a, // 0xa54ff53a
                0x51, 0x0e, 0x52, 0x7f, // 0x510e527f
                0x9b, 0x05, 0x68, 0x8c, // 0x9b05688c
                0x1f, 0x83, 0xd9, 0xab, // 0x1f83d9ab
                0x5b, 0xe0, 0xcd, 0x19  // 0x5be0cd19
            };
            assert(IS_16_BYTE_ALIGNED(digest3));
            Sha256(digest3, iv, m3, mBLen);

            // Compare them.
            if (memcmp(digest1, digest2, SHA256_HASH_SIZE_IN_BYTES) == 0 &&
                memcmp(digest1, digest3, SHA256_HASH_SIZE_IN_BYTES) == 0) {
                continue;
            } else {
                fputs("SHA-256: FAILED\n", stdout);
                exit(EXIT_FAILURE);
            }
        }
        FREE_THEN_NULL(m3);
        FREE_THEN_NULL(m2);
        FREE_THEN_NULL(m1);
    }
    fputs("SHA-256: PASS\n", stdout);

    return 0;
}
#endif                          // CHECK_SHA256


#ifdef BENCH_SHA256
#include <inttypes.h>
#include <openssl/sha.h>

static inline int ascendingOrder(const void *const x, const void *const y)
{
    const uint64_t x64 = *(uint64_t *const) x;
    const uint64_t y64 = *(uint64_t *const) y;
    if (x64 > y64) {
        return 1;
    } else if (x64 < y64) {
        return -1;
    } else {
        return 0;
    }
}


int main(int argc, char *argv[])
{
    enum {
        // 4 message blocks = 4 * 512 bits = 2,048 bits = 256 bytes
        MAX_MESSAGE_BYTE_LENGTH = 256,
        MAX_REPEAT_COUNT = 1 + 1024 * 64
    };

    for (size_t mBLen = 0; mBLen <= MAX_MESSAGE_BYTE_LENGTH; ++mBLen) {
        uint8_t *m1 = NULL;
        uint8_t *m2 = NULL;
        if (mBLen != 0) {
            // The address of a block returned by malloc in GCC is always a
            // multiple of sixteen on 64-bit systems.
            // https://www.gnu.org/software/libc/manual/html_node/Aligned-Memory-Blocks.html
            m1 = calloc(mBLen, sizeof(uint8_t));
            m2 = calloc(mBLen, sizeof(uint8_t));
            if (m1 == NULL || m2 == NULL) {
                perror(NULL);
                exit(EXIT_FAILURE);
            }
            assert(IS_16_BYTE_ALIGNED(m1) && IS_16_BYTE_ALIGNED(m2));
        }
        uint64_t *lap1 = calloc(MAX_REPEAT_COUNT, sizeof(uint64_t));
        uint64_t *lap2 = calloc(MAX_REPEAT_COUNT, sizeof(uint64_t));
        if (lap1 == NULL || lap2 == NULL) {
            perror(NULL);
            exit(EXIT_FAILURE);
        }

        for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
            if (m1 != NULL && m2 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                memcpy(m2, m1, mBLen * sizeof(uint8_t));
            }

            // OpenSSL
            uint8_t digest1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(digest1));
            uint64_t start = 0;
            uint64_t stop = 0;
            unsigned int cidStart = 0;
            unsigned int cidStop = 0;
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                SHA256(m1, mBLen, digest1);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
            } while (cidStart != cidStop);
            assert(start < stop);
            lap1[n] = stop - start;

            //Self-made SHA-256
            uint8_t digest2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(digest2));
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                Sha256(digest2, NULL, m2, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
            } while (cidStart != cidStop);
            assert(start < stop);
            lap2[n] = stop - start;

            if (memcmp(digest1, digest2, sizeof(digest1)) != 0) {
                fputs("SHA-256: FAILED\n", stdout);
                exit(EXIT_FAILURE);
            }
        }
        qsort(lap1, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
        qsort(lap2, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
        fprintf(stdout, "%zu , %" PRIu64 " , %" PRIu64 "\n", mBLen,
                lap1[MAX_REPEAT_COUNT / 2], lap2[MAX_REPEAT_COUNT / 2]);
        fflush(stdout);

        FREE_THEN_NULL(lap2);
        FREE_THEN_NULL(lap1);
        FREE_THEN_NULL(m2);
        FREE_THEN_NULL(m1);
    }
    return 0;
}
#endif                          // CHECK_SHA256

// end of file
