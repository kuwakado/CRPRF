/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include <openssl/hmac.h>

#include "sha256cf.h"
#include "hmac.h"
#include "khc1.h"
#include "khc2.h"
#include "macro.h"


// Use in qsort() for ascending order
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


void CrPrfBenchmark(const size_t maxMassageByteLength,
                    const size_t stepByte, const size_t repeatCount)
{
    assert(stepByte > 0 && repeatCount > 0 && repeatCount % 2 == 1);

    uint64_t *lap1 = calloc(repeatCount, sizeof(uint64_t));
    uint64_t *lap2 = calloc(repeatCount, sizeof(uint64_t));
    uint64_t *lap3 = calloc(repeatCount, sizeof(uint64_t));
    uint64_t *lap4 = calloc(repeatCount, sizeof(uint64_t));
    assert(lap1 != NULL && lap2 != NULL && lap3 != NULL && lap4 != NULL);

    uint8_t key1[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
    uint8_t key2[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
    uint8_t key3[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
    uint8_t key4[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
    const size_t keyByteLength = SHA256_CHAIN_SIZE_IN_BYTES;

    uint8_t tag1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
    uint8_t tag2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
    uint8_t tag3[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
    uint8_t tag4[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
    unsigned int tagByteLength = SHA256_HASH_SIZE_IN_BYTES;

    fputs("Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2\n", stdout);
    fflush(stdout);
    for (size_t mBLen = 0; mBLen <= maxMassageByteLength;
         mBLen += stepByte) {
        uint8_t *m1 = NULL;
        uint8_t *m2 = NULL;
        uint8_t *m3 = NULL;
        uint8_t *m4 = NULL;
        if (mBLen != 0) {
            m1 = calloc(mBLen, sizeof(uint8_t));
            m2 = calloc(mBLen, sizeof(uint8_t));
            m3 = calloc(mBLen, sizeof(uint8_t));
            m4 = calloc(mBLen, sizeof(uint8_t));
            assert(m1 != NULL && m2 != NULL && m3 != NULL && m4 != NULL);
        }

        for (volatile size_t c = 0; c < repeatCount; ++c) {
            // Choose a key at random.
            assert(key1 != NULL);
            for (size_t i = 0; i < NELMS(key1); ++i) {
                key1[i] = rand8();
            }
            assert(key2 != NULL && key3 != NULL && key4 != NULL);
            memcpy(key2, key1, sizeof(key2));
            memcpy(key3, key1, sizeof(key3));
            memcpy(key4, key1, sizeof(key4));

            // Choose a message at random.
            if (m1 != NULL && m2 != NULL && m3 != NULL && m4 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                memcpy(m2, m1, mBLen);
                memcpy(m3, m1, mBLen);
                memcpy(m4, m1, mBLen);
            }
            // timestamp counters at start/ stop
            uint64_t start = 0;
            uint64_t stop = 0;
            // Read the timestamp from the same core as the first timestamp.
            unsigned int cidStart = 0;
            unsigned int cidStop = 0;
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                HMAC(EVP_sha256(), key1, keyByteLength, m1, mBLen, tag1,
                     &tagByteLength);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
                if (cidStart != cidStop) {
                    fprintf(stderr,
                            "OpenSSL HMAC: different core %u %u\n",
                            cidStart, cidStop);
                    fprintf(stderr, "%" PRIu64 "\n", start);
                    fprintf(stderr, "%" PRIu64 "\n", stop);
                }
            } while (cidStart != cidStop);
            assert(start < stop);
            lap1[c] = stop - start;

            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                Hmac(tag2, key2, keyByteLength, m2, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
                if (cidStart != cidStop) {
                    fprintf(stderr,
                            "HMAC: different core %u %u\n",
                            cidStart, cidStop);
                    fprintf(stderr, "%" PRIu64 "\n", start);
                    fprintf(stderr, "%" PRIu64 "\n", stop);
                }
            } while (cidStart != cidStop);
            assert(start < stop);
            lap2[c] = stop - start;
            
            if (false) {
                // Check the results of HMAC.
                if (memcmp(tag1, tag2, sizeof(tag1)) != 0) {
                    fputs("HMAC FAILED\n", stdout);
                    exit(EXIT_FAILURE);
                }
            }

            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                KHC1(tag3, key3, keyByteLength, m3, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
                if (cidStart != cidStop) {
                    fprintf(stderr,
                            "HKC1: different core %u %u\n",
                            cidStart, cidStop);
                    fprintf(stderr, "%" PRIu64 "\n", start);
                    fprintf(stderr, "%" PRIu64 "\n", stop);
                }
            } while (cidStart != cidStop);
            assert(start < stop);
            lap3[c] = stop - start;

            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                KHC2(tag4, key4, keyByteLength, m4, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
                if (cidStart != cidStop) {
                    fprintf(stderr,
                            "HKC2: different core %u %u\n",
                            cidStart, cidStop);
                    fprintf(stderr, "%" PRIu64 "\n", start);
                    fprintf(stderr, "%" PRIu64 "\n", stop);
                }
            } while (cidStart != cidStop);
            assert(start < stop);
            lap4[c] = stop - start;
        }

        // Use qsort() to find the median.
        //
        // To Do: Chapter 9 of the book (*) by Cormen et al. presents a
        // linear-time randomized algorithm for finding the median. But to be
        // linear in time, all the element must be distinct. Arrays lapN[] do
        // not satisfy this assumption, so what is the time complexity? Even if
        // I implemented the algorithm, I do not think it would be able to beat
        // qsort() in terms of time or memory.
        //
        // (*)  T. H. Cormen, C. E. Leiserson, R. L. Rivest, and C. Stein,
        // Introduction to Algorithms, fourth edition, MIT Press, 2022.
        qsort(lap1, repeatCount, sizeof(uint64_t), ascendingOrder);
        qsort(lap2, repeatCount, sizeof(uint64_t), ascendingOrder);
        qsort(lap3, repeatCount, sizeof(uint64_t), ascendingOrder);
        qsort(lap4, repeatCount, sizeof(uint64_t), ascendingOrder);
        fprintf(stdout,
                "%zu , %" PRIu64 " , %" PRIu64 " , %" PRIu64 " , %" PRIu64
                "\n", mBLen, lap1[repeatCount / 2], lap2[repeatCount / 2],
                lap3[repeatCount / 2], lap4[repeatCount / 2]);
        fflush(stdout);

        FREE_THEN_NULL(m4);
        FREE_THEN_NULL(m3);
        FREE_THEN_NULL(m2);
        FREE_THEN_NULL(m1);
    }
    FREE_THEN_NULL(lap4);
    FREE_THEN_NULL(lap3);
    FREE_THEN_NULL(lap2);
    FREE_THEN_NULL(lap1);
}

//  end of file
