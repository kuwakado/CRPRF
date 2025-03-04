/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

// Measure the time to perform two 128-bit XOR operations and the overhead time
// for the measurement.

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>


static uint32_t rand32(void)
{
    // Pi
    static uint32_t next = 314159;
    // https://en.wikipedia.org/wiki/Linear_congruential_generator
    // ANSI C: Watcom, Digital Mars, CodeWarrior, IBM VisualAge C/C++ C90, C99,
    // C11: Suggestion in the ISO/IEC 9899, C17
    next = (1103515245 * next + 12345) & 0x7fffffffffffffffUL;
    uint32_t v1 = next;
    next = (1103515245 * next + 12345) & 0x7fffffffffffffffUL;
    uint32_t v2 = next;
    return v1 + v2;
}


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
        MAX_REPEAT_COUNT = 1 + 1024 * 1024 * 32
    };
    uint64_t *lap = calloc(MAX_REPEAT_COUNT, sizeof(uint64_t));
    assert(lap != NULL);

    uint32_t a[4] = { 0x00, };
    uint32_t b[4] = { 0x00, };
    uint32_t c[4] = { 0x00, };
    uint32_t x[4] = { 0x00, };
    uint32_t y[4] = { 0x00, };
    uint32_t z[4] = { 0x00, };
    uint32_t v[4] = { 0x00, };

    // Measure the time of two XORs (+ _mm_lfence).
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        for (int i = 0; i < 4; ++i) {
            a[i] = x[i] = rand32();
            b[i] = y[i] = rand32();
            v[i] = a[i] ^ b[i];
        }
        __m128i *amm = (__m128i *) a;
        __m128i *bmm = (__m128i *) b;
        __m128i *cmm = (__m128i *) c;
        __m128i *xmm = (__m128i *) x;
        __m128i *ymm = (__m128i *) y;
        __m128i *zmm = (__m128i *) z;

        uint64_t start = 0;
        uint64_t stop = 0;
        unsigned int cidStart = 0;
        unsigned int cidStop = 0;
        do {
            _mm_lfence();
            start = __rdtscp(&cidStart);
            *cmm = _mm_xor_si128(*amm, *bmm);
            *zmm = _mm_xor_si128(*xmm, *ymm);
            _mm_lfence();
            stop = __rdtscp(&cidStop);
        } while (cidStart != cidStop);
        assert(start < stop);
        lap[n] = stop - start;
        if (memcmp(v, c, sizeof(v)) == 0 && memcmp(v, z, sizeof(v)) == 0) {
            continue;
        } else {
            fputs("two 128-bit XORs: FAILED\n", stdout);
            exit(EXIT_FAILURE);
        }
    }
    fputs("two 128-bit XORs: PASS\n", stdout);
    qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
    fprintf(stdout, "two 128-bit XORs (+lfence) %" PRIu64 " [clocks]\n",
            lap[MAX_REPEAT_COUNT / 2]);

    // Measure the time of two XORs (+ _mm_mfence).
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        for (int i = 0; i < 4; ++i) {
            a[i] = x[i] = rand32();
            b[i] = y[i] = rand32();
            v[i] = a[i] ^ b[i];
        }
        __m128i *amm = (__m128i *) a;
        __m128i *bmm = (__m128i *) b;
        __m128i *cmm = (__m128i *) c;
        __m128i *xmm = (__m128i *) x;
        __m128i *ymm = (__m128i *) y;
        __m128i *zmm = (__m128i *) z;

        uint64_t start = 0;
        uint64_t stop = 0;
        unsigned int cidStart = 0;
        unsigned int cidStop = 0;
        do {
            _mm_mfence();
            start = __rdtscp(&cidStart);
            *cmm = _mm_xor_si128(*amm, *bmm);
            *zmm = _mm_xor_si128(*xmm, *ymm);
            _mm_mfence();
            stop = __rdtscp(&cidStop);
        } while (cidStart != cidStop);
        assert(start < stop);
        lap[n] = stop - start;
        if (memcmp(v, c, sizeof(v)) == 0 && memcmp(v, z, sizeof(v)) == 0) {
            continue;
        } else {
            fputs("two 128-bit XORs: FAILED\n", stdout);
            exit(EXIT_FAILURE);
        }
    }
    fputs("two 128-bit XORs: PASS\n", stdout);
    qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
    fprintf(stdout, "two 128-bit XORs (+mfence) %" PRIu64 " [clocks]\n",
            lap[MAX_REPEAT_COUNT / 2]);

    // Measure the time of NOP. That is, measure the overhead for using
    // _mm_lfence() and __rdtscp().
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        uint64_t start = 0;
        uint64_t stop = 0;
        unsigned int cidStart = 0;
        unsigned int cidStop = 0;
        do {
            _mm_lfence();
            start = __rdtscp(&cidStart);
            _mm_lfence();
            stop = __rdtscp(&cidStop);
        } while (cidStart != cidStop);
        assert(start < stop);
        lap[n] = stop - start;
    }
    qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
    fprintf(stdout, "NOP (+lfence) %" PRIu64 " [clocks]\n",
            lap[MAX_REPEAT_COUNT / 2]);

    // Measure the time of NOP. That is, measure the overhead for using
    // _mm_mfence() and __rdtscp().
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        uint64_t start = 0;
        uint64_t stop = 0;
        unsigned int cidStart = 0;
        unsigned int cidStop = 0;
        do {
            _mm_mfence();
            start = __rdtscp(&cidStart);
            _mm_mfence();
            stop = __rdtscp(&cidStop);
        } while (cidStart != cidStop);
        assert(start < stop);
        lap[n] = stop - start;
    }
    qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
    fprintf(stdout, "NOP (+mfence) %" PRIu64 " [clocks]\n",
            lap[MAX_REPEAT_COUNT / 2]);

    free(lap);
    lap = NULL;

    return 0;
}

// end of file
