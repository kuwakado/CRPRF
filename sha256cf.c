/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <x86intrin.h>

#include "sha256cf.h"
#include "macro.h"


// SHA-256 compression function using SHA-NI
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
// https://www.officedaytime.com/simd512/simdimg/sha256.html
// https://en.wikipedia.org/wiki/Intel_SHA_extensions
void Sha256CompressionFunction(Sha256Context *const c)
{
    assert(c != NULL);

#ifndef SHA256CF_MOC
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    assert(IS_16_BYTE_ALIGNED(K));

    // 128 bits x 16 = 64 x 32 bits
    const __m128i *const Kmm = (const __m128i *const) K;
    if (false) {
        for (size_t i = 0; i < sizeof(K) / (4 * sizeof(uint32_t)); ++i) {
            printLnXmm(Kmm + i);
        }
        EXIT_HERE();
    }
    // message block: 512 bits = 4 x 128 bits = 64 x 8 bits
    __m128i *const wmm = (__m128i *const) (c->remMessage);
#if 1
    // Convert little endian to big endian. (x86_64 CPU: little endian)
    // According to Section 3.1 in FIPS PUB 180, the big-endian convention is
    // used when expressing a 32-bit word.
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    const __m128i toBig =
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    // wmm0 = w3 | w2 | w1 | w0
    __m128i wmm0 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 0), toBig);
    // wmm1 = w7 | w6 | w5 | w4
    __m128i wmm1 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 1), toBig);
    // wmm2 = w11 | w10 | w9 | w8
    __m128i wmm2 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 2), toBig);
    // wmm3 = w15 | w14 | w13 | w12
    __m128i wmm3 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 3), toBig);
#else
    // The following code is equivalent to the code above.
    // Convert little endian to big endian. (x86_64 CPU: little endian)
    static const uint8_t toBig[16] = {
        0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
        0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
    };
    assert(IS_16_BYTE_ALIGNED(toBig));
    // wmm0 = w3 | w2 | w1 | w0
    __m128i wmm0 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 0),
                                    *(const __m128i *const) toBig);
    // wmm1 = w7 | w6 | w5 | w4
    __m128i wmm1 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 1),
                                    *(const __m128i *const) toBig);
    // wmm2 = w11 | w10 | w9 | w8
    __m128i wmm2 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 2),
                                    *(const __m128i *const) toBig);
    // wmm3 = w15 | w14 | w13 | w12
    __m128i wmm3 = _mm_shuffle_epi8(_mm_loadu_si128(wmm + 3),
                                    *(const __m128i *const) toBig);
#endif
    if (false) {
        printLnXmm2(&wmm0, &wmm1);
        printLnXmm2(&wmm2, &wmm3);
        EXIT_HERE();
    }
    // Save the state at start.
    __m128i state1 = c->h0145;
    __m128i state2 = c->h2367;

    // round 0-3
    __m128i tmp = _mm_add_epi32(wmm0, Kmm[0]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 4-7
    tmp = _mm_add_epi32(wmm1, Kmm[1]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 8-11
    tmp = _mm_add_epi32(wmm2, Kmm[2]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 12-15
    tmp = _mm_add_epi32(wmm3, Kmm[3]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 16-19
    // wmm0 = w3+s0(w4) | w2+s0(w3) | w1+s0(w2) | w0+s0(w1)
    // That is, w7, w6, and w5 in wmm1 are not used.
    wmm0 = _mm_sha256msg1_epu32(wmm0, wmm1);
    // Since wmm3 = w15 | w14 | w13 | w12, wmm2 = w11 | w10 | w9 | w8,
    // _mm_alignr_epi8() produces w12 | w11 | w10 | w9.
    // wmm0 = w12+w3+s0(w4) | w11+w2+s0(w3) | w10+w1+s0(w2) | w9+w0+s0(w1).
    wmm0 = _mm_add_epi32(wmm0, _mm_alignr_epi8(wmm3, wmm2, 4));
    // wmm0 = s1(w17)+w12+w3+s0(w4) | s1(w16)+w11+w2+s0(w3) |
    //        s1(w15)+w10+w1+s0(w2) | s1(w14)+w9+w0+s0(w1),
    // That is, w13 and w12 in wmm3 are not used.
    wmm0 = _mm_sha256msg2_epu32(wmm0, wmm3);
    // wmm0 = w19 | w18 | w17 | w16 has been generated.
    tmp = _mm_add_epi32(wmm0, Kmm[4]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 20-23
    // wmm1 = w23 | w22 | w21 | w20
    wmm1 = _mm_sha256msg1_epu32(wmm1, wmm2);
    wmm1 = _mm_add_epi32(wmm1, _mm_alignr_epi8(wmm0, wmm3, 4));
    wmm1 = _mm_sha256msg2_epu32(wmm1, wmm0);
    tmp = _mm_add_epi32(wmm1, Kmm[5]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 24-27
    // wmm2 = w27 | w26 | w25 | w24
    wmm2 = _mm_sha256msg1_epu32(wmm2, wmm3);
    wmm2 = _mm_add_epi32(wmm2, _mm_alignr_epi8(wmm1, wmm0, 4));
    wmm2 = _mm_sha256msg2_epu32(wmm2, wmm1);
    tmp = _mm_add_epi32(wmm2, Kmm[6]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 28-31
    // wmm3 = w31 | w30 | w29 | w28
    wmm3 = _mm_sha256msg1_epu32(wmm3, wmm0);
    wmm3 = _mm_add_epi32(wmm3, _mm_alignr_epi8(wmm2, wmm1, 4));
    wmm3 = _mm_sha256msg2_epu32(wmm3, wmm2);
    tmp = _mm_add_epi32(wmm3, Kmm[7]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 32-35
    // wmm0 = w35 | w34 | w33 | w32
    wmm0 = _mm_sha256msg1_epu32(wmm0, wmm1);
    wmm0 = _mm_add_epi32(wmm0, _mm_alignr_epi8(wmm3, wmm2, 4));
    wmm0 = _mm_sha256msg2_epu32(wmm0, wmm3);
    tmp = _mm_add_epi32(wmm0, Kmm[8]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 36-39
    // wmm1 = w39 | w38 | w37 | w36
    wmm1 = _mm_sha256msg1_epu32(wmm1, wmm2);
    wmm1 = _mm_add_epi32(wmm1, _mm_alignr_epi8(wmm0, wmm3, 4));
    wmm1 = _mm_sha256msg2_epu32(wmm1, wmm0);
    tmp = _mm_add_epi32(wmm1, Kmm[9]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 40-43
    // wmm2 = w43 | w42 | w41 | w40
    wmm2 = _mm_sha256msg1_epu32(wmm2, wmm3);
    wmm2 = _mm_add_epi32(wmm2, _mm_alignr_epi8(wmm1, wmm0, 4));
    wmm2 = _mm_sha256msg2_epu32(wmm2, wmm1);
    tmp = _mm_add_epi32(wmm2, Kmm[10]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 44-47
    // wmm3 = w47 | w46 | w45 | w44
    wmm3 = _mm_sha256msg1_epu32(wmm3, wmm0);
    wmm3 = _mm_add_epi32(wmm3, _mm_alignr_epi8(wmm2, wmm1, 4));
    wmm3 = _mm_sha256msg2_epu32(wmm3, wmm2);
    tmp = _mm_add_epi32(wmm3, Kmm[11]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 48-51
    // wmm0 = w51 | w50 | w49 | w48
    wmm0 = _mm_sha256msg1_epu32(wmm0, wmm1);
    wmm0 = _mm_add_epi32(wmm0, _mm_alignr_epi8(wmm3, wmm2, 4));
    wmm0 = _mm_sha256msg2_epu32(wmm0, wmm3);
    tmp = _mm_add_epi32(wmm0, Kmm[12]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 52-55
    // wmm1 = w55 | w54 | w53 | w52
    wmm1 = _mm_sha256msg1_epu32(wmm1, wmm2);
    wmm1 = _mm_add_epi32(wmm1, _mm_alignr_epi8(wmm0, wmm3, 4));
    wmm1 = _mm_sha256msg2_epu32(wmm1, wmm0);
    tmp = _mm_add_epi32(wmm1, Kmm[13]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 56-59
    // wmm2 = w59 | w58 | w57 | w56
    wmm2 = _mm_sha256msg1_epu32(wmm2, wmm3);
    wmm2 = _mm_add_epi32(wmm2, _mm_alignr_epi8(wmm1, wmm0, 4));
    wmm2 = _mm_sha256msg2_epu32(wmm2, wmm1);
    tmp = _mm_add_epi32(wmm2, Kmm[14]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // round 60-63
    // wmm3 = w63 | w62 | w61 | w60
    wmm3 = _mm_sha256msg1_epu32(wmm3, wmm0);
    wmm3 = _mm_add_epi32(wmm3, _mm_alignr_epi8(wmm2, wmm1, 4));
    wmm3 = _mm_sha256msg2_epu32(wmm3, wmm2);
    tmp = _mm_add_epi32(wmm3, Kmm[15]);
    state2 = _mm_sha256rnds2_epu32(state2, state1, tmp);
    tmp = _mm_unpackhi_epi64(tmp, tmp);
    state1 = _mm_sha256rnds2_epu32(state1, state2, tmp);
    if (false) {
        swapPrintLnXmm2(&state1, &state2);
        EXIT_HERE();
    }
    // Add to the starting state. (Not XOR)
    c->h0145 = _mm_add_epi32(state1, c->h0145);
    c->h2367 = _mm_add_epi32(state2, c->h2367);
    if (false) {
        swapPrintLnXmm2(&c->h0145, &c->h2367);
        EXIT_HERE();
    }
#endif                          // SHA256CF_MOC
}


// SHA-256 sub functions
// CH(x, y, z) = (x AND y) XOR ((NOT x) AND z)
static inline uint32_t Ch(const uint32_t x, const uint32_t y,
                          const uint32_t z)
{
    return (x & y) | ((~x) & z);
}

// MAJ(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
static inline uint32_t Maj(const uint32_t x, const uint32_t y,
                           const uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t shr(const size_t bits, const uint32_t word)
{
    assert(bits <= 32);
    return word >> bits;
}

static inline uint32_t rotl(const size_t bits, const uint32_t word)
{
    assert(bits <= 32);
    return (word << bits) | (word >> (32 - bits));
}

static inline uint32_t rotr(const size_t bits, const uint32_t word)
{
    assert(bits <= 32);
    return (word >> bits) | (word << (32 - bits));
}

static inline uint32_t SIGMA0(const uint32_t word)
{
    return rotr(2, word) ^ rotr(13, word) ^ rotr(22, word);
}

static inline uint32_t SIGMA1(const uint32_t word)
{
    return rotr(6, word) ^ rotr(11, word) ^ rotr(25, word);
}

static inline uint32_t sigma0(const uint32_t word)
{
    return rotr(7, word) ^ rotr(18, word) ^ shr(3, word);
}

static inline uint32_t sigma1(const uint32_t word)
{
    return rotr(17, word) ^ rotr(19, word) ^ shr(10, word);
}


// Ref. RFC6234 https://datatracker.ietf.org/doc/html/rfc6234.html
uint32_t *Sha256CompressionFunctionRef(uint32_t
                                       inout[SHA256_CHAIN_SIZE_IN_WORDS],
                                       const uint8_t
                                       messageBlock
                                       [SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES])
{
    assert(inout != NULL);
    assert(messageBlock != NULL);

    /* Constants defined in FIPS 180-3, section 4.2.2 */
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initialize the first 16 words from 64 bytes.
    uint32_t W[64] = { 0x00 };
    // The byte order is changed from a little endianness to a big endianness.
    for (int t = 0; t < 16; ++t) {
        W[t] = (((uint32_t) messageBlock[4 * t + 0]) << 24) |
            (((uint32_t) messageBlock[4 * t + 1]) << 16) |
            (((uint32_t) messageBlock[4 * t + 2]) << 8) |
            (((uint32_t) messageBlock[4 * t + 3]) << 0);
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    uint32_t A = inout[0];
    uint32_t B = inout[1];
    uint32_t C = inout[2];
    uint32_t D = inout[3];
    uint32_t E = inout[4];
    uint32_t F = inout[5];
    uint32_t G = inout[6];
    uint32_t H = inout[7];

    for (int t = 0; t < 64; ++t) {
        uint32_t temp1 = H + SIGMA1(E) + Ch(E, F, G) + K[t] + W[t];
        uint32_t temp2 = SIGMA0(A) + Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
        if (false) {
            fprintf(stdout,
                    "%2d  %08X %08X %08X %08X %08X %08X %08X %08X\n", t, A,
                    B, C, D, E, F, G, H);
            if (t == 63) {
                EXIT_HERE();
            }
        }
    }

    inout[0] += A;
    inout[1] += B;
    inout[2] += C;
    inout[3] += D;
    inout[4] += E;
    inout[5] += F;
    inout[6] += G;
    inout[7] += H;

    return inout;
}


#ifdef CHECK_SHA256CF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    const uint32_t H[SHA256_CHAIN_SIZE_IN_WORDS] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    assert(IS_16_BYTE_ALIGNED(H));

    if (true) {
        // Test using the first test vector given in
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        uint32_t inout[SHA256_CHAIN_SIZE_IN_WORDS] = { 0x00 };
        assert(sizeof(H) == sizeof(inout));
        memcpy(inout, H, sizeof(inout));

        Sha256Context c = { 0x00 };
        c.h0145 = _mm_set_epi32(H[0], H[1], H[4], H[5]);
        c.h2367 = _mm_set_epi32(H[2], H[3], H[6], H[7]);

        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        uint8_t mb1[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
        assert(IS_16_BYTE_ALIGNED(mb1));
        mb1[0] = 'a';
        mb1[1] = 'b';
        mb1[2] = 'c';
        mb1[3] = 0x80;
        mb1[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES - 1] = 0x18;
        uint8_t mb2[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
        assert(IS_16_BYTE_ALIGNED(mb2));
        memcpy(mb2, mb1, SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
        c.remMessage = mb2;
        c.remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

        Sha256CompressionFunctionRef(inout, mb1);
        Sha256CompressionFunction(&c);

        // Reorder 4 words of in an __m128i value.
        __m128i h0123 = _mm_unpackhi_epi64(c.h2367, c.h0145);
        __m128i h4567 = _mm_unpacklo_epi64(c.h2367, c.h0145);
        uint32_t hc[SHA256_CHAIN_SIZE_IN_WORDS] = { 0x00 };
        assert(IS_16_BYTE_ALIGNED(hc));
        for (int i = 0; i < 4; ++i) {
            hc[i + 0] = ((uint32_t *) &h0123)[3 - i];
            hc[i + 4] = ((uint32_t *) &h4567)[3 - i];
        }

        // True digest:
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        const uint32_t trueDigest[] = {
            0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223,
            0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD,
        };
        assert(IS_16_BYTE_ALIGNED(trueDigest));
        fputs("SHA-256 CF Ref (test vector): ", stdout);
        if (memcmp(inout, trueDigest, sizeof(trueDigest)) == 0) {
            fputs("PASS\n", stdout);
        } else {
            fputs("FAILED\n", stdout);
        }
        fputs("SHA-256 CF (test vector): ", stdout);
        if (memcmp(hc, trueDigest, sizeof(trueDigest)) == 0) {
            fputs("PASS\n", stdout);
        } else {
            fputs("FAILED\n", stdout);
        }
    }

    uint32_t inout[SHA256_CHAIN_SIZE_IN_WORDS] = { 0x00 };
    assert(IS_16_BYTE_ALIGNED(inout));
    assert(sizeof(H) == sizeof(inout));
    memcpy(inout, H, sizeof(inout));

    Sha256Context c = { 0x00, };
    c.h0145 = _mm_set_epi32(H[0], H[1], H[4], H[5]);
    c.h2367 = _mm_set_epi32(H[2], H[3], H[6], H[7]);

    enum {
        MAX_REPEAT_COUNT = 1024 * 1024
    };
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        uint8_t mb1[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
        uint8_t mb2[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
        assert(IS_16_BYTE_ALIGNED(mb1));
        assert(IS_16_BYTE_ALIGNED(mb2));
        for (size_t i = 0; i < SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES; ++i) {
            mb1[i] = rand8();
        }
        memcpy(mb2, mb1, SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
        c.remMessage = mb2;
        c.remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

        Sha256CompressionFunctionRef(inout, mb1);
        Sha256CompressionFunction(&c);

        // Reorder 4 words of in an __m128i value.
        __m128i h0123 = _mm_unpackhi_epi64(c.h2367, c.h0145);
        __m128i h4567 = _mm_unpacklo_epi64(c.h2367, c.h0145);
        uint32_t hc[SHA256_CHAIN_SIZE_IN_WORDS] = { 0x00 };
        for (int i = 0; i < 4; ++i) {
            hc[i + 0] = ((uint32_t *) &h0123)[3 - i];
            hc[i + 4] = ((uint32_t *) &h4567)[3 - i];
        }

        // Compare them.
        if (memcmp(inout, hc, sizeof(hc)) == 0) {
            continue;
        } else {
            fputs("SHA-256 CF: FAILED\n", stdout);
            exit(EXIT_FAILURE);
        }
    }
    fputs("SHA-256 CF: PASS\n", stdout);

    return 0;
}
#endif                          // CHECK_SHA256CF


#ifdef BENCH_SHA256CF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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
    if (lap == NULL) {
        perror(NULL);
        exit(EXIT_FAILURE);
    }

    const uint32_t H[SHA256_CHAIN_SIZE_IN_WORDS] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    assert(IS_16_BYTE_ALIGNED(H));
    Sha256Context c = { 0x00, };
    c.h0145 = _mm_set_epi32(H[0], H[1], H[4], H[5]);
    c.h2367 = _mm_set_epi32(H[2], H[3], H[6], H[7]);
    for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
        // During the iteration, 'c.h0145' and 'c.h2367' are the previous output
        // values.
        uint8_t mb[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
        assert(IS_16_BYTE_ALIGNED(mb));
        for (size_t i = 0; i < SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES; ++i) {
            mb[i] = rand8();
        }
        c.remMessage = mb;
        c.remMessageByteLength = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

        uint64_t start = 0;
        uint64_t stop = 0;
        unsigned int cidStart = 0;
        unsigned int cidStop = 0;
        do {
            _mm_mfence();
            start = __rdtscp(&cidStart);
            Sha256CompressionFunction(&c);
            _mm_mfence();
            stop = __rdtscp(&cidStop);
        } while (cidStart != cidStop);
        assert(start < stop);
        lap[n] = stop - start;

        c.remMessage = NULL;
        c.remMessageByteLength = 0;
    }
    // To find the median, qsort() is used.
    //
    // To Do: Chapter 9 of the book (*) by Cormen et al. presents a linear-time
    // randomized algorithm for finding the median. But to be linear in time,
    // all the element must be distinct. Array lap[] does not satisfy this
    // assumption, so what is the time complexity? Even if I implemented the
    // algorithm, I do not think it would be able to beat qsort() in terms of
    // time or memory.
    //
    // (*)  T. H. Cormen, C. E. Leiserson, R. L. Rivest, and C. Stein,
    // Introduction to Algorithms, fourth edition, MIT Press, 2022.
    qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
    fprintf(stdout,
            "Sha256CompressionFunction ,  %" PRIu64 " , [clocks]\n",
            lap[MAX_REPEAT_COUNT / 2]);
    FREE_THEN_NULL(lap);

    return 0;
}
#endif                          // BENCH_SHA256CF

// end of file
