/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

#include "sha256cf.h"
#include "macro.h"

// To avoid having to worry about endianness, all 32 bytes (256 bits) are set to
// the same value. The bit length of the constant is 256 bits (8 words), but
// since the __m128i type is used, a 128-bit (4-word) constant is prepared.
static const uint32_t c0[SHA256_CHAIN_SIZE_IN_WORDS / 2] = {
    0x11111111, 0x11111111, 0x11111111, 0x11111111
};

static const uint32_t c10[SHA256_CHAIN_SIZE_IN_WORDS / 2] = {
    0x22222222, 0x22222222, 0x22222222, 0x22222222
};

static const uint32_t c11[SHA256_CHAIN_SIZE_IN_WORDS / 2] = {
    0x44444444, 0x44444444, 0x44444444, 0x44444444
};

static const uint32_t c010[SHA256_CHAIN_SIZE_IN_WORDS / 2] = {
    // c0[0] ^ c10[0], c0[1] ^ c10[1], c0[2] ^ c10[2], c0[3] ^ c10[3],
    0x11111111 ^ 0x22222222, 0x11111111 ^ 0x22222222,
    0x11111111 ^ 0x22222222, 0x11111111 ^ 0x22222222
};

static const uint32_t c011[SHA256_CHAIN_SIZE_IN_WORDS / 2] = {
    // c0[0] ^ c11[0], c0[1] ^ c11[1], c0[2] ^ c11[2], c0[3] ^ c11[3],
    0x11111111 ^ 0x44444444, 0x11111111 ^ 0x44444444,
    0x11111111 ^ 0x44444444, 0x11111111 ^ 0x44444444
};



static void KHC2NoPaddingMessageBlocks(uint8_t
                                       tag[SHA256_HASH_SIZE_IN_BYTES],
                                       uint8_t *const key,
                                       const size_t keyByteLength,
                                       uint8_t *const message,
                                       const size_t messageByteLength)
{
    assert(tag != NULL);
    assert(key != NULL);
    // Assumption of this implementation
    assert(keyByteLength == SHA256_CHAIN_SIZE_IN_BYTES);
    assert(message != NULL);
    assert(messageByteLength >= 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
    assert(messageByteLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES == 0);
    assert((message != NULL)
           && (messageByteLength >= 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES)
           && (messageByteLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES ==
               0));

    Sha256Context c = { 0x00, };
    const size_t m =
        messageByteLength / SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

    // Convert the little-endian key to a big-endian key.
    __m128i *const keymm = (__m128i *const) key;
    const __m128i toBig =
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    keymm[0] = _mm_shuffle_epi8(_mm_loadu_si128(keymm + 0), toBig);
    keymm[1] = _mm_shuffle_epi8(_mm_loadu_si128(keymm + 1), toBig);
    // The IV of SHA-256 is an array of 32-bit words.
    uint32_t *const key32 = (uint32_t *const) key;
    // The order of 32-bit IVs is somewhat odd due to SHA-NI.
    c.h0145 = _mm_set_epi32(key32[0], key32[1], key32[4], key32[5]);
    c.h2367 = _mm_set_epi32(key32[2], key32[3], key32[6], key32[7]);

    // The first block
    c.remMessage = message;
    c.remMessageByteLength = messageByteLength;
    Sha256CompressionFunction(&c);
    c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

    if (m > 2) {
        // Xor the result with the constant c_0.
        c.h0145 = _mm_xor_si128(c.h0145, *(const __m128i *const) c0);
        c.h2367 = _mm_xor_si128(c.h2367, *(const __m128i *const) c0);

        for (size_t i = 2; i <= m - 1; ++i) {
            Sha256CompressionFunction(&c);
            c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
            c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        }

        // Xor the result with the constant c_{1,0}.
        c.h0145 = _mm_xor_si128(c.h0145, *(const __m128i *const) c10);
        c.h2367 = _mm_xor_si128(c.h2367, *(const __m128i *const) c10);
    } else {
        // When there are no loops, the number of XORs can be reduced by using
        // precomputed results (i.e., c010 = c0 ^ c10).
        assert(m == 2);
        c.h0145 = _mm_xor_si128(c.h0145, *(const __m128i *const) c010);
        c.h2367 = _mm_xor_si128(c.h2367, *(const __m128i *const) c010);
    }

    // The last block
    Sha256CompressionFunction(&c);
    c.remMessage = NULL;
    c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    assert(c.remMessageByteLength == 0);

    // Convert the tag to a uint8_t-type array.
    // h0:h1:h4:h5, h2:h3:h6:h7 -> h0:h1:h2:h3, h4:h5:h6:h7
    __m128i h0123 = _mm_unpackhi_epi64(c.h2367, c.h0145);
    __m128i h4567 = _mm_unpacklo_epi64(c.h2367, c.h0145);
    // Convert big endian to little endian.
    const __m128i toLittle =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    h0123 = _mm_shuffle_epi8(h0123, toLittle);
    h4567 = _mm_shuffle_epi8(h4567, toLittle);
    __m128i *const tagmm = (__m128i *const) tag;
    _mm_storeu_si128(tagmm + 0, h0123);
    _mm_storeu_si128(tagmm + 1, h4567);
}


static void KHC2PaddingMessageBlocks(uint8_t
                                     tag[SHA256_HASH_SIZE_IN_BYTES],
                                     uint8_t *key,
                                     const size_t keyByteLength,
                                     uint8_t *message,
                                     const size_t messageByteLength)
{
    assert(tag != NULL);
    assert(key != NULL);
    // Assumption of this implementation
    assert(keyByteLength == SHA256_CHAIN_SIZE_IN_BYTES);
    assert((message == NULL && messageByteLength == 0) ||
           (messageByteLength < 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES ||
            messageByteLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES != 0));

    Sha256Context c = { 0x00, };

    // Convert the little-endian key to a big-endian key.
    __m128i *const keymm = (__m128i *const) key;
    const __m128i toBig =
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    keymm[0] = _mm_shuffle_epi8(_mm_loadu_si128(keymm + 0), toBig);
    keymm[1] = _mm_shuffle_epi8(_mm_loadu_si128(keymm + 1), toBig);
    // The IV of SHA-256 is an array of 32-bit words.
    uint32_t *const key32 = (uint32_t *const) key;
    // The order of 32-bit IVs is somewhat odd due to SHA-NI.
    c.h0145 = _mm_set_epi32(key32[0], key32[1], key32[4], key32[5]);
    c.h2367 = _mm_set_epi32(key32[2], key32[3], key32[6], key32[7]);

    if (messageByteLength == 0) {
        uint8_t mbs[2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] =
            { 0x80, 0x00, };
        assert(IS_16_BYTE_ALIGNED(mbs));
        c.remMessage = mbs;
        c.remMessageByteLength = 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        // The first block
        Sha256CompressionFunction(&c);
        c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        // c011 = c_{0} ^ c_{1,1}
        c.h0145 = _mm_xor_si128(c.h0145, *(__m128i *const) c011);
        c.h2367 = _mm_xor_si128(c.h2367, *(__m128i *const) c011);
        // The last block
        Sha256CompressionFunction(&c);
        c.remMessage = NULL;
        c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        assert(c.remMessageByteLength == 0);
    } else if (messageByteLength <=
               2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES - 1) {
        // Produce a padded message block.
        uint8_t mbs[2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00, };
        assert(IS_16_BYTE_ALIGNED(mbs));
        memcpy(mbs, message, messageByteLength);
        mbs[messageByteLength] = 0x80;
        c.remMessage = mbs;
        c.remMessageByteLength = 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        // the first padded message block
        Sha256CompressionFunction(&c);
        c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        // c011 = c_{0} ^ c_{1,1}
        c.h0145 = _mm_xor_si128(c.h0145, *(__m128i *const) c011);
        c.h2367 = _mm_xor_si128(c.h2367, *(__m128i *const) c011);
        // The last padded message block
        Sha256CompressionFunction(&c);
        c.remMessage = NULL;
        c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        assert(c.remMessageByteLength == 0);
    } else {
        c.remMessage = message;
        c.remMessageByteLength = messageByteLength;
        // the first message block
        Sha256CompressionFunction(&c);
        c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        // XOR with the constant c_{0}.
        c.h0145 = _mm_xor_si128(c.h0145, *(__m128i *const) c0);
        c.h2367 = _mm_xor_si128(c.h2367, *(__m128i *const) c0);
        while (c.remMessageByteLength >=
               SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES) {
            Sha256CompressionFunction(&c);
            c.remMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
            c.remMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        }
        assert(1 <= c.remMessageByteLength
               && c.remMessageByteLength <=
               SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
        c.h0145 = _mm_xor_si128(c.h0145, *(__m128i *const) c11);
        c.h2367 = _mm_xor_si128(c.h2367, *(__m128i *const) c11);
        // the last padded message block
        uint8_t mb[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00, };
        assert(IS_16_BYTE_ALIGNED(mb));
        memcpy(mb, c.remMessage, c.remMessageByteLength);
        mb[c.remMessageByteLength] = 0x80;
        c.remMessage = mb;
        Sha256CompressionFunction(&c);
        c.remMessage = NULL;
        c.remMessageByteLength = 0;
    }

    // Convert the tag to a uint8_t-type array.
    // h0:h1:h4:h5, h2:h3:h6:h7 -> h0:h1:h2:h3, h4:h5:h6:h7
    __m128i h0123 = _mm_unpackhi_epi64(c.h2367, c.h0145);
    __m128i h4567 = _mm_unpacklo_epi64(c.h2367, c.h0145);
    // Convert big endian to little endian.
    const __m128i toLittle =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    h0123 = _mm_shuffle_epi8(h0123, toLittle);
    h4567 = _mm_shuffle_epi8(h4567, toLittle);
    __m128i *const tagmm = (__m128i *const) tag;
    _mm_storeu_si128(tagmm + 0, h0123);
    _mm_storeu_si128(tagmm + 1, h4567);
}

static inline bool isAllBytesEqual(const uint32_t x)
{
    uint8_t a = (x >> 0) & 0xff;
    uint8_t b = (x >> 8) & 0xff;
    uint8_t c = (x >> 16) & 0xff;
    uint8_t d = (x >> 24) & 0xff;
    return (a == b) && (b == c) && (c == d);
}

void KHC2(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES],
          uint8_t *const key, const size_t keyByteLength,
          uint8_t *const message, const size_t messageByteLength)
{
    // assumptions of this implementation
    assert(isAllBytesEqual(c0[0]));
    assert(isAllBytesEqual(c10[0]));
    assert(isAllBytesEqual(c11[0]));
    assert(c0[0] == c0[1] && c0[1] == c0[2] && c0[2] == c0[3]);
    assert(c10[0] == c10[1] && c10[1] == c10[2] && c10[2] == c10[3]);
    assert(c11[0] == c11[1] && c11[1] == c11[2] && c11[2] == c11[3]);
    assert(IS_16_BYTE_ALIGNED(c0));
    assert(IS_16_BYTE_ALIGNED(c10));
    assert(IS_16_BYTE_ALIGNED(c11));
    assert(IS_16_BYTE_ALIGNED(c010));
    assert(IS_16_BYTE_ALIGNED(c011));

    // assumptions of KHC2
    assert(c0[0] != 0x00000000 && c10[0] != 0x00000000
           && c11[0] != 0x00000000);
    assert((c0[0] ^ c10[0]) != 0x00000000 && (c0[0] ^ c11[0]) != 0x00000000
           && (c10[0] ^ c11[0]) != 0x00000000);
    assert((c0[0] ^ c10[0] ^ c11[0]) != 0x00000000);

    // c_{0}, c_{1,0}, and c_{1,1} are distinct each other and are note zero.
    assert(c0[0] != c10[0] && c0[0] != c11[0] && c10[0] != c11[0]);
    assert((c0[0] ^ c10[0]) != 0x00000000);
    assert((c0[0] ^ c11[0]) != 0x00000000);
    assert((c10[0] ^ c11[0]) != 0x00000000);
    assert((c0[0] ^ c10[0] ^ c11[0]) != 0x00000000);

    assert(tag != NULL);
    assert(key != NULL);
    // assumption of this implementation
    assert(keyByteLength == SHA256_CHAIN_SIZE_IN_BYTES);
    assert((message == NULL && messageByteLength == 0) ||
           (message != NULL && messageByteLength > 0));

#ifndef KHC2_MOC
    if (messageByteLength >= 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES &&
        messageByteLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES == 0) {
        KHC2NoPaddingMessageBlocks(tag, key, keyByteLength, message,
                                   messageByteLength);
    } else {
        KHC2PaddingMessageBlocks(tag, key, keyByteLength, message,
                                 messageByteLength);
    }
#endif                          // KHC2_MOC
}


#ifdef CHECK_KHC2
static uint8_t *pad2(size_t *paddedMessageByteLength,
                     const uint8_t *const message,
                     const size_t messageByteLength)
{
    assert(paddedMessageByteLength != NULL);
    assert((message == NULL && messageByteLength == 0) ||
           (message != NULL && messageByteLength > 0));

    assert(SIZE_MAX / 8 >= messageByteLength);
    const size_t messageBitLength = 8 * messageByteLength;
    uint8_t *paddedMessage = NULL;
    if (messageBitLength >= 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BITS &&
        messageBitLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BITS == 0) {
        *paddedMessageByteLength = messageByteLength;
        paddedMessage = calloc(*paddedMessageByteLength, sizeof(uint8_t));
        if (paddedMessage == NULL) {
            perror(NULL);
            EXIT_HERE();
        }
        memcpy(paddedMessage, message,
               (*paddedMessageByteLength) * sizeof(uint8_t));
    } else {
        // In this implementation, the message is assumed to be a byte sequence,
        // so d is an integer such that the bit length of 1|0^d is a multiple of
        // 8. In other words, d satisfies d = 7 mod 8. Therefore, there exists
        // an integer t such that d=8*t+7, so if the bit length of the message
        // is denoted by z, then it holds that z+1+(8*t+7)=0 mod 512, where 512
        // is the bit length of the SHA-256 message block.
        const size_t z =
            messageBitLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BITS;
        // Because the message is assumed to be a byte sequence.
        assert(z <= SHA256_MESSAGE_BLOCK_SIZE_IN_BITS - 8);
        assert((SHA256_MESSAGE_BLOCK_SIZE_IN_BITS - (z + 8)) % 8 == 0);
        const size_t t = (SHA256_MESSAGE_BLOCK_SIZE_IN_BITS - (z + 8)) / 8;
        const size_t d = 8 * t + 7;
        const size_t padByteLength = (1 + d) / 8;
        assert((1 + d) % 8 == 0);
        *paddedMessageByteLength = messageByteLength + padByteLength;
        assert(0 < *paddedMessageByteLength && (*paddedMessageByteLength) %
               SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES == 0);
        if (*paddedMessageByteLength <
            2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES) {
            *paddedMessageByteLength += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        }
        if (false) {
            fprintf(stdout, "paddedMessageByteLength %zu\n",
                    *paddedMessageByteLength);
            PRINT_HERE();
        }
        paddedMessage = calloc(*paddedMessageByteLength, sizeof(uint8_t));
        if (paddedMessage == NULL) {
            perror(NULL);
            EXIT_HERE();
        }
        memcpy(paddedMessage, message, messageByteLength);
        paddedMessage[messageByteLength] = 0x80;
        // The remaining elements have been initialized to 0 thanks to calloc().
    }
    return paddedMessage;
}

static uint32_t *xorChain(uint32_t *inout, const uint32_t *const mask)
{
    // assumption of this implementation
    assert(mask[0] == mask[1] && mask[0] == mask[2] && mask[0] == mask[3]);
    for (size_t i = 0; i < SHA256_CHAIN_SIZE_IN_WORDS; ++i) {
        inout[i] ^= mask[0];
    }
    return inout;
}

static void KHC2Ref(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES],
                    uint8_t *key, const size_t keyByteLength,
                    uint8_t *message, const size_t messageByteLength)
{
    // assumptions of this implementation
    assert(isAllBytesEqual(c0[0]));
    assert(isAllBytesEqual(c10[0]));
    assert(isAllBytesEqual(c11[0]));
    assert(c0[0] == c0[1] && c0[1] == c0[2] && c0[2] == c0[3]);
    assert(c10[0] == c10[1] && c10[1] == c10[2] && c10[2] == c10[3]);
    assert(c11[0] == c11[1] && c11[1] == c11[2] && c11[2] == c11[3]);

    // Assumptions of KHC2
    assert(c0[0] != 0x00000000 && c10[0] != 0x00000000
           && c11[0] != 0x00000000);
    assert((c0[0] ^ c10[0]) != 0x00000000 && (c0[0] ^ c11[0]) != 0x00000000
           && (c10[0] ^ c11[0]) != 0x00000000);
    assert((c0[0] ^ c10[0] ^ c11[0]) != 0x00000000);

    assert(tag != NULL);
    assert(key != NULL);
    assert(keyByteLength == SHA256_CHAIN_SIZE_IN_BYTES);
    assert((message == NULL && messageByteLength == 0) ||
           (message != NULL && messageByteLength > 0));

    uint32_t inout[SHA256_CHAIN_SIZE_IN_WORDS] = { 0x00, };
    // little endian -> big endian
    for (int i = 0; i < SHA256_CHAIN_SIZE_IN_WORDS; ++i) {
        inout[i] = ((uint32_t) key[4 * i + 0]) << 24 |
            ((uint32_t) key[4 * i + 1]) << 16 |
            ((uint32_t) key[4 * i + 2]) << 8 |
            ((uint32_t) key[4 * i + 3]) << 0;
    }

    // Pad the message.
    size_t paddedMessageByteLength = 0;
    uint8_t *paddedMessage =
        pad2(&paddedMessageByteLength, message, messageByteLength);
    assert(paddedMessage != NULL);
    assert(paddedMessageByteLength != 0);
    uint8_t *origPaddedMessage = paddedMessage;
    if (false) {
        fputs("padded M ", stdout);
        for (size_t i = 0; i < paddedMessageByteLength; ++i) {
            fprintf(stdout, "%02x", paddedMessage[i]);
        }
        fputc('\n', stdout);
        fprintf(stdout, "padded M BLen %zu\n", paddedMessageByteLength);
        PRINT_HERE();
    }
    // Use the same symbol standing for the compression function.
    uint32_t *(*F)(uint32_t *, const uint8_t *) =
        Sha256CompressionFunctionRef;
    const size_t m =
        paddedMessageByteLength / SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;

    xorChain(F(inout, paddedMessage), c0);
    paddedMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    paddedMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    for (size_t i = 2; i <= m - 1; ++i) {
        F(inout, paddedMessage);
        paddedMessage += SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
        paddedMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    }
    assert(SIZE_MAX / 8 >= messageByteLength);
    const size_t messageBitLength = 8 * messageByteLength;
    if (messageBitLength >= 2 * SHA256_MESSAGE_BLOCK_SIZE_IN_BITS &&
        messageBitLength % SHA256_MESSAGE_BLOCK_SIZE_IN_BITS == 0) {
        xorChain(inout, c10);
    } else {
        xorChain(inout, c11);
    }
    if (false) {
        fputs("last padded M ", stdout);
        for (size_t i = 0; i < SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES; ++i) {
            fprintf(stdout, "%02x", paddedMessage[i]);
        }
        fputc('\n', stdout);
        PRINT_HERE();
    }
    F(inout, paddedMessage);
    paddedMessage = NULL;
    paddedMessageByteLength -= SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES;
    assert(paddedMessageByteLength == 0);
    FREE_THEN_NULL(origPaddedMessage);

    // big-endian word -> bytes
    for (int i = 0; i < SHA256_CHAIN_SIZE_IN_WORDS; ++i) {
        tag[4 * i + 0] = (inout[i] >> 24) & 0xff;
        tag[4 * i + 1] = (inout[i] >> 16) & 0xff;
        tag[4 * i + 2] = (inout[i] >> 8) & 0xff;
        tag[4 * i + 3] = (inout[i] >> 0) & 0xff;
        assert(4 * i + 3 < SHA256_HASH_SIZE_IN_BYTES);
    }
}


int main(int argc, char *argv[])
{
    enum {
        // The bit length of a key is fixed to be 256 bits.
        KEY_BYTE_LENGTH = SHA256_CHAIN_SIZE_IN_BYTES,
        // 5 message blocks = 5 * 512 bits = 320 bytes
        MAX_MESSAGE_BYTE_LENGTH = 320,
        MAX_REPEAT_COUNT = 1 + 1024 * 4
    };

    for (size_t mBLen = 0; mBLen <= MAX_MESSAGE_BYTE_LENGTH; ++mBLen) {
        if (false) {
            fprintf(stdout, "mBLen %zu\n", mBLen);
            PRINT_HERE();
        }
        uint8_t *m1 = NULL;
        uint8_t *m2 = NULL;
        if (mBLen != 0) {
            m1 = calloc(mBLen, sizeof(uint8_t));
            m2 = calloc(mBLen, sizeof(uint8_t));
            assert(m1 != NULL && m2 != NULL);
            assert(IS_16_BYTE_ALIGNED(m1) && IS_16_BYTE_ALIGNED(m2));
        }

        for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
            // key
            uint8_t key1[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
            uint8_t key2[SHA256_CHAIN_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(key1) && IS_16_BYTE_ALIGNED(key2));
            for (size_t i = 0; i < NELMS(key1); ++i) {
                key1[i] = rand8();
            }
            assert(sizeof(key1) == sizeof(key2));
            memcpy(key2, key1, sizeof(key2));

            // message
            if (m1 != NULL && m2 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                memcpy(m2, m1, mBLen);
            }

            // Reference implementation
            uint8_t tag1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag1));
            assert((m1 == NULL && mBLen == 0)
                   || (m1 != NULL && mBLen > 0));
            KHC2Ref(tag1, key1, sizeof(key1), m1, mBLen);

            // Optimized implementation
            uint8_t tag2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag2));
            KHC2(tag2, key2, sizeof(key2), m2, mBLen);

            // Compare them.
            if (memcmp(tag1, tag2, SHA256_HASH_SIZE_IN_BYTES) == 0) {
                continue;
            } else {
                fputs("KHC2-SHA-256: FAILED\n", stdout);
                if (false) {
                    fputs("tag1 ", stdout);
                    for (int i = 0; i < SHA256_HASH_SIZE_IN_BYTES; ++i) {
                        fprintf(stdout, "%02x", tag1[i]);
                    }
                    fputc('\n', stdout);
                    fputs("tag2 ", stdout);
                    for (int i = 0; i < SHA256_HASH_SIZE_IN_BYTES; ++i) {
                        fprintf(stdout, "%02x", tag2[i]);
                    }
                    fputc('\n', stdout);
                    PRINT_HERE();
                }
                exit(EXIT_FAILURE);
            }
        }

        FREE_THEN_NULL(m2);
        FREE_THEN_NULL(m1);
    }
    fputs("KHC2-SHA-256: PASS\n", stdout);

    return 0;
}
#endif                          // CHECK_KHC2

#ifdef BENCH_KHC2
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
        // The bit length of a key is fixed to be 256 bits.
        KEY_BYTE_LENGTH = SHA256_CHAIN_SIZE_IN_BYTES,
        // 4 message blocks = 4 * 512 bits = 2,048 bits = 256 bytes
        MAX_MESSAGE_BYTE_LENGTH = 256,
        MAX_REPEAT_COUNT = 1 + 1024 * 64
    };

    for (size_t mBLen = 0; mBLen <= MAX_MESSAGE_BYTE_LENGTH; ++mBLen) {
        uint8_t *m = NULL;
        if (mBLen != 0) {
            m = calloc(mBLen, sizeof(uint8_t));
            assert(m != NULL);
            assert(IS_16_BYTE_ALIGNED(m));
        }
        uint64_t *lap = calloc(MAX_REPEAT_COUNT, sizeof(uint64_t));
        if (lap == NULL) {
            perror(NULL);
            EXIT_HERE();
        }

        for (volatile int n = 0; n < MAX_REPEAT_COUNT; ++n) {
            // key
            uint8_t key[KEY_BYTE_LENGTH] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(key));
            for (size_t i = 0; i < NELMS(key); ++i) {
                key[i] = rand8();
            }
            // message
            if (m != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m[i] = rand8();
                }
            }

            // optimized implementation
            uint8_t tag[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag));
            uint64_t start = 0;
            uint64_t stop = 0;
            unsigned int cidStart = 0;
            unsigned int cidStop = 0;
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                KHC2(tag, key, sizeof(key), m, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
            } while (cidStart != cidStop);
            assert(start < stop);
            lap[n] = stop - start;
        }
        qsort(lap, MAX_REPEAT_COUNT, sizeof(uint64_t), ascendingOrder);
        fprintf(stdout, "%zu , %" PRIu64 "\n", mBLen,
                lap[MAX_REPEAT_COUNT / 2]);

        FREE_THEN_NULL(lap);
        FREE_THEN_NULL(m);
    }

    return 0;
}
#endif                          // BENCH_KHC2

// end of file
