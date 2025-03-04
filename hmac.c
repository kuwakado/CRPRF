/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

#include "sha256cf.h"
#include "sha256.h"
#include "macro.h"


static void HmacShortenKey(uint8_t *key, size_t *keyByteLength)
{
    assert(key != NULL);
    assert(*keyByteLength > SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);

    uint8_t newKey[SHA256_HASH_SIZE_IN_BYTES] = { 0x00 };
    Sha256(newKey, NULL, key, *keyByteLength);
    memcpy(key, newKey, SHA256_HASH_SIZE_IN_BYTES);
    *keyByteLength = SHA256_HASH_SIZE_IN_BYTES;
}


void Hmac(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES],
          uint8_t *key, size_t keyByteLength,
          uint8_t *message, const size_t messageByteLength)
{
    assert(tag != NULL);
    assert(key != NULL);
    assert(keyByteLength > 0);
    assert((message == NULL && messageByteLength == 0) ||
           (message != NULL && messageByteLength != 0));

#ifndef HMAC_MOC
    // Shorten the key so that its length is the same as the hash length.
    if (keyByteLength > SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES) {
        HmacShortenKey(key, &keyByteLength);
    }
    // SHA-256 information
    Sha256Context c = { 0x00 };

    // N*8-bit Key -> (N*8)/128-element array
    __m128i *keymm = (__m128i *) key;
    if (false) {
        for (size_t i = 0; i < keyByteLength; ++i) {
            fprintf(stdout, "%02x", key[i]);
            if (i == keyByteLength - 1) {
                fputc('\n', stdout);
            } else if (i % 4 == 3) {
                fputc(' ', stdout);
            } else {
                // Do nothing.
            }
        }
        EXIT_HERE();
    }
    // Inner part
    // Create an inner key, iKey.
    uint8_t iKey[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00, };
    assert(IS_16_BYTE_ALIGNED(iKey));
    enum { IPAD = 0x36 };
    memset(iKey, IPAD, SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
    assert(keyByteLength == SHA256_HASH_SIZE_IN_BYTES);
    __m128i *const iKeymm = (__m128i *const) iKey;
    iKeymm[0] = _mm_xor_si128(iKeymm[0], keymm[0]);
    iKeymm[1] = _mm_xor_si128(iKeymm[1], keymm[1]);
    assert(sizeof(iKey) == SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
    // Perform the SHA-256 compression function on 'iKey' as the message block.
    Sha256Init(&c, NULL, iKey, sizeof(iKey));
    Sha256Update(&c);
    assert(c.remMessageByteLength == 0);

    // Hash the message using SHA-256.
    c.remMessage = message;
    c.remMessageByteLength = messageByteLength;
    Sha256Update(&c);
    uint8_t innerDigest[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
    assert(IS_16_BYTE_ALIGNED(iKey));
    assert(sizeof(innerDigest) == SHA256_HASH_SIZE_IN_BYTES);
    // The message length is not the length of the given message.
    Sha256Final(innerDigest, &c,
                SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES + messageByteLength);
    if (false) {
        fputs("inner digest  ", stdout);
        printDigest(innerDigest);
        EXIT_HERE();
    }
    // Outer part
    // Create an outer key, oKey.
    uint8_t oKey[SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES] = { 0x00 };
    assert(IS_16_BYTE_ALIGNED(oKey));
    enum { OPAD = 0x5c };
    memset(oKey, OPAD, SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
    assert(keyByteLength == SHA256_HASH_SIZE_IN_BYTES);
    __m128i *oKeymm = (__m128i *) oKey;
    oKeymm[0] = _mm_xor_si128(oKeymm[0], keymm[0]);
    oKeymm[1] = _mm_xor_si128(oKeymm[1], keymm[1]);
    assert(sizeof(oKey) == SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES);
    // Perform the SHA-256 compression function on 'oKey' as the message block.
    Sha256Init(&c, NULL, oKey, sizeof(oKey));
    Sha256Update(&c);
    assert(c.remMessageByteLength == 0);
    // Hash the inner digest using SHA-256.
    c.remMessage = innerDigest;
    c.remMessageByteLength = SHA256_HASH_SIZE_IN_BYTES;
    Sha256Update(&c);
    Sha256Final(tag, &c,
                SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES +
                SHA256_HASH_SIZE_IN_BYTES);
    if (false) {
        fputs("outer digest  ", stdout);
        printDigest(tag);
        EXIT_HERE();
    }
#endif                          // HMAC_MOC
}


#ifdef CHECK_HMAC
#include <openssl/hmac.h>

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
        uint8_t *m1 = NULL;
        uint8_t *m2 = NULL;
        if (mBLen != 0) {
            // The address of a block returned by malloc in GCC is always a
            // multiple of sixteen on 64-bit systems.
            // https://www.gnu.org/software/libc/manual/html_node/Aligned-Memory-Blocks.html
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

            for (int i = 0; i < SHA256_CHAIN_SIZE_IN_BYTES; ++i) {
                key1[i] = rand8();
            }
            memcpy(key2, key1, sizeof(key2));


            // message
            if (m1 != NULL && m2 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                if (m2 != NULL && m1 != NULL) {
                    memcpy(m2, m1, mBLen);
                }
            }
            // OpenSSL HMAC
            uint8_t tag1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag1));
            unsigned int tag1Len = SHA256_HASH_SIZE_IN_BYTES;
            HMAC(EVP_sha256(), key1, SHA256_CHAIN_SIZE_IN_BYTES,
                 m1, mBLen, tag1, &tag1Len);

            // Self-made HMAC
            uint8_t tag2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag2));
            Hmac(tag2, key2, SHA256_CHAIN_SIZE_IN_BYTES, m2, mBLen);

            // Compare them.
            if (memcmp(tag1, tag2, SHA256_HASH_SIZE_IN_BYTES) == 0) {
                continue;
            } else {
                fputs("HMAC-SHA-256: FAILED\n", stdout);
                exit(EXIT_FAILURE);
            }
        }

        FREE_THEN_NULL(m2);
        FREE_THEN_NULL(m1);
    }
    fputs("HMAC-SHA-256: PASS\n", stdout);

    return 0;
}
#endif                          // CHECK_HMAC


#ifdef BENCH_HMAC
#include <inttypes.h>
#include <openssl/hmac.h>

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
        // In this implementation, the key length is fixed to be 256 bits.
        KEY_BYTE_LENGTH = SHA256_CHAIN_SIZE_IN_BYTES,
        // 4 message blocks = 4 * 512 bits = 2,048 bits = 256 bytes
        MAX_MESSAGE_BYTE_LENGTH = 256,
        MAX_REPEAT_COUNT = 1 + 1024 * 64,
    };

    uint8_t key1[KEY_BYTE_LENGTH] = { 0x00, };
    uint8_t key2[KEY_BYTE_LENGTH] = { 0x00, };
    assert(sizeof(key1) == sizeof(key2));
    // This implementation assume that the key length is fixed to be 256 bits.
    assert(sizeof(key1) == SHA256_CHAIN_SIZE_IN_BYTES);

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
            // Choose the key at random.
            for (size_t i = 0; i < NELMS(key1); ++i) {
                key1[i] = rand8();
            }
            memcpy(key2, key1, sizeof(key2));
            // Choose the message at random.
            if (m1 != NULL && m2 != NULL) {
                for (size_t i = 0; i < mBLen; ++i) {
                    m1[i] = rand8();
                }
                memcpy(m2, m1, mBLen * sizeof(uint8_t));
            }

            // OpenSSL HMAC-SHA-256
            uint8_t tag1[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag1));
            unsigned int tag1Len = SHA256_HASH_SIZE_IN_BYTES;
            uint64_t start = 0;
            uint64_t stop = 0;
            unsigned int cidStart = 0;
            unsigned int cidStop = 0;
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                HMAC(EVP_sha256(), key1, SHA256_CHAIN_SIZE_IN_BYTES,
                     m1, mBLen, tag1, &tag1Len);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
            } while (cidStart != cidStop);
            assert(start < stop);
            lap1[n] = stop - start;

            //Self-made HMAC-SHA-256
            uint8_t tag2[SHA256_HASH_SIZE_IN_BYTES] = { 0x00, };
            assert(IS_16_BYTE_ALIGNED(tag2));
            do {
                _mm_mfence();
                start = __rdtscp(&cidStart);
                Hmac(tag2, key2, SHA256_CHAIN_SIZE_IN_BYTES, m2, mBLen);
                _mm_mfence();
                stop = __rdtscp(&cidStop);
            } while (cidStart != cidStop);
            assert(start < stop);
            lap2[n] = stop - start;

            if (memcmp(tag1, tag2, sizeof(tag1)) != 0) {
                fputs("HMAC-SHA-256: FAILED\n", stdout);
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
#endif                          // BENCH_HMAC

// end of file
