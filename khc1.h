/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___KHC1_H_
#define ___KHC1_H_

#include <stdint.h>

#include "sha256.h"

/* khc1.c */
void KHC1(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES], uint8_t *const key,
          const size_t keyByteLength, uint8_t *const message,
          const size_t messageByteLength);

#endif                          // ___KHC1_H_

// end of file
