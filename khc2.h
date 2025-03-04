/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___KHC2_H_
#define ___KHC2_H_

#include <stddef.h>

#include "sha256cf.h"

/* khc2.c */
void KHC2(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES], uint8_t *const key,
          const size_t keyByteLength, uint8_t *const message,
          const size_t messageByteLength);

#endif                          // ___KHC2_H_

// end of file
