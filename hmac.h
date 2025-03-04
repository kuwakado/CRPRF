/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___HMAC_H_
#define ___HMAC_H_

#include <stdint.h>

#include "sha256cf.h"

/* hmac.c */
void Hmac(uint8_t tag[SHA256_HASH_SIZE_IN_BYTES], uint8_t *key,
          size_t keyByteLength, uint8_t *message,
          const size_t messageByteLength);

#endif                          // ___HMAC_H_

// end of file
