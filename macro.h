/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#ifndef ___MACRO_H_
#define ___MACRO_H_

#ifndef NELMS
#define NELMS(a) (sizeof(a)/sizeof(a[0]))
#else
#error NELMS() has been defined.
#endif                          // NELMS


#ifndef FREE_THEN_NULL
#include <stdlib.h>
#define FREE_THEN_NULL(p) do { \
    free(p); \
    p = NULL; \
} while (0)
#else
#error FREE_THEN_NULL() has been defined.
#endif                          // FREE_THEN_NULL


#ifndef EXIT_HERE
#include <stdio.h>
#include <stdlib.h>
#define EXIT_HERE() do { \
    fprintf(stdout, "%s %d\n", __FILE__, __LINE__); \
    fflush(stdout); \
    exit(EXIT_FAILURE); \
} while (0)
#else
#error EXIT_HERE() has been defined.
#endif                          // EXIT_HERE


#ifndef xEXIT_HERE
#include <stdio.h>
#define xEXIT_HERE() do { \
    fprintf(stdout, "%s %d\n", __FILE__, __LINE__); \
    fflush(stdout); \
} while (0)
#else
#error xEXIT_HERE() has been defined.
#endif                          // xEXIT_HERE


#ifndef PRINT_HERE
#include <stdio.h>
#define PRINT_HERE() do { \
    fprintf(stdout, "%s %d\n", __FILE__, __LINE__); \
    fflush(stdout); \
} while (0)
#else
#error PRINT_HERE() has been defined.
#endif                          // EXIT_HERE


#ifndef IS_16_BYTE_ALIGNED
#include <stdint.h>
#define IS_16_BYTE_ALIGNED(p) ((((uint64_t)(p)) & 0x0f) == 0x00)
#else
#error IS_16_BYTE_ALIGNED() has been defined.
#endif                          // IS_16_BYTE_ALIGNED


// toy random generator
#include <stdint.h>
static inline uint8_t rand8(void)
{
    // Pi
    static uint32_t next = 314159;
    // https://en.wikipedia.org/wiki/Linear_congruential_generator
    // ANSI C: Watcom, Digital Mars, CodeWarrior, IBM VisualAge C/C++ C90, C99,
    // C11: Suggestion in the ISO/IEC 9899, C17
    next = (1103515245 * next + 12345) & 0x7fffffffffffffffUL;
    return (uint8_t) ((next >> 17) & 0xff);
}

#endif                          // ___MACRO_H_

// end of file
