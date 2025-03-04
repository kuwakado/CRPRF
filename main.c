/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "crprfBenchmark.h"
#include "sha256cf.h"
#include "macro.h"


// https://www.jpcert.or.jp/sc-rules/c-int06-c.html
static int atoi_s(const char *const str)
{
    char *end = NULL;
    const long int sl = strtol(str, &end, 10);

    if (end == str) {
        printf("%s: not a decimal number\n", str);
        exit(EXIT_FAILURE);
    } else if ('\0' != *end) {
        printf("%s: extra characters at end of input: %s\n", str, end);
        exit(EXIT_FAILURE);
    } else if ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == 0) {
        printf("%s: out of range of type long\n", str);
        exit(EXIT_FAILURE);
    } else if (sl > INT_MAX) {
        printf("%ld: greater than INT_MAX\n", sl);
        exit(EXIT_FAILURE);
    } else if (sl < INT_MIN) {
        printf("%ld: less than INT_MIN\n", sl);
        exit(EXIT_FAILURE);
    } else {
        return (int) sl;
    }
}


// default parameters
enum {
    DEFAULT_MAX_MESSAGE_BYTE_LENGTH =
        4 * SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES,
    DEFAULT_REPEAT_COUNT = 1 + 128,
    DEFAULT_STEP_BYTE = SHA256_MESSAGE_BLOCK_SIZE_IN_BYTES / 2
};


// commadline options
static const struct option longOpts[] = {
    { "help", no_argument, NULL, 140 },
    { "maxMessageByteLength", required_argument, NULL, 143 },
    { "repeatCount", required_argument, NULL, 147 },
    { "stepByte", required_argument, NULL, 150 },
    { 0, 0, 0, 0 },
};


static void usage(const char *const argv0)
{
    int i = 0;
    fprintf(stdout, "Usage: %s [options]\n", argv0);
    fprintf(stdout, "--%s  print this help\n", longOpts[i++].name);
    fprintf(stdout,
            "--%s=L  message length from 0 to L bytes (default: %d)\n",
            longOpts[i++].name, DEFAULT_MAX_MESSAGE_BYTE_LENGTH);
    fprintf(stdout,
            "--%s=N  repeat (odd) N times for obtaining the median  (default: %d)\n",
            longOpts[i++].name, DEFAULT_REPEAT_COUNT);
    fprintf(stdout,
            "--%s=S  increase the message length by S bytes each (default: %d)\n",
            longOpts[i++].name, DEFAULT_STEP_BYTE);
    assert(i == NELMS(longOpts) - 1);
}


int main(int argc, char *argv[])
{
    const char *const argv0 = argv[0];
    bool isValidMaxMessageByteLength = true;
    bool isValidRepeatCount = true;
    bool isValidStepByte = true;
    int maxMessageByteLength = DEFAULT_MAX_MESSAGE_BYTE_LENGTH;
    int repeatCount = DEFAULT_REPEAT_COUNT;
    int stepByte = DEFAULT_STEP_BYTE;
    bool isGivenAnyOption = false;
    while (1) {
        int opt = getopt_long_only(argc, argv, "", longOpts, NULL);
        if (opt == -1) {
            break;
        }
        isGivenAnyOption = true;
        switch (opt) {
        case 140:              // help
            usage(argv0);
            exit(EXIT_SUCCESS);
            break;
        case 143:              // maxMessageByteLength
            maxMessageByteLength = atoi_s(optarg);
            if (maxMessageByteLength >= 0) {
                isValidMaxMessageByteLength = true;
            } else {
                isValidMaxMessageByteLength = false;
            }
            break;
        case 147:              // repeatCount
            repeatCount = atoi_s(optarg);
            // "repeatCount" is odd because it makes easy to compute an median.
            if (repeatCount > 0 && repeatCount % 2 == 1) {
                isValidRepeatCount = true;
            } else {
                isValidRepeatCount = false;
            }
            break;
        case 150:              // stepByte
            stepByte = atoi_s(optarg);
            if (stepByte > 0) {
                isValidStepByte = true;
            } else {
                isValidStepByte = false;
            }
            break;
        default:
            isGivenAnyOption = false;
            fputs("Unknown option\n", stdout);
            exit(EXIT_FAILURE);
        }
    }

    if (isValidMaxMessageByteLength && isValidRepeatCount
        && isValidStepByte) {
        if (isGivenAnyOption) {
            CrPrfBenchmark(maxMessageByteLength, stepByte, repeatCount);
        } else {
            // Execute the program with default parameters.
            fprintf(stdout, "maxMessageByteLength: %d\n",
                    DEFAULT_MAX_MESSAGE_BYTE_LENGTH);
            fprintf(stdout, "repeatCount: %d\n", DEFAULT_REPEAT_COUNT);
            fprintf(stdout, "stepByte: %d\n", DEFAULT_STEP_BYTE);
            fflush(stdout);
            CrPrfBenchmark(DEFAULT_MAX_MESSAGE_BYTE_LENGTH,
                           DEFAULT_STEP_BYTE, DEFAULT_REPEAT_COUNT);
        }
    } else if (!isValidMaxMessageByteLength) {
        fputs("Invalid value: maxMessageByteLength\n", stdout);
        usage(argv0);
        exit(EXIT_FAILURE);
    } else if (!isValidRepeatCount) {
        fputs("Invalid value: repeatCount\n", stdout);
        usage(argv0);
        exit(EXIT_FAILURE);
    } else if (!isValidStepByte) {
        fputs("Invalid value: stepByte\n", stdout);
        usage(argv0);
        exit(EXIT_FAILURE);
    } else {
        // Do nothing.
    }

    return 0;
}

// end of file
