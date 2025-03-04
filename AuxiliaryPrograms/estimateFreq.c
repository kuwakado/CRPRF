/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

// Estimate CPU clock frequency from a value of rdtscp().

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <x86intrin.h>


int main(int argc, char *argv[])
{
    enum {
        // nano = 10^{-9}
        // 1000000 [ns] = 0.001[s]
        TIME_IN_NANOSECONDS = 1000000
    };
    const struct timespec req = { 0, TIME_IN_NANOSECONDS };

    struct timeval t0 = { 0x00, };
    struct timeval t1 = { 0x00, };
    uint64_t start = 0;
    uint64_t stop = 0;
    unsigned int cidStart = 0;
    unsigned int cidStop = 0;
    do {
        gettimeofday(&t0, NULL);
        _mm_mfence();
        start = __rdtscp(&cidStart);
        if (nanosleep(&req, NULL) != 0) {
            continue;
        }
        _mm_mfence();
        stop = __rdtscp(&cidStop);
        gettimeofday(&t1, NULL);
    } while (cidStart != cidStop);
    assert(start < stop);

    printf("Core ID: %u  ", cidStart);
    uint64_t diffOfTSCP = stop - start;
    uint64_t hz = (1000000000 / TIME_IN_NANOSECONDS) * diffOfTSCP;
    double ghz = hz / (1000.0 * 1000.0 * 1000.0);
    printf("estimated clock frequency: %" PRIu64 " [Hz] = %.2lf [GHz]\n",
           hz, ghz);

    return 0;
}

// end of file
