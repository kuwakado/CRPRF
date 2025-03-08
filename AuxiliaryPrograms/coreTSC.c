/*
 * Released under the MIT License
 * https://opensource.org/license/mit
 * Copyright 2025  Hidenori Kuwakado
 */

// Display the value of the timestamp counter of each processor. Display the
// clock resolution of each processor. Calculate the operating frequency from
// the timestamp counter and clock resolution of each processor.

#define _GNU_SOURCE
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>


typedef struct {
    int threadId;
    bool didSuccessfullyReadTsc;
    uint64_t tsc;
    unsigned int cid;
    long int resolution;
    double ghz;
} thread_args_t;


// When 'isTimeToReadTsc' becomes true, each thread reads a time stamp counter.
static bool isTimeToReadTsc = false;
static pthread_mutex_t mutex;


static void *readTsc(void *const arg)
{
    thread_args_t *const a = (thread_args_t *const) arg;

    if (a->threadId == 0) {
        // Assume that all threads start within one second.
        const unsigned int sec = 1;
        sleep(sec);

        pthread_mutex_lock(&mutex);
        // When 'isTimeToReadTsc' becomes true, each thread reads the time stamp
        // counter. Ideally, all threads would read the time stamp counter at
        // the same time, but since 'isTimeToReadTsc' is mutually exclusive,
        // each thread sequentially finds that this variable has become true.
        isTimeToReadTsc = true;
        pthread_mutex_unlock(&mutex);
        _mm_mfence();
        a->tsc = __rdtscp(&(a->cid));
    } else {
        // Wait until global variable 'isTimeToReadTsc' becomes true.
        while (true) {
            pthread_mutex_lock(&mutex);
            bool isBreak = isTimeToReadTsc;
            pthread_mutex_unlock(&mutex);
            if (isBreak) {
                _mm_mfence();
                a->tsc = __rdtscp(&(a->cid));
                break;
            } else {
                continue;
            }
        }
    }
    a->didSuccessfullyReadTsc = true;

    // Find the resolution of CLOCK_REALTIME.
    // https://manpages.org/clock_gettime/2
    struct timespec res = { 0, 0 };
    clock_getres(CLOCK_REALTIME, &res);
    a->resolution = res.tv_nsec;

    // Wait 'FACTOR' times the resolution. If this value is small, the precise
    // frequency cannot be estimated.
    const int FACTOR = 1000000;
    assert(res.tv_sec < LONG_MAX / FACTOR);
    const struct timespec request = { res.tv_sec, FACTOR * res.tv_nsec };

    // Estimate CPU clock frequency from a value of rdtscp().
    struct timespec tsStart = { 0, 0 };
    struct timespec tsStop = { 0, 0 };
    uint64_t start = 0;
    uint64_t stop = 0;
    unsigned int cidStart = 0;
    unsigned int cidStop = 0;
    int ret = clock_gettime(CLOCK_REALTIME, &tsStart);
    assert(ret == 0);
    _mm_mfence();
    start = __rdtscp(&cidStart);
    // Wait a moment
    // https://manpages.ubuntu.com/manpages/noble/en/man2/clock_nanosleep.2.html
    ret = clock_nanosleep(CLOCK_REALTIME, 0, &request, NULL);
    assert(ret == 0);
    _mm_mfence();
    stop = __rdtscp(&cidStop);
    ret = clock_gettime(CLOCK_REALTIME, &tsStop);
    assert(ret == 0);
    assert(start < stop && cidStart == cidStop);

    uint64_t hz = (1000000000 / request.tv_nsec) * (stop - start);
    a->ghz = hz / (1000.0 * 1000.0 * 1000.0);

    return NULL;
}


int main(int argc, char *argv[])
{
    // https://manpages.ubuntu.com/manpages/noble/en/man3/sysconf.3.html
    // _SC_NPROCESSORS_ONLN may not be standard.
    long int numProcs = sysconf(_SC_NPROCESSORS_ONLN);
    assert(numProcs > 0);

    // variable length array
    // C99: mandatory, C11: optional
    assert(numProcs < 256);
    thread_args_t readTscArgs[numProcs];
    pthread_attr_t attrs[numProcs];
    pthread_t threads[numProcs];
    for (int i = 0; i < numProcs; ++i) {
        memset(readTscArgs, 0x00, numProcs * sizeof(thread_args_t));
        memset(attrs, 0x00, numProcs * sizeof(pthread_attr_t));
        memset(threads, 0x00, numProcs * sizeof(pthread_t));
    }

    for (int i = 0; i < numProcs; ++i) {
        // The cpu_set_t data structure represents a set of CPUs.
        // https://man7.org/linux/man-pages/man3/CPU_SET.3.html
        cpu_set_t set;
        CPU_ZERO(&set);
        // Add the i-th processor to set.
        CPU_SET(i, &set);

        // https://manpages.org/pthread_attr_init/3
        int ret = pthread_attr_init(&attrs[i]);
        assert(ret == 0);
        // https://manpages.org/pthread_attr_setaffinity_np/3
        ret = pthread_attr_setaffinity_np(&attrs[i],
                                          sizeof(cpu_set_t), &set);
        assert(ret == 0);
    }

    pthread_mutex_init(&mutex, NULL);
    for (int i = 0; i < numProcs; ++i) {
        readTscArgs[i].threadId = i;
        readTscArgs[i].didSuccessfullyReadTsc = false;
        readTscArgs[i].tsc = 0;
        readTscArgs[i].cid = 0;
        readTscArgs[i].ghz = 0.0;
        int ret = pthread_create(&threads[i], &attrs[i],
                                 readTsc, &readTscArgs[i]);
        assert(ret == 0);
    }

    for (int i = 0; i < numProcs; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_mutex_destroy(&mutex);
    for (int i = 0; i < numProcs; i++) {
        pthread_attr_destroy(&attrs[i]);
    }

    for (int i = 0; i < numProcs; i++) {
        fprintf(stdout, "Thread No.%d ", i);
        fprintf(stdout, "%s  ",
                readTscArgs[i].didSuccessfullyReadTsc ?
                "succeeded" : "failed");
        fprintf(stdout, "Processor No.%u  ", readTscArgs[i].cid);
        fprintf(stdout, "TSC %" PRIu64 "  ", readTscArgs[i].tsc);
        fprintf(stdout, "Resolution %ld [ns]  ",
                readTscArgs[i].resolution);
        fprintf(stdout, "Frequency %.2lf [GHz]\n", readTscArgs[i].ghz);
    }

    return 0;
}

// end of file
