/*
 * interleaved_timing_harness.c
 *
 * Improved version of the fixed-vs-random timing experiment that
 * INTERLEAVES fixed and random measurements (alternating one at a time)
 * instead of running all fixed samples then all random samples.
 *
 * Why this matters: running all-fixed-then-all-random means any time-
 * varying system condition (background services settling after boot,
 * thermal ramp-up, CPU frequency scaling) becomes a confound that can
 * masquerade as a fixed-vs-random timing difference. Interleaving
 * cancels this out, because both conditions are sampled from the same
 * moments in time.
 *
 * Build:
 *   gcc -O2 -o interleaved_timing_harness src/bigint.c src/interleaved_timing_harness.c
 *
 * Run:
 *   ./interleaved_timing_harness 100000 > data/timing_data.csv
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bigint.h"

static bigint512 p    = {{0xdd6ac7b86778043bUL,0xd32e6dcd83bc9478UL,0x004b6fabfcf56188UL,0xde8ede0ba85c6e4aUL,0,0,0,0}};
static bigint512 q    = {{0x3e83b91f25440fe1UL,0x697c392387fa841aUL,0xae8a781390e0a95bUL,0xae183554cae28e66UL,0,0,0,0}};
static bigint512 dp   = {{0x453ddff0d4f8f797UL,0x8471571e4f3fd0c4UL,0x84d77fa2f9dd3c52UL,0x0ecd83d954a66933UL,0,0,0,0}};
static bigint512 dq   = {{0x92af064f113174e1UL,0x0601bba51f33d41fUL,0xb698611a5bd516abUL,0xa93a5cf4fc767787UL,0,0,0,0}};
static bigint512 qinv = {{0x90064d107f428698UL,0x9235bb40ef8bfc8dUL,0xdd408babb3e814eeUL,0x68df381b5c60e063UL,0,0,0,0}};

static void random_bigint(bigint512 *x) {
    for (int i = 0; i < LIMBS; i++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v = (v << 8) | (uint64_t)(rand() & 0xFF);
        x->v[i] = v;
    }
}

static long sign_once(const bigint512 *m) {
    bigint512 sp, sq, sig;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    bigint_mod_exp_fixed_window(&sp, m, &dp, &p);
    bigint_mod_exp_fixed_window(&sq, m, &dq, &q);
    bigint_crt_combine(&sig, &sp, &sq, &p, &q, &qinv);
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <num_runs_per_type>\n", argv[0]);
        return 1;
    }
    long n = atol(argv[1]);

    bigint512 fixed_msg = {{0x0123456789abcdefUL,0x0123456789abcdefUL,
                            0x0123456789abcdefUL,0x0123456789abcdefUL,0,0,0,0}};
    srand(12345);

    /* shared warm-up, both types, before any measurement begins */
    for (int w = 0; w < 1000; w++) {
        sign_once(&fixed_msg);
        bigint512 rm; random_bigint(&rm); sign_once(&rm);
    }

    printf("run,type,time_ns\n");
    for (long i = 0; i < n; i++) {
        /* fixed measurement */
        long t_fixed = sign_once(&fixed_msg);
        printf("%ld,fixed,%ld\n", i, t_fixed);

        /* random measurement, immediately after, same "moment" in time */
        bigint512 rm;
        random_bigint(&rm);
        long t_random = sign_once(&rm);
        printf("%ld,random,%ld\n", i, t_random);
    }
    return 0;
}
