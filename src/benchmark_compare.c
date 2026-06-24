/*
 * benchmark_compare.c
 *
 * Section 5.6 performance evaluation: measures signing time for both
 * the constant-time and baseline (non-constant-time) implementations
 * under identical conditions, to quantify the overhead of constant-time
 * engineering (RQ3).
 *
 * Build:
 *   gcc -O2 -o benchmark_compare src/bigint.c src/baseline.c src/benchmark_compare.c
 *
 * Run:
 *   echo "run,impl,time_ns" > data/benchmark_data.csv
 *   ./benchmark_compare >> data/benchmark_data.csv
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bigint.h"
#include "baseline.h"

static bigint512 p    = {{0xdd6ac7b86778043bUL,0xd32e6dcd83bc9478UL,0x004b6fabfcf56188UL,0xde8ede0ba85c6e4aUL,0,0,0,0}};
static bigint512 q    = {{0x3e83b91f25440fe1UL,0x697c392387fa841aUL,0xae8a781390e0a95bUL,0xae183554cae28e66UL,0,0,0,0}};
static bigint512 dp   = {{0x453ddff0d4f8f797UL,0x8471571e4f3fd0c4UL,0x84d77fa2f9dd3c52UL,0x0ecd83d954a66933UL,0,0,0,0}};
static bigint512 dq   = {{0x92af064f113174e1UL,0x0601bba51f33d41fUL,0xb698611a5bd516abUL,0xa93a5cf4fc767787UL,0,0,0,0}};
static bigint512 qinv = {{0x90064d107f428698UL,0x9235bb40ef8bfc8dUL,0xdd408babb3e814eeUL,0x68df381b5c60e063UL,0,0,0,0}};
static bigint512 m    = {{0x0123456789abcdefUL,0x0123456789abcdefUL,
                          0x0123456789abcdefUL,0x0123456789abcdefUL,0,0,0,0}};

#define RUNS 5000

int main(void) {
    bigint512 sp, sq, sig;

    /* warm-up both */
    for (int w = 0; w < 200; w++) {
        bigint_mod_exp_fixed_window(&sp, &m, &dp, &p);
        bigint_mod_exp_fixed_window(&sq, &m, &dq, &q);
        bigint_crt_combine(&sig, &sp, &sq, &p, &q, &qinv);
        baseline_crt_sign(&sig, &m, &p, &q, &dp, &dq, &qinv);
    }

    for (long i = 0; i < RUNS; i++) {
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);
        bigint_mod_exp_fixed_window(&sp, &m, &dp, &p);
        bigint_mod_exp_fixed_window(&sq, &m, &dq, &q);
        bigint_crt_combine(&sig, &sp, &sq, &p, &q, &qinv);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long ct_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);

        clock_gettime(CLOCK_MONOTONIC, &start);
        baseline_crt_sign(&sig, &m, &p, &q, &dp, &dq, &qinv);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long bl_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);

        printf("%ld,constant_time,%ld\n", i, ct_ns);
        printf("%ld,baseline,%ld\n", i, bl_ns);
    }
    return 0;
}
