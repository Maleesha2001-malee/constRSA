/*
 * real_timing_harness.c
 *
 * Section 5.5 fixed-vs-random timing experiment, using the REAL
 * constant-time CRT signing function (not a placeholder).
 *
 * Build:
 *   gcc -O2 -o real_timing_harness src/bigint.c src/real_timing_harness.c
 *
 * Run:
 *   echo "run,type,time_ns" > data/timing_data.csv
 *   ./real_timing_harness fixed  100000 >> data/timing_data.csv
 *   ./real_timing_harness random 100000 >> data/timing_data.csv
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bigint.h"

/* Same RSA-512 keypair used throughout testing (seed=42) */
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

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s [fixed|random] <num_runs>\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];
    long n = atol(argv[2]);
    int is_fixed = (strcmp(mode, "fixed") == 0);

    bigint512 fixed_msg = {{0x0123456789abcdefUL,0x0123456789abcdefUL,
                            0x0123456789abcdefUL,0x0123456789abcdefUL,0,0,0,0}};
    srand(12345);

    bigint512 sp, sq, sig;

    /* warm-up */
    for (int w = 0; w < 500; w++) {
        bigint_mod_exp_fixed_window(&sp, &fixed_msg, &dp, &p);
        bigint_mod_exp_fixed_window(&sq, &fixed_msg, &dq, &q);
        bigint_crt_combine(&sig, &sp, &sq, &p, &q, &qinv);
    }

    for (long i = 0; i < n; i++) {
        bigint512 m;
        if (is_fixed) m = fixed_msg;
        else random_bigint(&m);
        /* reduce m mod p*q-ish range isn't strictly necessary here since
         * we feed m directly into per-prime exponentiation already mod p / mod q
         * implicitly via the modexp's internal reduction -- fine for timing
         * purposes since we only care about execution time, not validity. */

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        bigint_mod_exp_fixed_window(&sp, &m, &dp, &p);
        bigint_mod_exp_fixed_window(&sq, &m, &dq, &q);
        bigint_crt_combine(&sig, &sp, &sq, &p, &q, &qinv);
        clock_gettime(CLOCK_MONOTONIC, &end);

        long ns = (end.tv_sec - start.tv_sec) * 1000000000L
                 + (end.tv_nsec - start.tv_nsec);
        printf("%ld,%s,%ld\n", i, mode, ns);
    }
    return 0;
}
