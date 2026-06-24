#include <stdio.h>
#include <string.h>
#include "../src/baseline.h"

static int limbs_equal(const bigint512 *a, const bigint512 *b) {
    for (int i = 0; i < LIMBS; i++) if (a->v[i] != b->v[i]) return 0;
    return 1;
}

/* same key/vector as test_crt_sign.c */
static bigint512 p    = {{0xdd6ac7b86778043bUL,0xd32e6dcd83bc9478UL,0x004b6fabfcf56188UL,0xde8ede0ba85c6e4aUL,0,0,0,0}};
static bigint512 q    = {{0x3e83b91f25440fe1UL,0x697c392387fa841aUL,0xae8a781390e0a95bUL,0xae183554cae28e66UL,0,0,0,0}};
static bigint512 dp   = {{0x453ddff0d4f8f797UL,0x8471571e4f3fd0c4UL,0x84d77fa2f9dd3c52UL,0x0ecd83d954a66933UL,0,0,0,0}};
static bigint512 dq   = {{0x92af064f113174e1UL,0x0601bba51f33d41fUL,0xb698611a5bd516abUL,0xa93a5cf4fc767787UL,0,0,0,0}};
static bigint512 qinv = {{0x90064d107f428698UL,0x9235bb40ef8bfc8dUL,0xdd408babb3e814eeUL,0x68df381b5c60e063UL,0,0,0,0}};
static bigint512 m    = {{0x0123456789abcdefUL,0x0123456789abcdefUL,0x0123456789abcdefUL,0x0123456789abcdefUL,0,0,0,0}};
static bigint512 expected_sig = {{0x49d7269cc303658aUL,0x88d7a3718f3e0897UL,0x423313052aa81386UL,0xda434d48cddd3201UL,0x121ee43cefd31c51UL,0x5b43e46e734b6372UL,0x25a838097e30c80fUL,0x6c8f8926a8b767f0UL}};

int main(void) {
    bigint512 sig;
    baseline_crt_sign(&sig, &m, &p, &q, &dp, &dq, &qinv);

    if (limbs_equal(&sig, &expected_sig)) {
        printf("PASS: baseline implementation produces the same signature\n");
        printf("      as the constant-time implementation (correctness match)\n");
        return 0;
    } else {
        printf("FAIL: baseline signature does not match constant-time result\n");
        return 1;
    }
}
