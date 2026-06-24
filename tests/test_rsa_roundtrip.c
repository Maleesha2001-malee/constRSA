#include <stdio.h>
#include <string.h>
#include "../src/rsa_sign.h"

/* Same RSA-512 keypair as test_crt_sign.c (seed=42 in generate_crt_vectors.py) */
static bigint512 p    = {{0xdd6ac7b86778043bUL,0xd32e6dcd83bc9478UL,0x004b6fabfcf56188UL,0xde8ede0ba85c6e4aUL,0,0,0,0}};
static bigint512 q    = {{0x3e83b91f25440fe1UL,0x697c392387fa841aUL,0xae8a781390e0a95bUL,0xae183554cae28e66UL,0,0,0,0}};
static bigint512 dp   = {{0x453ddff0d4f8f797UL,0x8471571e4f3fd0c4UL,0x84d77fa2f9dd3c52UL,0x0ecd83d954a66933UL,0,0,0,0}};
static bigint512 dq   = {{0x92af064f113174e1UL,0x0601bba51f33d41fUL,0xb698611a5bd516abUL,0xa93a5cf4fc767787UL,0,0,0,0}};
static bigint512 qinv = {{0x90064d107f428698UL,0x9235bb40ef8bfc8dUL,0xdd408babb3e814eeUL,0x68df381b5c60e063UL,0,0,0,0}};

int main(void) {
    rsa_private_key priv = { .p = p, .q = q, .dp = dp, .dq = dq, .qinv = qinv };

    /* n = p * q, computed here using the plain multiply helper.
     * (p, q are each <=256 bits, so the product fits in 512 bits.) */
    bigint512 n;
    bigint_mul_low512(&n, &p, &q);

    bigint512 e = {{0x10001UL,0,0,0,0,0,0,0}}; /* 65537 */
    rsa_public_key pub = { .n = n, .e = e };

    const char *message = "ConstRSA end-to-end test message";
    unsigned char sig[64];

    rsa_sign((const unsigned char *)message, strlen(message), &priv, sig);

    printf("Signature: ");
    for (int i = 0; i < 64; i++) printf("%02x", sig[i]);
    printf("\n");

    int ok = rsa_verify((const unsigned char *)message, strlen(message), sig, &pub);
    printf("Verify (correct message): %s\n", ok ? "VALID" : "INVALID");
    if (!ok) { printf("FAIL: signature should have verified\n"); return 1; }

    /* tamper test: verifying against a different message must fail */
    const char *tampered = "ConstRSA end-to-end test mussage"; /* one char changed */
    int ok2 = rsa_verify((const unsigned char *)tampered, strlen(tampered), sig, &pub);
    printf("Verify (tampered message): %s\n", ok2 ? "VALID (BUG!)" : "INVALID (correct)");
    if (ok2) { printf("FAIL: tampered message should NOT verify\n"); return 1; }

    printf("PASS: sign+verify round trip and tamper detection both correct\n");
    return 0;
}
