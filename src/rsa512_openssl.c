/*
 * rsa512_openssl.c — ConstRSA: Real 512-bit Constant-Time RSA
 * ============================================================
 * Uses OpenSSL for:
 *   - Real 512-bit RSA key generation
 *   - Real SHA-256 hashing
 *   - RSA-PSS signing and verification
 *   - Constant-time operations (RSA_FLAG_NO_BLINDING disabled)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* ── Timing ── */
static long long now_ns(void)
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (long long)(count.QuadPart * 1000000000LL /
                       freq.QuadPart);
}

/* ── Print OpenSSL errors ── */
static void print_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
        fprintf(stderr, "OpenSSL error: %s\n",
                ERR_error_string(err, NULL));
}

/* SECTION 1: RSA-512 Key Generation*/
EVP_PKEY *rsa512_keygen(void)
{
    printf("[KeyGen] Generating RSA-512 key pair...\n");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) { print_errors(); return NULL; }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        print_errors(); EVP_PKEY_CTX_free(ctx); return NULL;
    }

    /* Set key size to 512 bits */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 512) <= 0) {
        print_errors(); EVP_PKEY_CTX_free(ctx); return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        print_errors(); EVP_PKEY_CTX_free(ctx); return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Print key info */
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa) {
        printf("[KeyGen] Key size : %d bits\n",
               RSA_size(rsa) * 8);
        const BIGNUM *n, *e, *d;
        RSA_get0_key(rsa, &n, &e, &d);
        printf("[KeyGen] n (hex)  : ");
        BN_print_fp(stdout, n);
        printf("\n[KeyGen] e        : ");
        BN_print_fp(stdout, e);
        printf("\n");
        RSA_free(rsa);
    }

    printf("[KeyGen] Done!\n\n");
    return pkey;
}

/* 
 * SECTION 2: RSA-PSS Signing (SHA-256)
 * Constant-time via OpenSSL blinding
 */
int rsa512_sign(EVP_PKEY *pkey,
                const unsigned char *msg, size_t msg_len,
                unsigned char **sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    /* RSA-PSS with SHA-256 */
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(ctx, &pctx,
                           EVP_sha256(), NULL, pkey) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    /* Set PSS padding */
    if (EVP_PKEY_CTX_set_rsa_padding(pctx,
                                      RSA_PKCS1_PSS_PADDING) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    /* Set salt length */
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 20) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    /* Sign */
    if (EVP_DigestSignUpdate(ctx, msg, msg_len) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    /* Get signature size */
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    *sig = (unsigned char *)malloc(*sig_len);
    if (!*sig) { EVP_MD_CTX_free(ctx); return 0; }

    if (EVP_DigestSignFinal(ctx, *sig, sig_len) <= 0) {
        print_errors();
        free(*sig); EVP_MD_CTX_free(ctx); return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

/* SECTION 3: RSA-PSS Verification */
int rsa512_verify(EVP_PKEY *pkey,
                   const unsigned char *msg, size_t msg_len,
                   const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx,
                              EVP_sha256(), NULL, pkey) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx,
                                      RSA_PKCS1_PSS_PADDING) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 20) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) <= 0) {
        print_errors(); EVP_MD_CTX_free(ctx); return 0;
    }

    int result = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    EVP_MD_CTX_free(ctx);
    return (result == 1) ? 1 : 0;
}

/* SECTION 4: Timing experiment → CSV */
void timing_experiment(EVP_PKEY *pkey, int runs)
{
    printf("[Timing] Collecting %d runs...\n", runs);

    FILE *fp = fopen("data\\timing_512.csv", "w");
    if (!fp) { printf("ERROR: cannot open CSV!\n"); return; }

    fprintf(fp, "run,input_type,time_ns\n");

    const char *fixed_msg = "ConstRSA fixed message 2020ICT47";
    size_t fixed_len = strlen(fixed_msg);

    /* Fixed message timing */
    for (int i = 0; i < runs; i++) {
        unsigned char *sig = NULL;
        size_t sig_len = 0;

        long long t1 = now_ns();
        rsa512_sign(pkey,
                    (unsigned char *)fixed_msg,
                    fixed_len, &sig, &sig_len);
        long long t2 = now_ns();

        fprintf(fp, "%d,fixed,%lld\n", i, t2 - t1);
        free(sig);
    }

    /* Random message timing */
    char rand_msg[64];
    for (int i = 0; i < runs; i++) {
        snprintf(rand_msg, sizeof(rand_msg),
                 "ConstRSA random msg %d uov 2020ict47", i);
        size_t rand_len = strlen(rand_msg);

        unsigned char *sig = NULL;
        size_t sig_len = 0;

        long long t1 = now_ns();
        rsa512_sign(pkey,
                    (unsigned char *)rand_msg,
                    rand_len, &sig, &sig_len);
        long long t2 = now_ns();

        fprintf(fp, "%d,random,%lld\n", i, t2 - t1);
        free(sig);
    }

    fclose(fp);
    printf("[Timing] CSV saved: data\\timing_512.csv\n\n");
}

/* Main*/
int main(void)
{
    printf("\n");
    printf("  ConstRSA — Real 512-bit RSA-PSS + SHA-256\n");
    printf("\n\n");

    /* Generate RSA-512 key */
    EVP_PKEY *pkey = rsa512_keygen();
    if (!pkey) {
        printf("Key generation failed!\n");
        return 1;
    }

    /* Sign a message */
    const char *msg     = "ConstRSA: Real 512-bit RSA-PSS test";
    size_t      msg_len = strlen(msg);

    unsigned char *sig  = NULL;
    size_t         sig_len = 0;

    printf("[Sign] Message: %s\n", msg);

    if (!rsa512_sign(pkey,
                     (unsigned char *)msg, msg_len,
                     &sig, &sig_len)) {
        printf("Signing failed!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("[Sign] Signature length: %zu bytes (%zu bits)\n",
           sig_len, sig_len * 8);

    /* Print signature hex */
    printf("[Sign] Signature (hex): ");
    for (size_t i = 0; i < sig_len; i++)
        printf("%02x", sig[i]);
    printf("\n\n");

    /* Verify */
    int ok = rsa512_verify(pkey,
                            (unsigned char *)msg, msg_len,
                            sig, sig_len);
    printf("[Verify] Result: %s\n\n",
           ok ? "VALID ✓" : "INVALID ✗");

    /* Tamper test */
    const char *tampered = "ConstRSA: Real 512-bit RSA-PSS TAMPERED";
    int ok2 = rsa512_verify(pkey,
                             (unsigned char *)tampered,
                             strlen(tampered),
                             sig, sig_len);
    printf("[Tamper Test] Result: %s\n\n",
           ok2 ? "VALID (WRONG!)" : "INVALID ✓ (tamper detected)");

    /* Timing experiment */
    timing_experiment(pkey, 5000);

    free(sig);
    EVP_PKEY_free(pkey);

    printf("  Done! Check data\\timing_512.csv\n");
    

    return 0;
}