/*
 * verify_test.c — ConstRSA Signature Verification Tests
 * ======================================================
 * Tests:
 *   1. Valid signature   → PASS
 *   2. Wrong message     → FAIL (tampered message)
 *   3. Wrong signature   → FAIL (corrupted signature)
 *   4. Multiple messages → All PASS
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

/* ── Utilities ── */
static inline u64 ct_select(int bit, u64 a, u64 b)
{
    u64 mask = -(u64)(unsigned int)bit;
    return (a & mask) | (b & ~mask);
}

static inline u64 mulmod(u64 a, u64 b, u64 m)
{
    return (u128)a * b % m;
}

/* ── Modular exponentiation ── */
u64 ct_mod_exp(u64 base, u64 exp, u64 n)
{
    u64 R = 1, A = base % n;
    for (int i = 63; i >= 0; i--) {
        R = mulmod(R, R, n);
        u64 T = mulmod(R, A, n);
        int ebit = (int)((exp >> i) & 1u);
        R = ct_select(ebit, T, R);
    }
    return R;
}

/* ── Extended GCD ── */
static long long ext_gcd(long long a, long long b,
                          long long *x, long long *y)
{
    if (b == 0) { *x = 1; *y = 0; return a; }
    long long x1, y1;
    long long g = ext_gcd(b, a % b, &x1, &y1);
    *x = y1; *y = x1 - (a / b) * y1;
    return g;
}

static u64 mod_inverse(u64 e, u64 phi)
{
    long long x, y;
    ext_gcd((long long)e, (long long)phi, &x, &y);
    return (u64)((x % (long long)phi +
                  (long long)phi) % (long long)phi);
}

/* ── RSA Key ── */
typedef struct {
    u64 n, e, d, p, q, dp, dq;
} RSAKey;

void rsa_keygen(RSAKey *key, u64 p, u64 q)
{
    key->p  = p; key->q = q;
    key->n  = p * q;
    key->e  = 65537;
    u64 phi = (p - 1) * (q - 1);
    key->d  = mod_inverse(key->e, phi);
    key->dp = key->d % (p - 1);
    key->dq = key->d % (q - 1);
}

/* ── Hash ── */
static u64 simple_hash(const char *msg)
{
    u64 h = 14695981039346656037ULL;
    while (*msg) {
        h ^= (u64)(unsigned char)*msg++;
        h *= 1099511628211ULL;
    }
    return h;
}

/* ── Sign ── */
u64 rsa_sign_ct(const char *msg, RSAKey *key)
{
    u64 m  = simple_hash(msg) % key->n;
    u64 s1 = ct_mod_exp(m % key->p, key->dp, key->p);
    u64 s2 = ct_mod_exp(m % key->q, key->dq, key->q);
    u64 h  = mulmod((s1 - s2 + key->p),
                     mod_inverse(key->q, key->p), key->p);
    return (s2 + key->q * h) % key->n;
}

/* ── Verify ── */
int rsa_verify(const char *msg, u64 sig, RSAKey *key)
{
    u64 m         = simple_hash(msg) % key->n;
    u64 recovered = ct_mod_exp(sig, key->e, key->n);
    return (recovered == m) ? 1 : 0;
}

/* ── Test helper ── */
static int passed = 0;
static int failed = 0;

void run_test(const char *test_name, int result, int expected)
{
    if (result == expected) {
        printf("  [PASS] %s\n", test_name);
        passed++;
    } else {
        printf("  [FAIL] %s  (expected=%d, got=%d)\n",
               test_name, expected, result);
        failed++;
    }
}

/* ── Main ── */
int main(void)
{
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  ConstRSA — Signature Verification Tests ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    RSAKey key;
    rsa_keygen(&key, 999983ULL, 999979ULL);
    printf("\nRunning tests...\n\n");

    /* ── Test 1: Valid signature ── */
    {
        const char *msg = "Hello ConstRSA";
        u64 sig = rsa_sign_ct(msg, &key);
        run_test("Valid signature verifies correctly",
                 rsa_verify(msg, sig, &key), 1);
    }

    /* ── Test 2: Tampered message ── */
    {
        const char *msg      = "Hello ConstRSA";
        const char *tampered = "Hello ConstRSA!";
        u64 sig = rsa_sign_ct(msg, &key);
        run_test("Tampered message fails verification",
                 rsa_verify(tampered, sig, &key), 0);
    }

    /* ── Test 3: Corrupted signature ── */
    {
        const char *msg = "Hello ConstRSA";
        u64 sig = rsa_sign_ct(msg, &key) + 1;  /* corrupt */
        run_test("Corrupted signature fails verification",
                 rsa_verify(msg, sig, &key), 0);
    }

    /* ── Test 4: Multiple different messages ── */
    const char *messages[] = {
        "Research Project 2020/ICT/47",
        "University of Vavuniya",
        "Constant-time RSA-512",
        "Side-channel attack prevention",
        "Welch t-test timing analysis"
    };
    int n_msgs = 5;

    printf("\n  Multiple message tests:\n");
    for (int i = 0; i < n_msgs; i++) {
        u64 sig = rsa_sign_ct(messages[i], &key);
        char test_name[64];
        snprintf(test_name, sizeof(test_name),
                 "Message %d signs and verifies", i + 1);
        run_test(test_name, rsa_verify(messages[i], sig, &key), 1);
    }

    /* ── Test 5: Cross-signature check ── */
    printf("\n  Cross-signature tests:\n");
    {
        u64 sig1 = rsa_sign_ct(messages[0], &key);
        u64 sig2 = rsa_sign_ct(messages[1], &key);
        run_test("Sig1 does not verify msg2",
                 rsa_verify(messages[1], sig1, &key), 0);
        run_test("Sig2 does not verify msg1",
                 rsa_verify(messages[0], sig2, &key), 0);
    }

    /* ── Summary ── */
    printf("\n══════════════════════════════════════════\n");
    printf("  Total : %d   Passed : %d   Failed : %d\n",
           passed + failed, passed, failed);
    if (failed == 0)
        printf("  All tests PASSED ✓\n");
    else
        printf("  Some tests FAILED ✗\n");
    printf("══════════════════════════════════════════\n");

    return (failed == 0) ? 0 : 1;
}