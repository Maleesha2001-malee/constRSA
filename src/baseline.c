#include "bigint.h"
#include <string.h>

/* ============================================================
 * BASELINE (NON-CONSTANT-TIME) IMPLEMENTATION
 *
 * IMPORTANT METHODOLOGY NOTE: this uses the SAME Montgomery
 * multiplication + fixed-window exponentiation structure as the
 * constant-time version, so that the only difference being measured
 * is the constant-time hardening itself (RQ3), not a different,
 * less-efficient algorithm. The two places hardening was removed:
 *   1. conditional subtraction inside Montgomery reduction uses a
 *      real `if` instead of a mask-select
 *   2. window-table lookup directly indexes table[window] instead of
 *      scanning all 16 entries
 * DO NOT use this for anything security-sensitive -- its timing
 * depends on secret exponent bits, which is exactly the vulnerability
 * this whole project studies.
 * ============================================================ */

/* Same CIOS Montgomery multiplication as bigint_mont_mul, except the
 * final conditional subtraction uses a real branch instead of a
 * constant-time mask select. */
static void baseline_mont_mul(bigint512 *r, const bigint512 *a, const bigint512 *b,
                               const bigint512 *n, uint64_t n_inv) {
    uint64_t t[LIMBS + 1] = {0};

    for (int i = 0; i < LIMBS; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            unsigned __int128 prod = (unsigned __int128)a->v[i] * b->v[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[LIMBS] + carry;
        t[LIMBS] = (uint64_t)sum;

        uint64_t m = t[0] * n_inv;
        carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            unsigned __int128 prod = (unsigned __int128)m * n->v[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        sum = (unsigned __int128)t[LIMBS] + carry;
        t[LIMBS] = (uint64_t)sum;

        for (int j = 0; j < LIMBS; j++) t[j] = t[j + 1];
        t[LIMBS] = 0;
    }

    bigint512 result;
    memcpy(result.v, t, sizeof(uint64_t) * LIMBS);

    /* NON-CONSTANT-TIME: real branch instead of mask-select */
    if (bigint_cmp_ct(&result, n)) {
        bigint_sub(&result, &result, n);
    }
    memcpy(r->v, result.v, sizeof(result.v));
}

void baseline_mod_exp(bigint512 *r, const bigint512 *base, const bigint512 *exp,
                       const bigint512 *mod) {
    bigint512 r2modn;
    bigint_compute_r2_mod_n(&r2modn, mod);
    uint64_t ninv = bigint_compute_n_inv(mod);

    bigint512 base_m;
    baseline_mont_mul(&base_m, base, &r2modn, mod, ninv);

    bigint512 one = {{1,0,0,0,0,0,0,0}};
    bigint512 table[16];
    baseline_mont_mul(&table[0], &one, &r2modn, mod, ninv);
    table[1] = base_m;
    for (int i = 2; i < 16; i++) {
        baseline_mont_mul(&table[i], &table[i-1], &base_m, mod, ninv);
    }

    bigint512 result = table[0];

    for (int w = 127; w >= 0; w--) {
        for (int s = 0; s < 4; s++) {
            bigint512 sq;
            baseline_mont_mul(&sq, &result, &result, mod, ninv);
            result = sq;
        }
        int bit_offset = w * 4;
        int limb_idx = bit_offset / 64;
        int shift = bit_offset % 64;
        uint64_t window = (exp->v[limb_idx] >> shift) & 0xF;

        /* NON-CONSTANT-TIME: direct table index by secret window value,
         * instead of scanning all 16 entries */
        bigint512 multiplicand = table[window];

        bigint512 multiplied;
        baseline_mont_mul(&multiplied, &result, &multiplicand, mod, ninv);
        result = multiplied;
    }

    baseline_mont_mul(r, &result, &one, mod, ninv);
}

void baseline_crt_sign(bigint512 *sig, const bigint512 *m,
                        const bigint512 *p, const bigint512 *q,
                        const bigint512 *dp, const bigint512 *dq,
                        const bigint512 *qinv) {
    bigint512 sp, sq;
    baseline_mod_exp(&sp, m, dp, p);
    baseline_mod_exp(&sq, m, dq, q);
    bigint_crt_combine(sig, &sp, &sq, p, q, qinv);
}
