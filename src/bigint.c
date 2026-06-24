#include "bigint.h"
#include <string.h>

/* All operations below avoid secret-dependent branches and secret-dependent
 * memory access. Loop bounds are fixed and public (always LIMBS iterations).
 */

/* constant-time addition with carry propagation, fixed number of limbs */
void bigint_add(bigint512 *r, const bigint512 *a, const bigint512 *b) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < LIMBS; i++) {
        unsigned __int128 sum = (unsigned __int128)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint64_t)sum;
        carry = sum >> 64; /* 0 or 1, not secret-dependent branch, just data flow */
    }
}

/* constant-time subtraction (a - b), borrow propagation.
 * Uses bit-masking instead of `if` so the executed instructions are
 * identical regardless of secret data values (no secret-dependent branch).
 */
void bigint_sub(bigint512 *r, const bigint512 *a, const bigint512 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < LIMBS; i++) {
        uint64_t ai = a->v[i], bi = b->v[i];
        uint64_t diff = ai - bi - borrow;
        /* borrow occurs iff ai < bi + borrow_in. Compute this without
         * branching using the standard trick:
         * borrow_out = ((~ai & bi) | (~(ai ^ bi) & diff)) >> 63
         * This is the classic constant-time subtract-with-borrow formula. */
        uint64_t borrow_out = ((~ai & bi) | (~(ai ^ bi) & diff)) >> 63;
        r->v[i] = diff;
        borrow = borrow_out;
    }
}

/* constant-time comparison: returns 1 if a>=b, 0 otherwise.
 * Computed via constant-time subtraction's final borrow flag --
 * no early exit, no secret-dependent branch, fixed loop bound. */
int bigint_cmp_ct(const bigint512 *a, const bigint512 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < LIMBS; i++) {
        uint64_t ai = a->v[i], bi = b->v[i];
        uint64_t diff = ai - bi - borrow;
        uint64_t borrow_out = ((~ai & bi) | (~(ai ^ bi) & diff)) >> 63;
        borrow = borrow_out;
    }
    /* borrow == 1 means a < b (a-b underflowed); we want a>=b */
    return (int)(1 - borrow);
}

/* Montgomery multiplication: r = a*b*R^-1 mod n
 * n_inv = -n^-1 mod 2^64 (precomputed)
 * This is the CIOS (Coarsely Integrated Operand Scanning) method,
 * written with fixed loop bounds and no secret-dependent branches.
 */
void bigint_mont_mul(bigint512 *r, const bigint512 *a, const bigint512 *b,
                      const bigint512 *n, uint64_t n_inv) {
    uint64_t t[LIMBS + 1] = {0};

    for (int i = 0; i < LIMBS; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            unsigned __int128 prod = (unsigned __int128)a->v[i] * b->v[j]
                                      + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[LIMBS] + carry;
        t[LIMBS] = (uint64_t)sum;

        uint64_t m = t[0] * n_inv; /* reduction factor, fixed-time multiply */
        carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            unsigned __int128 prod = (unsigned __int128)m * n->v[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        sum = (unsigned __int128)t[LIMBS] + carry;
        t[LIMBS] = (uint64_t)sum;

        /* shift t right by one limb */
        for (int j = 0; j < LIMBS; j++) t[j] = t[j + 1];
        t[LIMBS] = 0;
    }

    bigint512 result;
    memcpy(result.v, t, sizeof(uint64_t) * LIMBS);

    /* constant-time conditional subtraction of n, regardless of comparison
     * outcome both branches are computed and selected via mask */
    bigint512 reduced;
    bigint_sub(&reduced, &result, n);
    uint64_t ge_mask = (uint64_t)(0 - (uint64_t)bigint_cmp_ct(&result, n));
    for (int i = 0; i < LIMBS; i++) {
        r->v[i] = ct_select_u64(ge_mask, reduced.v[i], result.v[i]);
    }
}

/* ---- Montgomery context helpers ---- */

/* r = (2*a) mod n, constant-time (no branch on comparison outcome) */
static void mont_mod_double(bigint512 *r, const bigint512 *a, const bigint512 *n) {
    bigint512 doubled;
    uint64_t carry = 0;
    for (int i = 0; i < LIMBS; i++) {
        uint64_t bit = a->v[i] >> 63;
        doubled.v[i] = (a->v[i] << 1) | carry;
        carry = bit;
    }
    bigint512 reduced;
    bigint_sub(&reduced, &doubled, n);
    /* if doubled >= n (no extra carry-out limb needed since n < 2^512),
     * select reduced, else doubled. carry==1 means overflow past 512 bits,
     * which also implies doubled >= n. Both masks built without ternaries. */
    uint64_t carry_mask = (uint64_t)(0ULL - carry); /* 0 or ~0, no branch */
    uint64_t ge = (uint64_t)(0ULL - (uint64_t)bigint_cmp_ct(&doubled, n)) | carry_mask;
    for (int i = 0; i < LIMBS; i++) {
        r->v[i] = ct_select_u64(ge, reduced.v[i], doubled.v[i]);
    }
}

/* Computes R^2 mod n where R = 2^512, by repeated doubling of 1.
 * n is the (public) RSA modulus, so this loop's fixed 1024 iterations
 * are fine -- the modulus itself is not secret. */
void bigint_compute_r2_mod_n(bigint512 *r2, const bigint512 *n) {
    bigint512 acc;
    memset(acc.v, 0, sizeof(acc.v));
    acc.v[0] = 1;
    for (int i = 0; i < 1024; i++) {
        mont_mod_double(&acc, &acc, n);
    }
    memcpy(r2->v, acc.v, sizeof(acc.v));
}

/* n_inv = -n^-1 mod 2^64, via Newton's iteration (modulus n is public,
 * so ordinary branching here does not create a secret-dependent timing
 * channel). */
uint64_t bigint_compute_n_inv(const bigint512 *n) {
    uint64_t x = n->v[0];
    uint64_t y = 1;
    /* Newton's method for inverse mod 2^64: doubles correct bits each round */
    for (int i = 0; i < 6; i++) {
        y = y * (2 - x * y);
    }
    return (uint64_t)(0ULL - y); /* negate mod 2^64 */
}

/* Constant-time integer equality mask: returns all-1s if x==y, all-0s
 * otherwise, using only bitwise ops (no comparison operators that a
 * compiler might turn into a conditional branch / cmov-or-branch). */
static inline uint64_t ct_eq_mask64(uint64_t x, uint64_t y) {
    uint64_t diff = x ^ y;
    diff |= diff >> 32;
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    /* bit0 of diff is now 0 iff x==y, 1 otherwise */
    return (diff & 1) - 1; /* 0-1 = all-1s (equal); 1-1 = 0 (not equal) */
}

/* Constant-time table select: scans all 16 entries regardless of `index`,
 * so memory access pattern does not depend on secret window value. */
static void ct_table_select(bigint512 *out, const bigint512 table[16], int index) {
    memset(out->v, 0, sizeof(out->v));
    for (int i = 0; i < 16; i++) {
        uint64_t mask = ct_eq_mask64((uint64_t)i, (uint64_t)index);
        for (int j = 0; j < LIMBS; j++) {
            out->v[j] |= table[i].v[j] & mask;
        }
    }
}

/* r = (a + b) mod n, constant-time (analogous to mont_mod_double) */
static void mod_add(bigint512 *r, const bigint512 *a, const bigint512 *b, const bigint512 *n) {
    bigint512 sum;
    bigint_add(&sum, a, b);
    bigint512 reduced;
    bigint_sub(&reduced, &sum, n);
    uint64_t ge = (uint64_t)(0 - (uint64_t)bigint_cmp_ct(&sum, n));
    for (int i = 0; i < LIMBS; i++) {
        r->v[i] = ct_select_u64(ge, reduced.v[i], sum.v[i]);
    }
}

/* generic modular multiplication via double-and-add. Not Montgomery-based;
 * used for the small CRT-combination step (h = qinv*(sp-sq) mod p), which
 * runs only once per signature so performance is not critical here. */
void bigint_mulmod(bigint512 *r, const bigint512 *a, const bigint512 *b, const bigint512 *mod) {
    bigint512 result;
    memset(result.v, 0, sizeof(result.v));
    for (int limb = LIMBS - 1; limb >= 0; limb--) {
        for (int bit = 63; bit >= 0; bit--) {
            mod_add(&result, &result, &result, mod); /* double (mod) */

            /* CONSTANT-TIME: unconditional masked add instead of branching
             * on the bit -- this loop is used in bigint_crt_combine where
             * `b` may be qinv (a private key component), so branching on
             * its bits here would leak key material via timing. */
            uint64_t bit_mask = (uint64_t)(0ULL - ((b->v[limb] >> bit) & 1ULL));
            bigint512 addend;
            for (int k = 0; k < LIMBS; k++) {
                addend.v[k] = a->v[k] & bit_mask;
            }
            mod_add(&result, &result, &addend, mod);
        }
    }
    memcpy(r->v, result.v, sizeof(result.v));
}

/* plain (non-modular) multiply, keeping only the low 512 bits of the
 * product. Safe to use without reduction when the caller already knows
 * the true product fits in 512 bits (e.g. two ~256-bit CRT operands). */
void bigint_mul_low512(bigint512 *r, const bigint512 *a, const bigint512 *b) {
    uint64_t t[LIMBS] = {0};
    for (int i = 0; i < LIMBS; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < LIMBS - i; j++) {
            unsigned __int128 prod = (unsigned __int128)a->v[i] * b->v[j] + t[i+j] + carry;
            t[i+j] = (uint64_t)prod;
            carry = prod >> 64;
        }
    }
    memcpy(r->v, t, sizeof(t));
}

/* CRT recombination (Garner's formula):
 *   h = qinv * (sp - sq) mod p
 *   s = sq + h * q
 * sp = m^dp mod p, sq = m^dq mod q must be computed by the caller
 * (each via bigint_mod_exp_fixed_window). p, q, qinv are the standard
 * RSA-CRT private parameters. */
void bigint_crt_combine(bigint512 *s, const bigint512 *sp, const bigint512 *sq,
                         const bigint512 *p, const bigint512 *q, const bigint512 *qinv) {
    /* h_raw = (sp + p - sq), which lies in [0, 2p) since sp,sq in [0,p) */
    bigint512 padded;
    bigint_add(&padded, sp, p);
    bigint512 diff;
    bigint_sub(&diff, &padded, sq);

    bigint512 reduced;
    bigint_sub(&reduced, &diff, p);
    uint64_t ge_p = (uint64_t)(0 - (uint64_t)bigint_cmp_ct(&diff, p));
    bigint512 h_raw;
    for (int i = 0; i < LIMBS; i++) {
        h_raw.v[i] = ct_select_u64(ge_p, reduced.v[i], diff.v[i]);
    }

    bigint512 h;
    bigint_mulmod(&h, &h_raw, qinv, p);

    bigint512 hq;
    bigint_mul_low512(&hq, &h, q);

    bigint_add(s, sq, &hq);
}

/* bytes[0] is the most-significant byte (big-endian), matching how
 * RSA moduli and PSS-encoded messages are conventionally represented. */
void bigint_from_bytes_be(bigint512 *r, const unsigned char bytes[64]) {
    for (int limb = 0; limb < LIMBS; limb++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) {
            /* limb 0 = least significant = last 8 bytes of the buffer */
            v = (v << 8) | bytes[64 - (limb * 8) - 8 + b];
        }
        r->v[limb] = v;
    }
}

void bigint_to_bytes_be(unsigned char bytes[64], const bigint512 *a) {
    for (int limb = 0; limb < LIMBS; limb++) {
        uint64_t v = a->v[limb];
        for (int b = 7; b >= 0; b--) {
            bytes[64 - (limb * 8) - 8 + b] = (unsigned char)(v & 0xFF);
            v >>= 8;
        }
    }
}

/* Fixed-window (4-bit) constant-time modular exponentiation in Montgomery
 * domain. base, exp, mod, result are all ordinary (non-Montgomery) form;
 * conversion happens internally. */
void bigint_mod_exp_fixed_window(bigint512 *r, const bigint512 *base,
                                  const bigint512 *exp, const bigint512 *mod) {
    bigint512 r2modn;
    bigint_compute_r2_mod_n(&r2modn, mod);
    uint64_t ninv = bigint_compute_n_inv(mod);

    /* convert base to Montgomery form: base_m = base * R mod n */
    bigint512 base_m;
    bigint_mont_mul(&base_m, base, &r2modn, mod, ninv);

    /* table[0] = Mont(1) = R mod n */
    bigint512 one = {{1,0,0,0,0,0,0,0}};
    bigint512 table[16];
    bigint_mont_mul(&table[0], &one, &r2modn, mod, ninv);
    table[1] = base_m;
    for (int i = 2; i < 16; i++) {
        bigint_mont_mul(&table[i], &table[i-1], &base_m, mod, ninv);
    }

    bigint512 result = table[0];

    /* process exponent 4 bits at a time, MSB-first, fixed 128 windows
     * for a 512-bit exponent (no early termination on leading zero bits --
     * that would leak exponent bit-length). */
    for (int w = 127; w >= 0; w--) {
        /* square 4 times */
        for (int s = 0; s < 4; s++) {
            bigint512 sq;
            bigint_mont_mul(&sq, &result, &result, mod, ninv);
            result = sq;
        }
        /* extract 4-bit window value from exponent. Since 64 is divisible
         * by 4, a 4-bit window never straddles a limb boundary -- shift
         * always lands in {0,4,8,...,60}. */
        int bit_offset = w * 4;
        int limb_idx = bit_offset / 64;
        int shift = bit_offset % 64;
        uint64_t window = (exp->v[limb_idx] >> shift) & 0xF;

        bigint512 multiplicand;
        ct_table_select(&multiplicand, table, (int)window);

        bigint512 multiplied;
        bigint_mont_mul(&multiplied, &result, &multiplicand, mod, ninv);
        result = multiplied;
    }

    /* convert result out of Montgomery form: result * 1 * Rinv mod n */
    bigint_mont_mul(r, &result, &one, mod, ninv);
}
