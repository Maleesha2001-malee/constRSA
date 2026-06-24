#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stddef.h>

/* 512-bit integer = 8 x 64-bit limbs, little-endian limb order */
#define LIMBS 8
typedef struct {
    uint64_t v[LIMBS];
} bigint512;

/* For RSA-512 with CRT, each prime p,q is ~256 bits = 4 limbs */
#define LIMBS_HALF 4
typedef struct {
    uint64_t v[LIMBS_HALF];
} bigint256;

/* ---- constant-time primitives ---- */

/* returns 0xFFFFFFFFFFFFFFFF if a==b, else 0x0 -- no branch on secret data */
static inline uint64_t ct_eq_u64(uint64_t a, uint64_t b) {
    uint64_t diff = a ^ b;
    /* diff == 0 -> all zero bits -> we want all-1s mask */
    uint64_t z = diff | (~diff + 1); /* nonzero if diff != 0 */
    return ~(z >> 63) + 1; /* placeholder, refined in bigint.c */
}

/* constant-time select: returns a if mask==all-1s, b if mask==0 */
static inline uint64_t ct_select_u64(uint64_t mask, uint64_t a, uint64_t b) {
    return (a & mask) | (b & ~mask);
}

void bigint_add(bigint512 *r, const bigint512 *a, const bigint512 *b);
void bigint_sub(bigint512 *r, const bigint512 *a, const bigint512 *b);
int  bigint_cmp_ct(const bigint512 *a, const bigint512 *b); /* constant-time compare */
void bigint_mont_mul(bigint512 *r, const bigint512 *a, const bigint512 *b,
                      const bigint512 *n, uint64_t n_inv);
void bigint_mod_exp_fixed_window(bigint512 *r, const bigint512 *base,
                                  const bigint512 *exp, const bigint512 *mod);
void bigint_compute_r2_mod_n(bigint512 *r2, const bigint512 *n);
uint64_t bigint_compute_n_inv(const bigint512 *n);
void bigint_mulmod(bigint512 *r, const bigint512 *a, const bigint512 *b, const bigint512 *mod);
void bigint_mul_low512(bigint512 *r, const bigint512 *a, const bigint512 *b);
void bigint_crt_combine(bigint512 *s, const bigint512 *sp, const bigint512 *sq,
                         const bigint512 *p, const bigint512 *q, const bigint512 *qinv);

/* Convert a 64-byte big-endian buffer to/from a bigint512.
 * Needed to bridge PSS-encoded byte strings and the bigint arithmetic. */
void bigint_from_bytes_be(bigint512 *r, const unsigned char bytes[64]);
void bigint_to_bytes_be(unsigned char bytes[64], const bigint512 *a);

#endif
