#ifndef RSA_SIGN_H
#define RSA_SIGN_H

#include "bigint.h"

typedef struct {
    bigint512 p, q, dp, dq, qinv;  /* CRT private key components */
} rsa_private_key;

typedef struct {
    bigint512 n;       /* modulus */
    bigint512 e;       /* public exponent, typically 65537 */
} rsa_public_key;

/* Signs `msg` (arbitrary length) with RSA-PSS (SHA-256, salt length 0).
 * Writes a 64-byte signature to sig_out. */
void rsa_sign(const unsigned char *msg, size_t msg_len,
              const rsa_private_key *key, unsigned char sig_out[64]);

/* Verifies a 64-byte signature against msg using the public key.
 * Returns 1 if valid, 0 if invalid. */
int rsa_verify(const unsigned char *msg, size_t msg_len,
               const unsigned char sig[64], const rsa_public_key *key);

#endif
