#ifndef PSS_H
#define PSS_H

#include <stddef.h>
#include <stdint.h>

#define HASH_LEN 32   /* SHA-256 output size */
#define EM_LEN   64   /* RSA-512 modulus size in bytes */

/* SHA-256 wrapper (OpenSSL one-shot). out must have HASH_LEN bytes. */
void sha256(const unsigned char *data, size_t len, unsigned char out[HASH_LEN]);

/* MGF1 mask generation function based on SHA-256, per RFC 8017 Appendix B.2.1 */
void mgf1_sha256(const unsigned char *seed, size_t seed_len,
                  unsigned char *mask, size_t mask_len);

/* EMSA-PSS-ENCODE with salt length 0 (deterministic), RFC 8017 9.1.1.
 * mHash must be HASH_LEN bytes (already hashed message).
 * em_out must have EM_LEN bytes. */
void pss_encode(const unsigned char mHash[HASH_LEN], unsigned char em_out[EM_LEN]);

/* EMSA-PSS-VERIFY: returns 1 if valid, 0 if invalid. */
int pss_verify(const unsigned char mHash[HASH_LEN], const unsigned char em[EM_LEN]);

#endif
