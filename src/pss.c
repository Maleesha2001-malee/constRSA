#include "pss.h"
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

void sha256(const unsigned char *data, size_t len, unsigned char out[HASH_LEN]) {
    SHA256(data, len, out);
}

void mgf1_sha256(const unsigned char *seed, size_t seed_len,
                  unsigned char *mask, size_t mask_len) {
    uint32_t counter = 0;
    size_t produced = 0;
    unsigned char *buf = malloc(seed_len + 4);
    memcpy(buf, seed, seed_len);

    while (produced < mask_len) {
        buf[seed_len + 0] = (unsigned char)((counter >> 24) & 0xFF);
        buf[seed_len + 1] = (unsigned char)((counter >> 16) & 0xFF);
        buf[seed_len + 2] = (unsigned char)((counter >> 8) & 0xFF);
        buf[seed_len + 3] = (unsigned char)(counter & 0xFF);

        unsigned char digest[HASH_LEN];
        sha256(buf, seed_len + 4, digest);

        size_t chunk = (mask_len - produced) < HASH_LEN ? (mask_len - produced) : HASH_LEN;
        memcpy(mask + produced, digest, chunk);
        produced += chunk;
        counter++;
    }
    free(buf);
}

/* EMSA-PSS-ENCODE, salt length = 0 (deterministic variant, RFC 8017 9.1.1).
 * emLen = EM_LEN = 64, hLen = HASH_LEN = 32, sLen = 0.
 * DB length = emLen - hLen - 1 = 31
 * PS length = emLen - sLen - hLen - 2 = 30 zero bytes
 */
void pss_encode(const unsigned char mHash[HASH_LEN], unsigned char em_out[EM_LEN]) {
    const size_t db_len = EM_LEN - HASH_LEN - 1; /* 31 */

    /* M' = 8 zero bytes || mHash || salt(empty) */
    unsigned char mprime[8 + HASH_LEN];
    memset(mprime, 0, 8);
    memcpy(mprime + 8, mHash, HASH_LEN);

    unsigned char H[HASH_LEN];
    sha256(mprime, sizeof(mprime), H);

    /* DB = PS(zeros) || 0x01 || salt(empty) */
    unsigned char DB[64]; /* db_len <= 64, safe upper bound */
    memset(DB, 0, db_len - 1);
    DB[db_len - 1] = 0x01;

    unsigned char dbMask[64];
    mgf1_sha256(H, HASH_LEN, dbMask, db_len);

    unsigned char maskedDB[64];
    for (size_t i = 0; i < db_len; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    /* clear leftmost bit: emBits = modBits-1 = 511, emLen*8=512,
     * so exactly 1 extra bit must be zeroed in the first byte */
    maskedDB[0] &= 0x7F;

    memcpy(em_out, maskedDB, db_len);
    memcpy(em_out + db_len, H, HASH_LEN);
    em_out[EM_LEN - 1] = 0xBC;
}

int pss_verify(const unsigned char mHash[HASH_LEN], const unsigned char em[EM_LEN]) {
    const size_t db_len = EM_LEN - HASH_LEN - 1; /* 31 */

    if (em[EM_LEN - 1] != 0xBC) return 0;

    unsigned char maskedDB[64];
    memcpy(maskedDB, em, db_len);
    unsigned char H[HASH_LEN];
    memcpy(H, em + db_len, HASH_LEN);

    if (maskedDB[0] & 0x80) return 0; /* leftmost bit must be zero */

    unsigned char dbMask[64];
    mgf1_sha256(H, HASH_LEN, dbMask, db_len);

    unsigned char DB[64];
    for (size_t i = 0; i < db_len; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }
    DB[0] &= 0x7F; /* matches the bit we cleared during masking */

    /* DB should be: zeros (db_len-1 of them) || 0x01 */
    for (size_t i = 0; i < db_len - 1; i++) {
        if (DB[i] != 0) return 0;
    }
    if (DB[db_len - 1] != 0x01) return 0;

    /* M' = 8 zero bytes || mHash || salt(empty) */
    unsigned char mprime[8 + HASH_LEN];
    memset(mprime, 0, 8);
    memcpy(mprime + 8, mHash, HASH_LEN);

    unsigned char H_check[HASH_LEN];
    sha256(mprime, sizeof(mprime), H_check);

    return memcmp(H, H_check, HASH_LEN) == 0;
}
