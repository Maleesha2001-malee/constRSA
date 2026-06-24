#include "rsa_sign.h"
#include "pss.h"
#include <string.h>

void rsa_sign(const unsigned char *msg, size_t msg_len,
              const rsa_private_key *key, unsigned char sig_out[64]) {
    unsigned char mHash[HASH_LEN];
    sha256(msg, msg_len, mHash);

    unsigned char em[EM_LEN];
    pss_encode(mHash, em);

    bigint512 m;
    bigint_from_bytes_be(&m, em);

    bigint512 sp, sq, sig;
    bigint_mod_exp_fixed_window(&sp, &m, &key->dp, &key->p);
    bigint_mod_exp_fixed_window(&sq, &m, &key->dq, &key->q);
    bigint_crt_combine(&sig, &sp, &sq, &key->p, &key->q, &key->qinv);

    bigint_to_bytes_be(sig_out, &sig);
}

int rsa_verify(const unsigned char *msg, size_t msg_len,
               const unsigned char sig[64], const rsa_public_key *key) {
    bigint512 s;
    bigint_from_bytes_be(&s, sig);

    bigint512 m;
    bigint_mod_exp_fixed_window(&m, &s, &key->e, &key->n);

    unsigned char em[EM_LEN];
    bigint_to_bytes_be(em, &m);

    unsigned char mHash[HASH_LEN];
    sha256(msg, msg_len, mHash);

    return pss_verify(mHash, em);
}
