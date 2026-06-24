#ifndef BASELINE_H
#define BASELINE_H

#include "bigint.h"

/* Non-constant-time reference implementations, for performance and
 * correctness comparison only. See src/baseline.c for warnings. */
void baseline_mod_exp(bigint512 *r, const bigint512 *base, const bigint512 *exp,
                       const bigint512 *mod);

void baseline_crt_sign(bigint512 *sig, const bigint512 *m,
                        const bigint512 *p, const bigint512 *q,
                        const bigint512 *dp, const bigint512 *dq,
                        const bigint512 *qinv);

#endif
