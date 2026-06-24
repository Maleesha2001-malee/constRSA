#include <stdio.h>
#include <string.h>
#include "../src/bigint.h"

static void print_limbs(const char *label, const bigint512 *x) {
    printf("%s = ", label);
    for (int i = LIMBS - 1; i >= 0; i--) printf("%016lx", x->v[i]);
    printf("\n");
}

static int limbs_equal(const bigint512 *a, const bigint512 *b) {
    for (int i = 0; i < LIMBS; i++) if (a->v[i] != b->v[i]) return 0;
    return 1;
}

int main(void) {
    bigint512 n = {{0xb0c1d2e3f405162dUL, 0x8394a5b6c7d8e9faUL,
                    0x8b1c2d3e4f506172UL, 0x0c3a1b2f4e5d6a79UL,
                    0,0,0,0}};
    bigint512 base = {{0xa00010427000020cUL, 0x831024164090a9c8UL,
                       0x8b10241648102140UL, 0x0012100648102a49UL,
                       0,0,0,0}};
    bigint512 exp = {{0x10001UL, 0,0,0,0,0,0,0}};
    bigint512 expected = {{0xc7656dd89fa79dccUL, 0x5409ea78e84f5310UL,
                           0xa9c9f509a7b67dcbUL, 0x0b9d9d382130b28dUL,
                           0,0,0,0}};

    bigint512 result;
    bigint_mod_exp_fixed_window(&result, &base, &exp, &n);

    print_limbs("got     ", &result);
    print_limbs("expected", &expected);

    if (limbs_equal(&result, &expected)) {
        printf("PASS: modular exponentiation matches reference (pow(base,exp,n))\n");
        return 0;
    } else {
        printf("FAIL: modular exponentiation does NOT match reference\n");
        return 1;
    }
}
