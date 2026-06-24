#include <stdio.h>
#include <string.h>
#include "../src/bigint.h"

static void print_bigint(const char *label, const bigint512 *x) {
    printf("%s = ", label);
    for (int i = LIMBS - 1; i >= 0; i--) printf("%016lx", x->v[i]);
    printf("\n");
}

int main(void) {
    bigint512 a = {{1, 0, 0, 0, 0, 0, 0, 0}};
    bigint512 b = {{2, 0, 0, 0, 0, 0, 0, 0}};
    bigint512 r;

    bigint_add(&r, &a, &b);
    print_bigint("a+b", &r);
    if (r.v[0] != 3) { printf("FAIL: add\n"); return 1; }

    bigint_sub(&r, &b, &a);
    print_bigint("b-a", &r);
    if (r.v[0] != 1) { printf("FAIL: sub\n"); return 1; }

    /* test constant-time comparison */
    if (bigint_cmp_ct(&b, &a) != 1) { printf("FAIL: cmp (b>=a should be true)\n"); return 1; }
    if (bigint_cmp_ct(&a, &b) != 0) { printf("FAIL: cmp (a>=b should be false)\n"); return 1; }
    if (bigint_cmp_ct(&a, &a) != 1) { printf("FAIL: cmp (a>=a should be true)\n"); return 1; }
    printf("Comparison tests passed.\n");

    printf("All basic tests passed.\n");
    printf("NOTE: Montgomery multiplication and modular exponentiation\n");
    printf("still need full test vectors against a known RSA-512 reference\n");
    printf("(e.g. cross-check against Python's pow(base, exp, mod)).\n");
    return 0;
}
