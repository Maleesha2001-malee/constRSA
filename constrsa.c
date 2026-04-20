#include <stdio.h>
#include <stdint.h>
#include <windows.h>

typedef uint64_t u64;

static inline u64 ct_select(int bit, u64 a, u64 b)
{
    u64 mask = -(u64)(unsigned int)bit;
    return (a & mask) | (b & ~mask);
}

static u64 mulmod(u64 a, u64 b, u64 m)
{
    return (__uint128_t)a * b % m;
}

u64 ct_mod_exp(u64 base, u64 exp, u64 n)
{
    u64 R = 1;
    u64 A = base % n;
    for (int i = 63; i >= 0; i--) {
        R = mulmod(R, R, n);
        u64 T = mulmod(R, A, n);
        int ebit = (int)((exp >> i) & 1u);
        R = ct_select(ebit, T, R);
    }
    return R;
}

u64 naive_mod_exp(u64 base, u64 exp, u64 n)
{
    u64 R = 1;
    u64 A = base % n;
    for (int i = 63; i >= 0; i--) {
        R = mulmod(R, R, n);
        if ((exp >> i) & 1u)
            R = mulmod(R, A, n);
    }
    return R;
}

static long long now_ns(void)
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (long long)(count.QuadPart * 1000000000LL / freq.QuadPart);
}

int main(void)
{
    u64 base  = 123456789ULL;
    u64 exp_fixed  = 987654321ULL;   /* fixed exponent  */
    u64 n     = 1000000007ULL;
    int RUNS  = 10000;

    FILE *fp = fopen("timing_data.csv", "w");
    if (!fp) {
        printf("ERROR: cannot open CSV file!\n");
        return 1;
    }

    /* CSV header */
    fprintf(fp, "run,input_type,implementation,time_ns\n");

    printf("Collecting timing data — please wait...\n");
    printf("Total measurements: %d\n\n", RUNS * 4);

    volatile u64 sink = 0;

    /* 1. Constant-time — FIXED exponent */
    for (int i = 0; i < RUNS; i++) {
        long long t1 = now_ns();
        sink ^= ct_mod_exp(base, exp_fixed, n);
        long long t2 = now_ns();
        fprintf(fp, "%d,fixed,ct,%lld\n", i, t2 - t1);
    }

    /* 2. Constant-time — RANDOM exponent */
    for (int i = 0; i < RUNS; i++) {
        u64 exp_rand = exp_fixed ^ ((u64)i * 6364136223846793005ULL);
        long long t1 = now_ns();
        sink ^= ct_mod_exp(base, exp_rand, n);
        long long t2 = now_ns();
        fprintf(fp, "%d,random,ct,%lld\n", i, t2 - t1);
    }

    /* 3. Naive — FIXED exponent */
    for (int i = 0; i < RUNS; i++) {
        long long t1 = now_ns();
        sink ^= naive_mod_exp(base, exp_fixed, n);
        long long t2 = now_ns();
        fprintf(fp, "%d,fixed,naive,%lld\n", i, t2 - t1);
    }

    /* 4. Naive — RANDOM exponent */
    for (int i = 0; i < RUNS; i++) {
        u64 exp_rand = exp_fixed ^ ((u64)i * 6364136223846793005ULL);
        long long t1 = now_ns();
        sink ^= naive_mod_exp(base, exp_rand, n);
        long long t2 = now_ns();
        fprintf(fp, "%d,random,naive,%lld\n", i, t2 - t1);
    }

    fclose(fp);

    printf("=== Done! ===\n");
    printf("CSV file saved: C:\\constrsa\\timing_data.csv\n");
    printf("Total rows: %d\n", RUNS * 4);
    printf("(sink=%llu)\n", sink);

    return 0;
}