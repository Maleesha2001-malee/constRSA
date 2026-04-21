/*
 * sig_generator.c — ConstRSA Signature Dataset Generator
 * =======================================================
 * Generates:
 *   - 10,000 valid signatures   (label = 1)
 *   - 10,000 invalid signatures (label = 0)
 *
 * CSV columns:
 *   msg_hash, signature, verify_result, label
 *
 * verify_result = actual RSA verify output (1/0)
 * label         = ground truth (1=valid, 0=invalid)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

static inline u64 ct_select(int bit, u64 a, u64 b)
{
    u64 mask = -(u64)(unsigned int)bit;
    return (a & mask) | (b & ~mask);
}

static inline u64 mulmod(u64 a, u64 b, u64 m)
{
    return (u128)a * b % m;
}

u64 ct_mod_exp(u64 base, u64 exp, u64 n)
{
    u64 R = 1, A = base % n;
    for (int i = 63; i >= 0; i--) {
        R = mulmod(R, R, n);
        u64 T = mulmod(R, A, n);
        int ebit = (int)((exp >> i) & 1u);
        R = ct_select(ebit, T, R);
    }
    return R;
}

static long long ext_gcd(long long a, long long b,
                          long long *x, long long *y)
{
    if (b == 0) { *x=1; *y=0; return a; }
    long long x1, y1;
    long long g = ext_gcd(b, a%b, &x1, &y1);
    *x = y1; *y = x1-(a/b)*y1;
    return g;
}

static u64 mod_inverse(u64 e, u64 phi)
{
    long long x, y;
    ext_gcd((long long)e, (long long)phi, &x, &y);
    return (u64)((x%(long long)phi+
                  (long long)phi)%(long long)phi);
}

typedef struct { u64 n,e,d,p,q,dp,dq; } RSAKey;

void rsa_keygen(RSAKey *key, u64 p, u64 q)
{
    key->p=p; key->q=q; key->n=p*q; key->e=65537;
    u64 phi=(p-1)*(q-1);
    key->d=mod_inverse(key->e,phi);
    key->dp=key->d%(p-1);
    key->dq=key->d%(q-1);
}

static u64 simple_hash(const char *msg)
{
    u64 h=14695981039346656037ULL;
    while(*msg){
        h^=(u64)(unsigned char)*msg++;
        h*=1099511628211ULL;
    }
    return h;
}

u64 rsa_sign_ct(const char *msg, RSAKey *key)
{
    u64 m=simple_hash(msg)%key->n;
    u64 s1=ct_mod_exp(m%key->p,key->dp,key->p);
    u64 s2=ct_mod_exp(m%key->q,key->dq,key->q);
    u64 h=mulmod((s1-s2+key->p),
                  mod_inverse(key->q,key->p),key->p);
    return (s2+key->q*h)%key->n;
}

/*
 * rsa_verify_detail:
 * Returns verify result AND recovered hash
 */
int rsa_verify_detail(u64 msg_hash, u64 sig,
                       RSAKey *key, u64 *recovered)
{
    *recovered = ct_mod_exp(sig, key->e, key->n);
    return (*recovered == msg_hash % key->n) ? 1 : 0;
}

static void gen_msg(char *buf, int len, u64 seed)
{
    const char chars[]="abcdefghijklmnopqrstuvwxyz0123456789";
    u64 s=seed;
    for(int i=0;i<len-1;i++){
        s=s*6364136223846793005ULL+1442695040888963407ULL;
        buf[i]=chars[s%36];
    }
    buf[len-1]='\0';
}

int main(void)
{
    RSAKey key;
    rsa_keygen(&key, 999983ULL, 999979ULL);

    int N = 10000;

    FILE *fp = fopen("C:\\constrsa\\data\\sig_dataset.csv","w");
    if(!fp){ printf("ERROR!\n"); return 1; }

    /* CSV header */
    fprintf(fp, "msg_hash,signature,recovered_hash,"
                "hash_matches,sig_in_range,label\n");

    printf("Generating %d valid signatures...\n", N);

    char msg[20];
    u64 recovered;

    /* ── Valid signatures ── */
    for(int i=0; i<N; i++){
        gen_msg(msg, 16, (u64)i * 123456789ULL);
        u64 h   = simple_hash(msg) % key.n;
        u64 sig = rsa_sign_ct(msg, &key);
        int vr  = rsa_verify_detail(h, sig, &key, &recovered);

        /* Features:
         * msg_hash      — message hash
         * signature     — RSA signature
         * recovered_hash — s^e mod n
         * hash_matches  — recovered == msg_hash (1/0)
         * sig_in_range  — sig < n (1/0)
         * label         — 1 = valid
         */
        fprintf(fp, "%llu,%llu,%llu,%d,%d,1\n",
                h, sig, recovered, vr,
                (sig < key.n) ? 1 : 0);
    }

    printf("Generating %d invalid signatures...\n", N);

    /* ── Invalid signatures ── */
    for(int i=0; i<N; i++){
        gen_msg(msg, 16, (u64)i * 987654321ULL);
        u64 h = simple_hash(msg) % key.n;

        /* Random fake signature */
        u64 fake_sig = (h * 6364136223846793005ULL +
                        (u64)i * 1442695040888963407ULL)
                       % key.n;

        int vr = rsa_verify_detail(h, fake_sig,
                                    &key, &recovered);

        fprintf(fp, "%llu,%llu,%llu,%d,%d,0\n",
                h, fake_sig, recovered, vr,
                (fake_sig < key.n) ? 1 : 0);
    }

    fclose(fp);

    printf("\nDataset saved: data\\sig_dataset.csv\n");
    printf("Total: %d rows (valid: %d, invalid: %d)\n",
           N*2, N, N);
    printf("Columns: msg_hash, signature, recovered_hash,\n");
    printf("         hash_matches, sig_in_range, label\n");

    return 0;
}