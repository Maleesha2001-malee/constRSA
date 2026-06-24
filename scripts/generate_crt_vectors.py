"""
generate_crt_vectors.py
Generates a real (small, test-only) RSA-512-style keypair and computes
both the direct signature (m^d mod n) and the CRT-based signature
(via p, q, dp, dq, qinv + Garner recombination) so we can verify our
C implementation's CRT path against a known-correct reference.
"""

import random

def is_probable_prime(n, k=20):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29,31]:
        if n % p == 0: return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def to_limbs(x, num_limbs=8):
    limbs = []
    for _ in range(num_limbs):
        limbs.append(x & 0xFFFFFFFFFFFFFFFF)
        x >>= 64
    return limbs

def fmt_limbs(x):
    return ",".join(f"0x{l:016x}UL" for l in to_limbs(x))

if __name__ == "__main__":
    random.seed(42)  # reproducible test vector
    p = gen_prime(256)
    q = gen_prime(256)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)

    m = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef % n

    sig_direct = pow(m, d, n)

    sp = pow(m, dp, p)
    sq = pow(m, dq, q)
    h = (qinv * (sp - sq)) % p
    sig_crt = (sq + h * q) % n

    assert sig_direct == sig_crt, "sanity check failed!"

    print(f"static bigint512 p    = {{{{{fmt_limbs(p)}}}}};")
    print(f"static bigint512 q    = {{{{{fmt_limbs(q)}}}}};")
    print(f"static bigint512 dp   = {{{{{fmt_limbs(dp)}}}}};")
    print(f"static bigint512 dq   = {{{{{fmt_limbs(dq)}}}}};")
    print(f"static bigint512 qinv = {{{{{fmt_limbs(qinv)}}}}};")
    print(f"static bigint512 m    = {{{{{fmt_limbs(m)}}}}};")
    print(f"static bigint512 expected_sig = {{{{{fmt_limbs(sig_crt)}}}}};")
    print()
    print("n =", hex(n))
    print("sig (hex) =", hex(sig_crt))
