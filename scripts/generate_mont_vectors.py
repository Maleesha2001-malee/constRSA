"""
generate_mont_vectors.py

Generates known-answer test vectors for Montgomery multiplication so we
can verify bigint_mont_mul() in C is mathematically correct.

Montgomery multiplication computes: result = (a * b * R^-1) mod n
where R = 2^512 (since our bigint is 8 x 64-bit limbs = 512 bits).

Run:
    python3 generate_mont_vectors.py
"""

R_BITS = 512
R = 1 << R_BITS

def modinv(a, m):
    """Extended Euclidean algorithm for modular inverse."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("no inverse exists")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

def mont_mul_reference(a, b, n):
    """Direct mathematical definition, used as ground truth."""
    r_inv = modinv(R, n)
    return (a * b * r_inv) % n

def to_limbs(x, num_limbs=8):
    """Split big integer into 64-bit limbs, little-endian, for C struct init."""
    limbs = []
    for _ in range(num_limbs):
        limbs.append(x & 0xFFFFFFFFFFFFFFFF)
        x >>= 64
    return limbs

def n_inv_neg(n):
    """n_inv = -n^-1 mod 2^64, used inside CIOS Montgomery multiplication."""
    inv = modinv(n, 1 << 64)
    return (-inv) % (1 << 64)

if __name__ == "__main__":
    # A small worked example with a real-looking 512-bit-ish odd modulus.
    # n must be odd (true for RSA moduli, product of two odd primes).
    n = 0xC3A1B2F4E5D6A798B1C2D3E4F5061728394A5B6C7D8E9FAB0C1D2E3F405162D \
        & ((1 << 512) - 1) | 1  # force odd just in case

    a = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD & (n - 1)
    b = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA09876543 & (n - 1)

    expected = mont_mul_reference(a, b, n)
    ninv = n_inv_neg(n)

    print("n       =", hex(n))
    print("a       =", hex(a))
    print("b       =", hex(b))
    print("n_inv   =", hex(ninv), " (pass this as n_inv to bigint_mont_mul)")
    print("expected mont_mul(a,b,n) =", hex(expected))
    print()
    print("C limb arrays (little-endian, v[0] = lowest 64 bits):")
    print("n.v =", [hex(x) for x in to_limbs(n)])
    print("a.v =", [hex(x) for x in to_limbs(a)])
    print("b.v =", [hex(x) for x in to_limbs(b)])
    print("expected.v =", [hex(x) for x in to_limbs(expected)])
