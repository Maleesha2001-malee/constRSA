"""
generate_modexp_vectors.py
Generates a base^exp mod n test vector using Python's built-in pow(),
to verify bigint_mod_exp_fixed_window() in C.
"""

def to_limbs(x, num_limbs=8):
    limbs = []
    for _ in range(num_limbs):
        limbs.append(x & 0xFFFFFFFFFFFFFFFF)
        x >>= 64
    return limbs

if __name__ == "__main__":
    # same modulus as the Montgomery multiplication test, for consistency
    n = 0x0c3a1b2f4e5d6a798b1c2d3e4f5061728394a5b6c7d8e9fab0c1d2e3f405162d
    base = 0x12100648102a498b10241648102140831024164090a9c8a00010427000020c
    exp  = 0x10001  # 65537, typical RSA public exponent, small enough to be fast

    result = pow(base, exp, n)

    print("n.v    =", [hex(x) for x in to_limbs(n)])
    print("base.v =", [hex(x) for x in to_limbs(base)])
    print("exp.v  =", [hex(x) for x in to_limbs(exp)])
    print("result.v =", [hex(x) for x in to_limbs(result)])
    print()
    print("result (hex) =", hex(result))
