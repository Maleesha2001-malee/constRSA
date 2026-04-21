# generate_data.py
# Pure Python RSA signature dataset generator

import csv
import random

print("Generating RSA signature dataset...")

# RSA key (same as C code)
p   = 999983
q   = 999979
n   = p * q
e   = 65537
phi = (p - 1) * (q - 1)

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

d  = mod_inverse(e, phi)
dp = d % (p - 1)
dq = d % (q - 1)

def simple_hash(msg):
    h = 14695981039346656037
    for c in msg.encode():
        h ^= c
        h = (h * 1099511628211) % (2**64)
    return h % n

def rsa_sign(msg):
    m  = simple_hash(msg)
    s1 = pow(m % p, dp, p)
    s2 = pow(m % q, dq, q)
    h  = ((s1 - s2 + p) * mod_inverse(q, p)) % p
    return (s2 + q * h) % n

def rsa_verify(msg_hash, sig):
    recovered = pow(sig, e, n)
    return 1 if recovered == msg_hash else 0

# Generate dataset
N = 10000
rows = []

print(f"Generating {N} valid signatures...")
for i in range(N):
    msg      = f"message_{i:05d}_constrsa"
    h        = simple_hash(msg)
    sig      = rsa_sign(msg)
    recovered = pow(sig, e, n)
    hash_matches = 1 if recovered == h else 0
    sig_in_range = 1 if sig < n else 0
    rows.append([h, sig, recovered, hash_matches, sig_in_range, 1])

print(f"Generating {N} invalid signatures...")
for i in range(N):
    msg       = f"message_{i:05d}_constrsa"
    h         = simple_hash(msg)
    fake_sig  = (h * 6364136223846793005 +
                 i * 1442695040888963407) % n
    recovered = pow(fake_sig, e, n)
    hash_matches = 1 if recovered == h else 0
    sig_in_range = 1 if fake_sig < n else 0
    rows.append([h, fake_sig, recovered, hash_matches, sig_in_range, 0])

# Save CSV
with open("data\\sig_dataset.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["msg_hash","signature","recovered_hash",
                     "hash_matches","sig_in_range","label"])
    writer.writerows(rows)

print(f"\nDataset saved: data\\sig_dataset.csv")
print(f"Total rows   : {len(rows)}")
print(f"Valid (1)    : {N}")
print(f"Invalid (0)  : {N}")