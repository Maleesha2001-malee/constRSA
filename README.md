# ConstRSA

**Design and Statistical Validation of a Minimal Constant-Time RSA-512 Digital Signature on Standard Consumer Laptops**

> Research project — Bachelor of Science Honours in Information Technology  
> Department of Physical Science, Faculty of Applied Science, University of Vavuniya, Sri Lanka

| | |
|---|---|
| **Author** | R.M.S. Rathnayake (2020/ICT/47) |
| **Supervisors** | Mr. B. Yogarajah · Dr. S. Kirushanth · Mr. K. Mathanaharan |
| **University** | University of Vavuniya, Sri Lanka |

---

## Research Aim

To design, implement, and statistically validate a minimal constant-time RSA-512 digital signature (RSA-PSS with SHA-256) that eliminates secret-dependent timing leakage, verified using Welch's t-test on standard consumer laptops.

**Research Questions:**
- **RQ1** — How can RSA-512 signing be engineered to avoid secret-dependent control flow?
- **RQ2** — Does the implementation exhibit statistically significant timing leakage?
- **RQ3** — What is the performance overhead of constant-time engineering vs. a naive baseline?

---

## Key Results

| Metric | Value | Interpretation |
|---|---|---|
| CT timing p-value | **0.607** | No timing leak detected (p > 0.05) ✓ |
| Naive timing p-value | **≈ 0.000** | Timing leak confirmed ✓ |
| CT vs Naive timing diff | **0.17 ns** | Negligible difference |
| Naive timing diff | **225.9 ns** | Measurable secret-dependent gap |
| CT overhead | **+49.8%** | Cost of constant-time safety |
| ML leak detector accuracy | **99.8%** | CT vs Naive distinguishable by ML |
| ML signature verifier accuracy | **100%** | Valid vs invalid signatures |
| 512-bit RSA-PSS p-value | **0.083** | No leak in real OpenSSL RSA-512 |

---

## Constant-Time Design

The core guarantee: **execution time does not depend on secret key bits.**

```c
// Branchless selection — no if-statement on secret data
static inline u64 ct_select(int bit, u64 a, u64 b) {
    u64 mask = -(u64)(unsigned int)bit;
    return (a & mask) | (b & ~mask);
}

// Square-and-multiply-always — always squares, always multiplies
// ct_select picks the result — no branch on exponent bit
u64 ct_mod_exp(u64 base, u64 exp, u64 n) {
    u64 R = 1, A = base % n;
    for (int i = 63; i >= 0; i--) {
        R = mulmod(R, R, n);          // always square
        u64 T = mulmod(R, A, n);      // always multiply
        int ebit = (exp >> i) & 1u;
        R = ct_select(ebit, T, R);    // branchless select
    }
    return R;
}
```

**Guarantees:**
- No secret-dependent branches
- No secret-dependent memory access
- Result selection via arithmetic masking only
- CRT optimization for signing speed

---

## Repository Structure

```
constrsa/
├── src/
│   ├── constrsa.c          # Core constant-time RSA implementation
│   ├── rsa512_openssl.c    # Real 512-bit RSA-PSS via OpenSSL
│   └── sig_generator.c     # Signature dataset generator (C)
├── tests/
│   ├── analysis.py         # Welch's t-test timing analysis
│   ├── analysis_512.py     # 512-bit timing analysis
│   ├── ml_analysis.py      # ML timing leak detector
│   ├── sig_ml.py           # ML signature verifier
│   ├── full_pipeline.py    # End-to-end pipeline
│   ├── generate_data.py    # Python dataset generator
│   └── verify_test.c       # Signature verification tests
├── data/
│   ├── timing_data.csv     # 200,000 timing observations (CT + Naive)
│   ├── timing_512.csv      # 10,000 observations (real RSA-512)
│   ├── sig_dataset.csv     # 20,000 signatures (valid + invalid)
│   ├── ml_results.csv      # ML timing leak detector metrics
│   ├── sig_ml_results.csv  # ML signature verifier metrics
│   └── pipeline_results.csv # Final combined results
├── docs/
│   └── timing_chart.png    # Timing distribution visualization
└── README.md
```

---

## How to Build and Run

### Requirements

- GCC or Clang (C99 or later)
- Python 3.8+ with `pandas`, `scipy`, `scikit-learn`, `matplotlib`
- OpenSSL (for `rsa512_openssl.c` only)

### Core Implementation (Windows)

```bash
gcc -O2 -o constrsa src/constrsa.c
./constrsa
# Output: timing_data.csv in data/
```

### Real 512-bit RSA-PSS (OpenSSL required)

```bash
gcc -O2 -o rsa512 src/rsa512_openssl.c -lssl -lcrypto
./rsa512
# Output: timing_512.csv in data/
```

### Signature Verification Tests

```bash
gcc -O2 -o verify_test tests/verify_test.c
./verify_test
# Expected: All 10/10 tests PASS
```

---

## How to Run Analysis

### Welch's t-test — Timing Leak Detection

```bash
python tests/analysis.py
# Output: CT p=0.607 (no leak), Naive p≈0 (leak confirmed)
```

### 512-bit Timing Analysis

```bash
python tests/analysis_512.py
```

### ML Timing Leak Detector

```bash
python tests/ml_analysis.py
# Output: 99.8% accuracy distinguishing CT vs Naive
```

### ML Signature Verifier

```bash
python tests/sig_ml.py
# Output: 100% accuracy on valid vs invalid signatures
```

### Full End-to-End Pipeline

```bash
python tests/full_pipeline.py
# Output: pipeline_results.csv with all metrics
```

---

## End-to-End Pipeline

```
RSA Key Generation
       │
       ├──────────────────────┐
       ▼                      ▼
  CT Signing            Naive Signing
  (branchless)          (if-branch leak)
       │                      │
       ▼                      ▼
 Timing × 50,000        Timing × 50,000
 fixed + random         fixed + random
       │                      │
       └──────────┬───────────┘
                  ▼
           timing_data.csv
           (200,000 rows)
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
  Welch's t-test       ML Leak Detector
  CT p=0.607 ✓         99.8% accuracy
  Naive p≈0 ✗
        │                    │
        └─────────┬──────────┘
                  ▼
         ML Signature Verifier
           100% accuracy
                  │
                  ▼
        pipeline_results.csv
```

---

## References

1. Aldaya & Brumley (2020). *When one vulnerable primitive turns viral: Novel single-trace attacks on ECDSA and RSA*. TCHES.
2. Luo, Fei & Kaeli (2019). *Side-channel timing attack of RSA on a GPU*. ACM TACO.
3. Luo, Fei & Kaeli (2018). *GPU acceleration of RSA is vulnerable to side-channel timing attacks*. ICCAD.
4. Kou et al. (2023). *Cache side-channel attacks and defenses of the sliding window algorithm in TEEs*. DATE.
5. Ding (2024). *Analyzing the research and application of the RSA cryptosystem in the context of digital signatures*. TCSISR.

---

## License

This project is released for academic and educational purposes.  
© 2025 R.M.S. Rathnayake, University of Vavuniya, Sri Lanka.
