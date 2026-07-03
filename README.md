# ConstRSA — Minimal Constant-Time RSA-512 Signature

Research artifact for: *ConstRSA: A Minimal Constant-Time RSA-512 Digital
Signature with Statistical Timing-Leak Verification on Standard Laptops*

## Build

```bash
sudo apt update
sudo apt install build-essential libssl-dev python3-pip
pip install pandas scipy --break-system-packages

sudo apt-get install -y tmux   # if not already installed
tmux new -s constrsa
cd ~/Downloads/constRSA-main


make clean
make
./bigint_test
./mont_test
./modexp_test
./crt_test
./rsa_roundtrip_test
./baseline_test

./interleaved_timing_harness 100000 > data/timing_data.csv            #run the Timing Experiment (the main research part)
python3 scripts/analyze_timing.py data/timing_data.csv

./document_timing_harness data/corpus 50000 > data/timing_data_docs.csv   #Document-based timing experiment
python3 scripts/analyze_timing.py data/timing_data_docs.csv

echo "run,impl,time_ns" > data/benchmark_data.csv      # Run the Performance Benchmark
./benchmark_compare >> data/benchmark_data.csv
python3 scripts/analyze_benchmark.py data/benchmark_data.csv

chmod +x run_1000_combined.sh
./run_1000_combined.sh
```

## Status (honest checklist — update as you go)

- [x] Project structure
- [x] bigint.h / bigint.c — add, sub, constant-time compare, Montgomery
      multiplication skeleton
- [x] **Montgomery multiplication — VERIFIED against Python reference
      vectors** (see `scripts/generate_mont_vectors.py` and
      `tests/test_mont_mul.c`) — PASS
- [x] **bigint_sub / bigint_cmp_ct rewritten as constant-time** using
      mask-based borrow propagation (no `if`/ternary on secret data)
- [x] Fixed-window modular exponentiation — implemented and VERIFIED
      against Python `pow(base, exp, n)` (see `tests/test_modexp.c`):
  - [x] Montgomery context setup (R² mod n via repeated doubling, n_inv
        via Newton's iteration)
  - [x] Precomputed 16-entry window table
  - [x] Constant-time table lookup (scans all 16 entries every time)
  - [x] **HARDENED**: `ct_table_select`'s equality check was rewritten as
        a pure bitwise mask (`ct_eq_mask64`) instead of `(i==index)?:`,
        because the original real-world experiment on this exact code
        detected statistically significant timing leakage (Welch's
        t-test, p < 0.001) that traced back to this comparison being
        compiler-dependent on whether it became a branch or a cmov.
        Re-run the timing experiment after pulling this fix.
- [x] CRT signing (dp, dq, qinv, Garner recombination) — VERIFIED with a
      real, freshly-generated 512-bit RSA keypair against Python's
      `pow(m, d, n)` (see `scripts/generate_crt_vectors.py` and
      `tests/test_crt_sign.c`). This is the core "sign a message" pipeline
      working end-to-end on real key material.
- [x] RSA-PSS encoding (RFC 8017) + SHA-256 via libcrypto — implemented
      with salt length 0 (deterministic PSS), the maximum salt length
      that standard PSS allows is not available for RSA-512 + SHA-256
      (modulus is too small: needs >= 2*hLen+2 = 66 bytes, we only have
      64). This is a real, documented constraint of using RSA-512 with
      SHA-256-based PSS, not a shortcut — flag this clearly in the
      thesis writeup. See `src/pss.c`, `src/rsa_sign.c`.
  - [x] Full sign+verify round trip implemented (`tests/test_rsa_roundtrip.c`)
        — needs to be run on your machine (sandbox has no libcrypto)
  - [x] Byte<->bigint conversion logic verified directly in sandbox
- [x] Baseline (non-constant-time) reference implementation — uses the
      SAME Montgomery+windowing algorithm as the constant-time version,
      differing only in: (1) conditional subtraction via real `if`
      instead of mask-select, (2) direct table[window] indexing instead
      of scanning all 16 entries. This is the correct comparison for
      RQ3 (algorithmic differences would otherwise confound the result).
      Correctness verified identical to constant-time output.
- [x] Real timing harness (`src/real_timing_harness.c`) — uses the
      actual constant-time CRT sign function, not a placeholder
- [x] Performance benchmark (`src/benchmark_compare.c` +
      `scripts/analyze_benchmark.py`) — measures constant-time vs
      baseline overhead under identical conditions
- [x] Welch's t-test analysis script (`scripts/analyze_timing.py`)
  - [x] **HARDENED (2nd pass)**: `bigint_mulmod` (used inside
        `bigint_crt_combine` for `h = qinv * h_raw mod p`) had a real
        `if` branch on bits of its second operand -- since that operand
        is `qinv`, a private key component, this leaked key-dependent
        timing. Replaced with an unconditional masked add. Also cleaned
        up two unnecessary ternaries in `mont_mod_double` (operates only
        on the public modulus, so not a secret leak, but inconsistent
        with the rest of the constant-time style).
- [ ] Run full 100k+ sample experiments on real hardware
- [ ] Performance benchmark tables (constant-time vs baseline)
- [ ] Write-up / docs / publish to GitHub

## Running the timing experiment (RQ2 -- leakage test)

**Use the interleaved harness, not the block harness.** Running all
fixed samples then all random samples (the original `real_timing_harness`)
showed a consistent variance asymmetry (fixed variance several times
higher than random) across BOTH WSL and bare-metal live-USB runs --
this is a measurement-order confound (system settling after boot,
background services, thermal ramp-up), not a property of the crypto
code. `interleaved_timing_harness` alternates fixed/random measurements
one at a time, cancelling this out.

```bash
make
./interleaved_timing_harness 100000 > data/timing_data.csv
python3 scripts/analyze_timing.py data/timing_data.csv
```

## Running the timing experiment with REAL documents (per supervisor request)

Instead of synthetic random bytes, this variant signs actual files
(PDF, text, email, etc.) from a corpus directory. "fixed" = the same
single real document every time; "random"/"varied" = cycling through
the other real documents in the corpus.

```bash
mkdir -p data/corpus
# Copy 5-10 real files into data/corpus/ (PDFs, emails, text files --
# similar sizes if possible, to reduce unrelated size-driven variance)
cp /path/to/some/*.pdf data/corpus/

make
./document_timing_harness data/corpus 50000 > data/timing_data_docs.csv
python3 scripts/analyze_timing.py data/timing_data_docs.csv
```

Note: signing time legitimately scales with document size (SHA-256
hashing cost depends on public message length, not secret key bits).
This is expected and not a side-channel concern -- but using similarly
sized documents reduces irrelevant noise and makes the fixed-vs-varied
comparison cleaner.

## Running the performance benchmark (RQ3 -- constant-time overhead)

```bash
echo "run,impl,time_ns" > data/benchmark_data.csv
./benchmark_compare >> data/benchmark_data.csv
python3 scripts/analyze_benchmark.py data/benchmark_data.csv
```

## Important note on correctness vs constant-time

Get the algorithm **mathematically correct first** (test against known
RSA-512 vectors), **then** harden for constant-time, **then** measure.
Doing them in this order avoids debugging crypto bugs and timing
artifacts at the same time.

## Note on the "under 10 KB" target

The proposal's <10 KB target should be understood as the **core RSA
arithmetic engine** (`bigint.c` + `rsa_sign.c`, the Montgomery
multiplication / fixed-window exponentiation / CRT signing logic),
which is what RQ1 is actually about. Compiled object sizes:

| File | Size |
|---|---|
| bigint.c (source) | ~13 KB |
| bigint.o (compiled) | ~4.4 KB |
| rsa_sign.c + rsa_sign.o | ~1 KB / 0.6 KB |
| pss.c (PSS+MGF1, source) | ~3.4 KB |

The PSS/SHA-256 padding layer is a standard, well-understood building
block (not the novel/auditable part of this project) and pulls in
OpenSSL's SHA-256, so it's reasonable to scope the <10 KB claim to the
RSA arithmetic core specifically. State this scoping explicitly in the
thesis to avoid an examiner question.

## Known limitations to disclose in the thesis (do not hide these --
## naming them explicitly is a sign of rigor, not weakness)

1. **PSS salt length = 0** (deterministic), because RSA-512 + SHA-256
   doesn't have room for a full 32-byte salt (needs >=66 bytes,
   modulus is only 64). This is a real, documented RSA-512 + SHA-256
   constraint, not a shortcut.
2. **Timing messages use `rand()` seeded with a fixed seed (12345)**,
   i.e. pseudorandom, not cryptographically random. Fine for a timing
   experiment (you're testing execution time, not key secrecy), but
   say so explicitly if asked.
3. **WSL2 is a virtualized environment.** Development and debugging
   were done there; final timing numbers reported in the thesis should
   come from a bare-metal run (see below) since virtualization adds
   scheduling noise that isn't representative of the "commodity laptop"
   threat model the proposal describes.
