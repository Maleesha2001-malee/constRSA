import pandas as pd
from scipy import stats
import matplotlib.pyplot as plt
import numpy as np

# ── Data load කරන්න ──
df = pd.read_csv("C:\\constrsa\\timing_data.csv")
print(f"Total rows: {len(df)}")
print(df.head(10))

# ── Outliers ඉවත් කරන්න (top 1%) ──
df = df[df["time_ns"] < df["time_ns"].quantile(0.99)]

# ── Constant-time: fixed vs random ──
ct_fixed  = df[(df["implementation"]=="ct") & (df["input_type"]=="fixed")]["time_ns"]
ct_random = df[(df["implementation"]=="ct") & (df["input_type"]=="random")]["time_ns"]

# ── Naive: fixed vs random ──
nv_fixed  = df[(df["implementation"]=="naive") & (df["input_type"]=="fixed")]["time_ns"]
nv_random = df[(df["implementation"]=="naive") & (df["input_type"]=="random")]["time_ns"]

# ── Welch's t-test ──
ct_t, ct_p = stats.ttest_ind(ct_fixed, ct_random, equal_var=False)
nv_t, nv_p = stats.ttest_ind(nv_fixed, nv_random, equal_var=False)

print("\n=== Welch's t-test Results ===")
print(f"\nConstant-time implementation:")
print(f"  t-statistic : {ct_t:.4f}")
print(f"  p-value     : {ct_p:.6f}")
if ct_p > 0.05:
    print(f"  Result      : NO timing leak detected (p > 0.05) ✓")
else:
    print(f"  Result      : Timing leak DETECTED (p < 0.05) ✗")

print(f"\nNaive implementation:")
print(f"  t-statistic : {nv_t:.4f}")
print(f"  p-value     : {nv_p:.6f}")
if nv_p < 0.05:
    print(f"  Result      : Timing leak DETECTED (p < 0.05) ✗")
else:
    print(f"  Result      : No timing leak detected (p > 0.05) ✓")

# ── Statistics Summary ──
print("\n=== Timing Statistics (ns) ===")
print(f"{'':30s} {'Mean':>10} {'Median':>10} {'Std':>10}")
print(f"{'CT Fixed':30s} {ct_fixed.mean():>10.1f} {ct_fixed.median():>10.1f} {ct_fixed.std():>10.1f}")
print(f"{'CT Random':30s} {ct_random.mean():>10.1f} {ct_random.median():>10.1f} {ct_random.std():>10.1f}")
print(f"{'Naive Fixed':30s} {nv_fixed.mean():>10.1f} {nv_fixed.median():>10.1f} {nv_fixed.std():>10.1f}")
print(f"{'Naive Random':30s} {nv_random.mean():>10.1f} {nv_random.median():>10.1f} {nv_random.std():>10.1f}")

# ── Chart එක හදන්න ──
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("ConstRSA: Timing Distribution — Fixed vs Random Input", fontsize=13)

# Constant-time chart
axes[0].hist(ct_fixed,  bins=50, alpha=0.6, color="steelblue", label="Fixed")
axes[0].hist(ct_random, bins=50, alpha=0.6, color="coral",     label="Random")
axes[0].set_title(f"Constant-time\np = {ct_p:.6f}")
axes[0].set_xlabel("Time (ns)")
axes[0].set_ylabel("Count")
axes[0].legend()

# Naive chart
axes[1].hist(nv_fixed,  bins=50, alpha=0.6, color="steelblue", label="Fixed")
axes[1].hist(nv_random, bins=50, alpha=0.6, color="coral",     label="Random")
axes[1].set_title(f"Naive (insecure)\np = {nv_p:.6f}")
axes[1].set_xlabel("Time (ns)")
axes[1].set_ylabel("Count")
axes[1].legend()

plt.tight_layout()
plt.savefig("C:\\constrsa\\timing_chart.png", dpi=150)
plt.show()
print("\nChart saved: C:\\constrsa\\timing_chart.png")