import pandas as pd
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

print("=" * 55)
print("  ConstRSA 512-bit — Timing Leak Analysis")
print("=" * 55)

df = pd.read_csv("data\\timing_512.csv")
print(f"\nTotal rows: {len(df)}")
print(df.head(5))

# Remove outliers
df = df[df["time_ns"] < df["time_ns"].quantile(0.99)]

fixed  = df[df["input_type"]=="fixed"]["time_ns"]
random = df[df["input_type"]=="random"]["time_ns"]

print(f"\nFixed  — Mean: {fixed.mean():.1f} ns  Std: {fixed.std():.1f}")
print(f"Random — Mean: {random.mean():.1f} ns  Std: {random.std():.1f}")
print(f"Difference   : {abs(fixed.mean()-random.mean()):.1f} ns")

t, p = stats.ttest_ind(fixed, random, equal_var=False)
print(f"\nWelch's t-test:")
print(f"  t = {t:.4f}")
print(f"  p = {p:.6f}")
if p > 0.05:
    print(f"  Result: NO timing leak detected ✓")
else:
    print(f"  Result: small difference (p<0.05)")
    print(f"  Mean diff: {abs(fixed.mean()-random.mean()):.1f} ns")

# Plot
fig, ax = plt.subplots(figsize=(8,5))
ax.hist(fixed,  bins=50, alpha=0.6, color="steelblue", label="Fixed")
ax.hist(random, bins=50, alpha=0.6, color="coral",     label="Random")
ax.set_title(f"ConstRSA 512-bit Timing\np={p:.6f}")
ax.set_xlabel("Time (ns)")
ax.set_ylabel("Count")
ax.legend()
plt.tight_layout()
plt.savefig("docs\\timing_512_chart.png", dpi=150)
print("\nChart saved: docs\\timing_512_chart.png")
print("=" * 55)