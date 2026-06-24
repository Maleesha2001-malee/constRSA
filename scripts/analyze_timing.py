"""
analyze_timing.py

Runs Welch's t-test on the fixed-vs-random timing dataset as described
in Section 5.5 / 5.7 of the proposal. Also produces summary statistics
for the performance evaluation in Section 5.6.

Usage:
    python3 analyze_timing.py ../data/timing_data.csv
"""

import sys
import pandas as pd
from scipy import stats

def main():
    if len(sys.argv) != 2:
        print("usage: python3 analyze_timing.py <csv_path>")
        sys.exit(1)

    path = sys.argv[1]
    df = pd.read_csv(path)

    fixed = df[df['type'] == 'fixed']['time_ns']
    random = df[df['type'] == 'random']['time_ns']

    print(f"Fixed samples:  n={len(fixed)}")
    print(f"Random samples: n={len(random)}")
    print()

    print("Summary statistics (nanoseconds):")
    print(df.groupby('type')['time_ns'].agg(['mean', 'median', 'var', 'std']))
    print()

    t_stat, p_value = stats.ttest_ind(fixed, random, equal_var=False)  # Welch's t-test
    print(f"Welch's t-test: t-statistic = {t_stat:.4f}, p-value = {p_value:.6f}")

    # Effect size (Cohen's d) -- with large n, tiny noise differences can be
    # "statistically significant" (low p-value) without being practically
    # meaningful. Effect size tells us how LARGE the difference actually is.
    pooled_std = ((fixed.std()**2 + random.std()**2) / 2) ** 0.5
    cohens_d = (fixed.mean() - random.mean()) / pooled_std
    pct_diff = (fixed.mean() - random.mean()) / random.mean() * 100
    print(f"Cohen's d (effect size): {cohens_d:.4f}")
    print(f"Mean difference: {pct_diff:+.2f}% of random-input mean")
    print()
    print("Effect size guide: |d| < 0.2 = negligible, 0.2-0.5 = small,")
    print("0.5-0.8 = medium, > 0.8 = large")
    print()

    if p_value > 0.05:
        print("Result: No statistically significant timing difference detected")
        print("(consistent with constant-time behavior, p > 0.05)")
    elif abs(cohens_d) < 0.2:
        print("Result: Statistically significant (p < 0.05) BUT effect size")
        print("is negligible (|d| < 0.2). This pattern is often caused by")
        print("environment noise (especially in virtualized environments like")
        print("WSL) rather than genuine secret-dependent timing leakage.")
        print("Recommendation: re-run on bare-metal Linux with cpupower/taskset")
        print("noise control before drawing a final conclusion.")
    else:
        print("Result: Statistically significant timing difference detected")
        print("WITH a non-negligible effect size -- this is a stronger signal")
        print("of possible timing leakage. Review implementation for")
        print("secret-dependent branches or memory access patterns.")

if __name__ == "__main__":
    main()
