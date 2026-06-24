"""
analyze_benchmark.py
Analyzes constant_time vs baseline benchmark data (Section 5.6, RQ3).
Usage: python3 analyze_benchmark.py ../data/benchmark_data.csv
"""
import sys
import pandas as pd
from scipy import stats

def main():
    if len(sys.argv) != 2:
        print("usage: python3 analyze_benchmark.py <csv_path>")
        sys.exit(1)

    df = pd.read_csv(sys.argv[1])
    stat_table = df.groupby('impl')['time_ns'].agg(['mean', 'median', 'std', 'var', 'count'])
    print("Performance comparison (nanoseconds):")
    print(stat_table)
    print()

    ct = df[df['impl'] == 'constant_time']['time_ns']
    bl = df[df['impl'] == 'baseline']['time_ns']

    ct_mean = ct.mean()
    bl_mean = bl.mean()
    overhead_pct = (ct_mean - bl_mean) / bl_mean * 100

    print(f"Constant-time mean: {ct_mean:.1f} ns")
    print(f"Baseline mean:      {bl_mean:.1f} ns")
    print(f"Overhead of constant-time engineering: {overhead_pct:+.2f}%")
    print()

    t_stat, p_value = stats.ttest_ind(ct, bl, equal_var=False)  # Welch's t-test
    print(f"Welch's t-test: t-statistic = {t_stat:.4f}, p-value = {p_value:.6g}")

    pooled_std = ((ct.std()**2 + bl.std()**2) / 2) ** 0.5
    cohens_d = (ct_mean - bl_mean) / pooled_std
    print(f"Cohen's d (effect size): {cohens_d:.4f}")
    print()

    if p_value < 0.05:
        print("Result: The overhead is statistically significant (p < 0.05).")
    else:
        print("Result: The overhead is NOT statistically significant (p > 0.05) --")
        print("despite the mean difference, this could be noise given the variance.")

if __name__ == "__main__":
    main()