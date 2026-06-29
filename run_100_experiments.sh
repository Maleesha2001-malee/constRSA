#!/usr/bin/env bash
# =============================================================================
# run_100_experiments.sh
#
# Runs the ConstRSA real_timing_harness 100 times (each with 100,000 samples),
# collects per-run statistics, and writes a summary CSV + final report.
#
# Usage (from inside WSL, in the ConstRSA/ directory):
#   chmod +x run_100_experiments.sh
#   ./run_100_experiments.sh
#
# Outputs (written to data/):
#   data/runs/run_NNN_timing_data.csv   — raw timing data for each run
#   data/runs/run_NNN_analysis.txt      — analyze_timing.py output for each run
#   data/multi_run_summary.csv          — one row per run: t-stat, p-value, Cohen's d
#   data/multi_run_report.txt           — human-readable final summary
# =============================================================================

set -euo pipefail

RUNS=100
SAMPLES=100000
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="data/runs"
mkdir -p "$DATA_DIR"

# --------------------------------------------------------------------------
# 1. Build
# --------------------------------------------------------------------------
echo "========================================="
echo " ConstRSA 100-Run Timing Experiment"
echo "========================================="
echo ""
echo "[BUILD] Compiling real_timing_harness ..."
make real_timing_harness 2>&1
echo "[BUILD] Done."
echo ""

# --------------------------------------------------------------------------
# 2. Check dependencies
# --------------------------------------------------------------------------
if ! python3 -c "import pandas, scipy" 2>/dev/null; then
    echo "[DEP] Installing pandas and scipy ..."
    pip3 install pandas scipy --quiet --break-system-packages
fi

# --------------------------------------------------------------------------
# 3. Summary CSV header
# --------------------------------------------------------------------------
SUMMARY_CSV="data/multi_run_summary.csv"
echo "run,t_stat,p_value,cohens_d,pct_diff,fixed_mean_ns,random_mean_ns,fixed_std_ns,random_std_ns,significant,negligible_effect" \
    > "$SUMMARY_CSV"

# --------------------------------------------------------------------------
# 4. Run loop
# --------------------------------------------------------------------------
PASS=0
FAIL=0

for i in $(seq 1 $RUNS); do
    RUN_ID=$(printf "%03d" "$i")
    CSV="$DATA_DIR/run_${RUN_ID}_timing_data.csv"
    ANALYSIS="$DATA_DIR/run_${RUN_ID}_analysis.txt"

    printf "\r[RUN %3d/%d] Collecting %d samples ..." "$i" "$RUNS" "$SAMPLES"

    # Collect timing data
    echo "run,type,time_ns" > "$CSV"
    ./real_timing_harness fixed  "$SAMPLES" >> "$CSV"
    ./real_timing_harness random "$SAMPLES" >> "$CSV"

    # Run analysis and capture output
    python3 scripts/analyze_timing.py "$CSV" > "$ANALYSIS" 2>&1

    # Parse key metrics from analysis output
    T_STAT=$(grep "t-statistic" "$ANALYSIS" | grep -oP 't-statistic = \K[-0-9.]+' || echo "NA")
    P_VALUE=$(grep "p-value"    "$ANALYSIS" | grep -oP 'p-value = \K[0-9.eE+-]+' || echo "NA")
    COHENS_D=$(grep "Cohen's d" "$ANALYSIS" | grep -oP 'Cohen'\''s d \(effect size\): \K[-0-9.]+' || echo "NA")
    PCT_DIFF=$(grep "Mean difference" "$ANALYSIS" | grep -oP '[+-][0-9.]+' || echo "NA")
    FIXED_MEAN=$(python3 -c "
import pandas as pd, sys
df = pd.read_csv('$CSV')
print(f\"{df[df['type']=='fixed']['time_ns'].mean():.2f}\")
" 2>/dev/null || echo "NA")
    RANDOM_MEAN=$(python3 -c "
import pandas as pd, sys
df = pd.read_csv('$CSV')
print(f\"{df[df['type']=='random']['time_ns'].mean():.2f}\")
" 2>/dev/null || echo "NA")
    FIXED_STD=$(python3 -c "
import pandas as pd
df = pd.read_csv('$CSV')
print(f\"{df[df['type']=='fixed']['time_ns'].std():.2f}\")
" 2>/dev/null || echo "NA")
    RANDOM_STD=$(python3 -c "
import pandas as pd
df = pd.read_csv('$CSV')
print(f\"{df[df['type']=='random']['time_ns'].std():.2f}\")
" 2>/dev/null || echo "NA")

    # Determine pass/fail flags
    SIG="no"
    NEG="yes"
    if python3 -c "v=float('$P_VALUE'); exit(0 if v < 0.05 else 1)" 2>/dev/null; then
        SIG="yes"
    fi
    if python3 -c "import math; v=abs(float('$COHENS_D')); exit(0 if v < 0.2 else 1)" 2>/dev/null; then
        NEG="yes"
    else
        NEG="no"
    fi

    # Count practical failures (sig + non-negligible effect)
    if [ "$SIG" = "yes" ] && [ "$NEG" = "no" ]; then
        FAIL=$((FAIL + 1))
    else
        PASS=$((PASS + 1))
    fi

    # Append row to summary CSV
    echo "${i},${T_STAT},${P_VALUE},${COHENS_D},${PCT_DIFF},${FIXED_MEAN},${RANDOM_MEAN},${FIXED_STD},${RANDOM_STD},${SIG},${NEG}" \
        >> "$SUMMARY_CSV"
done

echo ""
echo ""

# --------------------------------------------------------------------------
# 5. Final aggregate report
# --------------------------------------------------------------------------
REPORT="data/multi_run_report.txt"

python3 - <<'PYEOF' > "$REPORT"
import pandas as pd
import numpy as np

df = pd.read_csv("data/multi_run_summary.csv")

total = len(df)
sig_count      = (df['significant'] == 'yes').sum()
neg_eff_count  = (df['negligible_effect'] == 'yes').sum()
concern_count  = ((df['significant'] == 'yes') & (df['negligible_effect'] == 'no')).sum()

lines = []
lines.append("=" * 60)
lines.append("  ConstRSA  —  100-Run Timing Experiment Report")
lines.append("=" * 60)
lines.append(f"  Runs completed     : {total}")
lines.append(f"  Samples / run      : 100,000  (fixed=50k, random=50k)")
lines.append("")
lines.append("── Cohen's d (Effect Size) ──────────────────────────────")
lines.append(f"  mean   : {df['cohens_d'].mean():+.4f}")
lines.append(f"  median : {df['cohens_d'].median():+.4f}")
lines.append(f"  std    : {df['cohens_d'].std():.4f}")
lines.append(f"  min    : {df['cohens_d'].min():+.4f}")
lines.append(f"  max    : {df['cohens_d'].max():+.4f}")
lines.append("")
lines.append("── p-value (Welch's t-test) ─────────────────────────────")
lines.append(f"  mean   : {df['p_value'].mean():.6f}")
lines.append(f"  median : {df['p_value'].median():.6f}")
lines.append(f"  runs with p < 0.05 : {sig_count} / {total}")
lines.append("")
lines.append("── Timing (nanoseconds) ─────────────────────────────────")
lines.append(f"  fixed  mean ± std : {df['fixed_mean_ns'].mean():.1f} ± {df['fixed_std_ns'].mean():.1f} ns")
lines.append(f"  random mean ± std : {df['random_mean_ns'].mean():.1f} ± {df['random_std_ns'].mean():.1f} ns")
lines.append(f"  mean pct_diff     : {df['pct_diff'].mean():+.3f}%")
lines.append("")
lines.append("── Verdict ──────────────────────────────────────────────")
lines.append(f"  Negligible effect (|d|<0.2) : {neg_eff_count} / {total} runs")
lines.append(f"  Concern (sig + |d|≥0.2)     : {concern_count} / {total} runs")
lines.append("")
if concern_count == 0:
    lines.append("  ✓  PASS — No run showed both p<0.05 AND a non-negligible")
    lines.append("     effect size. Cohen's d values are consistent with")
    lines.append("     platform noise, not secret-dependent timing leakage.")
elif concern_count <= 5:
    lines.append("  ⚠  MARGINAL — A small number of runs showed significant")
    lines.append("     p-values with non-negligible Cohen's d. This may be")
    lines.append("     noise; re-run on bare-metal with cpupower noise control.")
else:
    lines.append("  ✗  FAIL — Multiple runs show significant timing differences")
    lines.append("     with non-negligible effect size. Review implementation.")
lines.append("=" * 60)

print('\n'.join(lines))
PYEOF

# --------------------------------------------------------------------------
# 6. Print report to terminal
# --------------------------------------------------------------------------
cat "$REPORT"
echo ""
echo "Files written:"
echo "  $SUMMARY_CSV"
echo "  $REPORT"
echo "  $DATA_DIR/run_001_timing_data.csv  ...  run_100_timing_data.csv"
echo "  $DATA_DIR/run_001_analysis.txt     ...  run_100_analysis.txt"
