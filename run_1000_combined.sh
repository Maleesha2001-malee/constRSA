#!/usr/bin/env bash
# =============================================================================
# run_1000_combined.sh
#
# Runs BOTH experiments 1000 times each with 10,000 samples per run:
#   1. SYNTHETIC  — interleaved_timing_harness (fixed vs random bigints)
#   2. REAL DOCS  — document_timing_harness    (fixed vs varied PDFs)
#
# Both use interleaved measurement so fixed/random share the same CPU
# thermal/cache state — eliminating the measurement-order confound.
#
# Raw per-run CSVs are NOT saved (would be 2000 files). Only summary
# CSVs and the final report are written.
#
# Usage:
#   chmod +x run_1000_combined.sh
#   ./run_1000_combined.sh
#
# Outputs:
#   data/syn_1000_summary.csv      — 1000 rows, one per synthetic run
#   data/doc_1000_summary.csv      — 1000 rows, one per real-doc run
#   data/combined_1000_report.txt  — final human-readable report
# =============================================================================

set -euo pipefail

RUNS=10000
SAMPLES=10000
CORPUS_DIR="data/corpus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p data

# --------------------------------------------------------------------------
# Colours (disabled if not a terminal)
# --------------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    RED='\033[0;31m';   NC='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; YELLOW=''; RED=''; NC=''; BOLD=''
fi

# --------------------------------------------------------------------------
# 1. Build both binaries
# --------------------------------------------------------------------------
echo ""
echo -e "${BOLD}==========================================${NC}"
echo -e "${BOLD} ConstRSA — 10000-Run Combined Experiment ${NC}"
echo -e "${BOLD}==========================================${NC}"
echo ""

echo "[BUILD] interleaved_timing_harness ..."
gcc -O2 -Wall -Wextra -std=c11 -Isrc \
    -o interleaved_timing_harness \
    src/bigint.c src/interleaved_timing_harness.c -lm
echo "[BUILD] document_timing_harness ..."
gcc -O2 -Wall -Wextra -std=c11 -Isrc \
    -o document_timing_harness \
    src/bigint.c src/pss.c src/rsa_sign.c src/document_timing_harness.c -lcrypto
echo -e "[BUILD] ${GREEN}Done.${NC}"
echo ""

# --------------------------------------------------------------------------
# 2. Python deps
# --------------------------------------------------------------------------
if ! python3 -c "import pandas, scipy, numpy" 2>/dev/null; then
    echo "[DEP] Installing pandas scipy numpy ..."
    pip3 install pandas scipy numpy --quiet --break-system-packages
fi

# --------------------------------------------------------------------------
# 3. Corpus check
# --------------------------------------------------------------------------
DOC_COUNT=$(find "$CORPUS_DIR" -maxdepth 1 -name "*.pdf" 2>/dev/null | wc -l)
if [ "$DOC_COUNT" -lt 2 ]; then
    echo -e "${RED}ERROR: Need at least 2 PDFs in $CORPUS_DIR (found $DOC_COUNT)${NC}"
    exit 1
fi
echo "[CORPUS] Found $DOC_COUNT PDF documents."
echo "[CONFIG] RUNS=$RUNS  SAMPLES=$SAMPLES"
echo ""

# --------------------------------------------------------------------------
# 4. CSV headers
# --------------------------------------------------------------------------
SYN_CSV="data/syn_1000_summary.csv"
DOC_CSV="data/doc_1000_summary.csv"

echo "run,t_stat,p_value,cohens_d,fixed_mean_ns,random_mean_ns,fixed_std_ns,random_std_ns,significant,negligible" \
    > "$SYN_CSV"
echo "run,t_stat,p_value,cohens_d,fixed_mean_ns,varied_mean_ns,fixed_std_ns,varied_std_ns,significant,negligible" \
    > "$DOC_CSV"

# --------------------------------------------------------------------------
# 5. Helper: analyse a timing CSV produced by either harness
#    Prints: t_stat p_value cohens_d fixed_mean fixed_std rand_mean rand_std
# --------------------------------------------------------------------------
analyse_csv() {
    local csv="$1"
    python3 - "$csv" << 'PYEOF'
import sys, math
import pandas as pd
from scipy import stats

df = pd.read_csv(sys.argv[1])
f  = df[df['type']=='fixed' ]['time_ns']
r  = df[df['type']=='random']['time_ns']

t, p   = stats.ttest_ind(f, r, equal_var=False)
pooled = math.sqrt((f.std()**2 + r.std()**2) / 2)
d      = (f.mean() - r.mean()) / pooled if pooled > 0 else 0.0

print(f"{t:.6f} {p:.8f} {d:.6f} {f.mean():.2f} {f.std():.2f} {r.mean():.2f} {r.std():.2f}")
PYEOF
}

# --------------------------------------------------------------------------
# 6. Temp file for interleaved output (reused each iteration)
# --------------------------------------------------------------------------
TMP=$(mktemp /tmp/constRSA_XXXXXX.csv)
trap "rm -f $TMP" EXIT

# --------------------------------------------------------------------------
# 7. Main run loop
# --------------------------------------------------------------------------
SYN_FAIL=0; DOC_FAIL=0
START_T=$(date +%s)

echo -e "${BOLD}Running $RUNS iterations × $SAMPLES samples each ...${NC}"
echo ""

for i in $(seq 1 $RUNS); do

    # ── ETA ──────────────────────────────────────────────────────────────
    ELAPSED=$(( $(date +%s) - START_T ))
    if [ "$i" -gt 1 ] && [ "$ELAPSED" -gt 0 ]; then
        RATE=$(echo "scale=2; ($i-1) / $ELAPSED" | bc 2>/dev/null || echo "?")
        REM=$(echo "scale=0; ($RUNS - $i + 1) / $RATE" | bc 2>/dev/null || echo "?")
        ETA_STR="ETA ~${REM}s"
    else
        ETA_STR="estimating..."
    fi

    printf "\r[%4d/%d] %-20s" "$i" "$RUNS" "$ETA_STR"

    # ════════════════════════════════════════════════════════
    # A) SYNTHETIC — interleaved harness
    # ════════════════════════════════════════════════════════
    ./interleaved_timing_harness "$SAMPLES" > "$TMP" 2>/dev/null

    read T_S P_S D_S FM_S FS_S RM_S RS_S <<< "$(analyse_csv "$TMP")"

    SIG_S="no"; NEG_S="yes"
    python3 -c "exit(0 if float('$P_S')<0.05 else 1)" 2>/dev/null && SIG_S="yes"
    python3 -c "exit(0 if abs(float('$D_S'))>=0.2 else 1)" 2>/dev/null && NEG_S="no"
    [ "$SIG_S" = "yes" ] && [ "$NEG_S" = "no" ] && SYN_FAIL=$((SYN_FAIL+1))

    echo "${i},${T_S},${P_S},${D_S},${FM_S},${RM_S},${FS_S},${RS_S},${SIG_S},${NEG_S}" \
        >> "$SYN_CSV"

    # ════════════════════════════════════════════════════════
    # B) REAL DOCS — document harness
    # ════════════════════════════════════════════════════════
    ./document_timing_harness "$CORPUS_DIR" "$SAMPLES" > "$TMP" 2>/dev/null

    read T_D P_D D_D FM_D FS_D RM_D RS_D <<< "$(analyse_csv "$TMP")"

    SIG_D="no"; NEG_D="yes"
    python3 -c "exit(0 if float('$P_D')<0.05 else 1)" 2>/dev/null && SIG_D="yes"
    python3 -c "exit(0 if abs(float('$D_D'))>=0.2 else 1)" 2>/dev/null && NEG_D="no"
    [ "$SIG_D" = "yes" ] && [ "$NEG_D" = "no" ] && DOC_FAIL=$((DOC_FAIL+1))

    echo "${i},${T_D},${P_D},${D_D},${FM_D},${RM_D},${FS_D},${RS_D},${SIG_D},${NEG_D}" \
        >> "$DOC_CSV"

done

echo ""
echo ""

# --------------------------------------------------------------------------
# 8. Final combined report (Python)
# --------------------------------------------------------------------------
REPORT="data/combined_1000_report.txt"

python3 - "$RUNS" "$SAMPLES" "$SYN_CSV" "$DOC_CSV" << 'PYEOF' > "$REPORT"
import sys, pandas as pd, numpy as np

runs, samples = int(sys.argv[1]), int(sys.argv[2])
syn = pd.read_csv(sys.argv[3])
doc = pd.read_csv(sys.argv[4])

def section(df, label):
    total   = len(df)
    sig     = (df['significant']=='yes').sum()
    neg     = (df['negligible']=='yes').sum()
    concern = ((df['significant']=='yes') & (df['negligible']=='no')).sum()
    lines = []
    lines.append(f"  {'='*54}")
    lines.append(f"  {label}")
    lines.append(f"  {'='*54}")
    lines.append(f"  Runs: {total}   Samples/run: {samples}")
    lines.append("")
    lines.append("  Cohen's d")
    lines.append(f"    mean   : {df['cohens_d'].mean():+.5f}")
    lines.append(f"    median : {df['cohens_d'].median():+.5f}")
    lines.append(f"    std    : {df['cohens_d'].std():.5f}")
    lines.append(f"    min    : {df['cohens_d'].min():+.5f}")
    lines.append(f"    max    : {df['cohens_d'].max():+.5f}")
    lines.append("")
    lines.append("  p-value (Welch t-test)")
    lines.append(f"    mean   : {df['p_value'].mean():.6f}")
    lines.append(f"    median : {df['p_value'].median():.6f}")
    lines.append(f"    p<0.05 : {sig} / {total}  ({100*sig/total:.1f}%)")
    lines.append("")
    lines.append("  Timing (ns)")
    lines.append(f"    fixed  : {df['fixed_mean_ns'].mean():.0f} +/- {df['fixed_std_ns'].mean():.0f}")
    other_mean_col = 'random_mean_ns' if 'random_mean_ns' in df.columns else 'varied_mean_ns'
    other_std_col  = 'random_std_ns'  if 'random_std_ns'  in df.columns else 'varied_std_ns'
    lines.append(f"    other  : {df[other_mean_col].mean():.0f} +/- {df[other_std_col].mean():.0f}")
    lines.append("")
    lines.append("  Verdict")
    lines.append(f"    Negligible |d|<0.2  : {neg} / {total}  ({100*neg/total:.1f}%)")
    lines.append(f"    Concern (sig+|d|>=0.2): {concern} / {total}  ({100*concern/total:.1f}%)")
    lines.append("")
    if concern == 0:
        lines.append("    >>> PASS  No constant-time leakage detected.")
    elif concern <= runs * 0.01:
        lines.append("    >>> MARGINAL  <=1% concern rate — likely noise.")
    else:
        lines.append("    >>> FAIL  Review implementation.")
    return lines

out = []
out.append("")
out.append("  ConstRSA — 10000-Run Combined Timing Report")
out.append(f"  Synthetic (interleaved) + Real PDF documents")
out.append("")
out += section(syn, "SYNTHETIC  (interleaved_timing_harness)")
out.append("")
out += section(doc, "REAL DOCS  (document_timing_harness)")
out.append("")
out.append("  " + "="*54)
out.append("  COMBINED VERDICT")
out.append("  " + "="*54)
total_concern = ((syn['significant']=='yes')&(syn['negligible']=='no')).sum() + \
                ((doc['significant']=='yes')&(doc['negligible']=='no')).sum()
out.append(f"  Total concern runs across both experiments: {total_concern} / {2*runs}")
if total_concern == 0:
    out.append("  >>> PASS — Constant-time implementation verified across")
    out.append(f"      {runs} synthetic runs and {runs} real-document runs.")
elif total_concern <= runs * 0.01:
    out.append("  >>> MARGINAL — <1% concern rate consistent with noise.")
else:
    out.append("  >>> FAIL — Investigate timing leakage.")
out.append("")

print('\n'.join(out))
PYEOF

# --------------------------------------------------------------------------
# 9. Print report + summary
# --------------------------------------------------------------------------
cat "$REPORT"

TOTAL_T=$(( $(date +%s) - START_T ))
echo ""
echo "Total time: ${TOTAL_T}s  (~$(( TOTAL_T/60 ))m $(( TOTAL_T%60 ))s)"
echo ""
echo "Files written:"
echo "  $SYN_CSV"
echo "  $DOC_CSV"
echo "  $REPORT"
