#!/bin/bash

# ============================================================
# run_scanners.sh — Unified scanner wrapper
# Runs Trivy, Gitleaks, Semgrep in sequence
# Output: scanner/results/scan-summary.json
# Exit:   0 = all pass, 1 = any fail
# ============================================================

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_DIR="$SCRIPT_DIR/results"
SUMMARY_FILE="$RESULTS_DIR/scan-summary.json"

SCAN_TARGET=${1:-$SCRIPT_DIR/..}
STAGE=${2:-1}

mkdir -p "$RESULTS_DIR"

echo "========================================"
echo " Security Scan — Stage $STAGE"
echo " Target: $SCAN_TARGET"
echo "========================================"
echo ""

TRIVY_RESULT="pass"
GITLEAKS_RESULT="pass"
SEMGREP_RESULT="pass"

# Run Trivy
bash "$SCRIPT_DIR/trivy_scan.sh" "$SCAN_TARGET" "$STAGE"
if [ $? -ne 0 ]; then
    TRIVY_RESULT="fail"
fi
echo ""

# Run Gitleaks
bash "$SCRIPT_DIR/gitleaks_scan.sh" "$SCAN_TARGET" "$STAGE"
if [ $? -ne 0 ]; then
    GITLEAKS_RESULT="fail"
fi
echo ""

# Run Semgrep
bash "$SCRIPT_DIR/semgrep_scan.sh" "$SCAN_TARGET" "$STAGE"
if [ $? -ne 0 ]; then
    SEMGREP_RESULT="fail"
fi
echo ""

# Determine overall result
if [ "$TRIVY_RESULT" = "fail" ] || [ "$GITLEAKS_RESULT" = "fail" ] || [ "$SEMGREP_RESULT" = "fail" ]; then
    OVERALL="fail"
    EXIT_CODE=1
else
    OVERALL="pass"
    EXIT_CODE=0
fi

# Write overall summary JSON
python3 -c "
import json
summary = {
    'stage': $STAGE,
    'overall': '$OVERALL',
    'tools': {
        'trivy': '$TRIVY_RESULT',
        'gitleaks': '$GITLEAKS_RESULT',
        'semgrep': '$SEMGREP_RESULT'
    }
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

# Print overall summary
echo "========================================"
echo " Overall Result: $OVERALL"
echo "   Trivy    : $TRIVY_RESULT"
echo "   Gitleaks : $GITLEAKS_RESULT"
echo "   Semgrep  : $SEMGREP_RESULT"
echo "========================================"

exit $EXIT_CODE
