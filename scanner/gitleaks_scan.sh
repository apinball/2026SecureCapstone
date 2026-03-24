#!/bin/bash

# ============================================================
# gitleaks_scan.sh — Gitleaks secret scanner wrapper
# Output: scanner/results/gitleaks-result.json
# Exit:   0 = pass (no secrets found), 1 = fail (secrets found)
# ============================================================

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/gitleaks-result.json"
SUMMARY_FILE="$RESULTS_DIR/gitleaks-summary.json"
CONFIG_FILE="$SCRIPT_DIR/.gitleaks.toml"

SCAN_TARGET=${1:-$SCRIPT_DIR/..}
STAGE=${2:-1}

mkdir -p "$RESULTS_DIR"

echo "=== Gitleaks Scan ==="
echo "Target : $SCAN_TARGET"
echo "Stage  : $STAGE"
echo ""

# Run gitleaks scan
if [ -f "$CONFIG_FILE" ]; then
    gitleaks git --config "$CONFIG_FILE" --report-format json --report-path "$OUTPUT_FILE" "$SCAN_TARGET"
else
    gitleaks git --report-format json --report-path "$OUTPUT_FILE" "$SCAN_TARGET"
fi

GITLEAKS_EXIT=$?

# Count leaks from result file
if [ -f "$OUTPUT_FILE" ]; then
    LEAK_COUNT=$(python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    data = json.load(f)
print(len(data) if isinstance(data, list) else 0)
" 2>/dev/null || echo 0)
else
    LEAK_COUNT=0
fi

# Determine pass/fail
if [ "$GITLEAKS_EXIT" -eq 0 ]; then
    RESULT="pass"
    EXIT_CODE=0
elif [ "$GITLEAKS_EXIT" -eq 1 ]; then
    RESULT="fail"
    EXIT_CODE=1
else
    echo "[ERROR] Gitleaks execution failed with exit code $GITLEAKS_EXIT"
    exit 1
fi

# Write summary JSON
python3 -c "
import json
summary = {
    'tool': 'gitleaks',
    'result': '$RESULT',
    'stage': $STAGE,
    'summary': {
        'leaks_found': $LEAK_COUNT
    }
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

# Print summary
echo "=== Result ==="
echo "Leaks found: $LEAK_COUNT"
echo ""

if [ "$RESULT" = "pass" ]; then
    echo "[PASS] No secrets detected."
else
    echo "[FAIL] Secrets detected in repository."
fi

exit $EXIT_CODE
