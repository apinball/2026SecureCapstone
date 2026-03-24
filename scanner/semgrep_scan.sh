#!/bin/bash

# ============================================================
# semgrep_scan.sh — Semgrep SAST scanner wrapper
# Output: scanner/results/semgrep-result.json
# Exit:   0 = pass, 1 = fail (ERROR severity found)
# ============================================================

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/semgrep-result.json"
SUMMARY_FILE="$RESULTS_DIR/semgrep-summary.json"
RULES_DIR="$SCRIPT_DIR/rules"

SCAN_TARGET=${1:-$SCRIPT_DIR/..}
STAGE=${2:-1}

mkdir -p "$RESULTS_DIR"

echo "=== Semgrep Scan ==="
echo "Target : $SCAN_TARGET"
echo "Stage  : $STAGE"
echo ""

# Run semgrep scan
if [ -d "$RULES_DIR" ] && [ "$(ls -A $RULES_DIR)" ]; then
    semgrep --config "$RULES_DIR" --json --output "$OUTPUT_FILE" --quiet --exclude "*.yaml" --exclude "*.toml" "$SCAN_TARGET"
else
    echo "[WARN] No rules found in $RULES_DIR, skipping scan."
    python3 -c "
import json
with open('$OUTPUT_FILE', 'w') as f:
    json.dump({'results': [], 'errors': []}, f, indent=2)
"
fi

SEMGREP_EXIT=$?

# Check for rule schema errors
SCHEMA_ERRORS=$(python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    data = json.load(f)
errors = [e for e in data.get('errors', []) if e.get('type') == 'InvalidRuleSchemaError']
print(len(errors))
" 2>/dev/null || echo 0)

if [ "$SCHEMA_ERRORS" -gt 0 ]; then
    echo "[ERROR] $SCHEMA_ERRORS invalid rule(s) detected in $RULES_DIR — fix rule schema before proceeding."
    exit 1
fi

# Parse result counts
ERROR_COUNT=$(python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    data = json.load(f)
count = 0
for r in data.get('results', []):
    if r.get('extra', {}).get('severity', '').upper() == 'ERROR':
        count += 1
print(count)
" 2>/dev/null || echo 0)

WARNING_COUNT=$(python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    data = json.load(f)
count = 0
for r in data.get('results', []):
    if r.get('extra', {}).get('severity', '').upper() == 'WARNING':
        count += 1
print(count)
" 2>/dev/null || echo 0)

# Determine pass/fail
if [ "$ERROR_COUNT" -gt 0 ]; then
    RESULT="fail"
    EXIT_CODE=1
else
    RESULT="pass"
    EXIT_CODE=0
fi

# Write summary JSON
python3 -c "
import json
summary = {
    'tool': 'semgrep',
    'result': '$RESULT',
    'stage': $STAGE,
    'summary': {
        'error': $ERROR_COUNT,
        'warning': $WARNING_COUNT
    }
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

# Print summary
echo "=== Result ==="
echo "ERROR   : $ERROR_COUNT"
echo "WARNING : $WARNING_COUNT"
echo ""

if [ "$RESULT" = "pass" ]; then
    echo "[PASS] No ERROR severity findings."
else
    echo "[FAIL] ERROR severity findings detected."
fi

exit $EXIT_CODE
