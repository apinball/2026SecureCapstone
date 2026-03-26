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

# Run semgrep scan (crypto-classical.yaml only — tls-policy.yaml은 Security Gate Step에서 별도 실행)
CRYPTO_RULES="$RULES_DIR/crypto-classical.yaml"
if [ -f "$CRYPTO_RULES" ]; then
    semgrep --config "$CRYPTO_RULES" --json --output "$OUTPUT_FILE" --quiet --exclude "*.yaml" --exclude "*.toml" "$SCAN_TARGET"
else
    echo "[WARN] No rules found in $RULES_DIR, skipping scan."
    python3 -c "
import json
with open('$OUTPUT_FILE', 'w') as f:
    json.dump({'results': [], 'errors': []}, f, indent=2)
"
fi

SEMGREP_EXIT=$?

# Fail immediately if semgrep execution error (exit 2+)
if [ "$SEMGREP_EXIT" -ge 2 ]; then
    echo "[ERROR] Semgrep execution failed with exit code $SEMGREP_EXIT"
    exit 1
fi

# Fail if output file missing or empty
if [ ! -s "$OUTPUT_FILE" ]; then
    echo "[ERROR] Semgrep output file missing or empty"
    exit 1
fi

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
COUNTS=$(python3 -c "
import json, sys
try:
    with open('$OUTPUT_FILE') as f:
        data = json.load(f)
    error_count = 0
    warning_count = 0
    for r in data.get('results', []):
        sev = r.get('extra', {}).get('severity', '').upper()
        if sev == 'ERROR':
            error_count += 1
        elif sev == 'WARNING':
            warning_count += 1
    print(f'{error_count} {warning_count}')
except (json.JSONDecodeError, FileNotFoundError):
    print('0 0')
" 2>/dev/null || echo '0 0')

ERROR_COUNT=$(echo "$COUNTS" | awk '{print $1}')
WARNING_COUNT=$(echo "$COUNTS" | awk '{print $2}')

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
