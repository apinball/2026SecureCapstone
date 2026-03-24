#!/bin/bash

# ============================================================
# trivy_scan.sh — Trivy CVE/secret/misconfig scanner wrapper
# Output: scanner/results/trivy-result.json
# Exit:   0 = pass, 1 = fail (HIGH or CRITICAL found)
# ============================================================

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/trivy-result.json"
SUMMARY_FILE="$RESULTS_DIR/trivy-summary.json"

SCAN_TARGET=${1:-$SCRIPT_DIR/..}
STAGE=${2:-1}

mkdir -p "$RESULTS_DIR"

echo "=== Trivy Scan ==="
echo "Target : $SCAN_TARGET"
echo "Stage  : $STAGE"
echo ""

# Run Trivy scan
trivy fs \
    --scanners vuln,secret,misconfig \
    --severity HIGH,CRITICAL,MEDIUM \
    --format json \
    --output "$OUTPUT_FILE" \
    --quiet \
    "$SCAN_TARGET"

TRIVY_EXIT=$?

# Fail immediately if trivy execution error (exit 2+)
if [ "$TRIVY_EXIT" -ge 2 ]; then
    echo "[ERROR] Trivy execution failed with exit code $TRIVY_EXIT"
    exit 1
fi

# Fail if output file missing or empty
if [ ! -s "$OUTPUT_FILE" ]; then
    echo "[ERROR] Trivy output file missing or empty"
    exit 1
fi

# Parse result counts
COUNTS=$(python3 -c "
import json, sys
try:
    with open('$OUTPUT_FILE') as f:
        data = json.load(f)
    critical = 0
    high = 0
    medium = 0
    for r in data.get('Results', []):
        for v in (r.get('Vulnerabilities') or []) + (r.get('Misconfigurations') or []):
            sev = v.get('Severity')
            if sev == 'CRITICAL':
                critical += 1
            elif sev == 'HIGH':
                high += 1
            elif sev == 'MEDIUM':
                medium += 1
    print(f'{critical} {high} {medium}')
except (json.JSONDecodeError, FileNotFoundError):
    print('0 0 0')
" 2>/dev/null || echo '0 0 0')

CRITICAL_COUNT=$(echo "$COUNTS" | awk '{print $1}')
HIGH_COUNT=$(echo "$COUNTS" | awk '{print $2}')
MEDIUM_COUNT=$(echo "$COUNTS" | awk '{print $3}')

# Determine pass/fail
if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
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
    'tool': 'trivy',
    'result': '$RESULT',
    'stage': $STAGE,
    'summary': {
        'critical': $CRITICAL_COUNT,
        'high': $HIGH_COUNT,
        'medium': $MEDIUM_COUNT
    }
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

# Print summary
echo "=== Result ==="
echo "CRITICAL : $CRITICAL_COUNT"
echo "HIGH     : $HIGH_COUNT"
echo "MEDIUM   : $MEDIUM_COUNT"
echo ""

if [ "$RESULT" = "pass" ]; then
    echo "[PASS] No HIGH or CRITICAL vulnerabilities found."
else
    echo "[FAIL] HIGH/CRITICAL vulnerabilities detected."
fi

exit $EXIT_CODE
