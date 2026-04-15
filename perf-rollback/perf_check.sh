#!/bin/bash
# perf_check.sh — TLS handshake latency measurement and performance gate
# Usage: perf_check.sh <host> <port> <stage> [baseline_file]
# Runs inside the tls-tester container (openquantumsafe/curl)

set -euo pipefail

HOST="${1:-}"
PORT="${2:-}"
STAGE_ARG="${3:-}"
BASELINE_FILE="${4:-}"

if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$STAGE_ARG" ]; then
    echo "Usage: perf_check.sh <host> <port> <stage> [baseline_file]"
    echo "  stage: 1|ecc, 2|hybrid, 3|pq"
    exit 1
fi

# Normalize stage argument to integer
case "$STAGE_ARG" in
    1|ecc)     STAGE=1 ;;
    2|hybrid)  STAGE=2 ;;
    3|pq)      STAGE=3 ;;
    *)
        echo "[ERROR] Invalid stage: $STAGE_ARG (use 1|ecc, 2|hybrid, 3|pq)"
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"
SUMMARY_FILE="$RESULTS_DIR/perf-check-summary.json"

SAMPLE_COUNT=30
TARGET="${HOST}:${PORT}"
URL="https://${HOST}:${PORT}/"

# Select curves based on stage
case "$STAGE" in
    1) CURVES="x25519:prime256v1:secp384r1" ;;
    2) CURVES="X25519MLKEM768" ;;
    3) CURVES="mlkem1024" ;;
esac

echo "=== Performance Check ==="
echo "Target : $TARGET"
echo "Stage  : $STAGE"
echo "Curves : $CURVES"
echo "Samples: $SAMPLE_COUNT"
echo ""

MEASUREMENTS=()
FAIL_COUNT=0

# Measure TLS handshake latency SAMPLE_COUNT times
for i in $(seq 1 $SAMPLE_COUNT); do
    RAW=$(curl -k -s -o /dev/null \
        --write-out "%{time_appconnect}" \
        --connect-timeout 5 \
        --curves "$CURVES" \
        "$URL" 2>/dev/null) || true

    CURL_EXIT=$?
    # time_appconnect returns 0.000000 on connection failure
    if [ "$CURL_EXIT" -ne 0 ] || [ "$RAW" = "0.000000" ] || [ "$RAW" = "0" ]; then
        echo "  [$i/$SAMPLE_COUNT] FAIL (connection error)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        # Convert seconds to milliseconds
        MS=$(python3 -c "print(round(float('$RAW') * 1000, 3))")
        echo "  [$i/$SAMPLE_COUNT] ${MS} ms"
        MEASUREMENTS+=("$MS")
    fi
done

echo ""
echo "Measurement complete. Failures: ${FAIL_COUNT}/${SAMPLE_COUNT}"
echo ""

# Build Python list string from measurements array
PY_LIST="[$(IFS=,; echo "${MEASUREMENTS[*]-}")]"

# Compute statistics and write summary JSON
python3 - <<EOF
import json, sys, os

measurements = $PY_LIST
sample_count  = $SAMPLE_COUNT
fail_count    = $FAIL_COUNT
stage         = $STAGE
target        = "$TARGET"
baseline_file = "$BASELINE_FILE"
summary_file  = "$SUMMARY_FILE"

failure_rate = fail_count / sample_count

if measurements:
    s = sorted(measurements)
    n = len(s)
    # Median
    if n % 2 == 1:
        median_ms = s[n // 2]
    else:
        median_ms = round((s[n // 2 - 1] + s[n // 2]) / 2, 3)
    # 90th percentile
    idx = int(n * 0.9)
    if idx >= n:
        idx = n - 1
    p90_ms = s[idx]
else:
    median_ms = 0.0
    p90_ms    = 0.0

# Load baseline if provided
baseline_median = None
if baseline_file and os.path.isfile(baseline_file):
    try:
        with open(baseline_file) as f:
            bl = json.load(f)
        baseline_median = bl.get("metrics", {}).get("median_ms", None)
    except Exception:
        pass

# Determine result
# Stage 1 is always "baseline" (not a rollback target)
fail_reason = ""

if stage == 1 or not baseline_file:
    result = "baseline"
else:
    result = "pass"
    # Absolute threshold: median > 3000 ms
    if median_ms > 3000:
        result = "fail"
        fail_reason = f"median {median_ms} ms exceeds absolute threshold 3000 ms"
    # Relative threshold: median > 7x baseline median
    if baseline_median is not None and median_ms > baseline_median * 7:
        result = "fail"
        reason = f"median {median_ms} ms exceeds 7x baseline ({baseline_median} ms)"
        fail_reason = (fail_reason + "; " + reason).lstrip("; ")
    # Failure rate threshold: >= 10%
    if failure_rate >= 0.10:
        result = "fail"
        reason = f"failure rate {round(failure_rate * 100, 1)}% >= 10%"
        fail_reason = (fail_reason + "; " + reason).lstrip("; ")

summary = {
    "tool": "perf_check",
    "result": result,
    "stage": stage,
    "target": target,
    "metrics": {
        "median_ms":    median_ms,
        "p90_ms":       p90_ms,
        "failure_rate": round(failure_rate, 4),
        "sample_count": sample_count
    },
    "baseline_median_ms": baseline_median,
    "fail_reason": fail_reason
}

with open(summary_file, "w") as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))

if result == "pass":
    print("\n[PASS]")
    sys.exit(0)
elif result == "baseline":
    print("\n[BASELINE]")
    sys.exit(0)
else:
    print(f"\n[FAIL] {fail_reason}")
    sys.exit(1)
EOF
