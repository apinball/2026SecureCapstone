#!/bin/bash

# ============================================================
# tls_check.sh — TLS policy verification script
# Connects to server via openssl s_client and verifies
# negotiated cipher suite matches the expected stage policy.
# Output: scanner/results/tls-check-summary.json
# Exit:   0 = pass, 1 = fail
# Usage:  tls_check.sh <host> <port> <stage>
#         stage: 1|ecc, 2|hybrid, 3|pq
# ============================================================

SCRIPT_DIR=$(dirname "$(realpath "$0")")
RESULTS_DIR="$SCRIPT_DIR/results"
SUMMARY_FILE="$RESULTS_DIR/tls-check-summary.json"

HOST=${1:-localhost}
PORT=${2:-443}
STAGE=${3:-1}

mkdir -p "$RESULTS_DIR"

echo "=== TLS Policy Check ==="
echo "Host  : $HOST:$PORT"
echo "Stage : $STAGE"
echo ""

# Set expected curves per stage
if [ "$STAGE" = "1" ] || [ "$STAGE" = "ecc" ]; then
    CURVES="x25519:prime256v1:secp384r1"
    STAGE_NUM=1
elif [ "$STAGE" = "2" ] || [ "$STAGE" = "hybrid" ]; then
    CURVES="X25519MLKEM768:x25519"
    STAGE_NUM=2
elif [ "$STAGE" = "3" ] || [ "$STAGE" = "pq" ]; then
    CURVES="p521_mlkem1024:p384_mlkem768"
    STAGE_NUM=3
else
    echo "[ERROR] Invalid stage: $STAGE — use 1|ecc, 2|hybrid, 3|pq"
    exit 1
fi

# Connect and get TLS negotiation result
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT INT TERM

openssl s_client \
    -connect "$HOST:$PORT" \
    -groups "$CURVES" \
    -brief \
    -no_tls1 -no_tls1_1 \
    2>&1 </dev/null | tee "$TMPFILE"

OPENSSL_EXIT=${PIPESTATUS[0]}

# Fail if connection failed
if [ "$OPENSSL_EXIT" -ne 0 ] || ! grep -q "Protocol version" "$TMPFILE"; then
    echo "[ERROR] TLS connection to $HOST:$PORT failed"
    exit 1
fi

echo ""

# Parse negotiated values
PROTOCOL=$(grep "Protocol version" "$TMPFILE" | awk '{print $NF}')
CIPHER=$(grep "Ciphersuite" "$TMPFILE" | awk '{print $NF}')
GROUP=$(grep -E "Negotiated TLS1.3 group|Server Temp Key" "$TMPFILE" | cut -d: -f2- | tr -d ' ')

# Handle empty values
PROTOCOL=${PROTOCOL:-Unknown}
CIPHER=${CIPHER:-Unknown}
GROUP=${GROUP:-Unknown}

echo "=== Negotiated Values ==="
echo "Protocol : $PROTOCOL"
echo "Cipher   : $CIPHER"
echo "Group    : $GROUP"
echo ""

GROUP_LOWER=$(echo "$GROUP" | tr '[:upper:]' '[:lower:]')
RESULT="fail"
FAIL_REASON=""

# Policy check per stage
if [ "$STAGE_NUM" = "1" ]; then
    # Stage 1: must NOT have MLKEM
    if echo "$GROUP_LOWER" | grep -qi "mlkem"; then
        FAIL_REASON="Stage 1 policy violation: MLKEM group negotiated (PQC not expected)"
    else
        RESULT="pass"
    fi

elif [ "$STAGE_NUM" = "2" ]; then
    # Stage 2: must have X25519MLKEM768 AND classical fallback
    if ! echo "$GROUP_LOWER" | grep -qi "mlkem"; then
        FAIL_REASON="Stage 2 policy violation: X25519MLKEM768 not negotiated"
    elif ! echo "$GROUP_LOWER" | grep -qi "x25519"; then
        FAIL_REASON="Stage 2 policy violation: classical fallback (X25519) not present"
    else
        RESULT="pass"
    fi

elif [ "$STAGE_NUM" = "3" ]; then
    # Stage 3: must have MLKEM, must NOT have classical-only group
    if ! echo "$GROUP_LOWER" | grep -qi "mlkem"; then
        FAIL_REASON="Stage 3 policy violation: no MLKEM group negotiated"
    elif echo "$GROUP_LOWER" | grep -qiE "^x25519$|^prime256v1$|^secp384r1$"; then
        FAIL_REASON="Stage 3 policy violation: classical fallback group negotiated"
    else
        RESULT="pass"
    fi
fi

# Also fail if protocol is not TLS 1.3 for stage 2/3
if [ "$STAGE_NUM" != "1" ] && [ "$PROTOCOL" != "TLSv1.3" ]; then
    if [ "$RESULT" = "pass" ]; then
        FAIL_REASON="Stage $STAGE_NUM policy violation: TLSv1.3 required but got $PROTOCOL"
    fi
    RESULT="fail"
fi

# Write summary JSON
python3 -c "
import json
summary = {
    'tool': 'tls_check',
    'result': '$RESULT',
    'stage': $STAGE_NUM,
    'target': '$HOST:$PORT',
    'negotiated': {
        'protocol': '$PROTOCOL',
        'cipher': '$CIPHER',
        'group': '$GROUP'
    },
    'fail_reason': '$FAIL_REASON'
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

# Print result
echo "=== Result ==="
if [ "$RESULT" = "pass" ]; then
    echo "[PASS] Stage $STAGE_NUM policy satisfied."
else
    echo "[FAIL] $FAIL_REASON"
fi

if [ "$RESULT" = "pass" ]; then
    exit 0
else
    exit 1
fi
