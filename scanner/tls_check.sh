#!/bin/bash

# ============================================================
# tls_check.sh — TLS policy verification script
# Verifies TLS policy via handshake success/failure outcomes.
#
# NOTE: openquantumsafe/curl:0.11.0 bundles OpenSSL < 3.2.0,
# which does not support SSL_get_negotiated_group() — the key
# group field is absent from curl -v output. Policy is therefore
# verified by handshake result with specific --curves, not by
# parsing the SSL connection line.
#
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

case "$STAGE" in
    1|ecc)     STAGE_NUM=1 ;;
    2|hybrid)  STAGE_NUM=2 ;;
    3|pq)      STAGE_NUM=3 ;;
    *)
        echo "[ERROR] Invalid stage: $STAGE — use 1|ecc, 2|hybrid, 3|pq"
        exit 1
        ;;
esac

# Temp files for curl output
TMPFILE_PQ=$(mktemp)
TMPFILE_CLASSIC=$(mktemp)
trap 'rm -f "$TMPFILE_PQ" "$TMPFILE_CLASSIC"' EXIT INT TERM

# Helper: run curl with given curves, store output in file
# Returns curl exit code
do_curl() {
    local curves="$1" outfile="$2"
    curl -k -v --connect-timeout 5 --curves "$curves" \
        https://"$HOST":"$PORT"/ > "$outfile" 2>&1
}

# Extract TLS protocol from curl -v SSL line (always present regardless of curl version)
get_protocol() {
    grep "SSL connection using" "$1" | head -1 | grep -oE 'TLSv[0-9.]+'
}

RESULT="fail"
FAIL_REASON=""
DETAIL=""
PROTOCOL="Unknown"

# ── Stage 1: Classical ECC ─────────────────────────────────
if [ "$STAGE_NUM" = "1" ]; then
    echo "[Stage 1] classical connection test"
    do_curl "x25519:prime256v1:secp384r1" "$TMPFILE_PQ"
    ECC_EXIT=$?

    if [ "$ECC_EXIT" -ne 0 ] || ! grep -q "SSL connection using" "$TMPFILE_PQ"; then
        FAIL_REASON="Stage 1: classical TLS connection failed"
    else
        PROTOCOL=$(get_protocol "$TMPFILE_PQ")
        PROTOCOL=${PROTOCOL:-Unknown}
        DETAIL="classical handshake ok"
        RESULT="pass"
    fi

# ── Stage 2: Hybrid PQC ────────────────────────────────────
elif [ "$STAGE_NUM" = "2" ]; then
    # Test 1: PQ-only client (no classical fallback) must succeed
    # Proves the server actually negotiated MLKEM, not x25519 fallback
    echo "[Stage 2] PQ-only request (X25519MLKEM768, no fallback)"
    do_curl "X25519MLKEM768" "$TMPFILE_PQ"
    PQ_EXIT=$?

    # Test 2: Classical-only client must also succeed (hybrid allows fallback)
    echo "[Stage 2] classical-only request (x25519:prime256v1)"
    do_curl "x25519:prime256v1:secp384r1" "$TMPFILE_CLASSIC"
    CLASSIC_EXIT=$?

    PROTOCOL=$(get_protocol "$TMPFILE_PQ")
    PROTOCOL=${PROTOCOL:-Unknown}

    if [ "$PQ_EXIT" -ne 0 ] || ! grep -q "SSL connection using" "$TMPFILE_PQ"; then
        FAIL_REASON="Stage 2: PQ-only request (X25519MLKEM768) failed — server may not support hybrid PQC"
    elif [ "$CLASSIC_EXIT" -ne 0 ] || ! grep -q "SSL connection using" "$TMPFILE_CLASSIC"; then
        FAIL_REASON="Stage 2: classical-only request failed — hybrid fallback not working"
    else
        DETAIL="PQ-only handshake: ok, classical fallback: ok"
        RESULT="pass"
    fi

# ── Stage 3: PQ-only (no classical fallback allowed) ───────
elif [ "$STAGE_NUM" = "3" ]; then
    # Test 1: PQ curves must succeed
    echo "[Stage 3] PQ request (p521_mlkem1024:p384_mlkem768)"
    do_curl "p521_mlkem1024:p384_mlkem768" "$TMPFILE_PQ"
    PQ_EXIT=$?

    # Test 2: Classical-only must fail (server enforces PQ-only)
    echo "[Stage 3] classical-only request (must be rejected)"
    do_curl "x25519:prime256v1:secp384r1" "$TMPFILE_CLASSIC"
    CLASSIC_EXIT=$?

    PROTOCOL=$(get_protocol "$TMPFILE_PQ")
    PROTOCOL=${PROTOCOL:-Unknown}

    if [ "$PQ_EXIT" -ne 0 ] || ! grep -q "SSL connection using" "$TMPFILE_PQ"; then
        FAIL_REASON="Stage 3: PQ handshake (p521_mlkem1024:p384_mlkem768) failed"
    elif [ "$CLASSIC_EXIT" -eq 0 ] && grep -q "SSL connection using" "$TMPFILE_CLASSIC"; then
        FAIL_REASON="Stage 3: classical-only connection succeeded — PQ-only enforcement not working"
    else
        DETAIL="PQ handshake: ok, classical rejected: ok"
        RESULT="pass"
    fi
fi

# TLSv1.3 required for Stage 2/3 (skip if protocol undetected — curl version limitation)
if [ "$STAGE_NUM" != "1" ] && [ "$PROTOCOL" != "Unknown" ] && [ "$PROTOCOL" != "TLSv1.3" ]; then
    FAIL_REASON="Stage $STAGE_NUM: TLSv1.3 required but got $PROTOCOL"
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
        'detail': '$DETAIL'
    },
    'fail_reason': '$FAIL_REASON'
}
with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
"

echo ""
echo "=== Result ==="
if [ "$RESULT" = "pass" ]; then
    echo "[PASS] Stage $STAGE_NUM policy satisfied. $DETAIL"
    exit 0
else
    echo "[FAIL] $FAIL_REASON"
    exit 1
fi
