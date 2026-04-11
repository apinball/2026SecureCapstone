#!/bin/bash
# verify_tls.sh — OQS-curl로 TLS 협상 검증
# 사용법: verify_tls.sh <host> <port> <stage>
# 예시:   verify_tls.sh proxy-server 443 2

set -e

HOST="${1:?호스트 미지정}"
PORT="${2:-443}"
STAGE="${3:-1}"
URL="https://${HOST}:${PORT}/"

echo "[verify_tls] host=$HOST port=$PORT stage=$STAGE"

case "$STAGE" in
  1|ecc)
    CURVES="X25519:P-256"
    EXPECT="X25519"
    ;;
  2|hybrid)
    CURVES="X25519MLKEM768:X25519"
    EXPECT="X25519MLKEM768"
    ;;
  3|pq)
    CURVES="X25519MLKEM768"
    EXPECT="X25519MLKEM768"
    ;;
  *)
    echo "[verify_tls] 오류: stage=${STAGE} 는 유효하지 않습니다. {1|2|3}"
    exit 1
    ;;
esac

echo "[verify_tls] TLS 연결 시도 (curves=$CURVES)..."
RESULT=$(curl -skv --curves "$CURVES" "$URL" 2>&1)

# 연결 성공 여부 확인
if echo "$RESULT" | grep -qi "SSL connection using\|HTTP/"; then
    echo "[verify_tls] TLS 연결 성공"
else
    echo "[verify_tls] 오류: TLS 연결 실패"
    echo "$RESULT"
    exit 1
fi

# Stage별 알고리즘 확인
if echo "$RESULT" | grep -qi "$EXPECT"; then
    echo "[verify_tls] PASS — Stage $STAGE 알고리즘 협상 확인됨 ($EXPECT)"
    exit 0
else
    echo "[verify_tls] FAIL — 예상 알고리즘($EXPECT) 미감지"
    echo "$RESULT" | grep -i "ssl\|tls\|curve\|group" || true
    exit 1
fi
