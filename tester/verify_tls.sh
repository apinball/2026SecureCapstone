#!/bin/bash

HOST=${1:-proxy-server}
PORT=${2:-443}
STAGE=${3:-auto}

echo "=== TLS 협상 결과 검증: $HOST:$PORT (Stage: $STAGE) ==="
echo ""

# 안전한 임시 파일 관리
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT INT TERM

# Stage별 커브 설정
if [ "$STAGE" = "1" ] || [ "$STAGE" = "ecc" ]; then
    CURVES="x25519:prime256v1:secp384r1"
elif [ "$STAGE" = "2" ] || [ "$STAGE" = "hybrid" ]; then
    CURVES="X25519MLKEM768:x25519"
elif [ "$STAGE" = "3" ] || [ "$STAGE" = "pq" ]; then
    CURVES="p521_mlkem1024:p384_mlkem768"
else
    CURVES=""
fi

# curl 실행
if [ -n "$CURVES" ]; then
    curl -k -v --connect-timeout 5 --curves "$CURVES" https://"$HOST":"$PORT"/ > "$TMPFILE" 2>&1
else
    curl -k -v --connect-timeout 5 https://"$HOST":"$PORT"/ > "$TMPFILE" 2>&1
fi

# 연결 실패 확인
if ! grep -q "SSL connection using" "$TMPFILE"; then
    echo "[!] 오류: TLS 연결에 실패했거나 SSL 정보를 가져올 수 없습니다."
    echo "상세 에러 로그:"
    tail -n 3 "$TMPFILE"
    exit 1
fi

SSL_LINE=$(grep "SSL connection using" "$TMPFILE" | head -n 1)

# 추출 로직 (불필요한 공백 제거)
PROTOCOL=$(echo "$SSL_LINE" | awk -F'/' '{print $1}' | grep -oE 'TLSv[0-9.]+')
CIPHER=$(echo "$SSL_LINE" | awk -F'/' '{print $2}' | tr -d ' ')
GROUP=$(echo "$SSL_LINE" | awk -F'/' '{print $3}' | tr -d ' ')

echo "=== 요약 ==="
echo "Protocol : ${PROTOCOL:-Unknown}"
echo "Cipher   : ${CIPHER:-Unknown}"
echo "Key Group: ${GROUP:-Unknown}"
echo ""

# 판정 로직 (X25519 기반 = Stage 2, P-curve 기반 = Stage 3)
GROUP_LOWER=$(echo "$GROUP" | tr '[:upper:]' '[:lower:]')

if [[ "$GROUP_LOWER" == *"mlkem"* ]]; then
    if [[ "$GROUP_LOWER" == *"x25519"* ]]; then
        echo "판정: Stage 2 - Hybrid PQC-TLS ✓"
    else
        # p521_mlkem1024, p384_mlkem768 등 P-curve + MLKEM
        echo "판정: Stage 3 - Post-Quantum TLS ✓"
    fi
else
    echo "판정: Stage 1 - Classical TLS (ECC) - PQC 미적용"
    exit 1
fi

exit 0
