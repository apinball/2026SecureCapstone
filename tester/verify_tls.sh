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
    CURVES="X25519MLKEM768"
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

# 추출 로직 (curl 출력 형식 차이를 고려한 fallback 포함)
PROTOCOL=$(echo "$SSL_LINE" | grep -oE 'TLSv[0-9.]+' | head -n 1)
CIPHER=$(echo "$SSL_LINE" | sed -nE 's#.* / ([A-Z0-9_-]+) / .*#\1#p' | head -n 1)
GROUP=$(echo "$SSL_LINE" | sed -nE 's#.* / ([^ /]+)$#\1#p' | head -n 1)

if [ -z "$CIPHER" ]; then
    CIPHER=$(echo "$SSL_LINE" | awk -F'/' '{print $2}' | tr -d ' ')
fi
if [ -z "$GROUP" ]; then
    GROUP=$(echo "$SSL_LINE" | awk -F'/' '{print $3}' | tr -d ' ')
fi

echo "=== 요약 ==="
echo "Protocol : ${PROTOCOL:-Unknown}"
echo "Cipher   : ${CIPHER:-Unknown}"
echo "Key Group: ${GROUP:-Unknown}"
echo ""

GROUP_LOWER=$(echo "$GROUP" | tr '[:upper:]' '[:lower:]')

if [ "$STAGE" = "3" ] || [ "$STAGE" = "pq" ]; then
    # Stage 3: PQC 연결 성공 확인 후 클래식 폴백 차단 검증
    if [[ "$GROUP_LOWER" == *"mlkem"* ]]; then
        echo "판정: PQC 연결 성공 ✓"
        echo "검증 중: 클래식 전용 클라이언트 차단 여부..."
        CLASSIC_RESULT=$(curl -k --connect-timeout 5 --curves "x25519:prime256v1" \
            https://"$HOST":"$PORT"/ 2>&1)
        if echo "$CLASSIC_RESULT" | grep -q "handshake failure\|SSL"; then
            echo "판정: Stage 3 - PQC 강제 적용 ✓ (클래식 폴백 차단 확인)"
        else
            echo "[!] 경고: 클래식 클라이언트도 연결됨 — 폴백 차단 미확인"
            exit 1
        fi
    else
        echo "[!] 오류: PQC TLS 연결이 필요하지만 협상에 실패했습니다."
        exit 1
    fi
elif [[ "$GROUP_LOWER" == *"mlkem"* ]]; then
    echo "판정: Stage 2 - Hybrid PQC-TLS ✓"
    if [ "$STAGE" = "1" ] || [ "$STAGE" = "ecc" ]; then
        echo "[!] 오류: Classical TLS가 필요하지만 PQC가 협상되었습니다."
        exit 1
    fi
else
    echo "판정: Stage 1 - Classical TLS (ECC) - PQC 미적용"
    if [ "$STAGE" = "2" ] || [ "$STAGE" = "hybrid" ]; then
        echo "[!] 오류: PQC TLS 연결이 필요하지만 협상에 실패했습니다."
        exit 1
    fi
fi

exit 0
