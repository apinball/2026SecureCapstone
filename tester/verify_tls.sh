#!/bin/bash
# verify_tls.sh — OQS-curl로 TLS 협상 검증
# 사용법: verify_tls.sh <host> <port> <stage>
# 예시:   verify_tls.sh proxy-server 443 2
#
# NOTE: OQS-curl(OpenSSL < 3.2.0)은 SSL connection line에 그룹 정보를 포함하지 않으므로
# 알고리즘 확인은 핸드셰이크 성공/실패 결과로 판단합니다 (tls_check.sh와 동일한 방식).

HOST="${1:?호스트 미지정}"
PORT="${2:-443}"
STAGE="${3:-1}"
URL="https://${HOST}:${PORT}/"

TMPFILE_PQ=$(mktemp)
TMPFILE_CLASSIC=$(mktemp)
trap 'rm -f "$TMPFILE_PQ" "$TMPFILE_CLASSIC"' EXIT INT TERM

echo "[verify_tls] host=$HOST port=$PORT stage=$STAGE"

do_curl() {
    curl -k -v --connect-timeout 5 --curves "$1" "$URL" > "$2" 2>&1
    return $?
}

tls_ok() {
    grep -q "SSL connection using" "$1"
}

case "$STAGE" in
  1|ecc)
    echo "[verify_tls] Stage 1: classical 연결 시도 (X25519:P-256)..."
    do_curl "X25519:P-256" "$TMPFILE_PQ"; ECC_EXIT=$?
    if [ "$ECC_EXIT" -ne 0 ] || ! tls_ok "$TMPFILE_PQ"; then
        echo "[verify_tls] FAIL — Stage 1 classical 핸드셰이크 실패"
        cat "$TMPFILE_PQ"; exit 1
    fi
    echo "[verify_tls] PASS — Stage 1 classical TLS 연결 성공"
    ;;

  2|hybrid)
    echo "[verify_tls] Stage 2: PQ-only 연결 시도 (X25519MLKEM768)..."
    do_curl "X25519MLKEM768" "$TMPFILE_PQ"; PQ_EXIT=$?
    echo "[verify_tls] Stage 2: classical 연결 시도 (x25519:prime256v1)..."
    do_curl "x25519:prime256v1" "$TMPFILE_CLASSIC"; CLASSIC_EXIT=$?
    if [ "$PQ_EXIT" -ne 0 ] || ! tls_ok "$TMPFILE_PQ"; then
        echo "[verify_tls] FAIL — Stage 2 PQ 핸드셰이크 실패 (X25519MLKEM768)"
        cat "$TMPFILE_PQ"; exit 1
    fi
    if [ "$CLASSIC_EXIT" -ne 0 ] || ! tls_ok "$TMPFILE_CLASSIC"; then
        echo "[verify_tls] FAIL — Stage 2 classical fallback 핸드셰이크 실패"
        cat "$TMPFILE_CLASSIC"; exit 1
    fi
    echo "[verify_tls] PASS — Stage 2 PQ 핸드셰이크 성공, classical fallback 허용 확인"
    ;;

  3|pq)
    echo "[verify_tls] Stage 3: PQ 연결 시도 (mlkem1024)..."
    do_curl "mlkem1024" "$TMPFILE_PQ"; PQ_EXIT=$?
    echo "[verify_tls] Stage 3: classical 차단 확인 (x25519:prime256v1)..."
    do_curl "x25519:prime256v1" "$TMPFILE_CLASSIC"; CLASSIC_EXIT=$?
    if [ "$PQ_EXIT" -ne 0 ] || ! tls_ok "$TMPFILE_PQ"; then
        echo "[verify_tls] FAIL — Stage 3 PQ 핸드셰이크 실패 (mlkem1024)"
        cat "$TMPFILE_PQ"; exit 1
    fi
    if [ "$CLASSIC_EXIT" -eq 0 ] && tls_ok "$TMPFILE_CLASSIC"; then
        echo "[verify_tls] FAIL — Stage 3 classical 클라이언트가 차단되지 않음 (PQ-only 미적용)"
        exit 1
    fi
    echo "[verify_tls] PASS — Stage 3 PQ 핸드셰이크 성공, classical fallback 차단 확인"
    ;;

  *)
    echo "[verify_tls] 오류: stage=${STAGE} 는 유효하지 않습니다. {1|2|3}"
    exit 1
    ;;
esac

exit 0
