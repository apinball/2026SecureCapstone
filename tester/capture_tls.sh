#!/bin/sh
# capture_tls.sh — TLS 핸드셰이크 패킷 캡처
# 사용법: capture_tls.sh <stage> [host] [port]
# 예시:   docker exec tls-tester capture_tls.sh 1
#         docker exec tls-tester capture_tls.sh 2

STAGE="${1:?stage 미지정 (1 또는 2)}"
HOST="${2:-proxy-server}"
PORT="${3:-443}"
PCAP="/data/stage${STAGE}_capture.pcap"

case "$STAGE" in
  1|ecc)    CURVES="X25519:P-256"         LABEL="Stage 1 (Classical ECC)" ;;
  2|hybrid) CURVES="X25519MLKEM768:X25519" LABEL="Stage 2 (Hybrid PQC)"   ;;
  3|pq)     CURVES="X25519MLKEM768"        LABEL="Stage 3 (PQ-only)"       ;;
  *)
    echo "오류: stage=${STAGE} 는 유효하지 않습니다. {1|2|3}" >&2
    exit 1
    ;;
esac

echo "========================================"
echo " ${LABEL} TLS 핸드셰이크 캡처"
echo "========================================"
echo "대상: https://${HOST}:${PORT}"
echo "캡처 파일: ${PCAP}"
echo ""

# 기존 캡처 파일 삭제
rm -f "$PCAP"

# tshark 백그라운드 캡처 시작 (eth0, port 443, 최대 10초)
echo "[1/3] tshark 캡처 시작..."
tshark -i eth0 -f "tcp port ${PORT}" -w "$PCAP" -a duration:6 > /tmp/tshark.log 2>&1 &
TSHARK_PID=$!
sleep 1

# OQS-curl로 TLS 연결 (핸드셰이크 트리거)
echo "[2/3] TLS 연결 시도 (curves=${CURVES})..."
CURL_OUT=$(curl -skv --curves "$CURVES" "https://${HOST}:${PORT}/" 2>&1)

# curl 결과에서 TLS 협상 정보 출력
echo ""
echo "--- curl TLS 협상 결과 ---"
echo "$CURL_OUT" | grep -iE "ssl connection using|TLSv|curve|group|key" | head -10
echo ""

# tshark 종료 대기
wait $TSHARK_PID 2>/dev/null
echo "[3/3] 캡처 완료"

PACKET_COUNT=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
echo "    저장: ${PCAP} (${PACKET_COUNT}패킷)"
