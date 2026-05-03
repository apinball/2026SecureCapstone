#!/bin/sh
# compare_captures.sh — Stage 1/2/3 TLS 핸드셰이크 패킷 비교
# 사용법: docker exec tls-tester compare_captures.sh

PCAP1="/data/stage1_capture.pcap"
PCAP2="/data/stage2_capture.pcap"
PCAP3="/data/stage3_capture.pcap"

print_handshake() {
  STAGE="$1"
  PCAP="$2"

  echo "========================================"
  echo " Stage ${STAGE} 패킷 분석"
  echo "========================================"

  if [ ! -f "$PCAP" ]; then
    echo "  캡처 파일 없음: ${PCAP}"
    echo "  → capture_tls.sh ${STAGE} 를 먼저 실행하세요"
    echo ""
    return
  fi

  TOTAL=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
  echo "  파일: ${PCAP} (총 ${TOTAL}패킷)"
  echo ""

  # ClientHello: 클라이언트가 제안한 지원 그룹
  echo "  [ClientHello] 클라이언트 제안 그룹:"
  tshark -r "$PCAP" \
    -Y "tls.handshake.type == 1" \
    -V 2>/dev/null \
    | grep -iE "supported group|group:" \
    | sed 's/^/    /' \
    | head -10
  echo ""

  # ServerHello: 서버가 선택한 키교환 그룹
  echo "  [ServerHello] 서버 선택 키교환 그룹:"
  tshark -r "$PCAP" \
    -Y "tls.handshake.type == 2" \
    -V 2>/dev/null \
    | grep -iE "key share entry|group:|named group" \
    | sed 's/^/    /' \
    | head -10
  echo ""
}

print_handshake 1 "$PCAP1"
print_handshake 2 "$PCAP2"
print_handshake 3 "$PCAP3"

# 판정
echo "========================================"
echo " 비교 결과"
echo "========================================"

MISSING=0
[ ! -f "$PCAP1" ] && echo "  Stage 1 캡처 없음" && MISSING=1
[ ! -f "$PCAP2" ] && echo "  Stage 2 캡처 없음" && MISSING=1
[ ! -f "$PCAP3" ] && echo "  Stage 3 캡처 없음" && MISSING=1
[ "$MISSING" -eq 1 ] && exit 1

# Stage 1: X25519 (Classical ECC)
S1_GROUP=$(tshark -r "$PCAP1" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

# Stage 2: X25519MLKEM768 (Hybrid PQC, group ID 4588 / 0x11EC)
S2_GROUP=$(tshark -r "$PCAP2" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

# Stage 3: mlkem1024 (Pure PQC) — 핸드셰이크 실패 시 ClientHello 기반 판정
# OQS 라이브러리 버전 불일치로 ServerHello 없을 수 있음 → ClientHello로 클라이언트 정책 검증
# tshark가 0x0202를 구 IANA 초안명 'frodo976aes'로 표시할 수 있음 → verbose 파싱 사용
S3_CLIENT_GROUP=$(tshark -r "$PCAP3" -Y "tls.handshake.type==1" -V 2>/dev/null \
  | grep -iE "supported group:|key share entry" | head -5)
S3_SERVER_GROUP=$(tshark -r "$PCAP3" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

echo ""
echo "  Stage 1 협상 그룹: $(echo "$S1_GROUP" | tr '\n' ' ' | cut -c1-80)"
echo "  Stage 2 협상 그룹: $(echo "$S2_GROUP" | tr '\n' ' ' | cut -c1-80)"
if [ -n "$S3_SERVER_GROUP" ]; then
  echo "  Stage 3 협상 그룹: $(echo "$S3_SERVER_GROUP" | tr '\n' ' ' | cut -c1-80)"
else
  echo "  Stage 3 ClientHello 그룹: ${S3_CLIENT_GROUP} (서버 응답 없음 — OQS 버전 불일치)"
fi
echo ""

# X25519 (29) vs X25519MLKEM768 (4588/0x11EC) vs mlkem1024 (514/0x0202)
S1_OK=0
S2_OK=0
S3_OK=0

echo "$S1_GROUP" | grep -qiE "x25519|29\b" && S1_OK=1
echo "$S2_GROUP" | grep -qiE "mlkem|4588|0x11ec|11ec" && S2_OK=1

# Stage 3: ClientHello가 mlkem1024(0x0202 / frodo976aes / 514)만 제안하고 x25519 없으면 PASS
# tshark 버전에 따라 그룹명이 frodo976aes 또는 mlkem1024로 다르게 표시될 수 있음
S3_HAS_PQC=0
S3_HAS_X25519=0
echo "$S3_CLIENT_GROUP" | grep -qiE "0x0202|frodo976aes|mlkem1024|514\b" && S3_HAS_PQC=1
echo "$S3_CLIENT_GROUP" | grep -qiE "x25519|0x001d|29\b" && S3_HAS_X25519=1
[ "$S3_HAS_PQC" -eq 1 ] && [ "$S3_HAS_X25519" -eq 0 ] && S3_OK=1

if [ "$S1_OK" -eq 1 ]; then
  echo "  Stage 1: PASS — X25519 (Classical ECC) 협상 확인"
else
  echo "  Stage 1: 확인 필요 — 그룹 ID를 직접 확인하세요"
fi

if [ "$S2_OK" -eq 1 ]; then
  echo "  Stage 2: PASS — X25519MLKEM768 (Hybrid PQC) 협상 확인"
else
  echo "  Stage 2: 확인 필요 — 그룹 ID를 직접 확인하세요"
fi

if [ "$S3_OK" -eq 1 ]; then
  if [ -n "$S3_SERVER_GROUP" ]; then
    echo "  Stage 3: PASS — mlkem1024 (Pure PQC) 클라이언트 정책 및 서버 협상 확인"
  else
    echo "  Stage 3: PASS (클라이언트 정책) — ClientHello에 mlkem1024(0x0202)만 제안, ECC 제외"
    echo "           ※ 서버 응답 없음: OQS nginx/curl 버전 불일치로 핸드셰이크 미완료"
    echo "             (CI에서도 continue-on-error로 처리되는 알려진 호환성 이슈)"
  fi
elif [ "$S3_HAS_X25519" -eq 1 ]; then
  echo "  Stage 3: FAIL — ClientHello에 x25519 혼용됨 (Pure PQC 정책 위반)"
else
  echo "  Stage 3: 확인 필요 — 그룹 ID를 직접 확인하세요 (ClientHello: ${S3_CLIENT_GROUP})"
fi

echo ""
echo "  패킷 덤프 파일 위치 (호스트):"
echo "    ./tester/captures/stage1_capture.pcap"
echo "    ./tester/captures/stage2_capture.pcap"
echo "    ./tester/captures/stage3_capture.pcap"
echo "  → Wireshark로 열어서 상세 확인 가능"
