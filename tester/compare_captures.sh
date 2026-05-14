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

  # ClientHello: 직접 필드 추출 (verbose 파싱보다 효율적)
  echo "  [ClientHello] 클라이언트 제안 그룹:"
  tshark -r "$PCAP" \
    -Y "tls.handshake.type == 1" \
    -T fields \
    -e tls.handshake.extensions_supported_group \
    2>/dev/null \
    | tr ',' '\n' | sed 's/^/    /'
  echo ""

  # ServerHello: 서버가 선택한 키교환 그룹
  echo "  [ServerHello] 서버 선택 키교환 그룹:"
  tshark -r "$PCAP" \
    -Y "tls.handshake.type == 2" \
    -V 2>/dev/null \
    | grep -iE "key share entry|group:|named group" \
    | tr -d '\r' | cut -c1-80 | sed 's/^/    /' \
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

# Stage 1: X25519 (0x001d)
S1_GROUP=$(tshark -r "$PCAP1" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

# Stage 2: X25519MLKEM768 (0x11ec = 4588)
S2_GROUP=$(tshark -r "$PCAP2" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

# Stage 3: p521_mlkem1024 (0x11ee = 4590) 또는 p384_mlkem768 (0x11ef = 4591) — Hybrid PQC
S3_GROUP=$(tshark -r "$PCAP3" -Y "tls.handshake.type==2" -V 2>/dev/null \
  | grep -iE "key share entry|named group|group:" | head -5)

echo ""
echo "  Stage 1 협상 그룹: $(echo "$S1_GROUP" | tr '\n' ' ' | cut -c1-80)"
echo "  Stage 2 협상 그룹: $(echo "$S2_GROUP" | tr '\n' ' ' | cut -c1-80)"
echo "  Stage 3 협상 그룹: $(echo "$S3_GROUP" | tr '\n' ' ' | cut -c1-80)"
echo ""

# X25519 (group ID 29 / 0x001d)
S1_OK=0
# X25519MLKEM768 (group ID 4588 / 0x11ec)
S2_OK=0
# p521_mlkem1024 (0x11ee=4590) 또는 p384_mlkem768 (0x11ef=4591)
S3_OK=0

echo "$S1_GROUP" | grep -qiE "x25519|29\b" && S1_OK=1
echo "$S2_GROUP" | grep -qiE "4588|0x11ec|11ec" && S2_OK=1
echo "$S3_GROUP" | grep -qiE "4590|0x11ee|11ee|4591|0x11ef|11ef" && S3_OK=1

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
  echo "  Stage 3: PASS — p521_mlkem1024/p384_mlkem768 (Hybrid PQC) 협상 확인"
else
  echo "  Stage 3: 확인 필요 — 그룹 ID를 직접 확인하세요"
fi

echo ""
echo "  패킷 덤프 파일 위치 (호스트):"
echo "    ./tester/captures/stage1_capture.pcap"
echo "    ./tester/captures/stage2_capture.pcap"
echo "    ./tester/captures/stage3_capture.pcap"
echo "  → Wireshark로 열어서 상세 확인 가능"
