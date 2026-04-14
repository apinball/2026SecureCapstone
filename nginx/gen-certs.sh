#!/bin/sh
# gen-certs.sh — 로컬 테스트용 TLS 인증서 생성 스크립트
#
# Stage 1/2: RSA-2048 인증서 (시스템 openssl)
# Stage 3:   Dilithium3 인증서 (OQS-OpenSSL, Docker 필요)
#
# 사용법: sh nginx/gen-certs.sh
# 생성 위치: nginx/certs/ (로컬 테스트용)
# 참고: 컨테이너 내부 인증서는 Dockerfile 빌드 시 자동 생성됨

set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS_DIR"

# ─────────────────────────────────────────────────────────
# Stage 1 & 2 공용: RSA-2048 인증서
# ─────────────────────────────────────────────────────────
echo "=== [1/2] RSA-2048 인증서 생성 (Stage 1 ECC / Stage 2 Hybrid 공용) ==="
openssl req -x509 -newkey rsa:2048 -days 365 \
  -keyout "$CERTS_DIR/server.key" \
  -out    "$CERTS_DIR/server.crt" \
  -subj "/C=KR/O=QuantumJump/CN=localhost" \
  -nodes
echo "    → server.key / server.crt 생성 완료"

# ─────────────────────────────────────────────────────────
# Stage 3 전용: PQC 인증서 생성 (OQS-OpenSSL via Docker)
# ─────────────────────────────────────────────────────────
docker run --rm -u root \
  -v "$CERTS_DIR:/certs" \
  openquantumsafe/curl:0.8.0 \
  sh -c "
    OPENSSL_MODULES=/opt/oqssa/lib/ossl-modules \
    /opt/oqssa/bin/openssl req \
      -provider oqsprovider \
      -provider default \
      -x509 -newkey dilithium3 \
      -keyout /certs/dilithium3.key \
      -out    /certs/dilithium3.crt \
      -days 365 -nodes \
      -subj '/C=KR/O=QuantumJump/CN=localhost' && \
    chmod 600 /certs/dilithium3.key && \
    chmod 644 /certs/dilithium3.crt
  "
echo "    → PQC 인증서 (dilithium3 알고리즘) 생성 완료"

echo ""
echo "=== 완료 ==="
ls -la "$CERTS_DIR"
