#!/bin/sh
# entrypoint.sh — Docker 컨테이너 시작 시 TLS_STAGE에 따라 nginx 설정 선택
# switch_stage.sh의 Docker 호환 버전 (systemctl 미사용)
#
# TLS_STAGE: 1(ecc) | 2(hybrid) | 3(pq)  — 기본값: 1
#
# 사용법:
#   docker compose up                          # Stage 1 (ECC)
#   TLS_STAGE=2 docker compose up              # Stage 2 (Hybrid)
#   TLS_STAGE=3 docker compose up              # Stage 3 (PQ-only)

set -e

CONF_DIR="/opt/nginx/nginx-conf"

case "${TLS_STAGE:-1}" in
  1|ecc)
    echo "[entrypoint] Stage 1: Classical TLS (ECC) → nginx-ecc.conf 적용"
    rm -f "$CONF_DIR/nginx.conf" && cp "$CONF_DIR/nginx-ecc.conf" "$CONF_DIR/nginx.conf"
    ;;
  2|hybrid)
    echo "[entrypoint] Stage 2: Hybrid PQC-TLS → nginx-hybrid.conf 적용"
    rm -f "$CONF_DIR/nginx.conf" && cp "$CONF_DIR/nginx-hybrid.conf" "$CONF_DIR/nginx.conf"
    ;;
  3|pq)
    echo "[entrypoint] Stage 3: Post-Quantum TLS → nginx-pq.conf 적용"
    rm -f "$CONF_DIR/nginx.conf" && cp "$CONF_DIR/nginx-pq.conf" "$CONF_DIR/nginx.conf"
    ;;
  *)
    echo "[entrypoint] 오류: TLS_STAGE=${TLS_STAGE} 는 유효하지 않습니다. {1|ecc|2|hybrid|3|pq}" >&2
    exit 1
    ;;
esac

exec nginx -c "$CONF_DIR/nginx.conf" -g 'daemon off;'
