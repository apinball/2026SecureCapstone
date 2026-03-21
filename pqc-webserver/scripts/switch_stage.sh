#!/bin/bash

# .env 로드
SCRIPT_DIR=$(dirname "$(realpath "$0")")
ENV_FILE="$SCRIPT_DIR/../.env"

if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
else
    echo "오류: .env 파일이 없습니다. .env.example을 복사하여 .env를 생성하세요."
    exit 1
fi

STAGE=$1

case $STAGE in
    1|ecc)
        cp $NGINX_CONF_DIR/nginx-ecc.conf /etc/nginx/nginx.conf
        echo "Stage 1: Classical TLS (ECC)로 전환"
        ;;
    2|hybrid)
        cp $NGINX_CONF_DIR/nginx-hybrid.conf /etc/nginx/nginx.conf
        echo "Stage 2: Hybrid PQC-TLS로 전환"
        ;;
    3|pq)
        cp $NGINX_CONF_DIR/nginx-pq.conf /etc/nginx/nginx.conf
        echo "Stage 3: Post-Quantum TLS로 전환"
        ;;
    *)
        echo "사용법: $0 {1|ecc|2|hybrid|3|pq}"
        exit 1
        ;;
esac

nginx -t && systemctl restart nginx && echo "Nginx 재시작 완료"
