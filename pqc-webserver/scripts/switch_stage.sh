#!/bin/bash

STAGE=$1
NGINX_CONF_DIR=/home/yulimH/quantum-jump/pqc-webserver/nginx

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

nginx -t && systemctl start nginx && echo "Nginx 재시작 완료"
