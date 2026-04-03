FROM openquantumsafe/nginx

USER root

# RSA 인증서 생성 (Stage 1 ECC / Stage 2 Hybrid 공용)
RUN apk add --no-cache openssl curl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes

# Dilithium3 인증서 생성 (Stage 3 PQ-only 전용, OQS-OpenSSL 내장)
RUN openssl req -x509 -newkey dilithium3 -days 365 \
        -keyout /etc/nginx/certs/dilithium3.key \
        -out /etc/nginx/certs/dilithium3.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes && \
    chmod 600 /etc/nginx/certs/dilithium3.key

# 설정 파일을 컨테이너 안으로 복사
COPY nginx.conf /opt/nginx/nginx-conf/nginx.conf
COPY nginx-ecc.conf /opt/nginx/nginx-conf/nginx-ecc.conf
COPY nginx-hybrid.conf /opt/nginx/nginx-conf/nginx-hybrid.conf
COPY nginx-pq.conf /opt/nginx/nginx-conf/nginx-pq.conf

COPY entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# 기본 Stage: 1 (ECC)
ENV TLS_STAGE=1

EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.sh"]