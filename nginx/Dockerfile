# Stage 1: Dilithium3 인증서 생성 (OQS-OpenSSL 사용)
FROM openquantumsafe/oqs-ossl3:0.10.1 AS cert-builder
RUN mkdir -p /certs && \
    openssl req -x509 -newkey dilithium3 -days 365 \
        -keyout /certs/dilithium3.key \
        -out    /certs/dilithium3.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes && \
    chmod 600 /certs/dilithium3.key

# Stage 2: OQS-Nginx 본체
# NOTE: sha256 pin(d02e7d6e...)이 oqs-ossl3:0.10.1로 생성한 Dilithium3 인증서를
# OpenSSL SECLEVEL 정책으로 거부(ee key too small) → Stage 3 기동 실패.
# 검증된 조합으로 되돌림.
# TODO(#79): oqs-ossl3 호환 버전 확정 후 sha256 pin 복구
FROM openquantumsafe/nginx:0.11.0

USER root

# RSA 인증서 생성 (Stage 1 ECC / Stage 2 Hybrid 공용)
RUN apk add --no-cache openssl curl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes

# Dilithium3 인증서 복사 (Stage 3 PQ-only 전용)
COPY --from=cert-builder /certs/dilithium3.key /etc/nginx/certs/dilithium3.key
COPY --from=cert-builder /certs/dilithium3.crt /etc/nginx/certs/dilithium3.crt

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
