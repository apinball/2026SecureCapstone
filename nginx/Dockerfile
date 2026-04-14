# Stage 1: cert-builder
FROM openquantumsafe/curl@sha256:b91f49e027729cf6ba394f5ffe470341924708fe456b4549071ee6df043db89f AS cert-builder
USER root
RUN mkdir -p /certs && \
    OPENSSL_CONF=/opt/oqssa/ssl/openssl.cnf \
    OPENSSL_MODULES=/opt/oqssa/lib/ossl-modules \
    openssl req \
        -provider oqsprovider \
        -provider default \
        -x509 -newkey dilithium3 -days 365 \
        -keyout /certs/dilithium3.key \
        -out    /certs/dilithium3.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes && \
    chmod 600 /certs/dilithium3.key


# Stage 2: OQS-Nginx 본체
FROM openquantumsafe/nginx@sha256:d02e7d6ec43bc3ea1c174f24d35af0e60a29eec0c9e6c39f356dba8b43f19f34

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
