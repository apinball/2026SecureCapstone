FROM openquantumsafe/oqs-ossl3:0.10.1 AS cert-gen

# Dilithium3 인증서 생성 (Stage 3 PQ 전용)
RUN mkdir -p /certs && \
    openssl req -x509 -newkey dilithium3 \
        -keyout /certs/dilithium3.key \
        -out /certs/dilithium3.crt \
        -days 365 -nodes \
        -subj "/C=KR/O=QuantumJump/CN=localhost"


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

# Dilithium3 인증서 복사 (cert-gen 스테이지에서)
COPY --from=cert-gen /certs/dilithium3.key /etc/nginx/certs/dilithium3.key
COPY --from=cert-gen /certs/dilithium3.crt /etc/nginx/certs/dilithium3.crt

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
