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

# oqsprovider.so 위치 탐색 후 openssl.cnf에 로드 설정 추가
RUN OQS_PROV=$(find / -name "oqsprovider.so" 2>/dev/null | head -1) && \
    echo "oqsprovider.so: $OQS_PROV" && \
    if [ -n "$OQS_PROV" ]; then \
        SSL_CONF=$(find /opt /usr/local -name "openssl.cnf" 2>/dev/null | head -1) && \
        echo "openssl.cnf: $SSL_CONF" && \
        if [ -n "$SSL_CONF" ]; then \
            printf '\n[provider_sect]\ndefault = default_sect\noqsprovider = oqs_sect\n\n[default_sect]\nactivate = 1\n\n[oqs_sect]\nmodule = %s\nactivate = 1\n' "$OQS_PROV" >> "$SSL_CONF" && \
            echo "OPENSSL_CONF=$SSL_CONF" >> /etc/environment && \
            echo "[oqsprovider] openssl.cnf 설정 완료: $SSL_CONF"; \
        fi; \
    else \
        echo "[WARN] oqsprovider.so not found — OQS groups may not be available"; \
    fi

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