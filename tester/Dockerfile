FROM openquantumsafe/curl

USER root

# 필수 네트워크 및 검증 도구 설치
RUN apk add --no-cache \
    bash \
    nmap \
    net-tools \
    iputils \
    python3

COPY scanner/tls_check.sh /usr/local/bin/tls_check.sh
RUN sed -i 's/\r//' /usr/local/bin/tls_check.sh && \
    chmod +x /usr/local/bin/tls_check.sh