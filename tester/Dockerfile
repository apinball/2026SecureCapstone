FROM openquantumsafe/curl

USER root

# 필수 네트워크 및 검증 도구 설치
RUN apk add --no-cache \
    bash \
    nmap \
    net-tools \
    iputils

COPY verify_tls.sh /usr/local/bin/verify_tls.sh
RUN sed -i 's/\r//' /usr/local/bin/verify_tls.sh && \
    chmod +x /usr/local/bin/verify_tls.sh