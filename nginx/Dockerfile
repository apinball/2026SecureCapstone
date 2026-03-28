FROM openquantumsafe/nginx

USER root

# openssl 설치 및 인증서 자동 생성 (빌드 시 1회)
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes

# 설정 파일을 컨테이너 안으로 복사
COPY nginx.conf /opt/nginx/nginx-conf/nginx.conf
COPY nginx-ecc.conf /opt/nginx/nginx-conf/nginx-ecc.conf
COPY nginx-hybrid.conf /opt/nginx/nginx-conf/nginx-hybrid.conf
COPY nginx-pq.conf /opt/nginx/nginx-conf/nginx-pq.conf

EXPOSE 80 443

CMD ["nginx", "-c", "/opt/nginx/nginx-conf/nginx.conf", "-g", "daemon off;"]