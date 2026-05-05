# =============================================================================
# 자체 빌드 OQS-nginx (OpenSSL 3 + liboqs + oqs-provider 통일 라인)
#
# WHY: openquantumsafe/nginx:0.11.0 (sha256:d02e7d6...)는 OpenSSL 1.1.1q
# 정적 빌드라 OQS-curl 0.11.0 (OpenSSL 3.4 + oqs-provider)와 group code point가
# 안 맞아 PQ KEM 협상 자체가 실패. 같은 라인(OpenSSL 3 + oqs-provider)으로
# 통일 빌드하여 X25519MLKEM768 / p521_mlkem1024:p384_mlkem768 협상 보장.
# =============================================================================

ARG ALPINE_VERSION=3.20
ARG OPENSSL_VERSION=3.4.0
ARG LIBOQS_VERSION=0.13.0
ARG OQSPROVIDER_VERSION=0.9.0
ARG NGINX_VERSION=1.27.2

# -----------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS builder
ARG OPENSSL_VERSION
ARG LIBOQS_VERSION
ARG OQSPROVIDER_VERSION
ARG NGINX_VERSION

RUN apk add --no-cache \
    build-base linux-headers \
    cmake ninja git perl pcre-dev pcre2-dev zlib-dev \
    wget ca-certificates bash

WORKDIR /build

# OpenSSL 3
RUN wget -q https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar xf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./Configure --prefix=/opt/oqs --openssldir=/opt/oqs/ssl shared && \
    make -j$(nproc) && \
    make install_sw

ENV PATH=/opt/oqs/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/oqs/lib64:/opt/oqs/lib

# liboqs (OpenSSL은 KAT/test 용도라 OFF로 비활성화)
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    cmake -GNinja -B build \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_BUILD_ONLY_LIB=ON && \
    ninja -C build install

# oqs-provider
RUN git clone --depth 1 --branch ${OQSPROVIDER_VERSION} https://github.com/open-quantum-safe/oqs-provider.git && \
    cd oqs-provider && \
    cmake -GNinja -B build \
        -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs \
        -DOPENSSL_ROOT_DIR=/opt/oqs \
        -DCMAKE_PREFIX_PATH=/opt/oqs && \
    ninja -C build && \
    PROVIDER_DIR=$(find /opt/oqs -type d -name ossl-modules | head -1) && \
    mkdir -p "$PROVIDER_DIR" && \
    cp build/lib/oqsprovider.so "$PROVIDER_DIR/"

# openssl.cnf — oqsprovider 자동 로드 + SECLEVEL=0
# Why: oqs-provider 0.6.1이 PQ key strength를 0으로 보고 → "ee key too small" 회피.
# `openssl_conf = openssl_init` declaration이 있어야 OpenSSL이 [openssl_init]를 읽음.
RUN mkdir -p /opt/oqs/ssl && \
    cat > /opt/oqs/ssl/openssl.cnf <<'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /opt/oqs/lib64/ossl-modules/oqsprovider.so

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT:@SECLEVEL=0
EOF

# nginx (linked against /opt/oqs OpenSSL 3 + oqsprovider)
RUN unset LD_LIBRARY_PATH && \
    wget --no-check-certificate https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar xf nginx-${NGINX_VERSION}.tar.gz && \
    cd nginx-${NGINX_VERSION} && \
    ./configure --prefix=/opt/nginx \
        --conf-path=/opt/nginx/nginx-conf/nginx.conf \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-cc-opt="-I/opt/oqs/include" \
        --with-ld-opt="-L/opt/oqs/lib64 -L/opt/oqs/lib -Wl,-rpath,/opt/oqs/lib64:/opt/oqs/lib" && \
    make -j$(nproc) && \
    make install

# -----------------------------------------------------------------------------
FROM builder AS cert-builder
# Dilithium3 (NIST ML-DSA) 인증서 생성 — nginx와 같은 OpenSSL 3 + oqs-provider 사용
RUN mkdir -p /certs && \
    openssl req -x509 -new -newkey mldsa65 \
        -provider oqsprovider -provider default \
        -days 365 \
        -keyout /certs/dilithium3.key \
        -out    /certs/dilithium3.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes && \
    chmod 600 /certs/dilithium3.key

# -----------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache pcre pcre2 zlib bash curl ca-certificates

COPY --from=builder /opt/oqs   /opt/oqs
COPY --from=builder /opt/nginx /opt/nginx
COPY --from=cert-builder /certs/dilithium3.crt /etc/nginx/certs/dilithium3.crt
COPY --from=cert-builder /certs/dilithium3.key /etc/nginx/certs/dilithium3.key

ENV PATH=/opt/nginx/sbin:/opt/oqs/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/oqs/lib64:/opt/oqs/lib
ENV OPENSSL_CONF=/opt/oqs/ssl/openssl.cnf
ENV OPENSSL_MODULES=/opt/oqs/lib64/ossl-modules

# RSA 인증서 (Stage 1/2)
RUN openssl req -x509 -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/server.key \
        -out    /etc/nginx/certs/server.crt \
        -subj "/C=KR/O=QuantumJump/CN=localhost" \
        -nodes && \
    chmod 600 /etc/nginx/certs/server.key

COPY nginx.conf        /opt/nginx/nginx-conf/nginx.conf
COPY nginx-ecc.conf    /opt/nginx/nginx-conf/nginx-ecc.conf
COPY nginx-hybrid.conf /opt/nginx/nginx-conf/nginx-hybrid.conf
COPY nginx-pq.conf     /opt/nginx/nginx-conf/nginx-pq.conf

COPY entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh && \
    sed -i 's/\r$//' /docker-entrypoint.sh

ENV TLS_STAGE=1
EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
