FROM openquantumsafe/curl@sha256:b91f49e027729cf6ba394f5ffe470341924708fe456b4549071ee6df043db89f

USER root

# 필수 네트워크 및 검증 도구 설치
RUN apk add --no-cache \
    bash \
    nmap \
    net-tools \
    iputils \
    python3 \
    tshark

COPY scanner/tls_check.sh /usr/local/bin/tls_check.sh
COPY tester/capture_tls.sh /usr/local/bin/capture_tls.sh
COPY tester/compare_captures.sh /usr/local/bin/compare_captures.sh
COPY perf-rollback/perf_check.sh /usr/local/bin/perf_check.sh
RUN sed -i 's/\r//' /usr/local/bin/tls_check.sh \
                    /usr/local/bin/capture_tls.sh \
                    /usr/local/bin/compare_captures.sh \
                    /usr/local/bin/perf_check.sh && \
    chmod +x /usr/local/bin/tls_check.sh \
             /usr/local/bin/capture_tls.sh \
             /usr/local/bin/compare_captures.sh \
             /usr/local/bin/perf_check.sh
