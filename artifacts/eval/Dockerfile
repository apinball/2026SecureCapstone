# 평가 하네스용 컨테이너 — liboqs + oqs-python + cryptography + PyCryptodome.
# 사용:
#   docker build -t pqc-eval -f artifacts/eval/Dockerfile .
#   docker run --rm -e GITHUB_TOKEN -v ${PWD}/artifacts/eval:/eval pqc-eval \
#       python /eval/eval_runner.py --k 5

FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG LIBOQS_VERSION=0.14.0
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    cmake -GNinja -B build \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON && \
    ninja -C build install

# ──────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/oqs /opt/oqs
ENV LD_LIBRARY_PATH=/opt/oqs/lib

# liboqs를 dynamic linker cache에 등록 (oqs-python ctypes가 인식)
RUN echo "/opt/oqs/lib" > /etc/ld.so.conf.d/oqs.conf && ldconfig

RUN pip install --no-cache-dir liboqs-python==0.14.1 cryptography pycryptodome

WORKDIR /eval
ENTRYPOINT []
CMD ["python", "/eval/eval_runner.py", "--offline", "--use-reference", "--k", "1"]
