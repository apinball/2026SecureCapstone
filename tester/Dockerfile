FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# 필수 네트워크 및 검증 도구 설치
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    nmap \
    net-tools \
    iputils-ping \
    tshark \
    && rm -rf /var/lib/apt/lists/*