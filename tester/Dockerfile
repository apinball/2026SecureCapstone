FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN printf "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware\n" > /etc/apt/sources.list && \
apt-get update && \
apt-get install -y --no-install-recommends \
ca-certificates \
curl \
wget \
nmap \
net-tools \
iputils-ping \
tshark \
&& rm -rf /var/lib/apt/lists/*