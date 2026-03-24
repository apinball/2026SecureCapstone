# Quantum Jump — PQC 웹 서버 설정 가이드

팀원 1 (최유림) 담당: OpenSSL 3 + oqs-provider + Nginx TLS 단계별 전환 환경

---

## 환경 요구사항

- WSL2 + Kali Linux (또는 Ubuntu 22.04 이상)
- OpenSSL 3.x (Kali 기본 탑재)
- 인터넷 연결 (GitHub clone)

---

## 1단계: 의존성 설치

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y build-essential cmake ninja-build libssl-dev git wget curl python3
```

---

## 2단계: liboqs 빌드 및 설치

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git ~/liboqs
cmake -S ~/liboqs -B ~/liboqs/build \
    -DOQS_DIST_BUILD=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build ~/liboqs/build --parallel $(nproc)
sudo cmake --install ~/liboqs/build
sudo ldconfig
```

---

## 3단계: oqs-provider 빌드 및 설치

```bash
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git ~/oqs-provider
cmake -S ~/oqs-provider -B ~/oqs-provider/build \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -Dliboqs_DIR=/usr/local/lib/cmake/liboqs
cmake --build ~/oqs-provider/build --parallel $(nproc)
sudo cmake --install ~/oqs-provider/build
sudo ldconfig
```

---

## 4단계: OpenSSL에 oqs-provider 등록

```bash
# openssl.cnf에 oqs-provider 섹션 추가
sudo tee -a /usr/lib/ssl/openssl.cnf << 'CNFEOF'

[provider_sect]
default = default_sect
oqsprovider = oqs_sect

[default_sect]
activate = 1

[oqs_sect]
activate = 1
module = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so
CNFEOF

# Kali Linux 한정: kali.cnf에 oqs-provider 추가
sudo sed -i '/\[kali_wide_compatibility_providers\]/a oqsprovider = oqs_sect' /etc/ssl/kali.cnf
```

### 검증

```bash
openssl list -providers                      # oqsprovider 가 보이면 성공
openssl list -kem-algorithms | grep -i mlkem # ML-KEM 알고리즘 목록 확인
```

---

## 5단계: Nginx 설치

```bash
sudo apt-get install -y nginx
```

---

## 6단계: 인증서 생성

```bash
mkdir -p ~/quantum-jump/pqc-webserver/certs
cd ~/quantum-jump/pqc-webserver/certs

# 자체 CA 생성
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=KR/O=QuantumJump/CN=QuantumJump-CA"

# 서버 인증서 생성 및 서명
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=KR/O=QuantumJump/CN=localhost"
openssl x509 -req -days 365 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt
```

> 인증서 파일은 .gitignore로 제외되어 있습니다. 각자 로컬에서 생성해야 합니다.

---

## 사용법

### TLS 단계 전환

```bash
sudo bash ~/quantum-jump/pqc-webserver/scripts/switch_stage.sh 1   # Stage 1: Classical TLS (ECC)
sudo bash ~/quantum-jump/pqc-webserver/scripts/switch_stage.sh 2   # Stage 2: Hybrid PQC-TLS
sudo bash ~/quantum-jump/pqc-webserver/scripts/switch_stage.sh 3   # Stage 3: Post-Quantum TLS (실험적)
```

### TLS 협상 결과 검증

```bash
bash ~/quantum-jump/pqc-webserver/scripts/verify_tls.sh localhost 443 1
bash ~/quantum-jump/pqc-webserver/scripts/verify_tls.sh localhost 443 2
bash ~/quantum-jump/pqc-webserver/scripts/verify_tls.sh localhost 443 3
```

### 예상 결과

| 단계 | Key Group | 판정 |
|------|-----------|------|
| Stage 1 | X25519 | Classical TLS (ECC) |
| Stage 2 | X25519MLKEM768 | Hybrid PQC-TLS |
| Stage 3 | — | 실험적 (표준 미확정) |

---

## Makefile 사용법

```bash
make all        # liboqs + oqs-provider 설치 + 인증서 생성 한번에
make stage1     # Stage 1 전환 + 검증
make stage2     # Stage 2 전환 + 검증
make stage3     # Stage 3 전환 + 검증
make verify1    # Stage 1 검증만
make verify2    # Stage 2 검증만
make verify3    # Stage 3 검증만
make status     # OpenSSL provider 및 Nginx 상태 확인
```

---

## 파일 구조

```
pqc-webserver/
├── nginx/
│   ├── nginx-ecc.conf       # Stage 1: Classical TLS
│   ├── nginx-hybrid.conf    # Stage 2: Hybrid PQC-TLS
│   └── nginx-pq.conf        # Stage 3: Post-Quantum TLS (실험적)
├── certs/                   # 로컬에서 생성 (git 제외)
│   ├── ca.key / ca.crt
│   └── server.key / server.crt
├── scripts/
│   ├── switch_stage.sh      # 단계 전환 스크립트
│   └── verify_tls.sh        # TLS 협상 검증 스크립트
├── Makefile
├── README.md
└── .gitignore
```

---

## 문제 해결

**oqsprovider가 목록에 안 보일 때**

```bash
sudo ldconfig
openssl list -providers
```

**Nginx 시작 실패 시**

```bash
sudo nginx -t
sudo systemctl status nginx
```
