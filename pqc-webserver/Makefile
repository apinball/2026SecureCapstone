HOME_DIR := $(shell echo $$HOME)
BASE_DIR  := $(HOME_DIR)/quantum-jump/pqc-webserver
CERTS_DIR := $(BASE_DIR)/certs
SCRIPTS_DIR := $(BASE_DIR)/scripts
NGINX_DIR := $(BASE_DIR)/nginx

.PHONY: all install certs stage1 stage2 stage3 verify1 verify2 verify3 status clean

all: install certs
	@echo "=== 전체 설치 완료 ==="

## 빌드 및 설치 ##

install: install-liboqs install-oqs-provider register-provider
	@echo "=== oqs-provider 설치 완료 ==="

install-liboqs:
	@echo "--- liboqs 빌드 중 ---"
	git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git $(HOME_DIR)/liboqs
	cmake -S $(HOME_DIR)/liboqs -B $(HOME_DIR)/liboqs/build \
		-DOQS_DIST_BUILD=ON \
		-DBUILD_SHARED_LIBS=ON \
		-DCMAKE_INSTALL_PREFIX=/usr/local
	cmake --build $(HOME_DIR)/liboqs/build --parallel $$(nproc)
	sudo cmake --install $(HOME_DIR)/liboqs/build
	sudo ldconfig

install-oqs-provider:
	@echo "--- oqs-provider 빌드 중 ---"
	git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git $(HOME_DIR)/oqs-provider
	cmake -S $(HOME_DIR)/oqs-provider -B $(HOME_DIR)/oqs-provider/build \
		-DCMAKE_INSTALL_PREFIX=/usr/local \
		-Dliboqs_DIR=/usr/local/lib/cmake/liboqs
	cmake --build $(HOME_DIR)/oqs-provider/build --parallel $$(nproc)
	sudo cmake --install $(HOME_DIR)/oqs-provider/build
	sudo ldconfig

register-provider:
	@echo "--- OpenSSL에 oqs-provider 등록 중 ---"
	sudo sed -i '/\[kali_wide_compatibility_providers\]/a oqsprovider = oqs_sect' /etc/ssl/kali.cnf
	@printf '\n[provider_sect]\ndefault = default_sect\noqsprovider = oqs_sect\n\n[default_sect]\nactivate = 1\n\n[oqs_sect]\nactivate = 1\nmodule = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so\n' | sudo tee -a /usr/lib/ssl/openssl.cnf
	@echo "--- provider 등록 검증 ---"
	openssl list -providers | grep oqsprovider

## 인증서 생성 ##

certs:
	@echo "--- 인증서 생성 중 ---"
	mkdir -p $(CERTS_DIR)
	openssl genrsa -out $(CERTS_DIR)/ca.key 4096
	openssl req -new -x509 -days 3650 -key $(CERTS_DIR)/ca.key -out $(CERTS_DIR)/ca.crt \
		-subj "/C=KR/O=QuantumJump/CN=QuantumJump-CA"
	openssl genrsa -out $(CERTS_DIR)/server.key 2048
	openssl req -new -key $(CERTS_DIR)/server.key -out $(CERTS_DIR)/server.csr \
		-subj "/C=KR/O=QuantumJump/CN=localhost"
	openssl x509 -req -days 365 -in $(CERTS_DIR)/server.csr \
		-CA $(CERTS_DIR)/ca.crt -CAkey $(CERTS_DIR)/ca.key -CAcreateserial \
		-out $(CERTS_DIR)/server.crt
	@echo "=== 인증서 생성 완료 ==="

## TLS 단계 전환 ##

stage1:
	@echo "--- Stage 1: Classical TLS (ECC) 전환 ---"
	sudo bash $(SCRIPTS_DIR)/switch_stage.sh 1
	@$(MAKE) verify1

stage2:
	@echo "--- Stage 2: Hybrid PQC-TLS 전환 ---"
	sudo bash $(SCRIPTS_DIR)/switch_stage.sh 2
	@$(MAKE) verify2

stage3:
	@echo "--- Stage 3: Post-Quantum TLS 전환 (실험적) ---"
	sudo bash $(SCRIPTS_DIR)/switch_stage.sh 3
	@$(MAKE) verify3

## TLS 검증 ##

verify1:
	bash $(SCRIPTS_DIR)/verify_tls.sh localhost 443 1

verify2:
	bash $(SCRIPTS_DIR)/verify_tls.sh localhost 443 2

verify3:
	bash $(SCRIPTS_DIR)/verify_tls.sh localhost 443 3

## 상태 확인 ##

status:
	@echo "=== OpenSSL Provider 상태 ==="
	openssl list -providers
	@echo ""
	@echo "=== Nginx 상태 ==="
	sudo systemctl status nginx --no-pager

## 정리 ##

clean:
	@echo "--- 빌드 디렉토리 정리 ---"
	rm -rf $(HOME_DIR)/liboqs $(HOME_DIR)/oqs-provider
