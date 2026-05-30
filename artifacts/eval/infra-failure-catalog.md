# PQC 인프라 마이그레이션 함정 카탈로그 (B)

본 문서는 캡스톤 프로젝트에서 OQS 기반 PQC TLS를 도입하면서 직접 발견한 실패 모드를 정리한 것이다. 표준 DevSecOps 도구(Trivy, Semgrep, CBOM 등)로는 탐지되지 않는 종류의 함정을 강조한다.

---

## F-1: OQS 라이브러리 버전 비대칭 (oqs-provider sigalg drift)

| 항목 | 내용 |
|---|---|
| **트리거** | 동일 OQS 메이저 버전 태그(`0.11.0`)가 클라이언트(OQS-curl)와 서버(OQS-nginx) 양쪽에 사용됨에도 내부 oqs-provider 버전이 다름 (curl 0.9.0 vs nginx 0.6.1) |
| **증상** | TLS 1.3 ClientHello/ServerHello 단계에서 `alert handshake_failure (552)`. 핸드셰이크가 어떤 group 조합으로도 성공하지 않음 |
| **근본 원인** | oqs-provider 0.6.1과 0.9.0이 ML-DSA/ML-KEM 알고리즘에 다른 IANA code point를 등록. 양쪽이 sigalg/group을 광고하지만 매칭 0개 |
| **표준 도구 탐지** | ❌ Trivy(이미지 CVE 스캔), Semgrep(소스 룰), CBOM(알고리즘 인벤토리)으로 잡히지 않음 |
| **본 프로젝트 방어책** | 자체 빌드 멀티스테이지 Dockerfile로 OpenSSL/liboqs/oqs-provider 버전을 한 라인으로 고정 |
| **재현 명령** | `docker exec pqc-proxy openssl list -signature-algorithms` ↔ `docker exec tls-tester openssl list -signature-algorithms` 비교 |

---

## F-2: OpenSSL 1.1.1 ↔ 3.x 라인 인증서 OID 불일치

| 항목 | 내용 |
|---|---|
| **트리거** | OQS-OpenSSL 1.1.1 fork(oqs-engine 시대)와 OQS-OpenSSL 3.x(oqs-provider 시대)가 같은 알고리즘에 다른 OID 사용. Dilithium3 인증서가 두 라인에서 다른 OID로 인코딩됨 |
| **증상 1** | `nginx: [emerg] SSL_CTX_use_certificate failed (SSL: digital envelope routines::decode error)` |
| **증상 2** | 인증서 디코드 시 `Public Key Algorithm: 1.3.6.1.4.1.2.267.7.6.5 / Unable to load Public Key` (구 OID인데 새 라이브러리가 모름, 또는 그 반대) |
| **근본 원인** | `oqs-ossl3:0.10.1`(OpenSSL 3 라인)으로 cert를 만들면 ML-DSA NIST OID가 부착됨. 이 cert를 OQS-nginx 0.11.0(내부 OpenSSL 1.1.1q 정적 빌드, oqs-engine 시대)에 넣으면 OID 미인식으로 cert 로드 실패 |
| **표준 도구 탐지** | ❌ 인증서 자체는 X.509 유효 → 일반 인증서 검사기로는 정상 |
| **본 프로젝트 방어책** | cert-builder를 nginx 본체와 동일 OpenSSL 라인으로 통일하여 OID 일치 보장 |

---

## F-3: ML-KEM IETF code point ↔ 옛 Kyber OQS code point 충돌

| 항목 | 내용 |
|---|---|
| **트리거** | TLS 1.3 named group으로 `X25519MLKEM768`(IETF 표준 0x11ec) vs `x25519_kyber768`(OQS 사설 0x6399 같은 구 코드포인트)가 서로 다른 라이브러리 세대에서 사용됨 |
| **증상** | `ssl_ecdh_curve` 설정은 nginx config 파싱을 통과(이름이 등록되어 있음)하지만 실제 TLS 협상 시 ClientHello/ServerHello에서 매칭 group 0개 |
| **근본 원인** | OpenSSL 1.1.1 라인 OQS는 Kyber 시대 명칭/코드포인트, OpenSSL 3 라인 oqs-provider 0.9+는 ML-KEM IETF 표준 명칭/코드포인트로 등록. 같은 group이라도 wire format 상수가 다름 |
| **표준 도구 탐지** | ❌ TLS 정책 룰셋(Semgrep)은 string match만 하고 wire-level code point는 보지 않음 |
| **본 프로젝트 방어책** | (F-1과 동일) 동일 라이브러리 라인 통일 |

---

## F-4: PQ key strength 0 보고 → SECLEVEL 정책 거부

| 항목 | 내용 |
|---|---|
| **트리거** | oqs-provider가 ML-DSA/ML-KEM에 대해 OpenSSL `EVP_PKEY_security_bits()` 값을 0으로 보고 |
| **증상** | `nginx: [emerg] SSL_CTX_use_certificate failed (ssl/tls alert: ee key too small)` — PQ 인증서가 OpenSSL의 default SECLEVEL=2(112-bit 이상 요구)에 걸림 |
| **근본 원인** | NIST PQC 알고리즘의 "보안 비트" 정의가 OpenSSL의 전통적 RSA/ECC bits 기준과 다름. oqs-provider 0.9.0은 보수적으로 0 반환 |
| **표준 도구 탐지** | ❌ |
| **본 프로젝트 방어책** | `ssl_ciphers DEFAULT:@SECLEVEL=0` (임시 방편). oqs-provider가 strength 정상 보고 시 제거 예정 |
| **부작용 경고** | SECLEVEL=0은 약한 RSA/SHA-1까지 허용. 서버에서 PQ 외 알고리즘이 활성이면 다른 약점 노출. 본 프로젝트는 `ssl_protocols TLSv1.3` + group whitelist로 보완 |

---

## F-5: 같은 sha256 핀이 시점 따라 다른 소프트웨어를 가리킴

| 항목 | 내용 |
|---|---|
| **트리거** | OQS Project가 `openquantumsafe/nginx:0.11.0` 태그를 다시 빌드/푸시하면서 sha256이 변경됨. 우리 git 이력의 핀(`sha256:d02e7d6e...`)이 처음 PR에선 OpenSSL 3 빌드를 가리켰지만 4주 후 `docker pull` 시점엔 OpenSSL 1.1.1 빌드를 가리키게 됨 |
| **증상** | 이전 PR 머지 시 CI 통과한 핀이 시간이 지나 환경 재구성하면 핸드셰이크 실패 |
| **근본 원인** | Docker registry tag와 manifest list의 시간적 가변성. sha256 자체는 immutable이지만 사용자가 인지하는 "0.11.0"이라는 식별자는 가변 |
| **표준 도구 탐지** | ❌ 일반적 supply chain 스캐너(예: Trivy)는 알려진 CVE만 보고 빌드 대체 자체는 정상 동작 |
| **본 프로젝트 방어책** | nginx 자체 빌드로 외부 이미지 의존 자체를 제거. OpenSSL/liboqs/oqs-provider/nginx 모두 소스 + sha256 검증 |
| **교훈** | "sha256 핀 = 재현성 보장"이 PQC 도입 초기 도구 체인에서 깨질 수 있음. 빌드 from source가 더 안전 |

---

## F-6: standalone PQ group (ML-KEM-1024 등)이 hybrid보다 협상 불가능한 이미지

| 항목 | 내용 |
|---|---|
| **트리거** | `ssl_ecdh_curve mlkem1024` 단독 설정이 OQS-nginx 0.11.0 기본 빌드에서 협상 안 됨. 같은 빌드가 `p521_mlkem1024:p384_mlkem768` hybrid는 협상함 |
| **증상** | nginx 시작은 정상, ssl_ecdh_curve 파싱도 통과하지만 실제 TLS handshake 단계에서 협상 실패 |
| **근본 원인** | OQS-nginx 빌드 시 `OQS_KEM_DEFAULT_ALGS_ENABLED` CMake 플래그에 standalone PQ KEM이 빠지거나, oqs-provider config에서 group이 활성화되지 않음 |
| **표준 도구 탐지** | ❌ |
| **본 프로젝트 방어책** | hybrid group으로 회귀, CI matrix(PR #83)로 회귀 자동 감지 |

---

## 함정과 방어책 매핑 (요약 표)

| 함정 | Trivy | Semgrep | CBOM | matrix CI | AST 검증 | 자체빌드 |
|---|---|---|---|---|---|---|
| F-1 sigalg drift | ❌ | ❌ | ❌ | ⭕ (감지) | ❌ | ⭕ (예방) |
| F-2 OID mismatch | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-3 group code point | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-4 SECLEVEL 거부 | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ (config 통합) |
| F-5 sha256 시간 가변 | ❌ | ❌ | ❌ | ⭕ (지연 감지) | ❌ | ⭕ |
| F-6 standalone 미협상 | ❌ | ❌ | ❌ | ⭕ | ❌ | — |

**시사점**: 6개 함정 중 어느 하나도 표준 정적 분석/SCA/SBOM 도구로 사전에 잡히지 않는다. 런타임 매트릭스 CI와 자체 빌드(supply chain integrity 강제)가 PQC 도입 시 표준 도구의 사각지대를 메운다.

---

## 외부 타당성 (External Validity)

본 카탈로그는 OpenSSL/OQS 스택 한정. 그러나 동일 패턴이 다른 PQC 스택에서도 재현 가능:

- **BoringSSL + Cloudflare PQ fork**: 동일한 group code point drift가 CIRCL 라이브러리 마이너 버전 간 보고됨
- **Java BCJSSE + Bouncy Castle PQ**: OID/sigalg 비대칭 보고가 BC 1.77 → 1.78 마이그레이션에서 발생
- **공통**: NIST 표준화 이전 후보 알고리즘에서 표준화 이후 명칭/코드포인트로 전환되는 시점에 도구 체인이 라인을 단일화하지 못하면 동일한 함정 발생

따라서 본 카탈로그는 OpenSSL/OQS 한정 기록이 아니라 **PQC 표준화 전환기에 보편적으로 발생하는 도구 체인 함정의 사례 연구**로 위치.
