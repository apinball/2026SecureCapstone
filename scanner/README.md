# scanner/

## 개요

이 디렉토리는 DevSecOps 파이프라인의 정적/동적 보안 분석을 담당한다.

파이프라인 내 역할:
- Step 5: 고전 암호 탐지 (crypto-classical.yaml)
- Step 6: SAST · 시크릿 · CVE 스캔 (Trivy / Gitleaks / Semgrep)
- Step 7: TLS 암호 정책 검증 — Security Gate (tls-policy.yaml)
- Step 9: 동적 TLS 핸드셰이크 검증 (tls_check.sh)

---

## 스크립트

### run_scanners.sh

Trivy, Gitleaks, Semgrep을 순서대로 실행하는 통합 래퍼 스크립트.

**사용법**
```bash
bash scanner/run_scanners.sh <scan_target> <stage>
```

| 인자 | 설명 | 기본값 |
|---|---|---|
| `scan_target` | 스캔 대상 경로 | `scanner/..` (프로젝트 루트) |
| `stage` | TLS 마이그레이션 단계 (1~3) | `1` |

| exit code | 의미 |
|---|---|
| `0` | 전체 PASS |
| `1` | 1개 이상 도구 FAIL |

**output**: `scanner/results/scan-summary.json`

---

### trivy_scan.sh

Trivy를 사용해 CVE 취약점 및 미설정(Misconfiguration)을 스캔한다.
`--scanners vuln,misconfig` 옵션을 사용하며, 시크릿 스캔은 Gitleaks가 담당한다.

**사용법**
```bash
bash scanner/trivy_scan.sh <scan_target> <stage>
```

| exit code | 의미 |
|---|---|
| `0` | PASS (HIGH/CRITICAL 없음) |
| `1` | FAIL (HIGH 또는 CRITICAL 탐지) |

**output**: `scanner/results/trivy-result.json`, `scanner/results/trivy-summary.json`

---

### gitleaks_scan.sh

Gitleaks를 사용해 하드코딩된 시크릿(API 키, 토큰 등)을 탐지한다.
`detect --source` 방식으로 현재 파일 상태를 스캔한다.

**사용법**
```bash
bash scanner/gitleaks_scan.sh <scan_target> <stage>
```

| exit code | 의미 |
|---|---|
| `0` | PASS (시크릿 없음) |
| `1` | FAIL (시크릿 탐지) |

**output**: `scanner/results/gitleaks-result.json`, `scanner/results/gitleaks-summary.json`

---

### semgrep_scan.sh

Semgrep으로 코드 전체를 정적 분석한다. `crypto-classical.yaml` 룰만 적용하며,
`tls-policy.yaml`은 파이프라인 Step 7(Security Gate)에서 별도 실행된다.

**사용법**
```bash
bash scanner/semgrep_scan.sh <scan_target> <stage>
```

| exit code | 의미 |
|---|---|
| `0` | PASS (ERROR severity 없음) |
| `1` | FAIL (ERROR severity 탐지) |

> Semgrep exit code 1은 findings 존재(정상 동작), exit code 2 이상은 실행 오류

**output**: `scanner/results/semgrep-result.json`, `scanner/results/semgrep-summary.json`

---

### tls_check.sh

OQS-curl의 `--curves` 옵션으로 TLS 핸드셰이크를 시도하여 서버의 TLS 정책을 동적으로 검증한다.
파이프라인 Step 9에서 tls-tester 컨테이너 내부에서 실행된다.

**사용법**
```bash
tls_check.sh <host> <port> <stage>
# stage: 1|ecc, 2|hybrid, 3|pq
```

| Stage | 검증 내용 |
|---|---|
| 1 (Classical ECC) | 클래식 커브 연결 성공 + PQ-only 거부 확인 |
| 2 (Hybrid PQC) | X25519MLKEM768 연결 성공 + 클래식 폴백 허용 확인 |
| 3 (Pure PQC) | mlkem1024 연결 성공 + 클래식 거부 확인 |

| exit code | 의미 |
|---|---|
| `0` | PASS |
| `1` | FAIL |

**output**: `results/tls-check-summary.json` (컨테이너 내 `/usr/local/bin/results/`)

---

## Semgrep 룰

### rules/tls-policy.yaml — TLS 정책 검증 (Security Gate)

파이프라인 Step 7에서 `nginx/` 설정 파일을 대상으로 실행된다.

| 룰 ID | 심각도 | 탐지 대상 |
|---|---|---|
| `nginx-weak-tls-protocol-10` | ERROR | TLSv1.0 사용 |
| `nginx-weak-tls-protocol-11` | ERROR | TLSv1.1 사용 |
| `nginx-weak-ssl-ciphers-rc4` | ERROR | RC4 암호 사용 |
| `nginx-weak-ssl-ciphers-des` | ERROR | DES 암호 사용 |
| `nginx-classical-ecdh-curve` | WARNING | PQC 미포함 클래식 키교환 (`mlkem` 없음) |

### rules/crypto-classical.yaml — 레거시 암호 탐지 (SAST)

파이프라인 Step 5에서 코드 전체(Python, Java, 설정 파일)를 대상으로 실행된다.
RSA, MD5, SHA-1, DES, 클래식 ECDSA 등 고전 암호 패턴을 탐지한다.

---

## 설계 결정 사항

### tls_check.sh — openssl s_client 대신 curl --curves 방식 사용

TLS 정책 검증에 `openssl s_client` 대신 `curl --curves`를 사용한다.
tls-tester 컨테이너(`openquantumsafe/curl`)는 PQC 알고리즘 지원을 위해 OQS 라이브러리가 통합된 환경이며,
`--curves` 옵션으로 클라이언트가 제시하는 커브를 직접 제어하여 핸드셰이크 성공/실패로 정책을 검증한다.
이 방식은 특정 커브만 허용하는 서버에 의도적으로 거부당하는 시나리오(네거티브 테스트)를 구조적으로 표현할 수 있다.

### Semgrep WARNING 4건 — Stage 1 설계상 의도된 탐지

Stage 1(Classical ECC) 환경에서 `run_scanners.sh` 실행 시 `generic-rsa-key-size-weak` 룰이 WARNING 4건을 탐지한다.
이는 `nginx/Dockerfile`의 RSA 인증서 생성 코드를 탐지한 것으로, Stage 1의 설계상 의도된 결과이다.
해당 항목은 파이프라인을 차단하지 않으며(WARNING은 PASS 판정), Stage 2·3 전환 시 자동으로 해소된다.

---

## Output 파일

파이프라인 실행 후 `scanner/results/` 에 아래 파일들이 생성된다.

| 파일 | 생성 스크립트 | 설명 |
|---|---|---|
| `scan-summary.json` | `run_scanners.sh` | Trivy·Gitleaks·Semgrep 통합 결과 |
| `trivy-result.json` | `trivy_scan.sh` | Trivy 상세 결과 (CVE·Misconfig) |
| `trivy-summary.json` | `trivy_scan.sh` | Trivy 요약 (CRITICAL·HIGH·MEDIUM 건수) |
| `gitleaks-result.json` | `gitleaks_scan.sh` | Gitleaks 상세 결과 |
| `gitleaks-summary.json` | `gitleaks_scan.sh` | Gitleaks 요약 (leaks 건수) |
| `semgrep-result.json` | `semgrep_scan.sh` | Semgrep 상세 결과 |
| `semgrep-summary.json` | `semgrep_scan.sh` | Semgrep 요약 (ERROR·WARNING 건수) |
| `tls-check-summary.json` | `tls_check.sh` | TLS 동적 검증 결과 |
