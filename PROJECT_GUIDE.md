# 2026SecureCapstone — 프로젝트 가이드

> 새 세션이 이 프로젝트를 빠르게 파악하기 위한 종합 문서. 코드와 git history만으로는 잘 드러나지 않는 설계 의도와 흐름을 설명한다.

---

## 1. 프로젝트 개요

DevSecOps 캡스톤 프로젝트. **양자내성암호(PQC, Post-Quantum Cryptography) 기반 TLS 3단계 마이그레이션**과 그 전 과정을 자동화하는 CI/CD 파이프라인을 구축했다.

핵심 목표:

- 클래식 TLS → 하이브리드 PQC → 순수 PQC로 점진적 전환을 **CI 게이트로 강제**
- 보안 스캔(SAST·시크릿·CVE)과 PQC 정책 검증을 단일 파이프라인에 통합
- 성능 회귀 시 자동 롤백, 인증서 호환성 회귀 시 머지 전 차단
- LLM 기반 레거시 암호 코드 자동 마이그레이션 PoC
- 결과물을 CycloneDX CBOM으로 표준화

대상 환경: Open Quantum Safe(OQS) nginx/curl 컨테이너, Ubuntu 24.04 GitHub Actions runner.

---

## 2. TLS Stage 정의

| Stage | 분류 | nginx ssl_ecdh_curve | 인증서 | 용도 |
|-------|------|----------------------|--------|------|
| 1 | Classical ECC | `X25519:prime256v1:secp384r1` | RSA-2048 | 마이그레이션 출발점 |
| 2 | Hybrid PQC | `X25519MLKEM768:X25519` | RSA-2048 | 호환성 + PQC 동시 지원 |
| 3 | PQ-only | `mlkem1024` | Dilithium3 (ML-DSA-65) | 클래식 폴백 차단, 순수 PQC |

전환 흐름은 `nginx/entrypoint.sh`가 `TLS_STAGE` 환경변수(`1|2|3`)에 따라 `nginx-ecc.conf` / `nginx-hybrid.conf` / `nginx-pq.conf` 중 하나를 동적으로 적용하는 구조.

---

## 3. 디렉터리 구조

```
.
├── .github/workflows/
│   ├── devsecops-pipeline.yml    메인 파이프라인 (11 step)
│   ├── tls-stage-matrix.yml       Stage 2/3 회귀 감지 매트릭스
│   └── ai-migration.yml            LLM 기반 자동 마이그레이션 PoC (수동 트리거)
│
├── nginx/                          OQS-nginx 이미지 빌드 컨텍스트
│   ├── Dockerfile                   멀티스테이지 (cert-builder + nginx 본체)
│   ├── entrypoint.sh                TLS_STAGE에 따라 nginx.conf 교체
│   ├── nginx-ecc.conf               Stage 1 (Classical ECC)
│   ├── nginx-hybrid.conf            Stage 2 (Hybrid PQC)
│   ├── nginx-pq.conf                Stage 3 (Pure PQC, Dilithium3 cert)
│   └── nginx.conf                   런타임 동적 선택본 (entrypoint.sh가 덮어씀)
│
├── tester/                         OQS-curl 기반 테스트 클라이언트
│   ├── Dockerfile                   tshark, perf_check.sh 포함
│   ├── verify_tls.sh                Stage별 TLS 협상 검증 (curl --curves)
│   ├── capture_tls.sh               tshark 패킷 캡처 (시연용)
│   └── compare_captures.sh          Stage 1/2 핸드셰이크 패킷 비교
│
├── scanner/                        보안 스캔 도구 + 룰
│   ├── tls_check.sh                 TLS 정책 동적 검증 (handshake 기반)
│   ├── run_scanners.sh              Trivy + Gitleaks + Semgrep 통합 래퍼
│   ├── trivy_scan.sh / gitleaks_scan.sh / semgrep_scan.sh
│   ├── rules/
│   │   ├── crypto-classical.yaml    Python/Java RSA·MD5·DES 등 레거시 패턴
│   │   └── tls-policy.yaml          nginx 약한 프로토콜/cipher autofix 룰
│   └── README.md                     스크립트별 사용법, exit code, 설계 결정
│
├── policy/                         CBOM 생성 + 비교
│   ├── cbom_gen.py                  CycloneDX 1.7 CBOM 생성 (TLS 자산 → JSON)
│   ├── cbom_diff.py                 이전 CBOM과 diff → migration_progress 기록
│   │                                  + --verify-tls로 실제 TLS 핸드셰이크와 교차 검증
│   └── test_cbom_diff.py            cbom_diff 단위 테스트
│
├── perf-rollback/                  성능 게이트 + 자동 롤백
│   ├── perf_check.sh                tls-tester 컨테이너에서 30회 핸드셰이크 측정
│   │                                  중앙값/p90/실패율 → JSON 리포트
│   └── rollback.sh                   임계치 초과 시 이전 stage nginx.conf로 자동
│                                      커밋·푸시 ([skip ci] 포함)
│
├── ai-migration/                   LLM 기반 코드 자동 마이그레이션 PoC
│   ├── migrate.py                    semgrep 결과 → GitHub Models → 검증 → 자동 PR
│   ├── prompts/rsa_to_mlkem.txt      oqs-python API 가이드가 포함된 프롬프트
│   └── README.md                     사용법, 제한 사항, 안전장치
│
├── examples/                       데모용 의도된 vulnerable 코드
│   └── legacy_crypto_example.py      RSA 사용 (ai-migration 워크플로우 대상)
│
├── backend/                        FastAPI 백엔드 (proxy 뒤단)
├── pqc-webserver/                  레거시 PQC 웹서버 (참고용)
├── dashboard/                      GitHub Pages 보안 대시보드
├── artifacts/                      CI run 결과물 임시 저장소
└── docker-compose.yml              proxy-server / backend-api / tls-tester 정의
```

---

## 4. 메인 파이프라인 (`devsecops-pipeline.yml`)

`push` / `pull_request` / `workflow_dispatch` 트리거. 총 11단계.

| Step | 이름 | 기능 |
|------|------|------|
| 1 | 저장소 코드 가져오기 | `actions/checkout@v4` |
| 2 | Stage 감지 및 nginx.conf 준비 | `workflow_dispatch` 입력 또는 `nginx.conf` 내용으로 stage 결정 |
| 3 | Semgrep 설치 | PEP 668 환경 fallback 포함 |
| 4 | nginx 설정 자동 변경 | classical TLS 감지 시 hybrid로 자동 마이그레이션 + 자동 커밋·푸시 |
| 5 | 고전 암호 탐지 | `crypto-classical.yaml` 룰로 코드 전체 스캔 (`examples/*` 제외) |
| 6 | 정적 보안 분석 | Trivy(CVE) + Gitleaks(secret) + Semgrep(SAST) → 차단 판정 |
| 7 | TLS 암호 정책 검증 | `tls-policy.yaml` Security Gate (nginx-ecc.conf 제외) |
| 8 | PQC Nginx 도커 빌드 및 가동 | `docker compose up` + healthcheck 대기 |
| 9 | 배포 후 동적 검증 | tls-tester에서 `tls_check.sh` 실행 (Stage별 핸드셰이크 정책 검증) |
| 10 | 성능 검증 및 자동 롤백 | `perf_check.sh` 30회 측정 → 임계치 초과 시 `rollback.sh` |
| 11 | CBOM 명세서 생성 및 리포팅 | `cbom_gen.py` → `cbom_diff.py --verify-tls` → CycloneDX 1.7 schema 검증 |

추가 step:
- PR 보안 리포트 코멘트 (PR 이벤트만)
- 파이프라인 실패 시 GitHub Issue 자동 생성 + Slack 알람 (main 브랜치만)
- 스캔 결과 / CBOM artifact 업로드

---

## 5. 보조 워크플로우

### `tls-stage-matrix.yml` — Stage 2/3 회귀 감지 매트릭스

메인 파이프라인은 push 트리거에서 기본 Stage 1만 실행하므로, Stage 2/3에서만 드러나는 회귀(예: nginx 이미지 호환성, 인증서 SECLEVEL 거부)를 머지 전에 감지하지 못하는 구조적 공백이 있었음. 이를 보완하기 위해 별도 워크플로우 추가.

- 트리거: `nginx/**`, `tester/**`, `scanner/tls_check.sh`, `scanner/rules/tls-policy.yaml`, `docker-compose.yml`, 메인 파이프라인 yml 변경 시 PR/push 자동 실행
- 매트릭스: Stage 2 (Hybrid) + Stage 3 (PQ-only) 병렬
- 검증: docker compose up → healthcheck → `tls_check.sh`
- 실패 시 진단 로그 자동 출력 (`docker logs`, `nginx -T`, healthcheck 상세)

### `ai-migration.yml` — LLM 기반 코드 자동 마이그레이션 PoC

수동(`workflow_dispatch`) 트리거 전용. 비용/노이즈 격리 목적.

- 흐름: semgrep 탐지 → `migrate.py`가 LLM(GitHub Models, gpt-4o-mini) 호출 → AST 검증 → 별도 브랜치 커밋 + PR 자동 생성
- 안전장치: temperature=0, Python `compile()` 문법 검증, oqs-python API AST 검증, 자동 머지 없음(사람 리뷰 필수), 한 번에 최대 3개 파일

---

## 6. 핵심 기능별 상세

### 6.1 PQC Auto-Migration (nginx 설정)

`tls-policy.yaml`의 semgrep 룰:
- `nginx-weak-tls-protocol-10/11`: TLSv1.0/1.1 → TLSv1.3 자동 교체
- `nginx-classical-ecdh-curve`: MLKEM 미포함 커브 감지 → `X25519MLKEM768:X25519`로 autofix

파이프라인 Step 4가 `nginx.conf`에 `mlkem` 키워드 부재 시 `nginx-hybrid.conf` 복사 후 자동 커밋/푸시.

### 6.2 TLS 정책 동적 검증 (`tls_check.sh`)

OQS-curl 0.11.0이 OpenSSL < 3.2.0 번들로 `SSL_get_negotiated_group()` 미지원 → curl -v 출력에 그룹 필드 없음. 이 한계를 우회하기 위해 **핸드셰이크 성공/실패 자체로 정책 검증**:

| Stage | PQ 요청 (curve) | 클래식 요청 | 통과 조건 |
|-------|---------------|-----------|---------|
| 1 | `X25519MLKEM768` | `x25519:prime256v1:secp384r1` | classical ✓ + PQ ✗ |
| 2 | `X25519MLKEM768` | `x25519:prime256v1:secp384r1` | PQ ✓ + classical ✓ (둘 다 성공) |
| 3 | `mlkem1024` | `x25519:prime256v1:secp384r1` | PQ ✓ + classical ✗ |

curl 출력 파싱 의존성을 제거하여 OQS 이미지 버전 변경에도 안정적.

### 6.3 CBOM (CycloneDX 1.7)

- `cbom_gen.py`가 nginx 설정(정적 분석)과 실제 핸드셰이크/인증서 정보(동적 분석)를 결합해 CycloneDX 1.7 JSON 생성
- `cbom_diff.py`로 이전 run의 CBOM과 비교 → `migration_progress` 속성 추가 (BASELINE/IMPROVED/REGRESSED)
- `--verify-tls` 옵션으로 실제 TLS 핸드셰이크 결과와 CBOM 선언 알고리즘 교차 검증 (PASS/MISMATCH/SKIPPED)
- CycloneDX CLI v0.30.0으로 1.7 schema 검증 통과 강제

### 6.4 성능 게이트 + 자동 롤백 (Step 10)

- `perf_check.sh` (tls-tester 컨테이너 내부): OQS-curl `--curves` + `--write-out "%{time_appconnect}"`로 30회 측정. 중앙값·p90·실패율 → `perf-check-summary.json`
- 판정 기준 (Stage 2/3):
  - 중앙값 > 3000 ms (절대 임계치)
  - 중앙값 > baseline × 7배 (상대 임계치, Stage 1 baseline은 아티팩트로 보존)
  - 실패율 ≥ 10%
- `rollback.sh` (호스트): `result=fail`이면 이전 Stage nginx.conf 복사 → `[skip ci]` 커밋 + 푸시
- Stage 1은 항상 `baseline` 판정 (롤백 대상 아님)

### 6.5 AI 마이그레이션 PoC

semgrep `crypto-classical.yaml`이 탐지한 Python RSA 사용 코드를 LLM이 ML-KEM(FIPS 203) / ML-DSA(FIPS 204)로 변환:

```
semgrep → migrate.py → GitHub Models (gpt-4o-mini)
                    ├─ Python compile() 검증
                    └─ oqs-python AST 검증 (환각 패턴 차단)
        → auto-migration/<sha>-<ts> 브랜치
        → gh pr create + ai-generated 라벨
```

다층 방어: 정적 탐지 → AI 변환 → 자동 검증 → 봇 리뷰(Gemini Code Assist) → 사람 리뷰. AI가 만든 결함은 봇 리뷰가 즉시 잡아내며 사람 리뷰 단계에서 최종 차단.

PoC 범위 한정:
- 트리거: `workflow_dispatch` 수동만 (비용 격리)
- 대상: Python + RSA 룰 (`python-rsa-usage`, `python-rsa-keygen`, `generic-rsa-key-size-weak`)
- 한도: 한 번에 최대 3개 파일

### 6.6 Slack 알람 + Issue 자동 생성

`main` 브랜치 파이프라인 실패 시:
- GitHub Issue 자동 생성 (`pipeline-failure`, `security` 라벨)
- Slack Webhook으로 Stage·브랜치·실행 번호·로그 URL 전송 (`SLACK_WEBHOOK_URL` Secret 필요)

---

## 7. 도커 이미지 / 의존성 버전 정책

| 컴포넌트 | 버전 | 비고 |
|----------|------|------|
| `openquantumsafe/nginx` | `0.11.0` | sha256 pin 시도했으나 SECLEVEL 정책으로 Dilithium3 cert 거부 — 태그 고정으로 회귀 (Issue #79) |
| `openquantumsafe/curl` | sha256 pin | tester 이미지에서 사용 |
| `openquantumsafe/oqs-ossl3` | `0.10.1` | cert-builder. `dilithium3` 알고리즘 명칭 필요 (mldsa65 미지원 버전대) |
| `cyclonedx-cli` | `v0.30.0` | CycloneDX 1.7 validation 지원 |
| `gitleaks` | `8.21.2` | direct download |
| `trivy` | latest | GITHUB_TOKEN 인증으로 rate limit 회피 |
| `semgrep` | pip latest | PEP 668 fallback |

cert-builder ↔ nginx 호환 페어 조건은 `nginx/Dockerfile` 주석에 TODO로 표시. sha256 pin 복구 트리거 조건(`oqs-ossl3 ≥ 0.11` 확정 + Stage 3 검증 통과)은 Issue #79에 정의.

---

## 8. 브랜치 전략

```
feature/* ─→ develop (보호 안 됨, 팀 동료 리뷰) ─→ main (보호됨)
```

- 모든 작업은 `feature/*` 또는 `fix/*` 브랜치에서 시작
- PR base는 기본적으로 `develop`. 단, 의존 관계 있는 작업은 `--base feature/...` 형태로 직렬 PR 가능
- `workflow_dispatch` 노출은 `main` 브랜치에 워크플로우 파일이 존재해야 가능 → develop 머지 후 main 릴리스 PR 따라가야 함

---

## 9. 보안 정책 요약

| 영역 | 정책 | 강제 도구 |
|------|------|----------|
| 클래식 TLS 프로토콜 | TLSv1.0/1.1 차단 | `tls-policy.yaml` semgrep |
| 약한 cipher | RC4, DES, MD5 차단 | `tls-policy.yaml` |
| ECDH 커브 | MLKEM 미포함 시 WARNING | `tls-policy.yaml` (Stage 1 nginx-ecc.conf만 예외) |
| 코드 내 레거시 암호 | RSA, ECC, MD5, SHA-1 등 ERROR/WARNING | `crypto-classical.yaml` |
| 시크릿 하드코딩 | 발견 시 차단 | Gitleaks |
| CVE | HIGH/CRITICAL 차단 | Trivy |
| 인증서 자산 | dilithium3 (ML-DSA-65) | nginx-pq.conf |
| 키 교환 자산 | mlkem1024 (Stage 3), X25519MLKEM768 (Stage 2) | nginx-pq.conf, nginx-hybrid.conf |

---

## 10. 자주 마주치는 함정

1. **OQS 이미지 버전 페어** — nginx 이미지를 sha256 pin으로 고정하면서 cert-builder는 그대로 두면 Dilithium3 cert가 SECLEVEL로 거부됨. 두 이미지를 함께 올려야 함 (Issue #79)
2. **Stage 3 회귀 감지 공백** — push 트리거 기본 Stage 1로만 검증되므로 Stage 2/3 깨지는 변경이 머지될 수 있음. `tls-stage-matrix.yml`이 path filter로 보완 (Issue #78)
3. **OQS curl 그룹 필드 미출력** — OpenSSL < 3.2.0 번들 한계. 정책 검증은 핸드셰이크 결과로만 판정해야 함
4. **examples/legacy_crypto_example.py** — 의도된 vulnerable 코드. 메인 파이프라인 Step 5에서 `--exclude "examples/*"`로 제외되며, ai-migration 워크플로우만 이 파일을 스캔 대상으로 삼음
5. **`workflow_dispatch` UI 노출** — 워크플로우 파일이 main에 있어야 노출됨. develop 머지 후 main 릴리스 필요
6. **`[skip ci]` 자동 롤백** — `rollback.sh`가 자동 커밋 후 무한 루프 방지용으로 사용

---

## 11. 외부 자료

- CycloneDX 1.7 spec: https://cyclonedx.org/docs/1.7/json/
- liboqs-python (oqs-python): https://github.com/open-quantum-safe/liboqs-python
- OQS-OpenSSL provider: https://github.com/open-quantum-safe/oqs-provider
- ML-KEM (FIPS 203): https://csrc.nist.gov/pubs/fips/203/final
- ML-DSA (FIPS 204): https://csrc.nist.gov/pubs/fips/204/final
- GitHub Models: https://github.com/marketplace/models

---

## 12. 진행 중 작업 / 후속 항목

- 자체 CA 구현 검토 (현재 self-signed Dilithium3 → 내부 CA 체인 발급)
- 체크섬 검증 도입 (CycloneDX/Trivy/gitleaks 바이너리 SHA256)
- AI 마이그레이션 대상 확장 (Java, ECC, MD5/SHA-1)
- CBOM 시각화 (대시보드 팀 영역)
- `--fail-on-mismatch` 활성화 (현재는 관측 모드, 안정화 후 보안 게이트로 전환)
