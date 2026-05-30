# 세션 컨텍스트 — 2026SecureCapstone CICD

> 다음 세션에서 이 파일을 열고 Claude에게 "이 파일 읽고 이어서 작업해줘" 라고 하면 됩니다.

## 현재 브랜치 상태

- **현재 브랜치**: `feature/stage3ca`
- **최근 커밋**:
  - `6edaf85` fix(tls_check): curl 출력 파싱 의존성 제거, 핸드셰이크 결과 기반 검증으로 전환
  - `ed2b929` fix(pipeline): PR 액션 실패 수정
  - `9908609` fix(pipeline): Stage 1/2 TLS 검증 실패 수정
  - `b5ecbee` feat(stage3): Stage 3 PQC TLS 인증서 및 검증 수정
- **파이프라인 상태**: push ✅ 통과, PR #70 오픈 상태 (CI 2/2 통과)

---

## 프로젝트 개요

DevSecOps 캡스톤 프로젝트. OQS (Open Quantum Safe) nginx/curl 이미지(v0.11.0) 기반으로 PQC TLS 3단계 구현.

| Stage | 설명 | curl curves | nginx ssl_ecdh_curve |
|-------|------|-------------|----------------------|
| 1 | Classical ECC | `x25519:prime256v1:secp384r1` | (`nginx-ecc.conf` 사용) |
| 2 | Hybrid PQC | `X25519MLKEM768:x25519` | `X25519MLKEM768:X25519` |
| 3 | PQ-only | `p521_mlkem1024:p384_mlkem768` | `p521_mlkem1024:p384_mlkem768` |

---

## 이번 세션에서 완료한 작업

### 1. gh CLI 설치 및 오픈 PR 현황 파악

- PR #70 (apinball, feature/stage3ca): CI 2/2 ✅ — 우리 PR, 이미 오픈됨
- PR #71 (yulim4hyoung, Feat/docker tls migration): CI 1/1 ✅
- PR #72 (suimins, Feature/cyclonedx): CI 1/2 ⚠️

### 2. PR #71 설계 충돌 분석

PR #71이 `nginx-pq.conf`의 Stage 3 curve를 변경함:
```diff
- ssl_ecdh_curve p521_mlkem1024:p384_mlkem768;   ← PQ-only (NIST Level 5)
+ ssl_ecdh_curve X25519MLKEM768;                  ← Hybrid (NIST Level 3, Stage 2와 동일)
```
- Stage 3과 Stage 2의 보안 단계 차별점 소멸
- `# nosemgrep` 주석도 불필요 (X25519MLKEM768은 MLKEM 포함으로 룰 제외 대상)
- `nginx/Dockerfile` 이미지 버전 미고정 (`latest`), `mldsa65` vs `dilithium3` 명칭 문제
- `tester/verify_tls.sh` Stage 3 기대값이 Stage 2와 동일해짐

### 3. tls_check.sh 전면 개선 (`6edaf85`)

**배경**: `openquantumsafe/curl:0.11.0`이 OpenSSL < 3.2.0 번들 → `SSL_get_negotiated_group()` 미지원 → curl -v 출력에 그룹 필드 없음. 기존 `Group=Unknown → 연결 성공으로 추론` 방식은 Stage 2에서 오탐 가능 (x25519 폴백으로 PQC 없이도 연결 성공).

**변경 내용**:
- curl 출력 파싱 의존 완전 제거
- **Stage 2**: PQ-only 요청(`--curves X25519MLKEM768`, 폴백 없음) 성공 + 클래식 요청 성공 → 두 가지 핸드셰이크로 하이브리드 검증
- **Stage 3**: PQ 요청 성공 + 클래식 요청 실패(PQ-only 강제 확인) → 두 가지로 정책 검증
- 데드코드 제거: Stage 3의 `! grep mlkem` 이후 도달 불가한 classical 그룹 체크 분기

---

## 남은 작업 (우선순위 순)

1. **`feature/stage3ca` 브랜치 push** (커밋 `6edaf85` 푸시 필요)

2. **PR #70 코드리뷰 답변** (`feature/stage3ca` PR):
   - `ssl_ecdh_curve` 불일치 우려 → 비문제: `nginx-pq.conf` 12번 라인 주석 + 실제 설정값 모두 `p521_mlkem1024:p384_mlkem768`로 일치
   - healthcheck HTTPS 우려 → 비문제: `docker-compose.yml` healthcheck는 HTTP 포트 80 사용

3. **PR #71 리뷰 코멘트** (설계 충돌 지적):
   - Stage 3 curve 변경이 Stage 2와 동일해지는 설계 문제
   - Dockerfile 버전 미고정, mldsa65 vs dilithium3, nosemgrep 불필요 등

4. **PR 코멘트 JS 스크립트 TLS_CHECK 행 누락** (`devsecops-pipeline.yml` line 398~):
   - `tls-check-summary.json` 읽어 `tlsCheck` 변수 추가
   - 스캔 결과 테이블에 `| TLS 동적 검증 | ... |` 행 추가

5. **GitHub Secret 등록**: `SLACK_WEBHOOK_URL`

6. **PR #64 dead code**: `pipeline.yml` lines 379-381 exit 3 핸들링 → suimins에게 코멘트

---

## 주요 파일 위치

| 파일 | 역할 |
|------|------|
| `.github/workflows/devsecops-pipeline.yml` | 메인 파이프라인 |
| `nginx/nginx.conf` | Stage 2 서버 설정 (X25519MLKEM768:X25519) |
| `nginx/nginx-pq.conf` | Stage 3 서버 설정 (p521_mlkem1024:p384_mlkem768) |
| `nginx/nginx-ecc.conf` | Stage 1 서버 설정 (클래식 ECC) |
| `scanner/tls_check.sh` | TLS 정책 검증 스크립트 (핸드셰이크 기반으로 개선됨) |
| `scanner/semgrep_scan.sh` | Semgrep SAST 래퍼 |
| `scanner/rules/tls-policy.yaml` | TLS 정책 semgrep 룰 |
| `tester/verify_tls.sh` | TLS 협상 결과 검증 스크립트 |
| `policy/cbom_gen.py` | CBOM 생성 스크립트 (동적분석 실패 시 exit 2) |

---

## 알아두어야 할 기술적 사항

- **curl 7.81.0 / OQS curl:0.11.0**: `SSL_get_negotiated_group()` 미지원 (OpenSSL 3.2.0+ 필요, curl 8.3.0+부터 활용). TLS 그룹 정보가 curl -v 출력에 없음 → 핸드셰이크 성공/실패로 판정
- **OQS 이미지**: nginx/curl `0.11.0`, 인증서 생성용 `oqs-ossl3:0.10.1` (dilithium3 PQ 인증서)
- **semgrep tls-policy.yaml**: `nginx-classical-ecdh-curve` 룰이 `mlkem`/`MLKEM` 미포함 커브를 WARNING → `--error` 플래그로 실패 처리. 스캔 대상은 `nginx/nginx.conf` 단일 파일로 제한
- **GitHub Actions**: `if: always()`는 이전 step이 skip되어도 실행됨; `continue-on-error: true` step의 outcome은 "failure" (not "skipped")
- **docker-compose healthcheck**: HTTP 포트 80 사용 → TLS/PQC 설정과 무관
- **PR #71 설계 이슈**: Stage 3 curve를 `X25519MLKEM768`로 변경 → Stage 2와 동일해짐, 리뷰 코멘트 필요
