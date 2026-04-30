# 2026 Secure Capstone — PQC Migration DevSecOps

> 양자 컴퓨터 위협에 대비한 **Post-Quantum Cryptography(PQC) TLS 마이그레이션** 자동화 파이프라인 구축 프로젝트

---

## 프로젝트 개요

현재 인터넷 암호화의 근간인 RSA, ECDH 등의 알고리즘은 양자 컴퓨터 공격에 취약합니다.
이 프로젝트는 **기존 Classical TLS → Hybrid PQC-TLS → Full PQC-TLS** 단계적 마이그레이션을 구현하고,
GitHub Actions 기반 **DevSecOps 파이프라인**으로 각 단계의 보안 게이트를 자동 검증합니다.

### TLS 마이그레이션 3단계

| Stage | 방식 | 키 교환 알고리즘 | 상태 |
|:---:|---|---|:---:|
| Stage 1 | Classical TLS | X25519, P-256 (ECC) | ✅ |
| Stage 2 | Hybrid PQC-TLS | X25519MLKEM768 (ECC + ML-KEM) | ✅ |
| Stage 3 | Post-Quantum TLS | p521_mlkem1024, p384_mlkem768 | ✅ |

---

## 시스템 구성

```
클라이언트 (tls-tester)
      │  HTTPS (TLS 1.3 + PQC)
      ▼
[pqc-proxy]  openquantumsafe/nginx — PQC TLS 종단
      │  HTTP
      ▼
[service-backend]  FastAPI — 백엔드 API
```

### 컨테이너 구성

| 컨테이너 | 이미지 | 역할 |
|---|---|---|
| `pqc-proxy` | `openquantumsafe/nginx` | PQC TLS 프록시 |
| `service-backend` | Python FastAPI | 백엔드 API 서버 |
| `tls-tester` | `openquantumsafe/curl` | TLS 검증 도구 |

---

## 시작하기 (Getting Started)

### 사전 요구사항

- Docker Desktop
- Git

### 1. 저장소 클론

```bash
git clone <repository-url>
cd 2026SecureCapstone
```

### 2. 컨테이너 빌드 및 실행

```bash
docker compose up -d --build
```

> 인증서는 빌드 시 자동 생성됩니다. 별도 설정 불필요.

### 3. 동작 확인

```bash
docker compose ps
```

---

## TLS Stage 전환

### 방법 1: 직접 전환 (로컬)

`nginx/nginx.conf` 파일을 원하는 Stage의 내용으로 교체 후 nginx 재시작:

```bash
# Stage 1 (Classical ECC)
cp nginx/nginx-ecc.conf nginx/nginx.conf

# Stage 2 (Hybrid PQC) — 기본값
cp nginx/nginx-hybrid.conf nginx/nginx.conf

# Stage 3 (Post-Quantum)
cp nginx/nginx-pq.conf nginx/nginx.conf

docker compose restart proxy-server
```

### 방법 2: GitHub Actions (자동)

GitHub → Actions 탭 → **DevSecOps PQC Pipeline** → **Run workflow** → Stage 선택 → 실행

파이프라인이 자동으로 nginx.conf 교체 → Docker 빌드 → TLS 검증까지 수행합니다.

---

## TLS 검증

컨테이너 실행 중 tester에서 TLS 협상 결과 확인:

```bash
# Stage 1 검증
docker exec -it tls-tester verify_tls.sh pqc-proxy 443 1

# Stage 2 검증
docker exec -it tls-tester verify_tls.sh pqc-proxy 443 2

# Stage 3 검증
docker exec -it tls-tester verify_tls.sh pqc-proxy 443 3
```

### 출력 예시 (Stage 2)

```
=== TLS 협상 결과 검증: pqc-proxy:443 (Stage: 2) ===

=== 요약 ===
Protocol : TLSv1.3
Cipher   : TLS_AES_256_GCM_SHA384
Key Group: X25519MLKEM768

판정: Stage 2 - Hybrid PQC-TLS ✓
```

> **💡 검증 스크립트 작성 시 주의사항**
> Stage 2(`X25519MLKEM768`)와 Stage 3(`p521_mlkem1024` 등) 키 그룹 모두 `mlkem` 문자열을 포함합니다.
> 단순히 `mlkem` 포함 여부로 분기하면 Stage 3를 Stage 2로 오판할 수 있습니다.
> **정확한 판정 기준: `x25519` 기반이면 Stage 2, `p384`/`p521` 기반이면 Stage 3**

### TLS ↔ CBOM 교차 검증 (`--verify-tls`)

`policy/cbom_diff.py`에 실제 TLS 핸드셰이크 결과와 CBOM 선언 알고리즘을 비교하는 교차 검증 기능이 추가되었습니다. CI 파이프라인은 `--verify-tls --tls-host proxy-server --tls-port 443 --tls-exec-container tls-tester --fail-on-mismatch` 옵션으로 호출되어, CBOM에 선언된 KEM/서명/대칭 알고리즘이 실제 핸드셰이크에서 관측된 cipher·key group과 일치하는지 `PASS/MISMATCH/SKIPPED`로 리포트하고 불일치 시 파이프라인을 실패시킵니다. `--tls-exec-container`는 호스트가 아닌 지정 docker 컨테이너 내부에서 `openssl s_client`를 실행하는 옵션으로, 러너에서 docker-compose 내부 서비스명 DNS 해석 불가·OQS provider 부재 문제를 우회하기 위해 OQS 번들 openssl을 보유한 `tls-tester` 컨테이너에서 핸드셰이크를 수행합니다.

---

## CI/CD 파이프라인

`main`, `develop` 브랜치에 Push 또는 PR 시 자동 실행됩니다.
GitHub Actions → **DevSecOps PQC Pipeline** → **Run workflow** 에서 Stage를 선택해 수동 실행도 가능합니다.

### 파이프라인 흐름

```
Step 1.  저장소 코드 가져오기
Step 2.  Stage 감지 및 nginx.conf 준비
           └─ workflow_dispatch: 선택한 Stage로 nginx.conf 교체
           └─ push/PR: nginx.conf 내용으로 Stage 자동 감지
Step 3.  Semgrep 설치
Step 4.  PQC 자동 마이그레이션 ✨
           └─ Classical TLS(mlkem 없음) 감지 시 Hybrid PQC로 자동 교체 + 커밋
Step 5.  고전 암호 탐지 (코드 전체)
           └─ RSA, MD5, SHA-1, DES 등 레거시 암호 패턴 탐지
Step 6.  정적 보안 분석 (SAST & Secret & CVE)
           └─ Trivy(CVE/Misconfig) + Gitleaks(Secret) + Semgrep(SAST)
           └─ [GATE] 시크릿 탐지 또는 레거시 암호 탐지 시 파이프라인 차단
Step 7.  TLS 암호 정책 검증 (Security Gate)
           └─ [GATE] TLSv1.0/1.1, RC4, DES, mlkem 미포함 ecdh_curve 차단
Step 8.  Docker 빌드 및 가동
Step 9.  동적 TLS 검증 (TLS 협상 확인)
Step 10. CBOM 생성 + 마이그레이션 이력 추적
           └─ 이전 실행 CBOM과 비교 → BASELINE/IMPROVED/UNCHANGED/REGRESSED
```

### 보안 게이트

| 조건 | 동작 |
|------|------|
| 레거시 암호 사용 탐지 (RSA/MD5 등) | 파이프라인 차단 + GitHub Issue 자동 생성 |
| 하드코딩된 시크릿 탐지 | 파이프라인 차단 + GitHub Issue 자동 생성 |
| TLS 정책 위반 (TLSv1.0/1.1 등) | 파이프라인 차단 + GitHub Issue 자동 생성 |

### 시연 시나리오

**레거시 암호 탐지 → 차단 시나리오:**
```
1. 레거시 암호 코드 포함 상태로 push
   → Step 6에서 차단, GitHub Issue 자동 생성
2. 레거시 암호 코드 제거 후 push
   → 전체 통과, CBOM에 IMPROVED 기록
```

**PQC 자동 마이그레이션 시나리오:**
```
1. nginx.conf를 Stage 1(Classical ECC)로 설정 후 push
   → Step 4에서 감지, Hybrid PQC로 자동 교체 + 커밋
   → 이후 Stage 2 기준으로 파이프라인 계속 진행
```

### 결과 확인

- **Job Summary**: Actions 탭 → 실행 결과 → Summary 탭에서 스캔 결과 표 확인
- **PR 코멘트**: PR 이벤트 시 보안 리포트 자동 게시
- **CBOM 아티팩트**: `cbom-stage{N}-run{번호}` 형태로 실행마다 누적 보존
- **Scan 아티팩트**: `scan-results-stage{N}`에 Trivy/Gitleaks/Semgrep 상세 결과

---

## 폴더 구조

```
2026SecureCapstone/
 ┣ 📂 .github/
 ┃ ┗ 📂 workflows/
 ┃   ┗ 📜 devsecops-pipeline.yml  # CI/CD 파이프라인
 ┣ 📂 nginx/                      # OQS-Nginx 설정
 ┃ ┣ 📜 Dockerfile
 ┃ ┣ 📜 nginx.conf                # 활성 설정 (Stage 전환 대상)
 ┃ ┣ 📜 nginx-ecc.conf            # Stage 1: Classical TLS
 ┃ ┣ 📜 nginx-hybrid.conf         # Stage 2: Hybrid PQC-TLS
 ┃ ┗ 📜 nginx-pq.conf             # Stage 3: Post-Quantum TLS
 ┣ 📂 backend/                    # FastAPI 백엔드
 ┣ 📂 tester/                     # TLS 검증 도구
 ┃ ┣ 📜 Dockerfile
 ┃ ┗ 📜 verify_tls.sh             # TLS 협상 검증 스크립트
 ┣ 📂 pqc-webserver/              # WSL2 직접 설치 참고용 (레거시)
 ┣ 📜 docker-compose.yml          # 개발용
 ┣ 📜 docker-compose.prod.yml     # 배포용
 ┣ 📜 .gitattributes              # LF 줄바꿈 강제
 ┗ 📜 .gitignore
```

---

## 프로젝트 로드맵

- [x] Phase 1: 3-Tier 기반 Docker 베이스라인 구축 및 네트워크 연동
- [x] Phase 2: OQS-Nginx 기반 PQC TLS 3단계 Docker 통합
- [x] Phase 3: Hybrid PQC-TLS 검증 (X25519MLKEM768 협상 확인)
- [x] Phase 4: GitHub Actions DevSecOps 파이프라인 구현 (workflow_dispatch)
- [x] Phase 5: SAST, TLS 정책 검증, CBOM 생성 구현 (Trivy · Gitleaks · Semgrep 파이프라인 통합)
- [x] Phase 6: PQC 자동 마이그레이션, 레거시 암호 탐지, 보안 게이트 강화, CBOM 이력 추적
- [ ] Phase 7: LLM 기반 레거시 암호 코드 자동 마이그레이션 PR 생성

---

# 프로젝트 협업 규칙 (Contribution Guide)

이 프로젝트의 일관성을 유지하고 효율적인 협업을 위해 아래 규칙을 준수해 주세요.

---

## 1. 커밋 메시지 규칙 (Commit Convention)

커밋 메시지는 **`Type: Subject`** 형식을 사용하며, 첫 글자는 대문자로 시작합니다.

### 커밋 타입 (Type)
| 타입 | 설명 |
| :--- | :--- |
| `Feat` | 새로운 기능 추가 |
| `Fix` | 버그 수정 |
| `Docs` | 문서 수정 (README, Wiki 등) |
| `Style` | 코드 의미에 영향을 주지 않는 수정 (세미콜론 누락, 포맷팅 등) |
| `Refactor` | 코드 리팩토링 |
| `Chore` | 빌드 업무, 패키지 매니저 설정, 프로젝트 설정 변경 |

### 예시 (Example)
* `Feat: Stage 2 하이브리드 PQC용 nginx.conf 추가`
* `Fix: TLS 정책 검증 스크립트 정규식 파싱 오류 수정`
* `Docs: CBOM 생성 아키텍처 다이어그램 추가`

---

## 2. 브랜치 전략 (Branching Strategy)

기본적으로 **GitHub Flow** 전략을 따릅니다.

* **`main`**: 배포 가능한 상태의 안정된 코드만 관리합니다.
* **`develop`**: 다음 출시를 위한 개발을 진행하는 브랜치입니다.
* **`feature/기능명`**: 새로운 기능을 개발할 때 사용합니다.
    * 예: `feature/sast-scanner`, `feature/oqs-nginx`, `feature/github-actions`
* **`hotfix/이슈명`**: 배포 후 긴급 수정이 필요할 때 사용합니다.
* **`docs/기능명`**: 문서 수정이 필요할 때 사용합니다.

**Workflow:** `feature` 브랜치 작업 → PR 생성 → `develop` 병합 → 배포 시 `main` 병합

---

## 3. Pull Request 규칙

모든 코드는 PR을 통한 코드 리뷰 후 `main`에 병합(Merge)됩니다.

1. **Self-Review**: PR을 올리기 전 본인의 코드를 다시 한번 확인합니다.
2. **Reviewers**: 최소 1명 이상의 팀원을 리뷰어로 지정합니다.
3. **Template**: 아래 내용을 포함하여 작성합니다.
    * 작업 내용 (Summary)
    * 주의 사항 및 참고 자료 (Optional)

---
