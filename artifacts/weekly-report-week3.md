# 주간 보고 — 3주차

**AI 자동 마이그레이션 PoC 완성 + Stage 2/3 회귀 감지 매트릭스 도입 + Stage 3 standalone PQ 그룹 미지원 발견 (PR #82 `feature/ai-migration`, PR #83 `fix/ci-stage-matrix-78`, Issue #78·#79)**

---

## 상세 작업 내용

### 1. AI 자동 마이그레이션 PoC — PR #82 (`feature/ai-migration`)

- **워크플로우 구성**: `workflow_dispatch` 전용 신규 워크플로우 `ai-migration.yml`. semgrep `crypto-classical.yaml`이 탐지한 Python RSA 사용 코드를 GitHub Models(gpt-4o-mini)에 보내 ML-KEM(FIPS 203) / ML-DSA(FIPS 204)로 변환 → 별도 브랜치 커밋 → `gh pr create`로 자동 PR 생성
- **다층 검증**: Python `compile()` 문법 체크 + oqs-python AST 검증 (LLM이 자주 환각하는 `KeyEncapsulation.<method>()` 클래스 직접 호출, `encapsulate`/`decapsulate` 잘못된 메서드명 차단)
- **PoC 범위**: Python + RSA 룰 3종 (`python-rsa-usage`, `python-rsa-keygen`, `generic-rsa-key-size-weak`), 한 번에 최대 3개 파일, temperature=0
- **신규 파일**: `ai-migration/migrate.py`, `ai-migration/prompts/rsa_to_mlkem.txt`, `ai-migration/README.md`, `examples/legacy_crypto_example.py` (데모용 RSA 코드), `.github/workflows/ai-migration.yml`. 메인 파이프라인 Step 5에 `--exclude "examples/*"` 추가하여 의도된 vulnerable 코드가 차단되지 않도록 처리
- **라이브 데모**: 실제 실행으로 PR #81 자동 생성. Gemini 봇이 Breaking change 패턴 5건 즉시 지적 → "AI 변환 + 봇 리뷰 + 사람 리뷰" 다층 방어 narrative 입증
- **후속 보강** (커밋 `50b13b3`):
    - Gemini 봇 지적 반영해 프롬프트에 'API compatibility constraints' 섹션 추가 (전역 인스턴스 금지, `generate_keypair` 튜플 반환, 인자 보존, `shared_secret` 반환 보장, 동작 변경 docstring 명시 등 6개 룰)
    - subprocess `encoding="utf-8"` 추가로 Windows cp949 디코딩 에러 회피
    - 워크플로우에 `ai-generated` 라벨 자동 생성 step 추가
    - 로컬 dry-run 재시도에서 5개 지적 모두 해소 확인

### 2. Stage 2/3 회귀 감지 매트릭스 워크플로우 — PR #83 (`fix/ci-stage-matrix-78`)

- **배경**: PR #71 머지 시 Stage 3 회귀가 감지되지 않은 구조적 원인은 메인 파이프라인이 push/PR 트리거에서 기본 Stage 1만 실행하는 것. Issue #78에서 [blocker]로 분리해 추적
- **해결**: `.github/workflows/tls-stage-matrix.yml` 신설. PR/push에서 `nginx/**`, `tester/**`, `scanner/tls_check.sh`, `tls-policy.yaml`, `docker-compose.yml`, 메인/매트릭스 워크플로우 yml 변경 시에만 path filter로 자동 실행
- **검증 단계**: nginx 설정 적용 → docker compose up → healthcheck 대기 → `tls_check.sh` 정책 검증. 실패 시 진단 로그 자동 출력 (`docker inspect`, `docker logs pqc-proxy`, `nginx -T` config dump)
- **설계 결정**: Stage 1은 메인 파이프라인이 이미 커버하므로 매트릭스 제외 (중복 회피). 별도 워크플로우 파일로 분리해 진행 중인 PR(#77, #80)과 충돌 0
- **Stage 2 사전 로컬 검증**: `TLS_STAGE=2 docker compose up --build` → healthcheck `healthy` + `tls_check.sh PASS` 확인 후 PR

### 3. PR #76 리뷰 피드백 분리 처리 — Issue #78 / #79 + 커밋 `2cc7e5f`

- 리뷰어 피드백을 hotfix PR 범위 확장 대신 별도 이슈로 분리:
    - **Issue #78** [blocker]: Stage 3 회귀가 머지 전에 감지되지 않는 CI 구조 문제 (옵션 A nightly / B path filter+matrix / C required check 비교 후 B 채택)
    - **Issue #79**: cert-builder ↔ nginx 페어 호환 조건 문서화 + sha256 pin 복구 트리거 조건 명문화 (`oqs-ossl3 ≥ 0.11` 확정 + Stage 3 수동 실행 통과 체크리스트)
- `nginx/Dockerfile`에 `# TODO(#79): oqs-ossl3 호환 버전 확정 후 sha256 pin 복구` 주석 추가하여 코드 레벨에서도 추적 가능하도록 처리

### 4. Stage 3 standalone PQ 그룹 미지원 발견 — PR #83 CI 실행 결과

- PR #83 CI에서 Stage 3 매트릭스가 실패: `[FAIL] Stage 3: PQ handshake (mlkem1024) failed`
- **원인 분석**: PR #76 머지 검증 당시 본 `GET / HTTP/1.1 301` 로그는 nginx가 포트 80 HTTP 받는 것이지 포트 443 TLS 핸드셰이크 검증이 아니었음. `mlkem1024` standalone 그룹은 OQS-nginx 0.11.0에서 실제 협상이 되지 않음 (hybrid 그룹 `p521_mlkem1024`, `X25519MLKEM768` 등은 잘 지원되지만 standalone은 미지원/비활성화)
- **참고**: PR #71 리뷰 당시 이미 우려했던 케이스. PR #71이 Stage 3 curve를 `X25519MLKEM768` → `mlkem1024`로 변경했을 때 standalone 지원 여부가 검증되지 않은 채로 develop에 들어가 있었음
- **다음 작업**: `nginx/nginx-pq.conf`, `scanner/tls_check.sh`, `tester/verify_tls.sh`, `tester/capture_tls.sh`의 Stage 3 커브를 `p521_mlkem1024:p384_mlkem768`로 복원하는 hotfix PR 진행 예정 (Stage 3 = "강한 hybrid PQC, NIST L5"로 의미 정리, Stage 2 = "Hybrid PQC NIST L3"와 보안 단계 차이 유지)

### 5. 운영 문서화

- **`PROJECT_GUIDE.md`** 신설: 새 세션이 프로젝트 맥락을 빠르게 파악하도록 12개 섹션 종합 가이드 작성 (개요, Stage 정의, 디렉터리 구조, 메인 파이프라인 11 step, 보조 워크플로우, 핵심 기능 6종 상세, 도커/의존성 버전 정책, 브랜치 전략, 보안 정책, 자주 마주치는 함정, 외부 자료, 진행 중 작업)

---

## 산출물

| 종류 | 식별자 | 상태 |
|------|--------|------|
| PR | #82 feature/ai-migration → develop | 리뷰 대기 |
| PR | #83 fix/ci-stage-matrix-78 → develop | CI에서 Stage 3 미지원 발견, hotfix 후 재실행 예정 |
| PR | #81 auto-migration/<sha> (AI 자동 생성 데모) | 데모 artifact, 머지 안 함 |
| Issue | #78 [blocker] Stage 3 CI 감지 공백 | PR #83가 close 예정 |
| Issue | #79 cert-builder ↔ nginx 페어 문서화 | TODO, 후속 작업 |
| 신규 파일 | `ai-migration/`, `examples/`, `tls-stage-matrix.yml`, `ai-migration.yml`, `PROJECT_GUIDE.md` | develop 머지 대기 |

---

## 다음 주 계획

| 항목 | 내용 |
| --- | --- |
| Stage 3 커브 복원 hotfix | PR #83 CI 실패 후속. `mlkem1024` → `p521_mlkem1024:p384_mlkem768` 일괄 복원 (nginx-pq.conf / tls_check.sh / verify_tls.sh / capture_tls.sh) |
| PR #82, #83 머지 | 리뷰 통과 후 develop 머지. main 릴리스 PR도 따라가야 `workflow_dispatch` UI 노출됨 |
| 체크섬 검증 도입 | CycloneDX CLI / Trivy / gitleaks 바이너리 다운로드 시 SHA256 체크섬 검증 스텝 추가 |
| 자체 CA 구현 검토 | self-signed Dilithium3 인증서 → 내부 CA 체인 발급 구조로 전환 검토 |
| Issue #79 nginx/README.md 작성 | cert-builder ↔ nginx 페어 호환 조건 영구 문서화 |
| AI 마이그레이션 대상 확장 | Java RSA, ECC, MD5/SHA-1까지 룰 셋 확장 검토 |
