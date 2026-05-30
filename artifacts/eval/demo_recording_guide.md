# 발표 시연 영상 녹화 가이드 (스토리 4막 구조)

> **3분 무음 영상** — 발표 시 발표자가 라이브 나레이션 동반 사용
> 핵심 메시지: "개발자가 push만 하면 파이프라인이 PQC 전환을 알아서 한다"

---

## 0. 전체 구조

| Act | 시간 | 내용 | 시청자가 느끼는 것 |
|-----|------|------|-----|
| Act 1 — 문제 | 0:00~0:20 | 개발자가 classical 코드 push | "그래서 뭐가 문제?" |
| Act 2 — 자동 대응 | 0:20~1:30 | 파이프라인이 탐지·변환·PR·CBOM 자동 처리 | "이걸 사람 안 거치고?" |
| Act 3 — 동작 검증 | 1:30~2:20 | PQC TLS 실제 협상 + matrix CI 그린 | "정말 작동하네" |
| Act 4 — 회귀 차단 | 2:20~2:50 | 누군가 PQC 되돌리려 하면 차단 | "안전망까지 있구나" |
| 결말 | 2:50~3:00 | 결과 수치 정지 카드 | "효과가 이만큼" |

총 **3분**. 시청자가 한 사이클의 자동화 흐름을 끝까지 본다.

---

## 1. 사전 준비 (녹화 전 일회성, 10분)

### 1-1. 녹화 도구
권장: **OBS Studio** (무료, 컷 편집 가능)
- 다운로드: https://obsproject.com/
- 첫 실행 시 "최적화 마법사" → "녹화에 최적화" 선택
- 출력 설정: MP4, 30fps, 1920×1080

대안: **PowerPoint 화면 녹화** (편집 약함, 빠름)
- 삽입 → 화면 녹화
- 오디오 OFF, 마우스 포인터 ON

편집 도구 (Act별 영상 합칠 때): **Clipchamp** (Win11 내장) 또는 **DaVinci Resolve** (무료)

### 1-2. Docker 환경 기동
```bash
cd c:\Users\admin\Desktop\secure\2026SecureCapstone
TLS_STAGE=3 docker compose up -d
sleep 15
docker ps --format "table {{.Names}}\t{{.Status}}"
```

3개 컨테이너 모두 `Up X seconds (healthy)` 떠야 함.

### 1-3. 브라우저 탭 미리 준비
시연 중 URL 입력 안 하도록 미리 열어두기:

| # | 탭 | 사용 Act |
|---|----|---------| 
| 1 | https://github.com/apinball/2026SecureCapstone/actions | Act 2 (탐지) |
| 2 | https://github.com/apinball/2026SecureCapstone/pull/82 | Act 2 (AI PoC) |
| 3 | https://github.com/apinball/2026SecureCapstone/pull/81/files | Act 2 (봇 생성 PR) |
| 4 | https://github.com/apinball/2026SecureCapstone/actions/runs/25836908546 | Act 3 (matrix CI 그린) |
| 5 | https://github.com/apinball/2026SecureCapstone/actions/runs/26335439654 | Act 4 (실패 run) |

### 1-4. 터미널 환경
- 글꼴 크기 16~18pt로 확대
- 검은 배경 + 밝은 텍스트
- `clear`로 깨끗하게

### 1-5. VSCode 환경 (Act 1용)
- 미리 `app/keygen.py` 또는 RSA 사용 파일 열어두기
- 폰트 20pt 이상으로 확대

---

## 2. Act 1 — 문제 (0:00~0:20, 20초)

**목적**: "개발자가 classical 암호 코드를 작성·push하는 상황"을 시각화.

### 2-1. 화면 구성
```
0:00~0:10  VSCode: RSA 코드 보여주기
0:10~0:20  터미널: git push
```

### 2-2. VSCode 캡처 (10초)
- 파일: `examples/legacy_crypto_example.py` 또는 `app/keygen.py` 등 RSA 사용 파일
- 강조할 줄:
  ```python
  from cryptography.hazmat.primitives.asymmetric import rsa
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  ```
- 마우스 호버 또는 줄 선택으로 강조

### 2-3. 터미널 캡처 (10초)
- 시연용이라 실제 push는 하지 말고 명령만 보여주기:
  ```bash
  git add app/keygen.py
  git commit -m "feat: add user keygen module"
  git push
  ```
- 명령 입력 후 Enter는 누르지 말고 영상 종료 (또는 dry-run)

### 2-4. 자막
우상단에 작게: `Act 1 — 개발자가 classical 암호 코드를 push`

---

## 3. Act 2 — 파이프라인 자동 대응 (0:20~1:30, 70초)

**목적**: 파이프라인이 사람 손 없이 탐지·변환·PR·CBOM을 처리하는 흐름.

### 3-1. 화면 흐름 (4 컷)

```
컷 2-A (0:20~0:35, 15초)  GitHub Actions workflow 실행 시작 화면
컷 2-B (0:35~0:55, 20초)  Semgrep이 RSA 탐지하는 로그
컷 2-C (0:55~1:15, 20초)  AI 마이그레이션 + PR #81 자동 생성
컷 2-D (1:15~1:30, 15초)  CBOM 생성 + [IMPROVED] 라벨
```

### 3-2. 컷 2-A: Workflow 시작 화면 (15초)
- 탭 1 (Actions 페이지) 표시
- 기존 성공 run 하나 클릭 (예: 최근 develop 브랜치 run)
- workflow 그래프(여러 step이 직렬로 연결된 다이어그램) 표시
- 천천히 마우스 스크롤로 step 목록 훑기

### 3-3. 컷 2-B: Semgrep 탐지 로그 (20초)
- 선택한 run의 "5. 고전 암호 탐지" step 클릭
- 로그 펼치기 → 강조 라인:
  ```
  semgrep --config scanner/rules/crypto-classical.yaml
  Found: python-rsa-usage at app/keygen.py:5
  ```
- 마우스 커서로 해당 라인 가리키기

### 3-4. 컷 2-C: AI 마이그레이션 + PR #81 (20초)
- 탭 3 (PR #81 Files changed) 표시
- 봇이 생성한 PR임을 보여주기:
  - "Conversation" 탭으로 가서 작성자 `github-actions[bot]` 확대
  - 다시 "Files changed" 탭으로 가서 diff 표시
  - RSA → `oqs.KeyEncapsulation` 변환된 부분 강조
- 탭 2 (PR #82) 잠깐 표시 — "이 인프라가 PoC #82에서 구축됨" 암시

### 3-5. 컷 2-D: CBOM Diff [IMPROVED] (15초)
- 터미널로 전환
- 명령 실행:
  ```bash
  cd c:\Users\admin\Desktop\secure\2026SecureCapstone\artifacts\eval\cbom_diff_experiments
  python ../../../policy/cbom_diff.py --current stage2_cbom.json --previous stage1_cbom.json --out demo_s2.json
  ```
- 출력에서 `[IMPROVED] 해결 3건` 강조 후 3초 정지

### 3-6. 자막
우상단: `Act 2 — 파이프라인 자동 대응 (탐지 → 변환 → PR → CBOM)`

---

## 4. Act 3 — 실제 동작 검증 (1:30~2:20, 50초)

**목적**: 마이그레이션 결과가 실제 wire-level에서 PQC로 협상되는지 확인.

### 4-1. 화면 흐름 (2 컷)

```
컷 3-A (1:30~1:55, 25초)  터미널: Stage 3 핸드셰이크 실제 협상 + 클래식 거부
컷 3-B (1:55~2:20, 25초)  GitHub Actions: matrix CI 3개 그린 체크
```

### 4-2. 컷 3-A: Stage 3 핸드셰이크 (25초)
- 터미널에서 두 명령 연속 실행:

```bash
docker exec tls-tester verify_tls.sh proxy-server 443 3
```
→ 출력 `PASS — Stage 3 알고리즘 협상 확인됨 (p521_mlkem|p384_mlkem)` 보이면 **3초 정지**

```bash
docker exec tls-tester curl -sk --connect-timeout 5 --curves "X25519:P-256" https://proxy-server/ ; echo "Exit: $?"
```
→ 출력 `Exit: 35` (클래식 차단됨) 보이면 **3초 정지**

### 4-3. 컷 3-B: Matrix CI 그린 (25초)
- 탭 4 (run 25836908546) 표시
- "TLS Stage 2/3 Startup Verification" workflow run
- 3개 job (Stage 1 / Stage 2 / Stage 3) 모두 그린 체크 보이는 화면
- 마우스로 각 체크 마크 가리키기

### 4-4. 자막
우상단: `Act 3 — 실제 PQC 협상 + matrix CI 통과`

---

## 5. Act 4 — 회귀 시도 차단 (2:20~2:50, 30초)

**목적**: 누군가 PQC 설정을 되돌리려 하면 파이프라인이 막는다.

### 5-1. 화면 흐름 (2 컷)

```
컷 4-A (2:20~2:35, 15초)  의도적 회귀 diff
컷 4-B (2:35~2:50, 15초)  CI fail 또는 로컬 verify_tls FAIL
```

### 5-2. 컷 4-A: 회귀 diff (15초)
- VSCode 또는 GitHub PR diff 화면
- 예시: `nginx-pq.conf`에서 PQC curve를 classical로 되돌리는 변경
  ```diff
  - ssl_ecdh_curve p521_mlkem1024:p384_mlkem768;
  + ssl_ecdh_curve prime256v1;
  ```
- 빨간색 hunk가 잘 보이게 확대

### 5-3. 컷 4-B: 차단 시연 (15초) — 두 가지 옵션 중 선택

**옵션 A (안전): 로컬 verify_tls FAIL**
```bash
docker exec tls-tester verify_tls.sh proxy-server 443 1
```
→ 출력 `FAIL — TLS 연결 실패 또는 알고리즘 불일치` 보이면 빨갛게 강조

**옵션 B (임팩트 큼): 실제 실패 CI run 캡처**
- 탭 5 (run 26335439654) 표시
- "failure" 상태 + 빨간 X 마크 강조

### 5-4. 자막
우상단: `Act 4 — 회귀 시도는 자동 차단`

---

## 6. 결말 — 결과 카드 (2:50~3:00, 10초)

**정지 슬라이드 1장**. PowerPoint 또는 OBS에 임베드.

```
┌──────────────────────────────────────────────┐
│                                              │
│   표준 도구로 잡히는 PQC 함정       0 / 6    │
│                                              │
│   본 파이프라인이 잡는 함정         6 / 6    │
│                                              │
│   LLM 단독 → 다층 검증 위험률    100% → 0%  │
│                                              │
└──────────────────────────────────────────────┘
```

폰트: 36pt 이상, 굵게, 가운데 정렬.

---

## 7. 녹화 순서 권장

타임라인 순서와 다르게, **녹화하기 쉬운 순서**부터:

| 순서 | Act | 이유 |
|------|-----|------|
| 1 | Act 3 컷 3-A (Stage 3 터미널) | Docker 환경 확인 겸 워밍업 |
| 2 | Act 4 컷 4-B 옵션 A (로컬 FAIL) | 같은 터미널 환경 활용 |
| 3 | Act 2 컷 2-D (CBOM Diff) | 터미널 환경 마지막 정리 |
| 4 | Act 1 (VSCode + git push) | VSCode 켜는 김에 |
| 5 | Act 2 컷 2-A·B·C (브라우저) | 브라우저 한꺼번에 |
| 6 | Act 3 컷 3-B (브라우저) | Act 2 이어서 |
| 7 | Act 4 컷 4-A (diff) | 마지막 브라우저 작업 |
| 8 | 결말 카드 | 슬라이드만 |

---

## 8. 편집 단계 (각 Act 영상 합치기)

### 8-1. Clipchamp 사용 시 (가장 빠름)
1. Win11 시작 → "Clipchamp" 검색
2. 새 프로젝트 → 녹화한 mp4들 import
3. 타임라인에 Act 1 → 2 → 3 → 4 → 결말 순으로 드래그
4. 각 Act 사이에 **cross-dissolve 0.3초** 전환 적용
5. 우상단에 텍스트 박스로 `Act N — 제목` 자막 추가
6. 내보내기: MP4 1080p

### 8-2. PowerPoint 사용 시 (편집 약함)
- 슬라이드 5장 (Act별 1장 + 결말 1장)
- 각 슬라이드에 mp4 임베드
- 슬라이드 전환: 슬라이드 전환 → "없음" (수동으로 넘김)
- 영상 시작: 재생 탭 → 시작 = 자동

### 8-3. 자막 텍스트
| 시간 | 자막 |
|------|------|
| 0:00~0:20 | Act 1 — 개발자가 classical 암호 코드를 push |
| 0:20~1:30 | Act 2 — 파이프라인 자동 대응 |
| 1:30~2:20 | Act 3 — 실제 PQC 협상 + matrix CI 통과 |
| 2:20~2:50 | Act 4 — 회귀 시도는 자동 차단 |
| 2:50~3:00 | (자막 없음 — 정지 카드만) |

---

## 9. 발표 시 라이브 나레이션 스크립트

각 Act에서 발표자가 말할 내용 (영상에는 안 들어감):

### Act 1
> "개발자가 RSA를 사용한 코드를 작성해서 push했다고 가정합니다. 표준 도구로는 이 코드가 어디서 어떻게 PQC로 전환되어야 할지 자동으로 알기 어렵습니다."

### Act 2
> "본 파이프라인은 Semgrep으로 RSA 사용을 탐지하고, GitHub Models gpt-4o-mini를 호출해 ML-KEM 코드로 변환한 결과를 PR로 자동 생성합니다. 동시에 CBOM이 갱신되어 마이그레이션 진척도가 IMPROVED로 기록됩니다."

### Act 3
> "변환된 코드가 실제로 동작하는지 확인합니다. Stage 3 환경에서 양자내성 KEM인 p521_mlkem1024로 핸드셰이크가 성공하고, classical 클라이언트는 차단됩니다. matrix CI의 Stage 1·2·3 검증도 모두 통과합니다."

### Act 4
> "만약 누군가 PQC 설정을 되돌리려는 PR을 올리면 매트릭스 CI가 Stage 3 핸드셰이크 실패를 감지해 머지를 차단합니다. 회귀가 PR 단계에서 자동으로 막힙니다."

### 결말
> "결과적으로 표준 도구로 잡히지 않던 PQC 함정 6종을 본 파이프라인이 모두 감지하고, LLM 단독 시 100%였던 production crash 위험을 0%로 차단합니다."

---

## 10. 검증 체크리스트 (편집 완료 후)

영상 처음부터 끝까지 시청하며:

- [ ] 총 길이 3분 ± 15초 이내
- [ ] Act 간 전환이 부드러움 (cross-dissolve)
- [ ] Act 1: RSA 코드와 git push가 모두 보임
- [ ] Act 2: Semgrep 탐지 로그 + PR #81 봇 작성자 표시 + [IMPROVED] 라벨 모두 보임
- [ ] Act 3: `PASS` 글자와 `Exit: 35` 글자 모두 보임 + matrix CI 그린 체크 3개
- [ ] Act 4: `FAIL` 글자 또는 빨간 X 마크 보임
- [ ] 결말 카드: 세 수치 모두 가독성 좋음
- [ ] 한글 깨짐 없음
- [ ] 음성 안 들어감 (무음 확인)
- [ ] 마우스 커서가 화면에 보임

---

## 11. 트러블 슈팅

| 증상 | 원인 | 대응 |
|------|------|------|
| Docker 컨테이너 unhealthy | OQS 이미지 변경 | `docker compose down && TLS_STAGE=3 docker compose up -d --build` |
| `verify_tls.sh` FAIL | proxy-server 기동 안 됨 | `docker compose restart pqc-proxy` 후 10초 대기 |
| 한글 깨짐 | 터미널 폰트 | "D2Coding" 또는 "맑은 고딕" 설정 |
| OBS 검은 화면 | 그래픽 가속 | OBS 소스 → "디스플레이 캡처" 대신 "윈도우 캡처" |
| PowerPoint 임베드 영상 자동재생 안 됨 | 설정 | 영상 클릭 → 재생 탭 → 시작 = 자동 |
| Act 2 컷 2-A에서 적당한 run 못 찾음 | run 너무 옛것 | 새로 push해서 workflow 실행시키고 30분 후 캡처 |

---

## 12. 녹화 후 정리

```bash
docker compose down
rm artifacts/eval/cbom_diff_experiments/demo_*.json
```

영상 백업:
- 원본 .mp4 파일을 OneDrive/Google Drive에 업로드 (발표 당일 PC 사고 대비)
- 최종 편집본을 PowerPoint 슬라이드에도 임베드

---

## 13. 핵심 메시지 (한 줄)

이 영상이 시청자에게 남겨야 할 단 한 줄:

> **"개발자가 push만 하면 PQC 전환과 검증이 알아서 끝난다 — 그리고 회귀 시도는 자동으로 막힌다."**

이 한 줄이 영상에서 전달되지 않으면 어떤 장면이든 다시 찍는다.
