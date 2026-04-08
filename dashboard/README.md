# Pipeline Dashboard

DevSecOps PQC Pipeline의 GitHub Actions 실행 결과를 **단일 HTML 파일**로 정리해주는 리포트 생성기다.
발표/시연 중에 바로 열어볼 수 있도록 외부 CDN 없이 self-contained로 동작한다.

## 특징

- Python 표준 라이브러리만 사용 (추가 의존성 0)
- 외부 CDN, 프레임워크, 빌드 툴 없음 → 파일 하나만 열면 바로 렌더링
- 다크 테마 · 카드 UI · 타임라인 · 배지 기반 깔끔한 디자인
- JSON 파일이 없거나 구조가 달라도 "데이터 없음"으로 graceful fallback

## 입력 파일

아래 JSON들을 순차적으로 읽는다. 없어도 죽지 않는다.

| 경로 | 설명 |
|------|------|
| `artifacts/scan-summary.json` | Trivy / Gitleaks / Semgrep 종합 결과 |
| `artifacts/crypto-findings.json` | Semgrep 기반 고전 암호 탐지 결과 |
| `scanner/results/tls-check-summary.json` | TLS 동적 검증 결과 |
| `artifacts/cbom_stage{stage}.json` | CycloneDX CBOM (migration progress 포함) |

## 출력

단일 HTML 파일. GitHub Actions에서는 artifact로 업로드된다.

```
artifacts/pipeline-dashboard-stage{stage}-run{run_number}.html
```

## 대시보드 구성

1. **상단 요약 카드** — Stage, Run 번호, 전체 결과, 각 스캐너 상태, 레거시 암호 건수, CBOM migration progress, 수동 조치 건수
2. **파이프라인 타임라인** — checkout → 자동 마이그레이션 → 고전 암호 탐지 → 정적 분석 → TLS 검증 → 빌드 → 동적 검증 → CBOM 단계를 success/fail/warning/unknown 상태로 표시
3. **TLS 동적 검증 상세** — 협상된 프로토콜/cipher/key exchange group
4. **고전 암호 탐지 목록** — 파일·라인·rule·severity·메시지
5. **CBOM 마이그레이션 현황** — progress, summary, 수동 조치 필요 목록
6. **Raw JSON** — 각 입력 파일을 접을 수 있는 details 블록으로 제공

## 실행 방법

### 로컬 실행

```bash
python dashboard/generate_report.py \
  --stage 2 \
  --run-number 99 \
  --out artifacts/pipeline-dashboard.html
```

입력 파일 경로를 직접 지정할 수도 있다:

```bash
python dashboard/generate_report.py \
  --stage 2 --run-number 1 \
  --scan-summary artifacts/scan-summary.json \
  --crypto-findings artifacts/crypto-findings.json \
  --tls-summary scanner/results/tls-check-summary.json \
  --cbom artifacts/cbom_stage2.json \
  --out artifacts/pipeline-dashboard.html
```

### GitHub Actions에서

`.github/workflows/devsecops-pipeline.yml`의 CBOM 생성/Job Summary 작성 이후 단계에서
자동으로 실행되며, 생성된 HTML은 기존 scan-results artifact에 함께 포함된다.

## 상태 판정 규칙

| 상태 | 색상 | 의미 |
|------|------|------|
| `success` | 초록 | 통과 / 정상 |
| `fail` | 빨강 | 실패 / 차단 |
| `warning` | 노랑 | 주의 (레거시 암호 존재 등) |
| `unknown` | 회색 | JSON 만으로 추론 불가 |

파이프라인 단계별 세부 상태는 현재 JSON만으로 완벽하게 알 수 없으므로,
가능한 정보로 합리적으로 추론하고 확신할 수 없으면 `unknown`으로 둔다.
정확도보다 "사람이 보기 좋고 납득 가능한 요약"을 우선한다.
