# ai-migration/

AI 보조 PQC 코드 마이그레이션 PoC.

semgrep이 탐지한 레거시 RSA 사용 코드를 LLM(GitHub Models)에 보내 ML-KEM/ML-DSA로 변환한 뒤, 별도 브랜치에 커밋하고 PR을 자동 생성합니다.

## 흐름

```
crypto-classical.yaml semgrep 탐지
  ↓
artifacts/crypto-findings.json
  ↓
ai-migration/migrate.py
  ├─ 대상 필터링: Python 파일 + RSA 룰 (최대 3건)
  ├─ 파일별 LLM 호출 (GitHub Models, gpt-4o-mini)
  ├─ 응답 검증: 문법 체크 + 변경 여부 확인
  ├─ 새 브랜치 생성: auto-migration/<sha>-<timestamp>
  └─ gh pr create --base develop --label ai-generated
```

## 실행 환경

- **GITHUB_TOKEN**: 필수. `models:read` + `repo` (PR 생성) 스코프
- **gh CLI**: PR 생성용
- **Python 3.10+**

GitHub Actions 환경에서는 위 모두 자동 충족됨. 로컬 실행 시 `gh auth login` 후 `GITHUB_TOKEN=$(gh auth token)` 형태로 토큰 주입.

## 수동 실행

```bash
# semgrep 결과가 이미 있다면
python ai-migration/migrate.py \
  --findings artifacts/crypto-findings.json \
  --base develop

# 드라이런 (파일만 수정, git/PR 안 함)
python ai-migration/migrate.py --dry-run
```

## 트리거

`workflow_dispatch` 수동만 — `.github/workflows/ai-migration.yml` 참고.

자동 트리거(push/PR)는 비용·노이즈 부담으로 활성화하지 않음. 발표 시연 또는 의도적 일괄 마이그레이션 시 수동 실행.

## 제한 사항 (PoC)

| 항목 | 현재 | 향후 |
|------|------|------|
| 대상 언어 | Python | Java, Go, C/C++ 추가 |
| 대상 룰 | RSA 사용 (3종) | ECC, MD5, SHA-1 등 |
| 처리 한도 | 한 번에 3개 파일 | 비용 게이트로 동적 조정 |
| 검증 | 문법 체크 | pytest / unit test 자동 실행 |
| LLM | GitHub Models gpt-4o-mini | 다중 프로바이더 추상화 |

## 안전장치

- **자동 머지 없음**: 항상 PR 단계에서 멈춤. 사람 리뷰 필수
- **문법 검증**: `compile()` 실패한 응답은 적용 거부
- **변경 없음 거부**: LLM이 동일 내용 반환 시 적용 거부
- **`NO_MIGRATION_POSSIBLE` 회피**: 모델이 안전하지 않다고 판단하면 스킵
- **temperature=0**: 결정론적 출력
- **라벨 자동 부착**: `ai-generated` 라벨로 사람 리뷰 시 식별
