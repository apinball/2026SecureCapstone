# 평가 실행 가이드

## 사전 조건
- Docker Desktop 실행 중
- GitHub Personal Access Token (`models:read` scope, 무료 tier)
  - 발급: https://github.com/settings/tokens — fine-grained → permissions에 "Models: Read" 추가

## 1) Docker 이미지 빌드 (1회)
```powershell
docker build -t pqc-eval -f artifacts/eval/Dockerfile .
```

## 2) Sanity check (검증된 결과)

**(a) 정답을 후보로** → 모든 단계 100% 통과해야 정상
```powershell
$env:MSYS_NO_PATHCONV=1
docker run --rm -v "${PWD}/artifacts/eval:/eval" pqc-eval `
    python /eval/eval_runner.py --offline --use-reference --k 1 `
    --output /eval/benchmark/results/sanity.json
```
기대: L2/L3/L4 = 16/16/16/16. 이미 검증 완료 → `benchmark/results/sanity.json`.

**(b) 입력 RSA 그대로** → 0%여야 정상 (baseline)
```powershell
docker run --rm -v "${PWD}/artifacts/eval:/eval" pqc-eval `
    python /eval/eval_runner.py --offline --k 1 `
    --output /eval/benchmark/results/baseline.json
```
기대: 0/0/0/0. 이미 검증 완료.

## 3) 본 평가 (LLM 호출)

```powershell
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxx"

docker run --rm -e GITHUB_TOKEN -v "${PWD}/artifacts/eval:/eval" pqc-eval `
    python /eval/eval_runner.py --k 5 `
    --output /eval/benchmark/results/llm_k5.json
```

- 16 패턴 × 5 trial = 80 LLM 호출
- gpt-4o-mini 무료 tier 일 50건 한도 → k=3으로 줄이거나 분할 실행 (`--k 3`)
- 소요: 약 5-10분 (네트워크 의존)

결과는 `benchmark/results/llm_k5.json`에 저장. 각 trial별 L2/L3/L4 통과 여부 + LLM 응답 길이 + 에러 기록.

## 4) 결과 분석

JSON 파싱 예시 (Python):
```python
import json
data = json.load(open("artifacts/eval/benchmark/results/llm_k5.json", encoding="utf-8"))
trials = data["results"]

# 패턴별 통과율
from collections import defaultdict
by_pid = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0})
for t in trials:
    by_pid[t["pattern_id"]]["n"] += 1
    if t.get("L2_ast_ok"): by_pid[t["pattern_id"]]["l2"] += 1
    if t.get("L3_semantic_passed"): by_pid[t["pattern_id"]]["l3"] += 1
    if t.get("L4_equivalent"): by_pid[t["pattern_id"]]["l4"] += 1

for pid, s in sorted(by_pid.items()):
    print(f"{pid}: L2={s['l2']}/{s['n']} L3={s['l3']}/{s['n']} L4={s['l4']}/{s['n']}")
```

## 5) 논문 표 만들기 (선택)

`benchmark/results/llm_k5.json`에서 추출 가능한 지표:
- **다층 방어 ablation curve**: L1(전체 시도) → L2 통과 → L3 통과 → L4 통과 사이의 비율
- **패턴별 정확도 매트릭스**: 라이브러리 × 사용 케이스 × 복잡도
- **실패 모드 분포**: `L2_ast_issues` 텍스트 분류 (API hallucination / Constructor misuse / Library mix-up …)

원하시면 표/그래프 자동 생성 스크립트도 추가 가능합니다.

## 한계 사항 (논문에 적시)

- N=16 패턴은 합성. OSS 코퍼스 직접 평가 아님 (외부 타당성 약화)
- 단일 모델(gpt-4o-mini). Claude/Gemini 등 비교 X → 모델 일반화 X
- L4(equivalence)는 AST feature 매칭 근사. 완전한 의미 동등성 분석 아님
- liboqs 0.14.0 / oqs-python 0.14.1 기준. 다른 버전에서 정답 코드의 export_secret_key API가 다를 수 있음
