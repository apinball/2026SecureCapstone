# LLM 기반 RSA → PQC 마이그레이션 평가 벤치마크 스펙 (A-1)

## 목적

LLM(GPT-4o-mini via GitHub Models)이 RSA 사용 Python 코드를 oqs-python 기반 ML-KEM/ML-DSA로 자동 마이그레이션할 수 있는가? 다층 검증(prompt → AST → semantic test → bot review)이 단일 LLM 호출 대비 얼마나 오류를 줄이는가?

## 평가 차원

### 1. 입력 패턴 카테고리 (총 N=24)

| 축 | 값 | N |
|---|---|---|
| **라이브러리** | `cryptography.hazmat`, `PyCryptodome`, `M2Crypto` | 3 |
| **사용 케이스** | 키 생성, 암호화/복호화, 서명/검증, 키 교환(KEX) | 4 |
| **복잡도** | 단순(20 LOC 이하), 중간(클래스/파일 IO), 복잡(비동기/wrapper) | — |

**커버리지**: 3 라이브러리 × 4 케이스 × 2 복잡도 = 24 패턴

> 키 교환은 cryptography.hazmat에는 RSA-KEM이 없으므로 케이스별 라이브러리 제외 처리. 실제 N은 약 18-22로 조정.

### 2. 평가 지표 (다층 방어 ablation)

각 N개 입력에 대해 4단계 측정:

| 단계 | 입력 | 평가 | 출력 |
|---|---|---|---|
| **L1: prompt only** | 패턴 코드 | LLM 1회 호출 | 마이그레이션 결과 |
| **L2: + AST 검증** | L1 결과 | `validate_oqs_usage()` | pass/fail |
| **L3: + semantic test** | L2 통과분 | KEM encap/decap 셰어드시크릿 일치, 서명 verify 통과 등 | pass/fail |
| **L4: + 정답 비교** | L3 통과분 | 기준 답안과 의미 동등성 (수동/AST 매칭) | match/mismatch |

각 단계의 통과율 = `pass / N` 으로 ablation curve 생성.

### 3. 핵심 정량 지표

- **Static correctness rate** (L2 통과율): "API 사용이 올바른가"
- **Behavioral correctness rate** (L3 통과율): "실행 시 의도한 결과가 나오는가"
- **Semantic equivalence rate** (L4 통과율): "정답과 의미적으로 같은가"
- **Multi-layer error reduction**: L1-only vs L1+L2+L3 사이의 오류 감소 비율

### 4. 정성 분석: 실패 모드 분류

L1 실패 케이스를 다음 분류로 라벨링:

- **API hallucination**: 존재하지 않는 메서드 호출 (예: `kem.encapsulate()` 대신 `kem.encap_secret()`)
- **Semantic drift**: 동작은 하지만 RSA의 역할(서명 vs 암호)을 잘못 매핑
- **Incomplete migration**: RSA 일부만 교체, 나머지 RSA 잔존
- **Type/signature mismatch**: 함수 시그니처를 보존하지 않아 caller가 깨짐
- **Constructor misuse**: `KeyEncapsulation`을 모듈 레벨에서 인스턴스화 (race condition 위험)
- **Library mix-up**: oqs-python이 아닌 PyCryptodome PQ fork 등 다른 라이브러리 사용

이 분류는 PR #82 PoC 첫 시도 시 Gemini 봇이 발견한 5개 이슈 중 4개를 커버. 추가 이슈는 문서에서 확장.

## 패턴 파일 구조

```
artifacts/eval/benchmark/
├── patterns/
│   ├── 01_cryptography_keygen_simple.py        # 입력 (RSA 코드)
│   ├── 02_cryptography_keygen_complex.py
│   ├── 03_cryptography_encrypt_simple.py
│   ├── 04_cryptography_sign_simple.py
│   ├── ...
│   └── 24_m2crypto_kex_complex.py
├── reference/
│   ├── 01_cryptography_keygen_simple.py        # 정답 (oqs-python)
│   ├── ...
└── results/
    ├── L1_prompt_only.json                      # LLM 출력 N개
    ├── L2_ast_validation.json
    ├── L3_semantic_test.json
    └── L4_equivalence.json
```

## 평가 하네스

기존 `ai-migration/migrate.py`를 확장:

1. `eval_runner.py`: patterns/ 순회, 각 패턴에 LLM 호출 → results/L1
2. `validate_oqs_usage()` 재사용 → results/L2
3. `semantic_test.py`: 패턴별로 미리 정의된 테스트 케이스 (예: KEM은 encap/decap shared secret 일치) → results/L3
4. `equivalence_check.py`: 정답 AST 트리와 LLM 출력 AST 트리의 노드 매칭 비율 + 수동 confirm → results/L4

## 통계적 유의성

- N=24는 경향 보고에 충분, 통계 검정에는 제한적 (Wilson interval 95% CI 폭 ±20%p 수준)
- 각 패턴에 대해 LLM을 **k=5회** 반복 호출하여 N×k=120 샘플로 확대 (LLM stochasticity 측정 가능)
- 비용: GitHub Models gpt-4o-mini 무료 tier 기준 일 50 호출 한도 → 3일에 걸쳐 수집 가능

## 한계 및 외부 타당성

- 패턴은 합성된 것 → 실제 OSS 코드의 길이/스타일/주변 컨텍스트 다양성을 완전히 대표하지 못함
- 단일 LLM(gpt-4o-mini) 결과 → 다른 모델로 일반화 X. 보강하려면 Claude/Gemini 추가 호출
- 평가자(LLM-as-judge 미사용) → L4는 우리가 직접 라벨링, IAA(inter-annotator agreement) 보고 필요

## 논문 contribution 진술 (초안)

> 본 연구는 (1) PQC 마이그레이션을 위한 첫 LLM 평가 벤치마크 N=24 패턴을 제안하고, (2) 다층 검증(AST+semantic+equivalence)이 단일 LLM 호출 대비 오류를 X% 감소시킴을 정량적으로 보이며, (3) 표준 정적 분석으로 잡히지 않는 인프라 함정 6종(F-1 ~ F-6)을 함께 카탈로그화함으로써 PQC 도입 시 코드와 도구 체인 양 층의 자동 검증이 모두 필요함을 실증한다.
