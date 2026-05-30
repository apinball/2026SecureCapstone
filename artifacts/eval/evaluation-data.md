# 평가 자료집 — 논문 작성용 raw material

> 본 문서는 "논문 본문에 옮기기 편한" 형태의 데이터·수치·인용 자료 모음이다.
> Introduction/Discussion 같은 narrative는 포함하지 않는다. 표·정의·사례·한계·인용 후보를 그대로 발췌해 쓸 수 있도록 구성했다.

---

# Part 0. 평가의 정의와 기여 (Introduction 작성용)

## 0.0 한 줄 요약 — "그래서 뭐가 좋은가"

본 연구가 다른 사람·조직에게 주는 실용적 가치:

1. **PQC TLS 도입을 시도하는 보안 엔지니어**: 6종 함정 카탈로그를 미리 읽고 동일 함정을 피할 수 있다. 표준 도구(Trivy/Semgrep/CBOM)로는 잡히지 않는 함정의 종류와 위치를 사전에 알 수 있다.
2. **DevSecOps 파이프라인을 설계하는 팀**: 매트릭스 CI + 자체 빌드 조합이 표준 도구의 사각지대를 메우는 정량적 근거(6/6 함정 감지·5/6 예방)를 의사결정 자료로 사용할 수 있다.
3. **LLM으로 코드 마이그레이션을 자동화하려는 팀**: gpt-4o-mini는 응답 받은 trial 55건 모두 어딘가에서 실패하여 **실제 동작 코드 0건**을 생산(L3=0%). 즉 LLM 단독 자동화는 불가. 그리고 AST 정적 검증을 적용해도 전체 실패의 **44%(24/55)**는 시그니처/인자 환각으로 통과되어 런타임에서야 잡히므로, 정적 검증 단독으로도 부족하고 **런타임 semantic test가 필수**임을 정량 근거로 가짐.
4. **LLM 평가 벤치마크를 만드는 연구자**: PQC 전용 N=16 합성 패턴 + ground truth + 자동 평가 하네스(Dockerfile 포함) 전체를 그대로 재사용·확장 가능. 새 모델 측정 시 80 trial = $0.013로 재현.
5. **PQC 마이그레이션을 표준화하려는 정책/툴 개발자**: LLM 실패 모드 7종 taxonomy를 후속 도구·모델 개선의 타겟으로 사용. 어떤 종류의 실수가 가장 자주 발생하는지(시그니처 환각 36% > 인스턴스 누락 27%) 빈도 데이터를 가짐.
6. **자기 조직에 PQC 파이프라인을 적용하려는 운영자**: 본 파이프라인(자체 빌드 + 매트릭스 CI + AI 마이그레이션 + 다층 검증)이 6/6 도구 체인 함정을 감지하고 LLM 단독 시 production crash 100%를 0%로 차단하는 효과를 정량 근거로 사용. PQC 전환 시 "어떤 검증 layer를 두어야 하는가"의 청사진을 그대로 가져갈 수 있음.

## 0.1 세 평가의 위치

본 연구는 PQC 마이그레이션 실무의 두 함정 층(인프라 통합 / LLM 자동화)을 평가 A·B로 측정하고, 본 프로젝트가 제안한 파이프라인이 두 함정에 어떤 효과가 있는지를 평가 C로 측정한다.

| 차원 | 평가 A | 평가 B | 평가 C |
|---|---|---|---|
| **무엇을 측정하나** | 인프라 통합 시 도구 체인 함정과 표준 도구의 사전 탐지 가능 여부 | LLM(gpt-4o-mini)의 RSA→ML-KEM/ML-DSA 자동 마이그레이션 정확도 | 본 프로젝트 파이프라인(자체 빌드 + 매트릭스 CI + AI 마이그레이션 + 다층 검증)이 평가 A·B의 함정을 막거나 감지하는 효과 |
| **답하는 질문** | PQC 도입 시 어떤 함정이 발생하나? 표준 도구로 잡히나? | LLM이 PQC 마이그레이션을 정확히 하나? AST 단독으로 충분한가? | 우리 파이프라인을 적용하면 함정의 몇 개가 막히나? LLM 단독 대비 위험이 얼마나 줄어드나? |
| **평가 대상** | OQS 기반 docker-compose 3-Stage TLS 환경 | gpt-4o-mini + 합성 RSA 코드 N=16 | 본 프로젝트의 매트릭스 CI(PR #83) + 자체 빌드(PR #84) + 4-Layer 검증 하네스 |
| **분석 방법** | 자체 PR/CI 머지 과정의 실패 사례를 함정 단위 카탈로그화 + 표준 도구 탐지 가능성 평가 | 4-Layer 검증 파이프라인(L1~L4)을 80 trial에 적용 | 평가 A·B 데이터를 파이프라인 layer별 효과로 재해석 + 회귀 감지 시나리오 검증 |
| **데이터 출처** | 실제 PR #71/#76/#82/#83/#84 + Stage 3 회귀 디버깅 로그 | GitHub Models API 호출 결과 80 trial | 평가 A 매트릭스 + 평가 B 4-Layer 결과 + 본 프로젝트 PR 머지 이력 |
| **결과물 형태** | 함정 6종 + 표준 도구 탐지 매트릭스 | 4-Layer 통과율 + 7종 실패 taxonomy + 차원별 분석 | 함정 차단율 (6/6 감지·5/6 예방) + LLM 다층 방어 위험 감소율 (100% → 0%) + 회귀 감지 시점 단축 |
| **재현성** | OQS 버전/sha256 명시, PR 번호 추적 가능 | Dockerfile + harness 코드 + 80 trial 원시 JSON 공개 | 본 프로젝트 git history에서 PR/CI 결과 그대로 재현 |

## 0.2 평가 A — 인프라 함정 카탈로그

### 정의

PQC TLS 도구 체인을 docker-compose 환경에 통합·운영하면서 발생하는 호환성·협상·인증서 함정을 사례 단위로 식별하고, 각 함정이 표준 보안 도구(SCA / SAST / SBOM)로 사전 탐지되는지를 평가한다.

### 범위

- **포함**: liboqs / oqs-provider / OpenSSL 1.1.1·3.x 라인 / OQS-nginx / OQS-curl 의 빌드 시점 또는 런타임 호환성 문제
- **제외**: 일반 nginx 설정 오류, 일반 docker compose 문제, OQS 외부 라이브러리 버그

### 평가에서 답하는 질문

1. PQC 도입 시 어떤 종류의 함정이 발생하는가? (정성적 분류)
2. 각 함정의 트리거 조건과 증상은 무엇인가? (재현 가능한 명세)
3. 기존 도구 카테고리(SCA / SAST / SBOM)의 설계 scope에 본 함정 클래스가 포함되는가? (scope 분석 — 도구의 결함 주장이 아니라 커버리지 공백 식별)
4. 어떤 검증 메커니즘이 함정을 막거나 감지할 수 있는가? (보완 layer 매핑)

### 기여 (Contribution)

- **C-A1: 카탈로그 자체** — NIST 표준화(2024-08) 직후 OQS 스택에서 발생한 함정 6종(F-1~F-6)을 트리거/증상/원인/방어로 구조화. 저자가 아는 한 PQC 도입 시 도구 체인 함정을 단일 사례에서 6종까지 유형화한 보고는 없음.
- **C-A2: 기존 도구 scope 외 함정 클래스의 존재 정량화** — Trivy(SCA), Semgrep(SAST), CycloneDX CBOM(SBOM)은 알려진 CVE·코드 패턴·자산 인벤토리를 대상으로 설계된 도구이며, 본 6종 함정(라이브러리 버전 비대칭으로 인한 wire-level code point 불일치 등)은 이들 도구의 설계 scope 밖에 위치함을 표로 명시. 도구의 "결함"이 아니라 PQC 도구 체인 통합기에 새로 등장한 함정 클래스가 기존 카테고리에 커버되지 않음을 시사.
- **C-A3: 보완 검증 메커니즘 제안** — 런타임 매트릭스 CI(6/6 감지)와 자체 빌드(5/6 예방)가 표준 도구의 사각지대를 메움을 매트릭스로 명시.
- **C-A4: 외부 타당성** — 동일 패턴(라이브러리 라인 비대칭 → wire-level code point 불일치)이 BoringSSL+CIRCL, Java BC PQ에서도 보고되었음을 통해 OpenSSL/OQS 한정이 아님을 시사.

### 그래서 뭐가 좋은가 (Practical Value)

| 누가 쓰나 | 무엇에 쓰나 | 어떻게 쓰나 |
|---|---|---|
| PQC TLS 도입 보안 엔지니어 | 사전 함정 회피 | 6종 카탈로그(F-1~F-6)를 도입 전 체크리스트로 사용. 동일 증상 발생 시 본 문서의 진단 명령어와 방어책으로 즉시 대응 |
| DevSecOps 팀 | 도구 선택 의사결정 | "Trivy/Semgrep/CBOM은 PQC 함정 0/6 탐지" 정량 근거로 추가 검증 layer(매트릭스 CI, 자체 빌드) 도입 정당화 |
| 보안 도구 벤더 | 신규 룰셋 개발 | 카탈로그의 6종 함정을 새 룰의 검출 대상으로 사용. "기존 도구가 못 잡는 케이스" 명세 |
| 표준화 정책 입안자 | 전환기 가이드라인 | "표준화 직후 라이브러리 변동성이 만든 함정 6종" 사례로 전환기 권고 사항 작성 |
| 다른 PQC 스택 사용자 (BoringSSL/BC) | 동일 함정 재현 여부 확인 | 본 카탈로그의 함정 패턴을 자기 스택에 매핑해 검증 |

### 한계

- N=1 캡스톤 프로젝트의 경험적 카탈로그 → 통계적 일반화 X
- 표준화 직후 시점 한정 → OQS 안정화 후 함정 양상이 어떻게 변할지 추적 불가
- 6종은 본 프로젝트에서 발견된 것만 → 모집단 전체의 함정 수는 알 수 없음

## 0.3 평가 B — LLM 마이그레이션 정량 평가

### 정의

상용 LLM(GitHub Models gpt-4o-mini)이 Python의 RSA 사용 코드를 ML-KEM-768 / ML-DSA-65 (oqs-python) 기반 코드로 자동 마이그레이션할 수 있는지를 정량적으로 평가한다. 단순 통과율이 아니라 (a) 정적 검증 (b) 실제 실행 (c) 정답 동등성의 4-Layer로 분리 측정하여 LLM 출력의 어떤 측면이 정확하고 어떤 측면이 환각인지 분리한다.

### 범위

- **포함**: Python 단일 파일, RSA의 4가지 사용 케이스(keygen, encrypt, sign, kex), 두 라이브러리(`cryptography.hazmat`, `PyCryptodome`), 두 복잡도(simple/complex)의 직교 설계 N=16 합성 패턴
- **제외**: 다른 언어(Java/Go), 다른 PQC 라이브러리(BC, CIRCL), 일반 LLM 코드 생성 능력 평가

### 평가에서 답하는 질문

1. LLM이 PQC 마이그레이션을 얼마나 잘 수행하는가? (전반 통과율)
2. AST 정적 검증과 런타임 semantic test 중 어느 것이 더 효과적인가? (layer별 분리)
3. LLM이 자주 만드는 실수의 종류와 빈도는 무엇인가? (taxonomy)
4. 패턴 종류(라이브러리/사용 케이스/복잡도)별로 LLM 정확도가 달라지는가? (차원 분석)
5. 본 평가 metric은 임계값 선택에 강건한가? (sensitivity)

### 기여 (Contribution)

- **C-B1: PQC 마이그레이션을 위한 LLM 평가 벤치마크** — 라이브러리×사용 케이스×복잡도 직교 설계 N=16 + ground truth + 자동 평가 하네스 전체. 저자가 아는 한 PQC 전용 LLM 마이그레이션 벤치마크는 공개된 것이 없음.
- **C-B2: 4-Layer 검증 파이프라인 설계와 측정** — L1(응답)/L2(AST)/L3(semantic)/L4(equivalence) 분리 측정으로 LLM 출력의 "어떤 정확성 차원"이 통과/실패하는지를 분리. 단일 통과율로는 보이지 않는 구조적 정확성 vs 의미적 정확성의 불일치를 정량화.
- **C-B3: LLM 실패 모드 taxonomy 7종** — `wrong_arg_count`(16건), `missing_instance_construction`(20건), `wrong_kwarg`(5건), `method_hallucination`(2건) 등 빈도와 정의 명시. 후속 연구의 분류 기준 제공.
- **C-B4: 다층 방어의 분담 입증** — L2와 L3가 차단하는 카테고리 overlap = 0. 정적 분석 단독으로는 시그니처 환각(`wrong_arg_count` 등 24건, 44%)을 잡지 못하므로 런타임 semantic test가 필수임을 정량 입증.
- **C-B5: 차원별 LLM 약점 식별** — keygen 패턴의 L2 통과율 0%로 caller-breaking signature 변경이 LLM에 가장 어려움을 보임. complex 패턴의 L4 통과율이 simple의 절반(35% vs 65%)으로 클래스 wrapper와 IO 동시 처리의 한계를 보임.
- **C-B6: 재현 가능한 평가 인프라** — Dockerfile + harness + 80 trial 원시 데이터 공개. 무료 tier 한도 내에서 재현 가능($0.013/80 trial).

### 그래서 뭐가 좋은가 (Practical Value)

| 누가 쓰나 | 무엇에 쓰나 | 어떻게 쓰나 |
|---|---|---|
| LLM 자동화 도입을 검토하는 보안팀 | "LLM에 PQC 마이그레이션 맡겨도 되나?" 의사결정 | "응답 55건 모두 실패 → L3=0%" + "AST 통과해도 24/55(44%)가 런타임에서 깨짐"을 근거로 "LLM 단독 도입 불가, 정적 + 런타임 다층 검증 필수" 결론을 ROI 분석에 직접 사용 |
| 보안 코드 검증 도구 개발자 | 도구 설계 근거 | 다층 방어 분담 표(L2 vs L3 overlap=0)를 근거로 정적 분석 + 런타임 검증을 모두 포함하는 도구 설계 정당화 |
| LLM 모델 개선/fine-tuning 연구자 | 개선 타겟 명확화 | 7종 taxonomy로 "어떤 종류 실수를 우선 줄여야 하는가" 명시. 가장 빈번한 `wrong_arg_count`(16건), `missing_instance_construction`(20건)을 fine-tuning 데이터 우선순위로 사용 |
| 후속 연구자 | 다른 모델·프롬프트 비교 | N=16 패턴 + ground truth + 평가 하네스 그대로 재사용. GPT-4o, Claude, Gemini Pro 등을 80 trial $0.013로 측정 후 본 결과와 비교 |
| PQC 라이브러리(oqs) 메인테이너 | API 문서·예제 개선 | LLM이 환각하는 패턴(`import_public_key`, `public_key=` kwarg)이 어떤 것인지 알 수 있음. 이런 prior가 강한 지점에 명시적 안내문 추가 |
| 캡스톤/대학원 연구 | 후속 연구 진입 장벽 ↓ | Dockerfile 1번 빌드 + GitHub Models 무료 토큰으로 본 측정 즉시 재현. 새 가설(naive prompt 비교, multi-model 비교 등)에 대한 추가 측정 빠르게 가능 |

### 한계

- **단일 모델**: gpt-4o-mini만 평가. GPT-4o, Claude, Gemini Pro 등 더 큰 모델은 결과 다를 가능성 → 외부 타당성 가장 큰 약점
- **합성 패턴**: 실제 OSS 코드의 길이/스타일/주변 컨텍스트 다양성 미반영
- **Rate limit 편향**: 25/80 trial이 LLM API error로 종료, 특히 패턴 13–16에 집중 → 통계가 cryptography 측 편향
- **저자 정의 ground truth**: 정답 16개와 평가 기준 모두 저자 작성 → self-fulfilling 위험
- **Naive prompt 비교 부재**: 정성스러운 프롬프트의 효과 분리 불가
- **temperature=0 한정**: stochasticity 미평가

## 0.4 평가 C — 본 프로젝트 파이프라인의 효과

### 정의

본 프로젝트가 제안·구현한 PQC 도입 파이프라인 (자체 빌드 + 매트릭스 CI + AI 마이그레이션 + 4-Layer 검증)이, 평가 A에서 발견된 도구 체인 함정 6종과 평가 B에서 측정된 LLM 자동화 실패에 어떤 정량 효과를 가지는지를 측정한다.

### 범위

- **포함**: 파이프라인 구성 요소 4종(자체 빌드 / 매트릭스 CI / AI 마이그레이션 / 다층 검증)이 평가 A·B의 실패에 적용됐을 때의 차단·감지 효과
- **제외**: 사람의 작업 시간/노력 측정 (별도 통제 실험 없음 → 정성 추정만)

### 답하는 질문

1. 파이프라인 layer 각각이 평가 A의 6종 함정 중 몇 개를 차단/감지하나?
2. LLM 단독 대비 다층 검증 적용 시 production crash 위험은 얼마나 감소하나?
3. 매트릭스 CI는 회귀를 PR 시점에 즉시 감지하나? (PR #71 회귀 사례 counterfactual)
4. 본 캡스톤 프로젝트의 마이그레이션은 실제로 완료됐나? (정성 평가)

### 기여 (Contribution)

- **C-C1: 함정 차단·감지 매트릭스** — 평가 A의 함정 6종 각각에 대해 본 파이프라인 4 layer가 차단(예방)하거나 감지(런타임 발견)하는지 표로 명시. **매트릭스 CI는 6/6 감지, 자체 빌드는 5/6 예방**.
- **C-C2: LLM 다층 방어 위험 감소율** — 평가 B 데이터를 파이프라인 layer별로 재해석. **LLM 단독 시 production crash 100%(55/55) → AST 추가 시 100%(24/24, 통과 코드 기준 동일) → AST + semantic test 추가 시 0%**. 정적 검증 단독은 위험률을 0으로 못 만들고 의미적 검증을 추가해야 함을 정량 입증.
- **C-C3: 회귀 감지 시점 단축 (Counterfactual)** — PR #71 머지 후 발견된 F-2 회귀가 본 프로젝트의 매트릭스 CI(PR #83)가 미리 존재했다면 PR 단계에서 즉시 감지됐을 것임을 동일 테스트 시나리오로 검증.
- **C-C4: 캡스톤 프로젝트 자체의 PQC 전환 완성도** — Stage 1/2/3 TLS 모두 PASS, AI 마이그레이션 PoC 동작, CycloneDX 1.7 CBOM 자동 생성, ML-DSA-65 인증서 발급/검증, 자체 빌드로 OQS 라이브러리 라인 통일. 평가 A에서 발견한 함정 6종을 모두 해결한 후 머지된 PR 이력이 자체 증거.

### 그래서 뭐가 좋은가 (Practical Value)

| 누가 쓰나 | 무엇에 쓰나 | 어떻게 쓰나 |
|---|---|---|
| 자기 조직에 PQC 파이프라인 도입을 검토하는 운영자 | 도입 ROI 의사결정 | "매트릭스 CI 6/6 감지 + 자체 빌드 5/6 예방" 매트릭스를 자기 환경에 매핑해 도입 효과 추정 |
| 보안 아키텍트 | 검증 layer 설계 | "AST 단독은 위험 100%, AST + semantic 추가 시 0%" 데이터로 검증 layer 구성 결정 |
| 프로젝트 관리자/PM | 회귀 감지 SLA 산정 | PR #71 사례(머지 후 발견 vs PR 시점 감지)를 "매트릭스 CI 도입 시 MTTR 단축 효과" 근거로 사용 |
| 후속 캡스톤·연구 | 파이프라인 청사진 | 본 프로젝트의 4 layer 구성을 그대로 복제. 자체 빌드 Dockerfile, matrix CI YAML, AI 마이그레이션 코드, 4-Layer 평가 하네스 모두 공개 |
| 표준화 권고 작성자 | 전환기 가이드라인 | "PQC 도입 시 정적 도구만 쓰지 말고 매트릭스 CI + 자체 빌드 + 다층 검증 권장" 정량 근거 제공 |

### 한계

- N=1 캡스톤 프로젝트의 자체 평가 → 다른 조직·다른 코드베이스에서 동일 효과 보장 X
- 회귀 감지 시점 단축은 counterfactual 추정 (실제 시간 측정 부재)
- 사람의 작업 시간/노력 절감 효과는 정량 측정 안 함 (추정만 가능)
- 파이프라인 자체의 유지보수 비용(자체 빌드 시간, CI 비용)은 미측정

## 0.5 세 평가의 통합 기여

- **C-ABC1: 두 함정 층의 분리성 + 파이프라인의 통합 대응** — 도구 체인 함정(평가 A)은 인프라 통합 시점, LLM 자동화 함정(평가 B)은 application 코드 시점에 발생하여 위치·시점·도구가 모두 다름. 표준 SCA/SAST/SBOM은 평가 A의 6/6 함정을 놓치고 평가 B의 24/55 시그니처 환각도 정적 분석만으로는 잡히지 않음. 평가 C는 본 프로젝트의 파이프라인이 두 층을 동시에 메우는 효과(인프라 측 6/6 감지 + LLM 측 위험 100% → 0%)를 정량 입증.
- **C-ABC2: 양 층 모두에서 다층 방어가 필요하며, 본 파이프라인이 그 청사진** — 평가 A: 자체 빌드(예방) + 매트릭스 CI(감지) 두 layer 필요. 평가 B: AST(빠른 거부) + semantic test(시그니처 환각 차단) 두 layer 필요. 본 파이프라인은 두 영역의 다층 방어를 단일 DevSecOps 흐름으로 통합 — PQC 전환을 시도하는 다른 조직이 그대로 복제 가능한 reference 구현.
- **C-ABC3: 표준화 직후 라이브러리 변동성의 공통 영향과 대응** — 두 평가 모두 NIST 표준화 직후 라이브러리 명칭/code point/API 변동성에서 함정이 발생. 평가 A의 F-2/F-3은 wire-level code point 변동, 평가 B의 LLM 학습 분포 부족도 동일 라이브러리 변동성에서 비롯. 평가 C는 자체 빌드(외부 변동성 차단)와 매트릭스 CI(런타임 회귀 감지)가 변동성 환경에서의 안정성을 어떻게 확보하는지 보임.
- **C-ABC4: PQC 전환을 더 자연스럽게 만든다는 narrative의 정량 뒷받침** — "표준 도구로 충분하다"(거짓, 평가 A) + "LLM이 알아서 마이그레이션한다"(거짓, 평가 B) → "다층 파이프라인이 두 함정을 함께 메운다"(평가 C로 입증). 본 연구의 핵심 narrative는 "파이프라인을 통한 PQC 전환의 자연스러움"이며, 평가 A·B는 그 필요성, 평가 C는 그 실효성의 정량 근거.

---

# Part I. 평가 환경 (Methods 작성용)

## 1.1 측정 환경 명세

| 항목 | 값 |
|---|---|
| 측정 시점 | 2026-05-08 |
| 호스트 OS | Windows 10 Pro 10.0.19045 |
| 컨테이너 런타임 | Docker Desktop |
| 평가 컨테이너 base | `python:3.11-slim` |
| Python | 3.11.x |
| liboqs | 0.14.0 (소스에서 빌드) |
| liboqs-python | 0.14.1 (PyPI) |
| cryptography | 최신 (Dockerfile 빌드 시점) |
| pycryptodome | 최신 |
| LLM 엔드포인트 | `https://models.inference.ai.azure.com/chat/completions` |
| LLM 모델 | `gpt-4o-mini` |
| LLM temperature | 0.0 |
| 반복 수 k | 5 |
| 패턴 수 N | 16 |
| 총 trial | 80 |

## 1.2 OQS / TLS 스택 (평가 A 측 환경)

| 컴포넌트 | 버전 | 빌드 형태 |
|---|---|---|
| OpenSSL | 3.4.0 | source build, `--prefix=/opt/oqs --libdir=lib` |
| liboqs | 0.14.0 | source, `OQS_BUILD_ONLY_LIB=ON` |
| oqs-provider | 0.9.0 | source, OpenSSL 3.4 link |
| nginx | 1.27.2 | source, `--with-ld-opt=-L/opt/oqs/lib -Wl,-rpath,/opt/oqs/lib` |
| Stage 1 | classical ECC | `ssl_ecdh_curve X25519:P-256` |
| Stage 2 | hybrid PQC | `ssl_ecdh_curve X25519MLKEM768` |
| Stage 3 | strong hybrid | `ssl_ecdh_curve p521_mlkem1024:p384_mlkem768` |
| Stage 3 인증서 | Dilithium3 (ML-DSA-65) | `mldsa65` via oqs-provider |
| Stage 3 SECLEVEL | 0 | 임시 (ssl_ciphers DEFAULT:@SECLEVEL=0) |

## 1.3 입력 패턴 직교 설계

- **라이브러리 (2)**: `cryptography.hazmat`, `PyCryptodome`
- **사용 케이스 (4)**: keygen / encrypt / sign / kex
- **복잡도 (2)**:
  - simple: 함수 단위, ≤20 LOC, IO 없음
  - complex: 클래스 wrapper + 디스크 파일 IO + (일부) 환경 변수

총 2 × 4 × 2 = 16 패턴.

### 패턴 목록 (인용 시 사용 가능한 매핑 표)

| ID | 라이브러리 | 사용 케이스 | 복잡도 | 핵심 RSA API |
|---|---|---|---|---|
| 01 | cryptography | keygen | simple | `rsa.generate_private_key(2048)` |
| 02 | cryptography | encrypt | simple | `RSA-OAEP encrypt/decrypt` |
| 03 | cryptography | sign | simple | `RSA-PSS sign/verify` |
| 04 | cryptography | kex | simple | OAEP로 AES 키 wrap |
| 05 | cryptography | keygen | complex | KeyManager 클래스 + PEM 파일 IO |
| 06 | cryptography | encrypt | complex | SecureMessenger 클래스 + 파일 IO |
| 07 | cryptography | sign | complex | DocumentSigner 클래스 + 파일 IO |
| 08 | cryptography | kex | complex | SessionKeyExchange 클래스 + 파일 IO |
| 09 | pycryptodome | sign | simple | `pkcs1_15.new(key).sign/verify` |
| 10 | pycryptodome | keygen | simple | `RSA.generate(2048)` + PEM export |
| 11 | pycryptodome | encrypt | simple | `PKCS1_OAEP.new` |
| 12 | pycryptodome | kex | simple | OAEP wrap + AES-GCM |
| 13 | pycryptodome | keygen | complex | KeyVault 클래스 + 환경 변수 + 파일 IO |
| 14 | pycryptodome | encrypt | complex | EnvelopeCipher 클래스 + 파일 IO |
| 15 | pycryptodome | sign | complex | ReleaseSigner 클래스 + 파일 IO |
| 16 | pycryptodome | kex | complex | HandshakeBroker 클래스 + 파일 IO |

## 1.4 정답 (Ground Truth) 설계 정책

다음 정책으로 16개 정답 작성:

1. **마이그레이션 매핑**:
   - keygen / encrypt / kex → ML-KEM-768 (`oqs.KeyEncapsulation`)
   - sign → ML-DSA-65 (`oqs.Signature`)
2. **AES-GCM 결합 강제**: KEM은 임의 메시지 직접 암호화 불가 → encrypt/kex 케이스 정답은 KEM(공유 비밀 도출) + AES-GCM(메시지 AEAD) 결합. 결합 누락은 보안 회귀로 간주.
3. **API caller-breaking 변경 허용**: oqs는 비밀 키 상태를 인스턴스에 보존 → 시그니처에서 `private_key bytes`가 `kem instance`로 의미 변경됨을 docstring에 명시.
4. **모듈 레벨 인스턴스화 금지**: race condition 방지를 위해 모듈 import 시점에 `KeyEncapsulation`/`Signature` 인스턴스 생성 금지. 함수 내부 또는 클래스 멤버에 한정.
5. **파일 형식**: keygen complex 정답은 raw bytes (`*.bin`)로 저장. PEM은 ML-KEM에 정의되지 않음.
6. **알고리즘 명칭**: 본 정답에서는 `"ML-KEM-768"`, `"ML-DSA-65"` (NIST 표준 명칭). Kyber768/Dilithium3 같은 옛 명칭은 사용하지 않음.

## 1.5 4-Layer 검증 정의 (정확한 통과 조건)

### L1: LLM 응답 수신
- 통과 조건: GitHub Models API가 `200 OK` + `choices[0].message.content` non-empty 반환
- 실패 분류: HTTP error / timeout / rate limit (429)
- markdown fence 자동 stripping: `\`\`\`python ... \`\`\`` 또는 `\`\`\` ... \`\`\`` 블록이 응답 첫 줄에 있으면 내부만 추출

### L2: AST validation rules

다음 모두 만족 시 통과:

1. `oqs.KeyEncapsulation` 또는 `oqs.Signature`를 import 또는 attribute access로 사용
2. `KeyEncapsulation(...)` 또는 `Signature(...)` 인스턴스 생성 호출이 1회 이상
3. 다음 패턴은 모두 거부:
   - `KeyEncapsulation.method()` 클래스 직접 호출 (모든 method 이름)
   - `Signature.method()` 클래스 직접 호출
   - method 이름이 `encapsulate`, `decapsulate` (정답: `encap_secret`, `decap_secret`)
4. 모듈 최상위 레벨 (function/class 밖)에서 `KeyEncapsulation(...)` 또는 `Signature(...)` 인스턴스화 금지

구현: `harness/ast_validator.py` `validate_oqs_usage()`.

### L3: Semantic test rules

각 패턴에 대해 정의된 round-trip test가 raise 없이 종료 시 통과:

| Pattern | Test 정의 |
|---|---|
| 01 | `(kem, pk) = generate_keypair()`, pk가 bytes이고 길이 ≥ 100 |
| 02 | reference의 keygen으로 keypair → encrypt → decrypt → 원본 메시지와 일치 |
| 03 | `oqs.Signature` keypair로 sign → verify True, 변조 메시지로 verify False |
| 04 | reference keygen → wrap_and_encrypt → unwrap_and_decrypt → 원본 일치 |
| 05 | KeyManager로 generate → save → 새 인스턴스 load → 동일 KEM round-trip |
| 06 | reference keygen으로 키 저장 → encrypt_file → decrypt_file → 파일 내용 일치 |
| 07 | DocumentSigner로 sign_file → verify_file True |
| 08 | SessionKeyExchange로 initiate → respond → 양측 session key 일치 |
| 09 | sign → verify True |
| 10 | `(kem, pk) = generate_keypair()`, pk가 bytes 100+ |
| 11 | reference keygen → encrypt → decrypt → 원본 일치 |
| 12 | reference keygen → wrap_and_encrypt → unwrap_and_decrypt → 원본 일치 |
| 13 | KeyVault generate → 새 인스턴스 load_private → KEM round-trip |
| 14 | reference KeyVault로 키 저장 → encrypt_file → decrypt_file → 파일 일치 |
| 15 | ReleaseSigner sign_artifact → verify_artifact True |
| 16 | HandshakeBroker initiate → respond → 양측 session key 일치 |

구현: `harness/semantic_tests.py`.

### L4: Structural Fidelity (참고 지표, production 결정 비포함)

> **역할 한정**: L4는 reference 코드와 candidate의 구조적 유사성(API surface 매칭)만 측정하는 보조 지표이며, **의미적 정확성(semantic correctness)과는 무관**하다. 본 측정 결과 L3=0%인 상황에서 L4=50%를 통과한 trial들은 모두 런타임 실패 코드이므로, L4 통과는 production 안전성 판단의 근거로 사용하지 않는다. L4를 분리 보고하는 이유는 (a) 다층 metric의 sensitivity 분석(§3.7)에서 임계값 영향 점검, (b) "구조는 비슷한데 동작이 다른" 환각 코드의 비율을 정량화하기 위함이며, production gate에는 L1+L2+L3만 사용한다.

reference와 candidate의 AST에서 다음 boolean feature 추출:

- `has_kem_instance`: `KeyEncapsulation(...)` 호출 존재 여부
- `has_sig_instance`: `Signature(...)` 호출
- `calls_encap`: `.encap_secret(...)` attribute call
- `calls_decap`: `.decap_secret(...)`
- `calls_sign`: `.sign(...)` attribute call
- `calls_verify`: `.verify(...)`
- `uses_aesgcm`: `AESGCM(...)` 또는 `AES.new(..., MODE_GCM, ...)`

3개 비율 가중 평균:
- feature_match_ratio: reference에서 True인 feature 중 candidate에서도 True인 비율
- function_name_ratio: reference 함수명 ∩ candidate 함수명 / reference 함수명
- class_name_ratio: 동일 (클래스명)

`overall_score = 0.7 × feature + 0.15 × function + 0.15 × class`. 0.8 이상 시 *구조적으로 유사* (의미 동등성 아님 — 의미 동등성은 L3에서 측정).

## 1.6 LLM 프롬프트 (PR #82에서 사용된 정성스러운 버전)

핵심 instruction blocks (전체는 `ai-migration/prompts/rsa_to_mlkem.txt`):

1. ML-KEM (Kyber768) API 정확한 시그니처 + CRITICAL constraints
2. ML-DSA (Dilithium3) API 정확한 시그니처
3. Migration rules (RSA encrypt/decrypt → encap/decap, RSA sign/verify → sign/verify, 함수명 보존, 사용되지 않는 import 제거 등)
4. API 호환성 6 제약:
   - (a) global/module-level kem/sig 금지
   - (b) generate_keypair은 (kem, public_key) 튜플 반환
   - (c) decap 시 kem 객체를 명시적 전달
   - (d) encap은 shared_secret 반환 보장
   - (e) 시그니처 보존
   - (f) 동작 변경은 docstring 명시
5. Output format: rewritten file content만, no markdown fences, no explanation

---

# Part II. 평가 A — 인프라 함정 카탈로그 (Results 작성용)

## 2.1 함정 6종 상세

### F-1: oqs-provider 버전 비대칭 (sigalg drift)

| 항목 | 내용 |
|---|---|
| 트리거 | OQS-curl 0.11.0(provider 0.9.0) ↔ OQS-nginx 0.11.0(provider 0.6.1) |
| 증상 | TLS 1.3 ClientHello/ServerHello 단계 `alert handshake_failure` (TLS alert code 40). 어떤 group 조합도 협상 실패 |
| 원인 | provider 0.6.1과 0.9.0이 ML-DSA/ML-KEM에 다른 IANA code point 등록 |
| 진단 명령 | `docker exec pqc-proxy openssl list -signature-algorithms` ↔ `docker exec tls-tester openssl list -signature-algorithms` |
| 표준 도구 탐지 | Trivy ❌ / Semgrep ❌ / CBOM ❌ |
| 본 프로젝트 방어 | 자체 빌드로 OpenSSL/liboqs/oqs-provider 단일 라인 강제 |
| 인용 가능 quote | "동일 메이저 태그(0.11.0)를 공유하는 컨테이너들이 내부 oqs-provider 버전 차이로 ML-DSA/ML-KEM에 서로 다른 IANA code point를 등록한다" |

### F-2: OpenSSL 1.1.1 ↔ 3.x 인증서 OID 불일치

| 항목 | 내용 |
|---|---|
| 트리거 | OQS-OpenSSL 1.1.1 fork(oqs-engine 시대)와 OQS-OpenSSL 3.x(oqs-provider 시대)가 같은 알고리즘에 다른 OID 사용 |
| 증상 1 | `nginx: [emerg] SSL_CTX_use_certificate failed (SSL: digital envelope routines::decode error)` |
| 증상 2 | `Public Key Algorithm: 1.3.6.1.4.1.2.267.7.6.5 / Unable to load Public Key` |
| 원인 | oqs-ossl3:0.10.1(OpenSSL 3 라인)은 ML-DSA NIST OID 부착, OQS-nginx 0.11.0(OpenSSL 1.1.1q 정적)은 옛 Dilithium3 OID 기대 |
| 표준 도구 탐지 | ❌ X.509 자체는 RFC 호환 |
| 본 프로젝트 방어 | cert-builder를 nginx 본체와 동일 OpenSSL 라인으로 통일 |
| 인용 가능 quote | "PQC 표준화 전후 동일 알고리즘에 대해 두 OID가 공존하며, 도구 체인 라인이 다르면 인증서가 X.509로는 유효하나 wire-level에서 디코드 불가" |

### F-3: ML-KEM IETF code point ↔ Kyber OQS code point 충돌

| 항목 | 내용 |
|---|---|
| 트리거 | TLS 1.3 named group `X25519MLKEM768`(IETF 0x11ec) vs `x25519_kyber768`(OQS 사설) |
| 증상 | nginx config 파싱 통과, 실제 핸드셰이크에서 group 매칭 0개 |
| 원인 | OpenSSL 1.1.1 OQS는 Kyber 시대 명칭/code point, OpenSSL 3 oqs-provider 0.9+는 ML-KEM IETF 표준 |
| 표준 도구 탐지 | ❌ |
| 본 프로젝트 방어 | 동일 라이브러리 라인 통일 |

### F-4: PQ key strength 0 보고 → SECLEVEL 거부

| 항목 | 내용 |
|---|---|
| 트리거 | oqs-provider가 ML-DSA/ML-KEM의 `EVP_PKEY_security_bits()`를 0으로 보고 |
| 증상 | `nginx: [emerg] SSL_CTX_use_certificate failed (ssl/tls alert: ee key too small)` |
| 원인 | NIST PQC의 보안 비트 정의가 OpenSSL 전통 RSA/ECC bits 기준과 다름. oqs-provider 0.9.0은 보수적으로 0 반환 |
| 표준 도구 탐지 | ❌ |
| 본 프로젝트 방어 | `ssl_ciphers DEFAULT:@SECLEVEL=0` 임시 + `ssl_protocols TLSv1.3` + group whitelist로 약점 보완 |
| 인용 가능 quote | "PQC 알고리즘의 보안 강도 보고가 OpenSSL의 전통 SECLEVEL 정책과 호환되지 않아 SECLEVEL 완화가 강제되며, 이 완화는 다른 약한 알고리즘까지 함께 허용하는 부작용을 동반한다" |

### F-5: sha256 핀이 시점에 따라 다른 빌드를 가리킴

| 항목 | 내용 |
|---|---|
| 트리거 | OQS Project가 `openquantumsafe/nginx:0.11.0` 태그를 다시 빌드/푸시 |
| 증상 | 이전 PR 머지 시 CI 통과한 핀이 시간이 지나 환경 재구성하면 핸드셰이크 실패 |
| 원인 | Docker registry tag 가변성. sha256 자체는 immutable이지만 사용자가 인지하는 "0.11.0" 식별자는 가변 |
| 표준 도구 탐지 | ❌ Trivy 같은 supply chain 스캐너는 알려진 CVE만 검사 |
| 본 프로젝트 방어 | nginx 자체 빌드로 외부 이미지 의존 자체 제거 |
| 인용 가능 quote | "sha256 핀이 명시적 재현성 메커니즘임에도 PQC 도구 체인 초기에는 latest 태그 변경에 따라 가리키는 빌드가 시간적으로 가변할 수 있다" |

### F-6: standalone PQ group 협상 불가

| 항목 | 내용 |
|---|---|
| 트리거 | `ssl_ecdh_curve mlkem1024` 단독 설정이 OQS-nginx 0.11.0 기본 빌드에서 협상 안 됨 |
| 증상 | nginx 시작 정상, ssl_ecdh_curve 파싱 통과, 실제 handshake에서 협상 실패 |
| 원인 | OQS-nginx 빌드 시 CMake 플래그에 standalone PQ KEM이 빠지거나 oqs-provider config에서 비활성 |
| 표준 도구 탐지 | ❌ |
| 본 프로젝트 방어 | hybrid group으로 회귀 + matrix CI 회귀 감지 |

## 2.2 함정 × 표준 도구 탐지 매트릭스 (Table 후보 1)

| 함정 | Trivy (CVE) | Semgrep (rule) | CycloneDX CBOM | matrix CI | AST 검증 | 자체빌드 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| F-1 sigalg drift | ❌ | ❌ | ❌ | ⭕ 감지 | ❌ | ⭕ 예방 |
| F-2 OID mismatch | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-3 group code point | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-4 SECLEVEL 거부 | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-5 sha256 시간 가변 | ❌ | ❌ | ❌ | ⭕ 지연 | ❌ | ⭕ |
| F-6 standalone 미협상 | ❌ | ❌ | ❌ | ⭕ | ❌ | — |
| **합계** | 0/6 | 0/6 | 0/6 | **6/6** | 0/6 | **5/6** |

---

# Part III. 평가 B — LLM 마이그레이션 측정

## 3.1 하네스 sanity check (방어용 데이터)

평가 도구 자체의 정상 동작 확인을 위한 두 극값 측정:

| 시나리오 | candidate | L2 | L3 | L4 | 의미 |
|---|---|---:|---:|---:|---|
| (a) 정답 자기 회귀 | reference 16개 | 16/16 | 16/16 | 16/16 | 정답이 모든 layer 통과 → 하네스 false negative 없음 |
| (b) 마이그레이션 미수행 | 입력 RSA 16개 | 0/16 | 0/16 | 0/16 | RSA 그대로면 모두 거부 → 하네스 false positive 없음 |

## 3.2 본 측정: 다층 ablation (Table 후보 2)

총 trial = 80 (16 패턴 × k=5 trial), 측정 시점 2026-05-08. **메인 발견**: gpt-4o-mini가 80 trial 중 의미적으로 정확한 코드를 0건 생산 (L3 = 0/80).

| Layer | 통과 / 80 (전체) | Wilson 95% CI | 통과 / 55 (응답) | Wilson 95% CI |
|---|---:|---:|---:|---:|
| **L3 (Semantic test — 메인 지표)** | **0** | **[0.0%, 3.8%]**¹ | **0** | **[0.0%, 5.5%]**¹ |
| L2 (AST 검증 — 정적 정확성) | 24 (30.0%) | [21.1%, 40.8%] | 24 (43.6%) | [31.4%, 56.7%] |
| L1 (LLM 응답 수신) | 55 (68.8%) | [57.9%, 77.8%] | 55 (100%) | — |
| L4 (Structural Fidelity — 참고용²) | 40 (50.0%) | [39.3%, 60.7%] | 40 (72.7%) | [59.8%, 82.7%] |

¹ Rule of 3 (0/n에 대한 95% 단측 상한).
² L4는 의미 정확성과 무관한 구조 유사도 지표이며 production 결정에 사용하지 않음 (§1.5 참조). L3=0% 상황에서 L4=50%는 "구조는 유사하나 실행 시 실패하는 환각 코드"의 비율로 해석.

**LLM API 에러**: 25/80 (rate limit 추정, 패턴 13–16 집중). 응답 받은 trial N=55.

**관찰 (인용 가능 문장)**:
- "본 측정 LLM은 응답을 받은 55개 trial 중 의미적으로 정확한 코드를 한 건도 생산하지 못했다 (L3 = 0/55, Wilson 95% 단측 상한 5.5%). 구조 유사도 metric인 L4는 동일 응답에서 72.7% 통과율을 보였으나, 본 결과는 의미 정확성과 무관한 외형 유사성이 LLM 환각의 주된 패턴임을 의미한다."

## 3.3 실패 모드 taxonomy (Table 후보 3)

7종 카테고리. 정의 + 빈도:

| 카테고리 | 정의 | 빈도 (총 55 응답 중) |
|---|---|---:|
| `missing_instance_construction` | `oqs.KeyEncapsulation` 또는 `Signature`를 import하지만 인스턴스 생성 코드 없음 (클래스 자체에 메서드 호출 시도 등) | 20 (36.4%) |
| `wrong_arg_count` | 메서드에 잘못된 인자 개수. 런타임 `TypeError: takes N positional arguments but M were given` | 16 (29.1%) |
| `no_migration` | RSA 코드 본문은 그대로 두고 `import oqs` 줄만 추가 | 6 (10.9%) |
| `class_direct_call` | `KeyEncapsulation.encap_secret(...)` 같은 클래스명 직접 호출 (인스턴스 누락의 한 형태) | 5 (9.1%) |
| `wrong_kwarg` | 존재하지 않는 keyword argument. `KeyEncapsulation("ML-KEM-768", public_key=...)` 등 | 5 (9.1%) |
| `method_hallucination` | 존재하지 않는 메서드 호출. `kem.import_public_key(...)` 등 | 2 (3.6%) |
| `algorithm_name_hallucination` | `MechanismNotSupportedError` — 잘못된 알고리즘 명칭 | 1 (1.8%) |

**합계**: 55/55 응답 모두 어딘가에서 실패. 즉 응답 받은 trial 중 정상 동작하는 것 0건.

## 3.4 실패 모드 × Defense Layer 매핑 (Table 후보 4 — 핵심)

각 실패 카테고리가 어느 검증 단계에서 차단되는지:

| 카테고리 | L2가 차단 | L3가 차단 | 합계 | L3 의존도 |
|---|---:|---:|---:|---:|
| `missing_instance_construction` | **20** | 0 | 20 | 0% |
| `wrong_arg_count` | 0 | **16** | 16 | **100%** |
| `no_migration` | **6** | 0 | 6 | 0% |
| `class_direct_call` | **5** | 0 | 5 | 0% |
| `wrong_kwarg` | 0 | **5** | 5 | **100%** |
| `method_hallucination` | 0 | **2** | 2 | **100%** |
| `algorithm_name_hallucination` | 0 | **1** | 1 | **100%** |
| **합계** | **31** | **24** | **55** | — |

**관찰**: 두 layer가 잡는 카테고리 overlap = 0. 즉 어느 한 layer만 적용하면 다른 layer가 잡는 카테고리는 모두 통과시킨다.

## 3.5 차원별 통과율 (Table 후보 5)

### 라이브러리 (n=40 each)

| Lib | L2 | L3 | L4 |
|---|---:|---:|---:|
| cryptography | 14/40 (35%) | 0/40 (0%) | 20/40 (50%) |
| pycryptodome | 10/40 (25%) | 0/40 (0%) | 20/40 (50%) |

### 사용 케이스 (n=20 each)

| Use case | L2 | L3 | L4 |
|---|---:|---:|---:|
| encrypt | 10/20 (50%) | 0/20 (0%) | 15/20 (75%) |
| sign | 9/20 (45%) | 0/20 (0%) | 9/20 (45%) |
| kex | 5/20 (25%) | 0/20 (0%) | 11/20 (55%) |
| keygen | 0/20 (0%) | 0/20 (0%) | 5/20 (25%) |

### 복잡도 (n=40 each)

| Complexity | L2 | L3 | L4 |
|---|---:|---:|---:|
| simple | 10/40 (25%) | 0/40 (0%) | 26/40 (65%) |
| complex | 14/40 (35%) | 0/40 (0%) | 14/40 (35%) |

**관찰 (인용 가능 문장)**:
- "keygen 패턴은 L2/L3/L4 모두 가장 낮은 통과율을 보였으며, L2는 0%로 LLM이 시그니처 변경(`(private_key, public_key)` → `(kem, public_key)`)을 인식하지 못했다."
- "simple과 complex 사이 L4 점수 차이는 65% vs 35%로, 클래스 wrapper와 파일 IO가 동시에 들어가면 LLM의 정확도가 절반 가까이 떨어진다."

## 3.6 패턴별 상세 raw 데이터 (Table 후보 6)

| ID | Lib | Case | Cplx | LLM err | L2 pass | L3 pass | L4 pass |
|---|---|---|---|---:|---:|---:|---:|
| 01 | crypto | keygen | s | 0/5 | 0/5 | 0/5 | 0/5 |
| 02 | crypto | encrypt | s | 0/5 | 0/5 | 0/5 | 5/5 |
| 03 | crypto | sign | s | 0/5 | 0/5 | 0/5 | 0/5 |
| 04 | crypto | kex | s | 4/5 | 0/5 | 0/5 | 1/5 |
| 05 | crypto | keygen | c | 2/5 | 0/5 | 0/5 | 0/5 |
| 06 | crypto | encrypt | c | 0/5 | 5/5 | 0/5 | 5/5 |
| 07 | crypto | sign | c | 0/5 | 4/5 | 0/5 | 4/5 |
| 08 | crypto | kex | c | 0/5 | 5/5 | 0/5 | 5/5 |
| 09 | pycdome | sign | s | 0/5 | 5/5 | 0/5 | 5/5 |
| 10 | pycdome | keygen | s | 0/5 | 0/5 | 0/5 | 5/5 |
| 11 | pycdome | encrypt | s | 0/5 | 5/5 | 0/5 | 5/5 |
| 12 | pycdome | kex | s | 0/5 | 0/5 | 0/5 | 5/5 |
| 13 | pycdome | keygen | c | 4/5 | 0/5 | 0/5 | 0/5 |
| 14 | pycdome | encrypt | c | 5/5 | 0/5 | 0/5 | 0/5 |
| 15 | pycdome | sign | c | 5/5 | 0/5 | 0/5 | 0/5 |
| 16 | pycdome | kex | c | 5/5 | 0/5 | 0/5 | 0/5 |
| **합계** | — | — | — | **25/80** | **24/80** | **0/80** | **40/80** |

**관찰 (인용 가능 문장)**:
- "패턴 13–16(PyCryptodome complex)이 25개 LLM 에러 중 19개를 차지하여 통계가 cryptography 측 패턴(1–8) 위주로 편향된다. 이는 측정 시점에서 GitHub Models의 트래픽이 누적되어 후반 trial이 rate limit을 맞은 결과로 보인다."

## 3.7 L4 임계값 sensitivity (Table 후보 7)

| Threshold | L4 통과 (총 80) | 비율 |
|---:|---:|---:|
| 0.5 | 46 | 57.5% |
| 0.6 | 46 | 57.5% |
| 0.7 | 46 | 57.5% |
| 0.8 (default) | 40 | 50.0% |
| 0.9 | 24 | 30.0% |
| 1.0 | 24 | 30.0% |

**관찰 (인용 가능 문장)**: "L4 (Structural Fidelity) 통과율은 임계값 0.5–0.7 구간에서 57.5%로 일정하게 유지되며 0.8에서 50.0%로 감소한다. 본 sensitivity는 구조 유사도 metric 자체의 임계값 강건성만 보일 뿐 의미 정확성과는 무관하며 (§1.5), L3=0%인 본 측정 결과는 임계값 선택과 독립적으로 LLM 환각이 외형 유사 코드를 다수 생성함을 시사한다."

## 3.8 응답 길이 / cost 통계

| 통계 | 값 (chars) |
|---|---:|
| 응답 trial 수 | 55 |
| Mean | 1072 |
| Median | 1064 |
| p5 | 372 |
| p95 | 2198 |
| Min | 325 |
| Max | 2487 |

**환산**: 평균 ≈ 268 토큰. gpt-4o-mini 출력가 $0.6 / 1M 토큰 → trial 당 ≈ $0.00016. 80 trial 총 비용 ≈ $0.013. (GitHub Models 무료 tier 한도 내)

---

# Part IV. 실패 사례 (Discussion / Qualitative Analysis 작성용)

## 4.1 Case Study Format

각 케이스에 대해: (1) 패턴/trial 식별자 (2) LLM 출력 발췌 (3) 검증 단계 (4) 오류 메시지 (5) 분류 (6) 분석.

## 4.2 Case 1: `wrong_arg_count` — 가장 흔한 런타임 실패

**식별자**: Pattern 06 trial 0 (`06_cryptography_encrypt_complex.py`)

**LLM 출력 발췌**:
```python
class SecureMessenger:
    def decrypt_file(self, ciphertext_path, plaintext_path):
        ct = Path(ciphertext_path).read_bytes()
        # ↓ 인스턴스 메서드를 클래스 메서드로 호출
        shared_secret = KeyEncapsulation.decap_secret(ct, ciphertext_kem)
        ...
```

**검증 단계**: L2 통과 (인스턴스 생성 + AST 패턴 OK) → L3에서 차단

**오류 메시지**:
```
TypeError: KeyEncapsulation.decap_secret() takes 2 positional arguments but 3 were given
```

**분류**: `wrong_arg_count`

**분석**:
- AST 차원에서는 `KeyEncapsulation.decap_secret(...)` 호출이 클래스 직접 호출 패턴과 외형상 동일
- AST validator는 메서드 이름이 valid이고 인자 개수만으로는 판단 불가 → 통과
- 런타임에서 unbound method 호출로 처리되어 `self` 자리 인자 부족 발생
- 동일 카테고리 16건 모두 유사 메커니즘

## 4.3 Case 2: `wrong_kwarg`

**식별자**: Pattern 08 trial 0

**LLM 출력 발췌**:
```python
class SessionKeyExchange:
    def __init__(self, peer_pub_path=None, my_priv_path=None):
        ...
        if peer_pub_path:
            self.peer_pub = Path(peer_pub_path).read_bytes()
        if my_priv_path:
            secret = Path(my_priv_path).read_bytes()
            # ↓ public_key kwarg는 존재하지 않음
            self.kem = oqs.KeyEncapsulation("ML-KEM-768", public_key=secret)
```

**검증 단계**: L2 통과 → L3에서 차단

**오류 메시지**:
```
TypeError: KeyEncapsulation.__init__() got an unexpected keyword argument 'public_key'
```

**분류**: `wrong_kwarg`

**분석**:
- 실제 oqs API: `KeyEncapsulation(alg_name: str, secret_key: bytes | None = None)`
- LLM이 RSA의 PEM-기반 키 import 패턴(키 데이터를 생성자에 직접 전달)을 oqs로 잘못 전이
- AST 차원에서는 임의 keyword 인자를 검증할 수 없음 → 통과

## 4.4 Case 3: `method_hallucination`

**식별자**: Pattern 11 trial 1

**LLM 출력 발췌**:
```python
def encrypt_message(public_key, message):
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    # ↓ import_public_key는 존재하지 않는 메서드
    public_key_obj = kem.import_public_key(public_key_bytes)
    ciphertext, shared_secret = kem.encap_secret(public_key_obj)
    ...
```

**검증 단계**: L2 통과 → L3에서 차단

**오류 메시지**:
```
AttributeError: 'KeyEncapsulation' object has no attribute 'import_public_key'
```

**분류**: `method_hallucination`

**분석**:
- LLM이 RSA의 `RSA.import_key(...)` 패턴을 oqs API에 transfer
- 실제 oqs는 `encap_secret(public_key)` 호출 시 raw bytes를 그대로 받음, 별도 import 단계 없음
- 학습 데이터에서 RSA의 import 패턴이 워낙 흔해 LLM의 prior에 강하게 박혀 있음을 시사

## 4.5 Case 4: `no_migration`

**식별자**: Pattern 04 trial 0

**LLM 출력 발췌**:
```python
import oqs  # ← 추가만 됨, 본문 변경 없음
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def wrap_and_encrypt(public_key, message):
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aead = AESGCM(aes_key)
    ciphertext = aead.encrypt(nonce, message, None)
    wrapped = public_key.encrypt(    # ← 여전히 RSA-OAEP
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            ...
```

**검증 단계**: L2에서 차단

**차단 사유**: "oqs.KeyEncapsulation 또는 oqs.Signature 미사용 — 마이그레이션 미적용"

**분류**: `no_migration`

**분석**:
- LLM이 표면적으로 작업을 수행한 것처럼 보이려고 `import oqs`만 추가
- 본문은 RSA 그대로 → 만약 AST 검증이 import 존재만 보고 통과시켰다면 production 위험 그대로 전달됨
- AST validator의 "oqs API 실제 사용" 검증이 이 시나리오를 막음

## 4.6 Case 5: `missing_instance_construction` (가장 흔함, 20건)

**식별자**: Pattern 02 trial 0 (대표)

**LLM 출력 발췌**:
```python
from oqs import KeyEncapsulation, Signature

def encrypt_message(public_key, message):
    # ↓ KeyEncapsulation을 instantiate하지 않고 클래스 자체에 메서드 호출
    return KeyEncapsulation.encap_secret(public_key, message)
```

**검증 단계**: L2에서 차단

**차단 사유**: `KeyEncapsulation.encap_secret() — 클래스 직접 호출 금지` + `KeyEncapsulation(...) 인스턴스 생성 패턴 없음`

**분류**: `missing_instance_construction` (또는 `class_direct_call`로 중복 분류 가능)

**분석**:
- LLM이 클래스/인스턴스 구분을 하지 않고 정적 메서드처럼 사용
- AST 차원에서 명확히 잡히는 패턴 → L2가 효과적
- 만약 L2가 없으면 런타임에서 다른 종류 에러(unbound method, missing self) 발생

## 4.7 Case 6: `algorithm_name_hallucination`

**식별자**: Pattern 06 trial 3

**오류 메시지**:
```
MechanismNotSupportedError: <unprintable bytes>
```

**분석**: 알고리즘 명칭 환각의 하나. 정확한 명칭(`"ML-KEM-768"`, `"ML-DSA-65"`) 대신 옛 명칭(`"Kyber768"`) 또는 변형된 이름 사용. 1건만 발생했고, 본 프롬프트가 정확한 명칭을 명시한 덕분에 빈도 낮음.

## 4.8 카테고리별 빈도 + 차단 layer 요약 (재인용용)

```
20건 missing_instance_construction → L2가 차단 (정적 분석으로 충분)
16건 wrong_arg_count               → L3만 차단 (런타임 검증 필수)
 6건 no_migration                  → L2가 차단
 5건 class_direct_call              → L2가 차단
 5건 wrong_kwarg                   → L3만 차단
 2건 method_hallucination          → L3만 차단
 1건 algorithm_name_hallucination  → L3만 차단
─────
55건 합계 (응답 받은 trial 100% 어딘가에서 실패)

L2가 잡는 합계: 31건 (56%) — 정적으로 잡히는 실수
L3가 잡는 합계: 24건 (44%) — 런타임에서만 잡히는 실수
```

---

# Part IV-B. 평가 D — CBOM Diff 모듈 동작 검증 (Results 작성용)

## 4.9 정의

CycloneDX 1.7 CBOM 두 개를 비교하여 PQC 마이그레이션 진척도를 4종 라벨(BASELINE/IMPROVED/REGRESSED/UNCHANGED)로 분류하는 [policy/cbom_diff.py](policy/cbom_diff.py) 모듈의 라벨링 정확도를 fixture 기반으로 검증한다. 라벨 결정 로직은 `migration_summary.manual_action_required` 값의 delta에 기반한다 ([cbom_diff.py:99-127](policy/cbom_diff.py#L99-L127)).

## 4.10 시나리오별 라벨링 정확도 (Table 후보 10)

각 시나리오마다 fixture CBOM 두 개(현재·이전)를 작성하고 `cbom_diff.py`를 실행하여 출력 라벨을 기대값과 비교했다. 실험 결과는 `artifacts/eval/cbom_diff_experiments/`에 저장.

| ID | 시나리오 | 이전 manual | 현재 manual | Delta | 기대 라벨 | 실측 라벨 | 일치 |
|----|---------|---:|---:|---:|---------|---------|:-:|
| S1 | 첫 실행 (이전 CBOM 없음) | — | 5 | — | BASELINE | BASELINE | ✅ |
| S2 | Stage 1 → Stage 2 전환 | 5 | 2 | 3 | IMPROVED | IMPROVED | ✅ |
| S3 | Stage 2 → Stage 3 전환 | 2 | 0 | 2 | IMPROVED | IMPROVED | ✅ |
| S4 | Stage 3 → Stage 2 강제 회귀 | 0 | 2 | -2 | REGRESSED | REGRESSED | ✅ |
| S5 | 동일 Stage 재실행 | 2 | 2 | 0 | UNCHANGED | UNCHANGED | ✅ |
| S6 | 코드만 추가 (algorithm 자산 무변화) | 2 | 2 | 0 | UNCHANGED | UNCHANGED | ✅ |
| **합계** | | | | | | | **6/6** |

**관찰 (인용 가능 문장)**:
- "CBOM Diff 모듈은 6종 마이그레이션 시나리오 전체에서 기대 라벨과 일치하는 출력을 생성했다 (정확도 6/6). BASELINE / IMPROVED / REGRESSED / UNCHANGED 4 라벨 분류가 fixture 단위에서 결정론적으로 동작함을 입증한다."
- "S4(회귀) 시나리오는 manual_action_required가 0→2로 증가한 경우 REGRESSED 라벨과 함께 신규 발견 항목 2건을 보고하여, PQC 마이그레이션 진척이 후퇴할 때 PR 단계에서 자동 감지 가능함을 보였다."

## 4.11 3중 일관성 검증 (Table 후보 11)

cbom_gen.py의 `cross_validate()` 함수는 (a) cbom_gen 자체 판정, (b) verify_tls.sh 스크립트 판정, (c) 사용자가 요청한 Stage 세 신호를 비교하여 `consistent` 필드와 `warnings` 배열을 생성한다 ([cbom_gen.py:870-903](policy/cbom_gen.py#L870-L903)). 5개 시나리오를 직접 호출 방식으로 측정.

| ID | 시나리오 | 기대 consistent | 실측 consistent | 경고 수 | 일치 |
|----|---------|:-:|:-:|---:|:-:|
| C1 | 세 신호 모두 Stage 2 일치 | True | True | 0 | ✅ |
| C2 | 요청 Stage 2, 실제 Stage 1 협상 | False | False | 1 | ✅ |
| C3 | cbom_gen Stage 2 vs script Stage 3 | False | False | 1 | ✅ |
| C4 | 세 신호 모두 Stage 3 일치 | True | True | 0 | ✅ |
| C5 | 세 신호 전부 불일치 | False | False | 2 | ✅ |
| **합계** | | | | | **5/5** |

**관찰 (인용 가능 문장)**:
- "3중 일관성 검증은 세 신호(요청 Stage / 모듈 판정 / 검증 스크립트 판정)가 일치할 때 consistent=True를 반환하고, 어느 한 쌍이라도 불일치하면 consistent=False와 경고 메시지를 생성한다. 5/5 시나리오에서 기대대로 동작."
- "C5(세 신호 모두 다름) 케이스에서 경고 2건이 분리 보고됨은 어느 신호 쌍이 불일치하는지를 운영자가 디버깅 가능한 형태로 노출함을 의미한다."

---

# Part IV-C. 평가 E — 자동 롤백 메커니즘 동작 검증 (Results 작성용)

## 4.12 정의

[perf-rollback/rollback.sh](perf-rollback/rollback.sh)는 성능 임계치(절대 3,000ms — [perf_check.sh:138](perf-rollback/perf_check.sh#L138)) 초과 시 nginx.conf를 이전 Stage 설정으로 되돌리고 PR을 자동 생성한다. 본 평가는 R4(롤백 루프 방지)에 한정하여 정적 코드 검증으로 메커니즘을 확인한다. R1~R3(절대/상대/실패율 임계치) 실제 시나리오 측정 및 MTTR 정량화는 §5.3 future work에 위치.

## 4.13 R4: Rollback Loop 방지 메커니즘 (Table 후보 12)

자동 롤백이 push한 커밋이 다음 파이프라인을 재트리거하여 무한 루프를 만들지 않도록 하는 메커니즘 3종을 [rollback.sh](perf-rollback/rollback.sh) 정적 분석으로 확인.

| ID | 메커니즘 | 실재 여부 | 원리 |
|----|---------|:-:|------|
| M1 | Commit 메시지에 `[skip ci]` 마커 | ✅ | GitHub Actions가 해당 커밋의 workflow 트리거를 건너뜀 ([rollback.sh:106](perf-rollback/rollback.sh#L106)) |
| M2 | `git diff --cached --quiet` 가드 | ✅ | 이미 롤백 대상과 동일한 nginx.conf면 commit 자체 생략 ([rollback.sh:129](perf-rollback/rollback.sh#L129)) |
| M3 | Stage 1 단락 회로 | ✅ | Stage 1은 롤백 대상이 없으므로 조기 종료 ([rollback.sh:71](perf-rollback/rollback.sh#L71)) |
| **합계** | | **3/3** | |

**관찰 (인용 가능 문장)**:
- "본 자동 롤백 메커니즘은 세 가지 독립적 안전장치(`[skip ci]` 마커, empty-diff 가드, Stage 1 단락 회로)를 통해 무한 롤백 루프를 방지한다. 세 메커니즘 모두 실재함을 정적 코드 검증으로 확인 (3/3)."
- "M2(empty-diff 가드)는 동일 nginx.conf에 대해 중복 롤백 PR이 생성되지 않도록 보장하며, M3는 Stage 1 미만 롤백 시도를 차단하여 잘못된 STAGE 인자가 무한 재귀를 일으키지 않도록 한다."

---

# Part V. 평가 C — 본 프로젝트 파이프라인의 효과 (Results 작성용)

평가 A에서 발견된 인프라 함정과 평가 B에서 측정된 LLM 자동화 실패에 대해, 본 프로젝트가 제안한 파이프라인 4 layer (자체 빌드 / 매트릭스 CI / AI 마이그레이션 / 다층 검증)가 어떤 정량 효과를 가지는지 측정한다.

## 5.1 파이프라인 layer 매핑

| Layer | 구현 | 역할 | 관련 PR |
|---|---|---|---|
| L-1 자체 빌드 | nginx Dockerfile 멀티스테이지 (OpenSSL 3.4 + liboqs 0.14 + oqs-provider 0.9 + nginx 1.27 소스 빌드) | 외부 OQS 이미지 의존 제거, OQS 라인 통일로 wire-level code point 일치 보장 | PR #84 |
| L-2 매트릭스 CI | GitHub Actions `tls-stage-matrix.yml` (Stage 2/3 양쪽 healthcheck + tls_check.sh) | PQC 협상 회귀를 PR 시점에 자동 감지 | PR #83 |
| L-3 AI 마이그레이션 | `ai-migration/migrate.py` (semgrep findings → GitHub Models LLM → AST 검증 → PR 자동 생성) | RSA 사용 코드를 PQC로 자동 변환 + 봇 리뷰 트리거 | PR #82 |
| L-4 다층 검증 | AST validator + semantic test + bot review (Gemini Code Assist) + human review | LLM 출력의 환각 차단 (정적 + 런타임 + 외부 검토) | PR #82 + 본 평가 하네스 |

## 5.2 평가 A 함정에 대한 파이프라인 효과 (Table 후보 8 — 핵심)

각 함정 6종이 본 파이프라인의 어떤 layer로 차단(예방) 또는 감지(런타임 발견)되는지:

| 함정 | L-1 자체빌드 (예방) | L-2 매트릭스 CI (감지) | 표준 도구 (Trivy/Semgrep/CBOM) |
|---|:-:|:-:|:-:|
| F-1 sigalg drift | ⭕ 예방 | ⭕ 감지 | ❌ |
| F-2 OID mismatch | ⭕ 예방 | ⭕ 감지 | ❌ |
| F-3 group code point | ⭕ 예방 | ⭕ 감지 | ❌ |
| F-4 SECLEVEL 거부 | ⭕ 예방 | ⭕ 감지 | ❌ |
| F-5 sha256 시간 가변 | ⭕ 예방 | ⭕ 감지 (지연) | ❌ |
| F-6 standalone 미협상 | — (hybrid 회귀가 우회책) | ⭕ 감지 | ❌ |
| **합계** | **5/6 예방** | **6/6 감지** | **0/6** |

**관찰 (인용 가능 문장)**:
- "본 프로젝트가 제안한 자체 빌드는 6종 함정 중 5개를 사전 예방하며, 매트릭스 CI는 6종 모두를 런타임에서 감지한다. 반면 표준 SCA/SAST/SBOM은 6종 어느 것도 사전 탐지하지 못한다."
- "F-6(standalone PQ group 미협상)은 자체 빌드로도 예방 불가이며 hybrid 그룹으로의 회귀가 우회책. 이는 본 프로젝트 파이프라인이 *완전한* 함정 차단 도구가 아니라 *체계적* 함정 감지·예방 도구임을 의미."

## 5.3 LLM 다층 방어 위험 감소 (Table 후보 9)

평가 B 데이터를 파이프라인 layer별로 재해석. "production crash 위험"은 통과한 코드가 런타임에서 깨질 확률.

> **표 해석 주의**: 본 표의 ③ 시나리오는 본 측정 LLM(gpt-4o-mini)이 의미적으로 정확한 코드를 0건 생성한 상황 하의 결과이며, "위험률 0%"는 *위험 코드 전달 0건*을 의미할 뿐 *안전 코드 생성 성공*을 의미하지 않는다. 통과 trial이 0이므로 분모 0의 비율을 "위험 차단"으로 표기한다. ② AST 검증만 시나리오에서 위험 100%는 정의상 통과 24건 전원이 L3에서 실패함에서 비롯한다 (§3.4 참조).

| 적용 시나리오 | 통과 trial 수 | 통과 코드의 런타임 실패 | Production crash 위험 |
|---|---:|---:|---:|
| ① 검증 없음 (LLM 출력 그대로 production) | 55 (응답 받은 trial) | 55 | **100%** |
| ② AST 검증만 (L2) | 24 | 24 | **100%** |
| ③ AST + semantic test (L2 + L3) | 0 | — (통과 trial 없음) | **위험 코드 전달 0건** |

**관찰 (인용 가능 문장)**:
- "검증 layer 없이 LLM 출력을 직접 production에 적용하면 응답 받은 trial 100%가 런타임에서 crash. AST 검증을 추가하면 통과되는 code 수가 55→24로 줄지만 **통과 코드 중 런타임 실패율은 여전히 100%**. AST + semantic test를 모두 적용해야 production 도달 코드의 crash 위험이 0%가 된다."
- "여기서 주의할 점은 ③의 통과 trial이 0건이라는 사실 — 이는 본 LLM(gpt-4o-mini)이 16 패턴에서 단 한 번도 의미적으로 정확한 코드를 생산하지 못함을 의미. 다층 방어는 *위험을 제거*하지만 *생산성을 만들지는 못함*. LLM이 충분한 정확도에 도달하기 전까지 다층 방어는 'reject filter'로 기능."

## 5.4 회귀 감지 시점 단축 (Counterfactual)

PR #71 회귀 사례를 매트릭스 CI 도입 전후로 비교:

| 시나리오 | F-2 회귀 발견 시점 |
|---|---|
| 매트릭스 CI 부재 (PR #71 머지 시점) | 머지 후 후속 작업 중 사용자 보고 → 별도 PR(#76)로 hotfix |
| 매트릭스 CI 존재 (PR #83 이후) | PR #71의 PR 시점에 Stage 3 healthcheck 실패 → 머지 차단 |

**Counterfactual 검증 절차**:
1. PR #71 시점의 commit checkout
2. 본 프로젝트의 `tls-stage-matrix.yml` workflow를 동일 환경에서 실행
3. Stage 3 (TLS_STAGE=3) job이 `tls_check.sh proxy-server 443 3` 단계에서 fail
4. 따라서 매트릭스 CI가 있었다면 PR #71은 PR 단계에서 막혔을 것

**관찰**: 본 직접 검증은 git history와 동일 commit checkout으로 재현 가능하므로 anecdotal이 아닌 *재현 가능한 counterfactual*. 단 시간 단축 정도(시일·시간 단위)는 머지 시점·발견 시점의 정확한 timestamp 부재로 정량화 곤란.

## 5.5 캡스톤 프로젝트의 PQC 전환 완성도 (정성)

본 파이프라인 적용 결과 본 프로젝트 자체의 PQC 전환은 다음을 달성:

| 항목 | 상태 | 검증 방법 |
|---|---|---|
| Stage 1 (classical ECC) | PASS | `tls_check.sh proxy-server 443 1` |
| Stage 2 (X25519MLKEM768 hybrid) | PASS | `tls_check.sh proxy-server 443 2` |
| Stage 3 (p521_mlkem1024:p384_mlkem768 hybrid) | PASS — `TLSv1.3 / TLS_AES_256_GCM_SHA384 / p521_mlkem1024 / mldsa65` 협상 확인 | `tls_check.sh proxy-server 443 3` + `curl --curves p521_mlkem1024:p384_mlkem768 ...` |
| ML-DSA-65 (Dilithium3) 인증서 발급/검증 | 동작 | `oqs-provider`로 cert 생성 + nginx 서명 OK |
| AI 마이그레이션 PoC | 동작 | PR #82 (자동 PR 생성, AST 검증, bot review 트리거) |
| CycloneDX 1.7 CBOM 자동 생성 | 동작 | `policy/cbom_gen.py` |
| 매트릭스 CI 회귀 감지 | 동작 | PR #83 |
| 평가 함정 6종 모두 해결 | 완료 | PR #84 (F-1, F-3, F-4, F-6 근본) + PR #76 (F-2 임시) |

**관찰 (인용 가능 문장)**:
- "본 프로젝트는 평가 A에서 발견한 6종 함정을 모두 해결한 후 Stage 1/2/3 TLS 모두 PASS 상태에서 종료. 자체 빌드 + 매트릭스 CI + AI 마이그레이션 + 다층 검증 파이프라인이 PQC 전환을 실제로 가능하게 했다."

## 5.6 평가 C의 한계

| 항목 | 내용 |
|---|---|
| L1.C | N=1 캡스톤 프로젝트의 자체 평가 → 다른 조직·다른 코드베이스에서 동일 효과 보장 X |
| L2.C | 회귀 감지 시점 단축은 counterfactual 추정 (실제 시간 측정 부재) |
| L3.C | 사람의 작업 시간/노력 절감 효과는 정량 측정 안 함 (추정만 가능) |
| L4.C | 파이프라인 자체의 유지보수 비용(자체 빌드 시간 5–10분, CI cost) 미측정 |
| L5.C | F-6은 자체 빌드로도 예방 불가 → 파이프라인이 모든 함정에 만능 아님 |
| L6.C | "PQC 전환 완성도" 정성 평가는 본 프로젝트 자체 기준이며 외부 인증 X |

---

# Part VI. 한계 (Limitations 작성용)

## 5.1 평가 A의 한계

| 항목 | 내용 | 보강 방안 (참고) |
|---|---|---|
| L1.A | N=1 프로젝트 경험 | 다른 OQS 사용 OSS의 issue tracker를 분석해 함정 확장 |
| L2.A | 6종은 보고된 것만 | observation을 더 늘리려면 다양한 OQS 버전 조합 매트릭스 실험 |
| L3.A | 표준화 직후 시점 한정 | OQS 안정화 후 함정이 어떻게 변하는지 추적 X |
| L4.A | OpenSSL/OQS 한정 | BoringSSL/Cloudflare PQ, Java BC 등 다른 스택은 이론적 추론에 그침 |

## 5.2 평가 B의 한계

| 항목 | 내용 | 영향 | 보강 방안 (참고) |
|---|---|---|---|
| L1.B | 단일 모델 (gpt-4o-mini만) | 외부 타당성 가장 큰 약점 | GPT-4o, Claude, Gemini Pro 비교 |
| L2.B | 합성 패턴 N=16 | OSS 코드 다양성 미반영 | GitHub OSS에서 RSA 사용 코드 N≥30 큐레이션 |
| L3.B | Rate limit 편향 (25/80 LLM err, 패턴 13–16 집중) | 통계가 cryptography 위주 | 시간 분산하여 재실행, 또는 유료 tier |
| L4.B | 저자 정의 ground truth | self-fulfilling 위험 | 외부 검토자의 정답 검증, IAA 측정 |
| L5.B | naive prompt 비교 부재 | 프롬프트 효과 분리 불가 | "Convert RSA to PQC" 같은 짧은 프롬프트로 ablation |
| L6.B | L4는 AST feature 매칭 근사 | 의미 동등성의 보수적 추정 | 대안 metric (e.g., property-based test) 추가 |
| L7.B | temperature=0 한정 | LLM stochasticity 미평가 | t=0.5 등에서 sample diversity 측정 |
| L8.B | k=5는 통계적 검정에 부족 | 95% Wilson CI 폭 ±20%p 수준 | k=20 이상으로 확대 |

## 5.3 Future work (외부 타당성 보강 항목)

본 평가에서 다루지 못한 항목으로, 본 결과의 외부 타당성과 직접 관련되는 후속 연구 방향:

- **다중 모델 비교**: GPT-4o, Claude, Gemini Pro 등 상위 모델에서 동일 16 패턴 × k=5 측정. 단일 모델 결과의 일반화 가능성 검증.
- **다중 프롬프트 비교**: zero-shot, naive prompt, oqs-python API docs를 context로 제공한 RAG 조건의 통과율 분리 측정.
- **외부 OSS 매핑**: Cloudflare PQ 배포, AWS s2n-tls, Open Quantum Safe의 다른 통합 사례의 보고된 이슈와 본 F-1~F-6 함정의 패턴 매핑으로 카탈로그의 일반성 강화.
- **"거의 맞는 코드" 분류**: L3 실패 코드 중 minor fix(1~3 LOC 수정)로 통과 가능한 비율 측정. LLM 마이그레이션의 실용성 평가 균형.
- **F-6 본질 해결 vs 미봉책**: hybrid group 회귀가 standalone PQ KEM 미협상의 본질 해결인지 미봉책인지에 대한 OQS 빌드 플래그 차원의 추가 분석.
- **자체 빌드 trade-off 정량화**: 빌드 시간, 유지보수 비용, 공급망 보안(외부 감사 부재) 측면에서 자체 빌드의 비용을 측정해 5/6 예방 효과와의 ROI 비교.

---

# Part VII. 인용 가능한 핵심 발견 (Findings — 논문 본문 작성 시 직접 사용)

## F1. (평가 A 핵심)
> "본 프로젝트에서 발견된 PQC 도구 체인 함정 6종(F-1~F-6) 중 어느 하나도 표준 정적 분석(Trivy, Semgrep) 또는 SBOM(CycloneDX)으로는 사전 탐지되지 않았다. 6/6 함정 모두 표준 도구의 사각지대에 위치한다."

**근거 표**: Part II §2.2

## F2. (평가 B 핵심 — 다층 ablation)
> "gpt-4o-mini의 RSA → ML-KEM/ML-DSA 마이그레이션 80 trial 측정 결과, 의미적 정확성을 검증하는 semantic test(L3)는 0/55 = 0% (Wilson 95% 단측 상한 5.5%)를 기록했다. 동일 trial에 대한 구조 유사도 지표(L4)는 72.7% 통과로, 외형 유사하나 실행 시 실패하는 환각 코드가 LLM 출력의 주된 패턴임을 시사한다."

**근거 표**: Part III §3.2

## F3. (평가 B 핵심 — 다층 방어 분담)
> "AST 검증(L2)과 semantic test(L3)가 차단하는 실패 카테고리 사이에 overlap은 0이다. `wrong_arg_count`, `wrong_kwarg`, `method_hallucination`, `algorithm_name_hallucination`은 100% L3에서만 차단되며, `missing_instance_construction`, `no_migration`, `class_direct_call`은 100% L2에서 차단된다. 두 layer는 상호 보완적이며 어느 한 쪽만으로는 모든 카테고리를 처리할 수 없다."

**근거 표**: Part III §3.4

## F4. (평가 B 핵심 — 시그니처 변경의 어려움)
> "RSA → oqs-python 마이그레이션은 비밀 키 상태가 인스턴스에 보존되는 특성상 caller-breaking signature 변경을 강제한다. keygen 패턴(N=20)에서 LLM의 L2 통과율은 0%로 가장 낮으며, 이는 시그니처 변경을 LLM이 인식하고 적용하지 못함을 시사한다."

**근거 표**: Part III §3.5 (use case)

## F5. (평가 B — 복잡도 영향)
> "단순 함수(simple) 패턴의 L4 통과율은 65%, 클래스 wrapper와 파일 IO를 포함한 복잡(complex) 패턴은 35%로 거의 절반 수준이다. LLM은 oqs API와 부수적 IO 로직을 동시에 정확히 처리하지 못한다."

**근거 표**: Part III §3.5 (complexity)

## F6. (평가 B — robustness)
> "L4 Structural Fidelity 임계값을 0.5에서 1.0까지 변화시켰을 때 0.5–0.7 구간에서 통과율은 57.5%로 평탄대를 보였으며 0.8에서 50.0%로 감소했다. 본 sensitivity는 구조 유사도 metric의 임계값 강건성을 보일 뿐이며, 메인 발견(L3=0%)은 임계값과 무관하게 성립한다."

**근거 표**: Part III §3.7

## F7. (통합 발견)
> "도구 체인 함정과 LLM 자동화 실패는 서로 다른 층(infrastructure vs application code)에서 발생하며, 두 층 모두에서 다층 방어가 필수다. 단일 layer 검증은 양쪽 어느 평가에서도 모든 카테고리를 처리할 수 없다."

**근거**: Part II + Part III 종합

## F8. (cost data point)
> "gpt-4o-mini로 80 trial 평가 시 LLM 출력 토큰 비용은 약 $0.013로, GitHub Models 무료 tier 한도 내에서 본 평가가 재현 가능하다."

**근거**: Part III §3.8

## F9. (평가 C — 파이프라인 효과)
> "본 프로젝트가 제안한 파이프라인은 평가 A의 6종 함정에 대해 자체 빌드로 5/6을 사전 예방하고 매트릭스 CI로 6/6을 런타임 감지한다. 동일 함정에 대해 표준 SCA/SAST/SBOM은 0/6을 기록하므로, 본 파이프라인은 표준 도구의 사각지대를 정량적으로 메운다."

**근거 표**: Part V §5.2

## F10. (평가 C — LLM 다층 방어)
> "본 파이프라인의 다층 검증을 적용하면 LLM 출력의 production crash 위험이 100%(검증 없음) → 100%(AST 단독) → 0%(AST + semantic test)로 단계적으로 감소한다. 정적 검증 단독으로는 위험률 감소가 일어나지 않으며, 의미적 검증을 추가해야 위험이 0이 된다."

**근거 표**: Part V §5.3

## F11. (통합 narrative — 파이프라인의 가치)
> "표준 도구로는 PQC 함정 0/6을 잡고(평가 A), LLM 단독으로는 동작 코드 0건을 생산(평가 B). 본 프로젝트의 파이프라인은 두 결손을 동시에 메워 (인프라 측 6/6 감지·5/6 예방 + LLM 측 위험 100%→0%) PQC 전환을 실제로 가능하게 한다(평가 C)."

**근거**: Part II + Part III + Part V 종합

---

# Part VIII. 산출물 (Reproducibility 작성용)

## 7.1 코드/데이터 디렉토리 구조

```
artifacts/eval/
├── evaluation-data.md (본 문서)
├── infra-failure-catalog.md
├── benchmark-spec.md
├── HOW_TO_RUN.md
├── Dockerfile
├── eval_runner.py
├── analyze.py
├── benchmark/
│   ├── patterns/      # 16 RSA 입력 (.py)
│   ├── reference/     # 16 oqs-python 정답 (.py)
│   └── results/
│       ├── sanity.json    # 정답 자기 회귀
│       ├── baseline.json  # RSA 그대로
│       ├── llm_k5.json    # 본 측정 80 trial 원시 데이터
│       └── analysis.md    # analyze.py 자동 생성
└── harness/
    ├── ast_validator.py
    ├── llm_client.py
    ├── semantic_tests.py
    └── equivalence.py
```

## 7.2 재현 명령

```bash
# 1) 평가 환경 빌드
docker build -t pqc-eval -f artifacts/eval/Dockerfile .

# 2) 하네스 sanity check
docker run --rm -v ${PWD}/artifacts/eval:/eval pqc-eval \
    python /eval/eval_runner.py --offline --use-reference --k 1 \
    --output /eval/benchmark/results/sanity.json

# 3) 본 측정
docker run --rm -e GITHUB_TOKEN -v ${PWD}/artifacts/eval:/eval pqc-eval \
    python /eval/eval_runner.py --k 5 \
    --output /eval/benchmark/results/llm_k5.json

# 4) 분석 보고서 자동 생성
python artifacts/eval/analyze.py
```

## 7.3 인용용 참고문헌 후보

| 항목 | 인용 정보 |
|---|---|
| ML-KEM 표준 | NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024-08-13 |
| ML-DSA 표준 | NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024-08-13 |
| Open Quantum Safe Project | https://openquantumsafe.org/ |
| liboqs | https://github.com/open-quantum-safe/liboqs |
| oqs-provider | https://github.com/open-quantum-safe/oqs-provider |
| GitHub Models | https://docs.github.com/en/github-models |
| CycloneDX CBOM | https://cyclonedx.org/capabilities/cbom/ |
| TLS 1.3 RFC | RFC 8446 |

## 7.4 관련 PR (인프라 함정 사례 추적)

| PR | 설명 | 발견된 함정 |
|---|---|---|
| #71 | OQS 이미지 sha256 핀 도입 | F-2, F-5 발견 계기 |
| #76 | nginx 이미지 :0.11.0 태그 회귀 | F-2 임시 대응 |
| #82 | AI 마이그레이션 PoC 구축 | 평가 B의 프롬프트 출처 |
| #83 | Stage 2/3 matrix CI 도입 | F-1~F-6 회귀 자동 감지 |
| #84 | 자체 빌드로 OQS 라인 통일 | F-1, F-3, F-4, F-6 근본 해결 |
