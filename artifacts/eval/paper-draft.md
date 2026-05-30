# PQC 마이그레이션의 두 함정: 도구 체인 측면과 LLM 자동화 측면의 실증 평가

> 본 문서는 2026 캡스톤 프로젝트의 논문 작성용 자료 정리본입니다. 표·수치·인용은 모두 실제 측정 데이터에 기반합니다. 출처 파일 경로는 각 절 끝에 명시했습니다.

---

## 초록 (후보)

본 연구는 NIST 표준화 직후 PQC TLS와 PQC 라이브러리 마이그레이션 실무에 두 층의 함정이 존재함을 실증한다: (1) **도구 체인 측면**에서 동일 메이저 태그를 공유하는 OQS 컨테이너들이 OpenSSL 라인·oqs-provider 버전 불일치로 group/sigalg code point 차원에서 호환되지 않아 표준 정적 분석·SBOM·SCA 도구로는 사전에 잡히지 않는 6종 함정(F-1~F-6)이 발생함을 실제 PR/CI 사례로 카탈로그화한다. (2) **LLM 자동화 측면**에서는 N=16 합성 패턴 × k=5 trial로 GitHub Models gpt-4o-mini의 RSA→ML-KEM/ML-DSA 마이그레이션을 평가한 결과, 구조적 유사성(L4: 72.7%)은 높지만 실제 동작(L3: **0%**)에 이르지 못하며, 시그니처 환각(`wrong_arg_count` 16건, `wrong_kwarg` 5건)은 정적 AST 검증에서 100% 통과되어 런타임 검증이 불가결함을 보인다. 결론: PQC 도입 시 **인프라 통합 검증과 코드 자동화 검증은 별개 층의 함정에 대응**하며, 양 층 모두에서 다층 방어가 필수다.

**키워드**: Post-Quantum Cryptography, ML-KEM, ML-DSA, OQS, LLM-assisted Migration, AST Validation, Software Supply Chain.

---

## 1. 서론

NIST가 2024년 8월 ML-KEM(FIPS 203), ML-DSA(FIPS 204)를 표준으로 확정하면서 RSA/ECC 기반 시스템의 PQC 마이그레이션이 산업 단위로 시작됐다. 그러나 (a) 표준화 직후 시점의 도구 체인은 알고리즘 명칭·OID·wire-level code point가 일제히 변경되는 전환기에 있어 메이저 태그가 같아도 실제 빌드가 호환되지 않는 사례가 빈번하고, (b) LLM 보조 코드 마이그레이션은 신규 라이브러리 API에 대한 학습 데이터가 부족하여 정적으로는 통과하지만 실제 동작하지 않는 코드를 생산할 수 있다.

본 연구의 기여:

1. **PQC 도구 체인 함정 카탈로그**: 단일 캡스톤 프로젝트에서 발생한 6종 함정(F-1~F-6)을 표준 보안 도구의 탐지 가능 여부와 함께 정리.
2. **LLM PQC 마이그레이션 평가 벤치마크**: cryptography·PyCryptodome × keygen/encrypt/sign/kex × simple/complex의 직교 설계 N=16 패턴과 정답, 4단 검증(L1-L4) 평가 하네스.
3. **실패 모드 taxonomy**: 7종 카테고리와 각각이 어느 검증 단계에서 잡히는지의 매핑.
4. **다층 방어의 정량 효과**: AST 검증과 semantic test가 서로 다른 카테고리의 실수를 잡는다는 실증.

---

## 2. 배경

### 2.1 PQC TLS 스택

OpenSSL 1.1.1 라인은 `oqs-engine`을 사용하며 ML-KEM 표준화 이전의 Kyber 명칭과 OQS 사설 group code point를 보유한다. OpenSSL 3.x 라인은 `oqs-provider`(0.6.x 이후) 기반으로 ML-KEM IETF 표준 명칭과 IANA code point로 등록한다. 두 라인의 wire-level 표현은 호환되지 않는다.

### 2.2 oqs-python

liboqs의 Python 바인딩. 핵심 API:
```python
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(public_key)
shared_secret = kem.decap_secret(ciphertext)

sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
signature = sig.sign(message)
ok = sig.verify(message, signature, public_key)
```

비밀 키 상태가 인스턴스에 보존되므로 **caller가 인스턴스 자체를 유지해야** decap이 가능하다. 이는 RSA의 stateless `(private_key, public_key)` 패턴과 본질적으로 다르며 caller 측 시그니처 변경을 강제한다.

---

## 3. 방법론

### 3.1 도구 체인 측면 평가

3-Stage TLS 환경(Stage 1: classical ECC, Stage 2: hybrid X25519MLKEM768, Stage 3: hybrid p521_mlkem1024:p384_mlkem768)을 docker-compose로 구축하고, 외부 OQS 이미지 사용 → 자체 빌드(OpenSSL 3.4.0 + liboqs 0.14.0 + oqs-provider 0.9.0)로 마이그레이션. 마이그레이션 과정에서 발생한 함정을 PR/issue 단위로 추적하여 카탈로그화.

### 3.2 LLM 평가 벤치마크 설계

**입력 패턴**: 16개 합성 Python 코드. 직교 설계:
- 라이브러리 (2): `cryptography.hazmat`, `PyCryptodome`
- 사용 케이스 (4): keygen / encrypt / sign / kex
- 복잡도 (2): simple (≤20 LOC) / complex (클래스 wrapper + 파일 IO + 환경 변수)

**정답 (Ground Truth)**: 16개. ML-KEM-768 (KEM/encrypt/kex), ML-DSA-65 (sign)를 oqs-python으로 작성. AES-GCM 결합으로 임의 메시지 암호화 처리. Caller-breaking signature 변경은 docstring에 명시.

**평가 layer (L1-L4)**:
- **L1 (LLM only)**: GitHub Models gpt-4o-mini에 PR #82의 정성스러운 프롬프트 + 원본 패턴 입력. temperature=0.
- **L2 (AST validation)**: `oqs.KeyEncapsulation`/`oqs.Signature` 인스턴스 생성, 클래스 직접 호출 금지, `encapsulate`/`decapsulate` 같은 환각 메서드명 차단, 모듈 레벨 인스턴스화 거부.
- **L3 (Semantic test)**: 마이그레이션 결과를 동적 import → 패턴별 round-trip 테스트 (KEM encap/decap shared_secret 일치, 서명 verify 통과, 파일 암호화/복호화 round-trip).
- **L4 (Equivalence)**: 정답과의 AST feature 매칭 점수 (overall_score ≥ 0.8 시 동등). KEM/Sig 인스턴스 사용·encap/decap·sign/verify 호출·AES-GCM 사용·함수/클래스명 보존을 가중 평균.

각 패턴 k=5 반복 → 80 trial. markdown fence 자동 stripping 처리.

**산출물**: [`patterns/`](benchmark/patterns/), [`reference/`](benchmark/reference/), [`harness/`](harness/), [`eval_runner.py`](eval_runner.py), [`Dockerfile`](Dockerfile).

---

## 4. 결과

### 4.1 도구 체인 함정 카탈로그 (B)

본 프로젝트에서 발견된 6종. 모두 표준 보안 도구로는 탐지되지 않음.

| ID | 함정 | 증상 | Trivy | Semgrep | CBOM | matrix CI | 자체빌드 |
|---|---|---|:-:|:-:|:-:|:-:|:-:|
| F-1 | OQS 라이브러리 버전 비대칭 (oqs-provider 0.6.1 vs 0.9.0 sigalg drift) | TLS alert 552 | ❌ | ❌ | ❌ | ⭕ | ⭕ |
| F-2 | OpenSSL 1.1.1 ↔ 3.x 인증서 OID 불일치 (Dilithium3 OID 두 가지) | `SSL_CTX_use_certificate failed` | ❌ | ❌ | ❌ | ⭕ | ⭕ |
| F-3 | ML-KEM IETF code point ↔ Kyber OQS code point 충돌 | 핸드셰이크에서 group 매칭 0개 | ❌ | ❌ | ❌ | ⭕ | ⭕ |
| F-4 | PQ key strength 0 보고 → SECLEVEL 거부 | `ee key too small` | ❌ | ❌ | ❌ | ⭕ | ⭕ |
| F-5 | sha256 핀이 시점에 따라 다른 빌드를 가리킴 | 시간 지연 후 환경 재구성 시 협상 실패 | ❌ | ❌ | ❌ | ⭕ | ⭕ |
| F-6 | standalone PQ group이 hybrid보다 협상 불가능한 빌드 | `ssl_ecdh_curve` 파싱은 통과, 실제 협상 실패 | ❌ | ❌ | ❌ | ⭕ | — |

**핵심 시사점**: 표준 정적 분석/SCA/SBOM은 6/6 함정에 대해 사전 탐지 불가. 런타임 매트릭스 CI(PR #83)와 자체 빌드(supply chain integrity 강제)가 표준 도구의 사각지대를 메운다.

상세: [`infra-failure-catalog.md`](infra-failure-catalog.md).

### 4.2 LLM 평가 결과

#### 4.2.1 다층 방어 ablation (Table 1)

| Layer | 통과 | 비율 (전체 N=80) | 비율 (응답 N=55) |
|---|---:|---:|---:|
| L1 (LLM 응답 받음) | 55 | 68.8% | 100% |
| L2 (AST 검증 통과) | 24 | 30.0% | 43.6% |
| L3 (semantic test 통과) | **0** | **0.0%** | **0.0%** |
| L4 (equivalence ≥ 0.8) | 40 | 50.0% | 72.7% |

**핵심 패턴**: L4 ≫ L2 ≫ L3 = 0. 즉 **LLM이 PQC 마이그레이션의 형태(structural shape)는 잡지만 정확한 API 시그니처는 거의 못 맞춘다**. 구조적 유사성과 의미적 정확성이 분리됨을 정량 입증.

#### 4.2.2 실패 모드 taxonomy (Table 2)

| 카테고리 | 빈도 | 설명 |
|---|---:|---|
| `missing_instance_construction` | 20 | Signature/KeyEncapsulation 인스턴스 생성 누락 |
| `wrong_arg_count` | 16 | 메서드에 잘못된 인자 개수 (시그니처 환각) |
| `no_migration` | 6 | RSA 잔존, oqs import만 추가 |
| `class_direct_call` | 5 | `KeyEncapsulation.encap_secret()` 직접 호출 |
| `wrong_kwarg` | 5 | 존재하지 않는 keyword argument |
| `method_hallucination` | 2 | `import_public_key` 같은 invent 메서드 |
| `algorithm_name_hallucination` | 1 | 잘못된 알고리즘 명칭 |

#### 4.2.3 실패 모드 × Defense Layer 매핑 (Table 3 — 핵심)

| 카테고리 | L2가 차단 | L3가 차단 | L3 의존도 |
|---|---:|---:|---:|
| `missing_instance_construction` | **20** | 0 | 0% |
| `wrong_arg_count` | 0 | **16** | **100%** |
| `no_migration` | **6** | 0 | 0% |
| `class_direct_call` | **5** | 0 | 0% |
| `wrong_kwarg` | 0 | **5** | **100%** |
| `method_hallucination` | 0 | **2** | **100%** |
| `algorithm_name_hallucination` | 0 | **1** | **100%** |

**핵심 발견**: 두 layer가 잡는 카테고리가 **완전 분리** (overlap 0). 시그니처/인자 환각(`wrong_arg_count`, `wrong_kwarg`, `method_hallucination`)은 100% L3에서만 잡히므로 정적 AST 분석만으로는 production 위험을 거를 수 없다. 반대로 인스턴스 생성 누락이나 클래스 직접 호출은 L2에서 일찍 차단된다. → **AST validation과 semantic test는 상호 보완적이며 둘 다 필요**.

#### 4.2.4 차원별 통과율 (Table 4)

**라이브러리**:

| Lib | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| cryptography | 40 | 35% | 0% | 50% |
| pycryptodome | 40 | 25% | 0% | 50% |

**사용 케이스**:

| Use case | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| encrypt | 20 | 50% | 0% | **75%** |
| sign | 20 | 45% | 0% | 45% |
| kex | 20 | 25% | 0% | 55% |
| keygen | 20 | **0%** | 0% | **25%** |

**복잡도**:

| Complexity | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| simple | 40 | 25% | 0% | **65%** |
| complex | 40 | 35% | 0% | 35% |

**해석**:
- `keygen` 패턴은 LLM에 가장 어려움. 원인: RSA의 `(private_key, public_key)` 시그니처를 ML-KEM의 `(kem_instance, public_key)`로 변경해야 하는 caller-breaking change를 모델이 인식하지 못함.
- `simple` 패턴이 `complex`보다 L4 점수 높음. 클래스 wrapper와 파일 IO가 들어가면 LLM이 oqs API + IO 양쪽을 동시에 정확히 처리하지 못함.

#### 4.2.5 L4 임계값 sensitivity (Table 5)

| Threshold | L4 통과 | 비율 |
|---:|---:|---:|
| 0.5 | 46/80 | 57.5% |
| 0.6 | 46/80 | 57.5% |
| 0.7 | 46/80 | 57.5% |
| 0.8 | 40/80 | 50.0% |
| 0.9 | 24/80 | 30.0% |
| 1.0 | 24/80 | 30.0% |

0.5~0.7 구간에서 결과 안정 → L4 결론은 임계값 선택에 강건(robust).

#### 4.2.6 Cost / Length proxy

| 통계 | 값 (chars) |
|---|---:|
| 응답 trial 수 | 55 |
| 평균 길이 | 1072 |
| Median | 1064 |
| p5 / p95 | 372 / 2198 |
| Min / Max | 325 / 2487 |

평균 ≈ 268 토큰. gpt-4o-mini 출력 $0.6/1M 기준 trial 당 약 $0.00016, 80 trial 총 $0.013. 무료 tier로 충분히 재현 가능.

### 4.3 Failure Case Study (대표 4건)

#### Case 1: `wrong_arg_count` (가장 흔한 런타임 실패)

Pattern 06 trial 0 (cryptography encrypt complex). LLM 출력 일부:
```python
# LLM 출력
shared_secret = KeyEncapsulation.decap_secret(kem_ct_data, ciphertext_kem, ...)
```
실패 사유: `TypeError: KeyEncapsulation.decap_secret() takes 2 positional arguments but 3 were given`

→ 인스턴스 메서드를 클래스 메서드로 호출하면서 `self` 자리에 데이터를 채움. AST 검증은 통과(클래스명 호출 패턴이 구조적으로는 인스턴스 호출과 구분 어려움). 런타임에서야 잡힘.

#### Case 2: `wrong_kwarg`

Pattern 08 trial 0 (cryptography kex complex):
```python
kem = oqs.KeyEncapsulation("ML-KEM-768", public_key=peer_pub)
```
실패: `TypeError: KeyEncapsulation.__init__() got an unexpected keyword argument 'public_key'`

→ LLM이 `public_key`를 constructor에 전달할 수 있다고 환각. 실제 API는 `secret_key`만 옵션 인자로 받음.

#### Case 3: `method_hallucination`

Pattern 11 trial 1:
```python
public_key_obj = kem.import_public_key(public_key_bytes)
```
실패: `AttributeError: 'KeyEncapsulation' object has no attribute 'import_public_key'`

→ 존재하지 않는 메서드. RSA에서 `RSA.import_key`가 있다는 사전 지식이 oqs로 전이.

#### Case 4: `no_migration`

Pattern 04 trial 0:
```python
import oqs  # 추가만 함
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ... RSA 코드 그대로 ...
```
실패: AST 검증 — "oqs.KeyEncapsulation 또는 oqs.Signature 미사용 — 마이그레이션 미적용"

→ LLM이 `import oqs`만 추가하고 본문은 RSA 그대로 유지. 6/55 trial.

상세: [`analysis.md`](benchmark/results/analysis.md).

---

## 5. 논의

### 5.1 두 함정의 분리성

도구 체인 함정(F-1~F-6)과 LLM 자동화 함정(taxonomy 7종)은 **서로 다른 층의 검증을 요구**한다. F-2(OID 불일치)는 인증서 디코드 단계에서 nginx가 emerg를 내며 즉시 실패하는 반면, LLM이 만든 `wrong_arg_count` 코드는 정적 AST에서 통과하고 함수 호출 시점에 비로소 TypeError. 두 종류의 실패는 위치(infra vs. app code), 시점(deploy vs. test), 검증 도구(integration test vs. unit test) 모두 다르다.

### 5.2 "구조적 정확성"의 함정

L4 결과는 LLM이 **PQC 마이그레이션의 외형**을 잘 학습했음을 시사한다 (oqs.KeyEncapsulation, encap_secret, decap_secret을 적시 적소에 사용). 그러나 L3 = 0은 **세부 시그니처는 학습되지 않았음**을 보인다. 이는 oqs-python이 stable API 라이브러리가 아니어서 GitHub corpus 학습 분포가 충분하지 않았을 가능성이 가장 큰 원인이다. 표준화 직후 라이브러리 API에 대한 LLM 자동화는 **구조적 외형은 자동화 가능, 시그니처 세부는 자동화 불가**라는 비대칭이 있다.

### 5.3 다층 방어가 "필요충분한" 조합

L2 ∩ L3가 잡는 카테고리가 분리된다는 발견(Table 3)은 다층 방어의 *효율적 분담*을 보인다. 만약 두 layer가 같은 실수를 잡는다면 어느 하나는 잉여(redundant). 본 결과는 redundant하지 않다는 실증.

다만 L3 = 0%는 **현 LLM(gpt-4o-mini)으로는 다층 방어가 quality gate가 아니라 reject filter로만 기능함**을 의미한다. 즉 안전성 측면에선 만족스럽지만(나쁜 코드는 모두 거부) 생산성 측면에선 0건도 production에 안전히 도달하지 못한다. 이 한계는 LLM 모델 개선 또는 fine-tuning으로만 해결 가능.

---

## 6. 한계

1. **단일 모델**: gpt-4o-mini만 평가. 더 큰 모델(GPT-4o, Claude, Gemini Pro)은 결과가 다를 가능성. **외부 타당성 가장 큰 약점**.
2. **합성 패턴 N=16**: 실제 OSS 코드의 길이/스타일/주변 컨텍스트 다양성을 대표하지 못함.
3. **Rate limit 편향**: 25/80 trial이 LLM API error로 종료 (특히 패턴 13-16). 효과적 N이 패턴별로 균형이 맞지 않음.
4. **저자 정의 ground truth**: 정답 16개와 평가 기준 모두 저자 작성. Self-fulfilling 위험. Inter-annotator agreement 미측정.
5. **Naive prompt 비교 부재**: 정성스러운 PR #82 프롬프트 vs 짧은 naive 프롬프트의 비교 없음 → 프롬프트 엔지니어링의 기여도 불명확.
6. **L4 equivalence는 AST feature 매칭 근사**: 완전한 의미 동등성 분석은 결정 불가능. 우리 metric은 보수적 근사.

---

## 7. 결론

PQC 도구 체인의 6종 함정과 LLM 자동화의 7종 실패 모드를 한 프로젝트에서 동시에 카탈로그화·정량화함으로써, **PQC 도입 시 인프라 통합과 코드 자동화는 별개 층의 검증을 요구**함을 실증했다. AST 기반 정적 검증과 런타임 semantic test가 잡는 실수 카테고리가 분리(overlap 0)되며, 따라서 양 layer 모두 필수다. 다만 본 평가는 단일 LLM(gpt-4o-mini), N=16 합성 패턴에 한정되므로 보다 큰 모델·실제 OSS 코퍼스에 대한 후속 평가가 필요하다.

---

## 8. 산출물 (Reproducibility)

GitHub repo: `apinball/2026SecureCapstone` (캡스톤 프로젝트).

| 산출물 | 경로 | 설명 |
|---|---|---|
| 인프라 함정 카탈로그 | [`infra-failure-catalog.md`](infra-failure-catalog.md) | F-1~F-6 상세 |
| 평가 벤치마크 패턴 | [`benchmark/patterns/`](benchmark/patterns/) | 16 RSA 입력 |
| 정답 (ground truth) | [`benchmark/reference/`](benchmark/reference/) | 16 oqs-python 정답 |
| 평가 하네스 코드 | [`harness/`](harness/) | AST/LLM/semantic/equivalence 모듈 |
| 메인 러너 | [`eval_runner.py`](eval_runner.py) | L1-L4 자동 실행 |
| 분석 스크립트 | [`analyze.py`](analyze.py) | 11개 표 + 케이스 스터디 자동 생성 |
| Docker 환경 | [`Dockerfile`](Dockerfile) | OpenSSL 3.4 + liboqs 0.14 + oqs-python 0.14.1 |
| 실행 가이드 | [`HOW_TO_RUN.md`](HOW_TO_RUN.md) | 명령어 + 토큰 요구사항 |

**원시 데이터**:
- [`benchmark/results/sanity.json`](benchmark/results/sanity.json) — 정답 자기 회귀 (16/16/16)
- [`benchmark/results/baseline.json`](benchmark/results/baseline.json) — RSA 그대로 (0/0/0)
- [`benchmark/results/llm_k5.json`](benchmark/results/llm_k5.json) — 80 trial 실측
- [`benchmark/results/analysis.md`](benchmark/results/analysis.md) — 자동 생성 분석 보고서

**관련 PR (인프라 함정 사례 출처)**:
- PR #71: OQS 이미지 sha256 핀 도입 — F-2, F-5 발견 계기
- PR #76: nginx 이미지 :0.11.0 태그 회귀 — F-2 임시 대응
- PR #84: 자체 빌드로 OQS 라인 통일 — F-1, F-3, F-4, F-6 근본 해결
- PR #83: Stage 2/3 matrix CI — 함정 회귀 자동 감지
- PR #82: AI 마이그레이션 PoC — A-1 평가의 입력 프롬프트 출처

---

## 부록 A: 평가 layer 정의 요약

- **L1 — LLM only**: GitHub Models gpt-4o-mini, temperature=0, PR #82 프롬프트, k=5 반복
- **L2 — AST validation**: oqs.KeyEncapsulation/Signature import 확인 + 인스턴스 생성 패턴 + 클래스 직접 호출 거부 + `encapsulate`/`decapsulate` 같은 환각 메서드명 차단 + 모듈 레벨 인스턴스화 거부
- **L3 — Semantic test**: 동적 import 후 패턴별 round-trip (KEM shared_secret 일치, 서명 verify, 파일 IO 회귀)
- **L4 — Equivalence**: AST feature 매칭 (`has_kem_instance`, `calls_encap`, `uses_aesgcm`, 함수/클래스 이름 보존 등) 가중 평균. 0.8 이상 동등.

## 부록 B: 데이터 수집 환경

- 호스트: Windows 10, Docker Desktop
- 평가 컨테이너: python:3.11-slim + liboqs 0.14.0 + liboqs-python 0.14.1 + cryptography + PyCryptodome
- LLM endpoint: `https://models.inference.ai.azure.com/chat/completions` (GitHub Models)
- 측정 시점: 2026-05-08
- 총 80 trial, 25 API error (rate limit), 효과 N=55
