# PQC 마이그레이션 평가 보고서

본 문서는 캡스톤 프로젝트에서 수행한 두 측면의 평가를 정리한다.
- **평가 A**: PQC 도구 체인 인프라 함정 카탈로그 (실제 PR/CI 사례 기반)
- **평가 B**: LLM 기반 RSA → ML-KEM/ML-DSA 코드 마이그레이션 정량 평가

---

## 1. 평가 A: 인프라 함정 카탈로그

### 1.1 평가 대상

`docker-compose` 기반 3-Stage TLS 환경:
- Stage 1 — classical ECC (X25519:P-256)
- Stage 2 — hybrid PQC (X25519MLKEM768)
- Stage 3 — hybrid PQ-only (p521_mlkem1024:p384_mlkem768)

OQS 도구 체인: liboqs / oqs-provider / OpenSSL 3.x / OQS-nginx / OQS-curl.

### 1.2 평가 방법

자체 PR/issue 추적 + Stage 3 회귀 디버깅 과정에서 발생한 모든 호환성/협상 실패를 함정 단위로 기록. 각 함정에 대해:
1. 트리거 조건 (어떤 환경에서 발생)
2. 관찰 가능한 증상 (로그·error 메시지)
3. 근본 원인 (라이브러리/버전/code point 분석)
4. 표준 보안 도구로 사전 탐지 가능 여부 (Trivy, Semgrep, CycloneDX CBOM)
5. 본 프로젝트의 방어책

### 1.3 발견된 함정 (총 6종)

#### F-1: OQS 라이브러리 버전 비대칭

- **트리거**: 동일 OQS 메이저 태그(`0.11.0`)가 client(OQS-curl)와 server(OQS-nginx) 양쪽에 사용되지만 내부 oqs-provider 버전이 다름 (curl 0.9.0 vs nginx 0.6.1).
- **증상**: TLS 1.3 ClientHello/ServerHello 단계 `alert handshake_failure (552)`. 어떤 group 조합도 성공하지 않음.
- **근본 원인**: oqs-provider 0.6.1과 0.9.0이 ML-DSA/ML-KEM에 다른 IANA code point 등록. 양쪽이 sigalg/group을 광고하지만 매칭 0개.
- **표준 도구 탐지**: ❌ Trivy(CVE), Semgrep(소스 룰), CBOM(인벤토리) 어느 것도 못 잡음.
- **본 프로젝트 방어책**: 자체 빌드 멀티스테이지 Dockerfile로 OpenSSL/liboqs/oqs-provider 버전을 한 라인으로 고정.
- **재현 명령**: `docker exec pqc-proxy openssl list -signature-algorithms` ↔ `docker exec tls-tester openssl list -signature-algorithms` 비교.

#### F-2: OpenSSL 1.1.1 ↔ 3.x 인증서 OID 불일치

- **트리거**: OQS-OpenSSL 1.1.1 fork(oqs-engine 시대)와 OQS-OpenSSL 3.x(oqs-provider 시대)가 같은 알고리즘에 다른 OID 사용. Dilithium3 인증서가 두 라인에서 다른 OID로 인코딩.
- **증상 1**: `nginx: [emerg] SSL_CTX_use_certificate failed (SSL: digital envelope routines::decode error)`.
- **증상 2**: 인증서 디코드 시 `Public Key Algorithm: 1.3.6.1.4.1.2.267.7.6.5 / Unable to load Public Key`.
- **근본 원인**: `oqs-ossl3:0.10.1`(OpenSSL 3 라인)으로 cert를 만들면 ML-DSA NIST OID. 이를 OQS-nginx 0.11.0(OpenSSL 1.1.1q 정적 빌드)에 넣으면 OID 미인식.
- **표준 도구 탐지**: ❌ X.509 자체는 유효 → 일반 인증서 검사기로는 정상.
- **본 프로젝트 방어책**: cert-builder를 nginx 본체와 동일 OpenSSL 라인으로 통일.

#### F-3: ML-KEM IETF code point ↔ Kyber OQS code point 충돌

- **트리거**: TLS 1.3 named group으로 `X25519MLKEM768`(IETF 0x11ec) vs `x25519_kyber768`(OQS 사설 code point)가 서로 다른 라이브러리 세대에서 사용.
- **증상**: `ssl_ecdh_curve` 설정은 nginx config 파싱 통과하지만 실제 TLS 협상 시 ClientHello/ServerHello 매칭 group 0개.
- **근본 원인**: OpenSSL 1.1.1 라인 OQS는 Kyber 시대 명칭/code point, OpenSSL 3 라인 oqs-provider 0.9+는 ML-KEM IETF 표준. 같은 group이라도 wire format 상수 다름.
- **표준 도구 탐지**: ❌ TLS 정책 룰셋(Semgrep)은 string match만, wire-level code point 미관여.
- **본 프로젝트 방어책**: 동일 라이브러리 라인 통일.

#### F-4: PQ key strength 0 보고 → SECLEVEL 정책 거부

- **트리거**: oqs-provider가 ML-DSA/ML-KEM의 `EVP_PKEY_security_bits()`를 0으로 보고.
- **증상**: `nginx: [emerg] SSL_CTX_use_certificate failed (ssl/tls alert: ee key too small)` — PQ 인증서가 OpenSSL default SECLEVEL=2(112-bit 이상)에 걸림.
- **근본 원인**: NIST PQC의 보안 비트 정의가 OpenSSL 전통적 RSA/ECC bits 기준과 다름. oqs-provider 0.9.0은 보수적으로 0 반환.
- **표준 도구 탐지**: ❌
- **본 프로젝트 방어책**: `ssl_ciphers DEFAULT:@SECLEVEL=0` 임시 방편 + `ssl_protocols TLSv1.3` + group whitelist로 약점 보완.
- **부작용 경고**: SECLEVEL=0은 약한 RSA/SHA-1까지 허용하는 광범위 완화 → group/protocol whitelist로 부작용 차단 필수.

#### F-5: sha256 핀이 시점에 따라 다른 빌드를 가리킴

- **트리거**: OQS Project가 `openquantumsafe/nginx:0.11.0` 태그를 다시 빌드/푸시하면서 sha256 변경. git 이력의 핀(`sha256:d02e7d6e...`)이 처음 PR에선 OpenSSL 3 빌드를 가리켰지만 4주 후 `docker pull` 시점엔 OpenSSL 1.1.1 빌드.
- **증상**: 이전 PR 머지 시 CI 통과한 핀이 시간이 지나 환경 재구성하면 핸드셰이크 실패.
- **근본 원인**: Docker registry tag와 manifest list의 시간적 가변성. sha256 자체는 immutable이지만 사용자가 인지하는 "0.11.0" 식별자는 가변.
- **표준 도구 탐지**: ❌ 일반 supply chain 스캐너는 알려진 CVE만 검사.
- **본 프로젝트 방어책**: nginx 자체 빌드로 외부 이미지 의존 자체 제거. OpenSSL/liboqs/oqs-provider/nginx 모두 소스 + sha256 검증.
- **교훈**: "sha256 핀 = 재현성 보장"이 PQC 도입 초기 도구 체인에서 깨질 수 있음. 빌드 from source가 더 안전.

#### F-6: standalone PQ group이 hybrid보다 협상 불가능한 빌드

- **트리거**: `ssl_ecdh_curve mlkem1024` 단독 설정이 OQS-nginx 0.11.0 기본 빌드에서 협상 안 됨. 같은 빌드가 `p521_mlkem1024:p384_mlkem768` hybrid는 협상.
- **증상**: nginx 시작 정상, `ssl_ecdh_curve` 파싱 통과, 실제 TLS handshake 단계에서 협상 실패.
- **근본 원인**: OQS-nginx 빌드 시 `OQS_KEM_DEFAULT_ALGS_ENABLED` CMake 플래그에 standalone PQ KEM이 빠지거나, oqs-provider config에서 group 비활성.
- **표준 도구 탐지**: ❌
- **본 프로젝트 방어책**: hybrid group으로 회귀, CI matrix(PR #83)로 회귀 자동 감지.

### 1.4 함정 × 표준 도구 탐지 매트릭스

| 함정 | Trivy | Semgrep | CBOM | matrix CI | AST 검증 | 자체빌드 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| F-1 sigalg drift | ❌ | ❌ | ❌ | ⭕ (감지) | ❌ | ⭕ (예방) |
| F-2 OID mismatch | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-3 group code point | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ |
| F-4 SECLEVEL 거부 | ❌ | ❌ | ❌ | ⭕ | ❌ | ⭕ (config 통합) |
| F-5 sha256 시간 가변 | ❌ | ❌ | ❌ | ⭕ (지연 감지) | ❌ | ⭕ |
| F-6 standalone 미협상 | ❌ | ❌ | ❌ | ⭕ | ❌ | — |

**관찰**: 6/6 함정에 대해 Trivy/Semgrep/CBOM 모두 ❌. 런타임 매트릭스 CI와 자체 빌드(supply chain integrity 강제)가 표준 도구 사각지대를 메운다.

### 1.5 외부 타당성

OpenSSL/OQS 한정이지만 동일 패턴이 다른 PQC 스택에서도 보고됨:
- BoringSSL + Cloudflare PQ fork: CIRCL 라이브러리 마이너 버전 간 group code point drift
- Java BCJSSE + Bouncy Castle PQ: BC 1.77 → 1.78 마이그레이션에서 OID/sigalg 비대칭

**공통점**: NIST 표준화 이전→이후 명칭/code point 전환기에 도구 체인이 라인을 단일화하지 못하면 동일한 함정 발생.

---

## 2. 평가 B: LLM 마이그레이션 정량 평가

### 2.1 평가 대상

GitHub Models `gpt-4o-mini` (temperature=0). RSA 사용 Python 코드를 oqs-python(ML-KEM-768 / ML-DSA-65) 기반으로 마이그레이션할 수 있는지 평가.

### 2.2 벤치마크 설계

**입력 패턴 N=16, 직교 설계**:
- 라이브러리 (2): `cryptography.hazmat`, `PyCryptodome`
- 사용 케이스 (4): keygen / encrypt / sign / kex (key exchange)
- 복잡도 (2): simple (≤20 LOC) / complex (클래스 wrapper + 파일 IO + 환경 변수)
- 총 2 × 4 × 2 = 16

**정답 (Ground Truth) N=16**:
- ML-KEM-768 (KEM/encrypt/kex), ML-DSA-65 (sign)
- AES-GCM 결합으로 임의 메시지 암호화 처리
- Caller-breaking signature 변경은 docstring에 명시
- 모듈 레벨 인스턴스화 금지

### 2.3 4-Layer 평가 정의

| Layer | 검증 내용 | 통과 조건 |
|---|---|---|
| **L1** | LLM 호출 자체 성공 | gpt-4o-mini가 응답 반환 (rate limit/네트워크 에러 아님) |
| **L2** | AST 검증 | `oqs.KeyEncapsulation`/`Signature` import 및 인스턴스 생성 + 클래스 직접 호출 거부 + 환각 메서드명(`encapsulate` 등) 차단 + 모듈 레벨 인스턴스화 거부 |
| **L3** | Semantic test | 동적 import 후 패턴별 round-trip (KEM shared_secret 일치, 서명 verify, 파일 IO 회귀) 모두 통과 |
| **L4** | Equivalence | 정답과의 AST feature 매칭 가중 평균 ≥ 0.8 (KEM/Sig 인스턴스 사용·encap/decap·sign/verify 호출·AES-GCM 사용·함수/클래스명 보존) |

### 2.4 평가 절차

1. 각 패턴 k=5 반복 → 80 trial
2. 프롬프트: PR #82에서 정성스럽게 작성한 instruction (oqs API 규약 + 6개 호환성 제약 명시)
3. markdown fence 자동 stripping (LLM이 \`\`\`python으로 감싸는 경우 처리)
4. 각 trial에 대해 L1, L2, L3, L4 모두 측정
5. 실행 환경: Docker (python:3.11-slim + liboqs 0.14.0 + liboqs-python 0.14.1 + cryptography + PyCryptodome)
6. 측정 시점: 2026-05-08

### 2.5 검증 절차의 자체 sanity check

평가 하네스가 정상 동작하는지 두 극값에서 확인:

| 시나리오 | L2 | L3 | L4 |
|---|---:|---:|---:|
| **(a) 정답을 후보로 입력** (16개) | 16/16 | 16/16 | 16/16 |
| **(b) 입력 RSA 코드 그대로** (16개) | 0/16 | 0/16 | 0/16 |

→ 하네스가 두 극값을 정확히 구분. semantic test도 실제 KEM round-trip이 동작.

### 2.6 결과: 다층 ablation

| Layer | 통과 | 비율 (전체 N=80) | 비율 (응답 N=55) |
|---|---:|---:|---:|
| L1 (LLM 응답 받음) | 55 | 68.8% | 100% |
| **L2 (AST)** | 24 | **30.0%** | **43.6%** |
| **L3 (Semantic)** | **0** | **0.0%** | **0.0%** |
| **L4 (Equivalence)** | 40 | **50.0%** | **72.7%** |

**관찰**: L4 ≫ L2 ≫ L3 = 0. 구조적 유사성은 높으나 실제 동작은 0건.

### 2.7 결과: 실패 모드 taxonomy (7종)

| 카테고리 | 빈도 | 설명 |
|---|---:|---|
| `missing_instance_construction` | 20 | Signature/KeyEncapsulation 인스턴스 생성 누락 (import만 함) |
| `wrong_arg_count` | 16 | 메서드에 잘못된 인자 개수 (시그니처 환각) |
| `no_migration` | 6 | RSA 그대로 두고 oqs import만 추가 |
| `class_direct_call` | 5 | `KeyEncapsulation.encap_secret()` 클래스 직접 호출 |
| `wrong_kwarg` | 5 | 존재하지 않는 keyword argument |
| `method_hallucination` | 2 | 존재하지 않는 메서드 호출 (`import_public_key` 등) |
| `algorithm_name_hallucination` | 1 | 잘못된 알고리즘 명칭 |

총 55건 (응답 받은 trial 모두 어딘가에서 실패).

### 2.8 결과: 실패 모드 × Defense Layer 매핑

| 카테고리 | L2가 차단 | L3가 차단 | L3 의존도 |
|---|---:|---:|---:|
| `missing_instance_construction` | **20** | 0 | 0% |
| `wrong_arg_count` | 0 | **16** | **100%** |
| `no_migration` | **6** | 0 | 0% |
| `class_direct_call` | **5** | 0 | 0% |
| `wrong_kwarg` | 0 | **5** | **100%** |
| `method_hallucination` | 0 | **2** | **100%** |
| `algorithm_name_hallucination` | 0 | **1** | **100%** |

**관찰**: 두 layer가 잡는 카테고리가 완전 분리(overlap 0). 시그니처/인자 환각은 100% L3에서만 잡힘 → AST 검증 단독 부족, semantic test 필수.

### 2.9 결과: 차원별 통과율

#### 라이브러리

| Lib | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| cryptography | 40 | 35% | 0% | 50% |
| pycryptodome | 40 | 25% | 0% | 50% |

#### 사용 케이스

| Use case | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| encrypt | 20 | 50% | 0% | **75%** |
| sign | 20 | 45% | 0% | 45% |
| kex | 20 | 25% | 0% | 55% |
| keygen | 20 | **0%** | 0% | **25%** |

#### 복잡도

| Complexity | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| simple | 40 | 25% | 0% | **65%** |
| complex | 40 | 35% | 0% | 35% |

**관찰**:
- `keygen` 패턴이 LLM에 가장 어려움 (시그니처 변경 강제)
- `simple`이 `complex`보다 L4 점수 높음 (클래스 wrapper + 파일 IO 동시 처리 시 정확도 하락)
- 라이브러리 종류별 차이는 미미 (cryptography 35% vs pycryptodome 25% L2)

### 2.10 결과: 패턴별 raw 데이터

| Pattern | Lib | Use case | Complexity | n | LLM err | L2 | L3 | L4 |
|---|---|---|---|---:|---:|---:|---:|---:|
| 01 | cryptography | keygen | simple | 5 | 0 | 0 | 0 | 0 |
| 02 | cryptography | encrypt | simple | 5 | 0 | 0 | 0 | 5 |
| 03 | cryptography | sign | simple | 5 | 0 | 0 | 0 | 0 |
| 04 | cryptography | kex | simple | 5 | 4 | 0 | 0 | 1 |
| 05 | cryptography | keygen | complex | 5 | 2 | 0 | 0 | 0 |
| 06 | cryptography | encrypt | complex | 5 | 0 | 5 | 0 | 5 |
| 07 | cryptography | sign | complex | 5 | 0 | 4 | 0 | 4 |
| 08 | cryptography | kex | complex | 5 | 0 | 5 | 0 | 5 |
| 09 | pycryptodome | sign | simple | 5 | 0 | 5 | 0 | 5 |
| 10 | pycryptodome | keygen | simple | 5 | 0 | 0 | 0 | 5 |
| 11 | pycryptodome | encrypt | simple | 5 | 0 | 5 | 0 | 5 |
| 12 | pycryptodome | kex | simple | 5 | 0 | 0 | 0 | 5 |
| 13 | pycryptodome | keygen | complex | 5 | 4 | 0 | 0 | 0 |
| 14 | pycryptodome | encrypt | complex | 5 | 5 | 0 | 0 | 0 |
| 15 | pycryptodome | sign | complex | 5 | 5 | 0 | 0 | 0 |
| 16 | pycryptodome | kex | complex | 5 | 5 | 0 | 0 | 0 |

**관찰**: 패턴 13-16(PyCryptodome complex)이 모두/대부분 LLM API error로 종료. 80 trial 중 25개가 rate limit. 효과 N이 패턴별로 균형 X — 통계적으로는 1-12번 패턴 위주 결론.

### 2.11 결과: L4 임계값 sensitivity

| Threshold | 통과 | 비율 |
|---:|---:|---:|
| 0.5 | 46/80 | 57.5% |
| 0.6 | 46/80 | 57.5% |
| 0.7 | 46/80 | 57.5% |
| 0.8 | 40/80 | 50.0% |
| 0.9 | 24/80 | 30.0% |
| 1.0 | 24/80 | 30.0% |

0.5–0.7 구간 안정 평탄대. 0.8에서 급락. 본 보고서 default 0.8 사용 — 보수적 (=엄격) 선택.

### 2.12 결과: 응답 길이 통계 (cost proxy)

| 통계 | 값 (chars) |
|---|---:|
| 응답 trial 수 | 55 |
| 평균 길이 | 1072 |
| Median | 1064 |
| p5 / p95 | 372 / 2198 |
| Min / Max | 325 / 2487 |

평균 ≈ 268 토큰 / trial. gpt-4o-mini 출력가 $0.6/1M 토큰 기준 trial당 ≈ $0.00016. 80 trial 총 ≈ $0.013 (무료 tier 한도 내).

### 2.13 실패 사례 (Case Study)

#### Case 1 — `wrong_arg_count` (런타임 실패, 16건 중 대표)

Pattern 06 trial 0 (cryptography encrypt complex) LLM 출력 일부:
```python
# AST 검증은 통과 (인스턴스 생성/메서드명 모두 valid해 보임)
shared_secret = KeyEncapsulation.decap_secret(kem_ct, ciphertext_kem)
```
런타임 오류:
```
TypeError: KeyEncapsulation.decap_secret() takes 2 positional arguments but 3 were given
```
원인: 인스턴스 메서드를 클래스 메서드로 호출. AST 단계에선 `클래스명.메서드()`가 인스턴스 호출과 구조적으로 구분 어려움. 런타임 호출 시점에 비로소 `self` 자리 데이터가 들어가 인자 수 불일치로 실패.

#### Case 2 — `wrong_kwarg`

Pattern 08 trial 0 (cryptography kex complex):
```python
kem = oqs.KeyEncapsulation("ML-KEM-768", public_key=peer_pub)
```
오류:
```
TypeError: KeyEncapsulation.__init__() got an unexpected keyword argument 'public_key'
```
원인: LLM이 `public_key`를 constructor에 전달할 수 있다고 환각. 실제 API는 `secret_key`만 옵션 인자.

#### Case 3 — `method_hallucination`

Pattern 11 trial 1 (pycryptodome encrypt simple):
```python
public_key_obj = kem.import_public_key(public_key_bytes)
```
오류:
```
AttributeError: 'KeyEncapsulation' object has no attribute 'import_public_key'
```
원인: 존재하지 않는 메서드 발명. RSA에서 `RSA.import_key`가 있다는 사전 지식이 oqs API로 전이.

#### Case 4 — `no_migration` (6건)

Pattern 04 trial 0 (cryptography kex simple):
```python
import oqs  # 추가만 됨
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ... RSA 코드 그대로 ...
```
AST 검증 차단 사유: `"oqs.KeyEncapsulation 또는 oqs.Signature 미사용 — 마이그레이션 미적용"`. LLM이 oqs를 import만 추가하고 본문은 RSA 그대로 유지.

#### Case 5 — `missing_instance_construction` (20건, 가장 흔함)

Pattern 02 trial 0:
```python
from oqs import KeyEncapsulation, Signature

def encrypt_message(public_key, message):
    return KeyEncapsulation.encap_secret(public_key, message)  # 클래스 직접 호출
```
AST 검증 차단 사유: `"KeyEncapsulation(...) 인스턴스 생성 패턴 없음"`.

### 2.14 평가 B의 한계

1. **단일 모델**: gpt-4o-mini만. 더 큰 모델(GPT-4o, Claude, Gemini Pro)은 결과 다를 가능성. **외부 타당성 가장 큰 약점**.
2. **합성 패턴 N=16**: 실제 OSS 코드의 길이/스타일/주변 컨텍스트를 대표하지 못함.
3. **Rate limit 편향**: 25/80 trial이 LLM API error로 종료, 특히 패턴 13-16. 효과적 N이 패턴별로 균형 X.
4. **저자 정의 ground truth**: 정답 16개와 평가 기준 모두 저자가 작성. Self-fulfilling 위험. Inter-annotator agreement 미측정.
5. **Naive prompt 비교 부재**: PR #82의 정성스러운 프롬프트 vs 짧은 naive 프롬프트의 비교 없음 → 프롬프트 엔지니어링의 기여도 분리 불가.
6. **L4는 AST feature 매칭 근사**: 완전한 의미 동등성 분석은 결정 불가능. 우리 metric은 보수적 근사.
7. **temperature=0 한정**: stochasticity 평가 부재. k=5는 같은 입력에 대한 모델 일관성 측정용이지 다양성 평가 아님.

---

## 3. 두 평가의 통합 관찰

### 3.1 함정의 분리성

평가 A의 도구 체인 함정(F-1~F-6)과 평가 B의 LLM 자동화 실패(taxonomy 7종)는 서로 다른 층에서 발생:

| 차원 | 평가 A (도구 체인) | 평가 B (LLM 자동화) |
|---|---|---|
| 발생 위치 | infrastructure / container / config | application code |
| 발생 시점 | deploy / TLS handshake | function call (런타임) |
| 검증 도구 | integration test / matrix CI | unit test / AST analyzer |
| 표준 도구 탐지 | Trivy/Semgrep/CBOM 모두 ❌ (6/6) | semgrep RSA 룰 ⭕ (탐지) but 마이그레이션 자체 검증은 ❌ |
| 방어책 | 자체 빌드 + 매트릭스 CI | AST + semantic test 다층 검증 |

### 3.2 다층 방어가 양쪽에서 모두 필수

- 평가 A: 자체 빌드(예방) + 매트릭스 CI(감지)의 두 layer가 필요
- 평가 B: AST 검증(빠른 거부) + semantic test(시그니처 환각 차단)의 두 layer가 필요

평가 A·B 모두에서 **단일 layer만으로는 0/6 또는 모든 카테고리 100% 통과 불가**.

### 3.3 LLM이 학습 분포 외에서 약함

평가 B의 L4 ≫ L3 = 0 결과는, gpt-4o-mini가 oqs-python의 *외형*은 학습 데이터에서 충분히 봤지만 (구조적 매칭 50%) 정확한 *시그니처*는 학습 분포에 충분하지 않음을 시사. 이는 평가 A의 F-3(code point 충돌)과 같은 기제 — 표준화 직후 라이브러리 API의 변동성이 LLM과 도구 체인 양쪽에 동일한 형태의 함정을 만든다.

---

## 4. 산출물 (재현용)

```
artifacts/eval/
├── evaluation-report.md              # 본 문서
├── infra-failure-catalog.md          # 평가 A 상세 (F-1~F-6)
├── benchmark-spec.md                 # 평가 B 설계
├── HOW_TO_RUN.md                     # 재현 명령
├── Dockerfile                        # liboqs 0.14 + oqs-python 0.14.1 환경
├── eval_runner.py                    # L1~L4 자동 실행
├── analyze.py                        # 11개 표 + 케이스 스터디 자동 생성
├── benchmark/
│   ├── patterns/   (16 RSA 입력)
│   ├── reference/  (16 oqs-python 정답)
│   └── results/
│       ├── sanity.json               # 정답 자기 회귀 (16/16/16)
│       ├── baseline.json             # RSA 그대로 (0/0/0)
│       ├── llm_k5.json               # 본 측정 80 trial
│       └── analysis.md               # 자동 생성 분석 보고서
└── harness/
    ├── ast_validator.py              # L2
    ├── llm_client.py                 # L1
    ├── semantic_tests.py             # L3 (16 테스트)
    └── equivalence.py                # L4
```

**관련 PR (인프라 함정 사례 출처)**:
- PR #71: OQS 이미지 sha256 핀 도입 — F-2, F-5 발견 계기
- PR #76: nginx 이미지 :0.11.0 태그 회귀 — F-2 임시 대응
- PR #84: 자체 빌드로 OQS 라인 통일 — F-1, F-3, F-4, F-6 근본 해결
- PR #83: Stage 2/3 matrix CI — 함정 회귀 자동 감지
- PR #82: AI 마이그레이션 PoC — 평가 B의 입력 프롬프트 출처

**측정 환경**:
- 호스트: Windows 10 Pro + Docker Desktop
- 평가 컨테이너: python:3.11-slim + liboqs 0.14.0 + liboqs-python 0.14.1
- LLM endpoint: GitHub Models (`models.inference.ai.azure.com/chat/completions`)
- 측정 시점: 2026-05-08
- 총 80 trial, 25 API error (rate limit), 효과 N=55
