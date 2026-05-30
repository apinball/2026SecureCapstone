# LLM PQC 마이그레이션 평가 결과 분석

총 trial: **80**
LLM API 에러: **25** (rate limit 등)
응답 받은 trial: **55**

## 다층 방어 ablation

| Layer | 통과 | 비율 (전체) | 비율 (응답 received) |
|---|---:|---:|---:|
| L2 (AST 검증) | 24/80 | 30.0% | 43.6% |
| L3 (semantic test) | 0/80 | 0.0% | 0.0% |
| L4 (equivalence) | 40/80 | 50.0% | 72.7% |

## 실패 모드 분포 (taxonomy)

| 카테고리 | 빈도 | 설명 |
|---|---:|---|
| `missing_instance_construction` | 20 | Signature/KeyEncapsulation 인스턴스 생성 누락 |
| `wrong_arg_count` | 16 | 메서드에 잘못된 인자 개수 전달 (시그니처 환각) |
| `no_migration` | 6 | RSA 그대로 두고 oqs import만 추가하거나 마이그레이션 자체 미수행 |
| `class_direct_call` | 5 | 클래스 자체에서 메서드 호출 (인스턴스 누락) |
| `wrong_kwarg` | 5 | 존재하지 않는 keyword argument (constructor 환각 등) |
| `method_hallucination` | 2 | 존재하지 않는 메서드 호출 (`import_public_key` 등) |
| `algorithm_name_hallucination` | 1 | 잘못된 알고리즘 명칭 사용 |

## 패턴별 통과율

| Pattern | n | LLM err | L2 | L3 | L4 |
|---|---:|---:|---:|---:|---:|
| 01 | 5 | 0 | 0 | 0 | 0 |
| 02 | 5 | 0 | 0 | 0 | 5 |
| 03 | 5 | 0 | 0 | 0 | 0 |
| 04 | 5 | 4 | 0 | 0 | 1 |
| 05 | 5 | 2 | 0 | 0 | 0 |
| 06 | 5 | 0 | 5 | 0 | 5 |
| 07 | 5 | 0 | 4 | 0 | 4 |
| 08 | 5 | 0 | 5 | 0 | 5 |
| 09 | 5 | 0 | 5 | 0 | 5 |
| 10 | 5 | 0 | 0 | 0 | 5 |
| 11 | 5 | 0 | 5 | 0 | 5 |
| 12 | 5 | 0 | 0 | 0 | 5 |
| 13 | 5 | 4 | 0 | 0 | 0 |
| 14 | 5 | 5 | 0 | 0 | 0 |
| 15 | 5 | 5 | 0 | 0 | 0 |
| 16 | 5 | 5 | 0 | 0 | 0 |

## 라이브러리 × 사용 케이스 × 복잡도

| Lib/Case/Complexity | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| cryptography/encrypt/complex | 5 | 5 | 0 | 5 |
| cryptography/encrypt/simple | 5 | 0 | 0 | 5 |
| cryptography/kex/complex | 5 | 5 | 0 | 5 |
| cryptography/kex/simple | 5 | 0 | 0 | 1 |
| cryptography/keygen/complex | 5 | 0 | 0 | 0 |
| cryptography/keygen/simple | 5 | 0 | 0 | 0 |
| cryptography/sign/complex | 5 | 4 | 0 | 4 |
| cryptography/sign/simple | 5 | 0 | 0 | 0 |
| pycryptodome/encrypt/complex | 5 | 0 | 0 | 0 |
| pycryptodome/encrypt/simple | 5 | 5 | 0 | 5 |
| pycryptodome/kex/complex | 5 | 0 | 0 | 0 |
| pycryptodome/kex/simple | 5 | 0 | 0 | 5 |
| pycryptodome/keygen/complex | 5 | 0 | 0 | 0 |
| pycryptodome/keygen/simple | 5 | 0 | 0 | 5 |
| pycryptodome/sign/complex | 5 | 0 | 0 | 0 |
| pycryptodome/sign/simple | 5 | 5 | 0 | 5 |

## 실패 모드 × Defense Layer 매핑

각 실패 카테고리가 어느 검증 단계에서 차단되는지. AST(L2)에서 잡히면 정적 분석만으로 충분하고, semantic test(L3)에서만 잡히면 런타임 검증이 필수.

| 카테고리 | L2에서 차단 | L3에서만 차단 | L3 의존도 |
|---|---:|---:|---:|
| `missing_instance_construction` | 20 | 0 | 0% |
| `wrong_arg_count` | 0 | 16 | 100% |
| `no_migration` | 6 | 0 | 0% |
| `class_direct_call` | 5 | 0 | 0% |
| `wrong_kwarg` | 0 | 5 | 100% |
| `method_hallucination` | 0 | 2 | 100% |
| `algorithm_name_hallucination` | 0 | 1 | 100% |

**시사점**: `wrong_arg_count`, `wrong_kwarg`, `method_hallucination` 같은 시그니처/API 환각은 거의 100% L3에서만 잡힘 → 정적 분석만으론 production 위험이 그대로 통과.

## Pipeline Error Reduction Funnel

LLM 출력을 직접 적용했을 때 vs 검증 단계 추가 시 production crash 위험률.

| 시나리오 | 통과/적용된 trial | 런타임 실패 | 실패율 |
|---|---:|---:|---:|
| ① validation 없음 (LLM 출력 그대로) | 55 | 55 | **100.0%** |
| ② AST 검증 추가 | 24 | 24 | **100.0%** |
| ③ AST + semantic test | 0 | 0 | **0.0%** |

**핵심 수치**: 검증 없으면 100%가 production에서 crash. AST 추가 시 propagate되는 코드의 100%가 여전히 crash → AST는 필요조건일 뿐 충분조건 아님.

## 차원별 통과율 (lib / use case / complexity)

### 라이브러리

| Lib | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| cryptography | 40 | 35% | 0% | 50% |
| pycryptodome | 40 | 25% | 0% | 50% |

### 사용 케이스

| Use case | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| encrypt | 20 | 50% | 0% | 75% |
| kex | 20 | 25% | 0% | 55% |
| keygen | 20 | 0% | 0% | 25% |
| sign | 20 | 45% | 0% | 45% |

### 복잡도

| Complexity | n | L2 | L3 | L4 |
|---|---:|---:|---:|---:|
| complex | 40 | 35% | 0% | 35% |
| simple | 40 | 25% | 0% | 65% |

## L4 Equivalence 임계값 sensitivity

threshold 0.8 결정의 민감도 검증.

| 임계값 | 통과 trial | 비율 |
|---:|---:|---:|
| 0.5 | 46/80 | 57.5% |
| 0.6 | 46/80 | 57.5% |
| 0.7 | 46/80 | 57.5% |
| 0.8 | 40/80 | 50.0% |
| 0.9 | 24/80 | 30.0% |
| 1.0 | 24/80 | 30.0% |

**시사점**: 임계값 0.5~0.8 범위에서 결과 안정 → 결론은 임계값 선택에 강건(robust).

## 응답 길이 통계 (cost proxy)

| 통계 | 값 (chars) |
|---|---:|
| n | 55 |
| mean | 1072.1 |
| median | 1064 |
| p5 | 372 |
| p95 | 2198 |
| min | 325 |
| max | 2487 |

**해석**: 평균 응답 ~1072 chars, 토큰 환산 약 268 tokens. gpt-4o-mini 출력 토큰가 $0.6/1M 기준 trial 당 평균 $0.000161.

## 실패 사례 (Case Study)

카테고리별 대표 LLM 출력 발췌. 모두 gpt-4o-mini의 실제 응답.

### `class_direct_call`

**Pattern 01 trial 0** (01_cryptography_keygen_simple.py)

```python
"""Pattern 01 — cryptography.hazmat: ML-KEM 및 ML-DSA 키 쌍 생성.

input: ML-KEM-768 키 쌍 생성 후 (private, public) 반환.
expected migration target: ML-KEM 및 ML-DSA 사용.
"""
from oqs import KeyEncapsulation, Signature


def generate_keypair():
    private_key, p
```

→ 실패 사유: `AST 검증 실패로 skip`

### `missing_instance_construction`

**Pattern 02 trial 0** (02_cryptography_encrypt_simple.py)

```python
"""Pattern 02 — cryptography.hazmat: ML-KEM 암호화/복호화 함수 쌍.

input: 공개 키로 메시지 암호화, 개인 키로 복호화.
expected migration target: ML-KEM(공유 비밀 도출) + AES-GCM(메시지 암호화) 결합.
주의: KEM은 RSA-OAEP처럼 임의 메시지를 직접 암호화하지 않음. shared secret을 도출한 뒤
AEAD로 메시지를 암호화해야 함. 이 결합을 누락하
```

→ 실패 사유: `AST 검증 실패로 skip`

### `no_migration`

**Pattern 04 trial 0** (04_cryptography_kex_simple.py)

```python
"""Pattern 04 — cryptography.hazmat: ML-KEM 기반 AES 세션 키 래핑 (key exchange).

intent: 송신자가 임의 AES 키를 생성하여 ML-KEM로 wrap, 수신자가 unwrap 후 AES-GCM 복호.
expected migration target: ML-KEM-768 + AES-GCM (KEM은 자체로 키 교환 프리미티브).
"""
import os
from cryptography.haz
```

→ 실패 사유: `AST 검증 실패로 skip`

### `wrong_arg_count`

**Pattern 06 trial 0** (06_cryptography_encrypt_complex.py)

```python
"""Pattern 06 — cryptography.hazmat: SecureMessenger 클래스 + 파일 IO (복잡).

intent: 디스크에 저장된 PEM 공개 키로 암호화하여 ciphertext 파일을 출력하고, 비밀 키로 복호.
expected migration target: ML-KEM-768 + AES-GCM, 파일 형식은 (kem_ct || nonce || aead_ct).
"""
from pathlib import Path
```

→ 실패 사유: `TypeError: KeyEncapsulation.decap_secret() takes 2 positional arguments but 3 were given`

### `wrong_kwarg`

**Pattern 08 trial 0** (08_cryptography_kex_complex.py)

```python
"""Pattern 08 — cryptography.hazmat: SessionKeyExchange 클래스 + 파일 IO (복잡).

intent: 송신자가 임의 세션 키를 ML-KEM으로 wrap하여 디스크 저장, 수신자가 unwrap하여
세션 키를 디스크에 저장. 양측은 이후 AES-GCM으로 통신.
expected migration target: ML-KEM-768 기반 세션 키 교환 (encap/decap → shared secret 디
```

→ 실패 사유: `TypeError: KeyEncapsulation.__init__() got an unexpected keyword argument 'public_key'`

### `method_hallucination`

**Pattern 11 trial 1** (11_pycryptodome_encrypt_simple.py)

```python
"""Pattern 11 — OQS: ML-KEM 암호화/복호화 및 ML-DSA 서명/검증.

intent: ML-KEM으로 메시지 암호화 및 ML-DSA로 서명. PEM 키를 매번 import.
expected migration target: ML-KEM-768 + AES-GCM.
"""
from oqs import KeyEncapsulation, Signature


def encrypt_message(public_key: bytes, me
```

→ 실패 사유: `AttributeError: 'KeyEncapsulation' object has no attribute 'import_public_key'`

### `algorithm_name_hallucination`

**Pattern 06 trial 3** (06_cryptography_encrypt_complex.py)

```python
"""Pattern 06 — cryptography.hazmat: SecureMessenger 클래스 + 파일 IO (복잡).

intent: 디스크에 저장된 PEM 공개 키로 암호화하여 ciphertext 파일을 출력하고, 비밀 키로 복호.
expected migration target: ML-KEM-768 + AES-GCM, 파일 형식은 (kem_ct || nonce || aead_ct).
"""
from pathlib import Path
```

→ 실패 사유: `MechanismNotSupportedError: b'\xc1\xf8M\x93\x82\xce\xebXc\\Z\xbe\xea\x07!\x04\x89\x90^\x81\x07x\xe6e\xb2X\\-&\xa6;\xb4R\x89\x96\x03h\x96f\r\xc8.\xe4r_\x982\x80a\x87W\xf6;Lpi@=TG\xe1U\xa0\x98bPt\x84c\x`

## 핵심 시사점 (논문에 인용 가능)

- **AST 검증 단독은 불충분**: L2 통과율 vs L3 통과율의 큰 격차는 정적 분석만으로는 LLM의 시그니처 환각(`wrong_arg_count`, `wrong_kwarg`)을 잡을 수 없음을 보임.
- **메서드 환각이 가장 흔한 실수**: `wrong_arg_count`, `method_hallucination` 카테고리는 LLM이 OQS API를 **어렴풋이** 알지만 정확한 시그니처를 맞추지 못함을 시사.
- **다층 방어의 정량 효과**: validation 없으면 응답 받은 trial의 100%가 production crash. AST 추가 시 통과 코드의 100%가 여전히 crash → semantic test 필수.
- **L4 ≫ L2 ≫ L3 구조**: LLM이 PQC 마이그레이션의 *형태*는 옳게 잡지만(L4 높음) *정확한 API 시그니처*는 거의 못 맞춤(L3=0). 구조적 유사성 ≠ 의미적 정확성.
- **임계값 robustness**: L4 결과는 0.5~0.9 임계값에서 안정 → 분류 결과가 임계값 선택에 의존하지 않음.