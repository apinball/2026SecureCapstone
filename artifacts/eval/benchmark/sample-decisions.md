# 샘플 3개의 설계 결정 (검토 요청)

벤치마크 패턴 24개 일괄 작성 전 3개 샘플로 정책 확정. 아래 결정들이 OK면 나머지 21개를 같은 정책으로 일괄 생성.

## 1. 정답에 AES-GCM 결합 포함 ✅ (Pattern 02)

`02_cryptography_encrypt_simple.py`의 정답이 ML-KEM 단독이 아니라 ML-KEM + AES-GCM 결합. 이유:

- KEM은 임의 메시지를 직접 암호화하지 못함 (RSA-OAEP와 본질적으로 다름)
- LLM이 AES-GCM 결합을 누락하면 보안 회귀 — 측정 가치 있는 함정
- 현실적으로 마이그레이션에서 가장 자주 발생하는 실수 중 하나 (정성 분석 시 분류 가능)

**측정 시나리오**: L1(LLM 단독) 결과의 다수가 KEM만 쓰고 메시지 암호화를 빠뜨릴 가능성. AES-GCM 결합 누락을 "Semantic drift" 또는 "Incomplete migration" 카테고리로 분류.

## 2. API 시그니처 변경 허용 ✅ (Pattern 01, 02, 03 모두)

oqs-python은 비밀 키 상태를 인스턴스에 보존 → caller가 `(kem, public_key)` 형태로 받아야 함. 원래 `(private_key, public_key)` 시그니처 보존 불가능. 정답에서 시그니처 변경을 허용하고 docstring에 명시.

**측정 시나리오**: LLM이 시그니처를 강제 보존하려다 모듈 레벨 KEM 인스턴스화(race condition 위험)나 글로벌 변수 사용 같은 안티패턴 생성하는지 측정. 이걸 "Constructor misuse" 카테고리로 분류.

## 3. 키 생성 시 ML-KEM vs ML-DSA 매핑 ⚠️ (Pattern 01)

`01_cryptography_keygen_simple.py`는 RSA 키 쌍 생성만 있고 용도 불명. 정답은 ML-KEM-768 선택. 이유:

- RSA의 가장 흔한 OSS 사용 = 키 교환/암호화 → KEM 매핑이 합리적 디폴트
- 그러나 서명 용도였다면 ML-DSA 매핑이 정답

**대안**: 이 패턴을 두 정답(ML-KEM, ML-DSA) 중 어느 쪽이든 인정하는 "ambiguous" 케이스로 처리. 또는 패턴에 docstring으로 의도(서명/암호화)를 명시해 모호성 제거.

→ **결정 필요**: (a) 의도 명시 (b) 둘 다 정답 인정

## 4. M2Crypto 케이스의 처리 (전체 24개 중 8개 영향)

M2Crypto는 OpenSSL 1.0/1.1 wrapper로, 최근 OSS에서는 거의 deprecated. 그러나 legacy 시스템에서 발견됨. 포함 여부 결정 필요.

**대안**:
- (a) 24 패턴에 포함 (legacy 케이스 평가)
- (b) M2Crypto 제외하고 N=16 (cryptography + PyCryptodome) — 더 깨끗
- (c) M2Crypto 대신 `pyca/cryptography` 다른 API(예: Ed25519, X25519)를 추가 → 현대 OSS 더 잘 반영

→ **결정 필요**

## 5. 복잡도 "복잡(complex)"의 정의

각 케이스의 복잡 패턴이 무엇을 포함할지:
- 클래스 wrapper (KeyManager 같은)
- 파일 IO (PEM 디스크 저장/로드)
- 비동기 (`async def`)
- 커스텀 예외 처리
- 환경 변수에서 키 읽기

→ **결정 필요**: 복잡 패턴에 위 요소 중 몇 개를 포함시킬지 (1개 vs 2-3개 조합)

---

## 진행

위 5가지 결정사항 (3, 4, 5는 명시 결정 필요) 답변 주시면 나머지 21개 패턴을 일괄 생성합니다. 답변 형식:

- 3번: (a) 의도 명시 / (b) 둘 다 정답 인정
- 4번: (a) M2Crypto 포함 / (b) 제외 / (c) 다른 API 대체
- 5번: 복잡 패턴에 어떤 요소 포함 (예: "클래스 wrapper + 파일 IO")
