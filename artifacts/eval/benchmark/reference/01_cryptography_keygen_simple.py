"""Reference 01 — RSA keygen → ML-KEM-768 keygen.

Migration notes:
- oqs.KeyEncapsulation 인스턴스가 비밀 키 상태를 보유 → caller에 인스턴스를 같이 반환해야
  decap 시점에 비밀 키 사용 가능.
- 원래 시그니처 `(private_key, public_key)`는 의미가 바뀜: private_key 자리에 KEM 인스턴스
  객체가 들어가도록 caller 측 변경이 강제됨.
- 모듈 레벨에서 KeyEncapsulation을 인스턴스화하지 않음 (race condition 방지).
"""
import oqs


def generate_keypair():
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    return kem, public_key
