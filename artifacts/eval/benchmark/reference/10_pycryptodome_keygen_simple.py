"""Reference 10 — RSA keygen (PyCryptodome) → ML-KEM-768 keygen.

Migration notes:
- PEM 형식이 ML-KEM에 정의되지 않음. raw bytes로 반환 (또는 호출 측에서 base64 처리).
- KEM 인스턴스가 비밀 상태 보유 → 시그니처 변경: 두 번째 반환값을 (kem_instance, public_key)로.
- 모듈 레벨 인스턴스화 금지.
"""
import oqs


def generate_keypair() -> tuple["oqs.KeyEncapsulation", bytes]:
    """반환: (kem_instance, public_key_bytes)."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    return kem, public_key
