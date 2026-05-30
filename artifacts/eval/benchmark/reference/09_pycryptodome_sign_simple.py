"""Reference 03 — RSA-PKCS1v15 sign/verify → ML-DSA-65 sign/verify.

Migration notes:
- sign 첫 인자 `private_key_pem: bytes`가 `signer: oqs.Signature`로 의미 변경. ML-DSA는
  비밀 키를 인스턴스에 보존하므로 PEM에서 매번 import 불가. 호출 측은 미리 generate_keypair
  로 인스턴스를 만들어 보관해야 함.
- ML-DSA는 자체 해싱 포함 (SHA-256 사전 해싱 단계 불필요).
- verify 두 번째 인자는 그대로 PEM 대신 raw public_key bytes를 받음 (oqs API 규약).
- 예외 처리: oqs.Signature.verify는 bool 반환이라 try/except 폐기 가능.
"""
import oqs


def sign(signer: "oqs.Signature", message: bytes) -> bytes:
    """signer는 generate_keypair()로 만든 oqs.Signature 인스턴스."""
    return signer.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """공개 키(raw bytes)로 ML-DSA-65 서명 검증."""
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(message, signature, public_key)
