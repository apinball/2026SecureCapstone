"""Reference 03 — RSA-PSS sign/verify → ML-DSA-65 sign/verify.

Migration notes:
- ML-DSA는 자체 해싱을 포함하므로 SHA-256 사전 해싱 + PSS padding 단계 폐기.
- 첫 인자 의미: cryptography RSAPrivateKey 객체 → oqs.Signature 인스턴스 (비밀 상태 보유).
- verify는 raw public_key bytes를 받음.
"""
import oqs


def sign(signer: "oqs.Signature", message: bytes) -> bytes:
    return signer.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(message, signature, public_key)
