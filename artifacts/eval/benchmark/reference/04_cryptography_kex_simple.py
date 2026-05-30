"""Reference 04 — RSA-OAEP key wrap → ML-KEM-768 encap/decap (자연스러운 KEM 매핑).

Migration notes:
- ML-KEM은 자체적으로 shared_secret을 도출 → 별도 AES 키 생성/wrap 불필요. encap이 곧
  ciphertext_kem과 shared_secret을 동시에 산출.
- 시그니처: wrap_and_encrypt(public_key, msg) → (kem_ct, nonce, aead_ct).
- unwrap_and_decrypt 첫 인자가 private_key 객체에서 kem 인스턴스로 의미 변경.
"""
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def wrap_and_encrypt(public_key: bytes, message: bytes) -> tuple[bytes, bytes, bytes]:
    """반환: (ciphertext_kem, nonce, aead_ciphertext)."""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    aead = AESGCM(shared_secret[:32])
    nonce = os.urandom(12)
    aead_ct = aead.encrypt(nonce, message, None)
    return ciphertext_kem, nonce, aead_ct


def unwrap_and_decrypt(kem, ciphertext_kem: bytes, nonce: bytes, aead_ct: bytes) -> bytes:
    shared_secret = kem.decap_secret(ciphertext_kem)
    aead = AESGCM(shared_secret[:32])
    return aead.decrypt(nonce, aead_ct, None)
