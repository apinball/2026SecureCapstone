"""Reference 12 — PKCS1_OAEP key wrap → ML-KEM-768 encap/decap.

Migration notes:
- ML-KEM은 자체로 키 교환 프리미티브이므로 AES 키 생성/wrap 단계 폐기.
- 시그니처 변경: unwrap_and_decrypt 첫 인자가 PEM bytes에서 kem 인스턴스로 의미 변경.
- 반환 형식 단순화: (kem_ct, nonce, tag, aead_ct).
"""
import os

import oqs
from Crypto.Cipher import AES


def wrap_and_encrypt(public_key: bytes, message: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    nonce = os.urandom(12)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ciphertext_kem, nonce, tag, ciphertext


def unwrap_and_decrypt(
    kem, ciphertext_kem: bytes, nonce: bytes, tag: bytes, ciphertext: bytes
) -> bytes:
    shared_secret = kem.decap_secret(ciphertext_kem)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
