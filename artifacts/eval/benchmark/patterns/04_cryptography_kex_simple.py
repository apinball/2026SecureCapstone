"""Pattern 04 — cryptography.hazmat: RSA-OAEP 기반 AES 세션 키 래핑 (key exchange).

intent: 송신자가 임의 AES 키를 생성하여 RSA-OAEP로 wrap, 수신자가 unwrap 후 AES-GCM 복호.
expected migration target: ML-KEM-768 + AES-GCM (KEM은 자체로 키 교환 프리미티브).
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def wrap_and_encrypt(public_key, message: bytes) -> tuple[bytes, bytes, bytes]:
    """반환: (wrapped_aes_key, nonce, ciphertext)."""
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aead = AESGCM(aes_key)
    ciphertext = aead.encrypt(nonce, message, None)
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped, nonce, ciphertext


def unwrap_and_decrypt(private_key, wrapped: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aes_key = private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aead = AESGCM(aes_key)
    return aead.decrypt(nonce, ciphertext, None)
