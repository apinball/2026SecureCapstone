"""Reference 02 — RSA-OAEP encrypt/decrypt → ML-KEM-768 + AES-GCM 결합.

Migration notes:
- KEM은 직접 메시지를 암호화하지 않음. encap_secret으로 도출한 shared_secret을 AES-GCM 키로
  사용하여 메시지를 AEAD로 암호화. ciphertext = ciphertext_kem || nonce(12) || aead_ct.
- decrypt_message 시그니처가 (private_key, ct) → (kem, ct)로 바뀜. KEM 인스턴스가 비밀 키
  상태를 보유하기 때문. 이 변경이 caller에 강제됨을 docstring에 명시.
- shared_secret 길이는 ML-KEM-768 기준 32 bytes → AES-256-GCM에 그대로 사용.
"""
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(public_key: bytes, message: bytes) -> bytes:
    """공개 키(bytes)로 메시지 암호화. ciphertext_kem || nonce || aead_ct 반환."""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    aead = AESGCM(shared_secret[:32])
    nonce = os.urandom(12)
    aead_ct = aead.encrypt(nonce, message, None)
    return ciphertext_kem + nonce + aead_ct


def decrypt_message(kem, ciphertext: bytes) -> bytes:
    """kem 인스턴스(generate_keypair로 생성, 비밀 상태 포함)로 복호화."""
    kem_ct_len = kem.details["length_ciphertext"]
    ciphertext_kem = ciphertext[:kem_ct_len]
    nonce = ciphertext[kem_ct_len : kem_ct_len + 12]
    aead_ct = ciphertext[kem_ct_len + 12 :]
    shared_secret = kem.decap_secret(ciphertext_kem)
    aead = AESGCM(shared_secret[:32])
    return aead.decrypt(nonce, aead_ct, None)
