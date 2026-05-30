"""Reference 11 — PKCS1_OAEP encrypt/decrypt → ML-KEM-768 + AES-GCM.

Migration notes:
- PEM 인자가 raw bytes로 의미 변경 (encrypt) 또는 kem 인스턴스로 변경 (decrypt).
- AES-GCM 결합으로 임의 길이 메시지 처리.
"""
import os

import oqs
from Crypto.Cipher import AES


def encrypt_message(public_key: bytes, message: bytes) -> bytes:
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    nonce = os.urandom(12)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
    aead_ct, tag = cipher.encrypt_and_digest(message)
    return ciphertext_kem + nonce + tag + aead_ct


def decrypt_message(kem, blob: bytes) -> bytes:
    kem_ct_len = kem.details["length_ciphertext"]
    ciphertext_kem = blob[:kem_ct_len]
    nonce = blob[kem_ct_len : kem_ct_len + 12]
    tag = blob[kem_ct_len + 12 : kem_ct_len + 28]
    aead_ct = blob[kem_ct_len + 28 :]
    shared_secret = kem.decap_secret(ciphertext_kem)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(aead_ct, tag)
