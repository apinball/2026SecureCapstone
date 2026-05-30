"""Reference 14 — PKCS1_OAEP EnvelopeCipher → ML-KEM-768 + AES-GCM EnvelopeCipher.

Migration notes:
- 공개 키 path는 raw bytes 파일을 가정 (PEM 아님). 비밀 키도 raw bytes.
- 인스턴스에 oqs.KeyEncapsulation을 보유하여 비밀 상태 보존.
- 파일 형식: kem_ct || nonce(12) || tag(16) || aead_ct.
"""
import os
from pathlib import Path

import oqs
from Crypto.Cipher import AES


class EnvelopeCipher:
    KEM_ALG = "ML-KEM-768"

    def __init__(self, public_key_path: Path | None = None, private_key_path: Path | None = None):
        self.public_key: bytes | None = None
        self.kem: oqs.KeyEncapsulation | None = None
        if public_key_path:
            self.public_key = Path(public_key_path).read_bytes()
        if private_key_path:
            secret = Path(private_key_path).read_bytes()
            self.kem = oqs.KeyEncapsulation(self.KEM_ALG, secret_key=secret)

    def encrypt_file(self, src: Path, dst: Path) -> None:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(src).read_bytes()
        with oqs.KeyEncapsulation(self.KEM_ALG) as kem:
            kem_ct, shared_secret = kem.encap_secret(self.public_key)
        nonce = os.urandom(12)
        cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
        aead_ct, tag = cipher.encrypt_and_digest(message)
        Path(dst).write_bytes(kem_ct + nonce + tag + aead_ct)

    def decrypt_file(self, src: Path, dst: Path) -> None:
        if self.kem is None:
            raise RuntimeError("비밀 키 미로드")
        blob = Path(src).read_bytes()
        kem_ct_len = self.kem.details["length_ciphertext"]
        kem_ct = blob[:kem_ct_len]
        nonce = blob[kem_ct_len : kem_ct_len + 12]
        tag = blob[kem_ct_len + 12 : kem_ct_len + 28]
        aead_ct = blob[kem_ct_len + 28 :]
        shared_secret = self.kem.decap_secret(kem_ct)
        cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
        Path(dst).write_bytes(cipher.decrypt_and_verify(aead_ct, tag))
