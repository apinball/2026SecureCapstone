"""Reference 06 — RSA-OAEP SecureMessenger → ML-KEM-768 + AES-GCM.

Migration notes:
- 키 저장 형식이 PEM에서 raw bytes로 바뀜. .pem 경로 인자를 그대로 받지만 파일 내용은 raw bytes 가정.
- 비밀 키는 oqs.KeyEncapsulation의 secret_key 파라미터로 import 후 인스턴스에 보존.
- 파일 ciphertext 형식: ciphertext_kem || nonce(12) || aead_ct.
- AES-GCM 결합 누락 시 임의 메시지 암호화 불가 → 보안 회귀.
"""
import os
from pathlib import Path

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureMessenger:
    KEM_ALG = "ML-KEM-768"

    def __init__(self, public_key_path: Path | None = None, private_key_path: Path | None = None):
        self.public_key: bytes | None = None
        self.kem: oqs.KeyEncapsulation | None = None
        if public_key_path:
            self.public_key = Path(public_key_path).read_bytes()
        if private_key_path:
            secret = Path(private_key_path).read_bytes()
            self.kem = oqs.KeyEncapsulation(self.KEM_ALG, secret_key=secret)

    def encrypt_file(self, plaintext_path: Path, ciphertext_path: Path) -> None:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(plaintext_path).read_bytes()
        with oqs.KeyEncapsulation(self.KEM_ALG) as kem:
            kem_ct, shared_secret = kem.encap_secret(self.public_key)
        nonce = os.urandom(12)
        aead = AESGCM(shared_secret[:32])
        aead_ct = aead.encrypt(nonce, message, None)
        Path(ciphertext_path).write_bytes(kem_ct + nonce + aead_ct)

    def decrypt_file(self, ciphertext_path: Path, plaintext_path: Path) -> None:
        if self.kem is None:
            raise RuntimeError("비밀 키 미로드")
        blob = Path(ciphertext_path).read_bytes()
        kem_ct_len = self.kem.details["length_ciphertext"]
        kem_ct = blob[:kem_ct_len]
        nonce = blob[kem_ct_len : kem_ct_len + 12]
        aead_ct = blob[kem_ct_len + 12 :]
        shared_secret = self.kem.decap_secret(kem_ct)
        aead = AESGCM(shared_secret[:32])
        Path(plaintext_path).write_bytes(aead.decrypt(nonce, aead_ct, None))
