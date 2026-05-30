"""Pattern 14 — PyCryptodome: PKCS1_OAEP 기반 EnvelopeCipher 클래스 (복잡).

intent: 클래스 인스턴스가 키를 보유하고 file 단위로 암호화/복호화.
expected migration target: ML-KEM-768 + AES-GCM, EnvelopeCipher 인스턴스가 KEM 인스턴스 보유.
"""
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class EnvelopeCipher:
    def __init__(self, public_key_path: Path | None = None, private_key_path: Path | None = None):
        self.public_key = None
        self.private_key = None
        if public_key_path:
            self.public_key = RSA.import_key(Path(public_key_path).read_bytes())
        if private_key_path:
            self.private_key = RSA.import_key(Path(private_key_path).read_bytes())

    def encrypt_file(self, src: Path, dst: Path) -> None:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        cipher = PKCS1_OAEP.new(self.public_key, hashAlgo=SHA256)
        Path(dst).write_bytes(cipher.encrypt(Path(src).read_bytes()))

    def decrypt_file(self, src: Path, dst: Path) -> None:
        if self.private_key is None:
            raise RuntimeError("비밀 키 미로드")
        cipher = PKCS1_OAEP.new(self.private_key, hashAlgo=SHA256)
        Path(dst).write_bytes(cipher.decrypt(Path(src).read_bytes()))
