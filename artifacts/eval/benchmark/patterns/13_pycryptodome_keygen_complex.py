"""Pattern 13 — PyCryptodome: KeyVault 클래스 + 환경 변수/파일 IO (복잡).

intent: KEY_DIR 환경 변수에서 디렉토리 결정, 키 생성 후 PEM 파일로 저장. 로드 시 디스크에서 읽음.
expected migration target: ML-KEM-768 KeyVault. raw bytes로 저장.
"""
import os
from pathlib import Path

from Crypto.PublicKey import RSA


class KeyVault:
    def __init__(self) -> None:
        self.dir = Path(os.environ.get("KEY_DIR", "./keys"))
        self.dir.mkdir(parents=True, exist_ok=True)
        self._key: RSA.RsaKey | None = None

    def generate(self, name: str) -> None:
        key = RSA.generate(2048)
        (self.dir / f"{name}.priv.pem").write_bytes(key.export_key(format="PEM"))
        (self.dir / f"{name}.pub.pem").write_bytes(key.publickey().export_key(format="PEM"))
        self._key = key

    def load_private(self, name: str) -> None:
        pem = (self.dir / f"{name}.priv.pem").read_bytes()
        self._key = RSA.import_key(pem)

    def public_pem(self, name: str) -> bytes:
        return (self.dir / f"{name}.pub.pem").read_bytes()

    @property
    def key(self) -> RSA.RsaKey:
        if self._key is None:
            raise RuntimeError("키 미로드")
        return self._key
