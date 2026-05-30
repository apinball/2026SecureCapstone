"""Reference 13 — RSA KeyVault → ML-KEM-768 KeyVault.

Migration notes:
- 키 파일 형식 PEM → raw bytes (.bin).
- _key 속성 타입이 RSA.RsaKey에서 oqs.KeyEncapsulation으로 변경.
- public_pem 메서드는 호환성 위해 메서드명 유지하되 raw bytes 반환 (의미 변경 docstring 명시).
- KEY_DIR 환경 변수 기반 동작은 보존.
"""
import os
from pathlib import Path

import oqs


class KeyVault:
    KEM_ALG = "ML-KEM-768"

    def __init__(self) -> None:
        self.dir = Path(os.environ.get("KEY_DIR", "./keys"))
        self.dir.mkdir(parents=True, exist_ok=True)
        self._kem: oqs.KeyEncapsulation | None = None

    def generate(self, name: str) -> None:
        kem = oqs.KeyEncapsulation(self.KEM_ALG)
        public_key = kem.generate_keypair()
        secret = kem.export_secret_key()
        (self.dir / f"{name}.priv.bin").write_bytes(secret)
        (self.dir / f"{name}.pub.bin").write_bytes(public_key)
        self._kem = kem

    def load_private(self, name: str) -> None:
        secret = (self.dir / f"{name}.priv.bin").read_bytes()
        self._kem = oqs.KeyEncapsulation(self.KEM_ALG, secret_key=secret)

    def public_pem(self, name: str) -> bytes:
        """호환성 위해 메서드명 유지. 반환은 raw bytes (PEM 인코딩 X)."""
        return (self.dir / f"{name}.pub.bin").read_bytes()

    @property
    def key(self) -> "oqs.KeyEncapsulation":
        if self._kem is None:
            raise RuntimeError("키 미로드")
        return self._kem
