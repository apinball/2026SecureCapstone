"""Reference 05 — RSA KeyManager → ML-KEM-768 KeyManager.

Migration notes:
- ML-KEM에는 PEM 표준 인코딩이 정의되지 않음. 정답에서는 raw bytes를 그대로 저장 (.bin 확장자).
- 비밀 키 export: oqs.KeyEncapsulation 인스턴스의 export_secret_key() 사용.
- load 시 import_secret_key()로 비밀 상태 복원. 인스턴스의 라이프사이클 관리가 PEM 기반 RSA와
  본질적으로 다름 → 모듈 레벨에서 인스턴스화하지 말고 KeyManager 인스턴스 안에서 보유.
"""
from pathlib import Path

import oqs


class KeyManager:
    KEM_ALG = "ML-KEM-768"

    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.kem: oqs.KeyEncapsulation | None = None
        self.public_key: bytes | None = None

    def generate(self) -> None:
        self.kem = oqs.KeyEncapsulation(self.KEM_ALG)
        self.public_key = self.kem.generate_keypair()

    def save(self, name: str) -> None:
        if self.kem is None or self.public_key is None:
            raise RuntimeError("키가 생성되지 않음")
        secret = self.kem.export_secret_key()
        (self.key_dir / f"{name}.priv.bin").write_bytes(secret)
        (self.key_dir / f"{name}.pub.bin").write_bytes(self.public_key)

    def load(self, name: str) -> None:
        secret = (self.key_dir / f"{name}.priv.bin").read_bytes()
        self.public_key = (self.key_dir / f"{name}.pub.bin").read_bytes()
        self.kem = oqs.KeyEncapsulation(self.KEM_ALG, secret_key=secret)
