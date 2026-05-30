"""Pattern 05 — cryptography.hazmat: KeyManager 클래스 + PEM 파일 IO (복잡).

intent: 키 생성 후 PEM 파일로 저장, 나중에 다시 로드. 일반적인 OSS 사용 패턴.
expected migration target: ML-KEM-768 KeyManager. PEM은 KEM 키에 정의돼 있지 않으므로
raw bytes로 저장 (또는 PKCS#8 PEM 별도 인코딩 — 정답에서 raw bytes 선택).
"""
from pathlib import Path

from oqs import KeyEncapsulation


class KeyManager:
    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.kem = None
        self.public_key = None

    # PQC migration: replaced RSA with ML-KEM
    def generate(self) -> None:
        self.kem = KeyEncapsulation("Kyber768")
        self.public_key = self.kem.generate_keypair()  # returns: bytes (public key)

    def save(self, name: str) -> None:
        if self.kem is None:
            raise RuntimeError("키가 생성되지 않음")
        # Note: No PEM format for KEM keys, saving raw bytes is assumed
        priv_bytes = self.kem.secret_key  # This is a placeholder; actual storage logic may vary
        pub_bytes = self.public_key
        (self.key_dir / f"{name}.priv").write_bytes(priv_bytes)
        (self.key_dir / f"{name}.pub").write_bytes(pub_bytes)

    def load(self, name: str) -> None:
        priv_bytes = (self.key_dir / f"{name}.priv").read_bytes()
        pub_bytes = (self.key_dir / f"{name}.pub").read_bytes()
        # Placeholder for loading logic; actual implementation may vary
        self.kem = KeyEncapsulation("Kyber768")  # Re-instantiate for secret key access
        self.kem.secret_key = priv_bytes  # This is a placeholder; actual loading logic may vary
        self.public_key = pub_bytes
