"""Pattern 05 — cryptography.hazmat: KeyManager 클래스 + PEM 파일 IO (복잡).

intent: 키 생성 후 PEM 파일로 저장, 나중에 다시 로드. 일반적인 OSS 사용 패턴.
expected migration target: ML-KEM-768 KeyManager. PEM은 KEM 키에 정의돼 있지 않으므로
raw bytes로 저장 (또는 PKCS#8 PEM 별도 인코딩 — 정답에서 raw bytes 선택).
"""
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyManager:
    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.private_key = None
        self.public_key = None

    def generate(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def save(self, name: str) -> None:
        if self.private_key is None:
            raise RuntimeError("키가 생성되지 않음")
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (self.key_dir / f"{name}.priv.pem").write_bytes(priv_pem)
        (self.key_dir / f"{name}.pub.pem").write_bytes(pub_pem)

    def load(self, name: str) -> None:
        priv_pem = (self.key_dir / f"{name}.priv.pem").read_bytes()
        pub_pem = (self.key_dir / f"{name}.pub.pem").read_bytes()
        self.private_key = serialization.load_pem_private_key(priv_pem, password=None)
        self.public_key = serialization.load_pem_public_key(pub_pem)
