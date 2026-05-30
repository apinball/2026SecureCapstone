"""Pattern 06 — cryptography.hazmat: SecureMessenger 클래스 + 파일 IO (복잡).

intent: 디스크에 저장된 PEM 공개 키로 암호화하여 ciphertext 파일을 출력하고, 비밀 키로 복호.
expected migration target: ML-KEM-768 + AES-GCM, 파일 형식은 (kem_ct || nonce || aead_ct).
"""
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class SecureMessenger:
    def __init__(self, public_key_path: Path | None = None, private_key_path: Path | None = None):
        self.public_key = None
        self.private_key = None
        if public_key_path:
            self.public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if private_key_path:
            self.private_key = serialization.load_pem_private_key(
                Path(private_key_path).read_bytes(), password=None
            )

    def encrypt_file(self, plaintext_path: Path, ciphertext_path: Path) -> None:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(plaintext_path).read_bytes()
        ct = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        Path(ciphertext_path).write_bytes(ct)

    def decrypt_file(self, ciphertext_path: Path, plaintext_path: Path) -> None:
        if self.private_key is None:
            raise RuntimeError("비밀 키 미로드")
        ct = Path(ciphertext_path).read_bytes()
        pt = self.private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        Path(plaintext_path).write_bytes(pt)
