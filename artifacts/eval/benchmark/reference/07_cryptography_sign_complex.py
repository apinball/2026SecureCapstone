"""Reference 07 — RSA-PSS DocumentSigner → ML-DSA-65 DocumentSigner.

Migration notes:
- 비밀 키 저장 형식: PEM → raw bytes. oqs.Signature(secret_key=...)로 import 후 인스턴스 보존.
- 공개 키도 raw bytes 파일에서 직접 로드.
- ML-DSA는 자체 해싱 포함 → 별도 SHA-256/PSS padding 불필요.
"""
from pathlib import Path

import oqs


class DocumentSigner:
    SIG_ALG = "ML-DSA-65"

    def __init__(self, private_key_path: Path | None = None, public_key_path: Path | None = None):
        self.signer: oqs.Signature | None = None
        self.public_key: bytes | None = None
        if private_key_path:
            secret = Path(private_key_path).read_bytes()
            self.signer = oqs.Signature(self.SIG_ALG, secret_key=secret)
        if public_key_path:
            self.public_key = Path(public_key_path).read_bytes()

    def sign_file(self, document_path: Path, signature_path: Path) -> None:
        if self.signer is None:
            raise RuntimeError("비밀 키 미로드")
        message = Path(document_path).read_bytes()
        sig = self.signer.sign(message)
        Path(signature_path).write_bytes(sig)

    def verify_file(self, document_path: Path, signature_path: Path) -> bool:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(document_path).read_bytes()
        sig = Path(signature_path).read_bytes()
        with oqs.Signature(self.SIG_ALG) as verifier:
            return verifier.verify(message, sig, self.public_key)
