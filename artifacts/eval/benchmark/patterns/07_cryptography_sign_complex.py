"""Pattern 07 — cryptography.hazmat: DocumentSigner 클래스 + 파일 IO (복잡).

intent: 파일 단위 서명/검증. 서명은 별도 .sig 파일로 출력.
expected migration target: ML-DSA-65 기반 DocumentSigner.
"""
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class DocumentSigner:
    def __init__(self, private_key_path: Path | None = None, public_key_path: Path | None = None):
        self.private_key = None
        self.public_key = None
        if private_key_path:
            self.private_key = serialization.load_pem_private_key(
                Path(private_key_path).read_bytes(), password=None
            )
        if public_key_path:
            self.public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())

    def sign_file(self, document_path: Path, signature_path: Path) -> None:
        if self.private_key is None:
            raise RuntimeError("비밀 키 미로드")
        message = Path(document_path).read_bytes()
        sig = self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        Path(signature_path).write_bytes(sig)

    def verify_file(self, document_path: Path, signature_path: Path) -> bool:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(document_path).read_bytes()
        sig = Path(signature_path).read_bytes()
        try:
            self.public_key.verify(
                sig,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
