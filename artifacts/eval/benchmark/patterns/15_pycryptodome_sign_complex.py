"""Pattern 15 — PyCryptodome: PSS 기반 ReleaseSigner 클래스 + 파일 IO (복잡).

intent: 릴리스 아티팩트(파일)에 PSS 서명을 부착하고 검증.
expected migration target: ML-DSA-65 기반 ReleaseSigner.
"""
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


class ReleaseSigner:
    def __init__(self, private_key_path: Path | None = None, public_key_path: Path | None = None):
        self.private_key = None
        self.public_key = None
        if private_key_path:
            self.private_key = RSA.import_key(Path(private_key_path).read_bytes())
        if public_key_path:
            self.public_key = RSA.import_key(Path(public_key_path).read_bytes())

    def sign_artifact(self, artifact_path: Path, sig_path: Path) -> None:
        if self.private_key is None:
            raise RuntimeError("비밀 키 미로드")
        h = SHA256.new(Path(artifact_path).read_bytes())
        signer = pss.new(self.private_key)
        Path(sig_path).write_bytes(signer.sign(h))

    def verify_artifact(self, artifact_path: Path, sig_path: Path) -> bool:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        h = SHA256.new(Path(artifact_path).read_bytes())
        verifier = pss.new(self.public_key)
        try:
            verifier.verify(h, Path(sig_path).read_bytes())
            return True
        except (ValueError, TypeError):
            return False
