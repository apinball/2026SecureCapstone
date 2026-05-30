"""Reference 15 — PSS ReleaseSigner → ML-DSA-65 ReleaseSigner.

Migration notes:
- 파일 키 형식 PEM → raw bytes.
- ML-DSA가 자체 해싱 포함 → SHA-256 사전 해싱 폐기.
- private 인스턴스는 oqs.Signature 객체로 비밀 상태 보존.
- verify 예외 처리 단순화: oqs.Signature.verify는 bool 반환.
"""
from pathlib import Path

import oqs


class ReleaseSigner:
    SIG_ALG = "ML-DSA-65"

    def __init__(self, private_key_path: Path | None = None, public_key_path: Path | None = None):
        self.signer: oqs.Signature | None = None
        self.public_key: bytes | None = None
        if private_key_path:
            secret = Path(private_key_path).read_bytes()
            self.signer = oqs.Signature(self.SIG_ALG, secret_key=secret)
        if public_key_path:
            self.public_key = Path(public_key_path).read_bytes()

    def sign_artifact(self, artifact_path: Path, sig_path: Path) -> None:
        if self.signer is None:
            raise RuntimeError("비밀 키 미로드")
        message = Path(artifact_path).read_bytes()
        Path(sig_path).write_bytes(self.signer.sign(message))

    def verify_artifact(self, artifact_path: Path, sig_path: Path) -> bool:
        if self.public_key is None:
            raise RuntimeError("공개 키 미로드")
        message = Path(artifact_path).read_bytes()
        sig = Path(sig_path).read_bytes()
        with oqs.Signature(self.SIG_ALG) as verifier:
            return verifier.verify(message, sig, self.public_key)
