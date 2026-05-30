"""Reference 16 — PKCS1_OAEP HandshakeBroker → ML-KEM-768 HandshakeBroker.

Migration notes:
- AES 세션 키 생성/wrap 단계 폐기. KEM encap이 곧 (ciphertext, shared_secret).
- responder는 oqs.KeyEncapsulation 인스턴스로 decap → shared_secret이 세션 키 역할.
- 키 파일 형식 PEM → raw bytes. wrapped_path 파일은 ML-KEM ciphertext.
"""
from pathlib import Path

import oqs


class HandshakeBroker:
    KEM_ALG = "ML-KEM-768"

    def __init__(
        self, peer_pub_path: Path | None = None, my_priv_path: Path | None = None
    ):
        self.peer_pub: bytes | None = None
        self.kem: oqs.KeyEncapsulation | None = None
        if peer_pub_path:
            self.peer_pub = Path(peer_pub_path).read_bytes()
        if my_priv_path:
            secret = Path(my_priv_path).read_bytes()
            self.kem = oqs.KeyEncapsulation(self.KEM_ALG, secret_key=secret)

    def initiate(self, wrapped_path: Path) -> bytes:
        if self.peer_pub is None:
            raise RuntimeError("peer 공개 키 미로드")
        with oqs.KeyEncapsulation(self.KEM_ALG) as kem:
            ciphertext_kem, shared_secret = kem.encap_secret(self.peer_pub)
        Path(wrapped_path).write_bytes(ciphertext_kem)
        return shared_secret

    def respond(self, wrapped_path: Path) -> bytes:
        if self.kem is None:
            raise RuntimeError("내 비밀 키 미로드")
        return self.kem.decap_secret(Path(wrapped_path).read_bytes())
