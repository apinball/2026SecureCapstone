"""Pattern 08 — cryptography.hazmat: SessionKeyExchange 클래스 + 파일 IO (복잡).

intent: 송신자가 임의 세션 키를 RSA-OAEP로 wrap하여 디스크 저장, 수신자가 unwrap하여
세션 키를 디스크에 저장. 양측은 이후 AES-GCM으로 통신.
expected migration target: ML-KEM-768 기반 세션 키 교환 (encap/decap → shared secret 디스크 저장).
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class SessionKeyExchange:
    def __init__(self, peer_pub_path: Path | None = None, my_priv_path: Path | None = None):
        self.peer_pub = None
        self.my_priv = None
        if peer_pub_path:
            self.peer_pub = serialization.load_pem_public_key(Path(peer_pub_path).read_bytes())
        if my_priv_path:
            self.my_priv = serialization.load_pem_private_key(
                Path(my_priv_path).read_bytes(), password=None
            )

    def initiate(self, wrapped_path: Path) -> bytes:
        """송신자 측: 새 세션 키 생성 후 peer 공개 키로 wrap, 디스크 저장. 세션 키 반환."""
        if self.peer_pub is None:
            raise RuntimeError("peer 공개 키 미로드")
        session_key = os.urandom(32)
        wrapped = self.peer_pub.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        Path(wrapped_path).write_bytes(wrapped)
        return session_key

    def respond(self, wrapped_path: Path) -> bytes:
        """수신자 측: 디스크에서 wrapped 키 로드 후 unwrap. 세션 키 반환."""
        if self.my_priv is None:
            raise RuntimeError("내 비밀 키 미로드")
        wrapped = Path(wrapped_path).read_bytes()
        session_key = self.my_priv.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return session_key
