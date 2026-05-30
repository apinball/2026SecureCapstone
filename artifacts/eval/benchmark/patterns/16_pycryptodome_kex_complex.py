"""Pattern 16 — PyCryptodome: HandshakeBroker 클래스 (복잡).

intent: 두 당사자가 디스크 매개체로 세션 키를 교환. initiator는 wrap한 키를 디스크에 두고,
responder가 디스크에서 wrap된 키를 읽어 unwrap.
expected migration target: ML-KEM-768 encap/decap 기반 HandshakeBroker.
"""
import os
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class HandshakeBroker:
    def __init__(
        self, peer_pub_path: Path | None = None, my_priv_path: Path | None = None
    ):
        self.peer_pub = None
        self.my_priv = None
        if peer_pub_path:
            self.peer_pub = RSA.import_key(Path(peer_pub_path).read_bytes())
        if my_priv_path:
            self.my_priv = RSA.import_key(Path(my_priv_path).read_bytes())

    def initiate(self, wrapped_path: Path) -> bytes:
        if self.peer_pub is None:
            raise RuntimeError("peer 공개 키 미로드")
        session_key = os.urandom(32)
        wrapper = PKCS1_OAEP.new(self.peer_pub, hashAlgo=SHA256)
        Path(wrapped_path).write_bytes(wrapper.encrypt(session_key))
        return session_key

    def respond(self, wrapped_path: Path) -> bytes:
        if self.my_priv is None:
            raise RuntimeError("내 비밀 키 미로드")
        unwrapper = PKCS1_OAEP.new(self.my_priv, hashAlgo=SHA256)
        return unwrapper.decrypt(Path(wrapped_path).read_bytes())
