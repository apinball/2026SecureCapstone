"""Reference 08 — RSA-OAEP SessionKeyExchange → ML-KEM-768 encap/decap.

Migration notes:
- ML-KEM은 자체로 키 교환 프리미티브이므로 별도 세션 키 생성/wrap 단계 폐기. encap이 곧
  ciphertext_kem과 shared_secret(세션 키 역할)을 동시에 산출.
- initiate는 세션 키(=shared_secret)를 반환. respond는 비밀 키 인스턴스로 decap하여 동일
  shared_secret 도출.
- wrapped 파일 형식이 RSA-OAEP ciphertext에서 ML-KEM ciphertext로 바뀜.
"""
from pathlib import Path

import oqs


class SessionKeyExchange:
    KEM_ALG = "ML-KEM-768"

    def __init__(self, peer_pub_path: Path | None = None, my_priv_path: Path | None = None):
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
        ciphertext_kem = Path(wrapped_path).read_bytes()
        return self.kem.decap_secret(ciphertext_kem)
