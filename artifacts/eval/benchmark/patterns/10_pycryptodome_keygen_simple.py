"""Pattern 10 — PyCryptodome: 단순 RSA 키 쌍 생성.

intent: 키 교환/암호화 용도 RSA 키 생성 후 PEM 직렬화.
expected migration target: ML-KEM-768 키 쌍 생성.
"""
from Crypto.PublicKey import RSA


def generate_keypair() -> tuple[bytes, bytes]:
    """반환: (private_pem, public_pem)."""
    key = RSA.generate(2048)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem
