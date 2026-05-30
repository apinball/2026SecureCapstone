"""Pattern 01 — cryptography.hazmat: 단순 RSA 키 쌍 생성.

input: RSA-2048 키 쌍 생성 후 (private, public) 반환.
expected migration target: ML-KEM-768 키 쌍 생성.
"""
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key
