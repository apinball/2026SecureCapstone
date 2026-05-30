"""Pattern 01 — cryptography.hazmat: 단순 RSA 키 쌍 생성.

input: RSA-2048 키 쌍 생성 후 (private, public) 반환.
expected migration target: ML-KEM-768 키 쌍 생성.
"""
from oqs import KeyEncapsulation


# PQC migration: replaced RSA with ML-KEM
def generate_keypair():
    kem = KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()        # returns: bytes (public key)
    return kem, public_key
