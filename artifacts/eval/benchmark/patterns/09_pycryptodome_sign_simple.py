"""Pattern 03 — PyCryptodome: PKCS#1 v1.5 RSA 서명/검증.

input: PEM 인코딩된 키로 SHA-256 해시 서명 및 검증.
expected migration target: ML-DSA-65 (Dilithium3) 서명/검증.
"""
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def sign(private_key_pem: bytes, message: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)


def verify(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
