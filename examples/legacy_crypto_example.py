"""Legacy RSA-based key transport — PQC migration target.

이 파일은 ai-migration 데모용으로 유지됩니다.
파이프라인의 semgrep crypto-classical.yaml 룰(`python-rsa-usage`,
`generic-rsa-key-size-weak`)이 RSA 사용을 탐지하면, ai-migration 워크플로우가
이 파일을 ML-KEM(FIPS 203) 기반으로 자동 변환하는 PR을 생성합니다.
"""

from oqs import KeyEncapsulation


# PQC migration: replaced RSA with ML-KEM
kem = KeyEncapsulation("Kyber768")

def generate_keypair():
    """Generate a keypair for key transport using ML-KEM."""
    public_key = kem.generate_keypair()        # returns: bytes (public key)
    return public_key


def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    """Encapsulate a session key using ML-KEM. Returns shared secret."""
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext  # The shared secret can be used as the session key.


def decrypt_session_key(ciphertext: bytes) -> bytes:
    """Decapsulate a session key using ML-KEM."""
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret  # The shared secret is returned.
