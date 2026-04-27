"""Legacy RSA-based key transport — PQC migration target.

이 파일은 ai-migration 데모용으로 유지됩니다.
파이프라인의 semgrep crypto-classical.yaml 룰(`python-rsa-usage`,
`generic-rsa-key-size-weak`)이 RSA 사용을 탐지하면, ai-migration 워크플로우가
이 파일을 ML-KEM(FIPS 203) 기반으로 자동 변환하는 PR을 생성합니다.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_keypair():
    """Generate an RSA-2048 keypair for key transport."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    """Encrypt a session key using RSA-OAEP."""
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_session_key(private_key, ciphertext: bytes) -> bytes:
    """Decrypt a session key using RSA-OAEP."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
