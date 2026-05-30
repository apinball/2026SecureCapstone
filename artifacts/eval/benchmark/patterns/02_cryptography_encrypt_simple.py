"""Pattern 02 — cryptography.hazmat: RSA-OAEP 암호화/복호화 함수 쌍.

input: 공개 키로 메시지 암호화, 개인 키로 복호화.
expected migration target: ML-KEM(공유 비밀 도출) + AES-GCM(메시지 암호화) 결합.
주의: KEM은 RSA-OAEP처럼 임의 메시지를 직접 암호화하지 않음. shared secret을 도출한 뒤
AEAD로 메시지를 암호화해야 함. 이 결합을 누락하면 보안 회귀.
"""
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_message(public_key, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_message(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
