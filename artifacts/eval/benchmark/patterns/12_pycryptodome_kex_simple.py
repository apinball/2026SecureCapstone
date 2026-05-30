"""Pattern 12 — PyCryptodome: PKCS1_OAEP 기반 AES 세션 키 wrap.

intent: 임의 AES 키 생성 후 RSA-OAEP로 wrap, AES-GCM으로 메시지 암호화.
expected migration target: ML-KEM-768 + AES-GCM.
"""
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def wrap_and_encrypt(public_key_pem: bytes, message: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """반환: (wrapped_aes_key, nonce, tag, ciphertext)."""
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    rsa_pub = RSA.import_key(public_key_pem)
    wrapper = PKCS1_OAEP.new(rsa_pub, hashAlgo=SHA256)
    wrapped = wrapper.encrypt(aes_key)

    return wrapped, nonce, tag, ciphertext


def unwrap_and_decrypt(
    private_key_pem: bytes, wrapped: bytes, nonce: bytes, tag: bytes, ciphertext: bytes
) -> bytes:
    rsa_priv = RSA.import_key(private_key_pem)
    unwrapper = PKCS1_OAEP.new(rsa_priv, hashAlgo=SHA256)
    aes_key = unwrapper.decrypt(wrapped)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
