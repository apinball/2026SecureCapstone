"""Pattern 11 — PyCryptodome: PKCS1_OAEP 암호화/복호화.

intent: RSA-OAEP로 메시지 암호화. PEM 키를 매번 import.
expected migration target: ML-KEM-768 + AES-GCM.
"""
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def encrypt_message(public_key_pem: bytes, message: bytes) -> bytes:
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.encrypt(message)


def decrypt_message(private_key_pem: bytes, ciphertext: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)
