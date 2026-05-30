"""Demo file to trigger AI migration."""
from oqs import KeyEncapsulation

# PQC migration: replaced RSA with ML-KEM
def generate_user_key():
    kem = KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()  # returns: bytes (public key)
    return kem, public_key


if __name__ == "__main__":
    kem, key = generate_user_key()
    print("Key generated")
