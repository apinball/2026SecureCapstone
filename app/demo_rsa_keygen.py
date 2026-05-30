"""Demo file to trigger AI migration."""
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_user_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


if __name__ == "__main__":
    key = generate_user_key()
    print("Key generated")
