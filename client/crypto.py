import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ------------------------------------------------------------
# RSA PUBLIC KEY ENCRYPTION (OAEP-SHA256)
# ------------------------------------------------------------
def rsa_encrypt(public_key_der: bytes, data: bytes) -> bytes:
    """
    Encrypt AES symmetric key using RSA-OAEP(SHA-256).
    Matches professor's Go implementation.
    """
    public_key = serialization.load_der_public_key(public_key_der)

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# ------------------------------------------------------------
# AES-GCM ENCRYPTION (matches Go)
# ------------------------------------------------------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """
    Returns (nonce, ciphertext).
    AES-GCM is authenticated encryption.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Go uses 12-byte GCM nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


# ------------------------------------------------------------
# HMAC-SHA256 (integrity protection)
# ------------------------------------------------------------
def generate_hmac(key: bytes, data: bytes) -> bytes:
    """
    Computes HMAC-SHA256 over ciphertext.
    """
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


# ------------------------------------------------------------
# Base64 convenience functions
# ------------------------------------------------------------
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode())
