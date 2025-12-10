import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ------------------------------------------------------------
# RSA KEY GENERATION (matches Go server)
# ------------------------------------------------------------
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

public_key_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# ------------------------------------------------------------
# RSA DECRYPTION (AES key)
# ------------------------------------------------------------
def rsa_decrypt(ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ------------------------------------------------------------
# AES-GCM DECRYPTION (matches Go server)
# ------------------------------------------------------------
def aes_gcm_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ------------------------------------------------------------
# HMAC-SHA256 VERIFICATION
# ------------------------------------------------------------
def verify_hmac(aes_key: bytes, data: bytes, recv_hmac: bytes) -> bool:
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(recv_hmac)
        return True
    except Exception:
        return False
