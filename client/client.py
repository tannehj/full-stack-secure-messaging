import os
import base64

import json
import requests

from student import Student
from crypto import (
    rsa_encrypt,
    aes_gcm_encrypt,
    generate_hmac,
    b64encode,
)


SERVER = "http://localhost:8000"   # Python server



# ------------------------------------------------------------
# STEP 1: GET SERVER RSA PUBLIC KEY
# ------------------------------------------------------------
def fetch_public_key():
    resp = requests.get(f"{SERVER}/publicKey")
    resp.raise_for_status()

    resp = requests.get(f"{SERVER}/publicKey")
    key_b64 = resp.json()["publicKey"]
    key_der = base64.b64decode(key_b64)
    return key_der


# ------------------------------------------------------------
# STEP 2: SEND RSA-ENCRYPTED AES KEY, RECEIVE SESSION ID
# ------------------------------------------------------------
def send_symmetric_key(aes_key: bytes, public_key_der: bytes):
    encrypted_key = rsa_encrypt(public_key_der, aes_key)

    payload = {
        "encryptedKey": b64encode(encrypted_key)
    }

    resp = requests.post(f"{SERVER}/session", json=payload)
    resp.raise_for_status()
    return resp.json()["sessionID"]


# ------------------------------------------------------------
# STEP 3: SEND ENCRYPTED MESSAGE USING SESSION ID
# ------------------------------------------------------------
def send_message(session_id, nonce, ciphertext, hmac_value):
    payload = {
        "sessionID": session_id,
        "ciphertext": b64encode(ciphertext),
        "nonce": b64encode(nonce),
        "hmac": b64encode(hmac_value),
    }

    resp = requests.post(f"{SERVER}/message", json=payload)
    resp.raise_for_status()

    print("\n----- SERVER RESPONSE -----")
    print(json.dumps(resp.json(), indent=4))


# ------------------------------------------------------------
# MAIN CLIENT LOGIC
# ------------------------------------------------------------
def main():
    # Step A: Serialize student object
    student = Student(1, "Daren Gold", 3.9)
    student_json = student.to_json().encode()
    print("Serialized student:", student_json.decode())

    # Step B: Get RSA public key
    print("Fetching server public key...")
    public_key_der = fetch_public_key()

    # Step C: Generate AES-256 key
    aes_key = os.urandom(32)
    print("Generated AES key.")

    # Step D: Send encrypted AES key to /session
    session_id = send_symmetric_key(aes_key, public_key_der)
    print("Session established:", session_id)

    # Step E: AES-GCM encrypt student JSON
    nonce, ciphertext = aes_gcm_encrypt(aes_key, student_json)
    print("AES encryption complete.")

    # Step F: HMAC(ciphertext)
    hmac_value = generate_hmac(aes_key, ciphertext)
    print("HMAC generated.")

    # Step G: Send encrypted message
    send_message(session_id, nonce, ciphertext, hmac_value)


if __name__ == "__main__":
    main()
