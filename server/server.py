from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import os
import json
from student import Student


from crypto import (
    public_key_der,
    rsa_decrypt,
    aes_gcm_decrypt,
    verify_hmac,
)
from anomaly_detector import is_anomalous


app = FastAPI()

# Store AES keys in memory just like Go server
session_keys = {}


# ------------------------------------------------------------
# Request Models
# ------------------------------------------------------------
class KeyExchangeRequest(BaseModel):
    encryptedKey: str


class MessageRequest(BaseModel):
    sessionID: str
    ciphertext: str
    nonce: str
    hmac: str


# ------------------------------------------------------------
# /publicKey endpoint
# ------------------------------------------------------------
@app.get("/publicKey")
def get_public_key():
    return {"publicKey": base64.b64encode(public_key_der).decode()}


# ------------------------------------------------------------
# /session endpoint (AES key exchange)
# ------------------------------------------------------------
@app.post("/session")
def create_session(req: KeyExchangeRequest):
    try:
        encrypted_key = base64.b64decode(req.encryptedKey)
        aes_key = rsa_decrypt(encrypted_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid encrypted key")

    # Create new session ID
    session_id = os.urandom(16).hex()
    session_keys[session_id] = aes_key

    return {"sessionID": session_id}


# ------------------------------------------------------------
# /message endpoint
# ------------------------------------------------------------
@app.post("/message")
def receive_message(req: MessageRequest):
    if req.sessionID not in session_keys:
        raise HTTPException(status_code=400, detail="Unknown session ID")

    aes_key = session_keys[req.sessionID]

    try:
        ciphertext = base64.b64decode(req.ciphertext)
        nonce = base64.b64decode(req.nonce)
        recv_hmac = base64.b64decode(req.hmac)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Base64 payload")

    # Step 1: Verify HMAC integrity
    valid_hmac = verify_hmac(aes_key, ciphertext, recv_hmac)
    if not valid_hmac:
        return {"validHMAC": False, "message": "HMAC verification failed"}

    # Step 2: AES-GCM decrypt
    try:
        plaintext_bytes = aes_gcm_decrypt(aes_key, nonce, ciphertext)
        plaintext = plaintext_bytes.decode()
    except Exception as e:
        return {"validHMAC": True, "message": f"Decryption failed: {str(e)}"}

    # Step 3: AI anomaly detection
    if is_anomalous(plaintext):
        return {
            "validHMAC": True,
            "message": "Anomaly detected — message flagged.",
            "student": None
        }

    # Step 4: Deserialize Student
    student=Student(**json.loads(plaintext))

    return {
        "validHMAC": True,
        "message": "Message decrypted successfully",
        "student": student.model_dump()

    }
