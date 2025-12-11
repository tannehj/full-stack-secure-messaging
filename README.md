
# Full-Stack Secure Messaging Application  
**Client–Server system using RSA, AES-GCM, HMAC, and REST API**

##  Overview
This project implements a secure full-stack messaging system where a Python client communicates with a Python FastAPI server using encrypted messages.  
All communication is performed end-to-end using:

- RSA – Secure symmetric session key exchange  
- AES-GCM – Fast, authenticated message encryption  
- HMAC-SHA256 – Integrity protection  
- Base64 Encoding – Network-safe message transport  
- Pydantic Models – JSON ↔ Object serialization/deserialization  
- AI Anomaly Detection – Flags suspicious JSON payloads  

The system follows the 10-step architecture required by the assignment.

---

##  Core Features
### 1. RSA Key Pair Generation (Server)
Server generates RSA-2048 key pair and exposes public key via `/publicKey`.

###  2. Symmetric Key Exchange (Client → Server)
Client:
- Generates AES-256 key  
- Encrypts AES key using RSA-OAEP  
- Sends encrypted key to `/session`  

Server decrypts AES key using its private RSA key.

###  3. AES-GCM Message Encryption (Client)
Student object JSON is encrypted using AES-GCM.

### 4. HMAC Integrity Validation
Client signs ciphertext with HMAC-SHA256.  
Server recomputes + validates before decrypting.

### 5. Server Decrypts & Deserializes
Server:
- Verifies HMAC  
- Decrypts AES-GCM  
- Converts JSON → Student object  

###  6. AI Anomaly Detection
Flags suspicious content (e.g., SQL injection).

###  7. JSON Response to Client
Server returns validated Student model.

---

## Project Structure
```
Project/
│
├── client/
│   ├── client.py
│   ├── crypto.py
│   └── student.py
│
└── server/
    ├── server.py
    ├── crypto.py
    ├── student.py
    └── anomaly_detector.py
```

---

## How to Run

### 1. Install dependencies
```bash
pip install fastapi uvicorn cryptography requests pydantic
```

### 2. Run Server
```bash
cd server
uvicorn server:app --reload
```

### 3. Run Client
```bash
cd client
python3 client.py
```

---

## Crypto Workflow (Steps 1–10)
1. Client serializes Student → JSON  
2. REST connectivity  
3. Server generates RSA keys  
4. Client fetches RSA public key  
5. Client encrypts AES key → sends to server  
6. AES-GCM encrypt JSON  
7. Client generates HMAC  
8. Server verifies HMAC  
9. Server decrypts AES-GCM  
10. Server deserializes JSON → Student object  

---

##  Anomaly Detection Logic
- SQL keywords detection  
- Suspicious names  
- Invalid GPA range  

If anomaly detected:

```
"student": null
```

---

##  Final Notes
This project demonstrates:
- Public Key Crypto  
- Symmetric Encryption  
- HMAC  
- REST APIs  
- Object Serialization  
- AI-based validation  
- Real client/server communication  


