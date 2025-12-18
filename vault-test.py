# vault_generate.py
import json
import os
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Config ---
password = "mysecretpassword"       # The password to unlock
plaintext = b"Hello from Python!"   # The secret data
iterations = 100_000                 # PBKDF2 iterations

# --- Generate salt ---
salt = os.urandom(16)

# --- Derive key ---
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,           # 256-bit key for AES-256
    salt=salt,
    iterations=iterations,
)
key = kdf.derive(password.encode('utf-8'))

# --- Encrypt with AES-GCM ---
nonce = os.urandom(12)               # 12-byte nonce
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# --- Encode as base64 for storage/transfer ---
vault_json = {
    "salt": b64encode(salt).decode('utf-8'),
    "nonce": b64encode(nonce).decode('utf-8'),
    "ciphertext": b64encode(ciphertext).decode('utf-8')
}

print(json.dumps(vault_json, indent=2))
