"""
MediCrypt Vault - Authentication Cryptography Module
Implements password hashing with PBKDF2-HMAC-SHA256, salt generation,
and constant-time verification against timing attacks.
"""

import os
import hashlib
import binascii
import secrets
import json

PBKDF2_ROUNDS = 100_000
SALT_SIZE_BYTES = 16
KEY_LENGTH_BYTES = 32

AUTH_STORE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "auth_store.json")


def hash_password(password: str, salt: bytes = None) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Format: pbkdf2_sha256${iterations}${salt_hex}${hash_hex}
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE_BYTES)
    
    pwd_bytes = password.encode('utf-8')
    derived = hashlib.pbkdf2_hmac(
        'sha256',
        pwd_bytes,
        salt,
        PBKDF2_ROUNDS,
        dklen=KEY_LENGTH_BYTES
    )
    
    salt_hex = binascii.hexlify(salt).decode('ascii')
    derived_hex = binascii.hexlify(derived).decode('ascii')
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt_hex}${derived_hex}"


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verify provided password against stored hash string using constant-time comparison.
    """
    try:
        parts = stored_hash.split('$')
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        
        rounds = int(parts[1])
        salt = binascii.unhexlify(parts[2].encode('ascii'))
        expected_hash = parts[3]
        
        derived = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            rounds,
            dklen=KEY_LENGTH_BYTES
        )
        derived_hex = binascii.hexlify(derived).decode('ascii')
        
        return secrets.compare_digest(derived_hex, expected_hash)
    except Exception:
        return False


def get_or_create_default_doctor(username: str = "testing", default_pin: str = "test123") -> dict:
    """
    Initialize default doctor account if not exists (Default: 'testing' / 'test123').
    """
    os.makedirs(os.path.dirname(AUTH_STORE_FILE), exist_ok=True)
    data = {}
    if os.path.exists(AUTH_STORE_FILE):
        try:
            with open(AUTH_STORE_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
                if username in data:
                    return data[username]
        except Exception:
            pass

    # Create user record
    phash = hash_password(default_pin)
    user_record = {
        "username": username,
        "full_name": "Dr. dr. Hartono Sp.PD-KGEH",
        "doctor_nip": "198204122010121002",
        "role": "Chief Medical Specialist & Cryptography Vault Custodian",
        "password_hash": phash,
        "biometrics_enrolled": True
    }
    
    data[username] = user_record
    with open(AUTH_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return user_record


def update_user_biometric_status(username: str, enrolled: bool = True):
    if os.path.exists(AUTH_STORE_FILE):
        with open(AUTH_STORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if username in data:
            data[username]["biometrics_enrolled"] = enrolled
            with open(AUTH_STORE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

