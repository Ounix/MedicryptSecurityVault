"""
MediCrypt Vault - Super Encryption Module (Classical + Modern)
Combines:
1. Classical Cipher: Extended 256-Byte Vigenère Cipher
   C1[i] = (P[i] + K_v[i % m]) mod 256
2. Modern Cipher: AES-256-GCM (Galois/Counter Mode) with 128-bit Authentication Tag
"""

import os
import base64
import hashlib
from Crypto.Cipher import AES


def vigenere_encrypt(plaintext: str, key: str) -> bytes:
    """
    Extended 256-Byte Vigenère Cipher encryption.
    Operates on full UTF-8 byte streams.
    Formula: C[i] = (P[i] + K[i % m]) mod 256
    """
    if not key:
        raise ValueError("Kunci Vigenère tidak boleh kosong!")
    
    p_bytes = plaintext.encode('utf-8')
    k_bytes = key.encode('utf-8')
    m = len(k_bytes)
    
    c_bytes = bytearray(len(p_bytes))
    for i in range(len(p_bytes)):
        c_bytes[i] = (p_bytes[i] + k_bytes[i % m]) % 256
        
    return bytes(c_bytes)


def vigenere_decrypt(ciphertext_bytes: bytes, key: str) -> str:
    """
    Extended 256-Byte Vigenère Cipher decryption.
    Formula: P[i] = (C[i] - K[i % m] + 256) mod 256
    """
    if not key:
        raise ValueError("Kunci Vigenère tidak boleh kosong!")
        
    k_bytes = key.encode('utf-8')
    m = len(k_bytes)
    
    p_bytes = bytearray(len(ciphertext_bytes))
    for i in range(len(ciphertext_bytes)):
        p_bytes[i] = (ciphertext_bytes[i] - k_bytes[i % m] + 256) % 256
        
    return p_bytes.decode('utf-8', errors='replace')


def derive_aes_key(passphrase: str) -> bytes:
    """
    Derives 256-bit (32 bytes) key from passphrase using SHA-256.
    """
    return hashlib.sha256(passphrase.encode('utf-8')).digest()


def super_encrypt(plaintext: str, vigenere_key: str, aes_key_str: str) -> dict:
    """
    Executes Super Encryption:
    Plaintext -> [Extended Vigenère] -> Intermediate Bytes -> [AES-256-GCM] -> Final Ciphertext
    """
    if not plaintext:
        raise ValueError("Pesan rekam medis tidak boleh kosong!")
    if not vigenere_key:
        raise ValueError("Kunci klasik (Vigenère) harus diisi!")
    if not aes_key_str:
        raise ValueError("Kunci modern (AES) harus diisi!")

    # Step 1: Classical Vigenère Cipher
    vigenere_bytes = vigenere_encrypt(plaintext, vigenere_key)
    step1_b64 = base64.b64encode(vigenere_bytes).decode('ascii')

    # Step 2: Modern AES-256-GCM
    aes_key = derive_aes_key(aes_key_str)
    cipher = AES.new(aes_key, AES.MODE_GCM) # Automatically generates 16-byte nonce or 12-byte nonce
    nonce = cipher.nonce
    ciphertext_aes, tag = cipher.encrypt_and_digest(vigenere_bytes)

    # Package: NONCE (12-16B) + TAG (16B) + CIPHERTEXT
    packed_binary = nonce + tag + ciphertext_aes
    final_token = base64.b64encode(packed_binary).decode('ascii')

    return {
        "success": True,
        "plaintext_length": len(plaintext),
        "vigenere_key": vigenere_key,
        "aes_key_preview": aes_key.hex()[:16] + "...",
        "step1_classical_b64": step1_b64,
        "step1_bytes_len": len(vigenere_bytes),
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "final_ciphertext_b64": base64.b64encode(ciphertext_aes).decode('ascii'),
        "packed_token": final_token
    }


def super_decrypt(packed_token: str, vigenere_key: str, aes_key_str: str) -> dict:
    """
    Executes Super Decryption:
    Packed Token -> Extract Nonce/Tag/Ciphertext -> [AES-256-GCM Decrypt & Tag Verification]
    -> Intermediate Bytes -> [Vigenère Decrypt] -> Original Plaintext
    """
    try:
        raw_binary = base64.b64decode(packed_token.strip().encode('ascii'))
        if len(raw_binary) < 28: # Min: 12B nonce + 16B tag
            return {"success": False, "error": "Ciphertext terlalu pendek atau format rusak!"}

        aes_key = derive_aes_key(aes_key_str)

        # Standard pycryptodome AES-GCM default nonce length is 16 bytes
        # Let's handle 16-byte nonce + 16-byte tag
        nonce_len = 16
        if len(raw_binary) < nonce_len + 16:
            return {"success": False, "error": "Payload token tidak valid."}

        nonce = raw_binary[:nonce_len]
        tag = raw_binary[nonce_len:nonce_len + 16]
        ciphertext_aes = raw_binary[nonce_len + 16:]

        # Step 1: Modern AES-256-GCM Decrypt & Verify Tag
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            intermediate_bytes = cipher.decrypt_and_verify(ciphertext_aes, tag)
        except ValueError:
            return {
                "success": False,
                "error": "VERIFIKASI INTEGRITAS GAGAL! Kunci AES salah atau ciphertext telah dirusak/dimanipulasi!"
            }

        # Step 2: Classical Vigenère Decrypt
        decrypted_text = vigenere_decrypt(intermediate_bytes, vigenere_key)

        return {
            "success": True,
            "decrypted_plaintext": decrypted_text,
            "step1_recovered_b64": base64.b64encode(intermediate_bytes).decode('ascii'),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "integrity_verified": True
        }
    except Exception as e:
        return {"success": False, "error": f"Kesalahan dekripsi: {str(e)}"}

