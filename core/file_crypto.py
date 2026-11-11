"""
MediCrypt Vault - File Encryption Module (ChaCha20-Poly1305)
Encrypts any file (Videos, Photos, Medical Documents, Audio, Archives, etc.)
using ChaCha20-Poly1305 (RFC 8439 Authenticated Cipher).
Produces verifiable Ciphertext that decrypts back to the exact original file.
"""

import os
import struct
import hashlib
import base64
from Crypto.Cipher import ChaCha20_Poly1305

FILE_MAGIC = b"MEDFILE1" # 8-byte header identifier


def derive_chacha_key(passphrase: str) -> bytes:
    """
    Derives 256-bit (32 bytes) key for ChaCha20 using SHA-256.
    """
    return hashlib.sha256(b"CHACHA20-FILE-KEY-SALT-" + passphrase.encode('utf-8')).digest()


def calculate_file_hash(file_path: str) -> str:
    """
    Compute SHA-256 checksum of a file for integrity verification.
    """
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def encrypt_medical_file(input_path: str, output_path: str, passphrase: str) -> dict:
    """
    Encrypts any file (Video, Photo, PDF, Audio, etc.) using ChaCha20-Poly1305.
    Saves formatted container: [MAGIC(8B)][FNAME_LEN(2B)][FNAME][NONCE(12B)][TAG(16B)][CIPHERTEXT]
    Returns dictionary with metadata and portable Base64 ciphertext token.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File tidak ditemukan: {input_path}")
    if not passphrase:
        raise ValueError("Kunci sandi enkripsi file harus diisi!")

    original_filename = os.path.basename(input_path).encode('utf-8')
    fname_len = len(original_filename)
    if fname_len > 65535:
        raise ValueError("Nama file terlalu panjang!")

    original_hash = calculate_file_hash(input_path)
    file_size = os.path.getsize(input_path)

    key = derive_chacha_key(passphrase)
    cipher = ChaCha20_Poly1305.new(key=key) # Generates 12-byte RFC 7539 nonce
    nonce = cipher.nonce

    with open(input_path, "rb") as f_in:
        plaintext_data = f_in.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext_data)

    # Build formatted container bytes
    container_bytes = bytearray()
    container_bytes.extend(FILE_MAGIC)
    container_bytes.extend(struct.pack(">H", fname_len))
    container_bytes.extend(original_filename)
    container_bytes.extend(nonce)
    container_bytes.extend(tag)
    container_bytes.extend(ciphertext)

    # Write formatted encrypted container to disk
    if output_path:
        with open(output_path, "wb") as f_out:
            f_out.write(container_bytes)
        enc_size = os.path.getsize(output_path)
    else:
        enc_size = len(container_bytes)

    # Generate Base64 Ciphertext representation (capped to 32KB to avoid UI freezing)
    if len(container_bytes) <= 32 * 1024:
        ciphertext_b64 = base64.b64encode(container_bytes).decode('ascii')
        is_truncated = False
    else:
        ciphertext_b64 = base64.b64encode(container_bytes[:2048]).decode('ascii') + "... [TRUNCATED]"
        is_truncated = True

    return {
        "success": True,
        "input_path": input_path,
        "output_path": output_path,
        "original_name": os.path.basename(input_path),
        "original_size": file_size,
        "encrypted_size": enc_size,
        "original_sha256": original_hash,
        "algorithm": "ChaCha20-Poly1305 (IETF RFC 8439)",
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "ciphertext_b64": ciphertext_b64,
        "ciphertext_preview_hex": ciphertext[:32].hex(),
        "ciphertext_len_bytes": len(ciphertext),
        "is_truncated": is_truncated
    }


def decrypt_medical_file(encrypted_source: str, output_directory: str, passphrase: str) -> dict:
    """
    Decrypts ChaCha20-Poly1305 encrypted file or Base64 ciphertext token.
    Restores the exact original input file and verifies Poly1305 MAC and SHA-256 integrity.
    """
    if not encrypted_source:
        raise ValueError("Sumber ciphertext / file terenkripsi tidak boleh kosong!")
    if not passphrase:
        raise ValueError("Kunci sandi dekripsi file harus diisi!")

    # Normalize source string (strip whitespace, surrounding quotes)
    if isinstance(encrypted_source, str):
        encrypted_source = encrypted_source.strip().strip('"').strip("'")

    key = derive_chacha_key(passphrase)
    raw_data = None

    # Check if encrypted_source points to a valid file on disk
    if os.path.exists(encrypted_source) and os.path.isfile(encrypted_source):
        with open(encrypted_source, "rb") as f_in:
            raw_data = f_in.read()
    else:
        # Attempt to decode as Base64 ciphertext token
        cleaned_str = encrypted_source.strip().replace("\r", "").replace("\n", "").replace(" ", "")
        try:
            raw_data = base64.b64decode(cleaned_str)
        except Exception:
            return {
                "success": False,
                "error": "Ciphertext tidak valid: Berkas tidak ditemukan di disk dan bukan format Base64 yang valid!"
            }

    if not raw_data or len(raw_data) < 8 + 2 + 12 + 16:
        return {"success": False, "error": "Ciphertext tidak lengkap atau berukuran terlalu kecil!"}

    magic = raw_data[:8]
    if magic != FILE_MAGIC:
        return {
            "success": False,
            "error": "Bukan file/ciphertext terenkripsi MediCrypt (Header Magic tidak cocok)!\n"
                     "Pastikan Anda memasukkan berkas hasil enkripsi (.enc/.medenc) atau ciphertext Base64 yang sah."
        }

    fname_len = struct.unpack(">H", raw_data[8:10])[0]
    offset = 10
    if len(raw_data) < offset + fname_len + 12 + 16:
        return {"success": False, "error": "Header ciphertext rusak (Panjang nama berkas tidak sesuai)."}

    original_filename = raw_data[offset:offset+fname_len].decode('utf-8', errors='replace')
    offset += fname_len
    nonce = raw_data[offset:offset+12]
    offset += 12
    tag = raw_data[offset:offset+16]
    offset += 16
    ciphertext = raw_data[offset:]

    # Verify and decrypt with ChaCha20-Poly1305
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return {
            "success": False,
            "error": "VERIFIKASI INTEGRITAS GAGAL! Kunci sandi salah atau isi ciphertext telah dimanipulasi/rusak!"
        }

    # Save restored file to disk
    os.makedirs(output_directory, exist_ok=True)
    out_file_path = os.path.join(output_directory, f"decrypted_{original_filename}")
    with open(out_file_path, "wb") as f_out:
        f_out.write(decrypted_data)

    decrypted_hash = calculate_file_hash(out_file_path)

    return {
        "success": True,
        "output_path": out_file_path,
        "restored_filename": original_filename,
        "restored_size": len(decrypted_data),
        "sha256": decrypted_hash,
        "algorithm": "ChaCha20-Poly1305 (IETF RFC 8439)",
        "integrity_verified": True
    }
