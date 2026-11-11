"""
MediCrypt Vault - LSB Steganography Module for Medical Imaging
Hides confidential patient diagnosis inside medical images (X-Ray / MRI / CT-Scan).
Features:
1. Stego-Crypto Hybrid: Payload is encrypted with AES-256 before LSB embedding.
2. Least Significant Bit (LSB) embedding on RGB channels.
3. Steganalysis Quality Evaluation: MSE (Mean Squared Error) and PSNR (Peak Signal-to-Noise Ratio).
"""

import os
import math
import struct
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

STEGO_MAGIC = b"STEG" # 4-byte header identifier


def _derive_stego_key(passphrase: str) -> bytes:
    return hashlib.sha256(b"STEGO-AES-KEY-" + passphrase.encode('utf-8')).digest()


def _encrypt_stego_payload(secret_text: str, passphrase: str) -> bytes:
    """
    Encrypts message with AES-128/256-CBC before embedding.
    Format: [IV(16B)][CIPHERTEXT]
    """
    key = _derive_stego_key(passphrase)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded = pad(secret_text.encode('utf-8'), AES.block_size)
    ct = cipher.encrypt(padded)
    return iv + ct


def _decrypt_stego_payload(payload_bytes: bytes, passphrase: str) -> str:
    if len(payload_bytes) < 16:
        raise ValueError("Payload steganografi rusak atau terlalu pendek.")
    iv = payload_bytes[:16]
    ct = payload_bytes[16:]
    key = _derive_stego_key(passphrase)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ct)
    decrypted = unpad(decrypted_padded, AES.block_size)
    return decrypted.decode('utf-8')


def embed_secret_in_image(image_path: str, output_path: str, secret_text: str, passphrase: str) -> dict:
    """
    Embeds secret text into carrier image using LSB steganography.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"File citra medis tidak ditemukan: {image_path}")
    if not secret_text:
        raise ValueError("Pesan diagnosis rahasia tidak boleh kosong!")
    if not passphrase:
        raise ValueError("Kunci stego harus diisi!")

    # Encrypt payload first
    encrypted_payload = _encrypt_stego_payload(secret_text, passphrase)
    payload_len = len(encrypted_payload)

    # Header: MAGIC(4B) + LENGTH(4B) + PAYLOAD
    full_stream = STEGO_MAGIC + struct.pack(">I", payload_len) + encrypted_payload

    # Convert to bit list
    bits = []
    for byte in full_stream:
        for bit_idx in range(7, -1, -1):
            bits.append((byte >> bit_idx) & 1)

    total_bits = len(bits)

    # Open image in RGB mode
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    h, w, c = pixels.shape
    total_capacity = h * w * c

    if total_bits > total_capacity:
        raise ValueError(f"Ukuran pesan melebihi kapasitas citra! Kapasitas: {total_capacity} bits, Dibutuhkan: {total_bits} bits.")

    # Flatten pixel array for linear bit replacement
    flat_pixels = pixels.flatten()
    orig_flat = flat_pixels.copy()

    for i in range(total_bits):
        # Clear least significant bit (using 0xFE mask) and insert payload bit
        flat_pixels[i] = (int(flat_pixels[i]) & 0xFE) | bits[i]

    stego_pixels = flat_pixels.reshape((h, w, c))
    stego_img = Image.fromarray(stego_pixels, 'RGB')
    stego_img.save(output_path, format="PNG")

    # Calculate Scientific Metrics: MSE and PSNR
    mse = float(np.mean((orig_flat[:total_bits] - flat_pixels[:total_bits]) ** 2))
    total_mse = float(np.mean((orig_flat - flat_pixels) ** 2))
    if total_mse == 0:
        psnr = 99.99
    else:
        psnr = 10 * math.log10((255 ** 2) / total_mse)

    orig_sz = os.path.getsize(image_path)
    stego_sz = os.path.getsize(output_path)

    return {
        "success": True,
        "input_path": image_path,
        "output_path": output_path,
        "payload_bytes": payload_len,
        "total_bits_embedded": total_bits,
        "image_resolution": f"{w}x{h} ({w*h} pixels)",
        "orig_file_size_bytes": orig_sz,
        "orig_file_size_formatted": f"{orig_sz / 1024:.2f} KB ({orig_sz:,} bytes)",
        "stego_file_size_bytes": stego_sz,
        "stego_file_size_formatted": f"{stego_sz / 1024:.2f} KB ({stego_sz:,} bytes)",
        "size_diff_bytes": stego_sz - orig_sz,
        "capacity_bits": total_capacity,
        "capacity_used_pct": round((total_bits / total_capacity) * 100, 3),
        "mse": round(total_mse, 6),
        "psnr_db": round(psnr, 2)
    }


def extract_secret_from_image(stego_image_path: str, passphrase: str) -> dict:
    """
    Extracts and decrypts secret message from stego image using LSB.
    """
    if not os.path.exists(stego_image_path):
        raise FileNotFoundError(f"Citra stego tidak ditemukan: {stego_image_path}")

    img = Image.open(stego_image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8).flatten()

    # Read first 64 bits (8 bytes): 4 bytes MAGIC + 4 bytes LENGTH
    if len(pixels) < 64:
        return {"success": False, "error": "Resolusi citra terlalu kecil."}

    header_bytes = bytearray()
    for byte_idx in range(8):
        byte_val = 0
        for bit_idx in range(8):
            bit = pixels[byte_idx * 8 + bit_idx] & 1
            byte_val = (byte_val << 1) | bit
        header_bytes.append(byte_val)

    magic = bytes(header_bytes[:4])
    if magic != STEGO_MAGIC:
        return {"success": False, "error": "Tidak ditemukan data steganografi MediCrypt pada citra ini (Magic header mismatch)!"}

    payload_len = struct.unpack(">I", bytes(header_bytes[4:8]))[0]

    # Validate reasonable payload length
    max_possible = (len(pixels) - 64) // 8
    if payload_len <= 0 or payload_len > max_possible:
        return {"success": False, "error": "Panjang data steganografi rusak / korup."}

    # Extract payload bits
    start_bit = 64
    end_bit = 64 + payload_len * 8
    payload_bytes = bytearray()

    for byte_idx in range(payload_len):
        byte_val = 0
        for bit_idx in range(8):
            bit = pixels[start_bit + byte_idx * 8 + bit_idx] & 1
            byte_val = (byte_val << 1) | bit
        payload_bytes.append(byte_val)

    # Decrypt extracted payload
    try:
        secret_message = _decrypt_stego_payload(bytes(payload_bytes), passphrase)
        return {
            "success": True,
            "secret_message": secret_message,
            "payload_bytes": payload_len,
            "stego_image": stego_image_path,
            "integrity_verified": True
        }
    except Exception as e:
        return {
            "success": False,
            "error": "GAGAL MENDEKRIPSI! Kunci stego salah atau bit citra telah rusak/dikompresi!"
        }


def generate_sample_xray_image(target_path: str):
    """
    Generates a realistic synthetic chest X-Ray graphic with ribcage contours
    so the user can immediately test steganography without downloading anything.
    """
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    w, h = 600, 600
    img = Image.new("RGB", (w, h), color=(15, 18, 24))
    draw = ImageDraw.Draw(img)

    # Draw ribcage silhouettes & lungs
    draw.ellipse([80, 100, 260, 480], fill=(35, 42, 55), outline=(60, 75, 95), width=2)
    draw.ellipse([340, 100, 520, 480], fill=(35, 42, 55), outline=(60, 75, 95), width=2)

    # Spine column
    draw.rectangle([285, 80, 315, 520], fill=(70, 85, 110))

    # Ribs arches
    for y in range(140, 450, 40):
        draw.arc([100, y-20, 300, y+35], start=160, end=350, fill=(90, 110, 140), width=3)
        draw.arc([300, y-20, 500, y+35], start=190, end=20, fill=(90, 110, 140), width=3)

    # Heart shadow
    draw.ellipse([240, 280, 390, 460], fill=(50, 60, 80))

    # Medical metadata text
    draw.text((20, 20), "MEDICRYPT RADIOLOGY DEPT - CHEST PA AP", fill=(180, 200, 220))
    draw.text((20, 40), "PATIENT: RM-2026-0081 (Bambang T.)", fill=(140, 160, 180))
    draw.text((20, 560), "HOSPITAL DIGITAL ARCHIVE - CONFIDENTIAL", fill=(100, 120, 140))
    draw.text((530, 20), "R", fill=(200, 220, 240))

    img.save(target_path, "PNG")
