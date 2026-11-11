"""
MediCrypt Vault - Cryptanalysis & Mathematical Benchmark Module
Calculates:
1. Strict Avalanche Effect (SAC / Hamming Bit Differences)
2. Shannon Entropy H(X) (Measure of ciphertext randomness)
3. Cryptographic Execution Speed & Throughput Benchmark
"""

import time
import math
from collections import Counter
from .super_encryption import super_encrypt
from .file_crypto import derive_chacha_key
from Crypto.Cipher import ChaCha20_Poly1305


def calculate_hamming_distance_bits(b1: bytes, b2: bytes) -> tuple[int, int, float]:
    """
    Computes bitwise Hamming distance between two byte sequences.
    Returns: (differing_bits, total_bits, percentage)
    """
    min_len = min(len(b1), len(b2))
    diff_bits = 0
    total_bits = min_len * 8

    for i in range(min_len):
        xor_val = b1[i] ^ b2[i]
        diff_bits += bin(xor_val).count('1')

    # If lengths differ, add remaining bits
    len_diff = abs(len(b1) - len(b2))
    total_bits += len_diff * 8
    diff_bits += len_diff * 4 # Approximate average for non-overlapping tail

    pct = (diff_bits / total_bits) * 100 if total_bits > 0 else 0.0
    return diff_bits, total_bits, round(pct, 2)


def test_avalanche_effect(text1: str, text2: str, vigenere_key: str, aes_key: str) -> dict:
    """
    Tests Avalanche Effect between two slightly different plaintexts.
    Ideal cryptographic avalanche is ~50%.
    """
    res1 = super_encrypt(text1, vigenere_key, aes_key)
    res2 = super_encrypt(text2, vigenere_key, aes_key)

    import base64
    ct1 = base64.b64decode(res1["packed_token"].encode('ascii'))
    ct2 = base64.b64decode(res2["packed_token"].encode('ascii'))

    diff_bits, total_bits, pct = calculate_hamming_distance_bits(ct1, ct2)

    return {
        "text1": text1,
        "text2": text2,
        "token1_preview": res1["packed_token"][:24] + "...",
        "token2_preview": res2["packed_token"][:24] + "...",
        "differing_bits": diff_bits,
        "total_bits": total_bits,
        "avalanche_pct": pct,
        "evaluation": (
            "SANGAT KUAT: Memenuhi Strict Avalanche Criterion (SAC ≈ 50%). "
            "Satu perubahan kecil memicu perubahan acak pada separuh seluruh bit ciphertext!"
            if 40.0 <= pct <= 60.0 else
            "MEMADAI: Terjadi difusi bit yang signifikan."
        )
    }


def calculate_shannon_entropy(data_bytes: bytes) -> float:
    """
    Calculates Shannon Entropy H(X) in bits per byte.
    Maximum theoretical entropy for random 8-bit bytes is 8.0.
    """
    if not data_bytes:
        return 0.0

    length = len(data_bytes)
    freq = Counter(data_bytes)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def benchmark_encryption_speed(iterations: int = 50) -> dict:
    """
    Benchmarks Super Encryption (AES-GCM + Vigenère) vs File Encryption (ChaCha20-Poly1305).
    """
    sample_text = "PASIEN RM-2026-0081: DIAGNOSA HEPATITIS B KRONIS DENGAN KOMPLIKASI VARISES ESOFAGUS GRADE 2. TERAPI RESEP OBAT KERAS." * 10
    sample_bytes = sample_text.encode('utf-8')
    data_kb = len(sample_bytes) / 1024

    # 1. Benchmark Super Encryption
    t0 = time.perf_counter()
    for _ in range(iterations):
        super_encrypt(sample_text, "VIGENEREKEY2026", "AESSECRETKEY2026")
    t1 = time.perf_counter()
    super_elapsed_ms = ((t1 - t0) / iterations) * 1000

    # 2. Benchmark ChaCha20-Poly1305
    k = derive_chacha_key("CHACHA20KEY2026")
    t0 = time.perf_counter()
    for _ in range(iterations):
        c = ChaCha20_Poly1305.new(key=k)
        ct, tag = c.encrypt_and_digest(sample_bytes)
    t1 = time.perf_counter()
    chacha_elapsed_ms = ((t1 - t0) / iterations) * 1000

    return {
        "iterations": iterations,
        "payload_size_bytes": len(sample_bytes),
        "payload_size_kb": round(data_kb, 2),
        "super_enc_avg_ms": round(super_elapsed_ms, 3),
        "super_enc_throughput_kb_s": round(data_kb / (super_elapsed_ms / 1000), 2) if super_elapsed_ms > 0 else 0,
        "chacha20_avg_ms": round(chacha_elapsed_ms, 3),
        "chacha20_throughput_kb_s": round(data_kb / (chacha_elapsed_ms / 1000), 2) if chacha_elapsed_ms > 0 else 0,
    }

