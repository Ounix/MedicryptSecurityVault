"""
MediCrypt Vault - Automated Comprehensive Verification Test Suite
Validates all 7 Project Criteria and Core Modules
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.auth_crypto import hash_password, verify_password, get_or_create_default_doctor
from core.hardware_dongle import write_dongle_token, verify_dongle_file, scan_for_dongle, VIRTUAL_DONGLE_DIR
from core.biometrics import (
    extract_face_features,
    enroll_doctor_face,
    verify_doctor_face,
    is_face_enrolled,
    enroll_doctor_fingerprint,
    verify_doctor_fingerprint_sensor
)
from core.super_encryption import super_encrypt, super_decrypt
from core.file_crypto import encrypt_medical_file, decrypt_medical_file
from core.db_crypto import init_database, insert_medical_record, get_all_records
from core.steganography import generate_sample_xray_image, embed_secret_in_image, extract_secret_from_image
from core.blockchain import MedicalBlockchain
from core.crypto_analyzer import test_avalanche_effect, calculate_shannon_entropy, benchmark_encryption_speed
import numpy as np


class TestMediCryptVault(unittest.TestCase):

    def test_01_criteria_login_hash(self):
        """Kriteria #2: Login Password Hash PBKDF2-HMAC-SHA256"""
        pwd = "DoctorSecretPassword2026!"
        hpwd = hash_password(pwd)
        self.assertTrue(hpwd.startswith("pbkdf2_sha256$100000$"))
        self.assertTrue(verify_password(hpwd, pwd))
        self.assertFalse(verify_password(hpwd, "WrongPassword"))

    def test_02_criteria_hardware_dongle(self):
        """Kriteria #1 (Part A): Hardware Dongle Protection with HMAC Signature"""
        os.makedirs(VIRTUAL_DONGLE_DIR, exist_ok=True)
        payload = write_dongle_token(VIRTUAL_DONGLE_DIR, "dr_hartono", "SN-TEST-992")
        self.assertIn("signature", payload)
        
        token_path = os.path.join(VIRTUAL_DONGLE_DIR, "medicrypt.dongle")
        valid, msg, data = verify_dongle_file(token_path, "dr_hartono")
        self.assertTrue(valid, msg)
        
        scan_res = scan_for_dongle("dr_hartono", allow_virtual=True)
        self.assertTrue(scan_res["is_valid"])

        # Clean up test artifact so live app does not falsely assume USB is present
        if os.path.exists(token_path):
            os.remove(token_path)

    def test_03_criteria_biometrics(self):
        """Kriteria #1 (Part B): Face Recognition & Fingerprint Verification"""
        # Use isolated test user profile so real enrolled doctor face is preserved
        test_user = "test_unit_doctor"
        fake_face = np.full((160, 160, 3), 120, dtype=np.uint8)
        ok, msg = enroll_doctor_face(fake_face, test_user)
        self.assertTrue(ok)
        self.assertTrue(is_face_enrolled(test_user))

        # Verify identical face
        matched, sim, vmsg = verify_doctor_face(fake_face, threshold_cosine=0.70, doctor_username=test_user)
        self.assertTrue(matched)
        self.assertGreater(sim, 0.90)

        # Fingerprint Model Tests: strict validation
        from core.biometrics import (
            is_fingerprint_enrolled,
            FINGERPRINT_PROFILE_FILE,
            enroll_doctor_fingerprint_data,
            verify_doctor_fingerprint_data
        )
        import cv2

        if os.path.exists(FINGERPRINT_PROFILE_FILE):
            os.remove(FINGERPRINT_PROFILE_FILE)

        self.assertFalse(is_fingerprint_enrolled())

        # Test Case 1: Enrolling blank sensor (without finger) MUST FAIL
        blank_img = np.full((200, 200, 3), 245, dtype=np.uint8)
        ok_blank_enroll, _ = enroll_doctor_fingerprint_data(blank_img, "dr_hartono")
        self.assertFalse(ok_blank_enroll, "Pendaftaran tanpa jari harus gagal!")

        # Enroll valid doctor thumb
        thumb_img = cv2.imread('data/sample_fingerprints/doctor_thumb.png')
        ok_enroll, _ = enroll_doctor_fingerprint_data(thumb_img, "dr_hartono")
        self.assertTrue(ok_enroll)
        self.assertTrue(is_fingerprint_enrolled())

        # Test Case 2: Verifying blank sensor (without finger) MUST FAIL
        ok_blank_ver, _, _ = verify_doctor_fingerprint_data(blank_img)
        self.assertFalse(ok_blank_ver, "Verifikasi tanpa jari harus gagal!")

        # Test Case 3: Verifying with different / unauthorized finger MUST FAIL
        unauth_img = cv2.imread('data/sample_fingerprints/unauthorized_finger.png')
        ok_diff_ver, score_diff, _ = verify_doctor_fingerprint_data(unauth_img, threshold=0.80)
        self.assertFalse(ok_diff_ver, "Verifikasi dengan jari berbeda harus gagal!")

        # Test Case 4: Verifying with the enrolled doctor thumb MUST SUCCEED
        ok_match_ver, score_match, _ = verify_doctor_fingerprint_data(thumb_img, threshold=0.80)
        self.assertTrue(ok_match_ver, "Verifikasi dengan jari yang sama harus sukses!")
        self.assertGreaterEqual(score_match, 0.85)

    def test_04_criteria_super_encryption(self):
        """Kriteria #3: Text Super Encryption (Vigenère Classical + AES-256-GCM Modern)"""
        msg = "Pasien NIK 327104: Diagnosa Sindrom Koroner Akut (STEMI Anterior). Pasang Ring Segera!"
        k_classic = "VIGENEREKLASIK2026"
        k_modern = "AES256GCMModernKey!"

        enc = super_encrypt(msg, k_classic, k_modern)
        self.assertTrue(enc["success"])
        self.assertIn("packed_token", enc)
        self.assertIn("step1_classical_b64", enc)

        # Decrypt
        dec = super_decrypt(enc["packed_token"], k_classic, k_modern)
        self.assertTrue(dec["success"])
        self.assertEqual(dec["decrypted_plaintext"], msg)
        self.assertTrue(dec["integrity_verified"])

        # Tampering test: modify 1 character in token
        first_char = enc["packed_token"][0]
        flipped_char = 'B' if first_char != 'B' else 'C'
        bad_token = flipped_char + enc["packed_token"][1:]
        bad_dec = super_decrypt(bad_token, k_classic, k_modern)
        self.assertFalse(bad_dec["success"])

    def test_05_criteria_file_encryption(self):
        """Kriteria #4: File Encryption using different cipher (ChaCha20-Poly1305)"""
        test_file = os.path.join("data", "unit_test_lab.txt")
        test_enc = test_file + ".medenc"
        os.makedirs("data", exist_ok=True)
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("HASIL PEMERIKSAAN HISTOPATOLOGI: Adenokarsinoma Kolorektal Moderately Differentiated")

        enc = encrypt_medical_file(test_file, test_enc, "ChaChaKeyFile2026!")
        self.assertTrue(enc["success"])
        self.assertEqual(enc["algorithm"], "ChaCha20-Poly1305 (IETF RFC 8439)")

        dec = decrypt_medical_file(test_enc, "data", "ChaChaKeyFile2026!")
        self.assertTrue(dec["success"])
        self.assertTrue(dec["integrity_verified"])
        with open(dec["output_path"], "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("HASIL PEMERIKSAAN HISTOPATOLOGI", content)

    def test_06_criteria_database_encryption(self):
        """Kriteria #5: Database Field-Level Encryption (FLE)"""
        init_database()
        rec_id = insert_medical_record(
            patient_id="RM-2026-0081",
            doctor_id="dr_hartono",
            vital_signs="TD: 120/80 mmHg",
            raw_diagnosis="Diabetes Melitus Tipe 2 dengan Neuropati Diabetik",
            raw_prescriptions="Metformin 500mg 3x1, Gabapentin 300mg 1x1 malam",
            raw_secret_notes="Keluarga menolak amputasi jari kaki kanan."
        )
        self.assertTrue(rec_id.startswith("REC-"))

        # Raw DB test: must be encrypted
        raw_list = get_all_records(decrypted=False)
        target = [r for r in raw_list if r["record_id"] == rec_id][0]
        self.assertTrue(target["diagnosis"].startswith("AES_CBC$"))
        self.assertTrue(target["prescriptions"].startswith("AES_CBC$"))

        # Decrypted DB test: must be clear
        dec_list = get_all_records(decrypted=True)
        dec_target = [r for r in dec_list if r["record_id"] == rec_id][0]
        self.assertEqual(dec_target["diagnosis"], "Diabetes Melitus Tipe 2 dengan Neuropati Diabetik")

    def test_07_criteria_steganography(self):
        """Kriteria #6: Medical Image Steganography (LSB + AES Encrypted Payload)"""
        xray_path = os.path.join("data", "test_xray.png")
        stego_path = os.path.join("data", "test_xray_stego.png")
        generate_sample_xray_image(xray_path)

        secret = "DIAGNOSA RAHASIA: Kista Ovarium Terpuntir Dextra (Ukuran 4.5 cm)"
        key = "StegoKeyPass2026!"

        emb = embed_secret_in_image(xray_path, stego_path, secret, key)
        self.assertTrue(emb["success"])
        self.assertGreater(emb["psnr_db"], 50.0) # PSNR > 50 dB implies zero perceptible distortion

        ext = extract_secret_from_image(stego_path, key)
        self.assertTrue(ext["success"])
        self.assertEqual(ext["secret_message"], secret)

    def test_08_criteria_blockchain(self):
        """Kriteria #7: Medical Assets Blockchain Ledger (SHA-256 + PoW Immutability)"""
        from core.blockchain import BLOCKCHAIN_LEDGER_FILE
        if os.path.exists(BLOCKCHAIN_LEDGER_FILE):
            os.remove(BLOCKCHAIN_LEDGER_FILE)

        bc = MedicalBlockchain(difficulty=3)
        initial_val = bc.validate_chain_integrity()
        self.assertTrue(initial_val["is_valid"], initial_val.get("message"))

        # Add new block with mining
        new_block = bc.add_asset_block(
            asset_id="AST-SURGERY-REPORT-99",
            asset_name="Laporan Operasi Reseksi Hepar",
            patient_id="RM-2026-0081",
            data_hash="abc123sha256hashdummy",
            doctor_signer="dr_hartono"
        )
        self.assertTrue(new_block.hash.startswith("000"))

        # Tamper simulation test
        bc.simulate_tamper(1, "DATA PALSU OLEH MALWARE")
        tamper_val = bc.validate_chain_integrity()
        self.assertFalse(tamper_val["is_valid"])
        self.assertEqual(tamper_val["error_type"], "HASH_CORRUPTED")

    def test_09_cryptanalysis_metrics(self):
        """Bonus Akademis: Avalanche Effect SAC & Shannon Entropy Benchmark"""
        av = test_avalanche_effect("DIAGNOSA: Pasien Sehat", "DIAGNOSA: Pasien Sakit", "KUNCI1", "KUNCI2")
        self.assertGreaterEqual(av["avalanche_pct"], 40.0)
        self.assertLessEqual(av["avalanche_pct"], 60.0)

        # Shannon Entropy of random ciphertext
        enc = super_encrypt("SAMPLE DATA", "K1", "K2")
        import base64
        c_bytes = base64.b64decode(enc["packed_token"].encode('ascii'))
        entropy = calculate_shannon_entropy(c_bytes)
        self.assertGreater(entropy, 4.5)

        # Speed benchmark
        bm = benchmark_encryption_speed(10)
        self.assertGreater(bm["super_enc_throughput_kb_s"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
