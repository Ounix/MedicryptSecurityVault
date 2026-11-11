"""
MediCrypt Vault - Main Application Entrypoint
Secure Electronic Health Record (EHR) Cryptographic Desktop Application

Fulfills all 7 Course Final Project Criteria:
1. Biometric Login (Face Recognition & Fingerprint) + Hardware USB Dongle Protection
2. Cryptographic Login Authentication (PBKDF2-HMAC-SHA256 Salted Hashing)
3. Text Message Super Encryption (Extended Vigenère + AES-256-GCM)
4. Medical File Encryption (ChaCha20-Poly1305 Stream Cipher)
5. Sensitive Medical Database Field-Level Encryption (SQLite AES-256-CBC)
6. Medical Image Steganography (LSB Embedding + AES Payload Encryption)
7. Medical Digital Assets Blockchain Ledger (SHA-256 + Proof of Work Immutability)
"""

import sys
import os
import warnings

# Suppress warnings and colored output in terminal
warnings.filterwarnings('ignore')
os.environ["OPENCV_LOG_LEVEL"] = "OFF"
os.environ["OPENCV_VIDEOIO_DEBUG"] = "0"

import cv2
if hasattr(cv2, 'utils') and hasattr(cv2.utils, 'logging'):
    try:
        cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_SILENT)
    except Exception:
        pass

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.db_crypto import init_database
from core.steganography import generate_sample_xray_image
from core.blockchain import MedicalBlockchain
from ui.login_window import LoginWindow
from ui.main_dashboard import MainDashboard


def initialize_environment():
    """Ensure initial files, sample images, and database are ready."""
    os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "data", "biometrics"), exist_ok=True)

    init_database()

    xray_path = os.path.join(os.path.dirname(__file__), "data", "sample_xray.png")
    if not os.path.exists(xray_path):
        generate_sample_xray_image(xray_path)

    MedicalBlockchain()


def launch_application():
    initialize_environment()

    def show_dashboard(doctor_profile, dongle_info):
        dashboard = MainDashboard(doctor_profile, dongle_info, on_logout_callback=show_login)
        dashboard.mainloop()

    def show_login():
        login_win = LoginWindow(on_login_success=show_dashboard)
        login_win.mainloop()

    show_login()


if __name__ == "__main__":
    launch_application()

