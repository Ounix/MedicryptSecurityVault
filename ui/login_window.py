"""
MediCrypt Vault - Modern 2-Factor Authentication & Login Window
Enforces:
1. Hardware USB Flashdisk Dongle (Physical Possession + HMAC-SHA256 Token)
2. Biometric Face Recognition (Google FaceNet 128-D Deep Embeddings + YuNet Tracking)
3. Cryptographic Password Hash Verification (PBKDF2-HMAC-SHA256)
"""

import os
import cv2
import threading
import customtkinter as ctk
from PIL import Image, ImageTk
from tkinter import messagebox

from core.auth_crypto import get_or_create_default_doctor, verify_password
from core.hardware_dongle import scan_for_dongle, write_dongle_token
from core.biometrics import (
    is_face_enrolled,
    enroll_doctor_face,
    verify_doctor_face,
    detect_faces
)


class LoginWindow(ctk.CTk):
    def __init__(self, on_login_success):
        super().__init__()
        self.on_login_success = on_login_success
        self.doctor_profile = get_or_create_default_doctor()

        self.title("MediCrypt Vault - Gerbang Autentikasi Kriptografi 2-Faktor")
        self.geometry("900x640")
        self.resizable(False, False)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # State flags
        self.dongle_verified = False
        self.dongle_data = {}
        self.face_verified = False

        self._build_ui()
        self._refresh_face_status_ui()
        self._check_dongle_silent()
        self._start_dongle_heartbeat()

    def _refresh_face_status_ui(self):
        """Update Factor 2 card based on database enrollment state."""
        if self.face_verified:
            return
        if is_face_enrolled("testing"):
            self.lbl_face_badge.configure(
                text="🟡 TERDAFTAR DI DATABASE",
                text_color="#F59E0B",
                fg_color="#451A03"
            )
            self.lbl_face_detail.configure(
                text="✅ Profil wajah dokter tersimpan di database. Anda TIDAK perlu daftar ulang lagi; cukup klik tombol di bawah untuk verifikasi wajah.",
                text_color="#38BDF8"
            )
            self.btn_open_face.configure(
                text="📷 Verifikasi Wajah Dokter",
                fg_color="#0D9488"
            )
        else:
            self.lbl_face_badge.configure(
                text="🔴 BELUM TERDAFTAR DI DATABASE",
                text_color="#EF4444",
                fg_color="#3A1215"
            )
            self.lbl_face_detail.configure(
                text="Wajah dokter belum terdaftar di database. Silakan klik tombol di bawah untuk mendaftarkan wajah Anda.",
                text_color="#94A3B8"
            )
            self.btn_open_face.configure(
                text="📸 Daftarkan Wajah Dokter",
                fg_color="#0284C7"
            )

    def _build_ui(self):
        # Main background container
        self.container = ctk.CTkFrame(self, fg_color="#0F172A", corner_radius=0)
        self.container.pack(fill="both", expand=True)

        inner = ctk.CTkFrame(self.container, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=35, pady=25)

        # ------------------ TOP HEADER ------------------
        hdr = ctk.CTkFrame(inner, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 18))

        # Title & Subtitle
        title_box = ctk.CTkFrame(hdr, fg_color="transparent")
        title_box.pack(side="left")

        ctk.CTkLabel(
            title_box,
            text="🛡️ MEDICRYPT SECURITY VAULT",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color="#38BDF8"
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Sistem Pengamanan Rekam Medis Rahasia Berbasis Kriptografi Multi-Faktor",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8"
        ).pack(anchor="w")

        # Security Status Pill (Top Right)
        self.pill_vault_status = ctk.CTkLabel(
            hdr,
            text="🔒 VAULT TERKUNCI",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#EF4444",
            fg_color="#450A0A",
            corner_radius=12,
            padx=14,
            pady=6
        )
        self.pill_vault_status.pack(side="right", pady=4)

        # ------------------ 2-FACTOR SIDE-BY-SIDE PANELS ------------------
        factor_grid = ctk.CTkFrame(inner, fg_color="transparent")
        factor_grid.pack(fill="x", pady=(0, 15))
        factor_grid.grid_columnconfigure(0, weight=1, uniform="factors")
        factor_grid.grid_columnconfigure(1, weight=1, uniform="factors")

        # ====== FACTOR 1: HARDWARE DONGLE USB ======
        card_dongle = ctk.CTkFrame(
            factor_grid,
            corner_radius=12,
            fg_color="#1E293B",
            border_width=1,
            border_color="#334155"
        )
        card_dongle.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)

        # Header Factor 1
        d_top = ctk.CTkFrame(card_dongle, fg_color="transparent")
        d_top.pack(fill="x", padx=18, pady=(15, 6))

        ctk.CTkLabel(
            d_top,
            text="🔑 FAKTOR 1: HARDWARE DONGLE",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#F8FAFC"
        ).pack(side="left")

        ctk.CTkLabel(
            d_top,
            text="[Possession]",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        ).pack(side="right")

        # Status Badge
        self.lbl_dongle_badge = ctk.CTkLabel(
            card_dongle,
            text="🔴 PORT USB BELUM TERHUBUNG",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#EF4444",
            fg_color="#3A1215",
            corner_radius=8,
            padx=10,
            pady=4
        )
        self.lbl_dongle_badge.pack(anchor="w", padx=18, pady=(4, 6))

        # Description
        self.lbl_dongle_detail = ctk.CTkLabel(
            card_dongle,
            text="Silakan colokkan USB Flashdisk yang memuat token otorisasi kriptografi ke port laptop.",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8",
            wraplength=360,
            justify="left"
        )
        self.lbl_dongle_detail.pack(anchor="w", padx=18, pady=(0, 12))

        # Single Rescan Button for Factor 1
        btn_dongle_rescan = ctk.CTkButton(
            card_dongle,
            text="🔄 Pindai Ulang Port USB",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_click_rescan_usb
        )
        btn_dongle_rescan.pack(fill="x", padx=18, pady=(0, 16))

        # ====== FACTOR 2: BIOMETRIC FACE RECOGNITION ======
        card_face = ctk.CTkFrame(
            factor_grid,
            corner_radius=12,
            fg_color="#1E293B",
            border_width=1,
            border_color="#334155"
        )
        card_face.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)

        # Header Factor 2
        f_top = ctk.CTkFrame(card_face, fg_color="transparent")
        f_top.pack(fill="x", padx=18, pady=(15, 6))

        ctk.CTkLabel(
            f_top,
            text="👤 FAKTOR 2: BIOMETRIK FACENET",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#F8FAFC"
        ).pack(side="left")

        ctk.CTkLabel(
            f_top,
            text="[Inherence]",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        ).pack(side="right")

        # Status Badge
        self.lbl_face_badge = ctk.CTkLabel(
            card_face,
            text="🔴 BELUM DIVERIFIKASI",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#EF4444",
            fg_color="#3A1215",
            corner_radius=8,
            padx=10,
            pady=4
        )
        self.lbl_face_badge.pack(anchor="w", padx=18, pady=(4, 6))

        # Description
        self.lbl_face_detail = ctk.CTkLabel(
            card_face,
            text="Model: Google FaceNet 128-D Deep Embeddings dengan pelacakan wajah dinamis (OpenCV YuNet).",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8",
            wraplength=360,
            justify="left"
        )
        self.lbl_face_detail.pack(anchor="w", padx=18, pady=(0, 12))

        # Scanner Button for Factor 2
        self.btn_open_face = ctk.CTkButton(
            card_face,
            text="📷 Buka Pemindai FaceNet",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            fg_color="#0D9488",
            hover_color="#0F766E",
            command=self._open_face_scanner
        )
        self.btn_open_face.pack(fill="x", padx=18, pady=(0, 16))

        # ------------------ DOCTOR CREDENTIALS & PBKDF2 HASH ------------------
        card_pwd = ctk.CTkFrame(
            inner,
            corner_radius=12,
            fg_color="#1E293B",
            border_width=1,
            border_color="#334155"
        )
        card_pwd.pack(fill="x", pady=(0, 15))

        f_pwd_hdr = ctk.CTkFrame(card_pwd, fg_color="transparent")
        f_pwd_hdr.pack(fill="x", padx=18, pady=(12, 4))

        ctk.CTkLabel(
            f_pwd_hdr,
            text="🔐 KREDENSIAL DOKTER & MASTER VAULT KEY",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#F8FAFC"
        ).pack(side="left")

        ctk.CTkLabel(
            f_pwd_hdr,
            text="NIST SP 800-132 • PBKDF2-HMAC-SHA256 (100.000 Iterasi)",
            font=ctk.CTkFont(size=10),
            text_color="#38BDF8"
        ).pack(side="right")

        input_row = ctk.CTkFrame(card_pwd, fg_color="transparent")
        input_row.pack(fill="x", padx=18, pady=(4, 12))

        # Username Field (Empty by default - user must input from memory)
        u_box = ctk.CTkFrame(input_row, fg_color="transparent")
        u_box.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkLabel(u_box, text="ID / Username Dokter:", font=ctk.CTkFont(size=11), text_color="#94A3B8").pack(anchor="w", pady=(0, 2))
        self.ent_user = ctk.CTkEntry(
            u_box,
            height=36,
            corner_radius=6,
            border_color="#475569",
            placeholder_text="Ketik Username Dokter (testing)..."
        )
        self.ent_user.pack(fill="x")

        # Password Field (Empty by default with toggle reveal - user must input from memory)
        p_box = ctk.CTkFrame(input_row, fg_color="transparent")
        p_box.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkLabel(p_box, text="Master Vault Password:", font=ctk.CTkFont(size=11), text_color="#94A3B8").pack(anchor="w", pady=(0, 2))

        p_entry_frame = ctk.CTkFrame(p_box, fg_color="transparent")
        p_entry_frame.pack(fill="x")

        self.pwd_hidden = False
        self.ent_pwd = ctk.CTkEntry(
            p_entry_frame,
            show="",
            height=36,
            corner_radius=6,
            border_color="#475569",
            placeholder_text="Ketik Master Password Vault (test123)..."
        )
        self.ent_pwd.pack(side="left", fill="x", expand=True)

        self.btn_toggle_pwd = ctk.CTkButton(
            p_entry_frame,
            text="🔒",
            width=36,
            height=36,
            corner_radius=6,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_pwd_visibility
        )
        self.btn_toggle_pwd.pack(side="right", padx=(6, 0))

        # ------------------ SUBMIT LOGIN BUTTON ------------------
        self.btn_login = ctk.CTkButton(
            inner,
            text="🔓 BUKA BRANKAS REKAM MEDIS (AUTHORIZE & UNLOCK VAULT)",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=46,
            corner_radius=8,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_attempt_login
        )
        self.btn_login.pack(fill="x", pady=(5, 8))

        # Bottom Sub-status label
        self.lbl_system_hint = ctk.CTkLabel(
            inner,
            text="Status Keamanan: Colokkan USB Flashdisk (Faktor 1) dan Pindai Wajah Dokter (Faktor 2) untuk membuka sistem.",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        )
        self.lbl_system_hint.pack()

    # ------------------ DONGLE & CREDENTIALS HANDLING ------------------
    def _toggle_pwd_visibility(self):
        """Toggle between password masking (*) and plain text."""
        self.pwd_hidden = not getattr(self, "pwd_hidden", False)
        if self.pwd_hidden:
            self.ent_pwd.configure(show="*")
            self.btn_toggle_pwd.configure(text="👁️")
        else:
            self.ent_pwd.configure(show="")
            self.btn_toggle_pwd.configure(text="🔒")

    def _start_dongle_heartbeat(self):
        """Periodically monitor USB port in a background daemon thread to eliminate UI lag/freezes."""
        import threading
        import time

        self._dongle_lost_event = False

        def heartbeat_worker():
            while True:
                try:
                    time.sleep(2.0)
                    if not getattr(self, "winfo_exists", lambda: False)():
                        break

                    if getattr(self, "dongle_verified", False):
                        res = scan_for_dongle("testing", allow_virtual=False)
                        if not res["is_valid"] and getattr(self, "dongle_verified", False):
                            self._dongle_lost_event = True
                except Exception:
                    pass

        t = threading.Thread(target=heartbeat_worker, daemon=True)
        t.start()

        def check_lost_flag():
            if not getattr(self, "winfo_exists", lambda: False)():
                return
            if getattr(self, "_dongle_lost_event", False) and getattr(self, "dongle_verified", False):
                self._dongle_lost_event = False
                self._apply_dongle_failed("⚠️ USB Dongle telah dicabut dari port laptop!")
            self.after(500, check_lost_flag)

        self.after(500, check_lost_flag)

    def _apply_dongle_success(self, res: dict):
        self.dongle_verified = True
        self.dongle_data = res
        sn = res["data"].get("device_serial", "SERIAL-OK")
        self.lbl_dongle_badge.configure(
            text=f"🟢 DONGLE TERPASANG ({res['drive']})",
            text_color="#10B981",
            fg_color="#064E3B"
        )
        self.lbl_dongle_detail.configure(
            text=f"Drive: {res['drive']} | HW Serial: {sn}\nToken HMAC-SHA256: VALID (Terotorisasi Sah)",
            text_color="#10B981"
        )
        self._check_overall_ready()

    def _apply_dongle_failed(self, message: str):
        self.dongle_verified = False
        self.dongle_data = {}
        self.lbl_dongle_badge.configure(
            text="🔴 DONGLE TIDAK TERDETEKSI",
            text_color="#EF4444",
            fg_color="#3A1215"
        )
        self.lbl_dongle_detail.configure(
            text=message,
            text_color="#EF4444"
        )
        self._check_overall_ready()

    def _check_dongle_silent(self):
        """Silently scan upon window opening (no popup)."""
        res = scan_for_dongle("testing", allow_virtual=False)
        if res["is_valid"]:
            self._apply_dongle_success(res)
        else:
            self._apply_dongle_failed(res["message"])

    def _on_click_rescan_usb(self):
        """Single explicit action triggered by the 'Pindai Ulang Port USB' button."""
        res = scan_for_dongle("testing", allow_virtual=False)
        if res["is_valid"]:
            self._apply_dongle_success(res)
            messagebox.showinfo(
                "Dongle Terverifikasi Sah",
                f"USB Flashdisk Dongle terdeteksi di {res['drive']}!\n\n"
                f"• Hardware Serial: {res['data'].get('device_serial', 'N/A')}\n"
                f"• Tanda Tangan HMAC-SHA256: VALID\n"
                f"• Status: Sah & Terotorisasi",
                parent=self
            )
        elif res.get("unregistered_usb"):
            unreg = res["unregistered_usb"]
            mount = unreg["mount"]
            sn = unreg["serial"]
            ask = messagebox.askyesno(
                "Otorisasi USB Flashdisk Baru",
                f"Perangkat USB Flashdisk baru terdeteksi di Drive {mount} (SN: {sn}).\n\n"
                f"Flashdisk ini belum memiliki token otorisasi MediCrypt Vault.\n"
                f"Apakah Anda ingin mendaftarkan dan menulis token kriptografi sah ke flashdisk ini sekarang?",
                parent=self
            )
            if ask:
                try:
                    write_dongle_token(mount, "testing", sn)
                    new_res = scan_for_dongle("testing", allow_virtual=False)
                    if new_res["is_valid"]:
                        self._apply_dongle_success(new_res)
                        messagebox.showinfo(
                            "Inisialisasi Berhasil",
                            f"Flashdisk {mount} berhasil didaftarkan sebagai Dongle Kriptografi resmi!",
                            parent=self
                        )
                    else:
                        messagebox.showerror("Error", new_res.get("message", "Gagal memverifikasi token baru"), parent=self)
                except Exception as e:
                    messagebox.showerror("Gagal Menulis Token", f"Error saat menulis ke USB: {str(e)}", parent=self)
            else:
                self._apply_dongle_failed(res["message"])
        else:
            self._apply_dongle_failed(res["message"])
            messagebox.showwarning(
                "USB Flashdisk Belum Terpasang",
                "Port USB laptop tidak mendeteksi Flashdisk apapun!\n\n"
                "Silakan masukkan USB Flashdisk Anda ke port USB laptop terlebih dahulu, kemudian klik '🔄 Pindai Ulang Port USB'.",
                parent=self
            )

    def _check_overall_ready(self):
        """Update top status pill and bottom hint dynamically."""
        if self.dongle_verified and self.face_verified:
            self.pill_vault_status.configure(
                text="🟢 2 FAKTOR TERPENUHI",
                text_color="#10B981",
                fg_color="#064E3B"
            )
            self.lbl_system_hint.configure(
                text="✅ Seluruh faktor biometrik & hardware terverifikasi! Masukkan password untuk membuka brankas.",
                text_color="#10B981"
            )
            self.btn_login.configure(fg_color="#059669", hover_color="#047857")
        elif self.dongle_verified:
            self.pill_vault_status.configure(
                text="🟡 MENUNGGU BIOMETRIK",
                text_color="#F59E0B",
                fg_color="#451A03"
            )
            self.lbl_system_hint.configure(
                text="Faktor 1 (Dongle USB) sah. Lakukan pemindaian wajah (Faktor 2) untuk melanjutkan.",
                text_color="#F59E0B"
            )
            self.btn_login.configure(fg_color="#0284C7", hover_color="#0369A1")
        elif self.face_verified:
            self.pill_vault_status.configure(
                text="🟡 MENUNGGU DONGLE",
                text_color="#F59E0B",
                fg_color="#451A03"
            )
            self.lbl_system_hint.configure(
                text="Faktor 2 (Biometrik Wajah) sah. Harap colokkan USB Flashdisk (Faktor 1) untuk melanjutkan.",
                text_color="#F59E0B"
            )
            self.btn_login.configure(fg_color="#0284C7", hover_color="#0369A1")
        else:
            self.pill_vault_status.configure(
                text="🔒 VAULT TERKUNCI",
                text_color="#EF4444",
                fg_color="#450A0A"
            )
            self.lbl_system_hint.configure(
                text="Status Keamanan: Colokkan USB Flashdisk (Faktor 1) dan Pindai Wajah Dokter (Faktor 2) untuk membuka sistem.",
                text_color="#64748B"
            )
            self.btn_login.configure(fg_color="#0284C7", hover_color="#0369A1")

    # ------------------ BIOMETRIC: FACE SCANNER ------------------
    def _open_face_scanner(self):
        scanner = ctk.CTkToplevel(self)
        scanner.title("Pemindai Wajah Dokter (Google FaceNet Deep Neural Network)")
        scanner.geometry("680x640")
        scanner.transient(self)
        scanner.grab_set()

        # Header Frame with Mirror Toggle
        hdr_frame = ctk.CTkFrame(scanner, fg_color="transparent")
        hdr_frame.pack(fill="x", padx=20, pady=(10, 4))

        title_box = ctk.CTkFrame(hdr_frame, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="PEMINDAI BIOMETRIK WAJAH (FACENET)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(title_box, text="Kotak hijau otomatis mendeteksi & mengikuti wajah (YuNet + FaceNet 128-D)", font=ctk.CTkFont(size=11), text_color="gray70").pack(anchor="w")

        # Mirror toggle state (Default: False = TIDAK MIRROR, as requested)
        mirror_mode = [False]

        def toggle_mirror():
            mirror_mode[0] = not mirror_mode[0]
            if mirror_mode[0]:
                btn_mirror.configure(text="🪞 Tampilan: Cermin (Mirror)", fg_color="#334155")
            else:
                btn_mirror.configure(text="📷 Tampilan: Tidak Mirror (Normal)", fg_color="#1E293B")

        btn_mirror = ctk.CTkButton(
            hdr_frame,
            text="📷 Tampilan: Tidak Mirror (Normal)",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=210,
            fg_color="#1E293B",
            command=toggle_mirror
        )
        btn_mirror.pack(side="right", pady=2)

        # Video canvas
        video_label = ctk.CTkLabel(scanner, text="Menghubungkan ke Webcam...", width=480, height=360, fg_color="black")
        video_label.pack(pady=5)

        # Initial status based on database
        is_enrolled_initial = is_face_enrolled("testing")
        init_status_text = "🟢 Profil dokter ditemukan di Database! Posisikan wajah lalu klik 'Verifikasi Wajah Live'." if is_enrolled_initial else "🟡 Wajah dokter belum terdaftar di Database. Posisikan wajah lalu klik 'Daftarkan Wajah'."
        init_status_clr = "#10B981" if is_enrolled_initial else "#F59E0B"

        lbl_sim_score = ctk.CTkLabel(scanner, text=init_status_text, font=ctk.CTkFont(size=12, weight="bold"), text_color=init_status_clr)
        lbl_sim_score.pack(pady=5)

        cap_lock = threading.Lock()
        is_running = [True]
        current_frame = [None]
        current_face_bbox = [None]

        cap = cv2.VideoCapture(0)

        def stream_loop():
            while is_running[0]:
                ret, raw_frame = cap.read()
                if ret:
                    # Apply mirror / unmirror preference
                    if mirror_mode[0]:
                        frame = cv2.flip(raw_frame, 1)
                    else:
                        frame = raw_frame.copy()

                    # Dynamic Face Tracking with YuNet
                    detected = detect_faces(frame, score_threshold=0.55)

                    with cap_lock:
                        current_frame[0] = frame.copy()
                        if detected:
                            bx, by, bw, bh = detected[0]["box"]
                            current_face_bbox[0] = (bx, by, bw, bh)
                            conf = detected[0]["confidence"]
                            # Draw dynamic tracking bounding box that follows the face!
                            cv2.rectangle(frame, (bx, by), (bx + bw, by + bh), (0, 255, 0), 2)
                            cv2.rectangle(frame, (bx, max(0, by - 24)), (bx + 190, by), (0, 255, 0), cv2.FILLED)
                            cv2.putText(
                                frame,
                                f"FACENET: {int(conf * 100)}%",
                                (bx + 4, max(16, by - 6)),
                                cv2.FONT_HERSHEY_SIMPLEX,
                                0.45,
                                (0, 0, 0),
                                1,
                                cv2.LINE_AA
                            )
                            status_txt = f"🟢 Wajah terdeteksi ({bw}x{bh} px) - Siap Diverifikasi"
                            status_clr = "#10B981"
                        else:
                            current_face_bbox[0] = None
                            status_txt = "🟡 Mencari wajah... Posisikan wajah Anda menghadap webcam"
                            status_clr = "#F59E0B"

                    if not is_running[0]:
                        break

                    # Convert BGR to RGB for Tkinter display
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    rgb_resized = cv2.resize(rgb, (480, 360))
                    img = Image.fromarray(rgb_resized)
                    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(480, 360))

                    try:
                        lbl_sim_score.configure(text=status_txt, text_color=status_clr)
                        video_label.configure(image=ctk_img, text="")
                        video_label.image = ctk_img
                    except Exception:
                        break
                else:
                    break

        thread = threading.Thread(target=stream_loop, daemon=True)
        thread.start()

        def on_close():
            is_running[0] = False
            cap.release()
            scanner.destroy()

        scanner.protocol("WM_DELETE_WINDOW", on_close)

        # Buttons Frame
        btn_box = ctk.CTkFrame(scanner, fg_color="transparent")
        btn_box.pack(pady=10)

        def enroll_face():
            with cap_lock:
                f = current_frame[0]
                box = current_face_bbox[0]
            if f is None or box is None:
                messagebox.showwarning("Peringatan", "Wajah belum terdeteksi! Tunggu hingga kotak hijau mengikuti wajah Anda.", parent=scanner)
                return
            ok, msg = enroll_doctor_face(f, "testing", bbox=box)
            if ok:
                self._refresh_face_status_ui()
                btn_ver.configure(fg_color="#059669", hover_color="#047857", text="🔍 Verifikasi Wajah Live")
                btn_reg.configure(fg_color="#334155", hover_color="#475569", text="🔄 Daftar Ulang (Update Foto)")
                messagebox.showinfo("Tersimpan di Database", "Wajah dokter berhasil didaftarkan dan tersimpan permanen di Database SQLite!\n\nSekarang Anda dapat langsung mengklik 'Verifikasi Wajah Live'.", parent=scanner)
            else:
                messagebox.showerror("Error", msg, parent=scanner)

        def verify_face():
            if not is_face_enrolled("testing"):
                messagebox.showwarning(
                    "Peringatan",
                    "Wajah dokter BELUM didaftarkan di sistem!\n\nSilakan klik tombol 'Daftarkan Wajah' terlebih dahulu.",
                    parent=scanner
                )
                return

            with cap_lock:
                f = current_frame[0]
                box = current_face_bbox[0]
            if f is None or box is None:
                messagebox.showwarning("Peringatan", "Wajah belum terdeteksi kamera! Tunggu hingga kotak hijau muncul di wajah Anda.", parent=scanner)
                return

            ok, sim, msg = verify_doctor_face(f, threshold_cosine=0.65, bbox=box, doctor_username="testing")
            lbl_sim_score.configure(text=msg, text_color="#10B981" if ok else "#EF4444")
            if ok:
                self.face_verified = True
                pct = round(max(0, sim) * 100, 1)
                self.lbl_face_badge.configure(
                    text=f"🟢 TERVERIFIKASI ({pct}%)",
                    text_color="#10B981",
                    fg_color="#064E3B"
                )
                self.lbl_face_detail.configure(
                    text=f"Vektor 128-D Cocok: Cosine Similarity {pct}% (Sah)\nIdentitas: {self.doctor_profile.get('full_name')}",
                    text_color="#10B981"
                )
                self.btn_open_face.configure(text="✅ Wajah Terverifikasi", fg_color="#059669")
                self._check_overall_ready()
                messagebox.showinfo("Verifikasi FaceNet Sukses", msg, parent=scanner)
                on_close()
            else:
                messagebox.showerror("Verifikasi FaceNet Gagal", msg, parent=scanner)

        if is_enrolled_initial:
            btn_ver = ctk.CTkButton(btn_box, text="🔍 Verifikasi Wajah Live", font=ctk.CTkFont(size=13, weight="bold"), width=230, height=40, fg_color="#059669", hover_color="#047857", command=verify_face)
            btn_ver.pack(side="left", padx=8)

            btn_reg = ctk.CTkButton(btn_box, text="🔄 Daftar Ulang (Update Foto)", font=ctk.CTkFont(size=12), width=190, height=40, fg_color="#334155", hover_color="#475569", command=enroll_face)
            btn_reg.pack(side="left", padx=8)
        else:
            btn_reg = ctk.CTkButton(btn_box, text="📸 Daftarkan Wajah ke Database", font=ctk.CTkFont(size=13, weight="bold"), width=230, height=40, fg_color="#0284C7", hover_color="#0369A1", command=enroll_face)
            btn_reg.pack(side="left", padx=8)

            btn_ver = ctk.CTkButton(btn_box, text="🔍 Verifikasi Wajah Live", font=ctk.CTkFont(size=12), width=190, height=40, fg_color="#334155", hover_color="#475569", command=verify_face)
            btn_ver.pack(side="left", padx=8)

    # ------------------ LOGIN ATTEMPT ------------------
    def _on_attempt_login(self):
        # 1. Check Credentials Inputs from user (must be typed from memory)
        u = self.ent_user.get().strip()
        p = self.ent_pwd.get().strip()

        if not u or not p:
            messagebox.showwarning(
                "Input Kosong",
                "Harap masukkan ID / Username Dokter dan Master Vault Password Anda!",
                parent=self
            )
            return

        # 2. Strict Live Check on Factor 1: Physical Dongle USB Presence
        # Re-verify that the authorized physical dongle is still physically plugged into the port:
        live_dongle = scan_for_dongle("testing", allow_virtual=False)
        if not live_dongle["is_valid"]:
            # If USB was physically unplugged, invalidate dongle state:
            self.dongle_verified = False
            self.dongle_data = {}
            self._apply_dongle_failed("⚠️ USB Dongle tidak terdeteksi atau telah dicabut dari port laptop!")
            messagebox.showerror(
                "Akses Ditolak: USB Dongle Dicabut / Tidak Ditemukan!",
                "Perangkat Hardware USB Dongle tidak ditemukan di port laptop!\n\n"
                "Sistem mendeteksi USB Flashdisk telah dicabut. Untuk menjaga integritas kriptografi brankas medis, Hardware Dongle USB wajib tetap tercolok di laptop saat membuka brankas.",
                parent=self
            )
            return

        # Dongle is physically present and verified
        self.dongle_verified = True
        self.dongle_data = live_dongle

        # 3. Check Factor 2: FaceNet Biometric Verification
        if not self.face_verified:
            messagebox.showerror(
                "Akses Ditolak: Faktor 2 (Biometrik Wajah)",
                "Otentikasi biometrik wajah Google FaceNet belum dilakukan!\n\n"
                "Silakan klik tombol '📷 Verifikasi Wajah Dokter' untuk memverifikasi wajah Anda.",
                parent=self
            )
            return

        # 4. Check Credentials: Username & Password PBKDF2-HMAC-SHA256 Hash
        # (If credentials are wrong, dongle and face status REMAIN verified!)
        if u != self.doctor_profile.get("username"):
            messagebox.showerror(
                "Akses Ditolak: Username Tidak Dikenal",
                f"Username dokter '{u}' salah atau tidak terdaftar dalam sistem!\n\n"
                "💡 Status verifikasi USB Dongle dan Biometrik Wajah tetap aktif (sah). Silakan periksa kembali ketikan username Anda.",
                parent=self
            )
            return

        stored_hash = self.doctor_profile.get("password_hash")
        if not verify_password(stored_hash, p):
            messagebox.showerror(
                "Akses Ditolak: Password Salah",
                "Master Password Vault yang Anda masukkan salah!\n\n"
                "Verifikasi nilai hash PBKDF2-HMAC-SHA256 (100.000 iterasi) tidak cocok.\n\n"
                "💡 Status verifikasi USB Dongle dan Biometrik Wajah tetap aktif (sah). Silakan masukkan password kembali.",
                parent=self
            )
            return

        # All 2 security factors + cryptographic password verified!
        messagebox.showinfo(
            "Otorisasi Lengkap - Akses Diberikan",
            f"Selamat Datang, {self.doctor_profile.get('full_name')}!\n\n"
            f"• Faktor 1 (Hardware USB Dongle): SAH ({self.dongle_data.get('drive', 'USB')})\n"
            f"• Faktor 2 (Biometrik Google FaceNet): TERVERIFIKASI SAH\n"
            f"• Kredensial PBKDF2-HMAC-SHA256: VALID (Hash Cocok)\n\n"
            f"Brankas Rekam Medis Elektronik Terbuka.",
            parent=self
        )
        self.destroy()
        self.on_login_success(self.doctor_profile, self.dongle_data)
