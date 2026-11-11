"""
MediCrypt Vault - Super Encryption UI Tab
Combines Classical Vigenère Cipher and Modern AES-256-GCM
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
from core.super_encryption import super_encrypt, super_decrypt


class SuperTextTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 15))

        title = ctk.CTkLabel(
            header,
            text="🔐 Super Enkripsi Teks Medis (Kriptografi Klasik + Modern)",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Menggabungkan Extended 256-Byte Vigenère Cipher (Klasik) dengan AES-256-GCM (Modern) "
                 "untuk menjamin kerahasiaan berlapis dan integritas pesan medis.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        # Main scrollable or two-column container
        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # ------------------ ENCRYPTION SECTION ------------------
        enc_card = ctk.CTkFrame(content_frame, corner_radius=8)
        enc_card.pack(fill="x", pady=5)

        ctk.CTkLabel(enc_card, text="1. INPUT REKAM MEDIS & KUNCI GANDA", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        # Text input
        ctk.CTkLabel(enc_card, text="Pesan Teks / Diagnosa Sensitif:", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=15, pady=(5, 2))
        self.txt_input = ctk.CTkTextbox(enc_card, height=80)
        self.txt_input.pack(fill="x", padx=15, pady=(0, 10))
        self.txt_input.insert("1.0", "Pasien NIK 327104: Diagnosa Tuberkulosis Paru Multi-Drug Resistant (MDR-TB). Resep: Bedaquiline 400mg, Linezolid 600mg.")

        # Keys Frame
        keys_frame = ctk.CTkFrame(enc_card, fg_color="transparent")
        keys_frame.pack(fill="x", padx=15, pady=(0, 10))

        # Key 1: Vigenere
        f1 = ctk.CTkFrame(keys_frame, fg_color="transparent")
        f1.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(f1, text="🔑 Kunci Klasik (Vigenère):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")

        vig_box = ctk.CTkFrame(f1, fg_color="transparent")
        vig_box.pack(fill="x", pady=3)

        self.vig_key_hidden = False
        self.ent_vig_key = ctk.CTkEntry(vig_box, show="", placeholder_text="Misal: CIPHERKLASIK2026")
        self.ent_vig_key.pack(side="left", fill="x", expand=True)
        self.ent_vig_key.insert(0, "KUNCIKLASIKMEDIS")

        self.btn_toggle_vig_key = ctk.CTkButton(
            vig_box,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_vig_key_visibility
        )
        self.btn_toggle_vig_key.pack(side="right", padx=(5, 0))

        # Key 2: AES
        f2 = ctk.CTkFrame(keys_frame, fg_color="transparent")
        f2.pack(side="left", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(f2, text="🔑 Kunci Modern (AES-256):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")

        aes_box = ctk.CTkFrame(f2, fg_color="transparent")
        aes_box.pack(fill="x", pady=3)

        self.aes_key_hidden = False
        self.ent_aes_key = ctk.CTkEntry(aes_box, show="", placeholder_text="Kunci Sandi AES Modern")
        self.ent_aes_key.pack(side="left", fill="x", expand=True)
        self.ent_aes_key.insert(0, "SuperSecretAES2026!")

        self.btn_toggle_aes_key = ctk.CTkButton(
            aes_box,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_aes_key_visibility
        )
        self.btn_toggle_aes_key.pack(side="right", padx=(5, 0))

        # Encrypt button
        btn_encrypt = ctk.CTkButton(
            enc_card,
            text="🔒 Jalankan Super Enkripsi (Vigenère -> AES-256-GCM)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_encrypt
        )
        btn_encrypt.pack(padx=15, pady=10)

        # ------------------ STAGES BREAKDOWN ------------------
        self.stages_card = ctk.CTkFrame(content_frame, corner_radius=8)
        self.stages_card.pack(fill="x", pady=10)

        ctk.CTkLabel(self.stages_card, text="2. VISUALISASI PROSES SUPER ENKRIPSI BERTAHAP", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        # Step 1 view
        ctk.CTkLabel(self.stages_card, text="Tahap 1: Ciphertext Klasik (Extended Vigenère):", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38BDF8").pack(anchor="w", padx=15, pady=(5, 2))
        self.lbl_step1 = ctk.CTkEntry(self.stages_card)
        self.lbl_step1.pack(fill="x", padx=15, pady=2)

        # Step 2 metadata
        meta_frame = ctk.CTkFrame(self.stages_card, fg_color="transparent")
        meta_frame.pack(fill="x", padx=15, pady=5)

        self.lbl_nonce = ctk.CTkLabel(meta_frame, text="AES Nonce (IV): -", font=ctk.CTkFont(family="Consolas", size=11))
        self.lbl_nonce.pack(side="left", padx=(0, 20))

        self.lbl_tag = ctk.CTkLabel(meta_frame, text="GCM Auth Tag: -", font=ctk.CTkFont(family="Consolas", size=11))
        self.lbl_tag.pack(side="left")

        # Step 2 final token view
        ctk.CTkLabel(self.stages_card, text="Tahap 2: Final Super Ciphertext (Base64 Token):", font=ctk.CTkFont(size=12, weight="bold"), text_color="#10B981").pack(anchor="w", padx=15, pady=(5, 2))
        self.txt_final_token = ctk.CTkTextbox(self.stages_card, height=70)
        self.txt_final_token.pack(fill="x", padx=15, pady=2)

        # Copy button
        btn_copy = ctk.CTkButton(self.stages_card, text="📋 Salin Token ke Clipboard", width=180, command=self._copy_token)
        btn_copy.pack(anchor="e", padx=15, pady=(5, 10))

        # ------------------ DECRYPTION SECTION ------------------
        dec_card = ctk.CTkFrame(content_frame, corner_radius=8)
        dec_card.pack(fill="x", pady=10)

        ctk.CTkLabel(dec_card, text="3. PROSES DEKRIPSI SUPER (VERIFIKASI INTEGRITAS GCM)", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        btn_decrypt = ctk.CTkButton(
            dec_card,
            text="🔓 Jalankan Super Dekripsi (AES-256-GCM -> Vigenère)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self._on_decrypt
        )
        btn_decrypt.pack(padx=15, pady=10)

        self.lbl_integrity_badge = ctk.CTkLabel(dec_card, text="", font=ctk.CTkFont(size=13, weight="bold"))
        self.lbl_integrity_badge.pack(padx=15, pady=2)

        ctk.CTkLabel(dec_card, text="Hasil Dekripsi Plaintext Asli:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(5, 2))
        self.txt_decrypted_result = ctk.CTkTextbox(dec_card, height=80)
        self.txt_decrypted_result.pack(fill="x", padx=15, pady=(0, 15))

    # ------------------ TOGGLE EYE BUTTONS ------------------
    def _toggle_vig_key_visibility(self):
        self.vig_key_hidden = not getattr(self, "vig_key_hidden", False)
        if self.vig_key_hidden:
            self.ent_vig_key.configure(show="*")
            self.btn_toggle_vig_key.configure(text="👁️")
        else:
            self.ent_vig_key.configure(show="")
            self.btn_toggle_vig_key.configure(text="🔒")

    def _toggle_aes_key_visibility(self):
        self.aes_key_hidden = not getattr(self, "aes_key_hidden", False)
        if self.aes_key_hidden:
            self.ent_aes_key.configure(show="*")
            self.btn_toggle_aes_key.configure(text="👁️")
        else:
            self.ent_aes_key.configure(show="")
            self.btn_toggle_aes_key.configure(text="🔒")

    def _on_encrypt(self):
        text = self.txt_input.get("1.0", "end-1c").strip()
        vig_key = self.ent_vig_key.get().strip()
        aes_key = self.ent_aes_key.get().strip()

        if not text:
            messagebox.showwarning("Peringatan", "Pesan teks medis tidak boleh kosong!")
            return
        if not vig_key or not aes_key:
            messagebox.showwarning("Peringatan", "Kedua kunci (Klasik & Modern) harus diisi!")
            return

        try:
            res = super_encrypt(text, vig_key, aes_key)
            self.lbl_step1.delete(0, "end")
            self.lbl_step1.insert(0, res["step1_classical_b64"])

            self.lbl_nonce.configure(text=f"AES Nonce (16B): {res['nonce_hex'][:16]}...")
            self.lbl_tag.configure(text=f"GCM Auth Tag (16B): {res['tag_hex']}")

            self.txt_final_token.delete("1.0", "end")
            self.txt_final_token.insert("1.0", res["packed_token"])
            messagebox.showinfo("Sukses", "Super Enkripsi berhasil dieksekusi dengan sempurna!")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal mengeksekusi super enkripsi: {str(e)}")

    def _copy_token(self):
        token = self.txt_final_token.get("1.0", "end-1c").strip()
        if token:
            self.clipboard_clear()
            self.clipboard_append(token)
            messagebox.showinfo("Disalin", "Token Super Ciphertext berhasil disalin ke clipboard!")

    def _on_decrypt(self):
        token = self.txt_final_token.get("1.0", "end-1c").strip()
        vig_key = self.ent_vig_key.get().strip()
        aes_key = self.ent_aes_key.get().strip()

        if not token:
            messagebox.showwarning("Peringatan", "Token ciphertext tidak ditemukan!")
            return

        res = super_decrypt(token, vig_key, aes_key)
        if res["success"]:
            self.lbl_integrity_badge.configure(
                text="✅ AUTHENTICATION TAG VERIFIED (100% Sah & Tidak Mengalami Modifikasi)",
                text_color="#10B981"
            )
            self.txt_decrypted_result.delete("1.0", "end")
            self.txt_decrypted_result.insert("1.0", res["decrypted_plaintext"])
        else:
            self.lbl_integrity_badge.configure(
                text=f"❌ {res['error']}",
                text_color="#EF4444"
            )
            self.txt_decrypted_result.delete("1.0", "end")
            messagebox.showerror("Gagal Dekripsi", res["error"])

