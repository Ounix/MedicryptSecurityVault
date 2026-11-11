"""
MediCrypt Vault - File Encryption UI Tab
Encrypts any file (Videos, Photos, Medical Documents, Audio, etc.) using ChaCha20-Poly1305.
Features a streamlined 2-column empty input decryption workflow:
  Column 1 (Empty): Paste Ciphertext
  Column 2 (Empty): Enter Key
  -> Decrypts back to the exact original file!
"""

import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from core.file_crypto import encrypt_medical_file, decrypt_medical_file, calculate_file_hash


class FileCryptoTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.selected_file_path = None
        self.last_encrypted_path = None
        self.last_restored_file = None
        self.enc_key_hidden = False
        self.dec_key_hidden = False
        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 15))

        title = ctk.CTkLabel(
            header,
            text="📁 Enkripsi Berkas Medis & Media (ChaCha20-Poly1305 RFC 8439)",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Mendukung seluruh format file (Video MP4/MKV, Foto/Citra Medis JPG/PNG/DICOM, Dokumen PDF/Word, Audio, dll). "
                 "Berkas dienkripsi menjadi Ciphertext terverifikasi, dan didekripsi kembali menjadi file inputan asli secara utuh.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # ================================================================
        # 1. FILE SELECTION & ENCRYPT
        # ================================================================
        card1 = ctk.CTkFrame(content_frame, corner_radius=8)
        card1.pack(fill="x", pady=5)

        ctk.CTkLabel(
            card1,
            text="1. PILIH BERKAS REKAM MEDIS & ENKRIPSI",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        # File picker row
        file_picker_frame = ctk.CTkFrame(card1, fg_color="transparent")
        file_picker_frame.pack(fill="x", padx=15, pady=5)

        self.lbl_selected_file = ctk.CTkEntry(
            file_picker_frame,
            placeholder_text="Pilih berkas dari komputer (Video MP4, Foto JPG/PNG, Dokumen PDF, dll)..."
        )
        self.lbl_selected_file.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse = ctk.CTkButton(
            file_picker_frame,
            text="🔍 Browse Berkas",
            width=140,
            command=self._browse_file
        )
        btn_browse.pack(side="right")

        # File detail label
        self.lbl_file_details = ctk.CTkLabel(
            card1,
            text="Status Berkas: Belum ada berkas yang dipilih.",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8"
        )
        self.lbl_file_details.pack(anchor="w", padx=15, pady=(0, 5))

        # Passphrase with Toggle Eye Button
        pw_frame = ctk.CTkFrame(card1, fg_color="transparent")
        pw_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(pw_frame, text="🔑 Kunci Sandi ChaCha20:", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 10))

        key_box1 = ctk.CTkFrame(pw_frame, fg_color="transparent")
        key_box1.pack(side="left", fill="x", expand=True)

        self.ent_file_key = ctk.CTkEntry(key_box1, show="", width=320, placeholder_text="Masukkan Kunci ChaCha20...")
        self.ent_file_key.pack(side="left", fill="x", expand=True)
        self.ent_file_key.insert(0, "ChaCha20FileSecretPass2026!")

        self.btn_toggle_enc_key = ctk.CTkButton(
            key_box1,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_enc_key_visibility
        )
        self.btn_toggle_enc_key.pack(side="left", padx=(6, 0))

        # Encrypt button
        self.btn_encrypt_file = ctk.CTkButton(
            card1,
            text="🔒 Jalankan Enkripsi Berkas ke Ciphertext (ChaCha20-Poly1305)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_encrypt_file
        )
        self.btn_encrypt_file.pack(padx=15, pady=(10, 15))

        # ================================================================
        # 2. HASIL CIPHERTEXT & KONTROL SALIN
        # ================================================================
        self.cipher_card = ctk.CTkFrame(content_frame, corner_radius=8)
        self.cipher_card.pack(fill="x", pady=10)

        ctk.CTkLabel(
            self.cipher_card,
            text="2. HASIL CIPHERTEXT KELUARAN ENKRIPSI",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 4))

        ctk.CTkLabel(
            self.cipher_card,
            text="Ciphertext yang dihasilkan (Gunakan tombol 'Salin Ciphertext' untuk disalin ke Bagian 3):",
            font=ctk.CTkFont(size=11),
            text_color="#38BDF8"
        ).pack(anchor="w", padx=15, pady=(2, 2))

        # Ciphertext display row
        c_row = ctk.CTkFrame(self.cipher_card, fg_color="transparent")
        c_row.pack(fill="x", padx=15, pady=4)

        self.ent_cipher_output = ctk.CTkEntry(
            c_row,
            font=ctk.CTkFont(family="Consolas", size=11),
            placeholder_text="Ciphertext hasil enkripsi akan muncul di sini setelah Anda mengklik 'Enkripsi Berkas'..."
        )
        self.ent_cipher_output.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_copy_cipher = ctk.CTkButton(
            c_row,
            text="📋 Salin Ciphertext",
            width=160,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._copy_ciphertext
        )
        btn_copy_cipher.pack(side="right")

        btn_open_enc = ctk.CTkButton(
            c_row,
            text="📂 Buka di Folder",
            width=130,
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_cipher_folder
        )
        btn_open_enc.pack(side="right", padx=(0, 6))

        # Technical Metadata Textbox
        self.txt_info = ctk.CTkTextbox(self.cipher_card, height=100, font=ctk.CTkFont(family="Consolas", size=11))
        self.txt_info.pack(fill="x", padx=15, pady=(6, 12))
        self.txt_info.insert("1.0", "Detail parameter kriptografi (Nonce, Poly1305 MAC, SHA-256 Checksum) akan muncul di sini.")

        # ================================================================
        # 3. DEKRIPSI: 2 KOLOM KOSONG (CIPHERTEXT + KUNCI) -> BERKAS ASLI
        # ================================================================
        card2 = ctk.CTkFrame(content_frame, corner_radius=8)
        card2.pack(fill="x", pady=10)

        ctk.CTkLabel(
            card2,
            text="3. DEKRIPSI: CIPHERTEXT + KUNCI -> KEMBALI KE BERKAS INPUTAN ASLI",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 4))

        ctk.CTkLabel(
            card2,
            text="Masukkan Ciphertext pada Kolom 1 dan Kunci pada Kolom 2 di bawah untuk memulihkan berkas asli.",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8"
        ).pack(anchor="w", padx=15, pady=(0, 8))

        # ------------------ KOLOM 1: CIPHERTEXT (KOSONG) ------------------
        col1_frame = ctk.CTkFrame(card2, fg_color="transparent")
        col1_frame.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(
            col1_frame,
            text="1. Kolom Ciphertext (Salin / Tempel Ciphertext di sini):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8"
        ).pack(anchor="w", pady=(0, 2))

        c_input_box = ctk.CTkFrame(col1_frame, fg_color="transparent")
        c_input_box.pack(fill="x")

        self.ent_dec_ciphertext = ctk.CTkEntry(
            c_input_box,
            font=ctk.CTkFont(family="Consolas", size=11),
            placeholder_text="[KOLOM KOSONG] Tempelkan Ciphertext hasil salinan di sini (atau klik tombol 'Tempel')..."
        )
        self.ent_dec_ciphertext.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_paste = ctk.CTkButton(
            c_input_box,
            text="📋 Tempel (Paste)",
            width=140,
            fg_color="#0D9488",
            hover_color="#0F766E",
            command=self._paste_ciphertext
        )
        btn_paste.pack(side="right")

        btn_browse_dec = ctk.CTkButton(
            c_input_box,
            text="🔍 Browse .enc",
            width=120,
            fg_color="#475569",
            hover_color="#334155",
            command=self._browse_decrypt_file
        )
        btn_browse_dec.pack(side="right", padx=(0, 6))

        # ------------------ KOLOM 2: KUNCI (KOSONG) ------------------
        col2_frame = ctk.CTkFrame(card2, fg_color="transparent")
        col2_frame.pack(fill="x", padx=15, pady=6)

        ctk.CTkLabel(
            col2_frame,
            text="2. Kolom Kunci Sandi ChaCha20:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8"
        ).pack(anchor="w", pady=(0, 2))

        k_input_box = ctk.CTkFrame(col2_frame, fg_color="transparent")
        k_input_box.pack(fill="x")

        self.ent_dec_key = ctk.CTkEntry(
            k_input_box,
            show="",
            placeholder_text="[KOLOM KOSONG] Masukkan kunci sandi ChaCha20 untuk mendekripsi berkas..."
        )
        self.ent_dec_key.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.btn_toggle_dec_key = ctk.CTkButton(
            k_input_box,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_dec_key_visibility
        )
        self.btn_toggle_dec_key.pack(side="right")

        # Decrypt button
        self.btn_decrypt_file = ctk.CTkButton(
            card2,
            text="🔓 Jalankan Dekripsi ke Berkas Asli (ChaCha20-Poly1305)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=42,
            fg_color="#059669",
            hover_color="#047857",
            command=self._on_decrypt_file
        )
        self.btn_decrypt_file.pack(padx=15, pady=(12, 6))

        # Result status badge and action buttons
        self.lbl_decrypt_status = ctk.CTkLabel(card2, text="", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_decrypt_status.pack(padx=15, pady=2)

        self.res_act_frame = ctk.CTkFrame(card2, fg_color="transparent")
        self.res_act_frame.pack(padx=15, pady=(2, 14))

        self.btn_open_file = ctk.CTkButton(
            self.res_act_frame,
            text="▶️ Buka / Putar Berkas Hasil Pulih",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._open_restored_file,
            state="disabled"
        )
        self.btn_open_file.pack(side="left", padx=5)

        self.btn_open_folder = ctk.CTkButton(
            self.res_act_frame,
            text="📂 Buka Folder Berkas",
            fg_color="#475569",
            hover_color="#334155",
            command=self._open_restored_folder,
            state="disabled"
        )
        self.btn_open_folder.pack(side="left", padx=5)

    # ------------------ TOGGLE EYE BUTTONS ------------------
    def _toggle_enc_key_visibility(self):
        self.enc_key_hidden = not getattr(self, "enc_key_hidden", False)
        if self.enc_key_hidden:
            self.ent_file_key.configure(show="*")
            self.btn_toggle_enc_key.configure(text="👁️")
        else:
            self.ent_file_key.configure(show="")
            self.btn_toggle_enc_key.configure(text="🔒")

    def _toggle_dec_key_visibility(self):
        self.dec_key_hidden = not getattr(self, "dec_key_hidden", False)
        if self.dec_key_hidden:
            self.ent_dec_key.configure(show="*")
            self.btn_toggle_dec_key.configure(text="👁️")
        else:
            self.ent_dec_key.configure(show="")
            self.btn_toggle_dec_key.configure(text="🔒")

    # ------------------ FILE BROWSING & CLIPBOARD ------------------
    def _browse_file(self):
        f = filedialog.askopenfilename(
            title="Pilih Berkas Apapun (Video, Foto, Dokumen, Audio, dll)",
            filetypes=[
                ("Semua Berkas (*.*)", "*.*"),
                ("Berkas Video (*.mp4;*.mkv;*.avi;*.mov;*.flv;*.wmv)", "*.mp4;*.mkv;*.avi;*.mov;*.flv;*.wmv"),
                ("Berkas Foto / Citra (*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.dcm)", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.dcm"),
                ("Dokumen Medis (*.pdf;*.docx;*.txt;*.xlsx)", "*.pdf;*.docx;*.txt;*.xlsx"),
                ("Berkas Audio (*.mp3;*.wav;*.ogg;*.m4a)", "*.mp3;*.wav;*.ogg;*.m4a"),
                ("Arsip & Lainnya (*.zip;*.rar;*.7z)", "*.zip;*.rar;*.7z")
            ]
        )
        if f:
            self.selected_file_path = f
            self.lbl_selected_file.delete(0, "end")
            self.lbl_selected_file.insert(0, f)
            sz = os.path.getsize(f)
            sz_str = f"{sz / (1024*1024):.2f} MB" if sz > 1024*1024 else f"{sz / 1024:.1f} KB"
            ext = os.path.splitext(f)[1].upper() or "FILE"
            self.lbl_file_details.configure(
                text=f"📁 Berkas Terpilih: {os.path.basename(f)} | Tipe: {ext} | Ukuran: {sz_str} ({sz:,} bytes)",
                text_color="#38BDF8"
            )

    def _browse_decrypt_file(self):
        f = filedialog.askopenfilename(
            title="Pilih Berkas Ciphertext (.enc / .medenc)",
            filetypes=[
                ("Ciphertext Files (*.enc;*.medenc)", "*.enc;*.medenc"),
                ("Semua Berkas (*.*)", "*.*")
            ]
        )
        if f:
            self.ent_dec_ciphertext.delete(0, "end")
            self.ent_dec_ciphertext.insert(0, f)

    def _copy_ciphertext(self):
        c = self.ent_cipher_output.get().strip()
        if c and not c.startswith("Ciphertext"):
            self.clipboard_clear()
            self.clipboard_append(c)
            messagebox.showinfo(
                "Ciphertext Disalin",
                f"Ciphertext berhasil disalin ke Clipboard!\n\n"
                f"Silakan tempelkan pada 'Kolom 1: Salin Ciphertext' di Bagian 3 di bawah untuk pengujian dekripsi."
            )
        else:
            messagebox.showwarning("Peringatan", "Belum ada ciphertext yang dihasilkan untuk disalin!")

    def _paste_ciphertext(self):
        try:
            cb = self.clipboard_get().strip()
            if cb:
                self.ent_dec_ciphertext.delete(0, "end")
                self.ent_dec_ciphertext.insert(0, cb)
            else:
                messagebox.showwarning("Peringatan", "Clipboard Anda kosong!")
        except Exception as e:
            messagebox.showerror("Error Paste", f"Gagal membaca clipboard: {str(e)}")

    def _open_cipher_folder(self):
        target = self.last_encrypted_path or self.ent_cipher_output.get().strip()
        if target and os.path.exists(target):
            try:
                os.startfile(os.path.dirname(target))
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membuka folder: {str(e)}")
        else:
            messagebox.showwarning("Peringatan", "Berkas ciphertext belum dibuat!")

    # ------------------ ENCRYPTION ACTION (ASYNC / THREADED) ------------------
    def _on_encrypt_file(self):
        src = self.lbl_selected_file.get().strip()
        pw = self.ent_file_key.get().strip()
        if not src or not os.path.exists(src):
            messagebox.showwarning("Peringatan", "Silakan pilih berkas yang valid terlebih dahulu!")
            return
        if not pw:
            messagebox.showwarning("Peringatan", "Kunci sandi ChaCha20 harus diisi!")
            return

        out_path = src + ".enc"

        # Show loading state to prevent UI freeze
        self.btn_encrypt_file.configure(state="disabled", text="⏳ Sedang Mengenkripsi Berkas... (Harap Tunggu)")

        import queue
        q = queue.Queue()

        def worker():
            try:
                res = encrypt_medical_file(src, out_path, pw)
                q.put(("success", res, out_path))
            except Exception as e:
                q.put(("error", str(e), None))

        threading.Thread(target=worker, daemon=True).start()

        def poll_encrypt_queue():
            try:
                status, data1, data2 = q.get_nowait()
                if status == "success":
                    self._on_encrypt_success(data1, data2)
                else:
                    self._on_encrypt_error(data1)
            except queue.Empty:
                self.after(50, poll_encrypt_queue)

        self.after(50, poll_encrypt_queue)

    def _on_encrypt_success(self, res: dict, out_path: str):
        self.btn_encrypt_file.configure(state="normal", text="🔒 Jalankan Enkripsi Berkas ke Ciphertext (ChaCha20-Poly1305)")
        self.last_encrypted_path = out_path

        # Fast and safe ciphertext identifier: displays cleanly in 0.001s without freezing UI
        ciphertext_identifier = out_path

        self.ent_cipher_output.delete(0, "end")
        self.ent_cipher_output.insert(0, ciphertext_identifier)

        info_text = (
            f"✅ ENKRIPSI BERKAS SUKSES MENGHASILKAN CIPHERTEXT\n"
            f"---------------------------------------------------\n"
            f"Nama Berkas Input  : {res['original_name']}\n"
            f"Ukuran Berkas Asli : {res['original_size']:,} bytes\n"
            f"Panjang Ciphertext : {res['ciphertext_len_bytes']:,} bytes ({res['encrypted_size']:,} bytes container)\n"
            f"SHA-256 Checksum   : {res['original_sha256']}\n"
            f"ChaCha20 Nonce     : {res['nonce_hex']}\n"
            f"Poly1305 MAC Tag   : {res['tag_hex']}\n"
            f"Lokasi File Simpan : {res['output_path']}\n"
            f"Algoritma          : {res['algorithm']}\n\n"
            f"💡 Silakan klik tombol 'Salin Ciphertext', lalu tempelkan pada Kolom 1 di Bagian 3."
        )
        self.txt_info.delete("1.0", "end")
        self.txt_info.insert("1.0", info_text)
        messagebox.showinfo(
            "Enkripsi Berhasil",
            f"Berkas '{res['original_name']}' berhasil dienkripsi ke Ciphertext!\n\n"
            f"Silakan klik tombol '📋 Salin Ciphertext' untuk menyalin, lalu tempelkan pada 2 kolom kosong di Bagian 3 untuk pengujian dekripsi."
        )

    def _on_encrypt_error(self, err_msg: str):
        self.btn_encrypt_file.configure(state="normal", text="🔒 Jalankan Enkripsi Berkas ke Ciphertext (ChaCha20-Poly1305)")
        messagebox.showerror("Error Enkripsi", f"Gagal mengenkripsi berkas: {err_msg}")

    # ------------------ DECRYPTION ACTION (ASYNC / THREADED) ------------------
    def _on_decrypt_file(self):
        source = self.ent_dec_ciphertext.get().strip()
        pw = self.ent_dec_key.get().strip()

        if not source:
            messagebox.showwarning("Peringatan", "Kolom 1 (Ciphertext) masih kosong! Silakan salin & tempelkan ciphertext terlebih dahulu.")
            return
        if not pw:
            messagebox.showwarning("Peringatan", "Kolom 2 (Kunci Sandi ChaCha20) masih kosong! Silakan masukkan kunci sandi.")
            return

        # Check if source is a file path
        out_dir = None
        source_clean = source.strip('"').strip("'")
        if os.path.exists(source_clean) and os.path.isfile(source_clean):
            source = source_clean
            out_dir = os.path.dirname(source_clean)
        elif self.last_encrypted_path and os.path.exists(self.last_encrypted_path):
            out_dir = os.path.dirname(self.last_encrypted_path)
        else:
            out_dir = os.path.join(os.path.expanduser("~"), "Downloads")

        # Show loading state
        self.btn_decrypt_file.configure(state="disabled", text="⏳ Sedang Mendekripsi Berkas & Verifikasi MAC...")

        import queue
        q = queue.Queue()

        def worker():
            try:
                res = decrypt_medical_file(source, out_dir, pw)
                q.put(("success", res))
            except Exception as e:
                q.put(("error", str(e)))

        threading.Thread(target=worker, daemon=True).start()

        def poll_decrypt_queue():
            try:
                status, data = q.get_nowait()
                if status == "success":
                    self._on_decrypt_success(data)
                else:
                    self._on_decrypt_error(data)
            except queue.Empty:
                self.after(50, poll_decrypt_queue)

        self.after(50, poll_decrypt_queue)

    def _on_decrypt_success(self, res: dict):
        self.btn_decrypt_file.configure(state="normal", text="🔓 Jalankan Dekripsi ke Berkas Asli (ChaCha20-Poly1305)")
        if res["success"]:
            self.last_restored_file = res["output_path"]
            self.lbl_decrypt_status.configure(
                text=f"✅ DEKRIPSI SUKSES: Berkas asli berhasil dipulihkan 100%!\n"
                     f"Nama: {res['restored_filename']} | Ukuran: {res['restored_size']:,} bytes\n"
                     f"Integritas Poly1305 MAC & Hash SHA-256 Terverifikasi 100% Sah.",
                text_color="#10B981"
            )
            self.btn_open_file.configure(state="normal")
            self.btn_open_folder.configure(state="normal")
            messagebox.showinfo(
                "Dekripsi Berhasil",
                f"Ciphertext berhasil didekripsi menggunakan Kunci ChaCha20!\n\n"
                f"Berkas inputan asli telah dipulihkan ke:\n{res['output_path']}\n\n"
                f"Silakan klik tombol 'Buka / Putar Berkas Sekarang' untuk memutar video atau membuka berkas."
            )
        else:
            self.lbl_decrypt_status.configure(
                text=f"❌ {res['error']}",
                text_color="#EF4444"
            )
            self.btn_open_file.configure(state="disabled")
            self.btn_open_folder.configure(state="disabled")
            messagebox.showerror("Gagal Dekripsi", res["error"])

    def _on_decrypt_error(self, err_msg: str):
        self.btn_decrypt_file.configure(state="normal", text="🔓 Jalankan Dekripsi ke Berkas Asli (ChaCha20-Poly1305)")
        self.btn_open_file.configure(state="disabled")
        self.btn_open_folder.configure(state="disabled")
        messagebox.showerror("Error Dekripsi", f"Terjadi kesalahan dekripsi: {err_msg}")

    def _open_restored_file(self):
        if self.last_restored_file and os.path.exists(self.last_restored_file):
            try:
                os.startfile(self.last_restored_file)
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membuka berkas: {str(e)}")
        else:
            messagebox.showwarning("Peringatan", "Berkas hasil pemulihan tidak ditemukan!")

    def _open_restored_folder(self):
        if self.last_restored_file and os.path.exists(self.last_restored_file):
            try:
                folder = os.path.dirname(self.last_restored_file)
                os.startfile(folder)
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membuka folder: {str(e)}")
        else:
            messagebox.showwarning("Peringatan", "Folder tidak ditemukan!")
