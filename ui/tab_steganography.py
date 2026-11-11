"""
MediCrypt Vault - Steganography UI Tab
Hides confidential medical notes inside medical images using LSB + AES Encryption
Features:
- Live image preview for original carrier image
- Side-by-side visual comparison (Cover Image vs Stego Image)
- Image quality analysis (PSNR, MSE) and file size comparison (Before vs After)
- Robust extraction and decryption of hidden medical notes
"""

import os
import queue
import threading
import customtkinter as ctk
from PIL import Image
from tkinter import filedialog, messagebox
from core.steganography import (
    embed_secret_in_image,
    extract_secret_from_image,
    generate_sample_xray_image
)

SAMPLE_XRAY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_xray.png")


def _load_ctk_image(image_path: str, max_size=(200, 200)):
    """
    Safely loads and scales an image into a CTkImage thumbnail preserving aspect ratio.
    """
    if not image_path or not os.path.exists(image_path):
        return None
    try:
        pil_img = Image.open(image_path).convert("RGB")
        pil_img.thumbnail(max_size, Image.Resampling.LANCZOS)
        w, h = pil_img.size
        return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(w, h))
    except Exception:
        return None


def _get_image_metadata(image_path: str):
    """
    Extracts image file metadata (resolution, file size, max LSB capacity).
    """
    if not image_path or not os.path.exists(image_path):
        return None
    try:
        sz = os.path.getsize(image_path)
        with Image.open(image_path) as img:
            w, h = img.size
            max_bytes = (w * h * 3) // 8 # 1 bit per RGB channel
        return {
            "filename": os.path.basename(image_path),
            "resolution": f"{w} × {h} px",
            "size_bytes": sz,
            "size_formatted": f"{sz / 1024:.2f} KB ({sz:,} bytes)",
            "max_capacity_bytes": max_bytes,
            "max_capacity_formatted": f"{max_bytes / 1024:.2f} KB ({max_bytes:,} bytes)"
        }
    except Exception:
        return None


class SteganographyTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        if not os.path.exists(SAMPLE_XRAY_PATH):
            generate_sample_xray_image(SAMPLE_XRAY_PATH)
        self.carrier_image_path = SAMPLE_XRAY_PATH
        self.stego_image_path = None
        self.stego_key_hidden = False
        self.extract_key_hidden = False

        # Keep references to CTkImage to prevent garbage collection
        self._ctk_carrier_img = None
        self._ctk_comp_orig_img = None
        self._ctk_comp_stego_img = None
        self._ctk_extract_img = None

        self._build_ui()
        self._update_carrier_preview(self.carrier_image_path)

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 12))

        title = ctk.CTkLabel(
            header,
            text="🖼️ Steganografi Citra Medis (LSB + Enkripsi Payload AES)",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Menyisipkan diagnosis rahasia ke dalam bit Least Significant Bit (LSB) citra rontgen/X-Ray. "
                 "Pesan dienkripsi terlebih dahulu dengan AES sebelum disematkan ke dalam piksel.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # =====================================================================
        # 1. ENCODING / EMBED SECTION
        # =====================================================================
        enc_card = ctk.CTkFrame(content_frame, corner_radius=8)
        enc_card.pack(fill="x", pady=6)

        ctk.CTkLabel(
            enc_card,
            text="1. PENYISIPAN PESAN RAHASIA KE DALAM CITRA MEDIS",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        # Image picker row
        img_pick_frame = ctk.CTkFrame(enc_card, fg_color="transparent")
        img_pick_frame.pack(fill="x", padx=15, pady=5)

        self.lbl_carrier_path = ctk.CTkEntry(img_pick_frame, width=380)
        self.lbl_carrier_path.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.lbl_carrier_path.insert(0, self.carrier_image_path)

        btn_browse_img = ctk.CTkButton(img_pick_frame, text="🔍 Pilih Citra", width=110, command=self._browse_image)
        btn_browse_img.pack(side="left", padx=(0, 6))

        btn_sample_xray = ctk.CTkButton(
            img_pick_frame,
            text="🩻 Gunakan X-Ray Medis",
            width=165,
            fg_color="#475569",
            hover_color="#334155",
            command=self._use_sample_xray
        )
        btn_sample_xray.pack(side="left")

        # --- LIVE PREVIEW AREA FOR CARRIER IMAGE ---
        self.carrier_preview_frame = ctk.CTkFrame(enc_card, fg_color=("#F1F5F9", "#0F172A"), corner_radius=8)
        self.carrier_preview_frame.pack(fill="x", padx=15, pady=8)

        preview_inner = ctk.CTkFrame(self.carrier_preview_frame, fg_color="transparent")
        preview_inner.pack(fill="x", padx=12, pady=10)

        # Image thumbnail on left
        self.lbl_carrier_img = ctk.CTkLabel(
            preview_inner,
            text="[Memuat Citra...]",
            width=200,
            height=200,
            fg_color=("#E2E8F0", "#1E293B"),
            corner_radius=6
        )
        self.lbl_carrier_img.pack(side="left", padx=(0, 15))

        # Metadata info on right
        info_col = ctk.CTkFrame(preview_inner, fg_color="transparent")
        info_col.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            info_col,
            text="📷 Pratinjau Citra Pembawa (Cover Image):",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        self.lbl_carrier_fname = ctk.CTkLabel(
            info_col,
            text="📁 Nama Berkas: -",
            font=ctk.CTkFont(family="Consolas", size=11),
            anchor="w"
        )
        self.lbl_carrier_fname.pack(anchor="w", pady=2)

        self.lbl_carrier_res = ctk.CTkLabel(
            info_col,
            text="📏 Resolusi Citra: -",
            font=ctk.CTkFont(family="Consolas", size=11),
            anchor="w"
        )
        self.lbl_carrier_res.pack(anchor="w", pady=2)

        self.lbl_carrier_size = ctk.CTkLabel(
            info_col,
            text="💾 Ukuran Berkas Awal: -",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color="#38BDF8",
            anchor="w"
        )
        self.lbl_carrier_size.pack(anchor="w", pady=2)

        self.lbl_carrier_cap = ctk.CTkLabel(
            info_col,
            text="🎯 Kapasitas Maksimum LSB: -",
            font=ctk.CTkFont(family="Consolas", size=11),
            anchor="w"
        )
        self.lbl_carrier_cap.pack(anchor="w", pady=2)

        self.lbl_carrier_status = ctk.CTkLabel(
            info_col,
            text="✅ Citra pembawa siap digunakan untuk penyisipan pesan rahasia",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#10B981",
            anchor="w"
        )
        self.lbl_carrier_status.pack(anchor="w", pady=(6, 0))

        # Secret message input
        ctk.CTkLabel(
            enc_card,
            text="Pesan Medis Rahasia yang Akan Disisipkan:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=15, pady=(8, 2))

        self.txt_secret_msg = ctk.CTkTextbox(enc_card, height=60)
        self.txt_secret_msg.pack(fill="x", padx=15, pady=(0, 5))
        self.txt_secret_msg.insert("1.0", "HASIL RADIOLOGI RAHASIA: Ditemukan karsinoma stadium dini pada lobus atas paru kanan (ukuran 1.4 cm).")

        # Stego key with Visibility Toggle
        key_frame = ctk.CTkFrame(enc_card, fg_color="transparent")
        key_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(key_frame, text="🔑 Kunci Kriptografi Stego (AES):", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 10))

        key_box1 = ctk.CTkFrame(key_frame, fg_color="transparent")
        key_box1.pack(side="left", fill="x", expand=True)

        self.ent_stego_key = ctk.CTkEntry(key_box1, show="", width=260, placeholder_text="Masukkan Kunci Sandi Stego...")
        self.ent_stego_key.pack(side="left", fill="x", expand=True)
        self.ent_stego_key.insert(0, "StegoSecretXRay2026!")

        self.btn_toggle_stego_key = ctk.CTkButton(
            key_box1,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_stego_key_visibility
        )
        self.btn_toggle_stego_key.pack(side="left", padx=(6, 0))

        self.btn_embed = ctk.CTkButton(
            enc_card,
            text="🧬 Sisipkan Pesan Rahasia (Encode LSB)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_embed
        )
        self.btn_embed.pack(padx=15, pady=(10, 15))

        # =====================================================================
        # 2. QUALITY ANALYSIS & SIDE-BY-SIDE VISUAL COMPARISON
        # =====================================================================
        self.metrics_card = ctk.CTkFrame(content_frame, corner_radius=8)
        self.metrics_card.pack(fill="x", pady=10)

        ctk.CTkLabel(
            self.metrics_card,
            text="2. ANALISIS KUALITAS CITRA & METRIK STEGANALISIS (PSNR, MSE & PERBANDINGAN UKURAN)",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        # Metric Stats Dashboard (3 Cards)
        stats_frame = ctk.CTkFrame(self.metrics_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=15, pady=5)
        stats_frame.columnconfigure((0, 1, 2), weight=1, uniform="stat_card")

        # Card A: File Size Comparison
        card_size = ctk.CTkFrame(stats_frame, fg_color=("#F1F5F9", "#0F172A"), corner_radius=6)
        card_size.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        ctk.CTkLabel(card_size, text="📊 Perbandingan Ukuran", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_stat_orig_size = ctk.CTkLabel(card_size, text="Awal : -", font=ctk.CTkFont(family="Consolas", size=10), anchor="w")
        self.lbl_stat_orig_size.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_stego_size = ctk.CTkLabel(card_size, text="Akhir: -", font=ctk.CTkFont(family="Consolas", size=10), anchor="w")
        self.lbl_stat_stego_size.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_diff_size = ctk.CTkLabel(card_size, text="Selisih: -", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#38BDF8", anchor="w")
        self.lbl_stat_diff_size.pack(anchor="w", padx=10, pady=(1, 8))

        # Card B: Scientific Steganalysis (PSNR & MSE)
        card_psnr = ctk.CTkFrame(stats_frame, fg_color=("#F1F5F9", "#0F172A"), corner_radius=6)
        card_psnr.grid(row=0, column=1, padx=4, pady=4, sticky="nsew")
        ctk.CTkLabel(card_psnr, text="🔬 Kualitas Citra (PSNR & MSE)", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_stat_psnr = ctk.CTkLabel(card_psnr, text="PSNR: -", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#10B981", anchor="w")
        self.lbl_stat_psnr.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_mse = ctk.CTkLabel(card_psnr, text="MSE : -", font=ctk.CTkFont(family="Consolas", size=10), anchor="w")
        self.lbl_stat_mse.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_eval = ctk.CTkLabel(card_psnr, text="Evaluasi: Belum disisipkan", font=ctk.CTkFont(size=10), text_color="gray", anchor="w")
        self.lbl_stat_eval.pack(anchor="w", padx=10, pady=(1, 8))

        # Card C: Payload & Capacity
        card_cap = ctk.CTkFrame(stats_frame, fg_color=("#F1F5F9", "#0F172A"), corner_radius=6)
        card_cap.grid(row=0, column=2, padx=4, pady=4, sticky="nsew")
        ctk.CTkLabel(card_cap, text="📦 Payload & Kapasitas", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_stat_payload = ctk.CTkLabel(card_cap, text="Ukuran Pesan: -", font=ctk.CTkFont(family="Consolas", size=10), anchor="w")
        self.lbl_stat_payload.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_cap_pct = ctk.CTkLabel(card_cap, text="Piksel Dipakai: -", font=ctk.CTkFont(family="Consolas", size=10), anchor="w")
        self.lbl_stat_cap_pct.pack(anchor="w", padx=10, pady=1)
        self.lbl_stat_cap_status = ctk.CTkLabel(card_cap, text="Status: Aman (< 5%)", font=ctk.CTkFont(size=10), text_color="#10B981", anchor="w")
        self.lbl_stat_cap_status.pack(anchor="w", padx=10, pady=(1, 8))

        # --- SIDE-BY-SIDE VISUAL COMPARISON AREA ---
        ctk.CTkLabel(
            self.metrics_card,
            text="👁️ Perbandingan Visual Berdampingan (Kasat Mata):",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 4))

        compare_frame = ctk.CTkFrame(self.metrics_card, fg_color=("#F1F5F9", "#0F172A"), corner_radius=8)
        compare_frame.pack(fill="x", padx=15, pady=5)
        compare_frame.columnconfigure((0, 1), weight=1, uniform="comp_col")

        # Column Left: Original Cover Image
        col_orig = ctk.CTkFrame(compare_frame, fg_color="transparent")
        col_orig.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        ctk.CTkLabel(
            col_orig,
            text="🖼️ Citra Medis Asli (Cover Image)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8"
        ).pack(anchor="center", pady=(0, 5))

        self.lbl_comp_orig_img = ctk.CTkLabel(
            col_orig,
            text="[Citra Asli]",
            width=200,
            height=200,
            fg_color=("#E2E8F0", "#1E293B"),
            corner_radius=6
        )
        self.lbl_comp_orig_img.pack(anchor="center", pady=4)

        self.lbl_comp_orig_sub = ctk.CTkLabel(
            col_orig,
            text="Ukuran Awal: -",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="gray"
        )
        self.lbl_comp_orig_sub.pack(anchor="center", pady=(2, 0))

        # Column Right: Stego Image Containing Secret Message
        col_stego = ctk.CTkFrame(compare_frame, fg_color="transparent")
        col_stego.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        ctk.CTkLabel(
            col_stego,
            text="🧬 Citra Stego (Mengandung Pesan Rahasia)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10B981"
        ).pack(anchor="center", pady=(0, 5))

        self.lbl_comp_stego_img = ctk.CTkLabel(
            col_stego,
            text="[Citra Stego Belum Dibuat]",
            width=200,
            height=200,
            fg_color=("#E2E8F0", "#1E293B"),
            corner_radius=6
        )
        self.lbl_comp_stego_img.pack(anchor="center", pady=4)

        self.lbl_comp_stego_sub = ctk.CTkLabel(
            col_stego,
            text="Ukuran Akhir: -",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="gray"
        )
        self.lbl_comp_stego_sub.pack(anchor="center", pady=(2, 0))

        # Educational banner about imperceptibility
        edu_banner = ctk.CTkFrame(self.metrics_card, fg_color=("#E2E8F0", "#1E293B"), corner_radius=6)
        edu_banner.pack(fill="x", padx=15, pady=(8, 10))

        ctk.CTkLabel(
            edu_banner,
            text="💡 Analisis Kasat Mata: Kedua citra secara visual 100% identik bagi mata manusia (Human Visual System / HVS).\n"
                 "Nilai bit LSB hanya mengalami perubahan biner ±1 sehingga tidak menimbulkan artefak visual apa pun.\n"
                 "Pesan rahasia terenkripsi AES-256 tersimpan aman dan hanya dapat diekstrak menggunakan kunci sandi yang sah.",
            font=ctk.CTkFont(size=11),
            justify="left",
            text_color=("gray20", "gray80")
        ).pack(anchor="w", padx=12, pady=8)

        # Technical log
        self.txt_metrics = ctk.CTkTextbox(self.metrics_card, height=85, font=ctk.CTkFont(family="Consolas", size=11))
        self.txt_metrics.pack(fill="x", padx=15, pady=(0, 12))
        self.txt_metrics.insert("1.0", "Belum ada proses penyisipan citra. Klik 'Sisipkan Pesan Rahasia (Encode LSB)' di atas.")

        # =====================================================================
        # 3. EXTRACTION / DECODE SECTION
        # =====================================================================
        dec_card = ctk.CTkFrame(content_frame, corner_radius=8)
        dec_card.pack(fill="x", pady=10)

        ctk.CTkLabel(
            dec_card,
            text="3. EKSTRAKSI PESAN RAHASIA DARI CITRA STEGO",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        ctk.CTkLabel(
            dec_card,
            text="Pilih Citra Medis Berisi Pesan Rahasia (_stego.png):",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8"
        ).pack(anchor="w", padx=15, pady=(2, 2))

        # Stego Image Picker Row
        ext_img_frame = ctk.CTkFrame(dec_card, fg_color="transparent")
        ext_img_frame.pack(fill="x", padx=15, pady=4)

        self.ent_extract_img = ctk.CTkEntry(ext_img_frame, placeholder_text="Pilih citra rontgen stego (_stego.png)...")
        self.ent_extract_img.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_browse_stego = ctk.CTkButton(
            ext_img_frame,
            text="🔍 Pilih Citra Stego",
            width=140,
            fg_color="#475569",
            hover_color="#334155",
            command=self._browse_stego_image
        )
        btn_browse_stego.pack(side="right")

        btn_load_last = ctk.CTkButton(
            ext_img_frame,
            text="⚡ Muat Hasil Stego",
            width=140,
            fg_color="#334155",
            hover_color="#475569",
            command=self._use_latest_stego
        )
        btn_load_last.pack(side="right", padx=(0, 6))

        # Mini preview for the stego image to be extracted
        self.frame_extract_preview = ctk.CTkFrame(dec_card, fg_color=("#F1F5F9", "#0F172A"), corner_radius=6)
        self.frame_extract_preview.pack(fill="x", padx=15, pady=6)

        ext_preview_inner = ctk.CTkFrame(self.frame_extract_preview, fg_color="transparent")
        ext_preview_inner.pack(fill="x", padx=10, pady=6)

        self.lbl_extract_img_thumb = ctk.CTkLabel(
            ext_preview_inner,
            text="[Citra Stego]",
            width=70,
            height=70,
            fg_color=("#E2E8F0", "#1E293B"),
            corner_radius=4
        )
        self.lbl_extract_img_thumb.pack(side="left", padx=(0, 12))

        ext_info_box = ctk.CTkFrame(ext_preview_inner, fg_color="transparent")
        ext_info_box.pack(side="left", fill="both", expand=True)

        self.lbl_extract_img_title = ctk.CTkLabel(
            ext_info_box,
            text="Citra Stego Target: Belum dipilih",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        )
        self.lbl_extract_img_title.pack(anchor="w", pady=(2, 1))

        self.lbl_extract_img_meta = ctk.CTkLabel(
            ext_info_box,
            text="Pilih citra _stego.png di atas atau klik 'Muat Hasil Stego'",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="gray",
            anchor="w"
        )
        self.lbl_extract_img_meta.pack(anchor="w")

        # Extraction Key Row with Toggle
        ext_key_frame = ctk.CTkFrame(dec_card, fg_color="transparent")
        ext_key_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(ext_key_frame, text="🔑 Kunci Dekripsi Stego (AES):", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 10))

        key_box2 = ctk.CTkFrame(ext_key_frame, fg_color="transparent")
        key_box2.pack(side="left", fill="x", expand=True)

        self.ent_extract_key = ctk.CTkEntry(key_box2, show="", width=260, placeholder_text="Kunci sandi dekripsi stego...")
        self.ent_extract_key.pack(side="left", fill="x", expand=True)
        self.ent_extract_key.insert(0, "StegoSecretXRay2026!")

        self.btn_toggle_extract_key = ctk.CTkButton(
            key_box2,
            text="🔒",
            width=36,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_extract_key_visibility
        )
        self.btn_toggle_extract_key.pack(side="left", padx=(6, 0))

        self.btn_extract = ctk.CTkButton(
            dec_card,
            text="🔍 Ekstrak & Dekripsi Pesan Rahasia (Decode LSB)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            fg_color="#059669",
            hover_color="#047857",
            command=self._on_extract
        )
        self.btn_extract.pack(padx=15, pady=(10, 5))

        self.lbl_extract_status = ctk.CTkLabel(dec_card, text="", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_extract_status.pack(padx=15, pady=2)

        ctk.CTkLabel(
            dec_card,
            text="Isi Pesan Medis Rahasia yang Berhasil Diekstrak:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=15, pady=(5, 2))

        self.txt_extracted = ctk.CTkTextbox(dec_card, height=65)
        self.txt_extracted.pack(fill="x", padx=15, pady=(0, 15))

    # ------------------ PREVIEW HELPERS ------------------
    def _update_carrier_preview(self, path: str):
        if not path or not os.path.exists(path):
            self.lbl_carrier_img.configure(image=None, text="[Citra Tidak Valid]")
            self.lbl_carrier_fname.configure(text="📁 Nama Berkas: Tidak ditemukan")
            self.lbl_carrier_res.configure(text="📏 Resolusi Citra: -")
            self.lbl_carrier_size.configure(text="💾 Ukuran Berkas Awal: -")
            self.lbl_carrier_cap.configure(text="🎯 Kapasitas Maksimum LSB: -")
            self.lbl_carrier_status.configure(text="❌ Berkas citra tidak ditemukan", text_color="#EF4444")
            return

        meta = _get_image_metadata(path)
        ctk_img = _load_ctk_image(path, max_size=(200, 200))
        self._ctk_carrier_img = ctk_img

        if ctk_img:
            self.lbl_carrier_img.configure(image=ctk_img, text="")
        else:
            self.lbl_carrier_img.configure(image=None, text="[Gagal Memuat]")

        if meta:
            self.lbl_carrier_fname.configure(text=f"📁 Nama Berkas: {meta['filename']}")
            self.lbl_carrier_res.configure(text=f"📏 Resolusi Citra: {meta['resolution']}")
            self.lbl_carrier_size.configure(text=f"💾 Ukuran Berkas Awal: {meta['size_formatted']}")
            self.lbl_carrier_cap.configure(text=f"🎯 Kapasitas Maksimum LSB: {meta['max_capacity_formatted']}")
            self.lbl_carrier_status.configure(text="✅ Citra pembawa siap digunakan untuk penyisipan pesan rahasia", text_color="#10B981")

            # Also prepare comparison left side
            self._ctk_comp_orig_img = _load_ctk_image(path, max_size=(200, 200))
            if self._ctk_comp_orig_img:
                self.lbl_comp_orig_img.configure(image=self._ctk_comp_orig_img, text="")
                self.lbl_comp_orig_sub.configure(text=f"Ukuran Awal: {meta['size_formatted']}")

    def _update_extract_preview(self, path: str):
        if not path or not os.path.exists(path):
            self.lbl_extract_img_thumb.configure(image=None, text="[Citra]")
            self.lbl_extract_img_title.configure(text="Citra Stego Target: Belum dipilih")
            self.lbl_extract_img_meta.configure(text="Pilih citra _stego.png di atas atau klik 'Muat Hasil Stego'")
            return

        meta = _get_image_metadata(path)
        ctk_img = _load_ctk_image(path, max_size=(70, 70))
        self._ctk_extract_img = ctk_img

        if ctk_img:
            self.lbl_extract_img_thumb.configure(image=ctk_img, text="")
        else:
            self.lbl_extract_img_thumb.configure(image=None, text="[Citra]")

        if meta:
            self.lbl_extract_img_title.configure(text=f"Citra Stego Target: {meta['filename']}")
            self.lbl_extract_img_meta.configure(text=f"Resolusi: {meta['resolution']} | Ukuran File: {meta['size_formatted']}")

    # ------------------ TOGGLE EYE BUTTONS ------------------
    def _toggle_stego_key_visibility(self):
        self.stego_key_hidden = not getattr(self, "stego_key_hidden", False)
        if self.stego_key_hidden:
            self.ent_stego_key.configure(show="*")
            self.btn_toggle_stego_key.configure(text="👁️")
        else:
            self.ent_stego_key.configure(show="")
            self.btn_toggle_stego_key.configure(text="🔒")

    def _toggle_extract_key_visibility(self):
        self.extract_key_hidden = not getattr(self, "extract_key_hidden", False)
        if self.extract_key_hidden:
            self.ent_extract_key.configure(show="*")
            self.btn_toggle_extract_key.configure(text="👁️")
        else:
            self.ent_extract_key.configure(show="")
            self.btn_toggle_extract_key.configure(text="🔒")

    def _browse_stego_image(self):
        f = filedialog.askopenfilename(
            title="Pilih Citra Stego",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")]
        )
        if f:
            self.ent_extract_img.delete(0, "end")
            self.ent_extract_img.insert(0, f)
            self._update_extract_preview(f)

    def _use_latest_stego(self):
        if self.stego_image_path and os.path.exists(self.stego_image_path):
            self.ent_extract_img.delete(0, "end")
            self.ent_extract_img.insert(0, self.stego_image_path)
            k = self.ent_stego_key.get()
            self.ent_extract_key.delete(0, "end")
            self.ent_extract_key.insert(0, k)
            self._update_extract_preview(self.stego_image_path)
            messagebox.showinfo("Telah Dimuat", f"Citra stego terakhir berhasil dimuat:\n{self.stego_image_path}")
        else:
            messagebox.showwarning("Peringatan", "Belum ada citra stego yang baru saja dibuat!")

    def _browse_image(self):
        f = filedialog.askopenfilename(
            title="Pilih Citra Medis Asli",
            filetypes=[("Image Files", "*.png;*.bmp")]
        )
        if f:
            self.carrier_image_path = f
            self.lbl_carrier_path.delete(0, "end")
            self.lbl_carrier_path.insert(0, f)
            self._update_carrier_preview(f)

    def _use_sample_xray(self):
        if not os.path.exists(SAMPLE_XRAY_PATH):
            generate_sample_xray_image(SAMPLE_XRAY_PATH)
        self.carrier_image_path = SAMPLE_XRAY_PATH
        self.lbl_carrier_path.delete(0, "end")
        self.lbl_carrier_path.insert(0, SAMPLE_XRAY_PATH)
        self._update_carrier_preview(SAMPLE_XRAY_PATH)
        messagebox.showinfo("Sampel Dimuat", "Citra Sampel Rontgen X-Ray Dada siap digunakan!")

    def _on_embed(self):
        src = self.lbl_carrier_path.get().strip()
        msg = self.txt_secret_msg.get("1.0", "end-1c").strip()
        key = self.ent_stego_key.get().strip()

        if not src or not os.path.exists(src):
            messagebox.showwarning("Peringatan", "Citra pembawa tidak valid!")
            return
        if not msg:
            messagebox.showwarning("Peringatan", "Pesan rahasia tidak boleh kosong!")
            return
        if not key:
            messagebox.showwarning("Peringatan", "Kunci stego harus diisi!")
            return

        out_path = os.path.splitext(src)[0] + "_stego.png"

        self.btn_embed.configure(state="disabled", text="⏳ Menyisipkan Pesan ke Piksel Citra...")

        q_embed = queue.Queue()

        def worker():
            try:
                res = embed_secret_in_image(src, out_path, msg, key)
                q_embed.put(("success", res, out_path, key, src))
            except Exception as e:
                q_embed.put(("error", str(e), None, None, None))

        threading.Thread(target=worker, daemon=True).start()

        def poll_embed():
            try:
                status, res, op, k, orig_src = q_embed.get_nowait()
                if status == "success":
                    self._on_embed_success(res, op, k, orig_src)
                else:
                    self._on_embed_error(res)
            except queue.Empty:
                self.after(50, poll_embed)

        self.after(50, poll_embed)

    def _on_embed_success(self, res: dict, out_path: str, key: str, orig_src: str):
        self.btn_embed.configure(state="normal", text="🧬 Sisipkan Pesan Rahasia (Encode LSB)")
        self.stego_image_path = out_path

        # 1. Update Stat Cards with exact file size comparison
        orig_sz_fmt = res.get("orig_file_size_formatted", "-")
        stego_sz_fmt = res.get("stego_file_size_formatted", "-")
        diff_bytes = res.get("size_diff_bytes", 0)

        self.lbl_stat_orig_size.configure(text=f"Awal : {orig_sz_fmt}")
        self.lbl_stat_stego_size.configure(text=f"Akhir: {stego_sz_fmt}")
        diff_prefix = "+" if diff_bytes >= 0 else ""
        self.lbl_stat_diff_size.configure(text=f"Selisih: {diff_prefix}{diff_bytes:,} bytes")

        psnr_val = res.get("psnr_db", 0)
        self.lbl_stat_psnr.configure(text=f"PSNR: {psnr_val} dB")
        self.lbl_stat_mse.configure(text=f"MSE : {res.get('mse', 0)}")
        if psnr_val >= 50.0:
            self.lbl_stat_eval.configure(text="Evaluasi: 100% Kasat Mata (Identik)", text_color="#10B981")
        else:
            self.lbl_stat_eval.configure(text="Evaluasi: Distorsi Ringan", text_color="#F59E0B")

        self.lbl_stat_payload.configure(text=f"Ukuran Pesan: {res.get('payload_bytes', 0)} bytes")
        self.lbl_stat_cap_pct.configure(text=f"Piksel Dipakai: {res.get('capacity_used_pct', 0)}%")

        # 2. Update Side-by-Side Visual Comparison
        self._ctk_comp_orig_img = _load_ctk_image(orig_src, max_size=(200, 200))
        if self._ctk_comp_orig_img:
            self.lbl_comp_orig_img.configure(image=self._ctk_comp_orig_img, text="")
            self.lbl_comp_orig_sub.configure(text=f"Ukuran Awal: {orig_sz_fmt}")

        self._ctk_comp_stego_img = _load_ctk_image(out_path, max_size=(200, 200))
        if self._ctk_comp_stego_img:
            self.lbl_comp_stego_img.configure(image=self._ctk_comp_stego_img, text="")
            self.lbl_comp_stego_sub.configure(text=f"Ukuran Akhir: {stego_sz_fmt}")

        # 3. Update Technical Log
        metrics_info = (
            f"✅ STEGANOGRAFI BERHASIL (LSB + AES ENCRYPTION)\n"
            f"---------------------------------------------------\n"
            f"Citra Stego Disimpan   : {res['output_path']}\n"
            f"Ukuran Citra Awal      : {orig_sz_fmt}\n"
            f"Ukuran Citra Stego     : {stego_sz_fmt} (Perubahan: {diff_prefix}{diff_bytes} bytes)\n"
            f"Resolusi Citra         : {res['image_resolution']}\n"
            f"Ukuran Payload Rahasia : {res['payload_bytes']} bytes ({res['total_bits_embedded']} bits)\n"
            f"Kapasitas Terpakai     : {res['capacity_used_pct']}% dari total piksel\n"
            f"Peak SNR (PSNR)        : {res['psnr_db']} dB  (> 50 dB = Sempurna, 100% Kasat Mata Tanpa Distorsi Visual)\n"
            f"Mean Squared Error     : {res['mse']}  (Mendekati 0.0, bit LSB hanya diubah ±1)\n"
        )
        self.txt_metrics.delete("1.0", "end")
        self.txt_metrics.insert("1.0", metrics_info)

        # 4. Auto-populate Section 3 (Ekstraksi)
        self.ent_extract_img.delete(0, "end")
        self.ent_extract_img.insert(0, out_path)
        self.ent_extract_key.delete(0, "end")
        self.ent_extract_key.insert(0, key)
        self._update_extract_preview(out_path)

        messagebox.showinfo(
            "Steganografi Sukses",
            f"Pesan berhasil disisipkan secara kasat mata ke citra!\n\n"
            f"Ukuran Awal : {orig_sz_fmt}\n"
            f"Ukuran Akhir: {stego_sz_fmt}\n"
            f"PSNR Quality: {res['psnr_db']} dB (Visual Identik)\n\n"
            f"Disimpan di:\n{out_path}"
        )

    def _on_embed_error(self, err_msg: str):
        self.btn_embed.configure(state="normal", text="🧬 Sisipkan Pesan Rahasia (Encode LSB)")
        messagebox.showerror("Error", f"Gagal menyisipkan pesan: {err_msg}")

    def _on_extract(self):
        target = self.ent_extract_img.get().strip()
        if not target or not os.path.exists(target):
            if self.stego_image_path and os.path.exists(self.stego_image_path):
                target = self.stego_image_path
                self.ent_extract_img.delete(0, "end")
                self.ent_extract_img.insert(0, target)
            else:
                def_path = os.path.splitext(self.lbl_carrier_path.get().strip())[0] + "_stego.png"
                if os.path.exists(def_path):
                    target = def_path
                    self.ent_extract_img.delete(0, "end")
                    self.ent_extract_img.insert(0, target)

        if not target or not os.path.exists(target):
            messagebox.showwarning("Peringatan", "Pilih citra stego (.png) yang valid terlebih dahulu!")
            return

        key = self.ent_extract_key.get().strip()
        if not key:
            key = self.ent_stego_key.get().strip()
            if key:
                self.ent_extract_key.delete(0, "end")
                self.ent_extract_key.insert(0, key)

        if not key:
            messagebox.showwarning("Peringatan", "Kunci sandi stego harus diisi!")
            return

        self._update_extract_preview(target)
        self.btn_extract.configure(state="disabled", text="⏳ Mengekstrak & Mendekripsi Pesan...")

        q_ext = queue.Queue()

        def worker():
            try:
                res = extract_secret_from_image(target, key)
                q_ext.put(("success", res))
            except Exception as e:
                q_ext.put(("error", str(e)))

        threading.Thread(target=worker, daemon=True).start()

        def poll_extract():
            try:
                status, res = q_ext.get_nowait()
                if status == "success":
                    self._on_extract_done(res)
                else:
                    self._on_extract_error(res)
            except queue.Empty:
                self.after(50, poll_extract)

        self.after(50, poll_extract)

    def _on_extract_done(self, res: dict):
        self.btn_extract.configure(state="normal", text="🔍 Ekstrak & Dekripsi Pesan Rahasia (Decode LSB)")
        if res["success"]:
            self.lbl_extract_status.configure(
                text="✅ EKSTRAKSI & DEKRIPSI BERHASIL (Pesan Rahasia Terpulihkan 100%)",
                text_color="#10B981"
            )
            self.txt_extracted.delete("1.0", "end")
            self.txt_extracted.insert("1.0", res["secret_message"])
            messagebox.showinfo("Sukses", "Pesan rahasia berhasil diekstrak dan didekripsi!")
        else:
            self.lbl_extract_status.configure(
                text=f"❌ {res['error']}",
                text_color="#EF4444"
            )
            self.txt_extracted.delete("1.0", "end")
            messagebox.showerror("Gagal Ekstrak", res["error"])

    def _on_extract_error(self, err_msg: str):
        self.btn_extract.configure(state="normal", text="🔍 Ekstrak & Dekripsi Pesan Rahasia (Decode LSB)")
        self.lbl_extract_status.configure(
            text=f"❌ Terjadi kesalahan: {err_msg}",
            text_color="#EF4444"
        )
        messagebox.showerror("Error", f"Terjadi kesalahan ekstraksi: {err_msg}")
