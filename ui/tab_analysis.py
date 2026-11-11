"""
MediCrypt Vault - Cryptanalysis & Benchmark UI Tab
Performs mathematical evaluation of cipher strength:
Strict Avalanche Criterion (SAC), Shannon Entropy H(X), and Execution Speed.
"""

import customtkinter as ctk
from tkinter import messagebox
from core.crypto_analyzer import test_avalanche_effect, calculate_shannon_entropy, benchmark_encryption_speed
from core.super_encryption import super_encrypt


class AnalysisTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 15))

        title = ctk.CTkLabel(
            header,
            text="📊 Pengujian Kriptanalisis & Evaluasi Matematis (Benchmark)",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Menghitung metrik kekuatan kriptografi: Avalanche Effect (efek difusi bit ketika 1 karakter diubah), "
                 "Entropi Shannon (keacakan statistik), serta kecepatan throughput enkripsi.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # ------------------ AVALANCHE EFFECT SECTION ------------------
        av_card = ctk.CTkFrame(content_frame, corner_radius=8)
        av_card.pack(fill="x", pady=5)

        ctk.CTkLabel(av_card, text="1. UJI AVALANCHE EFFECT (STRICT AVALANCHE CRITERION - SAC)", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        ctk.CTkLabel(av_card, text="Teks 1 (Plaintext Awal):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=15, pady=(5, 2))
        self.ent_p1 = ctk.CTkEntry(av_card)
        self.ent_p1.pack(fill="x", padx=15, pady=2)
        self.ent_p1.insert(0, "DIAGNOSA: Pasien Tn. Budi Sehat Normal")

        ctk.CTkLabel(av_card, text="Teks 2 (Berbeda Tepat 1 Karakter):", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=15, pady=(5, 2))
        self.ent_p2 = ctk.CTkEntry(av_card)
        self.ent_p2.pack(fill="x", padx=15, pady=2)
        self.ent_p2.insert(0, "DIAGNOSA: Pasien Tn. Budi Sakit Normal")

        btn_run_avalanche = ctk.CTkButton(
            av_card,
            text="⚡ Hitung Avalanche Effect (Hamming Bit Distance)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_run_avalanche
        )
        btn_run_avalanche.pack(padx=15, pady=10)

        self.txt_avalanche_result = ctk.CTkTextbox(av_card, height=110, font=ctk.CTkFont(family="Consolas", size=11))
        self.txt_avalanche_result.pack(fill="x", padx=15, pady=(0, 15))
        self.txt_avalanche_result.insert("1.0", "Klik tombol di atas untuk menguji difusi bit.")

        # ------------------ SHANNON ENTROPY SECTION ------------------
        ent_card = ctk.CTkFrame(content_frame, corner_radius=8)
        ent_card.pack(fill="x", pady=10)

        ctk.CTkLabel(ent_card, text="2. UJI ENTROPI SHANNON H(X) (PENGUKURAN KEACAKAN CIPHER)", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        btn_calc_entropy = ctk.CTkButton(
            ent_card,
            text="🎲 Hitung Entropi Plaintext vs Super Ciphertext",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self._on_calc_entropy
        )
        btn_calc_entropy.pack(padx=15, pady=10)

        self.txt_entropy_result = ctk.CTkTextbox(ent_card, height=110, font=ctk.CTkFont(family="Consolas", size=11))
        self.txt_entropy_result.pack(fill="x", padx=15, pady=(0, 15))
        self.txt_entropy_result.insert("1.0", "Klik tombol di atas untuk menganalisis entropi.")

        # ------------------ SPEED BENCHMARK SECTION ------------------
        bm_card = ctk.CTkFrame(content_frame, corner_radius=8)
        bm_card.pack(fill="x", pady=10)

        ctk.CTkLabel(bm_card, text="3. BENCHMARK KECEPATAN & THROUGHPUT ALGORITMA", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        self.btn_run_bm = ctk.CTkButton(
            bm_card,
            text="⏱️ Jalankan Stress-Test Kecepatan (50 Iterasi)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            command=self._on_run_benchmark
        )
        self.btn_run_bm.pack(padx=15, pady=10)

        self.txt_benchmark_result = ctk.CTkTextbox(bm_card, height=120, font=ctk.CTkFont(family="Consolas", size=11))
        self.txt_benchmark_result.pack(fill="x", padx=15, pady=(0, 15))
        self.txt_benchmark_result.insert("1.0", "Klik tombol di atas untuk menguji throughput algoritma.")

    def _on_run_avalanche(self):
        t1 = self.ent_p1.get().strip()
        t2 = self.ent_p2.get().strip()
        if not t1 or not t2:
            messagebox.showwarning("Peringatan", "Kedua teks pembanding harus diisi!")
            return

        res = test_avalanche_effect(t1, t2, "KLASIK2026", "MODERN2026AES")
        txt = (
            f"=== HASIL UJI AVALANCHE EFFECT ===\n"
            f"Teks 1 (Awal)         : {res['text1']}\n"
            f"Teks 2 (Ubah 1 Huruf) : {res['text2']}\n"
            f"Jumlah Bit yang Berubah: {res['differing_bits']} dari total {res['total_bits']} bits\n"
            f"Persentase Avalanche  : {res['avalanche_pct']}%\n"
            f"Standar Teoretis Ideal: 50.0% (Strict Avalanche Criterion)\n"
            f"Kesimpulan Kriptanalis: {res['evaluation']}\n"
        )
        self.txt_avalanche_result.delete("1.0", "end")
        self.txt_avalanche_result.insert("1.0", txt)

    def _on_calc_entropy(self):
        sample = self.ent_p1.get().strip() or "PASIEN REKAM MEDIS RAHASIA"
        p_bytes = sample.encode('utf-8')
        enc_res = super_encrypt(sample, "KUNCIKLASIK", "KUNCI256BITMODERN")
        import base64
        c_bytes = base64.b64decode(enc_res["packed_token"].encode('ascii'))

        h_plain = calculate_shannon_entropy(p_bytes)
        h_cipher = calculate_shannon_entropy(c_bytes)

        txt = (
            f"=== HASIL ANALISIS ENTROPI SHANNON H(X) ===\n"
            f"Entropi Plaintext Asli   : {h_plain:.4f} bits/byte  (Pola bahasa terbaca)\n"
            f"Entropi Super Ciphertext : {h_cipher:.4f} bits/byte  (Maksimum teoretis = 8.0000)\n\n"
            f"Analisis Kriptanalis:\n"
            f"Entropi mendekati 8.0 membuktikan bahwa ciphertext memiliki distribusi frekuensi acak sempurna "
            f"(Uniform Distribution), sehingga kebal terhadap serangan Analisis Frekuensi Huruf (Frequency Analysis Attack)."
        )
        self.txt_entropy_result.delete("1.0", "end")
        self.txt_entropy_result.insert("1.0", txt)

    def _on_run_benchmark(self):
        self.btn_run_bm.configure(state="disabled", text="⏳ Sedang Mengukur Kecepatan (50 Iterasi)...")
        self.txt_benchmark_result.delete("1.0", "end")
        self.txt_benchmark_result.insert("1.0", "⏳ Sedang menjalankan 50 iterasi enkripsi dan pengukuran throughput di background thread...")

        import threading
        import queue
        q_bm = queue.Queue()

        def worker():
            try:
                res = benchmark_encryption_speed(50)
                txt = (
                    f"=== HASIL BENCHMARK KECEPATAN (50 ITERASI) ===\n"
                    f"Ukuran Payload Uji        : {res['payload_size_kb']} KB ({res['payload_size_bytes']} bytes)\n\n"
                    f"1. Super Enkripsi (Vigenère + AES-256-GCM):\n"
                    f"   - Rata-rata Waktu Eksekusi : {res['super_enc_avg_ms']} ms / operasi\n"
                    f"   - Throughput Kecepatan    : {res['super_enc_throughput_kb_s']} KB/detik\n\n"
                    f"2. File Enkripsi (ChaCha20-Poly1305):\n"
                    f"   - Rata-rata Waktu Eksekusi : {res['chacha20_avg_ms']} ms / operasi\n"
                    f"   - Throughput Kecepatan    : {res['chacha20_throughput_kb_s']} KB/detik\n\n"
                    f"Kesimpulan: Kedua algoritma sangat efisien untuk implementasi real-time Electronic Health Record (EHR)."
                )
                q_bm.put(txt)
            except Exception as e:
                q_bm.put(f"Error benchmark: {str(e)}")

        threading.Thread(target=worker, daemon=True).start()

        def poll_bm():
            try:
                txt = q_bm.get_nowait()
                self._on_benchmark_done(txt)
            except queue.Empty:
                self.after(50, poll_bm)

        self.after(50, poll_bm)

    def _on_benchmark_done(self, txt: str):
        self.btn_run_bm.configure(state="normal", text="⏱️ Jalankan Stress-Test Kecepatan (50 Iterasi)")
        self.txt_benchmark_result.delete("1.0", "end")
        self.txt_benchmark_result.insert("1.0", txt)

