"""
MediCrypt Vault - Blockchain Ledger UI Tab
Visualizes Blockchain ledger for medical assets, Proof of Work mining,
tamper-detection simulation, and automatic consensus restoration.
"""

import os
import queue
import hashlib
import threading
import customtkinter as ctk
from tkinter import messagebox
from core.blockchain import MedicalBlockchain
from core.db_crypto import get_all_records


class BlockchainTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.blockchain = MedicalBlockchain()

        # Ensure initial state is ALWAYS 100% valid/correct before user interaction
        val = self.blockchain.validate_chain_integrity()
        if not val["is_valid"]:
            self.blockchain.heal_chain()

        self.is_tampered_state = False
        self.tampered_block_idx = None

        self._build_ui()
        self.render_chain()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 15))

        title = ctk.CTkLabel(
            header,
            text="⛓️ Pengamanan Aset Medis dengan Blockchain Sederhana",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Setiap aset medis (Hasil Biopsi, Rekam Genomik, Informed Consent) diamankan dalam "
                 "blok berantai berbasis SHA-256 & Proof-of-Work (PoW). Menjamin kekekalan data (immutability) dan anti-pemalsuan.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        # Control Bar
        ctrl_bar = ctk.CTkFrame(self, fg_color="transparent")
        ctrl_bar.pack(fill="x", padx=10, pady=(0, 10))

        btn_verify = ctk.CTkButton(
            ctrl_bar,
            text="🔍 Validasi Integritas Rantai",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._on_validate_chain
        )
        btn_verify.pack(side="left", padx=5)

        btn_mine = ctk.CTkButton(
            ctrl_bar,
            text="⛏️ Tambah & Tambang Aset Baru (PoW)",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_mine_dialog
        )
        btn_mine.pack(side="left", padx=5)

        # Dynamic Tamper / Heal Action Button
        self.btn_tamper_heal = ctk.CTkButton(
            ctrl_bar,
            text="🚨 Simulasi Serangan Hacker (Ubah Data)",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._on_toggle_tamper_heal
        )
        self.btn_tamper_heal.pack(side="left", padx=5)

        # Integrity Status Alert Box
        self.lbl_status = ctk.CTkLabel(
            self,
            text="🟢 STATUS RANTAI: Terverifikasi Sah (Seluruh Blok Valid & Tidak Ada Modifikasi)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#10B981",
            anchor="w"
        )
        self.lbl_status.pack(fill="x", padx=15, pady=(0, 5))

        # Scrollable Chain Explorer
        self.scroll_chain = ctk.CTkScrollableFrame(self)
        self.scroll_chain.pack(fill="both", expand=True, padx=10, pady=5)

    def render_chain(self):
        for widget in self.scroll_chain.winfo_children():
            widget.destroy()

        for b in self.blockchain.chain:
            is_genesis = (b.index == 0)
            is_tampered = (b.index == self.tampered_block_idx)

            card_border_color = "#EF4444" if is_tampered else ("#CBD5E1", "#334155")
            card_border_width = 2 if is_tampered else 0
            card_bg = ("#FEE2E2", "#450A0A") if is_tampered else ("#F1F5F9", "#1E293B")

            card = ctk.CTkFrame(
                self.scroll_chain,
                corner_radius=8,
                fg_color=card_bg,
                border_color=card_border_color,
                border_width=card_border_width
            )
            card.pack(fill="x", pady=6, padx=5)

            # Block Header
            hdr = ctk.CTkFrame(card, fg_color="transparent")
            hdr.pack(fill="x", padx=12, pady=(10, 4))

            if is_tampered:
                tag_text = f"🚨 BLOK #{b.index} - TERDETEKSI MANIPULASI ILEGAL!"
                tag_color = "#EF4444"
            elif is_genesis:
                tag_text = "⚓ ROOT GENESIS BLOCK"
                tag_color = "#38BDF8"
            else:
                tag_text = f"📦 BLOK #{b.index}"
                tag_color = "#F59E0B"

            ctk.CTkLabel(hdr, text=tag_text, font=ctk.CTkFont(size=14, weight="bold"), text_color=tag_color).pack(side="left")
            ctk.CTkLabel(hdr, text=f"Waktu: {b.timestamp} | Nonce PoW: {b.nonce}", font=ctk.CTkFont(family="Consolas", size=11), text_color="gray").pack(side="right")

            # Asset Info
            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(fill="x", padx=12, pady=2)

            name_color = "#EF4444" if is_tampered else ("gray10", "gray95")
            ctk.CTkLabel(body, text=f"Nama Aset Medis: {b.asset_name}", font=ctk.CTkFont(size=13, weight="bold"), text_color=name_color).pack(anchor="w")
            ctk.CTkLabel(body, text=f"ID Aset: {b.asset_id} | Pasien: {b.patient_id} | Penandatangan: {b.doctor_signer}", font=ctk.CTkFont(size=11), text_color=("gray30", "gray70")).pack(anchor="w")

            # Hashes
            h_frame = ctk.CTkFrame(card, fg_color="transparent")
            h_frame.pack(fill="x", padx=12, pady=(4, 10))

            ctk.CTkLabel(h_frame, text=f"Previous Hash : {b.previous_hash}", font=ctk.CTkFont(family="Consolas", size=10), text_color=("gray40", "gray60")).pack(anchor="w")

            if is_tampered:
                recalculated_hash = b.calculate_hash()
                ctk.CTkLabel(h_frame, text=f"Stored Hash   : {b.hash} (HASH TERCATAT LAMA)", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#F59E0B").pack(anchor="w")
                ctk.CTkLabel(h_frame, text=f"Kalkulasi Hash: {recalculated_hash} (TIDAK COCOK / PALSU!)", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#EF4444").pack(anchor="w")
            else:
                ctk.CTkLabel(h_frame, text=f"Block Hash    : {b.hash} (VALID PoW: diawali '000')", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#10B981").pack(anchor="w")

    def _on_toggle_tamper_heal(self):
        """
        Alternates between simulating a malicious tamper attack and auto-repairing/healing via consensus.
        """
        if not self.is_tampered_state:
            # Step 1: Simulate Malicious Tamper
            if len(self.blockchain.chain) <= 1:
                messagebox.showwarning("Peringatan", "Tambahkan blok terlebih dahulu sebelum simulasi peretasan!", parent=self)
                return

            target_idx = 1
            tampered_text = "⚠️ DATA HASIL BIOPSI TELAH DIMANIPULASI HACKER: Nodul Kanker Ganas Dihapus Menjadi Normal! ⚠️"
            self.blockchain.simulate_tamper(target_idx, tampered_text)
            self.is_tampered_state = True
            self.tampered_block_idx = target_idx

            self.render_chain()
            self.lbl_status.configure(
                text=f"🔴 KECURANGAN TERDETEKSI: Blok #{target_idx} telah dimanipulasi secara ilegal! Hash kalkulasi tidak cocok.",
                text_color="#EF4444"
            )
            self.btn_tamper_heal.configure(
                text="🛡️ Validasi & Benarkan Integritas (Konsensus Otomatis)",
                fg_color="#059669",
                hover_color="#047857"
            )

            messagebox.showwarning(
                "Simulasi Serangan Hacker Aktif",
                f"Data pada Blok #{target_idx} telah berhasil dipalsukan!\n\n"
                f"Akibat perubahan teks ini, rumus matematis SHA-256 menghasilkan hash yang berbeda dengan hash yang tercatat di blockchain.\n\n"
                f"Status rantai otomatis berubah menjadi KECURANGAN TERDETEKSI (MERAH).\n\n"
                f"Sekarang tekan tombol hijau '🛡️ Validasi & Benarkan Integritas' untuk mengaktifkan mekanisme konsensus yang secara otomatis mendeteksi kecurangan dan memulihkan data asli yang sah!",
                parent=self
            )
        else:
            # Step 2: Auto-validate and Heal via Consensus
            self._heal_now()

    def _heal_now(self):
        """
        Executes consensus auto-repair: restores authentic blocks and validates chain integrity.
        """
        res = self.blockchain.heal_chain()
        self.is_tampered_state = False
        self.tampered_block_idx = None

        self.render_chain()
        self.lbl_status.configure(
            text="🟢 STATUS RANTAI: VALID! Seluruh blok telah divalidasi dan integritas data berhasil dibenarkan 100% melalui konsensus kriptografi.",
            text_color="#10B981"
        )
        self.btn_tamper_heal.configure(
            text="🚨 Simulasi Serangan Hacker (Ubah Data)",
            fg_color="#DC2626",
            hover_color="#B91C1C"
        )

        messagebox.showinfo(
            "Integritas Berhasil Dibenarkan",
            "✅ Validasi & Pemulihan Konsensus Berhasil!\n\n"
            "Sistem konsensus kriptografi secara otomatis menolak blok hasil manipulasi ilegal "
            "dan memulihkan catatan ke data asli yang sah.\n\n"
            "Seluruh blok kini kembali valid dan saling terhubung 100%!",
            parent=self
        )

    def _on_validate_chain(self):
        val = self.blockchain.validate_chain_integrity()
        if val["is_valid"]:
            self.lbl_status.configure(
                text=f"🟢 STATUS RANTAI: VALID! {val['message']}",
                text_color="#10B981"
            )
            messagebox.showinfo("Verifikasi Integritas Sah", val["message"], parent=self)
        else:
            self.lbl_status.configure(
                text=f"🔴 KECURANGAN TERDETEKSI: {val['message']}",
                text_color="#EF4444"
            )
            remedy = messagebox.askyesno(
                "Pelanggaran Integritas Terdeteksi!",
                f"{val['message']}\n\n"
                f"Apakah Anda ingin sistem konsensus membenarkan dan memulihkan blok ke data aslinya yang sah sekarang?",
                parent=self
            )
            if remedy:
                self._heal_now()

    def _open_mine_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Penambangan Blok Aset Medis Baru (Proof-of-Work)")
        dialog.geometry("560x510")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="MINING BLOK ASET MEDIS (PoW SHA-256)", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)

        # Optional EHR Patient Record Selector
        ehr_records = get_all_records(decrypted=True)
        pat_options = ["-- Input Aset Medis Manual --"]
        if ehr_records:
            pat_options += [f"{r['record_id']} - {r['full_name']} ({r['visit_date']})" for r in ehr_records[:8]]

        ctk.CTkLabel(dialog, text="Sinkronisasi dari Rekam Medis Pasien (Opsional):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        combo_ehr = ctk.CTkComboBox(dialog, values=pat_options, width=520)
        combo_ehr.pack(padx=20, pady=2)

        ctk.CTkLabel(dialog, text="ID Aset Medis:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(8, 2))
        ent_aid = ctk.CTkEntry(dialog, width=520)
        ent_aid.pack(padx=20, pady=2)
        ent_aid.insert(0, f"AST-2026-DNA-SEQ-{len(self.blockchain.chain)+1:02d}")

        ctk.CTkLabel(dialog, text="Nama Aset / Dokumen Medis:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        ent_aname = ctk.CTkEntry(dialog, width=520)
        ent_aname.pack(padx=20, pady=2)
        ent_aname.insert(0, "Hasil Tes Sekuensing DNA BRCA1/BRCA2 Pasien")

        ctk.CTkLabel(dialog, text="ID Pasien:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        ent_pid = ctk.CTkEntry(dialog, width=520)
        ent_pid.pack(padx=20, pady=2)
        ent_pid.insert(0, "RM-2026-0081")

        def _on_ehr_select(choice):
            if " - " in choice:
                rec_id = choice.split(" - ")[0]
                target_rec = next((r for r in ehr_records if r["record_id"] == rec_id), None)
                if target_rec:
                    ent_aid.delete(0, "end")
                    ent_aid.insert(0, f"AST-EHR-{target_rec['record_id']}")
                    ent_aname.delete(0, "end")
                    ent_aname.insert(0, f"Rekam Medis: {target_rec['full_name']} ({target_rec['visit_date']})")
                    ent_pid.delete(0, "end")
                    ent_pid.insert(0, target_rec["patient_id"])

        combo_ehr.configure(command=_on_ehr_select)

        btn_start_mine = ctk.CTkButton(dialog, text="⛏️ Mulai Proof-of-Work & Catat ke Chain", font=ctk.CTkFont(size=13, weight="bold"), fg_color="#0284C7", height=38)
        btn_start_mine.pack(pady=20)

        def mine():
            aid = ent_aid.get().strip()
            aname = ent_aname.get().strip()
            pid = ent_pid.get().strip()

            if not aid or not aname or not pid:
                messagebox.showwarning("Peringatan", "Semua field aset medis harus diisi lengkap!", parent=dialog)
                return

            btn_start_mine.configure(state="disabled", text="⏳ Sedang Mining Blok PoW (Mencari Nonce)...")

            q_mine = queue.Queue()

            def worker():
                try:
                    data_hash = hashlib.sha256(f"{aid}|{aname}|{pid}".encode('utf-8')).hexdigest()
                    b = self.blockchain.add_asset_block(aid, aname, pid, data_hash, "dr_hartono")
                    # Update authentic backup snapshot with the newly mined block
                    self.blockchain.backup_authentic_chain()
                    q_mine.put(("success", b))
                except Exception as e:
                    q_mine.put(("error", str(e)))

            def on_done(b):
                messagebox.showinfo(
                    "Mining Proof-of-Work Sukses",
                    f"Blok #{b.index} berhasil ditambang secara matematis!\n\n"
                    f"ID Aset  : {b.asset_id}\n"
                    f"Nonce PoW: {b.nonce}\n"
                    f"Hash     : {b.hash}\n\n"
                    f"Blok baru telah sah dan terkunci secara permanen di blockchain.",
                    parent=dialog
                )
                dialog.destroy()
                self.render_chain()
                self._on_validate_chain()

            def on_err(err_msg):
                btn_start_mine.configure(state="normal", text="⛏️ Mulai Proof-of-Work & Catat ke Chain")
                messagebox.showerror("Error Mining", f"Gagal menambang: {err_msg}", parent=dialog)

            def poll_mine():
                try:
                    status, res = q_mine.get_nowait()
                    if status == "success":
                        on_done(res)
                    else:
                        on_err(res)
                except queue.Empty:
                    dialog.after(50, poll_mine)

            threading.Thread(target=worker, daemon=True).start()
            dialog.after(50, poll_mine)

        btn_start_mine.configure(command=mine)
