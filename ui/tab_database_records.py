"""
MediCrypt Vault - Database Records UI Tab
Demonstrates Field-Level Encryption (FLE) in SQLite Database
Includes Patient EHR Card View & Interactive Relational SQL Table Grid (MySQL/phpMyAdmin Style)
"""

import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from core.db_crypto import (
    get_all_records,
    insert_medical_record,
    get_patients_list,
    init_database,
    get_table_names,
    get_table_data,
    DB_PATH
)


class DatabaseRecordsTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        init_database()
        self.is_decrypted_mode = False
        self.current_table = "medical_records"
        self.current_columns = []
        self._init_treeview_styles()
        self._build_ui()
        self.refresh_records()

    def _init_treeview_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Custom.Treeview",
            background="#1E293B",
            foreground="#F8FAFC",
            fieldbackground="#1E293B",
            rowheight=28,
            font=("Consolas", 10)
        )
        style.configure(
            "Custom.Treeview.Heading",
            background="#0F172A",
            foreground="#38BDF8",
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )
        style.map(
            "Custom.Treeview",
            background=[("selected", "#0284C7")],
            foreground=[("selected", "#FFFFFF")]
        )
        style.map(
            "Custom.Treeview.Heading",
            background=[("active", "#1E293B")]
        )

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        header.pack(fill="x", padx=10, pady=(10, 10))

        title = ctk.CTkLabel(
            header,
            text="🗄️ Basis Data Rekam Medis Relasional (Field-Level Encryption - FLE)",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=15, pady=(10, 2))

        desc = ctk.CTkLabel(
            header,
            text="Kolom sensitif (NIK, Diagnosa Penyakit, Resep Obat, Catatan Rahasia) disimpan dalam bentuk "
                 "ciphertext AES-256-CBC di SQLite. Data tidak terbaca jika file database dicuri / dibuka pihak luar.",
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "gray70")
        )
        desc.pack(anchor="w", padx=15, pady=(0, 10))

        # Control Bar: Mode Toggle & View Switcher & Action Buttons
        ctrl_bar = ctk.CTkFrame(self, fg_color="transparent")
        ctrl_bar.pack(fill="x", padx=10, pady=(0, 8))

        # Mode switch
        self.switch_decrypt = ctk.CTkSwitch(
            ctrl_bar,
            text="🔓 Otorisasi Dokter (Dekripsi)",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._on_toggle_mode
        )
        self.switch_decrypt.pack(side="left", padx=5)

        # View mode selector (Card View vs MySQL Table Grid)
        self.seg_view = ctk.CTkSegmentedButton(
            ctrl_bar,
            values=["📋 Format Kartu Pasien", "🗄️ Tampilan Grid SQL (MySQL Mode)"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_view_changed
        )
        self.seg_view.set("📋 Format Kartu Pasien")
        self.seg_view.pack(side="left", padx=15)

        btn_add = ctk.CTkButton(
            ctrl_bar,
            text="➕ Tambah Rekam Medis",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._open_add_dialog
        )
        btn_add.pack(side="right", padx=5)

        btn_refresh = ctk.CTkButton(
            ctrl_bar,
            text="🔄 Refresh",
            width=80,
            command=self.refresh_records
        )
        btn_refresh.pack(side="right", padx=5)

        # Mode Status Banner
        self.lbl_mode_status = ctk.CTkLabel(
            self,
            text="🔴 TAMPILAN RAW DATABASE (Apa yang dilihat hacker / MySQL eksternal jika file database dicuri):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#EF4444",
            anchor="w"
        )
        self.lbl_mode_status.pack(fill="x", padx=15, pady=(0, 5))

        # --- VIEW 1: Patient Cards List (Scrollable) ---
        self.scroll_records = ctk.CTkScrollableFrame(self)
        self.scroll_records.pack(fill="both", expand=True, padx=10, pady=5)

        # --- VIEW 2: MySQL-Style Relational SQL Table Grid ---
        self.frame_sql_grid = ctk.CTkFrame(self, fg_color="transparent")
        # will be packed when user selects Grid Mode

        # SQL Grid Top Toolbar
        grid_toolbar = ctk.CTkFrame(self.frame_sql_grid, fg_color=("#F1F5F9", "#1E293B"), corner_radius=6)
        grid_toolbar.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            grid_toolbar,
            text="Pilih Tabel Relasional:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(10, 5), pady=8)

        table_list = get_table_names()
        if "medical_records" in table_list:
            default_tbl = "medical_records"
        elif table_list:
            default_tbl = table_list[0]
        else:
            default_tbl = "medical_records"

        self.combo_table = ctk.CTkComboBox(
            grid_toolbar,
            values=table_list if table_list else ["medical_records", "patients"],
            width=230,
            command=self._on_table_selected
        )
        self.combo_table.set(default_tbl)
        self.combo_table.pack(side="left", padx=5, pady=8)

        self.lbl_grid_info = ctk.CTkLabel(
            grid_toolbar,
            text="Total: - baris | - kolom",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#38BDF8"
        )
        self.lbl_grid_info.pack(side="left", padx=12, pady=8)

        self.btn_inspect = ctk.CTkButton(
            grid_toolbar,
            text="🔍 Detail Baris",
            width=100,
            command=self._inspect_selected_row
        )
        self.btn_inspect.pack(side="right", padx=(5, 10), pady=8)

        self.btn_open_file = ctk.CTkButton(
            grid_toolbar,
            text="📂 Buka Lokasi File .db",
            width=150,
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_db_folder
        )
        self.btn_open_file.pack(side="right", padx=5, pady=8)

        # Treeview Container
        tree_container = ctk.CTkFrame(self.frame_sql_grid, fg_color="#1E293B", corner_radius=6)
        tree_container.pack(fill="both", expand=True)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal")

        self.tree = ttk.Treeview(
            tree_container,
            style="Custom.Treeview",
            show="headings",
            selectmode="browse",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        # Double click to inspect
        self.tree.bind("<Double-1>", lambda e: self._inspect_selected_row())

        # SQL Grid Footer Note
        grid_footer = ctk.CTkLabel(
            self.frame_sql_grid,
            text="💡 File SQLite: data/medicrypt_ehr.db | Dapat dibuka langsung via DB Browser for SQLite, DBeaver, atau VS Code SQLite Viewer.",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        grid_footer.pack(anchor="w", padx=5, pady=(6, 0))

    def _on_view_changed(self, selected_mode):
        if "Grid SQL" in selected_mode:
            self.scroll_records.pack_forget()
            self.frame_sql_grid.pack(fill="both", expand=True, padx=10, pady=5)
            self.refresh_grid()
        else:
            self.frame_sql_grid.pack_forget()
            self.scroll_records.pack(fill="both", expand=True, padx=10, pady=5)
            self.refresh_cards()

    def _on_toggle_mode(self):
        self.is_decrypted_mode = self.switch_decrypt.get() == 1
        if self.is_decrypted_mode:
            self.lbl_mode_status.configure(
                text="🟢 TAMPILAN TERDEKRIPSI (Akses Otorisasi Dokter Terverifikasi):",
                text_color="#10B981"
            )
        else:
            self.lbl_mode_status.configure(
                text="🔴 TAMPILAN RAW DATABASE (Apa yang dilihat hacker / MySQL eksternal jika file database dicuri):",
                text_color="#EF4444"
            )
        self.refresh_records()

    def _on_table_selected(self, choice):
        self.current_table = choice
        self.refresh_grid()

    def _open_db_folder(self):
        try:
            abs_path = os.path.abspath(DB_PATH)
            if os.name == 'nt':
                subprocess.Popen(f'explorer /select,"{abs_path}"')
            else:
                os.system(f'open "{os.path.dirname(abs_path)}"')
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membuka folder: {e}", parent=self)

    def refresh_records(self):
        current_view = self.seg_view.get()
        if "Grid SQL" in current_view:
            self.refresh_grid()
        else:
            self.refresh_cards()

    def refresh_cards(self):
        for widget in self.scroll_records.winfo_children():
            widget.destroy()

        records = get_all_records(decrypted=self.is_decrypted_mode)

        if not records:
            ctk.CTkLabel(self.scroll_records, text="Belum ada data rekam medis di database.").pack(pady=20)
            return

        for rec in records:
            card = ctk.CTkFrame(self.scroll_records, corner_radius=8, fg_color=("#F1F5F9", "#1E293B"))
            card.pack(fill="x", pady=6, padx=5)

            # Top bar inside card
            top_frame = ctk.CTkFrame(card, fg_color="transparent")
            top_frame.pack(fill="x", padx=12, pady=(10, 4))

            ctk.CTkLabel(
                top_frame,
                text=f"🏥 {rec['full_name']} ({rec['patient_id']})",
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(side="left")

            ctk.CTkLabel(
                top_frame,
                text=f"ID Rekam: {rec['record_id']} | Tanggal: {rec['visit_date']}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color="gray"
            ).pack(side="right")

            # Patient details
            det_frame = ctk.CTkFrame(card, fg_color="transparent")
            det_frame.pack(fill="x", padx=12, pady=2)

            nik_color = "#10B981" if self.is_decrypted_mode else "#EF4444"
            ctk.CTkLabel(det_frame, text=f"NIK KTP: {rec['nik']}", font=ctk.CTkFont(family="Consolas", size=11), text_color=nik_color).pack(side="left", padx=(0, 20))
            ctk.CTkLabel(det_frame, text=f"Tanda Vital: {rec['vital_signs']}", font=ctk.CTkFont(size=11)).pack(side="left")

            # Sensitive Diagnosis Field
            diag_frame = ctk.CTkFrame(card, fg_color="transparent")
            diag_frame.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(diag_frame, text="Diagnosa Klinis:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w")
            lbl_diag = ctk.CTkEntry(diag_frame, font=ctk.CTkFont(family="Consolas", size=11))
            lbl_diag.pack(fill="x", pady=2)
            lbl_diag.insert(0, rec['diagnosis'])
            lbl_diag.configure(state="readonly")

            # Sensitive Prescription Field
            rx_frame = ctk.CTkFrame(card, fg_color="transparent")
            rx_frame.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(rx_frame, text="Resep Obat Keras:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w")
            lbl_rx = ctk.CTkEntry(rx_frame, font=ctk.CTkFont(family="Consolas", size=11))
            lbl_rx.pack(fill="x", pady=2)
            lbl_rx.insert(0, rec['prescriptions'])
            lbl_rx.configure(state="readonly")

            # Sensitive Secret Doctor Notes
            notes_frame = ctk.CTkFrame(card, fg_color="transparent")
            notes_frame.pack(fill="x", padx=12, pady=(4, 10))
            ctk.CTkLabel(notes_frame, text="Catatan Khusus Dokter:", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w")
            lbl_notes = ctk.CTkEntry(notes_frame, font=ctk.CTkFont(family="Consolas", size=11))
            lbl_notes.pack(fill="x", pady=2)
            lbl_notes.insert(0, rec['secret_notes'])
            lbl_notes.configure(state="readonly")

    def refresh_grid(self):
        table_name = self.combo_table.get()
        if not table_name:
            return

        self.current_table = table_name
        cols, rows = get_table_data(table_name, decrypted=self.is_decrypted_mode)
        self.current_columns = cols

        # Update Treeview columns
        self.tree["columns"] = cols
        for item in self.tree.get_children():
            self.tree.delete(item)

        for col in cols:
            self.tree.heading(col, text=col)
            # Adjust column width based on column name
            min_width = max(100, len(col) * 11)
            self.tree.column(col, width=min_width + 40, minwidth=80, anchor="w")

        # Insert rows
        for row in rows:
            display_row = []
            for val in row:
                str_val = str(val) if val is not None else "NULL"
                # Keep cell compact for display
                if len(str_val) > 75:
                    display_row.append(str_val[:72] + "...")
                else:
                    display_row.append(str_val)
            self.tree.insert("", "end", values=display_row)

        self.lbl_grid_info.configure(
            text=f"Tabel: [{table_name}] | {len(rows)} Baris, {len(cols)} Kolom | Double-klik baris untuk detail"
        )

    def _inspect_selected_row(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo(
                "Pilih Baris",
                "Silakan klik salah satu baris di tabel terlebih dahulu untuk melihat detail lengkapnya.",
                parent=self
            )
            return

        item_idx = self.tree.index(selected_item[0])
        cols, full_rows = get_table_data(self.current_table, decrypted=self.is_decrypted_mode)
        if item_idx >= len(full_rows):
            return

        selected_row_data = full_rows[item_idx]

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Detail Baris SQL: {self.current_table} [Baris #{item_idx + 1}]")
        dialog.geometry("760x560")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text=f"📋 Detail Data Relasional: {self.current_table}",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(12, 4))

        mode_text = "🟢 Mode Terdekripsi (Otorisasi Dokter)" if self.is_decrypted_mode else "🔴 Mode Raw Database (Ciphertext AES / External View)"
        mode_color = "#10B981" if self.is_decrypted_mode else "#EF4444"
        ctk.CTkLabel(dialog, text=mode_text, font=ctk.CTkFont(size=12, weight="bold"), text_color=mode_color).pack(pady=(0, 10))

        scroll_body = ctk.CTkScrollableFrame(dialog)
        scroll_body.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        for col_name, val in zip(cols, selected_row_data):
            row_frame = ctk.CTkFrame(scroll_body, fg_color=("#F1F5F9", "#1E293B"), corner_radius=6)
            row_frame.pack(fill="x", pady=4, padx=5)

            hdr = ctk.CTkFrame(row_frame, fg_color="transparent")
            hdr.pack(fill="x", padx=8, pady=(6, 2))

            ctk.CTkLabel(
                hdr,
                text=f"🔹 Kolom: {col_name}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#38BDF8"
            ).pack(side="left")

            val_str = str(val) if val is not None else "NULL"

            def copy_val(txt=val_str):
                self.clipboard_clear()
                self.clipboard_append(txt)
                messagebox.showinfo("Tersalin", "Nilai kolom berhasil disalin ke clipboard!", parent=dialog)

            ctk.CTkButton(
                hdr,
                text="📋 Salin",
                width=65,
                height=24,
                font=ctk.CTkFont(size=11),
                command=copy_val
            ).pack(side="right")

            if len(val_str) > 100 or "\n" in val_str:
                txt_box = ctk.CTkTextbox(row_frame, height=70, font=ctk.CTkFont(family="Consolas", size=11))
                txt_box.pack(fill="x", padx=8, pady=(2, 6))
                txt_box.insert("1.0", val_str)
                txt_box.configure(state="disabled")
            else:
                entry = ctk.CTkEntry(row_frame, font=ctk.CTkFont(family="Consolas", size=11))
                entry.pack(fill="x", padx=8, pady=(2, 6))
                entry.insert(0, val_str)
                entry.configure(state="readonly")

        ctk.CTkButton(dialog, text="Tutup", width=120, command=dialog.destroy).pack(pady=10)

    def _open_add_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Tambah Rekam Medis Baru (Auto Field-Level Encryption)")
        dialog.geometry("550x520")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="FORM REKAM MEDIS RAHASIA", font=ctk.CTkFont(size=15, weight="bold")).pack(pady=10)

        patients = get_patients_list()
        pat_options = [f"{p['patient_id']} - {p['full_name']}" for p in patients] if patients else ["RM-2026-0081 - Tn. Bambang"]

        ctk.CTkLabel(dialog, text="Pilih Pasien:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        combo_pat = ctk.CTkComboBox(dialog, values=pat_options, width=480)
        combo_pat.pack(padx=20, pady=2)

        ctk.CTkLabel(dialog, text="Tanda-tanda Vital:", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(5, 2))
        ent_vitals = ctk.CTkEntry(dialog, placeholder_text="TD: 120/80 mmHg, Suhu: 36.5 C", width=480)
        ent_vitals.pack(padx=20, pady=2)
        ent_vitals.insert(0, "TD: 125/80 mmHg, Nadi: 80x/m, RR: 18x/m")

        ctk.CTkLabel(dialog, text="Diagnosa Sensitif (Akan dienkripsi AES-256):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        txt_diag = ctk.CTkTextbox(dialog, height=60, width=480)
        txt_diag.pack(padx=20, pady=2)

        ctk.CTkLabel(dialog, text="Resep Obat (Akan dienkripsi AES-256):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        txt_rx = ctk.CTkTextbox(dialog, height=50, width=480)
        txt_rx.pack(padx=20, pady=2)

        ctk.CTkLabel(dialog, text="Catatan Rahasia Dokter (Akan dienkripsi AES-256):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=20, pady=(5, 2))
        txt_notes = ctk.CTkTextbox(dialog, height=50, width=480)
        txt_notes.pack(padx=20, pady=2)

        def save():
            selected_pat = combo_pat.get().split(" - ")[0]
            vitals = ent_vitals.get().strip()
            diag = txt_diag.get("1.0", "end-1c").strip()
            rx = txt_rx.get("1.0", "end-1c").strip()
            notes = txt_notes.get("1.0", "end-1c").strip()

            if not diag:
                messagebox.showwarning("Peringatan", "Diagnosa harus diisi!", parent=dialog)
                return

            rec_id = insert_medical_record(selected_pat, "dr_hartono", vitals, diag, rx, notes)
            messagebox.showinfo("Sukses", f"Data rekam medis berhasil dienkripsi dan disimpan!\nID: {rec_id}", parent=dialog)
            dialog.destroy()
            self.refresh_records()

        btn_save = ctk.CTkButton(dialog, text="💾 Simpan & Enkripsi ke Database", fg_color="#0284C7", command=save)
        btn_save.pack(pady=15)
