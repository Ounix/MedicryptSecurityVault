"""
MediCrypt Vault - Main Application Dashboard
Hosts sidebar navigation and the 6 specialized cryptographic tabs.
"""

import customtkinter as ctk
from tkinter import messagebox
from core.hardware_dongle import scan_for_dongle
from .tab_super_text import SuperTextTab
from .tab_file_crypto import FileCryptoTab
from .tab_database_records import DatabaseRecordsTab
from .tab_steganography import SteganographyTab
from .tab_blockchain import BlockchainTab


class MainDashboard(ctk.CTk):
    def __init__(self, doctor_info: dict, dongle_info: dict, on_logout_callback=None):
        super().__init__()
        self.doctor_info = doctor_info
        self.dongle_info = dongle_info
        self.on_logout_callback = on_logout_callback

        self.title("MediCrypt Vault - Electronic Health Record (EHR) Cryptographic Security System")
        self.geometry("1200x820")
        self.minsize(1050, 700)

        # Set theme
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self._is_monitoring_dongle = True
        self._current_tab_frame = None
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)

        self._build_layout()
        self._select_tab("super_text")
        self._start_dongle_monitor()

    def _build_layout(self):
        # Configure grid 1 row, 2 columns (Sidebar + Content)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ------------------ SIDEBAR FRAME ------------------
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # App Branding
        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="🏥 MEDICRYPT VAULT",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        logo_label.pack(anchor="w", padx=20, pady=(20, 2))

        sub_logo = ctk.CTkLabel(
            self.sidebar,
            text="Secure EHR Cryptographic System",
            font=ctk.CTkFont(size=12),
            text_color="gray70"
        )
        sub_logo.pack(anchor="w", padx=20, pady=(0, 15))

        # Doctor Profile Card
        doc_card = ctk.CTkFrame(self.sidebar, fg_color=("#E2E8F0", "#1E293B"), corner_radius=8)
        doc_card.pack(fill="x", padx=15, pady=(0, 10))

        doc_name = self.doctor_info.get("full_name", "Dr. dr. Hartono Sp.PD")
        ctk.CTkLabel(doc_card, text=f"👨‍⚕️ {doc_name}", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(doc_card, text=f"NIP: {self.doctor_info.get('doctor_nip', '198204122010121002')}", font=ctk.CTkFont(family="Consolas", size=10), text_color="gray70").pack(anchor="w", padx=10, pady=(0, 2))

        dongle_label = f"🛡️ Dongle: {self.dongle_info.get('drive', 'Active')}"
        ctk.CTkLabel(doc_card, text=dongle_label, font=ctk.CTkFont(size=10, weight="bold"), text_color="#10B981").pack(anchor="w", padx=10, pady=(0, 8))

        # Navigation Label
        ctk.CTkLabel(self.sidebar, text="MODUL KRIPTOGRAFI:", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60").pack(anchor="w", padx=20, pady=(10, 5))

        # Nav Buttons
        self.nav_buttons = {}

        tabs = [
            ("super_text", "🔐 Super Enkripsi Teks"),
            ("file_crypto", "📁 Enkripsi Berkas Medis"),
            ("db_records", "🗄 Database Terenkripsi (FLE)"),
            ("steganography", "🖼 Steganografi Citra Medis"),
            ("blockchain", "⛓ Blockchain Aset Medis")
        ]

        for tab_id, tab_label in tabs:
            btn = ctk.CTkButton(
                self.sidebar,
                text=tab_label,
                font=ctk.CTkFont(size=13),
                anchor="w",
                height=38,
                fg_color="transparent",
                text_color=("gray20", "gray90"),
                hover_color=("#CBD5E1", "#334155"),
                command=lambda tid=tab_id: self._select_tab(tid)
            )
            btn.pack(fill="x", padx=12, pady=2)
            self.nav_buttons[tab_id] = btn

        # Bottom spacer & Logout
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        btn_logout = ctk.CTkButton(
            self.sidebar,
            text="🚪 Kunci & Keluar (Logout)",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#EF4444",
            hover_color="#DC2626",
            command=self._on_logout
        )
        btn_logout.pack(fill="x", padx=20, pady=20)

        # ------------------ MAIN CONTENT AREA ------------------
        self.content_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    def _select_tab(self, tab_id: str):
        # Update button highlighting
        for tid, btn in self.nav_buttons.items():
            if tid == tab_id:
                btn.configure(fg_color=("#0284C7", "#0369A1"), text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=("gray20", "gray90"))

        # Destroy old tab frame
        if self._current_tab_frame is not None:
            self._current_tab_frame.destroy()

        # Instantiate new tab
        if tab_id == "super_text":
            self._current_tab_frame = SuperTextTab(self.content_container)
        elif tab_id == "file_crypto":
            self._current_tab_frame = FileCryptoTab(self.content_container)
        elif tab_id == "db_records":
            self._current_tab_frame = DatabaseRecordsTab(self.content_container)
        elif tab_id == "steganography":
            self._current_tab_frame = SteganographyTab(self.content_container)
        elif tab_id == "blockchain":
            self._current_tab_frame = BlockchainTab(self.content_container)

        self._current_tab_frame.pack(fill="both", expand=True)

    # ------------------ DONGLE REAL-TIME MONITORING ------------------
    def _start_dongle_monitor(self):
        """
        Continuously monitor physical USB Dongle presence in a background daemon thread.
        Thread-safe flag polling eliminates UI lag and '(Not Responding)' freezes completely.
        """
        import threading
        import time

        self._dongle_disconnected = False

        def monitor_worker():
            while getattr(self, "_is_monitoring_dongle", False):
                try:
                    time.sleep(1.8)
                    if not getattr(self, "_is_monitoring_dongle", False):
                        break

                    username = self.doctor_info.get("username", "testing")
                    is_virtual = self.dongle_info.get("is_virtual", False)
                    res = scan_for_dongle(username, allow_virtual=is_virtual)
                    if not res["is_valid"] and getattr(self, "_is_monitoring_dongle", False):
                        self._dongle_disconnected = True
                        break
                except Exception:
                    pass

        t = threading.Thread(target=monitor_worker, daemon=True)
        t.start()

        def check_flag():
            if not getattr(self, "_is_monitoring_dongle", False):
                return
            if getattr(self, "_dongle_disconnected", False):
                self._is_monitoring_dongle = False
                self._lock_and_return_to_login()
                return
            self.after(500, check_flag)

        self.after(500, check_flag)

    def _lock_and_return_to_login(self):
        """Lock the vault, notify user, and transition back to login screen."""
        self._is_monitoring_dongle = False
        messagebox.showwarning(
            "⚠️ KEAMANAN: USB DONGLE DICABUT!",
            "Perangkat Hardware USB Dongle telah dicabut dari laptop!\n\n"
            "Sesuai protokol Kriteria #1 Kriptografi, seluruh data rekam medis pasien seketika dikunci dan sistem dikembalikan ke gerbang autentikasi.",
            parent=self
        )
        self.destroy()
        if self.on_logout_callback:
            self.on_logout_callback()

    def _on_close_window(self):
        """Cleanly handle application window close."""
        self._is_monitoring_dongle = False
        self.destroy()

    def _on_logout(self):
        self._is_monitoring_dongle = False
        self.destroy()
        if self.on_logout_callback:
            self.on_logout_callback()

