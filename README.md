# 🏥 MediCrypt Vault - Confidential Electronic Health Record (EHR) Cryptographic Security System

Aplikasi Desktop GUI pengamanan rekam medis rahasia berbasis kriptografi modern dan klasik yang dibangun dengan bahasa pemrograman **Python** dan **CustomTkinter**. Aplikasi ini dirancang untuk memenuhi seluruh 7 kriteria Tugas Akhir Mata Kuliah Kriptografi secara komprehensif, akademis, dan tahan uji kriptanalisis.

---

## 📋 Pemenuhan 7 Kriteria Tugas Akhir

| No | Kriteria Tugas | Implementasi dalam MediCrypt Vault | File Modul |
|:---|:---|:---|:---|
| **1** | **Login Biometric & Bantuan Dongle** | **Hardware Dongle USB:** Membaca Volume Serial Number fisik flashdisk + verifikasi digital token HMAC-SHA256 (`medicrypt.dongle`). Aplikasi terkunci jika dongle dicabut.<br>**Biometric Recognition:** **Google FaceNet Deep Neural Network** via Webcam (128-Dimensional Deep Triplet Embeddings, *Cosine Similarity* & *Euclidean Distance*) dengan deteksi wajah dinamis (OpenCV YuNet). **Persistensi Database:** Profil vektor biometrik tersimpan permanen di Database SQLite (`doctor_biometrics`), sehingga dokter cukup mendaftar sekali dan tidak perlu daftar ulang saat dongle dicabut atau aplikasi ditutup. | [`core/hardware_dongle.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/hardware_dongle.py)<br>[`core/biometrics.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/biometrics.py) |
| **2** | **Login Menggunakan Algoritma Kriptografi** | Password dokter di-hash menggunakan standar NIST **PBKDF2-HMAC-SHA256** dengan 100.000 iterasi dan random salt 128-bit unik per akun untuk mencegah serangan *Dictionary* dan *Rainbow Table*. | [`core/auth_crypto.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/auth_crypto.py) |
| **3** | **Super Enkripsi pada Pesan Teks** | Menggabungkan **Extended 256-Byte Vigenère Cipher (Klasik)** dengan **AES-256-GCM (Modern)**. Menghasilkan visualisasi 2 tahap: Plaintext $\to$ Vigenère Ciphertext $\to$ AES-GCM + Nonce 16B + Auth Tag 16B (Authenticated Encryption). | [`core/super_encryption.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/super_encryption.py) |
| **4** | **Enkripsi File (Algoritma Berbeda dari Teks)** | Enkripsi berkas medis (PDF lab, scan rujukan, gambar) menggunakan **ChaCha20-Poly1305 (IETF RFC 8439)**, algoritma *stream cipher* berbasis operasi ARX yang berbeda rumpun dari AES. Dilengkapi kontainer `.medenc` dan verifikasi hash SHA-256. | [`core/file_crypto.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/file_crypto.py) |
| **5** | **Pesan Penting Terenkripsi pada Basis Data** | *Field-Level Encryption (FLE)* pada basis data **SQLite** (`medicrypt_ehr.db`). Kolom sensitif (NIK, Diagnosa, Resep Obat, Catatan Dokter) dienkripsi dengan **AES-256-CBC**. Tersedia tombol pembanding: *Mode Raw DB (Tampilan Peretas)* vs *Mode Terdekripsi*. | [`core/db_crypto.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/db_crypto.py) |
| **6** | **Pesan Gambar Diamankan dengan Steganografi** | Metode **Least Significant Bit (LSB)** pada citra medis (Rontgen X-Ray / CT-Scan). Dilengkapi perlindungan ganda (*Stego-Crypto Hybrid*) di mana payload dienkripsi dengan AES sebelum disisipkan ke piksel. Disertai evaluasi ilmiah **PSNR (> 50 dB)** dan **MSE (~0.0)**. | [`core/steganography.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/steganography.py) |
| **7** | **Aset Penting Diamankan dengan Blockchain Sederhana** | Buku besar terdistribusi mini-blockchain berbasis **SHA-256** dan konsensus **Proof of Work (PoW)** untuk mencatat aset medis digital (Hasil Biopsi, Informed Consent). Dilengkapi fitur interaktif **Simulasi Serangan Modifikasi Data (Tamper Attack)** dan **Verifikasi Keutuhan Rantai**. | [`core/blockchain.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/blockchain.py) |
| **+** | **Kriptanalisis & Evaluasi Matematis (Nilai Tambah)** | Menghitung **Avalanche Effect / SAC ($\approx 50\%$)**, **Entropi Shannon ($H \approx 8.0$)**, serta **Benchmark Kecepatan Throughput** untuk kebutuhan laporan dan slide presentasi UAS. | [`core/crypto_analyzer.py`](file:///d:/KULIAH/SEMESTER%205/Kriptografi/ProjectBesar/core/crypto_analyzer.py) |

---

## 🚀 Panduan Instalasi & Menjalankan Aplikasi

### 1. Prasyarat Sistem
- OS: Windows 10/11
- Python: Versi 3.10 - 3.14
- Perangkat: Webcam (untuk Face Recognition) dan Flashdisk USB (opsional, tersedia mode virtual).

### 2. Menjalankan Aplikasi
Buka terminal (Command Prompt / PowerShell) di direktori ini, lalu jalankan:

```powershell
python app.py
```

### 3. Kredensial Default Login
- **Username Dokter**: `testing`
- **Master Vault Password**: `test123`

---

## 🎬 Skenario Demonstrasi di Hadapan Dosen Penguji

Berikut urutan demo yang direkomendasikan saat presentasi:

### Tahap 1: Gerbang Login 2-Faktor Modern (Kriteria 1 & 2)
1. **Dongle Check (Faktor 1)**: Tunjukkan bahwa saat aplikasi pertama dibuka tanpa USB tercolok, status hardware dongle berwarna merah (`🔴 PORT USB BELUM TERHUBUNG`) dan brankas terkunci rapat.
   - Colokkan USB Flashdisk ke port laptop, lalu klik tombol **"🔄 Pindai Ulang Port USB"**.
   - Jika Flashdisk belum memiliki token, sistem langsung menawarkan konfirmasi untuk menginisialisasi dan menulis token sah secara otomatis ke flashdisk tersebut.
   - Status seketika berubah menjadi hijau (`🟢 DONGLE TERPASANG`) lengkap dengan Hardware Serial dan tanda tangan HMAC-SHA256.
2. **Biometrik Wajah (Faktor 2 - Google FaceNet)**: Karena profil wajah dokter tersimpan permanen di Database SQLite (`doctor_biometrics`), sistem langsung mengenali status `🟡 TERDAFTAR DI DATABASE`. Klik **"📷 Verifikasi Wajah Dokter"** $\to$ Klik **"🔍 Verifikasi Wajah Live"** $\to$ Wajah langsung terverifikasi sah dengan skor kemiripan Cosine Similarity (tidak perlu mendaftar ulang setiap kali aplikasi dibuka atau dongle dicabut).
3. **Kredensial Dokter & PBKDF2 Hash**: Kolom username dan password dimulai dalam keadaan **kosong**. Ketik ID dokter (`testing`) dan password master (`test123`) dari ingatan (tersedia tombol `👁️` untuk memeriksa karakter), lalu klik **"Buka Brankas Rekam Medis"** $\to$ Sistem melakukan hash PBKDF2-HMAC-SHA256 (100.000 iterasi) dan mencocokkannya dengan database secara *timing-safe* $\to$ Seluruh faktor keamanan terpenuhi dan Dashboard utama terbuka.

> [!IMPORTANT]
> **Proteksi Fisik Dongle Real-Time (Active Session Locking):**
> 1. **Saat Di Layar Login:** Jika USB dicabut setelah dipindai, tombol login akan langsung menolak akses karena melakukan *live re-check*.
> 2. **Saat Sudah Berada di Dashboard:** Jika USB dicabut kapan saja saat aplikasi sedang digunakan, *background watchdog* seketika mendeteksi pencabutan USB (dalam ~1 detik), memunculkan peringatan keamanan, menutup dashboard rekam medis, dan **otomatis melempar kembali ke gerbang login**.

### Tahap 2: Super Enkripsi Teks (Kriteria 3)
1. Buka tab **"🔐 Super Enkripsi Teks"**.
2. Masukkan pesan diagnosa sensitif, isi Kunci Klasik (Vigenère) dan Kunci Modern (AES).
3. Klik **"Kunci Super Enkripsi"**:
   - Tunjukkan **Tahap 1**: Ciphertext klasik hasil substitusi Vigenère mod 26/256.
   - Tunjukkan **Tahap 2**: Ciphertext modern hasil AES-256-GCM lengkap dengan Nonce dan Authentication Tag.
4. Klik **"Super Dekripsi"** $\to$ Tunjukkan badge hijau **AUTHENTICATION TAG VERIFIED**, membuktikan pesan 100% utuh dan tidak mengalami manipulasi bit.

### Tahap 3: Enkripsi Berkas Medis (Kriteria 4)
1. Buka tab **"📁 Enkripsi Berkas Medis"**.
2. Jelaskan kepada dosen bahwa algoritma file ini **berbeda** dari teks: teks menggunakan AES, sedangkan file menggunakan **ChaCha20-Poly1305**.
3. Pilih sembarang file (PDF hasil lab / TXT / gambar), masukkan kunci, klik **"Enkripsi Berkas ke Kontainer (.medenc)"**.
4. Klik **"Dekripsi Berkas"** $\to$ Tunjukkan pemulihan berkas asli dan kesamaan nilai hash SHA-256 sebelum dan sesudah.

### Tahap 4: Basis Data Terenkripsi (Kriteria 5)
1. Buka tab **"🗄️ Database Terenkripsi (FLE)"**.
2. Tunjukkan **Mode Raw Database (Merah)**: Seluruh kolom penting seperti NIK, Diagnosa Klinis, dan Resep Obat tampil teracak sebagai `AES_CBC$...`. Tekankan bahwa jika file `.db` dicuri atau dibuka dengan DB Browser SQLite, isinya tidak terbaca.
3. Geser tombol ke **Mode Terdekripsi (Hijau)** $\to$ Data berubah menjadi teks medis klinis yang rapi karena telah melalui otorisasi dokter.
4. Tambahkan rekam medis baru melalui tombol **"➕ Tambah Rekam Medis Baru"**.

### Tahap 5: Steganografi Citra Medis (Kriteria 6)
1. Buka tab **"🖼️ Steganografi Citra Medis"**.
2. Klik tombol **"🩻 Gunakan X-Ray Medis"** (memuat gambar rontgen dada sintetis bawaan).
3. Ketikkan pesan diagnosa rahasia, masukkan kunci stego AES, lalu klik **"Sisipkan Pesan Rahasia (Encode LSB)"**.
4. Tunjukkan kartu **Analisis Kualitas Citra**:
   - Nilai **PSNR (Peak Signal-to-Noise Ratio) > 50 dB** (menunjukkan secara matematis tidak ada degradasi visual pada gambar rontgen).
   - Nilai **MSE (Mean Squared Error) mendekati 0.0**.
5. Klik **"Ekstrak & Dekripsi Pesan Rahasia"** $\to$ Pesan rahasia kembali terbaca secara sempurna.

### Tahap 6: Blockchain Aset Medis & Simulasi Serangan (Kriteria 7)
1. Buka tab **"⛓ Blockchain Aset Medis"**.
2. Tunjukkan bahwa pada kondisi awal, seluruh blok berstatus **🟢 STATUS RANTAI: VALID (HIJAU)** (Root Genesis Block, Blok #1 Hasil Biopsi, Blok #2 Informed Consent).
3. Klik tombol **"🚨 Simulasi Serangan Hacker (Ubah Data)"** $\to$ Sistem mensimulasikan peretasan di mana data pada Blok #1 diubah secara paksa tanpa mining.
4. **Status seketika berubah merah (KECURANGAN TERDETEKSI)**: Blok #1 disorot merah karena hash hasil kalkulasi ulang tidak cocok dengan hash yang tercatat di rantai. Ini membuktikan sifat *tamper-evident* blockchain.
5. Tombol aksi secara otomatis berubah menjadi tombol hijau **"🛡️ Validasi & Benarkan Integritas (Konsensus Otomatis)"**.
6. Klik tombol hijau tersebut $\to$ Mekanisme konsensus kriptografi secara otomatis mendeteksi blok palsu, menolaknya, dan memulihkan data sah asli kembali utuh 100% (**Status kembali HIJAU**).
7. Demonstrasikan tombol **"⛏️ Tambah & Tambang Aset Baru (PoW)"** untuk menambahkan dokumen baru atau menyinkronkan rekam medis dari database EHR secara langsung.

---

## 🧪 Menjalankan Unit Test Otomatis

Seluruh logika kriptografi dilengkapi unit test otomatis:

```powershell
python test_suite.py
```
*Output yang diharapkan: `Ran 9 tests in ...s - OK`.*

---

## 📁 Struktur Direktori

```
ProjectBesar/
├── app.py                      # File utama pembuka aplikasi GUI
├── requirements.txt            # Daftar dependensi library Python
├── README.md                   # Dokumentasi lengkap & panduan presentasi
├── test_suite.py               # Unit test otomatis 7 kriteria
├── core/                       # Mesin Kriptografi (Logika Matematika)
│   ├── auth_crypto.py          # PBKDF2-HMAC-SHA256 password hashing
│   ├── hardware_dongle.py      # USB Flashdisk Serial & HMAC Dongle Token
│   ├── biometrics.py           # Face Recognition (OpenCV) & Fingerprint Sensor
│   ├── super_encryption.py     # Super Enkripsi (Vigenère + AES-256-GCM)
│   ├── file_crypto.py          # File Encryption (ChaCha20-Poly1305)
│   ├── db_crypto.py            # SQLite Field-Level Encryption (AES-CBC)
│   ├── steganography.py        # LSB Steganography + PSNR & MSE Analysis
│   ├── blockchain.py           # Simple Blockchain PoW SHA-256 Ledger
│   └── crypto_analyzer.py      # Avalanche Effect, Shannon Entropy & Benchmark
├── ui/                         # Antarmuka Desktop Modern (CustomTkinter)
│   ├── login_window.py         # Gerbang Login Multi-Faktor (Dongle + Biometrik + Pwd)
│   ├── main_dashboard.py       # Dashboard Utama & Sidebar Navigasi
│   ├── tab_super_text.py       # Tampilan Tab Super Enkripsi Teks
│   ├── tab_file_crypto.py      # Tampilan Tab Enkripsi Berkas
│   ├── tab_database_records.py # Tampilan Tab Basis Data Terenkripsi
│   ├── tab_steganography.py    # Tampilan Tab Steganografi Citra
│   ├── tab_blockchain.py       # Tampilan Tab Blockchain Aset Medis
│   └── tab_analysis.py         # Tampilan Tab Kriptanalisis & Benchmark
└── data/                       # Penyimpanan database, kunci, dan citra sampel
    ├── sample_xray.png         # Citra rontgen dada medis untuk steganografi
    ├── medicrypt_ehr.db        # Basis data SQLite rekam medis terenkripsi
    └── blockchain_ledger.json  # Buku besar blok rantai aset medis
```

