"""
MediCrypt Vault - Field-Level Database Encryption (FLE) Module
Implements SQLite database with sensitive field encryption (AES-256-CBC + PKCS#7).
Sensitive fields (NIK, Diagnosis, Prescriptions, Doctor Notes) are encrypted before insertion.
"""

import os
import sqlite3
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "medicrypt_ehr.db")
DB_MASTER_KEY = b"MediCrypt-Database-Master-FLE-Key-2026-Strict"


def derive_field_key() -> bytes:
    return hashlib.sha256(DB_MASTER_KEY).digest()


def encrypt_field(plaintext: str) -> str:
    """
    Encrypt a string field using AES-256-CBC.
    Returns format: 'AES_CBC$<iv_hex>$<ciphertext_b64>'
    """
    if not plaintext:
        return ""
    key = derive_field_key()
    cipher = AES.new(key, AES.MODE_CBC) # Automatically generates 16-byte IV
    iv = cipher.iv
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return f"AES_CBC${iv.hex()}${base64.b64encode(ciphertext).decode('ascii')}"


def decrypt_field(encrypted_str: str) -> str:
    """
    Decrypts AES_CBC string field.
    """
    if not encrypted_str or not encrypted_str.startswith("AES_CBC$"):
        return encrypted_str # Return as-is if not encrypted
    try:
        parts = encrypted_str.split('$')
        if len(parts) != 3:
            return encrypted_str
        iv = bytes.fromhex(parts[1])
        ciphertext = base64.b64decode(parts[2].encode('ascii'))
        key = derive_field_key()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[DECRYPT_ERROR: {str(e)}]"


def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """
    Create tables if not exist and populate initial records.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        patient_id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        encrypted_nik TEXT NOT NULL,
        birth_date TEXT,
        gender TEXT,
        blood_type TEXT,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medical_records (
        record_id TEXT PRIMARY KEY,
        patient_id TEXT NOT NULL,
        doctor_id TEXT NOT NULL,
        visit_date TEXT NOT NULL,
        vital_signs TEXT,
        encrypted_diagnosis TEXT NOT NULL,
        encrypted_prescriptions TEXT NOT NULL,
        encrypted_secret_notes TEXT NOT NULL,
        record_sha256 TEXT NOT NULL,
        blockchain_block_id INTEGER,
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
    )
    """)
    conn.commit()

    # Check if empty, populate initial sample patient & record
    cursor.execute("SELECT COUNT(*) FROM patients")
    if cursor.fetchone()[0] == 0:
        _populate_sample_ehr(conn)

    conn.close()


def _populate_sample_ehr(conn):
    from datetime import datetime
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sample Patient 1
    p1 = {
        "patient_id": "RM-2026-0081",
        "full_name": "Tn. Bambang Trihatmojo",
        "nik": "3271041908820003",
        "birth_date": "1982-08-19",
        "gender": "Laki-laki",
        "blood_type": "O+",
        "created_at": now_str
    }
    conn.execute("""
    INSERT INTO patients VALUES (:patient_id, :full_name, :encrypted_nik, :birth_date, :gender, :blood_type, :created_at)
    """, {
        "patient_id": p1["patient_id"],
        "full_name": p1["full_name"],
        "encrypted_nik": encrypt_field(p1["nik"]),
        "birth_date": p1["birth_date"],
        "gender": p1["gender"],
        "blood_type": p1["blood_type"],
        "created_at": p1["created_at"]
    })

    # Sample Record 1
    diag1 = "Sirosis Hepatis Stadium IIB ec Hepatitis B Kronis, Varises Esofagus Grade 2"
    rx1 = "Tenofovir 300mg 1x1, Propranolol 10mg 2x1, Spironolakton 100mg 1x1 pagi"
    notes1 = "Pasien meminta diagnosa hepatitis dirahasiakan dari pihak asuransi kantor. Pantau enzim SGOT/SGPT 2 minggu lagi."
    
    hash1 = hashlib.sha256(f"{p1['patient_id']}|{diag1}|{rx1}".encode('utf-8')).hexdigest()

    conn.execute("""
    INSERT INTO medical_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "REC-2026-0001",
        p1["patient_id"],
        "dr_hartono",
        now_str,
        "TD: 130/85 mmHg, Nadi: 78x/m, Suhu: 36.7 C",
        encrypt_field(diag1),
        encrypt_field(rx1),
        encrypt_field(notes1),
        hash1,
        1
    ))
    conn.commit()


def insert_medical_record(patient_id: str, doctor_id: str, vital_signs: str,
                          raw_diagnosis: str, raw_prescriptions: str, raw_secret_notes: str) -> str:
    """
    Encrypts fields and inserts medical record into SQLite.
    """
    import uuid
    from datetime import datetime

    record_id = f"REC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    enc_diag = encrypt_field(raw_diagnosis)
    enc_rx = encrypt_field(raw_prescriptions)
    enc_notes = encrypt_field(raw_secret_notes)

    rec_hash = hashlib.sha256(f"{patient_id}|{raw_diagnosis}|{raw_prescriptions}".encode('utf-8')).hexdigest()

    conn = get_db_connection()
    conn.execute("""
    INSERT INTO medical_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
    """, (
        record_id,
        patient_id,
        doctor_id,
        now_str,
        vital_signs,
        enc_diag,
        enc_rx,
        enc_notes,
        rec_hash
    ))
    conn.commit()
    conn.close()
    return record_id


def get_all_records(decrypted: bool = False) -> list[dict]:
    """
    Fetch all medical records joined with patient info.
    If decrypted=False, sensitive fields remain encrypted ciphertexts.
    If decrypted=True, sensitive fields are decrypted for authorized view.
    """
    conn = get_db_connection()
    rows = conn.execute("""
    SELECT r.record_id, r.patient_id, p.full_name, p.encrypted_nik, p.gender, p.blood_type,
           r.doctor_id, r.visit_date, r.vital_signs,
           r.encrypted_diagnosis, r.encrypted_prescriptions, r.encrypted_secret_notes,
           r.record_sha256, r.blockchain_block_id
    FROM medical_records r
    JOIN patients p ON r.patient_id = p.patient_id
    ORDER BY r.visit_date DESC
    """).fetchall()
    conn.close()

    results = []
    for row in rows:
        d = dict(row)
        if decrypted:
            d["nik"] = decrypt_field(d["encrypted_nik"])
            d["diagnosis"] = decrypt_field(d["encrypted_diagnosis"])
            d["prescriptions"] = decrypt_field(d["encrypted_prescriptions"])
            d["secret_notes"] = decrypt_field(d["encrypted_secret_notes"])
            d["is_encrypted_view"] = False
        else:
            d["nik"] = d["encrypted_nik"]
            d["diagnosis"] = d["encrypted_diagnosis"]
            d["prescriptions"] = d["encrypted_prescriptions"]
            d["secret_notes"] = d["encrypted_secret_notes"]
            d["is_encrypted_view"] = True
        results.append(d)
    return results


def get_patients_list() -> list[dict]:
    conn = get_db_connection()
    rows = conn.execute("SELECT patient_id, full_name, gender, blood_type FROM patients").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_table_names() -> list[str]:
    """
    Get list of all user table names in the database.
    """
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def get_table_data(table_name: str, decrypted: bool = False) -> tuple[list[str], list[tuple]]:
    """
    Fetches column names and all rows from the specified table.
    If decrypted=True, any string starting with 'AES_CBC$' is decrypted.
    Returns (columns, rows).
    """
    valid_tables = get_table_names()
    if table_name not in valid_tables:
        return ([], [])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    col_names = [desc[0] for desc in cursor.description]
    raw_rows = cursor.fetchall()
    conn.close()

    rows = []
    for r in raw_rows:
        row_list = []
        for val in r:
            if decrypted and isinstance(val, str) and val.startswith("AES_CBC$"):
                row_list.append(decrypt_field(val))
            else:
                row_list.append(val if val is not None else "NULL")
        rows.append(tuple(row_list))
    return (col_names, rows)


