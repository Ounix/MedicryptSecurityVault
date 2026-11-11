"""
MediCrypt Vault - Hardware Dongle Security Module
Detects USB Flash Drive, retrieves Volume Serial Number,
and verifies cryptographic digital token (HMAC-SHA256 signature).
"""

import os
import sys
import ctypes
import json
import hmac
import hashlib
import psutil

# System Master Secret used to sign authorized hardware dongles
DONGLE_MASTER_SECRET = b"MediCrypt-Vault-Hardware-Dongle-Secret-Key-2026-NIST"
DONGLE_FILENAME = "medicrypt.dongle"
VIRTUAL_DONGLE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "virtual_dongle")


def get_volume_serial_number(drive_path: str) -> str:
    """
    Retrieve hardware Volume Serial Number of a drive (e.g., 'E:\\' -> '38A4-B901').
    """
    try:
        drive_path = os.path.splitdrive(drive_path)[0] + "\\"
        serial_number = ctypes.c_ulong()
        max_component_len = ctypes.c_ulong()
        flags = ctypes.c_ulong()
        vol_name = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)

        success = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_path),
            vol_name,
            ctypes.sizeof(vol_name),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_len),
            ctypes.byref(flags),
            fs_name,
            ctypes.sizeof(fs_name)
        )
        if success:
            sn = serial_number.value
            return f"{(sn >> 16) & 0xFFFF:04X}-{sn & 0xFFFF:04X}"
    except Exception as e:
        pass
    return "UNKNOWN-SERIAL"


def compute_dongle_signature(payload: dict) -> str:
    """
    Compute HMAC-SHA256 signature for dongle payload binding device serial to user.
    """
    sign_data = f"{payload.get('dongle_uuid')}|{payload.get('device_serial')}|{payload.get('authorized_user')}|{payload.get('created_at')}"
    return hmac.new(DONGLE_MASTER_SECRET, sign_data.encode('utf-8'), hashlib.sha256).hexdigest()


def write_dongle_token(target_dir: str, username: str, device_serial: str = None) -> dict:
    """
    Write authorized cryptographic dongle token file to USB Flashdrive or target directory.
    """
    import uuid
    from datetime import datetime

    if not device_serial or device_serial == "UNKNOWN-SERIAL":
        device_serial = get_volume_serial_number(target_dir)

    payload = {
        "magic": "MEDICRYPT-HARDWARE-SECURITY-DONGLE-V1",
        "dongle_uuid": str(uuid.uuid4()),
        "device_serial": device_serial,
        "authorized_user": username,
        "created_at": datetime.now().isoformat(),
    }
    payload["signature"] = compute_dongle_signature(payload)

    target_file = os.path.join(target_dir, DONGLE_FILENAME)
    os.makedirs(target_dir, exist_ok=True)
    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return payload


def verify_dongle_file(file_path: str, expected_user: str = None) -> tuple[bool, str, dict]:
    """
    Verify integrity and signature of a dongle file.
    """
    if not os.path.exists(file_path):
        return False, "File token dongle tidak ditemukan", {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("magic") != "MEDICRYPT-HARDWARE-SECURITY-DONGLE-V1":
            return False, "Format file dongle tidak valid (Magic header mismatch)", {}

        expected_sig = compute_dongle_signature(data)
        if not hmac.compare_digest(data.get("signature", ""), expected_sig):
            return False, "Tanda tangan kriptografi dongle rusak / dipalsukan!", {}

        # Allow user match (accepting 'dr_hartono' as valid alias for 'testing')
        valid_users = [expected_user] if expected_user else []
        if "testing" in valid_users:
            valid_users.append("dr_hartono")
        if expected_user and data.get("authorized_user") not in valid_users:
            return False, f"Dongle milik user {data.get('authorized_user')}, bukan {expected_user}", {}

        # Check volume serial binding if on a physical drive
        drive = os.path.splitdrive(file_path)[0] + "\\"
        actual_serial = get_volume_serial_number(drive)
        recorded_serial = data.get("device_serial", "")

        is_virtual = str(recorded_serial).startswith("VIRTUAL-") or os.path.normpath(file_path).startswith(os.path.normpath(VIRTUAL_DONGLE_DIR))

        if not is_virtual and recorded_serial != "UNKNOWN-SERIAL" and actual_serial != "UNKNOWN-SERIAL":
            if recorded_serial != actual_serial:
                return False, f"Hardware Mismatch: Token dipindah ke perangkat lain! ({recorded_serial} != {actual_serial})", {}

        return True, "Dongle terverifikasi sah", data
    except Exception as e:
        return False, f"Gagal membaca token: {str(e)}", {}


def get_connected_usb_drives() -> list[dict]:
    """
    Find connected external / removable USB flash drives.
    """
    usb_drives = []
    try:
        partitions = psutil.disk_partitions(all=True)
        for part in partitions:
            if 'cdrom' in part.opts:
                continue
            mount = part.mountpoint
            is_removable = 'removable' in part.opts
            # On Windows, drives other than system drive C: and D: or flagged removable
            is_external_candidate = is_removable or (mount.upper() not in ["C:\\", "D:\\"])
            if is_external_candidate:
                sn = get_volume_serial_number(mount)
                token_file = os.path.join(mount, DONGLE_FILENAME)
                usb_drives.append({
                    "mount": mount,
                    "serial": sn,
                    "is_removable": is_removable,
                    "has_token": os.path.exists(token_file),
                    "token_path": token_file
                })
    except Exception:
        pass
    return usb_drives


def scan_for_dongle(expected_user: str = "testing", allow_virtual: bool = False) -> dict:
    """
    Scan physical removable drives (USB Flashdisk) for valid cryptographic token.
    Only falls back to virtual dongle if explicitly enabled (e.g. unit tests).
    """
    candidates = []
    unregistered_usb = None

    # 1. Scan physical drives (prioritizing removable USB drives)
    try:
        partitions = psutil.disk_partitions(all=True)
        for part in partitions:
            if 'cdrom' in part.opts:
                continue
            mount = part.mountpoint
            # Prioritize removable / external partitions
            is_candidate = 'removable' in part.opts or (mount.upper() not in ["C:\\", "D:\\"])
            token_path = os.path.join(mount, DONGLE_FILENAME)

            if os.path.exists(token_path):
                valid, msg, data = verify_dongle_file(token_path, expected_user)
                candidates.append({
                    "is_valid": valid,
                    "drive": mount,
                    "path": token_path,
                    "message": msg,
                    "data": data,
                    "is_virtual": False,
                    "unregistered_usb": None
                })
            elif is_candidate and unregistered_usb is None:
                sn = get_volume_serial_number(mount)
                unregistered_usb = {
                    "mount": mount,
                    "serial": sn,
                    "is_removable": 'removable' in part.opts
                }
    except Exception:
        pass

    # Return valid physical candidate if found
    for c in candidates:
        if c["is_valid"]:
            return c

    # 2. Virtual dongle ONLY if explicitly allowed (e.g. automated test suites)
    if allow_virtual:
        virtual_token = os.path.join(VIRTUAL_DONGLE_DIR, DONGLE_FILENAME)
        if os.path.exists(virtual_token):
            valid, msg, data = verify_dongle_file(virtual_token, expected_user)
            if valid:
                return {
                    "is_valid": True,
                    "drive": VIRTUAL_DONGLE_DIR,
                    "path": virtual_token,
                    "message": msg + " [Virtual Dongle Mode]",
                    "data": data,
                    "is_virtual": True,
                    "unregistered_usb": None
                }

    # If any exists on physical drives but invalid (e.g. signature mismatch)
    if candidates:
        candidates[0]["unregistered_usb"] = unregistered_usb
        return candidates[0]

    # If unformatted/unregistered USB is detected
    if unregistered_usb:
        return {
            "is_valid": False,
            "drive": unregistered_usb["mount"],
            "path": None,
            "message": f"USB Flashdisk terdeteksi di drive {unregistered_usb['mount']}, namun belum berisi token otorisasi.",
            "data": {},
            "is_virtual": False,
            "unregistered_usb": unregistered_usb
        }

    return {
        "is_valid": False,
        "drive": None,
        "path": None,
        "message": "USB Flashdisk Dongle Kriptografi belum dicolokkan ke laptop!",
        "data": {},
        "is_virtual": False,
        "unregistered_usb": None
    }


def list_available_drives() -> list[dict]:
    """
    List all connected drives that can be initialized as a USB Dongle.
    """
    results = []
    try:
        for p in psutil.disk_partitions(all=True):
            if 'cdrom' in p.opts:
                continue
            sn = get_volume_serial_number(p.mountpoint)
            is_removable = 'removable' in p.opts
            results.append({
                "mount": p.mountpoint,
                "device": p.device,
                "fstype": p.fstype,
                "serial": sn,
                "is_removable": is_removable,
                "label": f"{p.mountpoint} ({'USB Removable' if is_removable else 'Fixed Drive'}, SN: {sn})"
            })
    except Exception:
        pass
    return results
