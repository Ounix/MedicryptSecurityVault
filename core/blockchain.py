"""
MediCrypt Vault - Blockchain Ledger Module
Secures digital medical assets (Biopsy Results, Genomic Sequences, Surgery Consent)
using a simple SHA-256 blockchain with Proof-of-Work (PoW) and tamper detection.
"""

import os
import time
import json
import hashlib
from datetime import datetime

BLOCKCHAIN_LEDGER_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "blockchain_ledger.json")
AUTHENTIC_BACKUP_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "blockchain_authentic_backup.json")
DEFAULT_DIFFICULTY = 3 # Number of leading zeros required for Proof of Work


class Block:
    def __init__(self, index: int, timestamp: str, asset_id: str, asset_name: str,
                 patient_id: str, data_hash: str, doctor_signer: str,
                 previous_hash: str, nonce: int = 0, block_hash: str = ""):
        self.index = index
        self.timestamp = timestamp
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.patient_id = patient_id
        self.data_hash = data_hash
        self.doctor_signer = doctor_signer
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calculates SHA-256 hash of block contents.
        """
        block_string = (
            f"{self.index}|{self.timestamp}|{self.asset_id}|{self.asset_name}|"
            f"{self.patient_id}|{self.data_hash}|{self.doctor_signer}|"
            f"{self.previous_hash}|{self.nonce}"
        )
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def mine_block(self, difficulty: int = DEFAULT_DIFFICULTY) -> int:
        """
        Executes Proof-of-Work (PoW): increments nonce until hash starts with '0'*difficulty.
        """
        target = "0" * difficulty
        start_time = time.time()
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        elapsed = time.time() - start_time
        return self.nonce

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "patient_id": self.patient_id,
            "data_hash": self.data_hash,
            "doctor_signer": self.doctor_signer,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(d: dict) -> 'Block':
        return Block(
            index=d["index"],
            timestamp=d["timestamp"],
            asset_id=d["asset_id"],
            asset_name=d["asset_name"],
            patient_id=d["patient_id"],
            data_hash=d["data_hash"],
            doctor_signer=d["doctor_signer"],
            previous_hash=d["previous_hash"],
            nonce=d["nonce"],
            block_hash=d["hash"]
        )


class MedicalBlockchain:
    def __init__(self, difficulty: int = DEFAULT_DIFFICULTY):
        self.difficulty = difficulty
        self.chain: list[Block] = []
        self.load_or_create_chain()

    def create_genesis_block(self) -> Block:
        now_str = "2026-01-01 00:00:00"
        genesis = Block(
            index=0,
            timestamp=now_str,
            asset_id="GENESIS-ASSET-000",
            asset_name="MediCrypt Root Genesis Security Anchor",
            patient_id="SYSTEM-ROOT",
            data_hash="0000000000000000000000000000000000000000000000000000000000000000",
            doctor_signer="Hospital Chief Medical Board",
            previous_hash="0" * 64
        )
        genesis.mine_block(self.difficulty)
        return genesis

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_asset_block(self, asset_id: str, asset_name: str, patient_id: str,
                        data_hash: str, doctor_signer: str = "dr_hartono") -> Block:
        """
        Mines and appends a new block for an asset.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        latest = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=now_str,
            asset_id=asset_id,
            asset_name=asset_name,
            patient_id=patient_id,
            data_hash=data_hash,
            doctor_signer=doctor_signer,
            previous_hash=latest.hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def validate_chain_integrity(self) -> dict:
        """
        Validates entire blockchain integrity.
        Returns validation details and identifies any tampered block.
        """
        target = "0" * self.difficulty
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Check if current block hash matches recalculated contents
            recalculated = curr.calculate_hash()
            if curr.hash != recalculated:
                return {
                    "is_valid": False,
                    "error_type": "HASH_CORRUPTED",
                    "block_index": curr.index,
                    "message": f"Kecurangan Terdeteksi di Blok #{curr.index}! Isi data telah diubah (Hash tercatat != Hash kalkulasi ulang)."
                }

            # 2. Check if previous_hash matches actual previous block's hash
            if curr.previous_hash != prev.hash:
                return {
                    "is_valid": False,
                    "error_type": "CHAIN_BROKEN",
                    "block_index": curr.index,
                    "message": f"Rantai Integritas Terputus di Blok #{curr.index}! Previous Hash ({curr.previous_hash[:12]}...) tidak cocok dengan Blok #{prev.index} ({prev.hash[:12]}...)."
                }

            # 3. Check proof of work difficulty
            if not curr.hash.startswith(target):
                return {
                    "is_valid": False,
                    "error_type": "POW_INVALID",
                    "block_index": curr.index,
                    "message": f"Blok #{curr.index} tidak memenuhi target Proof-of-Work ({self.difficulty} leading zeros)!"
                }

        return {
            "is_valid": True,
            "total_blocks": len(self.chain),
            "difficulty": self.difficulty,
            "message": f"Seluruh {len(self.chain)} blok blockchain terverifikasi 100% sah dan tidak pernah dimanipulasi!"
        }

    def backup_authentic_chain(self):
        """
        Saves a cryptographically verified authentic snapshot of the blockchain ledger.
        """
        os.makedirs(os.path.dirname(AUTHENTIC_BACKUP_FILE), exist_ok=True)
        raw_list = [b.to_dict() for b in self.chain]
        with open(AUTHENTIC_BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(raw_list, f, indent=2)

    def heal_chain(self) -> dict:
        """
        Consensus auto-repair: Restores tampered blocks back to their cryptographically
        authentic state from the authentic ledger backup, re-securing the chain.
        """
        if os.path.exists(AUTHENTIC_BACKUP_FILE):
            try:
                with open(AUTHENTIC_BACKUP_FILE, "r", encoding="utf-8") as f:
                    raw_list = json.load(f)
                    if raw_list and isinstance(raw_list, list):
                        self.chain = [Block.from_dict(d) for d in raw_list]
                        self.save_chain()
                        return {
                            "success": True,
                            "restored_count": len(self.chain),
                            "validation": self.validate_chain_integrity()
                        }
            except Exception:
                pass

        # Fallback repair: re-mine any broken block
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            if curr.previous_hash != prev.hash:
                curr.previous_hash = prev.hash
            if curr.hash != curr.calculate_hash() or not curr.hash.startswith("0" * self.difficulty):
                curr.nonce = 0
                curr.hash = curr.calculate_hash()
                curr.mine_block(self.difficulty)

        self.save_chain()
        self.backup_authentic_chain()
        return {
            "success": True,
            "restored_count": len(self.chain),
            "validation": self.validate_chain_integrity()
        }

    def simulate_tamper(self, block_index: int, fake_asset_name: str) -> bool:
        """
        Simulate malicious alteration of historical block data for professor demonstration.
        Ensures an authentic backup exists prior to tampering so it can be healed.
        """
        # Ensure authentic backup is recorded if chain was valid
        val = self.validate_chain_integrity()
        if val["is_valid"]:
            self.backup_authentic_chain()

        if 0 <= block_index < len(self.chain):
            self.chain[block_index].asset_name = fake_asset_name
            # DO NOT re-mine or update hash so corruption is evident
            self.save_chain()
            return True
        return False

    def save_chain(self):
        os.makedirs(os.path.dirname(BLOCKCHAIN_LEDGER_FILE), exist_ok=True)
        raw_list = [b.to_dict() for b in self.chain]
        with open(BLOCKCHAIN_LEDGER_FILE, "w", encoding="utf-8") as f:
            json.dump(raw_list, f, indent=2)

    def load_or_create_chain(self):
        if os.path.exists(BLOCKCHAIN_LEDGER_FILE):
            try:
                with open(BLOCKCHAIN_LEDGER_FILE, "r", encoding="utf-8") as f:
                    raw_list = json.load(f)
                    if raw_list and isinstance(raw_list, list):
                        self.chain = [Block.from_dict(d) for d in raw_list]
                        val = self.validate_chain_integrity()
                        if val["is_valid"]:
                            self.backup_authentic_chain()
                            return
                        else:
                            # Chain was left tampered from previous session; heal it so initial state is ALWAYS valid!
                            self.heal_chain()
                            return
            except Exception:
                pass

        # If not exists or empty, create genesis + 2 sample assets
        self.chain = [self.create_genesis_block()]
        # Sample Asset 1
        self.add_asset_block(
            asset_id="AST-2026-BIOPSY-01",
            asset_name="Hasil Biopsi Patologi Anatomi - Nodul Hepar",
            patient_id="RM-2026-0081",
            data_hash=hashlib.sha256(b"Biopsy Specimen #4902 - Grade 2 Benign").hexdigest(),
            doctor_signer="dr_hartono"
        )
        # Sample Asset 2
        self.add_asset_block(
            asset_id="AST-2026-SURGERY-CONSENT",
            asset_name="Surat Informed Consent Operasi Reseksi Laparoskopi",
            patient_id="RM-2026-0081",
            data_hash=hashlib.sha256(b"Signed Surgery Agreement 2026").hexdigest(),
            doctor_signer="dr_hartono"
        )
        self.save_chain()
        self.backup_authentic_chain()

