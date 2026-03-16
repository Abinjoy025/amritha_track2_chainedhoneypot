#!/usr/bin/env python3
"""
blockchain/blockchain_manager.py  (v2)
──────────────────────────────────────
Phase 4  – Sepolia Testnet Integration via web3.py

Stores one record per attacker session:
  storeRecord(attackerIP, osintScore, attackType, ipfsCID)

ABI must match AttackEvidenceStorage.sol v2.
CONTRACT_ADDRESS is read from .env (HONEYPORT_CONTRACT_ADDRESS).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_attackerIP",  "type": "string"},
            {"internalType": "uint8",  "name": "_osintScore",  "type": "uint8"},
            {"internalType": "string", "name": "_attackType",  "type": "string"},
            {"internalType": "string", "name": "_ipfsCID",     "type": "string"},
        ],
        "name": "storeRecord",
        "outputs": [{"internalType": "uint256", "name": "recordId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "_id", "type": "uint256"}],
        "name": "getRecord",
        "outputs": [
            {"internalType": "string",  "name": "attackerIP", "type": "string"},
            {"internalType": "uint256", "name": "capturedAt", "type": "uint256"},
            {"internalType": "uint8",   "name": "osintScore", "type": "uint8"},
            {"internalType": "string",  "name": "attackType", "type": "string"},
            {"internalType": "string",  "name": "ipfsCID",    "type": "string"},
            {"internalType": "address", "name": "reporter",   "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "_n", "type": "uint256"}],
        "name": "getLatestRecords",
        "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "recordCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "internalType": "uint256", "name": "recordId",   "type": "uint256"},
            {"indexed": True,  "internalType": "string",  "name": "attackerIP", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "capturedAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint8",   "name": "osintScore", "type": "uint8"},
            {"indexed": False, "internalType": "string",  "name": "attackType", "type": "string"},
            {"indexed": False, "internalType": "string",  "name": "ipfsCID",    "type": "string"},
            {"indexed": False, "internalType": "address", "name": "reporter",   "type": "address"},
        ],
        "name": "RecordStored",
        "type": "event",
    },
]

# Mock storage for when no RPC is available
MOCK_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "blockchain_mock.json")


class BlockchainManager:
    def __init__(self, network: str = "sepolia"):
        self.network          = network
        self.w3: Web3 | None  = None
        self.contract         = None
        self.account          = None
        self._mock_mode       = False

        self._connect()
        self._load_contract()

    # ── Connection ──────────────────────────────────────────────────────────

    def _connect(self) -> None:
        provider_url = os.getenv("WEB3_PROVIDER_URL", "")
        if not provider_url:
            log.warning("WEB3_PROVIDER_URL not set – running in MOCK mode.")
            self._mock_mode = True
            return
        try:
            self.w3 = Web3(Web3.HTTPProvider(provider_url))
            if not self.w3.is_connected():
                raise ConnectionError("Provider did not respond.")
            log.info("Connected to %s (chainId=%s)", self.network, self.w3.eth.chain_id)
        except Exception as exc:
            log.warning("Blockchain connect failed: %s – MOCK mode.", exc)
            self._mock_mode = True

    def _load_contract(self) -> None:
        if self._mock_mode:
            return
        address = os.getenv("HONEYPORT_CONTRACT_ADDRESS", "")
        pk      = os.getenv("ETH_PRIVATE_KEY", "")
        if not address or not pk:
            log.warning("CONTRACT/KEY not set – MOCK mode.")
            self._mock_mode = True
            return
        try:
            self.account  = self.w3.eth.account.from_key(pk)
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=CONTRACT_ABI,
            )
            log.info("Contract loaded at %s", address)
        except Exception as exc:
            log.error("Contract init failed: %s", exc)
            self._mock_mode = True

    # ── Store record ────────────────────────────────────────────────────────

    def store_attack_record(
        self,
        attacker_ip: str,
        osint_score: int,
        attack_type: str,
        ipfs_cid:    str,
    ) -> dict:
        """
        Write one attack record to the smart contract.
        Returns a result dict with tx_hash (or mock_id in mock mode).
        """
        if self._mock_mode:
            return self._mock_store(attacker_ip, osint_score, attack_type, ipfs_cid)

        try:
            nonce   = self.w3.eth.get_transaction_count(self.account.address)
            gas_est = self.contract.functions.storeRecord(
                attacker_ip, min(osint_score, 255), attack_type, ipfs_cid
            ).estimate_gas({"from": self.account.address})

            tx = self.contract.functions.storeRecord(
                attacker_ip, min(osint_score, 255), attack_type, ipfs_cid
            ).build_transaction({
                "from":     self.account.address,
                "nonce":    nonce,
                "gas":      gas_est + 20_000,
                "gasPrice": self.w3.eth.gas_price,
            })
            signed  = self.w3.eth.account.sign_transaction(tx, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            result = {
                "success":      True,
                "tx_hash":      tx_hash.hex(),
                "block_number": receipt["blockNumber"],
                "gas_used":     receipt["gasUsed"],
                "network":      self.network,
                "timestamp":    datetime.utcnow().isoformat(),
            }
            log.info("TX confirmed: %s  (block %d)", tx_hash.hex()[:16], receipt["blockNumber"])
            return result

        except Exception as exc:
            log.error("TX failed: %s  – falling back to mock.", exc)
            return self._mock_store(attacker_ip, osint_score, attack_type, ipfs_cid)

    # ── Read records ────────────────────────────────────────────────────────

    def get_record(self, record_id: int) -> dict | None:
        if self._mock_mode:
            return self._mock_read(record_id)
        try:
            r = self.contract.functions.getRecord(record_id).call()
            return {
                "record_id":   record_id,
                "attacker_ip": r[0],
                "captured_at": r[1],
                "osint_score": r[2],
                "attack_type": r[3],
                "ipfs_cid":    r[4],
                "reporter":    r[5],
            }
        except Exception as exc:
            log.error("getRecord(%d) failed: %s", record_id, exc)
            return None

    def get_latest_records(self, n: int = 20) -> list[dict]:
        if self._mock_mode:
            return self._mock_latest(n)
        try:
            ids = self.contract.functions.getLatestRecords(n).call()
            records = [r for r in (self.get_record(i) for i in ids) if r]
            if records:
                return records
            # No on-chain records yet – return local fallback records so the
            # dashboard is populated even before TXs confirm on Sepolia.
            return self._mock_latest(n)
        except Exception as exc:
            log.error("getLatestRecords failed: %s", exc)
            return self._mock_latest(n)

    # ── Mock mode (no RPC) ───────────────────────────────────────────────────

    def _load_mock(self) -> list:
        if os.path.exists(MOCK_FILE):
            with open(MOCK_FILE) as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    pass
        return []

    def _save_mock(self, data: list) -> None:
        os.makedirs(os.path.dirname(MOCK_FILE), exist_ok=True)
        with open(MOCK_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def _mock_store(self, ip, score, attack_type, cid) -> dict:
        records  = self._load_mock()
        mock_id  = len(records) + 1
        entry    = {
            "record_id":   mock_id,
            "attacker_ip": ip,
            "captured_at": int(datetime.utcnow().timestamp()),
            "osint_score": score,
            "attack_type": attack_type,
            "ipfs_cid":    cid,
            "reporter":    "0x0000000000000000000000000000000000000000",
            "_mock":       True,
        }
        records.append(entry)
        self._save_mock(records)
        log.info("MOCK  stored record #%d for %s", mock_id, ip)
        return {"success": True, "mock_id": mock_id, "note": "stored in blockchain_mock.json"}

    def _mock_read(self, record_id: int) -> dict | None:
        records = self._load_mock()
        for r in records:
            if r.get("record_id") == record_id:
                return r
        return None

    def _mock_latest(self, n: int) -> list:
        records = self._load_mock()
        return sorted(records, key=lambda r: r.get("captured_at", 0), reverse=True)[:n]
