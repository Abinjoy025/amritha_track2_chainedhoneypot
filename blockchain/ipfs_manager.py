#!/usr/bin/env python3
"""
blockchain/ipfs_manager.py  (v2)
──────────────────────────────────
Phase 4  – IPFS Forensic Bundle Uploader

When an attacker session ends (disconnect or SOAR container recycle):
  1. Zips  →  Zeek logs (conn.log, ssh.log, …)
              Cowrie JSON log for this session
              Any downloaded malware files
  2. Uploads the zip to IPFS via Pinata REST API (JWT auth)
  3. Returns the CIDv1 hash for storage on the blockchain.

Falls back to a local JSON fallback file when Pinata is unreachable.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import time
import zipfile
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

PINATA_JWT       = os.getenv("PINATA_JWT", "")
PINATA_UPLOAD_URL = "https://uploads.pinata.cloud/v3/files"
FALLBACK_DIR     = os.path.join(os.path.dirname(__file__), "..", "data", "ipfs_fallback")

ZEEK_LOG_DIR     = os.getenv("ZEEK_LOG_DIR",      "/logs/zeek")
HONEYPOT_LOG_DIR = os.getenv("COWRIE_LOG_DIR",    "/logs/honeyport")   # reuses env key for compat
HONEYPOT_DL_DIR  = os.getenv("COWRIE_DL_DIR",     "/data/honeyport_dl")


class IPFSManager:
    def __init__(self):
        os.makedirs(FALLBACK_DIR, exist_ok=True)
        if not PINATA_JWT:
            log.warning("PINATA_JWT not set – uploads will use local fallback storage.")

    # ── Bundle creation ────────────────────────────────────────────────────

    def _build_zip(self, attacker_ip: str, session_id: str) -> bytes:
        """
        Create an in-memory zip of:
          • All Zeek log files (*.log) in ZEEK_LOG_DIR
          • Cowrie session JSON entries matching the attacker IP
          • Malware files downloaded during the session
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # ── Zeek logs ─────────────────────────────────────────────────
            zeek_path = Path(ZEEK_LOG_DIR)
            if zeek_path.exists():
                for log_file in zeek_path.glob("*.log"):
                    zf.write(log_file, arcname=f"zeek/{log_file.name}")
            else:
                zf.writestr("zeek/README.txt", "Zeek log directory not mounted.")

            # ── Honeyport session lines ───────────────────────────────────
            honeypot_log = Path(HONEYPOT_LOG_DIR) / "honeypot_logs.json"
            session_lines = []
            if honeypot_log.exists():
                with open(honeypot_log) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            if entry.get("attacker_ip") == attacker_ip:
                                session_lines.append(entry)
                        except json.JSONDecodeError:
                            pass
            zf.writestr(
                "honeyport/session.json",
                json.dumps(session_lines, indent=2),
            )

            # ── Downloaded malware / artifacts ────────────────────────────
            dl_path = Path(HONEYPOT_DL_DIR)
            if dl_path.exists():
                for malware_file in dl_path.iterdir():
                    if malware_file.is_file():
                        zf.write(malware_file, arcname=f"downloads/{malware_file.name}")

            # ── Metadata ─────────────────────────────────────────────────
            meta = {
                "attacker_ip": attacker_ip,
                "session_id":  session_id,
                "created_at":  datetime.utcnow().isoformat(),
                "tool":        "Honeyport v2",
            }
            zf.writestr("metadata.json", json.dumps(meta, indent=2))

        buf.seek(0)
        return buf.read()

    # ── Upload ─────────────────────────────────────────────────────────────

    def upload_session(self, attacker_ip: str, session_id: str) -> str:
        """
        Bundle and upload one attack session.
        Returns the IPFS CID string.
        """
        zip_bytes = self._build_zip(attacker_ip, session_id)
        filename  = f"honeyport_{attacker_ip.replace('.','_')}_{session_id[:8]}.zip"

        if PINATA_JWT:
            cid = self._upload_to_pinata(zip_bytes, filename)
            if cid:
                log.info("IPFS upload OK  CID=%s  size=%dB", cid, len(zip_bytes))
                return cid
            log.warning("Pinata upload failed – writing to fallback storage.")

        return self._save_fallback(zip_bytes, filename, attacker_ip, session_id)

    def _upload_to_pinata(self, data: bytes, filename: str) -> str | None:
        try:
            resp = requests.post(
                PINATA_UPLOAD_URL,
                headers={"Authorization": f"Bearer {PINATA_JWT}"},
                files={"file": (filename, data, "application/zip")},
                timeout=60,
            )
            resp.raise_for_status()
            body = resp.json()
            # v3 API: {"data": {"cid": "..."}}
            cid = body.get("data", {}).get("cid") or body.get("IpfsHash", "")
            return cid if cid else None
        except Exception as exc:
            log.error("Pinata error: %s", exc)
            return None

    def _save_fallback(
        self, data: bytes, filename: str, ip: str, session_id: str
    ) -> str:
        """
        Compute a SHA-256-based pseudo-CID and persist to local disk.
        Useful for demos / testing without Pinata credentials.
        """
        sha = hashlib.sha256(data).hexdigest()
        pseudo_cid = f"bafk-local-{sha[:16]}"

        fallback_path = os.path.join(FALLBACK_DIR, f"{sha[:16]}.zip")
        with open(fallback_path, "wb") as f:
            f.write(data)

        # Also write a manifest JSON
        manifest = {
            "pseudo_cid":  pseudo_cid,
            "sha256":      sha,
            "attacker_ip": ip,
            "session_id":  session_id,
            "filename":    filename,
            "timestamp":   datetime.utcnow().isoformat(),
            "zip_path":    fallback_path,
        }
        manifest_path = os.path.join(FALLBACK_DIR, f"{sha[:16]}.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        log.info("Fallback IPFS  pseudo_cid=%s  file=%s", pseudo_cid, fallback_path)
        return pseudo_cid

    # ── Retrieve ──────────────────────────────────────────────────────────

    def get_gateway_url(self, cid: str) -> str:
        """Return a public IPFS gateway URL for the given CID."""
        if cid.startswith("bafk-local-"):
            return f"file://local/{cid}"
        return f"https://gateway.pinata.cloud/ipfs/{cid}"
