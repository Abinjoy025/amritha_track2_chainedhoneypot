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

    def _collect_session_logs(self, attacker_ip: str) -> list:
        """Return all honeypot log entries for this attacker IP."""
        honeypot_log = Path(HONEYPOT_LOG_DIR) / "honeypot_logs.json"
        entries = []
        if honeypot_log.exists():
            with open(honeypot_log) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get("attacker_ip") == attacker_ip:
                            entries.append(entry)
                    except json.JSONDecodeError:
                        pass
        return entries

    def _collect_malware_info(self) -> list:
        """Return metadata + SHA-256 hash for every downloaded artifact."""
        artifacts = []
        dl_path = Path(HONEYPOT_DL_DIR)
        if dl_path.exists():
            for f in dl_path.iterdir():
                if f.is_file():
                    raw = f.read_bytes()
                    artifacts.append({
                        "filename":  f.name,
                        "size_bytes": len(raw),
                        "sha256":    hashlib.sha256(raw).hexdigest(),
                    })
        return artifacts

    def _collect_zeek_filenames(self) -> list:
        """Return list of Zeek log filenames present in ZEEK_LOG_DIR."""
        zeek_path = Path(ZEEK_LOG_DIR)
        if zeek_path.exists():
            return [p.name for p in zeek_path.glob("*.log")]
        return []

    def _build_zip(
        self,
        attacker_ip:  str,
        session_id:   str,
        prediction:   dict | None = None,
        osint:        dict | None = None,
        session_data: dict | None = None,
    ) -> tuple[bytes, str]:
        """
        Create an in-memory zip containing all attacker evidence:

          evidence_bundle.json  – structured record with all 8 fields
          zeek/                 – Zeek network traffic log files
          honeypot/session.json – raw honeypot log entries for this IP
          downloads/            – malware / payload files
        """
        session_logs  = self._collect_session_logs(attacker_ip)
        malware_info  = self._collect_malware_info()
        zeek_files    = self._collect_zeek_filenames()

        # ── Extract commands executed from session log entries ────────────
        commands_executed = []
        for entry in session_logs:
            cmd = entry.get("command") or entry.get("commands")
            if cmd:
                commands_executed.append({
                    "timestamp": entry.get("timestamp", ""),
                    "command":   cmd,
                })
            # Also capture POST body / payload as "commands"
            raw = entry.get("raw_payload") or entry.get("post_body")
            if raw and raw not in commands_executed:
                commands_executed.append({
                    "timestamp": entry.get("timestamp", ""),
                    "command":   f"[payload] {raw[:500]}",
                })

        # ── Derive attack timestamp ───────────────────────────────────────
        attack_timestamp = (
            (session_data or {}).get("timestamp")
            or (session_logs[0].get("timestamp") if session_logs else None)
            or datetime.utcnow().isoformat()
        )

        # ── Evidence bundle (all 8 fields) ───────────────────────────────
        bundle = {
            "attacker_network_info": {
                "ip":              attacker_ip,
                "threat_score":    (osint or {}).get("threat_score",  0),
                "country_code":    (osint or {}).get("country_code",  ""),
                "isp":             (osint or {}).get("isp",           ""),
                "open_ports":      (osint or {}).get("open_ports",    []),
                "shodan_tags":     (osint or {}).get("shodan_tags",   []),
                "abuse_reports":   (osint or {}).get("abuse_reports", 0),
                "osint_label":     (osint or {}).get("label",         ""),
            },
            "timestamp_of_attack":      attack_timestamp,
            "commands_executed":        commands_executed,
            "malware_payload_files":    malware_info,
            "network_traffic_logs":     {
                "zeek_log_dir":  ZEEK_LOG_DIR,
                "log_files":     zeek_files,
                "note": "Full Zeek .log files included in zeek/ directory of this bundle.",
            },
            "attack_classification":    {
                "attack_type":   (prediction or {}).get("attack_type",   "Unknown"),
                "confidence":    (prediction or {}).get("confidence",    0.0),
                "is_attack":     (prediction or {}).get("is_attack",     False),
                "rf_verdict":    (prediction or {}).get("rf_verdict",    "Unknown"),
                "rf_confidence": (prediction or {}).get("rf_confidence", 0.0),
                "top_features":  (prediction or {}).get("shap", {}).get("top_features", []),
                "all_proba":     (prediction or {}).get("all_proba",     {}),
            },
            "system_logs":              session_logs,
            "session_id":               session_id,
            "tool":                     "Honeyport v2",
            "evidence_hash":            "",   # filled after serialisation
        }

        # Compute evidence hash over the bundle (excluding the hash field itself)
        bundle_str    = json.dumps(bundle, sort_keys=True, default=str)
        evidence_hash = hashlib.sha256(bundle_str.encode()).hexdigest()
        bundle["evidence_hash"] = evidence_hash

        # ── Build ZIP ────────────────────────────────────────────────────
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1. Full evidence bundle (main forensic record)
            zf.writestr("evidence_bundle.json",
                        json.dumps(bundle, indent=2, default=str))

            # 2. Zeek network traffic logs
            zeek_path = Path(ZEEK_LOG_DIR)
            if zeek_path.exists():
                for log_file in zeek_path.glob("*.log"):
                    zf.write(log_file, arcname=f"zeek/{log_file.name}")
            else:
                zf.writestr("zeek/README.txt",
                            "Zeek log directory not mounted at time of capture.")

            # 3. Raw honeypot session entries
            zf.writestr("honeypot/session.json",
                        json.dumps(session_logs, indent=2, default=str))

            # 4. Malware / payload files
            dl_path = Path(HONEYPOT_DL_DIR)
            if dl_path.exists():
                for malware_file in dl_path.iterdir():
                    if malware_file.is_file():
                        zf.write(malware_file,
                                 arcname=f"downloads/{malware_file.name}")

        buf.seek(0)
        return buf.read(), evidence_hash

    # ── Upload ─────────────────────────────────────────────────────────────

    def upload_session(
        self,
        attacker_ip:  str,
        session_id:   str,
        prediction:   dict | None = None,
        osint:        dict | None = None,
        session_data: dict | None = None,
    ) -> tuple[str, str]:
        """
        Bundle and upload one attack session to IPFS.

        Args:
            attacker_ip:  Source IP of the attacker
            session_id:   Unique session identifier
            prediction:   XGBoost/RF prediction dict (attack_type, confidence, …)
            osint:        OsintResult.to_dict() output
            session_data: Extra context (timestamp, trigger, …)

        Returns:
            (cid, evidence_hash)  –  IPFS CID and SHA-256 evidence hash
        """
        zip_bytes, evidence_hash = self._build_zip(
            attacker_ip, session_id,
            prediction=prediction,
            osint=osint,
            session_data=session_data,
        )
        filename = f"honeyport_{attacker_ip.replace('.','_')}_{session_id[:8]}.zip"

        if PINATA_JWT:
            cid = self._upload_to_pinata(zip_bytes, filename)
            if cid:
                log.info("IPFS upload OK  CID=%s  evidence_hash=%s  size=%dB",
                         cid, evidence_hash[:16], len(zip_bytes))
                return cid, evidence_hash
            log.warning("Pinata upload failed – writing to fallback storage.")

        cid = self._save_fallback(zip_bytes, filename, attacker_ip, session_id,
                                  evidence_hash=evidence_hash)
        return cid, evidence_hash

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
        self, data: bytes, filename: str, ip: str, session_id: str,
        evidence_hash: str = "",
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
            "pseudo_cid":    pseudo_cid,
            "sha256":        sha,
            "evidence_hash": evidence_hash or sha,
            "attacker_ip":   ip,
            "session_id":    session_id,
            "filename":      filename,
            "timestamp":     datetime.utcnow().isoformat(),
            "zip_path":      fallback_path,
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
